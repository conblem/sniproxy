use crate::{Args, UpstreamConnector};
use std::error::Error;
use std::io::ErrorKind;
use std::net::SocketAddr;
use tls_parser::{
    parse_tls_client_hello_extensions, parse_tls_plaintext, TlsExtension, TlsMessage,
    TlsMessageHandshake,
};
use tokio::io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch::Receiver;
use tokio::task::JoinHandle;
use tracing::field::display;
use tracing::{info, Instrument, Span};
use tracing_attributes::instrument;

// todo: log peer addr
#[instrument(skip_all)]
pub(crate) fn loop_https(
    upstream_connector: UpstreamConnector,
    args: &'static Args,
    mut shutdown: Receiver<()>,
) -> JoinHandle<Result<(), Box<dyn Error + Send + Sync>>> {
    let addr = format!("{}:{}", args.listen, args.tls_port);

    tokio::spawn(
        async move {
            let listener = TcpListener::bind(addr).await?;

            loop {
                let accept = listener.accept();
                let shutdown_fut = shutdown.changed();
                let (socket, peer) = tokio::select! {
                    res = accept => res?,
                    _ = shutdown_fut => {
                        info!("Shutting down HTTPS");
                        return Ok(())
                    },
                };
                let upstream_connector = upstream_connector.clone();
                let mut shutdown = shutdown.clone();
                tokio::spawn(
                    async move {
                        let https = process_https(socket, peer, upstream_connector);
                        let shutdown = shutdown.changed();
                        tokio::select! {
                            res = https => res,
                            _ = shutdown => {
                                info!("Shutting down HTTPS");
                                Ok(())
                            },
                        }
                    }
                    .in_current_span(),
                );
            }
        }
        .in_current_span(),
    )
}

#[instrument(skip_all, fields(sni, peer = %_peer), err)]
async fn process_https(
    mut stream: TcpStream,
    _peer: SocketAddr,
    upstream_connector: UpstreamConnector,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut buffer = [0u8; 1024];
    let n = stream.read_buf(&mut buffer.as_mut()).await?;
    let buffer = &buffer[..n];

    let extensions = parse_extensions(buffer)?;
    let sni = parse_sni(extensions)?;
    Span::current().record("sni", display(sni));

    let mut upstream = upstream_connector.connect(sni, 443).await?;
    upstream.write_all(buffer).await?;

    // todo: figure out if we have to do something with the result
    let res = copy_bidirectional(&mut stream, &mut upstream).await;

    match res {
        Ok((sent_bytes, received_bytes)) => {
            info!(
                "Sent {} bytes, received {} bytes",
                sent_bytes, received_bytes
            );
        }
        Err(err) if matches!(err.kind(), ErrorKind::BrokenPipe) => {
            info!("Client disconnected")
        }
        Err(err) => Err(err)?,
    };

    Ok(())
}

#[instrument(skip_all, err)]
fn parse_extensions(buffer: &[u8]) -> Result<Vec<TlsExtension>, Box<dyn Error + Send + Sync>> {
    let msg = match parse_tls_plaintext(buffer) {
        Ok((_, plaintext)) => plaintext.msg,
        Err(_) => Err("Failed to parse TLS plaintext")?,
    };

    let handshake = match msg.first() {
        Some(TlsMessage::Handshake(handshake)) => handshake,
        _ => Err("No TLS handshake found")?,
    };
    let client_hello = match handshake {
        TlsMessageHandshake::ClientHello(client_hello) => client_hello,
        _ => Err("No ClientHello found")?,
    };
    let extensions = match client_hello.ext {
        Some(extensions) => extensions,
        None => Err("No extensions found")?,
    };

    match parse_tls_client_hello_extensions(extensions) {
        Ok((_, extensions)) => Ok(extensions),
        Err(_) => Err("Failed to parse TLS extensions")?,
    }
}

#[instrument(skip_all, err)]
fn parse_sni(extensions: Vec<TlsExtension>) -> Result<&str, Box<dyn Error + Send + Sync>> {
    let sni = extensions
        .iter()
        .filter_map(|ext| match ext {
            TlsExtension::SNI(sni) => Some(sni),
            _ => None,
        })
        .next()
        .ok_or("SNI Extension not found")?;

    match sni.first() {
        Some((_, sni)) => Ok(std::str::from_utf8(sni)?),
        None => Err("Couldn't parse SNI Name")?,
    }
}
