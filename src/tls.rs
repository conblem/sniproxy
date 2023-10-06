use anyhow::{anyhow, Error};
use once_cell::sync::Lazy;
use prometheus::{register_int_gauge, IntGauge};
use std::io::ErrorKind;
use std::net::SocketAddr;
use tls_parser::{
    parse_tls_client_hello_extensions, parse_tls_plaintext, TlsExtension, TlsMessage,
    TlsMessageHandshake,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tracing::field::display;
use tracing::{info, Instrument, Span};
use tracing_attributes::instrument;

use crate::shutdown::ShutdownReceiver;
use crate::util::ToGaugeFuture;
use crate::{UpstreamConnector, ARGS};

static TLS_CONNECTION_COUNT: Lazy<IntGauge> =
    Lazy::new(|| register_int_gauge!("tls_connection_count", "TLS Connection Count").unwrap());

// todo: log peer addr
#[instrument(skip_all)]
pub(crate) fn loop_https(
    upstream_connector: UpstreamConnector,
    shutdown: ShutdownReceiver,
) -> JoinHandle<Result<(), Error>> {
    let addr = format!("{}:{}", ARGS.listen, ARGS.tls_port);

    tokio::task::Builder::new()
        .name("loop_https")
        .spawn(
            async move {
                let listener = TcpListener::bind(addr).await?;

                loop {
                    let accept = listener.accept();

                    let shutdown_clone = shutdown.clone();
                    let shutdown_fut = shutdown.clone().wait();
                    let (socket, peer) = tokio::select! {
                        res = accept => res?,
                        _ = shutdown_fut => {
                            info!("Shutting down HTTPS");
                            return Ok(())
                        },
                    };
                    let upstream_connector = upstream_connector.clone();
                    tokio::task::Builder::new().name("process_https").spawn(
                        async move {
                            let https = process_https(socket, peer, upstream_connector);
                            let shutdown_fut = shutdown_clone.wait();
                            tokio::select! {
                                res = https => res,
                                _ = shutdown_fut => {
                                    info!("Shutting down HTTPS");
                                    Ok(())
                                },
                            }
                        }
                        .to_gauge(&*TLS_CONNECTION_COUNT)
                        .in_current_span(),
                    )?;
                }
            }
            .in_current_span(),
        )
        // todo: fix this
        .unwrap()
}

#[instrument(skip_all, fields(sni, peer = %_peer), err)]
async fn process_https(
    mut stream: TcpStream,
    _peer: SocketAddr,
    upstream_connector: UpstreamConnector,
) -> Result<(), Error> {
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
            info!("Client disconnected: {}", err)
        }
        Err(err) if matches!(err.kind(), ErrorKind::ConnectionReset) => {
            info!("Client disconnected: {}", err)
        }
        Err(err) => Err(err)?,
    };

    Ok(())
}

#[cfg(not(target_os = "linux"))]
async fn copy_bidirectional<A, B>(a: &mut A, b: &mut B) -> std::io::Result<(u64, u64)>
where
    A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    tokio::io::copy_bidirectional(a, b).await
}

#[cfg(target_os = "linux")]
async fn copy_bidirectional<A, B>(a: &mut A, b: &mut B) -> std::io::Result<(u64, u64)>
where
    A: tokio_splice::Stream + Unpin,
    B: tokio_splice::Stream + Unpin,
{
    tokio_splice::zero_copy_bidirectional(a, b).await
}

#[instrument(skip_all, err)]
fn parse_extensions(buffer: &[u8]) -> Result<Vec<TlsExtension>, Error> {
    let Ok((_, plaintext)) = parse_tls_plaintext(buffer) else {
        Err(anyhow!("Failed to parse TLS plaintext"))?
    };
    let Some(TlsMessage::Handshake(handshake)) = plaintext.msg.first() else {
        Err(anyhow!("No TLS handshake found"))?
    };
    let TlsMessageHandshake::ClientHello(client_hello) = handshake else {
        Err(anyhow!("No ClientHello found"))?
    };
    let Some(extensions) = client_hello.ext else {
        Err(anyhow!("No extensions found"))?
    };

    parse_tls_client_hello_extensions(extensions)
        .map(|(_, extensions)| extensions)
        .map_err(|_| anyhow!("Failed to parse TLS extensions"))
}

#[instrument(skip_all, err)]
fn parse_sni(extensions: Vec<TlsExtension>) -> Result<&str, Error> {
    let sni = extensions
        .iter()
        .filter_map(|ext| match ext {
            TlsExtension::SNI(sni) => Some(sni),
            _ => None,
        })
        .next()
        .ok_or(anyhow!("SNI Extension not found"))?;

    match sni.first() {
        Some((_, sni)) => Ok(std::str::from_utf8(sni)?),
        None => Err(anyhow!("Couldn't parse SNI Name"))?,
    }
}
