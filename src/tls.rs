use tls_parser::Err;
use anyhow::{anyhow, bail, Result};
use once_cell::sync::Lazy;
use prometheus::{register_int_gauge, IntGauge};
use std::io::ErrorKind;
use std::net::SocketAddr;
use tls_parser::{
    parse_tls_client_hello_extensions, parse_tls_plaintext, TlsExtension, TlsMessage,
    TlsMessageHandshake,
};
use tls_parser::nom::Needed;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tracing::field::display;
use tracing::{info, instrument, Span};

use crate::shutdown::ShutdownReceiver;
use crate::task::Task;
use crate::{UpstreamConnector, ARGS};

static TLS_CONNECTION_COUNT: Lazy<IntGauge> =
    Lazy::new(|| register_int_gauge!("tls_connection_count", "TLS Connection Count").unwrap());

#[instrument(skip_all)]
pub(crate) fn loop_https(
    upstream_connector: UpstreamConnector,
    shutdown: ShutdownReceiver,
) -> JoinHandle<Result<()>> {
    let addr = format!("{}:{}", ARGS.listen, ARGS.tls_port);

    Task::new("loop_https")
        .in_current_span()
        .with_shutdown(shutdown.clone())
        .spawn(async move {
            let listener = TcpListener::bind(addr).await?;
            let shutdown = shutdown.clone();

            loop {
                let (socket, peer) = listener.accept().await?;

                let upstream_connector = upstream_connector.clone();
                Task::new("process_https")
                    .in_current_span()
                    .with_gauge(&*TLS_CONNECTION_COUNT)
                    .with_shutdown(shutdown.clone())
                    .spawn(process_https(socket, peer, upstream_connector))?;
            }
        })
        .unwrap()
}

#[instrument(skip_all, fields(sni, peer = %_peer), err)]
async fn process_https(
    mut stream: TcpStream,
    _peer: SocketAddr,
    upstream_connector: UpstreamConnector,
) -> Result<()> {
    let mut buffer = [0u8; 1024 * 10];
    // try 10 times to read more data
    let mut counter = 0;
    let mut n = 0;
    let extensions = loop {
        counter += 1;
        if counter >= 10 {
            bail!("Failed to read TLS extensions after 10 attempts");
        }

        n = n + stream.read_buf(&mut buffer[n..].as_mut()).await?;

        if n > buffer.len() {
            bail!("Read more bytes than buffer can hold, {}", n);
        }

        let needed = match parse_extensions(&buffer[..n])? {
            ExtensionsOrMoreNeeded::Extensions(extensions) => break extensions,
            ExtensionsOrMoreNeeded::MoreNeeded(needed) => needed,
        };
        info!("Read {} bytes, need more: {:?}", n, needed);
    };

    let sni = parse_sni(extensions)?;
    Span::current().record("sni", display(sni));

    let mut upstream = upstream_connector.connect(sni, 443).await?;
    upstream.write_all(&buffer[..n]).await?;

    info!("Client Hello successfully sent {}", n);

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

enum ExtensionsOrMoreNeeded<'a> {
    Extensions(Vec<TlsExtension<'a>>),
    MoreNeeded(Needed),
}

#[instrument(skip_all, err)]
fn parse_extensions(buffer: &[u8]) -> Result<ExtensionsOrMoreNeeded> {
    let plaintext = match parse_tls_plaintext(buffer) {
        Ok((_, plaintext)) => plaintext,
        Err(Err::Incomplete(needed)) => return Ok(ExtensionsOrMoreNeeded::MoreNeeded(needed)),
        Err(err) => bail!("Failed to parse TLS plaintext, {}", err),
    };
    let Some(TlsMessage::Handshake(handshake)) = plaintext.msg.first() else {
        bail!("No TLS handshake found");
    };
    let TlsMessageHandshake::ClientHello(client_hello) = handshake else {
        bail!("No ClientHello found");
    };
    let Some(extensions) = client_hello.ext else {
        bail!("No extensions found");
    };

    parse_tls_client_hello_extensions(extensions)
        .map(|(_, extensions)| ExtensionsOrMoreNeeded::Extensions(extensions))
        .map_err(|err| anyhow!("Failed to parse TLS extensions, {}", err))
}

#[instrument(skip_all, err)]
fn parse_sni(extensions: Vec<TlsExtension>) -> Result<&str> {
    let sni = extensions
        .into_iter()
        .filter_map(|ext| match ext {
            TlsExtension::SNI(sni) => Some(sni),
            _ => None,
        })
        .next();

    let Some(sni) = sni else {
        bail!("SNI Extension not found");
    };

    match sni.first() {
        Some((_, sni)) => Ok(std::str::from_utf8(sni)?),
        None => bail!("Couldn't parse SNI Name"),
    }
}
