use clap::Parser;
use fast_socks5::client::{Config, Socks5Stream};
use std::error::Error;
use std::sync::Arc;
use tls_parser::{
    parse_tls_client_hello_extensions, parse_tls_plaintext, TlsExtension, TlsMessage,
    TlsMessageHandshake,
};
use tokio::io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Runtime;
use tracing::field::display;
use tracing::{info, Span};
use tracing_attributes::instrument;
use tracing_futures::Instrument;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::proto::rr::rdata::A;
use trust_dns_resolver::TokioAsyncResolver;
use url::Url;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Name of the person to greet
    #[arg(long)]
    socks: Option<Url>,

    #[arg(long, default_value = "443")]
    port: u16,

    #[arg(long, default_value = "0.0.0.0")]
    listen: String,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let socks = args.socks.map(Arc::new);

    let rt = Runtime::new()?;
    tracing_subscriber::fmt::init();
    rt.block_on(
        async move {
            let listener = TcpListener::bind(format!("{}:{}", args.listen, args.port)).await?;

            let resolver = TokioAsyncResolver::tokio(
                ResolverConfig::cloudflare_tls(),
                ResolverOpts::default(),
            );
            let resolver = Arc::new(resolver);

            loop {
                let (socket, _) = listener.accept().await?;
                let resolver = Arc::clone(&resolver);
                let socks = socks.as_ref().map(Arc::clone);
                tokio::spawn(
                    async move {
                        process_socket(socket, resolver.as_ref(), socks.as_deref())
                            .await
                            .unwrap();
                    }
                    .in_current_span(),
                );
            }
        }
        .in_current_span(),
    )
}

#[instrument(skip(resolver), err)]
async fn process_socket(
    mut stream: TcpStream,
    resolver: &TokioAsyncResolver,
    socks: Option<&Url>,
) -> Result<(), Box<dyn Error>> {
    let mut buffer = [0u8; 1024];
    let n = stream.read_buf(&mut buffer.as_mut()).await?;
    let buffer = &buffer[..n];

    let extensions = parse_extensions(buffer)?;
    let sni = parse_sni(extensions)?;

    println!("SNI: {}", sni);

    let mut upstream = match socks {
        Some(socks) => upstream_socks(sni, socks, resolver).await?,
        None => upstream_direct(sni, resolver).await?,
    };
    upstream.write_all(buffer).await?;

    let res = copy_bidirectional(&mut stream, &mut upstream).await;
    println!("finished: {:?}", res);

    Ok(())
}

#[instrument(skip(resolver), fields(record), err)]
async fn lookup_ip(sni: &str, resolver: &TokioAsyncResolver) -> Result<A, Box<dyn Error>> {
    let lookup = resolver.ipv4_lookup(sni).await?;

    let record = lookup.iter().next().ok_or("No IP found")?;
    info!("IP: {:?}", record);
    Span::current().record("record", display(record));

    Ok(*record)
}

#[instrument(skip(resolver), err)]
async fn upstream_direct(
    sni: &str,
    resolver: &TokioAsyncResolver,
) -> Result<TcpStream, Box<dyn Error>> {
    let target = lookup_ip(sni, resolver).await?;

    Ok(TcpStream::connect(format!("{}:443", target)).await?)
}

#[instrument(skip(resolver), err)]
async fn upstream_socks(
    sni: &str,
    socks: &Url,
    resolver: &TokioAsyncResolver,
) -> Result<TcpStream, Box<dyn Error>> {
    let target = match socks.scheme() {
        "socks5" => lookup_ip(sni, resolver).await?.to_string(),
        "socks5h" => sni.to_string(),
        _ => Err("Invalid scheme for socks")?,
    };

    let port = socks.port().unwrap_or(1080);
    let socks = match socks.host_str() {
        Some(host) => format!("{}:{}", host, port),
        None => Err("Invalid socks url")?,
    };

    let upstream = Socks5Stream::connect(socks.as_str(), target, 443, Config::default()).await?;

    Ok(upstream.get_socket())
}

#[instrument(skip_all, err)]
fn parse_extensions(buffer: &[u8]) -> Result<Vec<TlsExtension>, Box<dyn Error>> {
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
fn parse_sni(extensions: Vec<TlsExtension>) -> Result<&str, Box<dyn Error>> {
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
