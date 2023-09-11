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
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Name of the person to greet
    #[arg(long)]
    socks: Option<String>,

    #[arg(long, default_value = "443")]
    port: u16,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let socks = args.socks.map(|socks| &*socks.leak());

    let listener = TcpListener::bind(format!("127.0.0.1:{}", args.port)).await?;

    let resolver =
        TokioAsyncResolver::tokio(ResolverConfig::cloudflare_tls(), ResolverOpts::default());
    let resolver = Arc::new(resolver);

    loop {
        let (socket, _) = listener.accept().await?;
        let resolver = Arc::clone(&resolver);
        tokio::spawn(async move {
            process_socket(socket, resolver.as_ref(), socks)
                .await
                .unwrap();
        });
    }
}

async fn process_socket(
    mut stream: TcpStream,
    resolver: &TokioAsyncResolver,
    socks: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    let mut buffer = [0u8; 1024];
    let n = stream.read_buf(&mut buffer.as_mut()).await?;
    let buffer = &buffer[..n];

    let extensions = parse_extensions(buffer)?;
    let sni = parse_sni(extensions)?;

    println!("SNI: {}", sni);

    let mut upstream = match socks {
        Some(socks) => upstream_socks(sni, socks).await?,
        None => upstream_direct(sni, resolver).await?,
    };
    upstream.write_all(buffer).await?;

    let res = copy_bidirectional(&mut stream, &mut upstream).await;
    println!("finished: {:?}", res);

    Ok(())
}

async fn upstream_direct(
    sni: &str,
    resolver: &TokioAsyncResolver,
) -> Result<TcpStream, Box<dyn Error>> {
    let lookup = resolver.ipv4_lookup(sni).await?;

    let record = lookup.iter().next().ok_or("No IP found")?;
    let addr = format!("{}:443", record);

    Ok(TcpStream::connect(addr).await?)
}

async fn upstream_socks(sni: &str, socks: &str) -> Result<TcpStream, Box<dyn Error>> {
    let upstream = Socks5Stream::connect(socks, sni.to_string(), 443, Config::default()).await?;

    Ok(upstream.get_socket())
}

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
