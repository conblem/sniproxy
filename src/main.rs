use clap::Parser;
use fast_socks5::client::{Config, Socks5Stream};
use hyper::http::uri::{Parts, Scheme};
use hyper::server::conn::AddrStream;
use hyper::service::{make_service_fn, service_fn, Service};
use hyper::{Body, Client, Request, Response, Server, Uri};
use std::convert::Infallible;
use std::error::Error;
use std::future::{ready, Future};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tls_parser::{
    parse_tls_client_hello_extensions, parse_tls_plaintext, TlsExtension, TlsMessage,
    TlsMessageHandshake,
};
use tokio::io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Runtime;
use tokio::task::JoinHandle;
use tracing::field::display;
use tracing::{Instrument, Span};
use tracing_attributes::instrument;
use tracing_subscriber::filter::LevelFilter;
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

fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut args = Args::parse();
    let socks = args.socks.take().map(Arc::new);

    let rt = Runtime::new()?;
    tracing_subscriber::fmt::fmt()
        .with_max_level(LevelFilter::TRACE)
        .init();

    rt.block_on(
        async move {
            let resolver = TokioAsyncResolver::tokio(
                ResolverConfig::cloudflare_tls(),
                ResolverOpts::default(),
            );
            let resolver = Arc::new(resolver);

            let https = loop_https(resolver.clone(), &args, socks.clone()).in_current_span();
            let http = loop_http(resolver, &args, socks).in_current_span();

            tokio::select! {
                res = https => res?,
                res = http => res?,
            }
        }
        .in_current_span(),
    )
}

// add shutdown logic
fn loop_http(
    resolver: Arc<TokioAsyncResolver>,
    _args: &Args,
    _socks: Option<Arc<Url>>,
) -> JoinHandle<Result<(), Box<dyn Error + Send + Sync>>> {
    let client = Client::builder().build::<_, Body>(Connector { resolver });

    tokio::spawn(async move {
        let addr = "127.0.0.1:9081".parse()?;
        let make_svc = make_service_fn(|_socket: &AddrStream| {
            ready(Ok::<_, Infallible>(NewServer {
                client: client.clone(),
            }))
        });

        let server = Server::bind(&addr).serve(make_svc);
        server.await?;
        Ok(())
    })
}

struct NewServer {
    client: Client<Connector>,
}
impl Service<Request<Body>> for NewServer {
    type Response = Response<Body>;
    type Error = Box<dyn Error + Send + Sync>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        let client = self.client.clone();
        Box::pin(async move {
            let host = req.headers().get("host").unwrap();
            let host = host.to_str()?;

            let mut builder = Uri::builder().scheme(Scheme::HTTP).authority(host);
            if let Some(path_and_query) = req.uri().path_and_query() {
                builder = builder.path_and_query(path_and_query.clone());
            }

            *req.uri_mut() = builder.build()?;

            let res = client.request(req).await?;
            Ok(res)
        })
    }
}

#[derive(Clone)]
struct Connector {
    resolver: Arc<TokioAsyncResolver>,
}

impl Service<Uri> for Connector {
    type Response = TcpStream;
    type Error = Box<dyn Error + Send + Sync>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Uri) -> Self::Future {
        let resolver = Arc::clone(&self.resolver);
        Box::pin(async move {
            let target = lookup_ip(req.host().unwrap(), resolver.as_ref()).await?;

            let upstream = TcpStream::connect(format!("{}:80", target)).await?;
            Ok(upstream)
        })
    }
}

// todo: log peer addr
fn loop_https(
    resolver: Arc<TokioAsyncResolver>,
    args: &Args,
    socks: Option<Arc<Url>>,
) -> JoinHandle<Result<(), Box<dyn Error + Send + Sync>>> {
    let addr = format!("{}:{}", args.listen, args.port);
    let socks = socks.clone();

    tokio::spawn(async move {
        let listener = TcpListener::bind(addr).await?;

        loop {
            let (socket, _) = listener.accept().await?;
            let resolver = Arc::clone(&resolver);
            let socks = socks.clone();
            tokio::spawn(
                async move {
                    process_https(socket, resolver.as_ref(), socks.as_deref())
                        .await
                        .unwrap();
                }
                .in_current_span(),
            );
        }
    })
}

#[instrument(skip(resolver, socks), fields(socks, sni), err)]
async fn process_https(
    mut stream: TcpStream,
    resolver: &TokioAsyncResolver,
    socks: Option<&Url>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let socks_str = match socks {
        Some(socks) => socks.as_str(),
        None => "None",
    };
    Span::current().record("socks", display(socks_str));

    // todo: implement retry logic
    let mut buffer = [0u8; 1024];
    let n = stream.read_buf(&mut buffer.as_mut()).await?;
    let buffer = &buffer[..n];

    let extensions = parse_extensions(buffer)?;
    let sni = parse_sni(extensions)?;
    Span::current().record("sni", display(sni));

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

#[instrument(skip(resolver), ret, err)]
async fn lookup_ip(
    sni: &str,
    resolver: &TokioAsyncResolver,
) -> Result<A, Box<dyn Error + Send + Sync>> {
    let lookup = resolver.ipv4_lookup(sni).await?;

    let record = lookup.iter().next().ok_or("No IP found")?;

    Ok(*record)
}

#[instrument(skip(resolver), fields(target), err)]
async fn upstream_direct(
    sni: &str,
    resolver: &TokioAsyncResolver,
) -> Result<TcpStream, Box<dyn Error + Send + Sync>> {
    let target = lookup_ip(sni, resolver).await?;
    Span::current().record("target", display(target));

    Ok(TcpStream::connect(format!("{}:443", target)).await?)
}

// skips socks and record it with display instead
#[instrument(skip(socks, resolver), fields(socks = %socks), err)]
async fn upstream_socks(
    sni: &str,
    socks: &Url,
    resolver: &TokioAsyncResolver,
) -> Result<TcpStream, Box<dyn Error + Send + Sync>> {
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
