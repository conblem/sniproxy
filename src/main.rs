use crate::http::loop_http;
use crate::tls::loop_https;
use clap::Parser;
use fast_socks5::client::{Config as SocksConfig, Socks5Stream};
use std::error::Error;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::runtime::Runtime;
use tokio::signal::unix;
use tokio::signal::unix::SignalKind;
use tokio::sync::watch::channel;
use tracing::{info, info_span, Instrument};
use tracing_attributes::instrument;
use tracing_subscriber::filter::LevelFilter;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;
use url::Url;

mod http;
mod tls;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Name of the person to greet
    #[arg(long)]
    socks: Option<Url>,

    #[arg(long, default_value = "443")]
    tls_port: u16,

    #[arg(long, default_value = "80")]
    http_port: u16,

    #[arg(long, default_value = "0.0.0.0")]
    listen: String,
}

fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let args = &*Box::leak(Box::new(Args::parse()));

    let rt = Runtime::new()?;
    tracing_subscriber::fmt::fmt()
        .with_max_level(LevelFilter::INFO)
        .init();

    info_span!("main");
    info!("Starting up");

    let resolver =
        TokioAsyncResolver::tokio(ResolverConfig::cloudflare_tls(), ResolverOpts::default());
    let upstream_connector = UpstreamConnector::new(resolver, args);

    let (sender, shutdown) = channel(());
    rt.spawn(
        async move {
            let mut signal = unix::signal(SignalKind::terminate()).unwrap();
            signal.recv().await;
            info!("Ctrl C received");
            sender.send(()).unwrap();
        }
        .instrument(info_span!("shutdown")),
    );

    rt.block_on(
        async move {
            let https =
                loop_https(upstream_connector.clone(), args, shutdown.clone()).in_current_span();
            let http = loop_http(upstream_connector, args, shutdown).in_current_span();

            tokio::select! {
                res = https => res?,
                res = http => res?,
            }
        }
        .in_current_span(),
    )
}

#[derive(Clone)]
struct UpstreamConnector {
    resolver: Arc<TokioAsyncResolver>,
    args: &'static Args,
}

impl UpstreamConnector {
    fn new(upstream_connector: TokioAsyncResolver, args: &'static Args) -> Self {
        Self {
            resolver: Arc::new(upstream_connector),
            args,
        }
    }
}

impl UpstreamConnector {
    #[instrument(skip_all, fields(port = port), err)]
    async fn connect(
        &self,
        sni: &str,
        port: u16,
    ) -> Result<TcpStream, Box<dyn Error + Send + Sync>> {
        match self.args.socks {
            Some(ref socks) => self.upstream_socks(sni, port, socks).await,
            None => self.upstream_direct(sni, port).await,
        }
    }

    #[instrument(skip_all, err)]
    async fn upstream_direct(
        &self,
        sni: &str,
        port: u16,
    ) -> Result<TcpStream, Box<dyn Error + Send + Sync>> {
        let target = self.lookup_ip(sni).await?;

        Ok(TcpStream::connect((target, port)).await?)
    }

    #[instrument(skip_all, fields(socks = %socks), err)]
    async fn upstream_socks(
        &self,
        sni: &str,
        port: u16,
        socks: &Url,
    ) -> Result<TcpStream, Box<dyn Error + Send + Sync>> {
        let target = match socks.scheme() {
            "socks5" => self.lookup_ip(sni).await?.to_string(),
            "socks5h" => sni.to_string(),
            _ => Err("Invalid scheme for socks")?,
        };

        let socks_port = socks.port().unwrap_or(1080);
        let socks_host = match socks.host_str() {
            Some(socks_host) => (socks_host, socks_port),
            None => Err("Invalid socks url")?,
        };

        let upstream =
            Socks5Stream::connect(socks_host, target, port, SocksConfig::default()).await?;

        Ok(upstream.get_socket())
    }

    // add ipv6 support
    #[instrument(skip_all, ret, err)]
    async fn lookup_ip(&self, sni: &str) -> Result<Ipv4Addr, Box<dyn Error + Send + Sync>> {
        let lookup = self.resolver.ipv4_lookup(sni).await?;

        let record = lookup.iter().next().ok_or("No IP found")?;

        Ok(Ipv4Addr::from(record.octets()))
    }
}
