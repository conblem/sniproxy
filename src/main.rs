use crate::http::loop_http;
use crate::shutdown::{ShutdownReceiver, ShutdownTask};
use crate::tls::loop_https;
use crate::upstream::UpstreamConnector;
use anyhow::Error;
use clap::Parser;
use std::net::IpAddr;
use tokio::runtime::{Handle, Runtime};
use tracing::{info, info_span, Instrument, Level};
use tracing_subscriber::fmt::writer::MakeWriterExt;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;
use url::Url;

#[cfg(all(not(target_env = "msvc"), feature = "jemalloc"))]
use tikv_jemallocator::Jemalloc;

#[cfg(all(not(target_env = "msvc"), feature = "jemalloc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

mod http;
mod shutdown;
mod tls;
mod upstream;

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
    listen: IpAddr,

    #[arg(long)]
    console_listen: Option<IpAddr>,

    #[arg(long, default_value = "6669")]
    console_port: u16,
}

fn main() -> Result<(), Error> {
    let args = &*Box::leak(Box::new(Args::parse()));

    let rt = Runtime::new()?;

    init_tracing(args);

    let _span = info_span!("main").entered();

    info!("Starting up");

    let shutdown = init_shutdown(rt.handle())?;

    let resolver =
        TokioAsyncResolver::tokio(ResolverConfig::cloudflare_tls(), ResolverOpts::default());
    let upstream_connector = UpstreamConnector::new(resolver, args);

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

#[cfg(feature = "console")]
fn init_tracing(args: &Args) {
    let writer = std::io::stdout.with_max_level(Level::INFO);
    let fmt_layer = tracing_subscriber::fmt::layer().with_writer(writer);
    let registry = tracing_subscriber::registry().with(fmt_layer);
    if let Some(console_listen) = args.console_listen {
        let console_layer = console_subscriber::ConsoleLayer::builder()
            .server_addr((console_listen, args.console_port))
            .spawn();

        registry.with(console_layer).init();
    } else {
        registry.init();
    }
}

#[cfg(not(feature = "console"))]
fn init_tracing(args: &Args) {
    let writer = std::io::stdout.with_max_level(Level::INFO);
    let fmt_layer = tracing_subscriber::fmt::layer().with_writer(writer);
    tracing_subscriber::registry().with(fmt_layer).init();
}

fn init_shutdown(handle: &Handle) -> Result<ShutdownReceiver, Error> {
    let (shtudown_task, shutdown) = ShutdownTask::new();
    tokio::task::Builder::new().name("shutdown").spawn_on(
        shtudown_task.wait().instrument(info_span!("shutdown")),
        handle,
    )?;

    Ok(shutdown)
}
