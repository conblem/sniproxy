use anyhow::Error;
use clap::Parser;
use once_cell::sync::Lazy;
use opentelemetry::KeyValue;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::runtime::Tokio;
use opentelemetry_sdk::{trace, Resource};
use opentelemetry_semantic_conventions::resource::{SERVICE_NAME, SERVICE_VERSION};
use std::net::IpAddr;
use tokio::runtime::{Handle, Runtime};
use tracing::{info, info_span, Instrument, Level, Subscriber};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt::writer::MakeWriterExt;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::Layer;
use url::Url;

#[cfg(all(not(target_env = "msvc"), feature = "jemalloc"))]
use tikv_jemallocator::Jemalloc;

use crate::http::loop_http;
use crate::prom::loop_prom;
use crate::shutdown::{ShutdownReceiver, ShutdownTask};
use crate::tls::loop_https;
use crate::upstream::UpstreamConnector;

#[cfg(all(not(target_env = "msvc"), feature = "jemalloc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

mod http;
mod prom;
mod shutdown;
mod tls;
mod upstream;
mod util;

static ARGS: Lazy<Args> = Lazy::new(|| Args::parse());

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

    #[arg(long)]
    otel_endpoint: Option<String>,

    #[arg(long, default_value = "sniproxy")]
    otel_service_name: String,

    #[arg(long)]
    dns: Option<String>,
}

fn main() -> Result<(), Error> {
    let rt = Runtime::new()?;
    let _enter = rt.enter();

    init_tracing();

    let _span = info_span!("main").entered();

    info!("Starting up");

    let shutdown = init_shutdown(rt.handle())?;

    rt.block_on(
        async move {
            let upstream_connector = UpstreamConnector::new().await?;

            let https = loop_https(upstream_connector.clone(), shutdown.clone()).in_current_span();
            let http = loop_http(upstream_connector, shutdown.clone()).in_current_span();
            let prom = loop_prom(shutdown).in_current_span();

            tokio::select! {
                res = https => res?,
                res = http => res?,
                res = prom => res?,
            }
        }
        .in_current_span(),
    )
}

#[cfg(feature = "console")]
fn init_tracing() {
    let registry = tracing_subscriber::registry().with(fmt_layer());

    let Some(console_listen) = ARGS.console_listen else {
        registry.init();
        return;
    };

    let registry = registry.with(console_layer(console_listen, ARGS.console_port));

    let Some(otel_endpoint) = ARGS.otel_endpoint.clone() else {
        registry.init();
        return;
    };

    registry.with(otel_layer(otel_endpoint)).init();
}

#[cfg(not(feature = "console"))]
fn init_tracing(args: &Args) {
    tracing_subscriber::registry().with(fmt_layer()).init();
}

fn fmt_layer<S>() -> impl Layer<S>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    let writer = std::io::stdout.with_max_level(Level::INFO);
    tracing_subscriber::fmt::layer().with_writer(writer)
}

fn console_layer<S>(console_listen: IpAddr, console_port: u16) -> impl Layer<S>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    console_subscriber::ConsoleLayer::builder()
        .server_addr((console_listen, console_port))
        .spawn()
}

fn otel_layer<S>(otel_endpoint: String) -> impl Layer<S>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    let exporter = opentelemetry_otlp::new_exporter()
        .tonic()
        .with_endpoint(otel_endpoint);
    let tracer = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(exporter)
        .with_trace_config(otel_config())
        .install_batch(Tokio)
        .expect("Failed to create tracer");

    tracing_opentelemetry::layer()
        .with_tracer(tracer)
        .with_filter(LevelFilter::INFO)
}

const VERSION: Option<&str> = option_env!("CARGO_PKG_VERSION");

fn otel_config() -> trace::Config {
    let mut values = vec![KeyValue::new(SERVICE_NAME, &*ARGS.otel_service_name)];
    if let Some(version) = VERSION {
        values.push(KeyValue::new(SERVICE_VERSION, version));
    }

    trace::config().with_resource(Resource::new(values))
}

fn init_shutdown(handle: &Handle) -> Result<ShutdownReceiver, Error> {
    let (shtudown_task, shutdown) = ShutdownTask::new();
    tokio::task::Builder::new().name("shutdown").spawn_on(
        shtudown_task.wait().instrument(info_span!("shutdown")),
        handle,
    )?;

    Ok(shutdown)
}
