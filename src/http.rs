use anyhow::{anyhow, Error, Result};
use hyper::body::Incoming;
use hyper::http::uri::Scheme;
use hyper::rt::Executor;
use hyper::server::conn::http1::Builder;
use hyper::service::{service_fn, HttpService};
use hyper::{Request, Response, Uri};
use hyper_util::client::legacy::connect::Connect;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioIo;
use once_cell::sync::Lazy;
use prometheus::{register_int_gauge, IntGauge};
use std::future::Future;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio::runtime::Handle;
use tokio::task::JoinHandle;
use tracing::{info_span, instrument, Instrument, Span};

use crate::shutdown::ShutdownReceiver;
use crate::task::Task;
use crate::util::FutureExt;
use crate::{UpstreamConnector, ARGS};

static HTTP_CONNECTION_COUNT: Lazy<IntGauge> =
    Lazy::new(|| register_int_gauge!("http_connection_count", "HTTP Connection count").unwrap());

// add shutdown logic
#[instrument(skip_all)]
pub(crate) fn loop_http(
    upstream_connector: UpstreamConnector,
    _shutdown: ShutdownReceiver,
) -> JoinHandle<Result<(), Error>> {
    let connector = connector_factory(upstream_connector.clone());

    let client = Client::builder(SpanExecutor::from(info_span!("client_background")))
        .build::<_, Incoming>(connector);

    Task::new("loop_http")
        .in_current_span()
        .spawn(async move {
            let addr = format!("{}:{}", ARGS.listen, ARGS.http_port);

            let socket = TcpListener::bind(addr).await?;
            while let Ok((stream, socket)) = socket.accept().await {
                let service = service_factory(&client, socket);
                // todo: fix spans
                tokio::spawn(
                    async move {
                        Builder::new()
                            .serve_connection(TokioIo::new(stream), service)
                            // todo: figure out shutdown
                            .await
                    }
                    .in_current_span(),
                );
            }
            Ok(())
        })
        // todo: fix this
        .unwrap()
}

fn service_factory<C>(
    client: &Client<C, Incoming>,
    _socket: SocketAddr,
) -> impl HttpService<Incoming, ResBody = Incoming, Future = impl Send>
where
    C: Connect + Clone + Send + Sync + 'static,
{
    let span = Span::current();
    let client = client.clone();
    service_fn(move |req| {
        request(req, client.clone())
            .to_gauge(&*HTTP_CONNECTION_COUNT)
            .instrument(info_span!(parent: &span.clone(), "client"))
    })
}

fn connector_factory(upstream_connector: UpstreamConnector) -> impl Connect + Clone {
    let span = Span::current();

    tower::service_fn(move |req: Uri| {
        let upstream_connector = upstream_connector.clone();
        Box::pin(
            async move {
                let host = req.host().ok_or(anyhow!("missing host"))?;
                let stream = upstream_connector.connect(host, 80).await?;
                Ok::<_, Error>(TokioIo::new(stream))
            }
            .instrument(span.clone()),
        )
    })
}

#[derive(Clone)]
struct SpanExecutor {
    handle: Handle,
    span: Span,
}

impl From<Span> for SpanExecutor {
    fn from(span: Span) -> Self {
        Self {
            handle: Handle::current(),
            span,
        }
    }
}

impl<F> Executor<F> for SpanExecutor
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    fn execute(&self, fut: F) {
        self.handle.spawn(fut.instrument(self.span.clone()));
    }
}

#[instrument(skip_all, fields(req = ?req), err)]
async fn request<C>(
    mut req: Request<Incoming>,
    client: Client<C, Incoming>,
) -> Result<Response<Incoming>>
where
    C: Connect + Clone + Send + Sync + 'static,
{
    let host = req.headers().get("host").unwrap();
    let host = host.to_str()?;

    let mut builder = Uri::builder().scheme(Scheme::HTTP).authority(host);
    if let Some(path_and_query) = req.uri().path_and_query() {
        builder = builder.path_and_query(path_and_query.clone());
    }

    *req.uri_mut() = builder.build()?;

    let res = client.request(req).await?;
    Ok(res)
}
