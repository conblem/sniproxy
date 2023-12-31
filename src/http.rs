use anyhow::{anyhow, Error};
use hyper::client::connect::Connect;
use hyper::http::uri::Scheme;
use hyper::rt::Executor;
use hyper::server::conn::AddrStream;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Client, Request, Response, Server, Uri};
use once_cell::sync::Lazy;
use prometheus::{register_int_gauge, IntGauge};
use std::convert::Infallible;
use std::future::{ready, Future};
use tokio::runtime::Handle;
use tokio::task::JoinHandle;
use tracing::{info, info_span, Instrument, Span};
use tracing_attributes::instrument;

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
    shutdown: ShutdownReceiver,
) -> JoinHandle<Result<(), Error>> {
    let connector = connector_factory(upstream_connector.clone());

    let client = Client::builder()
        .executor(SpanExecutor::from(info_span!("client_background")))
        .build::<_, Body>(connector);

    Task::new("loop_http")
        .in_current_span()
        .spawn(async move {
            let addr = format!("{}:{}", ARGS.listen, ARGS.http_port).parse()?;

            let span = Span::current();
            let make_svc = make_service_fn(|_socket: &AddrStream| {
                let span = span.clone();
                let client = client.clone();
                ready(Ok::<_, Infallible>(service_fn(move |req| {
                    request(req, client.clone())
                        .to_gauge(&*HTTP_CONNECTION_COUNT)
                        .instrument(info_span!(parent: span.clone(), "client"))
                })))
            });

            Server::bind(&addr)
                .executor(SpanExecutor::from(info_span!("server_background")))
                .serve(make_svc)
                .with_graceful_shutdown(
                    async move {
                        shutdown.wait().await;
                        info!("Shutting down loop_http");
                    }
                    .in_current_span(),
                )
                .await?;
            Ok(())
        })
        // todo: fix this
        .unwrap()
}

fn connector_factory(upstream_connector: UpstreamConnector) -> impl Connect + Clone {
    let span = Span::current();

    tower::service_fn(move |req: Uri| {
        let upstream_connector = upstream_connector.clone();
        Box::pin(
            async move {
                let host = req.host().ok_or(anyhow!("missing host"))?;
                upstream_connector.connect(host, 80).await
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
async fn request<C>(mut req: Request<Body>, client: Client<C>) -> Result<Response<Body>, Error>
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
