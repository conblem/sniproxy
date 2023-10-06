use crate::shutdown::ShutdownReceiver;
use crate::task::Task;
use anyhow::Error;
use http_body::Full;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server};
use prometheus::{Encoder, TextEncoder};
use std::convert::Infallible;
use std::io::Cursor;
use std::net::SocketAddr;
use tokio::task::JoinHandle;
use tracing::{info, Instrument};
use tracing_attributes::instrument;

async fn handle(req: Request<Body>) -> Result<Response<Full<Cursor<Vec<u8>>>>, Infallible> {
    if req.method() != Method::GET {
        return Ok(error_response("Method not allowed"));
    }

    let metric_families = prometheus::gather();
    // Encode them to send.
    let encoder = TextEncoder::new();

    let mut buffer = Cursor::new(Vec::new());
    encoder.encode(&metric_families, &mut buffer).unwrap();

    let position = buffer.position() as usize;
    buffer.get_mut().truncate(position);
    buffer.set_position(0);

    Ok(Response::new(Full::new(buffer)))
}

fn error_response(error: &'static str) -> Response<Full<Cursor<Vec<u8>>>> {
    let body = Cursor::new(error.into());

    Response::builder()
        .status(500)
        .body(Full::new(body))
        .unwrap()
}

#[instrument(skip_all)]
pub(crate) fn loop_prom(shutdown: ShutdownReceiver) -> JoinHandle<Result<(), Error>> {
    let addr = SocketAddr::from(([127, 0, 0, 1], 9090));

    let make_service = make_service_fn(|_conn| async { Ok::<_, Infallible>(service_fn(handle)) });

    let server = Server::bind(&addr)
        .serve(make_service)
        .with_graceful_shutdown(
            async move {
                shutdown.wait().await;
                info!("Shutting down loop_prom");
            }
            .in_current_span(),
        );

    Task::new("loop_prom")
        .spawn(async move {
            server.await?;
            Ok(())
        })
        .unwrap()
}
