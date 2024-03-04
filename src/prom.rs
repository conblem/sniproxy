use crate::shutdown::ShutdownReceiver;
use crate::task::Task;
use anyhow::Result;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1::Builder;
use hyper::service::service_fn;
use hyper::{Method, Request, Response};
use hyper_util::rt::TokioIo;
use prometheus::{Encoder, TextEncoder};
use std::convert::Infallible;
use std::io::Cursor;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tracing::{instrument, Instrument};

async fn handle(req: Request<Incoming>) -> Result<Response<Full<Cursor<Vec<u8>>>>, Infallible> {
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
pub(crate) fn loop_prom(_shutdown: ShutdownReceiver) -> JoinHandle<Result<()>> {
    let addr = SocketAddr::from(([127, 0, 0, 1], 9090));

    Task::new("loop_prom")
        .spawn(async move {
            let listener = TcpListener::bind(addr).await?;
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(
                    async move {
                        Builder::new()
                            .serve_connection(TokioIo::new(stream), service_fn(handle))
                            // todo: figure out shutdown
                            .await
                    }
                    .in_current_span(),
                );
            }
            Ok(())
        })
        .unwrap()
}
