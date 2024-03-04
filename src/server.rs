use crate::shutdown::ShutdownReceiver;
use anyhow::Result;
use http_body::Body;
use hyper::body::Incoming;
use hyper::server::conn::http1::Builder;
use hyper::service::HttpService;
use hyper_util::rt::TokioIo;
use std::pin::pin;
use tokio::net::{TcpListener, ToSocketAddrs};
use tokio::task::JoinSet;
use tracing::{error, info, info_span, Instrument};

pub(crate) struct Server<T> {
    service: T,
    shutdown: ShutdownReceiver,
}

impl<T> Server<T>
where
    T: HttpService<Incoming> + Send + Clone + 'static,
    T::Future: Send,
    T::ResBody: Send,
    <T::ResBody as Body>::Error: std::error::Error + Send + Sync,
    <T::ResBody as Body>::Data: Send,
{
    pub(crate) fn new(service: T, shutdown: ShutdownReceiver) -> Self {
        Self { service, shutdown }
    }
    pub(crate) async fn listen(mut self, addr: impl ToSocketAddrs) -> Result<()> {
        let listener = TcpListener::bind(addr).await?;
        let mut tasks = JoinSet::new();
        loop {
            let (stream, _) = tokio::select! {
                res = listener.accept() => res?,
                _ = self.shutdown.wait() => break,
            };
            let stream = TokioIo::new(stream);
            let service = self.service.clone();
            let mut shutdown = self.shutdown.clone();

            tasks.spawn(
                async move {
                    let conn = Builder::new().serve_connection(stream, service);
                    let mut conn = pin!(conn);
                    loop {
                        tokio::select! {
                            res = conn.as_mut() => res?,
                            _ = shutdown.wait() => {
                                conn.as_mut().graceful_shutdown();
                                info!("shutting down connection");
                                continue;
                            },
                        }
                        break;
                    }
                    Ok::<_, anyhow::Error>(())
                }
                .instrument(info_span!("connection")),
            );
        }
        info!("shutting down");
        while let Some(task) = tasks.join_next().await {
            let Err(err) = task? else { continue };
            error!("Error in task: {}", err);
        }
        Ok(())
    }
}
