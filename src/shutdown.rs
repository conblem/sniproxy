#[cfg(not(target_family = "unix"))]
use tokio::signal;
#[cfg(target_family = "unix")]
use tokio::signal::unix;
#[cfg(target_family = "unix")]
use tokio::sync::watch::{channel, Receiver, Sender};
use tracing::{error, info};

pub(crate) struct ShutdownTask {
    sender: Sender<()>,
}

impl ShutdownTask {
    pub(crate) fn new() -> (Self, ShutdownReceiver) {
        let (sender, receiver) = channel(());
        (Self { sender }, ShutdownReceiver { receiver })
    }

    pub(crate) async fn wait(self) {
        self.signal().await;

        if let Err(err) = self.sender.send(()) {
            error!("Error sending shutdown: {}", err)
        }
    }

    // On unix, we listen to sigint and sigterm so it works with docker stop
    // todo: change to Result<impl Future>
    #[cfg(target_family = "unix")]
    async fn signal(&self) {
        let mut sigterm = unix::signal(unix::SignalKind::terminate()).unwrap();
        let sigterm = sigterm.recv();

        let mut sigint = unix::signal(unix::SignalKind::interrupt()).unwrap();
        let sigint = sigint.recv();

        tokio::select! {
            _ = sigterm => info!("SIGTERM received"),
            _ = sigint => info!("SIGINT received"),
        }
    }

    #[cfg(not(target_family = "unix"))]
    async fn signal(&self) {
        signal::ctrl_c().await.unwrap();
    }
}

#[derive(Clone)]
pub(crate) struct ShutdownReceiver {
    receiver: Receiver<()>,
}

impl ShutdownReceiver {
    pub(crate) async fn wait(mut self) {
        if let Err(err) = self.receiver.changed().await {
            error!("Error waiting for shutdown: {}", err);
        }
    }
}
