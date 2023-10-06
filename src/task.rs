use pin_project::pin_project;
use prometheus::core::{Atomic, AtomicI64, GenericGauge};
use std::borrow::Cow;
use std::future::{Future, Ready};
use std::ops::Deref;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::task::{Builder, JoinHandle};
use tracing::{info, Instrument, Span};

use crate::shutdown::ShutdownReceiver;
use crate::util::FutureExt;

pub(crate) struct Task<G: Atomic + 'static = AtomicI64> {
    name: Cow<'static, str>,
    shutdown: Option<ShutdownReceiver>,
    gauge: Option<&'static GenericGauge<G>>,
    span: Option<Span>,
}

impl Task<AtomicI64> {
    pub(crate) fn new<N: Into<Cow<'static, str>>>(name: N) -> Task<AtomicI64> {
        Task {
            name: name.into(),
            shutdown: None,
            gauge: None,
            span: None,
        }
    }
}

impl<G: Atomic> Task<G> {
    pub(crate) fn with_shutdown(mut self, shutdown: ShutdownReceiver) -> Self {
        self.shutdown = Some(shutdown);
        self
    }

    // a little more code so we can change the type of the gauge after the fact
    pub(crate) fn with_gauge<T: Atomic>(self, gauge: &'static GenericGauge<T>) -> Task<T> {
        Task {
            name: self.name,
            shutdown: self.shutdown,
            gauge: Some(gauge),
            span: self.span,
        }
    }

    pub(crate) fn in_current_span(mut self) -> Self {
        self.span = Some(Span::current());
        self
    }

    pub(crate) fn spawn<F, O, E>(self, fut: F) -> tokio::io::Result<JoinHandle<F::Output>>
    where
        F: Future<Output = Result<O, E>> + Send + 'static,
        F::Output: Send + 'static,
        O: Default + 'static,
        E: 'static,
    {
        let shutdown_factory = |shutdown: ShutdownReceiver| {
            let name = self.name.to_owned();
            async move {
                shutdown.wait().await;
                info!("Shutting down {}", name);
            }
        };

        let fut = Either::new(fut)
            .conditional_extend(self.shutdown, |fut, shutdown| {
                fut.with_shutdown(shutdown_factory(shutdown))
            })
            .conditional_extend(self.gauge, FutureExt::to_gauge)
            .conditional_extend(self.span, Instrument::instrument);

        Builder::new().name(self.name.deref()).spawn(fut)
    }
}

// This type is used to conditionally extend the future
// while keeping typings working
#[pin_project(project = EitherEnum)]
enum Either<L, R> {
    Left(#[pin] L),
    Right(#[pin] R),
}

impl<L: Future, R: Future<Output = L::Output>> Future for Either<L, R> {
    type Output = L::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.project() {
            EitherEnum::Left(l) => l.poll(cx),
            EitherEnum::Right(r) => r.poll(cx),
        }
    }
}

impl Either<(), ()> {
    fn new<T: Future>(fut: T) -> Either<T, Ready<T::Output>> {
        Either::Left(fut)
    }
}

impl<L: Future, R: Future<Output = L::Output>> Either<L, R> {
    fn conditional_extend<M: FnOnce(Self, I) -> N, N, I>(
        self,
        option: Option<I>,
        mapper: M,
    ) -> Either<N, Either<L, R>>
    where
        N: Future<Output = L::Output>,
    {
        match option {
            Some(input) => Either::Left(mapper(self, input)),
            None => Either::Right(self),
        }
    }
}
