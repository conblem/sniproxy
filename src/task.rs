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
    pub(crate) fn with_shutdown(mut self, shutdown: impl Into<Option<ShutdownReceiver>>) -> Self {
        self.shutdown = shutdown.into();
        self
    }

    // a little more code so we can change the type of the gauge after the fact
    pub(crate) fn with_gauge<T: Atomic>(
        self,
        gauge: impl Into<Option<&'static GenericGauge<T>>>,
    ) -> Task<T> {
        Task {
            name: self.name,
            shutdown: self.shutdown,
            gauge: gauge.into(),
            span: self.span,
        }
    }

    pub(crate) fn in_current_span(mut self) -> Self {
        self.span = Some(Span::current());
        self
    }

    pub(crate) fn with_span(mut self, span: impl Into<Option<Span>>) -> Self {
        self.span = span.into();
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
            let msg = format!("Shutting down {}", self.name);
            async move {
                shutdown.wait().await;
                info!(msg);
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
    Head(#[pin] L),
    Tail(#[pin] R),
}

impl<L: Future, R: Future<Output = L::Output>> Future for Either<L, R> {
    type Output = L::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.project() {
            EitherEnum::Head(l) => l.poll(cx),
            EitherEnum::Tail(r) => r.poll(cx),
        }
    }
}

impl Either<(), ()> {
    fn new<T: Future>(fut: T) -> Either<T, Ready<T::Output>> {
        Either::Head(fut)
    }
}

impl<L: Future, R: Future<Output = L::Output>> Either<L, R> {
    fn conditional_extend<M, N, O, I>(self, option: O, mapper: M) -> Either<N, Either<L, R>>
    where
        O: Into<Option<I>>,
        M: FnOnce(Self, I) -> N,
        N: Future<Output = L::Output>,
    {
        match option.into() {
            Some(input) => Either::Head(mapper(self, input)),
            None => Either::Tail(self),
        }
    }
}
