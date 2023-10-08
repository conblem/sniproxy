use pin_project::{pin_project, pinned_drop};
use prometheus::core::{Atomic, AtomicI64, GenericGauge};
use std::future::Future;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::task::{Context, Poll};

trait DropFunction<T> {
    fn drop_function(self, drop: Pin<&mut T>);
}

impl<T, F> DropFunction<T> for F
where
    F: FnOnce(Pin<&mut T>),
{
    fn drop_function(self, drop: Pin<&mut T>) {
        self(drop)
    }
}

#[pin_project(PinnedDrop)]
struct ClosureDropper<T, F: DropFunction<T>> {
    #[pin]
    inner: Option<T>,
    f: Option<F>,
}

impl<T, F: DropFunction<T>> Deref for ClosureDropper<T, F> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.inner.as_ref().unwrap()
    }
}

impl<T, F: DropFunction<T>> DerefMut for ClosureDropper<T, F> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.inner.as_mut().unwrap()
    }
}

#[pinned_drop]
impl<T, F: DropFunction<T>> PinnedDrop for ClosureDropper<T, F> {
    fn drop(mut self: Pin<&mut Self>) {
        let this = self.project();

        let f = this.f.take();
        let inner = this.inner.as_pin_mut();
        if let (Some(f), Some(inner)) = (f, inner) {
            f.drop_function(inner);
        }
    }
}

impl<T: Future, F: DropFunction<T>> Future for ClosureDropper<T, F> {
    type Output = T::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.project().inner.as_pin_mut().unwrap().poll(cx)
    }
}

struct DropGaugeFunction {}

impl<T, G: Atomic> DropFunction<GaugeFutureInner<'_, T, G>> for DropGaugeFunction {
    fn drop_function(self, drop: Pin<&mut GaugeFutureInner<T, G>>) {
        let this = drop.project();
        // only dec if the future has been polled
        // and in turn the gauge been incremented
        if *this.polled {
            this.gauge.dec();
        }
    }
}

#[pin_project]
pub(crate) struct GaugeFuture<'a, T, G: Atomic = AtomicI64> {
    #[pin]
    inner: ClosureDropper<GaugeFutureInner<'a, T, G>, DropGaugeFunction>,
}

impl<T: Future, G: Atomic> Future for GaugeFuture<'_, T, G> {
    type Output = T::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self
            .project()
            .inner
            .project()
            .inner
            .as_pin_mut()
            .unwrap()
            .project();

        if !*this.polled {
            this.gauge.inc();
            *this.polled = true;
        };

        this.inner.poll(cx)
    }
}

impl<T, G: Atomic> Deref for GaugeFuture<'_, T, G> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner.deref().inner
    }
}

impl<T, G: Atomic> DerefMut for GaugeFuture<'_, T, G> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner.deref_mut().inner
    }
}

#[pin_project]
struct GaugeFutureInner<'a, T, G: Atomic> {
    #[pin]
    inner: T,
    gauge: &'a GenericGauge<G>,
    polled: bool,
}

pub(crate) trait FutureExt: Future
where
    Self: Sized,
{
    fn to_gauge<G: Atomic>(self, gauge: &GenericGauge<G>) -> GaugeFuture<Self, G>;
    fn with_shutdown<S>(self, shutdown: S) -> ShutdownFuture<Self, S>;
}

impl<T: Future> FutureExt for T {
    fn to_gauge<G: Atomic>(self, gauge: &GenericGauge<G>) -> GaugeFuture<Self, G> {
        GaugeFuture {
            inner: ClosureDropper {
                inner: Some(GaugeFutureInner {
                    inner: self,
                    gauge,
                    polled: false,
                }),
                f: Some(DropGaugeFunction {}),
            },
        }
    }

    fn with_shutdown<S>(self, shutdown: S) -> ShutdownFuture<Self, S>
where {
        ShutdownFuture {
            inner: self,
            shutdown,
        }
    }
}

#[pin_project]
pub(crate) struct ShutdownFuture<T, S> {
    #[pin]
    inner: T,
    #[pin]
    shutdown: S,
}

impl<T, S, O, E> Future for ShutdownFuture<T, S>
where
    O: Default,
    T: Future<Output = Result<O, E>>,
    S: Future,
{
    type Output = T::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let inner = this.inner;
        let shutdown = this.shutdown;

        if let Poll::Ready(_) = shutdown.poll(cx) {
            return Poll::Ready(Ok(O::default()));
        }
        return inner.poll(cx);
    }
}
