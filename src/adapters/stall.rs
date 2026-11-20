//! A write-side stall bound shared by the IMAP, POP3 and SMTP sessions.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::AsyncWrite;
use tokio::time::{sleep, Sleep};

/// A writer whose every operation fails once it has made no progress
/// for `limit`: the peer is not reading, and the session ends on the
/// io error.
pub struct StallGuard<W> {
    inner: W,
    limit: Duration,
    /// Armed while an operation is pending; reset on every progress.
    stalled: Option<Pin<Box<Sleep>>>,
}

impl<W> StallGuard<W> {
    pub fn new(inner: W, limit: Duration) -> Self {
        Self {
            inner,
            limit,
            stalled: None,
        }
    }

    /// Fold the stall timer into one poll result: progress disarms it,
    /// a pending operation arms it (once) and fails when it fires.
    fn guard<T>(
        &mut self,
        cx: &mut Context<'_>,
        polled: Poll<std::io::Result<T>>,
    ) -> Poll<std::io::Result<T>> {
        if polled.is_ready() {
            self.stalled = None;
            return polled;
        }
        let limit = self.limit;
        let timer = self.stalled.get_or_insert_with(|| Box::pin(sleep(limit)));
        match timer.as_mut().poll(cx) {
            Poll::Ready(()) => {
                self.stalled = None;
                Poll::Ready(Err(std::io::ErrorKind::TimedOut.into()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for StallGuard<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let polled = Pin::new(&mut self.inner).poll_write(cx, buf);
        self.guard(cx, polled)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let polled = Pin::new(&mut self.inner).poll_flush(cx);
        self.guard(cx, polled)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let polled = Pin::new(&mut self.inner).poll_shutdown(cx);
        self.guard(cx, polled)
    }
}
