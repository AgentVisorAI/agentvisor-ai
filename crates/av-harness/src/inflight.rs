//! Track detached background tasks that must be drained by the
//! shutdown path.
//!
//! The `mcp_call` HTTP handler (`routes.rs`) intentionally decouples
//! the tool-execution body from axum's per-connection cancellation by
//! running the body under a fresh `tokio::spawn`. That decoupling is
//! required — a client disconnect between the sandbox debit and the
//! upstream tool call would otherwise strand durable state — but it
//! also decouples the body from axum's graceful-drain barrier. Without
//! a separate tracker, shutdown races the detached body: `wait_idle`
//! samples `pending == 0` before the body has reached its worker
//! submission, then returns; a fresh worker submission arriving after
//! that point rolls past `av_shutdown_session_close_timeouts_total`
//! and can quarantine an otherwise-recoverable session at restart.
//!
//! `InflightTracker` is the same shape as `WorkerHandle::wait_idle`
//! (`worker.rs:579`) — an `AcqRel` counter plus a `Notify` woken on
//! the zero transition — so the shutdown path can await every
//! detached body between HTTP drain and `wait_idle`.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::Notify;

/// Counts detached background tasks whose completion must be awaited
/// by the shutdown path. Currently only wraps `mcp_call_inner` spawns
/// in `routes.rs`; other detached-then-durable request bodies can
/// reuse the same tracker if they appear in future work.
#[derive(Default)]
pub struct InflightTracker {
    count: AtomicUsize,
    drained: Notify,
}

impl InflightTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment the tracker and return an `InflightGuard` whose
    /// `Drop` decrements and (on the zero transition) notifies every
    /// current `wait_drained` waiter.
    pub fn enter(self: &Arc<Self>) -> InflightGuard {
        self.count.fetch_add(1, Ordering::AcqRel);
        InflightGuard {
            tracker: Arc::clone(self),
        }
    }

    /// Current number of held `InflightGuard`s. Sampled by tests and
    /// by the shutdown-path metric emission on timeout.
    pub fn count(&self) -> usize {
        self.count.load(Ordering::Acquire)
    }

    /// Wait until every outstanding `InflightGuard` has been dropped.
    ///
    /// Uses the same pinned-Notified + `enable()`-before-load
    /// discipline as `WorkerHandle::wait_idle` (`worker.rs:600`); a
    /// `notify_waiters()` firing in the interval between a fresh
    /// `notified()` and its first poll would otherwise be lost.
    pub async fn wait_drained(&self) {
        loop {
            let notified = self.drained.notified();
            let mut notified = std::pin::pin!(notified);
            notified.as_mut().enable();
            if self.count.load(Ordering::Acquire) == 0 {
                return;
            }
            notified.await;
        }
    }
}

/// RAII decrement handle. Move into a detached spawn so its `Drop`
/// runs on the spawn's completion path (including panic-caught
/// unwind), not the outer request handler's cancellation.
pub struct InflightGuard {
    tracker: Arc<InflightTracker>,
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        if self.tracker.count.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.tracker.drained.notify_waiters();
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn wait_drained_returns_immediately_when_empty() {
        let tracker = Arc::new(InflightTracker::new());
        tokio::time::timeout(Duration::from_secs(1), tracker.wait_drained())
            .await
            .expect("wait_drained on empty tracker should return immediately");
        assert_eq!(tracker.count(), 0);
    }

    #[tokio::test]
    async fn wait_drained_blocks_until_last_guard_drops() {
        let tracker = Arc::new(InflightTracker::new());
        let guard_a = tracker.enter();
        let guard_b = tracker.enter();
        assert_eq!(tracker.count(), 2);

        let waiter_tracker = Arc::clone(&tracker);
        let waiter = tokio::spawn(async move { waiter_tracker.wait_drained().await });

        // Give the waiter a chance to subscribe.
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished(), "waiter must not fire while guards live");

        drop(guard_a);
        tokio::task::yield_now().await;
        assert!(
            !waiter.is_finished(),
            "waiter must not fire until the last guard drops"
        );

        drop(guard_b);
        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("waiter should wake within a second of last guard drop")
            .unwrap();
    }

    #[tokio::test]
    async fn many_guards_all_release_notify_the_waiter_once() {
        let tracker = Arc::new(InflightTracker::new());
        let guards: Vec<_> = (0..8).map(|_| tracker.enter()).collect();
        assert_eq!(tracker.count(), 8);

        let waiter_tracker = Arc::clone(&tracker);
        let waiter = tokio::spawn(async move { waiter_tracker.wait_drained().await });
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());

        drop(guards);
        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("waiter should wake within a second of the last guard drop")
            .unwrap();
        assert_eq!(tracker.count(), 0);
    }
}
