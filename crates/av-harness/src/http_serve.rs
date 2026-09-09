//! Accept loop with client-silence reaping — the slowloris defense
//! `axum::serve` cannot provide.
//!
//! `axum::serve` (0.8) builds hyper-util's connection builder with **no
//! timer and no `header_read_timeout`** and exposes no way to set one, so
//! a client that connects and sends a partial request line — or full
//! headers and then dribbles a `Content-Length` body forever — holds its
//! fd and connection task indefinitely (verified empirically: 90 s+ holds
//! with zero reaping). On the shipped k8s/systemd exposure that is an
//! unauthenticated fd-exhaustion vector on the proxy front door.
//!
//! This module owns the accept loop instead, mirroring axum's semantics
//! (`Router::call` per connection, `serve_connection_with_upgrades`,
//! graceful drain on shutdown) while adding exactly two client-silence
//! bounds — deliberately *not* a whole-request deadline, because a
//! legitimate upstream first token can take minutes and SSE responses
//! stream far longer than any sane global timeout:
//!
//! * **Header phase**: hyper's `header_read_timeout` (30 s), which also
//!   reaps pre-request idle keep-alive connections (hyper arms it
//!   between requests on an idle HTTP/1 connection).
//! * **Body phase**: a per-*frame* gap timeout on the request body
//!   (30 s between chunks), applied via `SilenceBoundedBody`. A slow
//!   uploader making real progress never trips it; a stalled one is
//!   aborted with a hyper error that resets the stream.
//! * **HTTP/2**: keep-alive pings (20 s interval / 30 s grace) reap
//!   silent peers; `header_read_timeout` covers the h1 preface path.
//!
//! Shutdown mirrors `axum::serve::with_graceful_shutdown`: when the
//! caller's shutdown future resolves, the listener is dropped (new
//! connects refused), every live connection gets
//! `graceful_shutdown()` via [`hyper_util::server::graceful::GracefulShutdown`],
//! and the returned future resolves once all connections finish — the
//! caller keeps its own drain-budget `timeout` around that future, so
//! the drain-timeout accounting in `main.rs` is unchanged.

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::Router;
use hyper::body::{Body, Frame, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder;
use hyper_util::server::graceful::GracefulShutdown;
use tower::ServiceExt as _;

/// Maximum client silence while reading request headers (also arms
/// between keep-alive requests, reaping pre-request idle connections).
/// Production value; passed by `main.rs` into the serve loop.
pub const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);
/// Maximum gap between request-body frames from the client.
/// Production value; passed by `main.rs` into the serve loop.
pub const BODY_FRAME_GAP_TIMEOUT: Duration = Duration::from_secs(30);
/// HTTP/2 keep-alive probe interval / unacknowledged-ping grace.
const H2_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(20);
const H2_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(30);

/// Serve `router` on `listener` with client-silence reaping, resolving
/// after `shutdown` fires and every remaining connection drains. The
/// caller wraps the post-shutdown tail in its own drain-budget timeout.
/// `on_accept` runs synchronously per accepted socket (socket-option
/// tuning — the caller owns its failure/log policy). The two silence
/// bounds are parameters so tests can exercise reaping in milliseconds;
/// production callers pass [`HEADER_READ_TIMEOUT`] /
/// [`BODY_FRAME_GAP_TIMEOUT`].
#[allow(clippy::too_many_arguments)]
pub async fn serve_with_client_silence_reaping(
    listener: tokio::net::TcpListener,
    router: Router,
    on_accept: impl Fn(&tokio::net::TcpStream) + Send,
    stalled_reaps: Arc<av_core::metrics::Counter>,
    accept_failures: Arc<av_core::metrics::Counter>,
    header_read_timeout: Duration,
    body_frame_gap: Duration,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    let graceful = GracefulShutdown::new();
    let mut shutdown = std::pin::pin!(shutdown);
    loop {
        let (stream, _remote) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(pair) => pair,
                Err(error) => {
                    // Transient accept errors (EMFILE under fd pressure,
                    // ECONNABORTED) must not kill the accept loop — that
                    // would turn resource pressure into a full outage.
                    // Warn ONCE per process: under sustained EMFILE the
                    // failing accept never drains the kernel queue, so
                    // this arm loops at ~20 Hz for the whole incident —
                    // an unthrottled warn floods the log pipeline during
                    // the exact resource emergency it reports (same
                    // dampener discipline as the TCP_NODELAY warn in
                    // main.rs). The counter is the primary signal.
                    static WARNED: std::sync::Once = std::sync::Once::new();
                    WARNED.call_once(|| {
                        tracing::warn!(
                            %error,
                            "accept failed; continuing. Subsequent failures counted only \
                             via av_http_accept_failures_total to avoid a log storm"
                        );
                    });
                    accept_failures.inc();
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
            () = shutdown.as_mut() => break,
        };
        on_accept(&stream);
        let router = router.clone();
        let reaps = Arc::clone(&stalled_reaps);
        let watcher = graceful.watcher();
        tokio::spawn(async move {
            // First-byte deadline. Hyper-util's auto builder sits in
            // protocol detection (ReadVersion) BEFORE either timed HTTP
            // connection exists, so `header_read_timeout` does not
            // cover a socket that connects and sends NOTHING — the
            // classic slowloris shape held the socket and this task
            // forever, exhausting fds without ever authenticating.
            // Peek (not read — hyper must still see the bytes) for the
            // first byte under the same header deadline. Residual: a
            // client stalling MID-version-prefix (e.g. 5 bytes of the
            // h2 preface) still parks in ReadVersion — closing that
            // needs a detection deadline inside hyper-util; the
            // zero-byte hold is the cheap, scripted attack.
            let mut first_byte = [0u8; 1];
            match tokio::time::timeout(header_read_timeout, stream.peek(&mut first_byte)).await {
                Ok(Ok(n)) if n > 0 => {}
                // Timeout, clean EOF, or socket error before any byte:
                // reap. Same counter as the in-request silence reaps —
                // it is the same "client went silent" class.
                _ => {
                    reaps.inc();
                    return;
                }
            }
            let io = TokioIo::new(stream);
            let mut builder = Builder::new(TokioExecutor::new());
            builder
                .http1()
                .timer(TokioTimer::new())
                .header_read_timeout(header_read_timeout);
            builder
                .http2()
                .timer(TokioTimer::new())
                .keep_alive_interval(H2_KEEPALIVE_INTERVAL)
                .keep_alive_timeout(H2_KEEPALIVE_TIMEOUT);
            let service = service_fn(move |request: hyper::Request<Incoming>| {
                let router = router.clone();
                let reaps = Arc::clone(&reaps);
                async move {
                    let request = request.map(|body| {
                        axum::body::Body::new(SilenceBoundedBody::new(body, body_frame_gap, reaps))
                    });
                    // `oneshot` = ready + call; Router is always ready and
                    // its error is Infallible, so this cannot fail.
                    let response = router.oneshot(request).await.unwrap_or_else(|e| match e {});
                    Ok::<_, Infallible>(response)
                }
            });
            let connection = builder.serve_connection_with_upgrades(io, service);
            if let Err(error) = watcher.watch(connection.into_owned()).await {
                // Routine peer misbehavior (resets, aborted handshakes,
                // tripped silence bounds) — connection-level, not fatal.
                tracing::debug!(%error, "connection ended with error");
            }
        });
    }
    // Refuse new connects immediately; then wait for live connections.
    drop(listener);
    graceful.shutdown().await;
    Ok(())
}

/// Request-body wrapper that enforces a maximum silence gap *between
/// frames*. Progress resets the clock, so arbitrarily large uploads pass
/// as long as bytes keep arriving; a stalled sender is cut with an error
/// that hyper turns into a connection/stream reset.
struct SilenceBoundedBody {
    inner: Incoming,
    gap: Duration,
    sleep: Option<Pin<Box<tokio::time::Sleep>>>,
    reaps: Arc<av_core::metrics::Counter>,
}

impl SilenceBoundedBody {
    fn new(inner: Incoming, gap: Duration, reaps: Arc<av_core::metrics::Counter>) -> Self {
        Self {
            inner,
            gap,
            sleep: None,
            reaps,
        }
    }
}

impl Body for SilenceBoundedBody {
    type Data = hyper::body::Bytes;
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Ready(ready) => {
                // Progress (frame, end, or error): disarm the gap clock.
                self.sleep = None;
                Poll::Ready(ready.map(|result| result.map_err(Into::into)))
            }
            Poll::Pending => {
                let gap = self.gap;
                let sleep = self
                    .sleep
                    .get_or_insert_with(|| Box::pin(tokio::time::sleep(gap)));
                match sleep.as_mut().poll(cx) {
                    Poll::Ready(()) => {
                        self.reaps.inc();
                        Poll::Ready(Some(Err(
                            "request body stalled: no frame within the silence bound".into(),
                        )))
                    }
                    Poll::Pending => Poll::Pending,
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]

    use super::*;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    /// Test-scale silence bounds: long enough that a healthy request
    /// never trips them under CI scheduler jitter (the workspace's
    /// documented 25× drift budget over a 10 ms timer), short enough
    /// that reap tests finish in well under a second.
    const TEST_HEADER_TIMEOUT: Duration = Duration::from_millis(300);
    const TEST_BODY_GAP: Duration = Duration::from_millis(300);
    /// Client-side hard stop: if reaping is broken the read would hang
    /// forever (the exact bug this module fixes), so every probe read
    /// is capped at a bound that is generous against jitter but far
    /// below "held for 90 s".
    const CLIENT_READ_DEADLINE: Duration = Duration::from_secs(10);

    fn test_router() -> Router {
        Router::new().route(
            "/echo",
            axum::routing::post(|body: axum::body::Bytes| async move { format!("len={}", body.len()) }),
        )
    }

    async fn spawn_server() -> (std::net::SocketAddr, Arc<av_core::metrics::Counter>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let reaps = Arc::new(av_core::metrics::Counter::default());
        let reaps_for_server = Arc::clone(&reaps);
        tokio::spawn(async move {
            serve_with_client_silence_reaping(
                listener,
                test_router(),
                |_| {},
                reaps_for_server,
                Arc::new(av_core::metrics::Counter::default()),
                TEST_HEADER_TIMEOUT,
                TEST_BODY_GAP,
                std::future::pending(),
            )
            .await
            .unwrap();
        });
        (addr, reaps)
    }

    /// Read until the peer closes, bounded by CLIENT_READ_DEADLINE.
    async fn read_to_close(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
        let mut collected = Vec::new();
        tokio::time::timeout(CLIENT_READ_DEADLINE, async {
            let mut buffer = [0_u8; 1024];
            loop {
                match stream.read(&mut buffer).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => collected.extend_from_slice(&buffer[..n]),
                }
            }
        })
        .await
        .expect("connection was never reaped: read still open at the client deadline");
        collected
    }

    /// The exact empirical repro from the live probe: partial request
    /// line, then silence. `axum::serve` held this ≥90 s (unbounded);
    /// the reaping loop must close it at the header timeout.
    #[tokio::test]
    async fn slow_header_connection_is_reaped_at_the_header_timeout() {
        let (addr, reaps) = spawn_server().await;
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"POST /echo HTTP/1.1\r\nHost: x\r\nX-Part")
            .await
            .unwrap();
        let response = read_to_close(&mut stream).await;
        // hyper answers the header timeout with 408 then closes; the
        // essential property is the close (no unbounded hold). No
        // body-phase reap is involved.
        let text = String::from_utf8_lossy(&response);
        assert!(
            text.is_empty() || text.contains("408"),
            "unexpected response to a reaped slow-header connection: {text:?}",
        );
        assert_eq!(reaps.get(), 0, "header-phase reap must not count as a body stall");
    }

    /// A socket that connects and sends NOTHING never leaves
    /// hyper-util's protocol detection, which sits BEFORE either timed
    /// HTTP connection — `header_read_timeout` never armed and the
    /// zero-byte slowloris held the socket + task forever. The
    /// first-byte peek deadline must close it at the header timeout
    /// and count it as a silence reap.
    #[tokio::test]
    async fn zero_byte_connection_is_reaped_at_the_header_timeout() {
        let (addr, reaps) = spawn_server().await;
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        // Send nothing at all.
        let response = read_to_close(&mut stream).await;
        assert!(
            response.is_empty(),
            "a never-spoke connection must be dropped without a response, got {:?}",
            String::from_utf8_lossy(&response)
        );
        assert_eq!(
            reaps.get(),
            1,
            "the zero-byte hold counts as a client-silence reap"
        );
    }

    /// Full headers + Content-Length, a few bytes, then silence: the
    /// body-phase half of the probe. Must be cut at the frame-gap bound
    /// and counted in the reap metric.
    #[tokio::test]
    async fn stalled_request_body_is_reaped_at_the_frame_gap() {
        let (addr, reaps) = spawn_server().await;
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 100000\r\n\r\nxxxxxxxxxx")
            .await
            .unwrap();
        let response = read_to_close(&mut stream).await;
        let text = String::from_utf8_lossy(&response);
        // Axum surfaces the failed body extraction as a 4xx client
        // error rather than a hang; the connection must terminate.
        assert!(
            text.contains("HTTP/1.1 4"),
            "expected a 4xx client-error response to the stalled body, got: {text:?}",
        );
        assert_eq!(reaps.get(), 1, "stall must be counted in the reap metric");
    }

    /// A slow-but-progressing upload must NOT be reaped: the gap clock
    /// resets on every frame, so total transfer time has no bound —
    /// only per-frame silence does. Total time here (8 × 60 ms) exceeds
    /// the 300 ms gap bound, proving the clock resets.
    #[tokio::test]
    async fn progressing_slow_upload_is_never_reaped() {
        let (addr, reaps) = spawn_server().await;
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 80\r\n\r\n")
            .await
            .unwrap();
        for _ in 0_u8..8 {
            stream.write_all(&[b'y'; 10]).await.unwrap();
            stream.flush().await.unwrap();
            tokio::time::sleep(Duration::from_millis(60)).await;
        }
        let mut response = Vec::new();
        tokio::time::timeout(CLIENT_READ_DEADLINE, async {
            let mut buffer = [0_u8; 512];
            while !response.windows(6).any(|w| w == b"len=80") {
                let n = stream.read(&mut buffer).await.unwrap();
                assert!(n > 0, "server closed a progressing upload");
                response.extend_from_slice(&buffer[..n]);
            }
        })
        .await
        .expect("upload response never arrived");
        let text = String::from_utf8_lossy(&response);
        assert!(text.contains("200 OK"), "upload must succeed: {text:?}");
        assert_eq!(reaps.get(), 0, "no reap for a progressing upload");
    }

    /// Ordinary fast requests and keep-alive reuse must be unaffected:
    /// two requests on one connection, both answered, zero reaps.
    #[tokio::test]
    async fn fast_requests_and_keepalive_reuse_pass_through() {
        let (addr, reaps) = spawn_server().await;
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        for _ in 0_u8..2 {
            stream
                .write_all(b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\nok")
                .await
                .unwrap();
            let mut collected = Vec::new();
            tokio::time::timeout(CLIENT_READ_DEADLINE, async {
                let mut buffer = [0_u8; 512];
                while !collected.windows(5).any(|w| w == b"len=2") {
                    let n = stream.read(&mut buffer).await.unwrap();
                    assert!(n > 0, "server closed a healthy keep-alive connection");
                    collected.extend_from_slice(&buffer[..n]);
                }
            })
            .await
            .expect("keep-alive response never arrived");
        }
        assert_eq!(reaps.get(), 0);
    }

    /// Shutdown contract: resolving the shutdown future must make the
    /// serve future return once connections drain (here: none live).
    #[tokio::test]
    async fn shutdown_future_resolves_the_serve_loop() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let serve = tokio::spawn(serve_with_client_silence_reaping(
            listener,
            test_router(),
            |_| {},
            Arc::new(av_core::metrics::Counter::default()),
            Arc::new(av_core::metrics::Counter::default()),
            TEST_HEADER_TIMEOUT,
            TEST_BODY_GAP,
            async move {
                let _ = rx.await;
            },
        ));
        tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), serve)
            .await
            .expect("serve loop must resolve after shutdown")
            .unwrap()
            .unwrap();
    }
}
