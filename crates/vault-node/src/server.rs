//! The vault-node HTTP surface on axum/tokio. Every connection is its own task.
//! `/sign` and `/events` retain their coordinator-consumed JSON contract;
//! undecodable signs remain 400 errors and absent/unparseable cursors read 0.
//! Edge statuses use axum defaults: oversized body 413, wrong method 405, and
//! unknown route 404.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{header, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use vault_proto::SignRequest;

use crate::{handle_sign_now, Node};

/// Unchanged 1 MiB cap applied before axum buffers a request body.
const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Handler deadline only: it never cancels an accepted sign job. A socket-level
/// header-read deadline is deferred v1 hardening.
const HANDLER_TIMEOUT: Duration = Duration::from_secs(10);

/// The deadline is state so the no-cancel test can force its path.
#[derive(Clone)]
struct AppState {
    node: Arc<Node>,
    handler_timeout: Duration,
    #[cfg(test)]
    sign_entered: Option<std::sync::mpsc::Sender<()>>,
}

/// Serve the one axum app (`/sign` + `/events`) over `listener`.
pub async fn serve(listener: tokio::net::TcpListener, node: Arc<Node>) -> std::io::Result<()> {
    axum::serve(listener, app(node)).await
}

/// Build the app with the production timeout.
pub(crate) fn app(node: Arc<Node>) -> Router {
    app_with_timeout(node, HANDLER_TIMEOUT)
}

/// Build the app with an explicit timeout for the no-cancel test.
pub(crate) fn app_with_timeout(node: Arc<Node>, handler_timeout: Duration) -> Router {
    router(AppState {
        node,
        handler_timeout,
        #[cfg(test)]
        sign_entered: None,
    })
}

fn router(state: AppState) -> Router {
    Router::new()
        .route("/sign", post(sign))
        .route("/events", get(events))
        // The body limit applies to every route (only `/sign` carries a body,
        // but a global limit is the safe default).
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

#[cfg(test)]
fn app_with_sign_entry(node: Arc<Node>, sign_entered: std::sync::mpsc::Sender<()>) -> Router {
    router(AppState {
        node,
        handler_timeout: HANDLER_TIMEOUT,
        sign_entered: Some(sign_entered),
    })
}

/// Byte-compatible `/sign`: 200 verdict JSON or 400 error JSON. Synchronous
/// policy/secp work runs off-runtime. A timed-out client stops waiting, but its
/// accepted job must finish and commit for idempotent resubmission.
async fn sign(State(state): State<AppState>, body: Bytes) -> Response {
    let request: SignRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(e) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                &format!("cannot decode request body: {e}"),
            );
        }
    };
    #[cfg(test)]
    if let Some(sign_entered) = &state.sign_entered {
        let _ = sign_entered.send(());
    }
    let node = state.node;
    // `/sign` is serialized BY DESIGN by one `Mutex<SignState>` across the whole
    // call. Dropping a timed-out JoinHandle detaches rather than aborts the job,
    // preventing half-mutated ghost state. The clock is read after that lock.
    let job = tokio::task::spawn_blocking(move || handle_sign_now(&node, &request));
    match tokio::time::timeout(state.handler_timeout, job).await {
        Ok(Ok(Ok(response))) => match serde_json::to_string(&response) {
            Ok(json) => json_response(StatusCode::OK, json),
            Err(e) => error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("cannot encode response: {e}"),
            ),
        },
        Ok(Ok(Err(bad_request))) => error_response(StatusCode::BAD_REQUEST, &bad_request.0),
        // The blocking task panicked (a bug, never an input): 500, not a hang.
        Ok(Err(_join_error)) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "sign task failed unexpectedly",
        ),
        // Handler timeout: stop waiting and answer, but the detached job keeps
        // running and commits its verdict for an idempotent resubmit.
        Err(_elapsed) => error_response(StatusCode::REQUEST_TIMEOUT, "sign timed out"),
    }
}

/// Pull alerts after `since`. This reads only the independent alert lock, so it
/// never waits behind `/sign`.
async fn events(State(state): State<AppState>, uri: Uri) -> Response {
    let since = parse_since(uri.query());
    let (alerts, cursor) = state.node.events(since);
    match serde_json::to_string(&serde_json::json!({ "alerts": alerts, "cursor": cursor })) {
        Ok(json) => json_response(StatusCode::OK, json),
        Err(e) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("cannot encode events: {e}"),
        ),
    }
}

/// Absent/unparseable cursors read 0; only `since=<n>` is recognized.
fn parse_since(query: Option<&str>) -> u64 {
    query
        .and_then(|q| q.strip_prefix("since="))
        .and_then(|value| value.parse().ok())
        .unwrap_or(0)
}

/// Return pre-serialized JSON with the old content type.
fn json_response(status: StatusCode, body: String) -> Response {
    (status, [(header::CONTENT_TYPE, "application/json")], body).into_response()
}

/// A `{"error": detail}` JSON body at `status`.
fn error_response(status: StatusCode, detail: &str) -> Response {
    json_response(status, serde_json::json!({ "error": detail }).to_string())
}

#[cfg(test)]
mod parse_since_tests {
    use super::parse_since;

    #[test]
    fn parse_since_reads_the_cursor_or_defaults_to_zero() {
        assert_eq!(parse_since(Some("since=42")), 42);
        // No query, empty value, or a non-numeric cursor all read as 0.
        assert_eq!(parse_since(None), 0);
        assert_eq!(parse_since(Some("since=")), 0);
        assert_eq!(parse_since(Some("since=abc")), 0);
        // An unrelated query (no `since`) reads as 0, like the old path parser.
        assert_eq!(parse_since(Some("foo=bar")), 0);
    }
}

/// HTTP regressions over real loopback sockets.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{ChainBackend, SpendSeen};
    use crate::test_support::node_and_valid_request;
    use crate::watchtower::{self, Alert, AlertKind};
    use crate::Error;
    use bitcoin::{ScriptBuf, Txid};
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpStream};
    use std::time::Instant;
    use tokio::task::spawn_blocking;
    use vault_proto::SignResponse;

    /// Send a `Connection: close` request and read its full response. Oversized
    /// requests tolerate axum closing before the client finishes writing.
    fn send(addr: SocketAddr, head: &str, body: &[u8], tolerate_write_err: bool) -> (u16, String) {
        let mut stream = TcpStream::connect(addr).expect("connect");
        let write = stream
            .write_all(head.as_bytes())
            .and_then(|()| stream.write_all(body));
        if !tolerate_write_err {
            write.expect("write request");
        }
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).expect("read response");
        parse_response(&raw)
    }

    fn parse_response(raw: &[u8]) -> (u16, String) {
        let split = raw
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("response has a header terminator");
        let head = String::from_utf8_lossy(&raw[..split]);
        let status = head
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .expect("status code");
        (
            status,
            String::from_utf8_lossy(&raw[split + 4..]).into_owned(),
        )
    }

    fn get(addr: SocketAddr, path: &str) -> (u16, String) {
        let head = format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
        send(addr, &head, b"", false)
    }

    /// A socket-bounded GET that works even if Tokio is blocked.
    fn get_with_timeout(
        addr: SocketAddr,
        path: &str,
        timeout: Duration,
    ) -> std::io::Result<(u16, String)> {
        let mut stream = TcpStream::connect(addr)?;
        stream.set_read_timeout(Some(timeout))?;
        write!(
            stream,
            "GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
        )?;
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw)?;
        Ok(parse_response(&raw))
    }

    fn post_head(path: &str, len: usize) -> String {
        format!(
            "POST {path} HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n\
             Content-Length: {len}\r\nConnection: close\r\n\r\n"
        )
    }

    fn post(addr: SocketAddr, path: &str, body: &str) -> (u16, String) {
        send(addr, &post_head(path, body.len()), body.as_bytes(), false)
    }

    fn post_bytes(addr: SocketAddr, path: &str, body: &[u8]) -> (u16, String) {
        send(addr, &post_head(path, body.len()), body, true)
    }

    /// Serve `app` on an ephemeral loopback port.
    async fn spawn_app(app: Router) -> SocketAddr {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind ephemeral port");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });
        addr
    }

    fn alert(n: u8) -> Alert {
        Alert {
            kind: AlertKind::UnrecognizedSpend,
            spend_txid: format!("{n:064x}"),
            outpoint: format!("{n:064x}:0"),
            script: "0014deadbeef".into(),
        }
    }

    /// Slow bitcoind stand-in. `entered` fires before the first RPC sleeps so the
    /// isolation probe cannot race ahead of the tick.
    struct SlowBackend {
        delay: Duration,
        entered: std::sync::Mutex<Option<std::sync::mpsc::Sender<()>>>,
    }

    impl SlowBackend {
        /// Signal entry once, before sleeping.
        fn signal_entered(&self) {
            if let Some(tx) = self.entered.lock().expect("entered lock").take() {
                let _ = tx.send(());
            }
        }
    }

    impl ChainBackend for SlowBackend {
        fn broadcast(&self, _raw_tx: &[u8]) -> Result<Txid, Error> {
            Err("SlowBackend does not broadcast".into())
        }
        fn tip_height(&self) -> Result<u32, Error> {
            self.signal_entered();
            std::thread::sleep(self.delay);
            Ok(0)
        }
        fn spends_of(
            &self,
            _scripts: &[ScriptBuf],
            _from_height: u32,
        ) -> Result<Vec<SpendSeen>, Error> {
            self.signal_entered();
            std::thread::sleep(self.delay);
            Ok(Vec::new())
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn post_sign_valid_body_returns_200_and_signed_json() {
        let (node, request) = node_and_valid_request();
        let addr = spawn_app(app(Arc::new(node))).await;
        let body = serde_json::to_string(&request).expect("encode request");
        let (status, resp) = spawn_blocking(move || post(addr, "/sign", &body))
            .await
            .expect("client task");
        assert_eq!(status, 200);
        let parsed: SignResponse = serde_json::from_str(&resp).expect("decode response");
        assert!(matches!(parsed, SignResponse::Signed(_)), "got {parsed:?}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn post_sign_garbage_returns_400_error_json() {
        let (node, _request) = node_and_valid_request();
        let addr = spawn_app(app(Arc::new(node))).await;
        let (status, resp) = spawn_blocking(move || post(addr, "/sign", "definitely not json"))
            .await
            .expect("client task");
        assert_eq!(status, 400);
        let body: serde_json::Value = serde_json::from_str(&resp).expect("error json");
        assert!(
            body["error"].is_string(),
            "a 400 must carry {{\"error\": ...}}, got {resp}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_oversized_body_is_rejected_and_the_status_is_locked() {
        let (node, _request) = node_and_valid_request();
        let addr = spawn_app(app(Arc::new(node))).await;
        // Lock axum's standard oversized-body status.
        let (status, _resp) =
            spawn_blocking(move || post_bytes(addr, "/sign", &vec![b'x'; MAX_BODY_BYTES + 1]))
                .await
                .expect("client task");
        assert_eq!(
            status, 413,
            "an oversized body must be 413 Payload Too Large"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn events_applies_the_since_cursor_over_the_socket() {
        let (node, _request) = node_and_valid_request();
        let node = Arc::new(node);
        {
            let mut queue = node.alerts.lock().expect("alerts lock");
            assert!(queue.push(alert(1)));
            assert!(queue.push(alert(2)));
        }
        let addr = spawn_app(app(node.clone())).await;

        let (status, body) = spawn_blocking(move || get(addr, "/events"))
            .await
            .expect("client task");
        assert_eq!(status, 200);
        let all: serde_json::Value = serde_json::from_str(&body).expect("events json");
        assert_eq!(all["alerts"].as_array().expect("alerts array").len(), 2);
        assert_eq!(all["cursor"], 2);

        let (_status, body) = spawn_blocking(move || get(addr, "/events?since=1"))
            .await
            .expect("client task");
        let newer: serde_json::Value = serde_json::from_str(&body).expect("events json");
        assert_eq!(newer["alerts"].as_array().expect("alerts array").len(), 1);
        assert_eq!(newer["cursor"], 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_unknown_route_returns_404() {
        let (node, _request) = node_and_valid_request();
        let addr = spawn_app(app(Arc::new(node))).await;
        let (status, _) = spawn_blocking(move || get(addr, "/nope"))
            .await
            .expect("client task");
        assert_eq!(status, 404);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_wrong_method_on_sign_returns_405() {
        let (node, _request) = node_and_valid_request();
        let addr = spawn_app(app(Arc::new(node))).await;
        let (status, _) = spawn_blocking(move || get(addr, "/sign"))
            .await
            .expect("client task");
        assert_eq!(status, 405);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_identical_concurrent_signs_stay_consistent() {
        let (node, request) = node_and_valid_request();
        let node = Arc::new(node);
        let addr = spawn_app(app(node.clone())).await;
        let body = serde_json::to_string(&request).expect("encode request");

        let (b1, b2) = (body.clone(), body);
        let one = spawn_blocking(move || post(addr, "/sign", &b1));
        let two = spawn_blocking(move || post(addr, "/sign", &b2));
        let (status1, resp1) = one.await.expect("client one");
        let (status2, resp2) = two.await.expect("client two");

        assert_eq!(status1, 200);
        assert_eq!(status2, 200);
        // One fresh acceptance and one replay produce the identical verdict.
        assert_eq!(resp1, resp2);
        assert!(matches!(
            serde_json::from_str::<SignResponse>(&resp1).expect("decode"),
            SignResponse::Signed(_)
        ));
        // Exactly one verdict: no interleaved double-accept or stray Hold.
        let state = node.sign_state.lock().expect("sign_state lock");
        assert_eq!(state.replay.len(), 1);
        assert_eq!(state.pending.len(), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn a_blocking_sign_does_not_delay_events() {
        // A single worker exposes inline-sign regressions. Hold sign-state so a
        // real `/sign` blocks while `/events` uses its independent alert lock.
        let (node, request) = node_and_valid_request();
        let node = Arc::new(node);
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let addr = spawn_app(app_with_sign_entry(node.clone(), entered_tx)).await;

        let gate = node.clone();
        let (held_tx, held_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let holder = std::thread::spawn(move || {
            let _guard = gate.sign_state.lock().expect("sign_state lock");
            held_tx.send(()).expect("signal held");
            release_rx.recv().expect("await release");
        });
        held_rx.recv().expect("lock held");

        let body = serde_json::to_string(&request).expect("encode request");
        let inflight = spawn_blocking(move || post(addr, "/sign", &body));
        // An OS thread waits for explicit handler entry, then times /events with
        // a socket deadline. It releases sign-state on every outcome, so an
        // inline-sign regression blocks neither the Tokio timeout machinery nor
        // the test forever.
        let probe = std::thread::spawn(move || {
            let result = (|| {
                entered_rx
                    .recv_timeout(Duration::from_secs(2))
                    .map_err(|e| format!("/sign never entered its handler: {e}"))?;
                get_with_timeout(addr, "/events", Duration::from_secs(2))
                    .map_err(|e| format!("/events blocked behind /sign: {e}"))
            })();
            let _ = release_tx.send(());
            result
        });
        let (status, _) = spawn_blocking(move || probe.join().expect("probe thread"))
            .await
            .expect("probe task")
            .expect("/events isolation");
        assert_eq!(status, 200);

        holder.join().expect("holder thread");
        let _ = tokio::time::timeout(Duration::from_secs(2), inflight)
            .await
            .expect("/sign did not finish after release")
            .expect("inflight sign task");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn a_slow_watchtower_tick_does_not_delay_events() {
        // A single worker exposes an inline slow-RPC regression; `/events` must
        // answer while the tick is inside its backend call.
        let (node, _request) = node_and_valid_request();
        let node = Arc::new(node);
        let addr = spawn_app(app(node.clone())).await;

        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let backend: Arc<dyn ChainBackend + Send + Sync> = Arc::new(SlowBackend {
            delay: Duration::from_secs(3),
            entered: std::sync::Mutex::new(Some(entered_tx)),
        });
        watchtower::spawn_driver(
            backend,
            node.vault_scripts(),
            Arc::clone(&node.sign_log),
            Arc::clone(&node.alerts),
        );
        // Keep entry wait and GET outside Tokio so an inline scan fails bounded.
        let probe = std::thread::spawn(move || {
            entered_rx
                .recv_timeout(Duration::from_secs(2))
                .map_err(|e| format!("slow tick never entered its RPC: {e}"))?;
            let started = Instant::now();
            let response = get_with_timeout(addr, "/events", Duration::from_secs(1))
                .map_err(|e| format!("/events blocked behind watchtower tick: {e}"))?;
            Ok::<_, String>((response, started.elapsed()))
        });
        let ((status, _), elapsed) = spawn_blocking(move || probe.join().expect("probe thread"))
            .await
            .expect("probe task")
            .expect("/events isolation");
        assert_eq!(status, 200);
        assert!(
            elapsed < Duration::from_secs(1),
            "/events was blocked behind a slow watchtower tick"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_stalled_client_does_not_block_a_fresh_request() {
        // An incomplete request must park only its own connection task.
        let (node, _request) = node_and_valid_request();
        let addr = spawn_app(app(Arc::new(node))).await;

        let stalled = spawn_blocking(move || {
            let mut stream = TcpStream::connect(addr).expect("connect");
            stream
                .write_all(b"GET /events HTTP/1.1\r\nHost: x\r\n")
                .expect("write partial headers");
            stream
        })
        .await
        .expect("stall task");

        let fresh = spawn_blocking(move || get(addr, "/events"));
        let result = tokio::time::timeout(Duration::from_secs(2), fresh).await;
        // Release the stalled connection before inspecting the result so even a
        // sequential-server regression can unwind instead of hanging the test.
        drop(stalled);
        let (status, _) = result
            .expect("a stalled client wedged the server")
            .expect("events client");
        assert_eq!(status, 200);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_timed_out_sign_still_commits_and_resubmit_is_idempotent() {
        let (node, request) = node_and_valid_request();
        let node = Arc::new(node);
        // Force timeout, then resubmit through the same node with a real deadline.
        let fast = spawn_app(app_with_timeout(node.clone(), Duration::ZERO)).await;
        let normal = spawn_app(app_with_timeout(node.clone(), Duration::from_secs(30))).await;
        let body = serde_json::to_string(&request).expect("encode request");

        // Blocking inside handle_sign makes the 408 deterministic.
        let gate = node.clone();
        let (held_tx, held_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let holder = std::thread::spawn(move || {
            let _guard = gate.sign_state.lock().expect("sign_state lock");
            held_tx.send(()).expect("signal held");
            release_rx.recv().expect("await release");
        });
        held_rx.recv().expect("lock held");

        // The client gets 408; its detached job remains blocked, not cancelled.
        let first_body = body.clone();
        let (status, _) = spawn_blocking(move || post(fast, "/sign", &first_body))
            .await
            .expect("first client");
        assert_eq!(status, 408, "a handler timeout must answer 408, never hang");

        // Wait for the detached job's commit before resubmitting; otherwise the
        // resubmit could win the lock and hide cancellation of the first job.
        release_tx.send(()).expect("release");
        holder.join().expect("holder thread");
        let mut committed = false;
        for _ in 0..250 {
            if node
                .sign_state
                .lock()
                .expect("sign_state lock")
                .replay
                .len()
                == 1
            {
                committed = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            committed,
            "the timed-out /sign job never committed its verdict"
        );

        // The resubmit returns the recorded Signed verdict.
        let (status, resp) = spawn_blocking(move || post(normal, "/sign", &body))
            .await
            .expect("resubmit client");
        assert_eq!(status, 200);
        assert!(matches!(
            serde_json::from_str::<SignResponse>(&resp).expect("decode"),
            SignResponse::Signed(_)
        ));

        // Exactly one log mutation: no ghost, lost sign, or pending timer.
        let state = node.sign_state.lock().expect("sign_state lock");
        assert_eq!(state.replay.len(), 1);
        assert_eq!(state.pending.len(), 0);
    }
}
