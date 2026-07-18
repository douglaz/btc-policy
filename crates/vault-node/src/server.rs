//! The vault-node HTTP surface on axum/tokio. Every connection is its own task.
//! `/sign` and `/events` retain their coordinator-consumed JSON contract;
//! undecodable signs remain 400 errors and absent/unparseable cursors read 0.
//! Edge statuses use axum defaults: oversized body 413, wrong method 405, and
//! unknown route 404.

use std::future::poll_fn;
use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, HttpBody};
use axum::extract::State;
use axum::http::{header, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use bytes::BytesMut;
use vault_proto::TaggedRequest;
use zeroize::Zeroize;

use crate::channel::{self, ChannelReply, RejectReason};
use crate::{handle_channel_body, handle_refresh_now, handle_sign_now, propagate_outbox, Node};

/// Unchanged 1 MiB cap applied while the zeroizing accumulator reads `/sign`.
const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Base handler deadline: production adds the configured maximum PIN backoff so
/// every policy refusal can retain the HTTP-200 contract. It never cancels an
/// accepted sign job. A socket-level header-read deadline is deferred v1 hardening.
const HANDLER_TIMEOUT: Duration = Duration::from_secs(10);

/// The uniquely-owned application buffer for a raw body. It may contain a plaintext
/// PIN even when JSON decoding fails, so success and every parse/read/limit return
/// scrub it rather than relying only on [`vault_proto::Pin`]'s later drop.
struct SecretRequestBytes(BytesMut);

impl SecretRequestBytes {
    fn new() -> SecretRequestBytes {
        SecretRequestBytes(BytesMut::new())
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn extend_from_slice(&mut self, bytes: &[u8]) {
        let needed = self
            .len()
            .checked_add(bytes.len())
            .expect("bounded request length cannot overflow usize");
        if needed > self.0.capacity() {
            // `BytesMut::reserve` may free its old allocation without wiping it.
            // Grow explicitly under a second guard, copy the live prefix, wipe the
            // old allocation, then swap. Thus every application-owned allocation is
            // scrubbed even when a body arrives across many growing frames.
            let capacity = self.0.capacity().saturating_mul(2).max(needed);
            let mut replacement = SecretRequestBytes(BytesMut::with_capacity(capacity));
            replacement.0.extend_from_slice(self.0.as_ref());
            self.zeroize();
            std::mem::swap(&mut self.0, &mut replacement.0);
        }
        self.0.extend_from_slice(bytes);
    }
}

impl AsRef<[u8]> for SecretRequestBytes {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Zeroize for SecretRequestBytes {
    fn zeroize(&mut self) {
        self.0.as_mut().zeroize();
    }
}

impl Drop for SecretRequestBytes {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SecretBodyError {
    TooLarge,
    ReadFailed,
}

/// Read a body directly into uniquely-owned zeroizing storage. Reading frame by
/// frame avoids `to_bytes`/the `Bytes` extractor returning a shared transport
/// allocation, and creating the guard before the first poll ensures a partial body
/// is wiped if the read errors, exceeds its cap, or its enclosing timeout cancels
/// this future.
async fn read_secret_body(
    mut body: Body,
    max_bytes: usize,
) -> Result<SecretRequestBytes, SecretBodyError> {
    let mut secret = SecretRequestBytes::new();
    loop {
        let frame = poll_fn(|cx| std::pin::Pin::new(&mut body).poll_frame(cx)).await;
        let Some(frame) = frame else {
            return Ok(secret);
        };
        let frame = frame.map_err(|_| SecretBodyError::ReadFailed)?;
        let Ok(data) = frame.into_data() else {
            continue;
        };
        let remaining = max_bytes.saturating_sub(secret.len());
        if data.len() > remaining {
            // Retain (and therefore wipe) the accepted prefix before rejecting. In
            // particular, a PIN early in an oversized body cannot bypass the guard.
            secret.extend_from_slice(&data[..remaining]);
            return Err(SecretBodyError::TooLarge);
        }
        secret.extend_from_slice(&data);
    }
}

/// Bound the pre-auth `/channel` body read so an incomplete or slow body cannot pin
/// a concurrency permit indefinitely. The permit is acquired BEFORE the body is
/// buffered; without this deadline a peer that promises a body (Content-Length) and
/// never sends it holds its permit forever, and `max_concurrent_channel_requests`
/// such connections exhaust §8's pre-auth concurrency guard — turning the DoS
/// *guard* into a DoS *vector* (every legitimate peer 429'd with no signature
/// required). A complete envelope (≤ `max_msg_bytes`) over a healthy transport
/// arrives well within this; a body that does not is a stalled peer we shed.
const CHANNEL_BODY_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// The deadline is state so the no-cancel test can force its path.
#[derive(Clone)]
struct AppState {
    node: Arc<Node>,
    handler_timeout: Duration,
    /// Deadline for buffering a `/channel` body while its pre-auth permit is held
    /// (see [`CHANNEL_BODY_READ_TIMEOUT`]). State so a test can force the path fast.
    channel_body_timeout: Duration,
    #[cfg(test)]
    sign_entered: Option<std::sync::mpsc::Sender<()>>,
}

/// Serve the one axum app (`/sign` + `/events`) over `listener`.
pub async fn serve(listener: tokio::net::TcpListener, node: Arc<Node>) -> std::io::Result<()> {
    node.require_channel_mode()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?;
    axum::serve(listener, app(node)).await
}

/// Build the app with the production timeout.
pub(crate) fn app(node: Arc<Node>) -> Router {
    let handler_timeout = production_handler_timeout(&node);
    app_with_timeout(node, handler_timeout)
}

fn production_handler_timeout(node: &Node) -> Duration {
    let max_backoff = node
        .pin_budget_config
        .backoff_schedule
        .iter()
        .copied()
        .max()
        .unwrap_or(0);
    HANDLER_TIMEOUT.saturating_add(Duration::from_secs(max_backoff))
}

/// Build the app with an explicit timeout for the no-cancel test.
pub(crate) fn app_with_timeout(node: Arc<Node>, handler_timeout: Duration) -> Router {
    router(AppState {
        node,
        handler_timeout,
        channel_body_timeout: CHANNEL_BODY_READ_TIMEOUT,
        #[cfg(test)]
        sign_entered: None,
    })
}

/// Build the app with an explicit `/channel` body-read deadline (the permit-pinning
/// test forces the timeout path fast).
#[cfg(test)]
pub(crate) fn app_with_channel_body_timeout(
    node: Arc<Node>,
    channel_body_timeout: Duration,
) -> Router {
    router(AppState {
        node,
        handler_timeout: HANDLER_TIMEOUT,
        channel_body_timeout,
        sign_entered: None,
    })
}

fn router(state: AppState) -> Router {
    let mut router = Router::new()
        .route("/sign", post(sign))
        .route("/events", get(events));
    // `/channel` is mounted ONLY in channel mode (absent `[channel]` ⇒ the route
    // does not exist, so a request 404s and the node behaves exactly as today).
    // The handler enforces its OWN `max_msg_bytes` cap and answers a TAGGED
    // `REJECTED`/400 for an oversized body (the channel surface is uniformly tagged).
    if state.node.channel.is_some() {
        router = router.route("/channel", post(channel));
    }
    router.with_state(state)
}

#[cfg(test)]
fn app_with_sign_entry(node: Arc<Node>, sign_entered: std::sync::mpsc::Sender<()>) -> Router {
    router(AppState {
        node,
        handler_timeout: HANDLER_TIMEOUT,
        channel_body_timeout: CHANNEL_BODY_READ_TIMEOUT,
        sign_entered: Some(sign_entered),
    })
}

/// Tagged `/sign`: Spend and Refresh arms return 200 verdict JSON or 400 error
/// JSON. Synchronous policy/secp work runs off-runtime. A timed-out client stops
/// waiting, but its accepted job must finish and commit for idempotent resubmission.
async fn sign(State(state): State<AppState>, body: Body) -> Response {
    let body = match read_secret_body(body, MAX_BODY_BYTES).await {
        Ok(body) => body,
        Err(SecretBodyError::TooLarge) => {
            return error_response(StatusCode::PAYLOAD_TOO_LARGE, "request body is too large")
        }
        Err(SecretBodyError::ReadFailed) => {
            return error_response(StatusCode::BAD_REQUEST, "cannot read request body")
        }
    };
    let request: TaggedRequest = match serde_json::from_slice(body.as_ref()) {
        Ok(request) => request,
        Err(e) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                &format!("cannot decode request body: {e}"),
            );
        }
    };
    // The parsed request's Pin newtype now owns the only application copy needed
    // by the job; wipe the raw JSON before queueing any Argon2/signing work.
    //
    // ZEROIZATION SCOPE (codex V0-4a audit, 2026-07-18): every copy this code OWNS
    // is wiped — `SecretRequestBytes` zeroizes on drop (incl. its realloc path),
    // this `body` drops before any Argon2/signing, and `Pin` zeroizes on drop. Two
    // residuals live in LIBRARY-internal buffers we cannot wipe without forking the
    // deps: (a) hyper's ref-counted `Bytes` read frames in `read_secret_body`, and
    // (b) serde_json's transient scratch when a pin is `\u`-escaped. Both are
    // defense-in-depth only — reaching them needs a SEPARATE heap-disclosure
    // primitive — and the pin already necessarily transits hyper's read buffer and
    // the trusted coordinator's RAM regardless. Accepted residual; closing it would
    // require a zeroizing JSON reader + unsafe wiping of shared Bytes, disproportion-
    // ate to the risk. Tracked for a possible v1 hardening pass.
    drop(body);
    #[cfg(test)]
    if let Some(sign_entered) = &state.sign_entered {
        let _ = sign_entered.send(());
    }
    let node = Arc::clone(&state.node);
    let propagation_node = Arc::clone(&state.node);
    // `/sign` is serialized BY DESIGN by one `Mutex<SignState>` across the whole
    // call. Dropping a timed-out JoinHandle detaches rather than aborts the job,
    // preventing half-mutated ghost state. The DETACHED JOB also owns propagation:
    // if the policy work finishes after the client deadline, it drains the outbox
    // then, rather than letting the timeout path drain too early and strand the
    // request on one node. The clock is read after the sign lock.
    let job = tokio::spawn(async move {
        let outcome = tokio::task::spawn_blocking(move || match request {
            TaggedRequest::Spend(request) => handle_sign_now(&node, &request),
            TaggedRequest::Refresh(request) => handle_refresh_now(&node, &request),
        })
        .await;
        propagate_outbox(&propagation_node);
        outcome
    });
    let outcome = tokio::time::timeout(state.handler_timeout, job).await;
    match outcome {
        Ok(Ok(Ok(Ok(response)))) => match serde_json::to_string(&response) {
            Ok(json) => json_response(StatusCode::OK, json),
            Err(e) => error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("cannot encode response: {e}"),
            ),
        },
        Ok(Ok(Ok(Err(bad_request)))) => error_response(StatusCode::BAD_REQUEST, &bad_request.0),
        // The blocking task panicked (a bug, never an input): 500, not a hang.
        Ok(Ok(Err(_join_error))) | Ok(Err(_join_error)) => error_response(
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

/// `POST /channel`: one signed envelope in, one tagged JSON reply out (§5b). The
/// verify-and-store work runs on `spawn_blocking` (secp verification is CPU-bound),
/// so a saturated channel load does not starve `/events` or the watchtower tick —
/// the isolation the async migration bought. Layered DoS guards: a pre-auth global
/// concurrency bound (RATE_LIMITED when saturated) and a per-`max_msg_bytes` body
/// cap (tagged REJECTED/OVERSIZED_BODY), before any crypto.
async fn channel(State(state): State<AppState>, body: Body) -> Response {
    let Some(ch) = state.node.channel.as_ref() else {
        // Unreachable — the route is mounted only when `channel.is_some()`.
        return error_response(StatusCode::NOT_FOUND, "channel not configured");
    };
    // Pre-auth: bound concurrent `/channel` work so forged traffic cannot burn CPU
    // or a victim peer's quota unboundedly.
    let permit = match ch.concurrency().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            return channel_response(ChannelReply::RateLimited {
                retry_after_secs: 1,
            })
        }
    };
    // Pre-auth: read at most `max_msg_bytes` AND within a bounded deadline while the
    // permit is held. An oversized body is a TAGGED reject; a body that does not
    // arrive in time is shed as RATE_LIMITED so a stalled/incomplete peer cannot pin
    // the permit indefinitely (else the pre-auth concurrency guard is exhaustible).
    let bytes = match tokio::time::timeout(
        state.channel_body_timeout,
        read_secret_body(body, ch.max_msg_bytes()),
    )
    .await
    {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(_)) => {
            drop(permit);
            return channel_response(ChannelReply::Rejected(RejectReason::OversizedBody));
        }
        Err(_elapsed) => {
            drop(permit);
            return channel_response(ChannelReply::RateLimited {
                retry_after_secs: 1,
            });
        }
    };
    let node = Arc::clone(&state.node);
    let propagation_node = Arc::clone(&state.node);
    // Own both ingest and propagation in a detached job. If the uploading peer
    // disconnects after the body arrives, axum may cancel this handler, but an
    // accepted request must still fan out rather than remain stranded locally.
    let outcome = tokio::spawn(async move {
        let outcome = tokio::task::spawn_blocking(move || {
            // Hold the pre-auth permit until ingest actually finishes — move it INTO
            // the job, not just the handler future. `spawn_blocking` detaches: if the
            // connection task is cancelled while we await the JoinHandle (a peer that
            // completes a body, then disconnects), the handler future drops, but this
            // CPU-bound job keeps running. Releasing the permit with the handler future
            // would let such a peer queue more detached verification jobs than
            // `max_concurrent_channel_requests`, defeating §8's pre-auth concurrency
            // guard and exhausting the blocking pool. Tying the permit to the job caps
            // in-flight work at the bound regardless of cancellation.
            let _permit = permit;
            // `handle_channel_body`, not `channel.ingest`: a `request` envelope has to
            // pass THIS node's own coordinator-auth + policy gates, which live on the
            // node, not the channel (§3).
            handle_channel_body(&node, bytes.as_ref(), channel::unix_now())
        })
        .await;
        // A `request` this node accepted now goes to every peer (§3), so delivery to
        // one node reaches all — even if the inbound connection vanished meanwhile.
        propagate_outbox(&propagation_node);
        outcome
    })
    .await;
    match outcome {
        Ok(Ok(reply)) => channel_response(reply),
        // Either detached layer panicked (a bug, never an input): 500, not a hang.
        Ok(Err(_join_error)) | Err(_join_error) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "channel task failed unexpectedly",
        ),
    }
}

/// Render a [`ChannelReply`] as its fixed `(status, JSON body)` (§5b).
fn channel_response(reply: ChannelReply) -> Response {
    let (code, body) = reply.http();
    let status = StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    json_response(status, body)
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
    use crate::chain::{ChainBackend, PackageVerdict, Prevout, SpendSeen};
    use crate::test_support::{node_and_valid_request, valid_refresh_request};
    use crate::watchtower::{self, Alert, AlertKind};
    use crate::Error;
    use bitcoin::{OutPoint, ScriptBuf, Txid};
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpStream};
    use std::time::Instant;
    use tokio::task::spawn_blocking;
    use vault_proto::{SignRequest, SignResponse, TaggedRequest};

    #[test]
    fn raw_request_buffers_are_wiped() {
        let mut body = SecretRequestBytes::new();
        body.extend_from_slice(br#"{"spend":{"pin":"buffer-secret"}}"#);
        body.zeroize();
        assert!(
            body.as_ref().iter().all(|byte| *byte == 0),
            "the owned HTTP request allocation must be overwritten, not merely dropped"
        );
    }

    #[test]
    fn production_timeout_includes_the_largest_pin_backoff() {
        let (node, _) = crate::test_support::node_and_valid_request_with_budget(
            "[pin_attempt_budget]\nbackoff_schedule = [0, 1, 30]\n",
        );
        assert_eq!(
            production_handler_timeout(&node),
            Duration::from_secs(40),
            "a documented 30s terminal backoff must still reach its HTTP-200 refusal"
        );
    }

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

    fn spend_body(request: &SignRequest) -> String {
        serde_json::to_string(&TaggedRequest::Spend(request.clone())).expect("encode spend arm")
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
        // This backend exists to stall the watchtower scan; the fire path is not
        // under test here, so its three methods are unreachable stubs.
        fn prevout(&self, _outpoint: &OutPoint) -> Result<Option<Prevout>, Error> {
            Err("SlowBackend has no chain view".into())
        }
        fn mempool_transaction(&self, _txid: &Txid) -> Result<Option<Vec<u8>>, Error> {
            Err("SlowBackend has no chain view".into())
        }
        fn transaction_confirmed(&self, _txid: &Txid) -> Result<bool, Error> {
            Err("SlowBackend has no chain view".into())
        }
        fn test_package_accept(&self, _raw_txs: &[Vec<u8>]) -> Result<PackageVerdict, Error> {
            Err("SlowBackend has no chain view".into())
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn post_sign_valid_body_returns_200_and_signed_json() {
        let (node, request) = node_and_valid_request();
        let addr = spawn_app(app(Arc::new(node))).await;
        let body = spend_body(&request);
        let (status, resp) = spawn_blocking(move || post(addr, "/sign", &body))
            .await
            .expect("client task");
        assert_eq!(status, 200);
        let parsed: SignResponse = serde_json::from_str(&resp).expect("decode response");
        assert!(
            matches!(parsed, SignResponse::Accepted(_)),
            "got {parsed:?}"
        );
    }

    /// The Refresh arm crosses the same auth + freshness ingress as Spend and is
    /// served on its own terms (pin-less, instant, bounded — ADR-0013 §2/§6).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn post_sign_serves_the_refresh_arm_over_the_same_ingress() {
        let (node, spend) = node_and_valid_request();
        let refresh = valid_refresh_request(&node, &spend, "refresh-over-http");
        let addr = spawn_app(app(Arc::new(node))).await;
        let body = serde_json::to_string(&TaggedRequest::Refresh(refresh.clone()))
            .expect("encode refresh arm");

        let (status, response) = spawn_blocking(move || post(addr, "/sign", &body))
            .await
            .expect("refresh client");
        assert_eq!(status, 200, "a policy outcome is a 200: {response}");
        let accepted: SignResponse = serde_json::from_str(&response).expect("accepted json");
        assert!(
            matches!(accepted, SignResponse::Accepted(_)),
            "got {accepted:?}"
        );

        // The authentic request consumed its nonce before answering, proving the
        // HTTP arm did not bypass the freshness gate.
        let replay_body = serde_json::to_string(&TaggedRequest::Refresh(refresh))
            .expect("encode replayed refresh arm");
        let (status, response) = spawn_blocking(move || post(addr, "/sign", &replay_body))
            .await
            .expect("refresh replay client");
        assert_eq!(status, 200);
        let refusal: SignResponse = serde_json::from_str(&response).expect("replay refusal json");
        assert!(matches!(
            refusal,
            SignResponse::Refusal(refusal)
                if refusal.code == vault_proto::RefusalCode::NonceReplayed
        ));
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
    async fn two_concurrent_signs_of_one_commitment_stay_consistent() {
        let (node, request) = node_and_valid_request();
        let node = Arc::new(node);
        let addr = spawn_app(app(node.clone())).await;

        // The SAME commitment sent twice concurrently, as a coordinator racing its
        // own retry does it: identical spend, but a fresh single-use nonce (and so
        // a fresh coord_sig) per transmission — a re-sent nonce is a replay by
        // definition (ADR-0013 §2) and would be refused at ingress instead of
        // exercising the anti-replay log this test is about.
        let mut second = request.clone();
        crate::test_support::coord_sign(&mut second, "concurrent-retry");
        let b1 = spend_body(&request);
        let b2 = spend_body(&second);
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
            SignResponse::Accepted(_)
        ));
        // Exactly one verdict and exactly one pending spend: the two concurrent
        // sends of the same commitment did not interleave into a double-accept.
        // (A hot-class spend is recorded pending until its commitment expires,
        // even at `hold_secs = 0` — it is outstanding until it broadcasts, and
        // that is what refresh subordination reads.)
        let state = node.sign_state.lock().expect("sign_state lock");
        assert_eq!(state.replay.len(), 1);
        assert_eq!(state.pending.len(), 1);
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

        let body = spend_body(&request);
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
            Arc::clone(&node.authorized),
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
        let body = spend_body(&request);
        // The resubmit is the real coordinator retry: the same commitment under a
        // fresh single-use nonce + coord_sig (ADR-0013 §2). Idempotency is keyed on
        // the commitment, not the transmission, so this still returns the ONE
        // recorded verdict rather than signing twice.
        let mut retry = request.clone();
        crate::test_support::coord_sign(&mut retry, "resubmit-after-408");
        let retry_body = spend_body(&retry);

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
        let (status, resp) = spawn_blocking(move || post(normal, "/sign", &retry_body))
            .await
            .expect("resubmit client");
        assert_eq!(status, 200);
        assert!(matches!(
            serde_json::from_str::<SignResponse>(&resp).expect("decode"),
            SignResponse::Accepted(_)
        ));

        // Exactly one log mutation: no ghost, no lost or duplicated acceptance.
        let state = node.sign_state.lock().expect("sign_state lock");
        assert_eq!(state.replay.len(), 1);
        assert_eq!(state.pending.len(), 1);
    }
}
