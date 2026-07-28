//! The vault-node HTTP surface on axum/tokio. Every connection is its own task.
//! `/sign` and `/events` retain their coordinator-consumed JSON contract;
//! undecodable signs remain 400 errors and absent/unparseable cursors read 0.
//! `/healthz` is the read-only operations liveness surface ([`crate::Health`]) and
//! `/pending` the read-only accepted-but-unsettled spend projection
//! ([`crate::PendingProjection`]).
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
use tokio::sync::Semaphore;
use vault_proto::TaggedRequest;
use zeroize::Zeroize;

use crate::channel::{ChannelReply, RejectReason};
use crate::{handle_channel_body_now, handle_refresh_now, handle_sign_now, propagate_outbox, Node};

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
/// `/pending` performs one short `sign_state` snapshot, but an unbounded number of
/// concurrent snapshots could all occupy Tokio blocking-pool workers while `/sign`
/// holds that lock for its memory-hard PIN work. One in-flight read is sufficient for
/// this polling surface and bounds that contention without adding a timeout that would
/// detach the still-blocked job and admit another one.
const PENDING_MAX_CONCURRENCY: usize = 1;

/// The deadline is state so the no-cancel test can force its path.
#[derive(Clone)]
struct AppState {
    node: Arc<Node>,
    handler_timeout: Duration,
    /// Deadline for buffering a `/channel` body while its pre-auth permit is held
    /// (see [`CHANNEL_BODY_READ_TIMEOUT`]). State so a test can force the path fast.
    channel_body_timeout: Duration,
    pending_concurrency: Arc<Semaphore>,
    #[cfg(test)]
    sign_entered: Option<std::sync::mpsc::Sender<()>>,
    #[cfg(test)]
    pending_entered: Option<std::sync::mpsc::Sender<()>>,
}

/// Re-check for a poisoned critical lock on a handler's outer `JoinError` arm and, if
/// poisoned, force the poison-independent terminal Lockdown. Covers a panic in the OUTER
/// job body (e.g. `propagate_outbox`) that poisoned a lock AFTER the in-job net
/// ([`blocking_with_lockdown_net`]) already returned. Idempotent and poison-independent,
/// gated on ACTUAL poison, so a benign panic that held no critical lock leaves the node
/// untouched (a plain 500).
fn outer_job_lockdown_recheck(node: &Node) {
    if node.critical_lock_poisoned() {
        node.force_lockdown_fail_closed();
    }
}

/// Run one blocking request job and force terminal Lockdown if it unwinds through a
/// crown-jewel lock. The caller may be detached by an HTTP timeout/disconnect, so the
/// poison check belongs here, inside the owned job, rather than only in the handler's
/// `JoinError` arm.
async fn blocking_with_lockdown_net<T>(
    node: Arc<Node>,
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, tokio::task::JoinError>
where
    T: Send + 'static,
{
    let outcome = tokio::task::spawn_blocking(work).await;
    if node.critical_lock_poisoned() {
        node.force_lockdown_fail_closed();
    }
    outcome
}

/// Serve the one axum app (`/sign` + `/events` + `/healthz` + `/pending`) over
/// `listener`.
///
/// `listener` is already bound, so this is the last production startup boundary
/// before any request can arm or register a candidate. Claim the config inode's
/// one-shot process generation here rather than relying on a particular binary
/// caller to remember it: every embedding that uses the public serving API then
/// preserves ADR-0012 reboot-death, and path-less test construction cannot be
/// exposed accidentally as a restartable signer.
pub async fn serve(listener: tokio::net::TcpListener, node: Arc<Node>) -> std::io::Result<()> {
    node.require_channel_mode()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?;
    node.claim_process_generation()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::PermissionDenied, e.to_string()))?;
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
        pending_concurrency: Arc::new(Semaphore::new(PENDING_MAX_CONCURRENCY)),
        #[cfg(test)]
        sign_entered: None,
        #[cfg(test)]
        pending_entered: None,
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
        pending_concurrency: Arc::new(Semaphore::new(PENDING_MAX_CONCURRENCY)),
        sign_entered: None,
        pending_entered: None,
    })
}

fn router(state: AppState) -> Router {
    let mut router = Router::new()
        .route("/sign", post(sign))
        .route("/events", get(events))
        // Mounted unconditionally, unlike `/channel`: nothing `/healthz` reports
        // depends on channel configuration, so the route stays out of that branch.
        // Not a claim that a channel-less daemon is an observable state — `Node::load`
        // and `serve` both reject one (`require_channel_mode`, line 182 above), so
        // every node that ever answers this route is a channel-mode node.
        .route("/healthz", get(healthz))
        // Unconditional for the same reason `/healthz` is: what it projects lives in
        // `SignState`, which every node has in both channel and absent-channel mode.
        .route("/pending", get(pending));
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
        pending_concurrency: Arc::new(Semaphore::new(PENDING_MAX_CONCURRENCY)),
        sign_entered: Some(sign_entered),
        pending_entered: None,
    })
}

#[cfg(test)]
fn app_with_pending_entry(node: Arc<Node>, pending_entered: std::sync::mpsc::Sender<()>) -> Router {
    router(AppState {
        node,
        handler_timeout: HANDLER_TIMEOUT,
        channel_body_timeout: CHANNEL_BODY_READ_TIMEOUT,
        pending_concurrency: Arc::new(Semaphore::new(PENDING_MAX_CONCURRENCY)),
        sign_entered: None,
        pending_entered: Some(pending_entered),
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
    // `/sign` uses one `Mutex<SignState>` for an atomic ingress phase and an atomic
    // replay/pending phase, with only the slow chain preflight between them. Dropping
    // a timed-out JoinHandle detaches rather than aborts the job, preventing
    // half-mutated ghost state. The DETACHED JOB also owns propagation:
    // if the policy work finishes after the client deadline, it drains the outbox
    // then, rather than letting the timeout path drain too early and strand the
    // request on one node. The clock is read after the sign lock.
    let job = tokio::spawn(async move {
        let outcome =
            blocking_with_lockdown_net(Arc::clone(&propagation_node), move || match request {
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
        // The job completed (no handler timeout) but reported a captured panic: 500, not
        // a hang. The in-job §2b net above already forces fail-closed Lockdown when the
        // BLOCKING sign work poisoned a critical lock; re-check here to also cover a panic
        // in the outer job body (e.g. `propagate_outbox`) on this awaited path. Idempotent
        // and poison-independent, gated on ACTUAL poison, so a benign panic that held no
        // lock stays a plain 500.
        Ok(Ok(Err(_join_error))) | Ok(Err(_join_error)) => {
            outer_job_lockdown_recheck(&state.node);
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "sign task failed unexpectedly",
            )
        }
        // Handler timeout: stop waiting and answer, but the detached job keeps running
        // and commits its verdict for an idempotent resubmit. A panic past the deadline
        // is no longer observed here, so this arm cannot be its fail-closed net. Coverage
        // is elsewhere: a panic in the BLOCKING work is latched by that job's OWN in-job
        // §2b net (above); a panic in the outer body (e.g. `propagate_outbox`) that
        // poisons a critical lock is latched by the 1 Hz fire/lockdown driver nets on the
        // next tick — which is exactly why poison recovery cannot live only on this handler.
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

/// `GET /healthz`: the node's non-secret liveness projection ([`crate::Health`]), so
/// an operator can tell a dead, store-wedged, poison-bricked, or locked-down node
/// from a healthy one without probing it with a spend (bead btc-policy-9y5.6). What
/// it deliberately does NOT cover — a backend-blocked release/combine or watchtower
/// pass — is [`Node::last_deadline_tick`]'s contract, and why.
///
/// Read-only and lock-free: [`Node::health`] reads three atomics, takes neither
/// `sign_state` nor the channel store, and mutates nothing. Both halves matter. It
/// answers promptly while a `/sign` or a fire pass holds those locks — the
/// contention an operator probing a stuck node is trying to see through, pinned by
/// `healthz_answers_while_sign_state_is_held` and
/// `healthz_answers_while_the_channel_store_is_held` — and it adds no handler-side
/// lock wait on a surface the hostile-at-wrench coordinator can poll at will. The
/// heartbeat producer itself can be delayed before a later iteration by shared-store
/// contention; that narrower scheduler residual is stated in
/// [`Node::last_deadline_tick`]. The response body's pin-uniformity is
/// [`crate::Health`]'s contract, not this handler's.
///
/// Residual, named rather than implied: what is claimed is that no branch, lock, or
/// byte of this path depends on arm state — not that a response's wall-clock latency
/// is independent of everything the HOST is doing. The release/combine pass does
/// arm-dependent work, so it contributes arm-dependent CPU load, and on a one- or
/// two-vCPU host that load is in principle schedulable-visible in the latency of any
/// observation of the machine — this handler, `/events`, or the TCP accept itself.
/// That channel is a property of co-residency, is not created or widened here, and
/// has no threat-derived bound to test against the way `/sign` has one Argon2
/// evaluation, so it is a documented co-residency residual (DESIGN.md), not a tested
/// `/healthz` property.
async fn healthz(State(state): State<AppState>) -> Response {
    match serde_json::to_string(&state.node.health()) {
        Ok(json) => json_response(StatusCode::OK, json),
        Err(e) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("cannot encode health: {e}"),
        ),
    }
}

/// `GET /pending`: the node's read-only projection of the spends it has ACCEPTED and
/// not yet seen settle ([`crate::PendingProjection`]) — the Hold-window surface that
/// makes a coordinator-auth-key theft visible WITHOUT relying on the coordinator relay
/// (bead btc-policy-k0t). That type's doc carries the argument for why it is not a
/// duress oracle, and the full list of what it deliberately does not report.
///
/// A PROJECTION, NOT A CONTROL PLANE. `GET` only, so there is no new way to cancel,
/// accelerate, or otherwise influence a candidate. The projection read itself mutates
/// nothing. Its shared panic net can only latch the already-required fail-closed
/// Lockdown after observing a poisoned crown-jewel lock; that is fault recovery, not a
/// candidate action.
///
/// Unlike `/healthz` this one DOES take `sign_state`, so it goes through
/// `spawn_blocking` rather than parking a runtime worker on a `std` mutex — the same
/// discipline every other lock-touching path here follows. The guarded section is one
/// `HashMap` scan with no I/O inside it ([`crate::Node::pending_projection`]).
///
/// LOCKDOWN — the deliberate answer: a locked-down node answers this exactly like any
/// other node. Same route, same shape, no branch. Lockdown is ALREADY public
/// (`/healthz` reports `locked_down`, and every `/sign` answers `FRAUD_SUSPECTED`), so
/// a Lockdown-shaped branch here would introduce a duress-correlated code path while
/// disclosing nothing that is not already disclosed — and the user needs the record of
/// what this node accepted MOST during the incident that locked it down. Emptying or
/// refusing post-`T` would delete exactly the evidence the endpoint exists to provide.
async fn pending(State(state): State<AppState>) -> Response {
    let Ok(permit) = Arc::clone(&state.pending_concurrency).try_acquire_owned() else {
        return error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "pending query already in progress",
        );
    };
    #[cfg(test)]
    if let Some(pending_entered) = &state.pending_entered {
        let _ = pending_entered.send(());
    }
    let node = Arc::clone(&state.node);
    let read = blocking_with_lockdown_net(Arc::clone(&state.node), move || {
        // Hold the permit until the snapshot actually finishes — move it INTO the
        // job, not just the handler future, exactly as `/channel` does with its
        // pre-auth permit. `spawn_blocking` detaches: a poller that disconnects
        // while this job is parked on `sign_state` cancels the handler future, and
        // a permit tied to that future would be released while the job stays
        // parked. Connect-and-drop in a loop would then queue unbounded blocking
        // workers behind `/sign`'s memory-hard PIN work — the exact contention
        // `PENDING_MAX_CONCURRENCY` exists to bound, and the one that could put
        // observational work in front of the fire path.
        let _permit = permit;
        node.pending_projection_now()
    })
    .await;
    match read {
        Ok(projection) => match serde_json::to_string(&projection) {
            Ok(json) => json_response(StatusCode::OK, json),
            Err(e) => error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("cannot encode pending: {e}"),
            ),
        },
        // The only way this read unwinds is a `sign_state` already poisoned by some
        // other critical section — which the panic nets have latched Lockdown for.
        // Answer 500 rather than a body a poller could mistake for "nothing pending".
        Err(_join_error) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "pending task failed unexpectedly",
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
    // Once a critical-lock panic has reached terminal Lockdown, no channel work is
    // safe or useful: an authenticated partial would re-enter the poisoned store,
    // panic at its fail-closed `.expect`, and invoke the panic hook on every peer retry.
    // Return the same 500 this handler already exposes for that panic, before body
    // parsing or authentication, so retries cannot fill the RAMDISK logs.
    if state.node.is_locked_down() && state.node.critical_lock_poisoned() {
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "channel task failed unexpectedly",
        );
    }
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
        let outcome = blocking_with_lockdown_net(Arc::clone(&propagation_node), move || {
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
            // `handle_channel_body_now`, not `channel.ingest`: a `request` envelope has to
            // pass THIS node's own coordinator-auth + policy gates, which live on the
            // node, not the channel (§3).
            handle_channel_body_now(&node, bytes.as_ref())
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
        // The job was observed (handler not cancelled) but a layer panicked: 500, not a
        // hang. The in-job §2b net above already forces Lockdown when the BLOCKING ingest
        // poisoned the channel store lock; re-check here to also cover a panic in the
        // outer job body (e.g. `propagate_outbox`) on this awaited path. Idempotent and
        // poison-independent, gated on ACTUAL poison, so a benign panic that held no lock
        // stays a plain 500.
        Ok(Err(_join_error)) | Err(_join_error) => {
            outer_job_lockdown_recheck(&state.node);
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "channel task failed unexpectedly",
            )
        }
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
    use crate::chain::{ChainBackend, PackageVerdict, Prevout};
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

    /// The handler's OUTER `JoinError` arm re-checks poison via
    /// [`outer_job_lockdown_recheck`]: a panic in the outer job body (e.g.
    /// `propagate_outbox`) that poisoned a critical lock AFTER the in-job net returned
    /// must still force terminal Lockdown. Drives a real outer-job panic to a `JoinError`
    /// and applies the arm's recheck, exactly as the `/sign` and `/channel` handlers do.
    #[tokio::test]
    async fn the_outer_job_join_error_arm_forces_lockdown_on_a_poisoned_critical_lock() {
        let (node, _request) = node_and_valid_request();
        let node = Arc::new(node);
        let panic_node = Arc::clone(&node);
        // The analogue of `propagate_outbox` panicking while a critical lock is poisoned,
        // AFTER a successful in-job net: the outer job poisons sign_state and panics, and
        // the handler's `tokio::spawn(...).await` surfaces the `JoinError` the arm handles.
        let join = tokio::spawn(async move {
            let _guard = panic_node
                .sign_state
                .lock()
                .expect("acquire sign_state for outer-job panic injection");
            panic!("injected outer-job-body panic while holding sign_state");
        })
        .await;
        assert!(join.is_err(), "the outer job must surface a JoinError");
        // The arm's exact behavior on that JoinError.
        outer_job_lockdown_recheck(&node);
        assert!(
            node.is_locked_down(),
            "an outer-job-body panic that poisoned a critical lock must force terminal Lockdown"
        );
    }

    /// The shared `/sign` + `/channel` blocking boundary catches an unwind after a
    /// crown-jewel lock is acquired and reaches Lockdown without re-locking it.
    #[tokio::test]
    async fn request_job_panic_net_forces_lockdown_after_critical_lock_panics() {
        let (node, request) = node_and_valid_request();
        let node = Arc::new(node);
        let panic_node = Arc::clone(&node);
        let sign_outcome = blocking_with_lockdown_net(Arc::clone(&node), move || {
            let _guard = panic_node
                .sign_state
                .lock()
                .expect("acquire sign_state for panic injection");
            panic!("injected panic while holding sign_state");
        })
        .await;
        assert!(
            sign_outcome.is_err(),
            "the blocking boundary must capture the sign-state panic"
        );
        assert!(
            node.is_locked_down(),
            "a request panic under sign_state must force terminal Lockdown"
        );
        assert!(matches!(
            crate::handle_sign(&node, &request, 0).expect("Lockdown refusal"),
            SignResponse::Refusal(refusal)
                if refusal.code == vault_proto::RefusalCode::FraudSuspected
        ));

        let fx = crate::channel::fixture::Fixture::new(2, 3);
        let node = Arc::new(
            crate::test_support::load_node(&fx.config(0, 0, ""))
                .expect("valid channel fixture node"),
        );
        let panic_node = Arc::clone(&node);
        let channel_outcome = blocking_with_lockdown_net(Arc::clone(&node), move || {
            panic_node
                .channel
                .as_ref()
                .expect("channel")
                .panic_while_holding_store();
        })
        .await;
        assert!(
            channel_outcome.is_err(),
            "the blocking boundary must capture the channel-store panic"
        );
        assert!(
            node.is_locked_down(),
            "a request panic under the channel store must force terminal Lockdown"
        );
    }

    /// Once the panic net has latched Lockdown around a poisoned store, `/channel`
    /// refuses before reading or authenticating another body. Without the handler's
    /// terminal-poison guard, this malformed sentinel reaches normal parsing and
    /// returns tagged 400 instead of the panic path's existing 500.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn channel_short_circuits_after_critical_poison_reaches_lockdown() {
        let fx = crate::channel::fixture::Fixture::new(2, 3);
        let node = Arc::new(
            crate::test_support::load_node(&fx.config(0, 0, ""))
                .expect("valid channel fixture node"),
        );
        let panic_node = Arc::clone(&node);
        let outcome = blocking_with_lockdown_net(Arc::clone(&node), move || {
            panic_node
                .channel
                .as_ref()
                .expect("channel")
                .panic_while_holding_store();
        })
        .await;
        assert!(outcome.is_err(), "the injected store panic must unwind");
        assert!(node.is_locked_down(), "the panic net must latch Lockdown");
        assert!(
            node.critical_lock_poisoned(),
            "the store must remain poisoned"
        );

        let addr = spawn_app(app(Arc::clone(&node))).await;
        let (status, response) =
            spawn_blocking(move || post(addr, "/channel", "definitely not json"))
                .await
                .expect("channel client");
        assert_eq!(
            status, 500,
            "terminal poison must short-circuit before malformed-body parsing"
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&response).expect("error json"),
            serde_json::json!({ "error": "channel task failed unexpectedly" })
        );
    }

    /// The negative twin: the `/channel` terminal-poison short-circuit is gated on
    /// `is_locked_down() && critical_lock_poisoned()`. A node locked down NORMALLY at T
    /// (not poisoned) must NOT hit the poison-500 — it still serves `/channel` so the
    /// in-flight escape sweep can be combined (ADR-0012: Lockdown accepts the sweep
    /// combine, it only blocks NEW signing). This pins the load-bearing
    /// `&& critical_lock_poisoned()` conjunct: dropping it would 500 every locked-down
    /// node and break sweep completion.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn channel_serves_a_normally_locked_down_node_that_is_not_poisoned() {
        let fx = crate::channel::fixture::Fixture::new(2, 3);
        let node = Arc::new(
            crate::test_support::load_node(&fx.config(0, 0, ""))
                .expect("valid channel fixture node"),
        );
        node.enter_lockdown();
        assert!(node.is_locked_down(), "the node is locked down");
        assert!(
            !node.critical_lock_poisoned(),
            "a normal Lockdown at T must NOT poison any critical lock"
        );

        let addr = spawn_app(app(Arc::clone(&node))).await;
        let (status, response) =
            spawn_blocking(move || post(addr, "/channel", "definitely not json"))
                .await
                .expect("channel client");
        // The short-circuit did NOT fire: the malformed body reaches normal parsing and
        // returns the handler's tagged rejection, never the poison-500.
        assert_ne!(
            status, 500,
            "a locked-down-but-not-poisoned node must not hit the terminal-poison short-circuit"
        );
        assert_ne!(
            serde_json::from_str::<serde_json::Value>(&response).ok(),
            Some(serde_json::json!({ "error": "channel task failed unexpectedly" })),
            "must not return the poison-500 body"
        );
    }

    // -- `/healthz`: the operations liveness surface (bead btc-policy-9y5.6) -----

    /// A fresh node answers the full projection: it is serving, not locked down, has
    /// no fire-driver heartbeat yet, and — being a path-less unit-test node — has
    /// claimed no process generation. Pins the field NAMES and the exact shape,
    /// because the wire contract is what an operator and the coordinator relay read.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn healthz_reports_serving_on_a_fresh_node() {
        let (node, _request) = node_and_valid_request();
        let addr = spawn_app(app(Arc::new(node))).await;
        let (status, body) = spawn_blocking(move || get(addr, "/healthz"))
            .await
            .expect("client task");
        assert_eq!(status, 200);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&body).expect("health json"),
            serde_json::json!({
                "serving": true,
                "locked_down": false,
                "last_deadline_tick": null,
                "generation_claimed": false,
            })
        );
    }

    /// Post-`T` Lockdown is PUBLIC state (ADR-0008: the node already answers
    /// `FRAUD_SUSPECTED` to every spend), and making it readable without a probe spend
    /// is the point of the endpoint.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn healthz_reports_locked_down_after_lockdown() {
        let (node, _request) = node_and_valid_request();
        let node = Arc::new(node);
        let addr = spawn_app(app(Arc::clone(&node))).await;
        node.enter_lockdown();

        let (status, body) = spawn_blocking(move || get(addr, "/healthz"))
            .await
            .expect("client task");
        assert_eq!(status, 200);
        let health: serde_json::Value = serde_json::from_str(&body).expect("health json");
        assert_eq!(health["locked_down"], serde_json::json!(true));
        // Still answering: Lockdown blocks signing, it does not take the node off the
        // air, and an operator reading "locked_down" needs the surface to stay up.
        assert_eq!(health["serving"], serde_json::json!(true));
    }

    /// `last_deadline_tick` is the SAFETY deadline driver's heartbeat — the wire name is
    /// the bead's, the publisher is that driver — so drive its real tick and watch it
    /// move in [`crate::DEADLINE_HEARTBEAT_RESOLUTION_SECS`] buckets. The best-effort
    /// release/combine pass does not WRITE it, and this test asserts that direct
    /// separation: publishing from that completion-scheduled pass would leak its
    /// phase even if the timestamp itself were bucketed. Shared-store contention can
    /// still postpone a later deadline iteration; that residual, and the fact that a
    /// backend-wedged release/combine pass does NOT show up here, are stated in
    /// [`crate::Node::last_deadline_tick`].
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn healthz_last_deadline_tick_advances_as_the_deadline_driver_ticks() {
        use crate::DEADLINE_HEARTBEAT_RESOLUTION_SECS as RESOLUTION;

        let fx = crate::channel::fixture::Fixture::new(2, 3);
        let node = Arc::new(
            crate::test_support::load_node(&fx.config(0, 0, "")).expect("channel fixture node"),
        );
        let addr = spawn_app(app(Arc::clone(&node))).await;
        let backend: Arc<dyn ChainBackend + Send + Sync> = Arc::new(SlowBackend {
            delay: Duration::ZERO,
            entered: std::sync::Mutex::new(None),
        });
        let read = |addr: SocketAddr| async move {
            let (status, body) = spawn_blocking(move || get(addr, "/healthz"))
                .await
                .expect("client task");
            assert_eq!(status, 200);
            serde_json::from_str::<serde_json::Value>(&body).expect("health json")
                ["last_deadline_tick"]
                .clone()
        };

        assert_eq!(
            read(addr).await,
            serde_json::Value::Null,
            "before the first pass there is no heartbeat to report"
        );

        // The absolute-schedule deadline pass publishes the heartbeat.
        let first = 1_800_000_000;
        crate::lockdown_tick_with_lockdown_net(&node, first);
        assert_eq!(read(addr).await, serde_json::json!(first));
        let later = first + RESOLUTION;

        // A release/combine pass at a later wall time does NOT publish. Its own
        // completion-scheduled invocation time therefore is not copied directly into
        // the externally visible heartbeat.
        crate::fire_tick(Arc::clone(&node), Arc::clone(&backend), later).await;
        assert_eq!(read(addr).await, serde_json::json!(first));

        crate::lockdown_tick_with_lockdown_net(&node, later);
        assert_eq!(read(addr).await, serde_json::json!(later));

        // Inside a bucket it does not move — the reported value is the bucket, not a
        // sub-bucket scheduler instant.
        crate::lockdown_tick_with_lockdown_net(&node, later + 1);
        crate::lockdown_tick_with_lockdown_net(&node, later + RESOLUTION - 1);
        assert_eq!(read(addr).await, serde_json::json!(later));
    }

    /// The headline operator claim of [`crate::Node::last_deadline_tick`]: a
    /// POISON-BRICKED node reads as a STALE heartbeat alongside `locked_down: true`,
    /// which is the state that was externally invisible before bead btc-policy-9y5.6.
    ///
    /// That pairing exists only because `record_deadline_tick` sits BELOW
    /// [`crate::lockdown_tick_with_lockdown_net`]'s terminal-poison early return.
    /// Hoisting it above the guard reads like a harmless "publish first,
    /// unconditionally" refactor and would leave every other `/healthz` test green
    /// while the heartbeat kept advancing on a node whose deadline driver runs no
    /// further pass — the one signal that names a bricked node, gone.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn healthz_heartbeat_freezes_on_a_poison_bricked_node() {
        const NOW: u64 = 1_800_000_000;

        let fx = crate::channel::fixture::Fixture::new(2, 3);
        let node = Arc::new(
            crate::test_support::load_node(&fx.config(0, 0, "")).expect("channel fixture node"),
        );
        crate::lockdown_tick_with_lockdown_net(&node, NOW);
        assert_eq!(
            node.health().last_deadline_tick,
            Some(NOW),
            "the live driver publishes before the brick, or this test proves nothing"
        );

        // Brick it exactly as production does: a request-path panic under the channel
        // store poisons that lock, and the blocking boundary's net latches the
        // poison-independent terminal Lockdown.
        let panic_node = Arc::clone(&node);
        let outcome = blocking_with_lockdown_net(Arc::clone(&node), move || {
            panic_node
                .channel
                .as_ref()
                .expect("channel")
                .panic_while_holding_store();
        })
        .await;
        assert!(outcome.is_err(), "the injected store panic must unwind");
        assert!(
            node.is_locked_down() && node.critical_lock_poisoned(),
            "the brick is the locked-down-AND-poisoned pair"
        );

        // Every later deadline tick returns at the terminal-poison guard, so it
        // publishes nothing — however far the wall clock moves on.
        crate::lockdown_tick_with_lockdown_net(
            &node,
            NOW + crate::DEADLINE_HEARTBEAT_RESOLUTION_SECS,
        );
        crate::lockdown_tick_with_lockdown_net(
            &node,
            NOW + 100 * crate::DEADLINE_HEARTBEAT_RESOLUTION_SECS,
        );

        let addr = spawn_app(app(Arc::clone(&node))).await;
        let (status, body) = spawn_blocking(move || get(addr, "/healthz"))
            .await
            .expect("client task");
        assert_eq!(status, 200);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&body).expect("health json"),
            serde_json::json!({
                "serving": true,
                "locked_down": true,
                "last_deadline_tick": NOW,
                "generation_claimed": false,
            }),
            "a poison-bricked node must read as a FROZEN heartbeat next to locked_down: true"
        );
    }

    /// Exercise the LIVE publisher tasks across a bucket boundary without lock
    /// contention. One node is armed and one is idle, and both deadline drivers are
    /// anchored to the same absolute Tokio schedule, so the direct publisher must
    /// transition on the same tick. This catches an edit that publishes from the
    /// completion-scheduled fire pass — deterministically, which no live end-to-end
    /// harness can do for a timing class without flaking. It deliberately does not
    /// model contention on the shared store; that store-contention latency residual is
    /// documented in DESIGN.md, not tested end-to-end.
    #[tokio::test(start_paused = true)]
    async fn healthz_live_heartbeat_transition_follows_the_deadline_schedule() {
        use std::sync::atomic::{AtomicU64, Ordering};

        const BUCKET: u64 = 1_800_000_000;
        const DURESS_DELAY: u64 = 600;

        let fx = crate::channel::fixture::Fixture::new(2, 3);
        let armed = Arc::new(
            crate::test_support::load_node(&fx.config(0, 0, "")).expect("channel fixture node"),
        );
        let idle = Arc::new(
            crate::test_support::load_node(&fx.config(0, 0, "")).expect("channel fixture node"),
        );
        let wall = Arc::new(AtomicU64::new(
            BUCKET + crate::DEADLINE_HEARTBEAT_RESOLUTION_SECS - 1,
        ));

        let armed_wall = Arc::clone(&wall);
        let armed_driver = tokio::spawn(crate::lockdown_driver_with_clock(
            Arc::clone(&armed),
            move || armed_wall.load(Ordering::Acquire),
        ));
        let idle_wall = Arc::clone(&wall);
        let idle_driver = tokio::spawn(crate::lockdown_driver_with_clock(
            Arc::clone(&idle),
            move || idle_wall.load(Ordering::Acquire),
        ));
        tokio::task::yield_now().await;
        assert_eq!(
            (
                armed.health().last_deadline_tick,
                idle.health().last_deadline_tick
            ),
            (Some(BUCKET), Some(BUCKET)),
            "both immediate deadline ticks publish the same starting bucket"
        );

        assert!(
            armed
                .channel
                .as_ref()
                .expect("channel")
                .arm_via_confirmation(
                    "duress-carrier",
                    "",
                    armed.threshold,
                    BUCKET,
                    crate::channel::DuressTiming {
                        duress_delay_secs: DURESS_DELAY,
                        epsilon_secs: 1,
                        combine_slack_secs: 60,
                    },
                ),
            "the arm must commit, or the live comparison proves nothing"
        );

        let boundary = BUCKET + crate::DEADLINE_HEARTBEAT_RESOLUTION_SECS;
        wall.store(boundary, Ordering::Release);
        tokio::time::advance(crate::FIRE_INTERVAL).await;
        tokio::task::yield_now().await;

        let armed_body = serde_json::to_vec(&armed.health()).expect("armed health");
        let idle_body = serde_json::to_vec(&idle.health()).expect("idle health");
        assert_eq!(
            armed_body, idle_body,
            "DURESS ORACLE: the live /healthz heartbeat flipped differently after arming"
        );
        assert_eq!(
            armed.health().last_deadline_tick,
            Some(boundary),
            "the common absolute-schedule tick publishes the new bucket"
        );
        assert!(!armed.is_locked_down(), "the live comparison remains pre-T");

        armed_driver.abort();
        idle_driver.abort();
    }

    /// THE LOAD-BEARING TEST: `/healthz` must not become a duress oracle.
    ///
    /// An ARMED-but-pre-`T` node is the state a hostile coordinator most wants to
    /// read — it is the whole content of the hostage window (ADR-0012 SILENCE). Two
    /// nodes built from the identical config, one armed through the production
    /// confirmation path and one untouched, must answer `/healthz` BYTE-IDENTICALLY.
    ///
    /// The comparison is on the COMPLETE body, not a chosen field: a leak added later
    /// would most plausibly arrive as a field nobody thought to name here, and a
    /// field-by-field check would sail past it. The heartbeat is stamped at the same
    /// instant on both so it is a compared byte too, rather than a normalized-away
    /// hole a same-width pin-dependent value could sit in.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn healthz_is_byte_identical_on_an_armed_pre_t_node() {
        const NOW: u64 = 1_800_000_000;
        const DURESS_DELAY: u64 = 600;

        let fx = crate::channel::fixture::Fixture::new(2, 3);
        // The SAME config twice: two nodes whose only difference is the arm below.
        let armed = Arc::new(
            crate::test_support::load_node(&fx.config(0, 0, "")).expect("channel fixture node"),
        );
        let idle = Arc::new(
            crate::test_support::load_node(&fx.config(0, 0, "")).expect("channel fixture node"),
        );
        let backend: Arc<dyn ChainBackend + Send + Sync> = Arc::new(SlowBackend {
            delay: Duration::ZERO,
            entered: std::sync::Mutex::new(None),
        });
        // One absolute-schedule deadline pass each at the same instant, so the
        // heartbeat is part of the compared bytes instead of a hole.
        crate::lockdown_tick_with_lockdown_net(&armed, NOW);
        crate::lockdown_tick_with_lockdown_net(&idle, NOW);

        assert!(
            armed
                .channel
                .as_ref()
                .expect("channel")
                .arm_via_confirmation(
                    "duress-carrier",
                    "",
                    armed.threshold,
                    NOW,
                    crate::channel::DuressTiming {
                        duress_delay_secs: DURESS_DELAY,
                        epsilon_secs: 1,
                        combine_slack_secs: 60,
                    },
                ),
            "the arm must commit, or this test compares two idle nodes and proves nothing"
        );
        // Pre-`T`, and it must stay that way for the whole comparison: after `T` the
        // Lockdown difference is legitimate and public, so a comparison that drifted
        // past it would be asserting the wrong thing.
        assert!(
            !crate::lockdown_tick(&armed, NOW),
            "the arm is pre-T; Lockdown is what happens AT T"
        );
        assert!(!armed.is_locked_down());

        // Deliberately give the completion-scheduled release/combine passes different
        // start instants after arming. Neither directly WRITES the public heartbeat;
        // only the explicit deadline ticks below publish in this contention-free
        // fixture.
        crate::fire_tick(Arc::clone(&armed), Arc::clone(&backend), NOW + 1).await;
        crate::fire_tick(Arc::clone(&idle), Arc::clone(&backend), NOW + 2).await;
        assert_eq!(
            armed.health().last_deadline_tick,
            idle.health().last_deadline_tick,
            "release/combine cadence must not reach the public heartbeat"
        );
        let next_bucket = NOW + crate::DEADLINE_HEARTBEAT_RESOLUTION_SECS;
        crate::lockdown_tick_with_lockdown_net(&armed, next_bucket);
        crate::lockdown_tick_with_lockdown_net(&idle, next_bucket);
        assert_eq!(
            (
                armed.health().last_deadline_tick,
                idle.health().last_deadline_tick
            ),
            (Some(next_bucket), Some(next_bucket)),
            "the public transition is fixed by the common deadline-driver schedule"
        );

        let armed_addr = spawn_app(app(Arc::clone(&armed))).await;
        let idle_addr = spawn_app(app(Arc::clone(&idle))).await;
        let (armed_status, armed_body) = spawn_blocking(move || get(armed_addr, "/healthz"))
            .await
            .expect("armed client");
        let (idle_status, idle_body) = spawn_blocking(move || get(idle_addr, "/healthz"))
            .await
            .expect("idle client");
        assert_eq!((armed_status, idle_status), (200, 200));
        assert_eq!(
            armed_body, idle_body,
            "DURESS ORACLE: /healthz differs between an armed pre-T node and an idle one"
        );

        // And the control that makes the equality mean something: this node really is
        // armed, and its Lockdown really does land at `T`. Without it the assertion
        // above would pass just as happily against an arm that never committed.
        assert!(armed
            .channel
            .as_ref()
            .expect("channel")
            .armed_snapshot()
            .is_some());
        assert!(
            crate::lockdown_tick(&armed, NOW + DURESS_DELAY),
            "the armed node must Lock Down at T"
        );
        let (_status, after_t) = spawn_blocking(move || get(armed_addr, "/healthz"))
            .await
            .expect("armed client after T");
        assert_ne!(
            after_t, idle_body,
            "post-T Lockdown is public state and MUST show up — if it does not, the \
             pre-T equality above is measuring an endpoint that reports nothing"
        );
    }

    /// `/healthz` is an operations surface, not a control surface: it is `GET`-only
    /// and cannot mutate node state.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn healthz_is_read_only() {
        let (node, _request) = node_and_valid_request();
        let addr = spawn_app(app(Arc::new(node))).await;
        let (status, _) = spawn_blocking(move || post(addr, "/healthz", "{}"))
            .await
            .expect("client task");
        assert_eq!(status, 405, "/healthz must not accept a mutating verb");
    }

    /// THE REASON THE ENDPOINT IS LOCK-FREE: a node stuck behind `sign_state` is the
    /// state an operator most needs to read, so `/healthz` must answer while that
    /// lock is held — by a wedged `/sign`, by a fire pass, by anything.
    ///
    /// [`Node::health`] reads atomics today, so this passes; the test exists for the
    /// EDIT that would break it. A later field taking `sign_state` (a pending count,
    /// say) would leave all six shape tests above green while silently destroying the
    /// property, because every one of them probes an idle node. One worker, as in
    /// [`a_blocking_sign_does_not_delay_events`], so an on-runtime regression cannot
    /// hide behind a spare core.
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn healthz_answers_while_sign_state_is_held() {
        let (node, request) = node_and_valid_request();
        let node = Arc::new(node);
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let addr = spawn_app(app_with_sign_entry(node.clone(), entered_tx)).await;

        // Hold `sign_state` from an OS thread, then wedge a REAL `/sign` behind it.
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

        // Probe from an OS thread with a socket deadline, and release the lock on
        // every outcome, so a regression fails bounded instead of hanging the suite.
        let probe = std::thread::spawn(move || {
            let result = (|| {
                entered_rx
                    .recv_timeout(Duration::from_secs(2))
                    .map_err(|e| format!("/sign never entered its handler: {e}"))?;
                get_with_timeout(addr, "/healthz", Duration::from_secs(2))
                    .map_err(|e| format!("/healthz blocked behind a held sign_state: {e}"))
            })();
            let _ = release_tx.send(());
            result
        });
        let (status, body) = spawn_blocking(move || probe.join().expect("probe thread"))
            .await
            .expect("probe task")
            .expect("/healthz lock isolation");
        assert_eq!(status, 200);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&body).expect("health json")["serving"],
            serde_json::json!(true),
            "a lock-blocked node must still report the full projection, not a stub"
        );

        holder.join().expect("holder thread");
        let _ = tokio::time::timeout(Duration::from_secs(2), inflight)
            .await
            .expect("/sign did not finish after release")
            .expect("inflight sign task");
    }

    /// The other half of the no-lock contract: the channel store. A wedged store is
    /// the poison-brick's own neighbourhood — the deadline driver blocks on it, the
    /// heartbeat freezes, and reading that pair is the whole point of the surface, so
    /// the read itself must not queue behind the same lock. Exercise the production
    /// scheduler shape: the deadline and fire-driver prologues occupy two workers, and
    /// `main`'s three-worker floor leaves a third to poll the listener and this
    /// handler. A floor on the worker COUNT, not a reservation of one worker — the
    /// third is shared with the acceptor, every connection task, the watchtower, and
    /// the cache refresher — and the property holds because all of those reach their
    /// blocking work through `spawn_blocking` instead of occupying a worker inside it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    async fn healthz_answers_while_the_channel_store_is_held() {
        let fx = crate::channel::fixture::Fixture::new(2, 3);
        let node = Arc::new(
            crate::test_support::load_node(&fx.config(0, 0, "")).expect("channel fixture node"),
        );
        let addr = spawn_app(app(Arc::clone(&node))).await;

        let gate = Arc::clone(&node);
        let (held_tx, held_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let holder = std::thread::spawn(move || {
            gate.channel
                .as_ref()
                .expect("channel")
                .hold_store_until(&held_tx, &release_rx);
        });
        held_rx.recv().expect("store held");

        // These are the exact two synchronous store calls at the heads of the
        // production deadline and fire drivers. Announce each task before it waits,
        // then yield once so both consume their worker while the holder owns the
        // store. With only the host-CPU-sized default runtime on a <=2-vCPU node,
        // the listener and `/healthz` handler would never be polled.
        let deadline_node = Arc::clone(&node);
        let (deadline_entered_tx, deadline_entered_rx) = tokio::sync::oneshot::channel();
        let deadline_waiter = tokio::spawn(async move {
            let _ = deadline_entered_tx.send(());
            deadline_node
                .channel
                .as_ref()
                .expect("channel")
                .lockdown_due(0)
        });
        let fire_node = Arc::clone(&node);
        let (fire_entered_tx, fire_entered_rx) = tokio::sync::oneshot::channel();
        let fire_waiter = tokio::spawn(async move {
            let _ = fire_entered_tx.send(());
            fire_node.channel.as_ref().expect("channel").prune_store(0);
        });
        deadline_entered_rx.await.expect("deadline task entered");
        fire_entered_rx.await.expect("fire task entered");
        tokio::task::yield_now().await;

        let probe = std::thread::spawn(move || {
            let result = get_with_timeout(addr, "/healthz", Duration::from_secs(2))
                .map_err(|e| format!("/healthz blocked behind a held channel store: {e}"));
            let _ = release_tx.send(());
            result
        });
        let (status, body) = spawn_blocking(move || probe.join().expect("probe thread"))
            .await
            .expect("probe task")
            .expect("/healthz lock isolation");
        assert_eq!(status, 200);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&body).expect("health json")["serving"],
            serde_json::json!(true)
        );
        holder.join().expect("holder thread");
        assert!(!deadline_waiter.await.expect("deadline waiter"));
        fire_waiter.await.expect("fire waiter");
    }

    // -- `/pending`: the accepted-but-unsettled projection (bead btc-policy-k0t) ---

    /// Re-`pin` and re-coord-sign `base` under a fresh `nonce`, exactly as the pin
    /// tests do: the PIN is inside the coordinator signature's preimage, so changing
    /// it invalidates the old signature. Nothing here touches the COMMITMENT preimage
    /// (`wallet_id`, the transaction, the fee, the expiry, the policy version), so both
    /// results still commit to the identical spend under the identical id — which is
    /// what makes a pin-uniformity comparison meaningful rather than trivially true.
    fn repin(base: &SignRequest, node: &Node, pin: &str, nonce: &str) -> SignRequest {
        let mut request = base.clone();
        request.pin = pin.into();
        crate::test_support::coord_sign(&mut request, &node.wallet_id, nonce);
        request
    }

    fn pending_ids(body: &str) -> Vec<String> {
        serde_json::from_str::<serde_json::Value>(body).expect("pending json")["pending"]
            .as_array()
            .expect("pending array")
            .iter()
            .map(|id| id.as_str().expect("commitment id string").to_owned())
            .collect()
    }

    /// A fresh node has accepted nothing, and the empty answer is the full shape — the
    /// wire contract an operator and the coordinator relay read.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn pending_is_empty_on_a_fresh_node() {
        let (node, _request) = node_and_valid_request();
        let addr = spawn_app(app(Arc::new(node))).await;
        let (status, body) = spawn_blocking(move || get(addr, "/pending"))
            .await
            .expect("client task");
        assert_eq!(status, 200);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&body).expect("pending json"),
            serde_json::json!({ "pending": [] })
        );
    }

    /// THE REASON THE ENDPOINT EXISTS: a spend the user never authorized, fed STRAIGHT
    /// to one node by someone holding the coordinator auth key, is visible on that
    /// node during its Hold — no coordinator relay in the loop.
    ///
    /// The POST below is precisely that thief's move: a coordinator-authenticated
    /// `/sign` the user's own coordinator never composed and never sees. Before this
    /// projection, the acceptance left no surface the user watches (`GET /events`
    /// carries on-chain watchtower alerts only), which is the gap
    /// `demo theft-refused` used to disclose as a printed caveat.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn pending_reports_a_candidate_the_user_never_authorized() {
        let (node, request) = node_and_valid_request();
        let node = Arc::new(node);
        let addr = spawn_app(app(Arc::clone(&node))).await;

        let body = spend_body(&request);
        let (status, accepted) = spawn_blocking(move || post(addr, "/sign", &body))
            .await
            .expect("thief client");
        assert_eq!(status, 200);
        let commitment_id = match serde_json::from_str::<SignResponse>(&accepted).expect("decode") {
            SignResponse::Accepted(accepted) => accepted.commitment_id,
            other => panic!("the direct feed must be accepted to be pending: {other:?}"),
        };

        let (status, body) = spawn_blocking(move || get(addr, "/pending"))
            .await
            .expect("client task");
        assert_eq!(status, 200);
        assert_eq!(
            pending_ids(&body),
            vec![commitment_id],
            "a candidate accepted straight from the wire must be visible during its Hold"
        );
    }

    /// THE LOAD-BEARING TEST: `/pending` must not become a duress oracle.
    ///
    /// Two nodes built from the identical config are fed the IDENTICAL spend — one
    /// under the enrolled normal PIN, one under the enrolled duress PIN — and must
    /// answer BYTE-IDENTICALLY. One request object is re-pinned rather than two being
    /// built, so the commitment (and therefore everything downstream of it) is the same
    /// by construction and the pin is genuinely the only variable.
    ///
    /// The comparison is on the COMPLETE body, never a chosen field or its length: a
    /// leak added later would most plausibly arrive as a field nobody thought to name
    /// here, or as a same-width value substituted into one that was, and either would
    /// sail straight past a field-by-field check.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn pending_is_byte_identical_under_the_normal_and_duress_pins() {
        // The SAME fixture twice: two nodes whose only difference is the pin below.
        let (normal_node, base) = node_and_valid_request();
        let (duress_node, _) = node_and_valid_request();
        let normal_node = Arc::new(normal_node);
        let duress_node = Arc::new(duress_node);
        let normal_request = repin(&base, &normal_node, "1234", "silence-normal");
        let duress_request = repin(&base, &duress_node, "9999", "silence-duress");

        let normal_addr = spawn_app(app(Arc::clone(&normal_node))).await;
        let duress_addr = spawn_app(app(Arc::clone(&duress_node))).await;
        for (addr, request) in [
            (normal_addr, &normal_request),
            (duress_addr, &duress_request),
        ] {
            let body = spend_body(request);
            let (status, response) = spawn_blocking(move || post(addr, "/sign", &body))
                .await
                .expect("sign client");
            assert_eq!(status, 200);
            assert!(
                matches!(
                    serde_json::from_str::<SignResponse>(&response).expect("decode"),
                    SignResponse::Accepted(_)
                ),
                "both pins must be ACCEPTED (ADR-0012 SILENCE), or this compares two \
                 different states: {response}"
            );
        }

        let (normal_status, normal_body) = spawn_blocking(move || get(normal_addr, "/pending"))
            .await
            .expect("normal client");
        let (duress_status, duress_body) = spawn_blocking(move || get(duress_addr, "/pending"))
            .await
            .expect("duress client");
        assert_eq!((normal_status, duress_status), (200, 200));
        assert_eq!(
            normal_body, duress_body,
            "DURESS ORACLE: /pending differs between a normal-pin and a duress-pin spend"
        );
        // The control that makes the equality mean something: both really did register
        // a pending candidate. Without it this would pass just as happily against an
        // endpoint that reports nothing at all.
        assert_eq!(
            pending_ids(&normal_body).len(),
            1,
            "the compared bodies must actually carry the candidate"
        );
        assert_eq!(
            duress_node.duress_arm_count(),
            1,
            "the duress node must really have seen a valid duress pin"
        );
        assert_eq!(normal_node.duress_arm_count(), 0);
    }

    /// The same claim against a node that has genuinely ARMED through the production
    /// confirmation path, pre-`T` — the state a hostile coordinator most wants to read,
    /// and the whole content of the hostage window (ADR-0012 SILENCE). The pin-level
    /// test above cannot reach it: an absent-channel node records the duress intent but
    /// has no store to arm.
    ///
    /// Both nodes are fed the identical hot spend under the identical NORMAL pin, so
    /// their pending logs start equal by construction and the arm is the only variable.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn pending_is_byte_identical_on_an_armed_pre_t_node() {
        const DURESS_DELAY: u64 = 600;
        // The Hold has to outlast `T`, or there is no pre-`T` window to compare in:
        // `T = min(first_seen + duress_delay, earliest hot fire_at - epsilon)`, so a
        // zero Hold would collapse `T` onto `now` and Lock the node down immediately.
        const HOLD: u64 = 3_600;

        let fx = crate::channel::fixture::Fixture::new(2, 3);
        let armed = Arc::new(
            crate::test_support::load_node(&fx.config(0, HOLD, "")).expect("channel fixture node"),
        );
        let idle = Arc::new(
            crate::test_support::load_node(&fx.config(0, HOLD, "")).expect("channel fixture node"),
        );
        let now = crate::unix_now();
        let spend = fx.spend_psbt(&fx.hot_spk, 0);
        let expiry = now + 7_200;
        for (index, node) in [&armed, &idle].into_iter().enumerate() {
            let request = fx.spend_request(&spend, expiry, &format!("k0t-arm-{index}"));
            assert!(
                matches!(
                    crate::handle_sign(node, &request, now).expect("decodable"),
                    SignResponse::Accepted(_)
                ),
                "both nodes must hold the same pending candidate before the arm"
            );
        }

        assert!(
            armed
                .channel
                .as_ref()
                .expect("channel")
                .arm_via_confirmation(
                    "duress-carrier",
                    "",
                    armed.threshold,
                    now,
                    crate::channel::DuressTiming {
                        duress_delay_secs: DURESS_DELAY,
                        epsilon_secs: 1,
                        combine_slack_secs: 60,
                    },
                ),
            "the arm must commit, or this test compares two idle nodes and proves nothing"
        );
        // Pre-`T`, and it must stay that way across the comparison: after `T` the
        // Lockdown difference is legitimate and public, so a comparison that drifted
        // past it would be asserting the wrong thing.
        assert!(!crate::lockdown_tick(&armed, now), "the arm is pre-T");
        assert!(!armed.is_locked_down());

        let armed_addr = spawn_app(app(Arc::clone(&armed))).await;
        let idle_addr = spawn_app(app(Arc::clone(&idle))).await;
        let (armed_status, armed_body) = spawn_blocking(move || get(armed_addr, "/pending"))
            .await
            .expect("armed client");
        let (idle_status, idle_body) = spawn_blocking(move || get(idle_addr, "/pending"))
            .await
            .expect("idle client");
        assert_eq!((armed_status, idle_status), (200, 200));
        assert_eq!(
            armed_body, idle_body,
            "DURESS ORACLE: /pending differs between an armed pre-T node and an idle one"
        );
        assert_eq!(
            pending_ids(&armed_body).len(),
            1,
            "the compared bodies must actually carry the candidate"
        );
        // The control: this node really is armed, and its Lockdown really does land at
        // `T` — so the equality above is measuring an armed node, not a failed arm.
        assert!(armed
            .channel
            .as_ref()
            .expect("channel")
            .armed_snapshot()
            .is_some());
        assert!(
            crate::lockdown_tick(&armed, now + DURESS_DELAY),
            "the armed node must Lock Down at T"
        );
    }

    /// A locked-down node answers exactly like any other node — the documented
    /// Lockdown behaviour (see the [`pending`] handler). The body is compared against
    /// the pre-Lockdown one so the claim is "unchanged", not merely "still 200":
    /// emptying or refusing here would delete the record of what the node accepted at
    /// precisely the moment the user needs it, and would do so to hide state
    /// `/healthz` and `/sign` already publish.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn pending_answers_unchanged_on_a_locked_down_node() {
        let (node, request) = node_and_valid_request();
        let node = Arc::new(node);
        let addr = spawn_app(app(Arc::clone(&node))).await;
        let body = spend_body(&request);
        let (status, _) = spawn_blocking(move || post(addr, "/sign", &body))
            .await
            .expect("sign client");
        assert_eq!(status, 200);
        let (_status, before) = spawn_blocking(move || get(addr, "/pending"))
            .await
            .expect("client task");
        assert_eq!(pending_ids(&before).len(), 1);

        node.enter_lockdown();
        assert!(node.is_locked_down());
        let (status, after) = spawn_blocking(move || get(addr, "/pending"))
            .await
            .expect("client task");
        assert_eq!(
            status, 200,
            "Lockdown must not take the projection off the air"
        );
        assert_eq!(
            after, before,
            "a locked-down node must answer /pending unchanged: the evidence of what it \
             accepted is what the user needs during the incident that locked it down"
        );
    }

    /// The candidate DISAPPEARS on both terminal paths, and on nothing else.
    ///
    /// Settlement first, through the production removal ([`crate::settle_candidate`],
    /// what one fire tick calls once a normal spend is on the network); then commitment
    /// expiry, which is why the projection filters rather than trusting the sweep. Both
    /// are the same pin-independent events for every node in the federation — which is
    /// exactly why the projection's disappearance cannot signal a pin class.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn pending_clears_when_a_candidate_settles_or_expires() {
        let fx = crate::channel::fixture::Fixture::new(2, 3);
        let node = Arc::new(
            crate::test_support::load_node(&fx.config(0, 0, "")).expect("channel fixture node"),
        );
        let now = crate::unix_now();
        let expiry = now + 3_600;
        let request = fx.spend_request(&fx.spend_psbt(&fx.hot_spk, 0), expiry, "k0t-settle");
        let commitment_id = match crate::handle_sign(&node, &request, now).expect("decodable") {
            SignResponse::Accepted(accepted) => accepted.commitment_id,
            other => panic!("the fixture spend must be accepted: {other:?}"),
        };

        let addr = spawn_app(app(Arc::clone(&node))).await;
        let (_status, body) = spawn_blocking(move || get(addr, "/pending"))
            .await
            .expect("client task");
        assert_eq!(pending_ids(&body), vec![commitment_id.clone()]);

        // Expiry: the entry stays live through its final authorized second (the same
        // boundary refresh subordination uses) and is gone the second after.
        assert_eq!(
            node.pending_projection(expiry).pending,
            vec![commitment_id.clone()],
            "a candidate is still pending in its final fire second"
        );
        assert!(
            node.pending_projection(expiry + 1).pending.is_empty(),
            "past commitment expiry the candidate is no longer pending"
        );

        // Settlement: the exact call one fire tick makes after a normal spend reaches
        // the mempool or the chain.
        crate::settle_candidate(
            &node,
            node.channel.as_ref().expect("channel"),
            &commitment_id,
        );
        let (status, body) = spawn_blocking(move || get(addr, "/pending"))
            .await
            .expect("client task");
        assert_eq!(status, 200);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&body).expect("pending json"),
            serde_json::json!({ "pending": [] }),
            "a settled candidate must leave the projection"
        );
    }

    /// An escape-class clawback is an implicit cancel even when it came from a
    /// separate request. Once that public conflicting transaction settles, retaining
    /// the defeated hot id would tell the user an unspendable candidate is still live
    /// and would keep refreshes subordinated until an unrelated commitment expiry.
    ///
    /// And the projection must not run AHEAD of the fire path: the defeated candidate
    /// leaves the due set in the same settlement, so an id `/pending` stops reporting
    /// is an id no later tick can still broadcast. Without that half, a mempool
    /// eviction of the clawback would let the defeated spend fire at its Hold expiry
    /// with nothing left on the surface that exists to show it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn pending_clears_after_an_independent_conflicting_clawback_settles() {
        let fx = crate::channel::fixture::Fixture::new(2, 3);
        let node = Arc::new(
            crate::test_support::load_node(&fx.config(0, 3_600, "")).expect("channel fixture node"),
        );
        let now = crate::unix_now();
        let expiry = now + 7_200;

        let hot = fx.spend_psbt(&fx.hot_spk, 7);
        let mut hot_request = fx.spend_request(&hot, expiry, "k0t-conflicted-hot");
        // Match the demo: the pending hot request's mandatory escape sweeps both
        // vault coins, so it is distinct from the later one-input clawback.
        hot_request.escape_psbt = fx.two_input_spend_psbt(&fx.escape_spk).to_string();
        fx.coord_sign(&mut hot_request, "k0t-conflicted-hot");
        let hot_id = match crate::handle_sign(&node, &hot_request, now).expect("decodable") {
            SignResponse::Accepted(accepted) => accepted.commitment_id,
            other => panic!("the hot spend must be pending: {other:?}"),
        };

        // A distinct escape-class request spends the hot candidate's input and carries
        // a disjoint residual, matching `demo theft-refused`'s clawback shape.
        let clawback = fx.spend_psbt(&fx.escape_spk, 7);
        let residual = fx.spend_psbt(&fx.escape_spk, 8);
        let mut clawback_request = fx.spend_request(&clawback, expiry, "k0t-independent-clawback");
        clawback_request.escape_psbt = residual.to_string();
        fx.coord_sign(&mut clawback_request, "k0t-independent-clawback");
        let clawback_id =
            match crate::handle_sign(&node, &clawback_request, now).expect("decodable") {
                SignResponse::Accepted(accepted) => accepted.commitment_id,
                other => panic!("the escape-class clawback must be accepted: {other:?}"),
            };
        assert_eq!(
            node.pending_projection(now).pending,
            vec![hot_id.clone()],
            "escape-class candidates themselves are never pending"
        );
        // The control for the claim below: before the clawback settles, the defeated
        // candidate is unlatched, i.e. one a later tick could still combine and send.
        let channel = node.channel.as_ref().expect("channel");
        assert_eq!(
            channel.candidate_is_broadcast(&hot_id),
            Some(false),
            "the hot candidate must be unlatched before the clawback settles, or the \
             assertion after it proves nothing"
        );

        crate::settle_candidate(&node, channel, &clawback_id);
        assert!(
            node.pending_projection(now).pending.is_empty(),
            "a settled conflicting clawback must remove the hot candidate it invalidated"
        );
        assert_eq!(
            channel.candidate_is_broadcast(&hot_id),
            Some(true),
            "a candidate dropped from /pending must also leave the due set (`due_for_fire` \
             gates on this flag): otherwise an evicted clawback lets the defeated spend \
             fire at its Hold expiry with nothing on the surface that exists to show it"
        );
    }

    /// THE STRUCTURAL GUARANTEE, made a test: the projection never reads the channel
    /// store. That store is where EVERY piece of duress state lives — arm intents, `T`,
    /// Armed-vs-Scheduled, the sweep and its ladder — so a handler that cannot touch it
    /// cannot leak it, whatever fields a later edit adds. Answering while the store is
    /// held is how that is observable from outside.
    ///
    /// Same three-worker production shape as
    /// [`healthz_answers_while_the_channel_store_is_held`]: the deadline and fire
    /// driver prologues occupy two workers on the held store, leaving one to poll the
    /// listener and this handler.
    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    async fn pending_answers_while_the_channel_store_is_held() {
        let fx = crate::channel::fixture::Fixture::new(2, 3);
        let node = Arc::new(
            crate::test_support::load_node(&fx.config(0, 0, "")).expect("channel fixture node"),
        );
        let addr = spawn_app(app(Arc::clone(&node))).await;

        let gate = Arc::clone(&node);
        let (held_tx, held_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let holder = std::thread::spawn(move || {
            gate.channel
                .as_ref()
                .expect("channel")
                .hold_store_until(&held_tx, &release_rx);
        });
        held_rx.recv().expect("store held");

        let deadline_node = Arc::clone(&node);
        let (deadline_entered_tx, deadline_entered_rx) = tokio::sync::oneshot::channel();
        let deadline_waiter = tokio::spawn(async move {
            let _ = deadline_entered_tx.send(());
            deadline_node
                .channel
                .as_ref()
                .expect("channel")
                .lockdown_due(0)
        });
        let fire_node = Arc::clone(&node);
        let (fire_entered_tx, fire_entered_rx) = tokio::sync::oneshot::channel();
        let fire_waiter = tokio::spawn(async move {
            let _ = fire_entered_tx.send(());
            fire_node.channel.as_ref().expect("channel").prune_store(0);
        });
        deadline_entered_rx.await.expect("deadline task entered");
        fire_entered_rx.await.expect("fire task entered");
        tokio::task::yield_now().await;

        let probe = std::thread::spawn(move || {
            let result = get_with_timeout(addr, "/pending", Duration::from_secs(2))
                .map_err(|e| format!("/pending blocked behind a held channel store: {e}"));
            let _ = release_tx.send(());
            result
        });
        let (status, body) = spawn_blocking(move || probe.join().expect("probe thread"))
            .await
            .expect("probe task")
            .expect("/pending store isolation");
        assert_eq!(status, 200);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&body).expect("pending json"),
            serde_json::json!({ "pending": [] })
        );
        holder.join().expect("holder thread");
        assert!(!deadline_waiter.await.expect("deadline waiter"));
        fire_waiter.await.expect("fire waiter");
    }

    /// At most one `/pending` snapshot may wait behind `sign_state`. Without this
    /// pre-lock bound, a local poll flood during `/sign`'s memory-hard PIN work could
    /// occupy the whole blocking pool and queue the fire path behind observational work.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn pending_sheds_concurrent_reads_before_the_sign_lock() {
        let (node, _request) = node_and_valid_request();
        let node = Arc::new(node);
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let addr = spawn_app(app_with_pending_entry(Arc::clone(&node), entered_tx)).await;

        let gate = Arc::clone(&node);
        let (held_tx, held_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let holder = std::thread::spawn(move || {
            let _guard = gate.sign_state.lock().expect("sign_state lock");
            held_tx.send(()).expect("held signal");
            release_rx.recv().expect("release signal");
        });
        held_rx.recv().expect("sign_state held");

        let first =
            std::thread::spawn(move || get_with_timeout(addr, "/pending", Duration::from_secs(5)));
        spawn_blocking(move || entered_rx.recv())
            .await
            .expect("entry waiter")
            .expect("first pending entered");

        let started = Instant::now();
        let (status, _) =
            spawn_blocking(move || get_with_timeout(addr, "/pending", Duration::from_secs(2)))
                .await
                .expect("second client task")
                .expect("second pending response");
        assert_eq!(status, 429);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "the second read queued behind sign_state instead of being shed"
        );

        release_tx.send(()).expect("release sign_state");
        holder.join().expect("holder thread");
        assert_eq!(
            first
                .join()
                .expect("first client thread")
                .expect("first pending response")
                .0,
            200
        );
    }

    /// The shed bound above survives CANCELLATION, which is the only way it is worth
    /// anything: `spawn_blocking` detaches, so a permit released with the handler
    /// future would let a poller connect-and-drop in a loop and park an unbounded
    /// number of blocking workers on `sign_state` — the contention the bound exists to
    /// keep off the fire path.
    ///
    /// Driven at the future level rather than over a socket, because that makes the
    /// cancellation exact instead of a race with the runtime noticing a closed
    /// connection: one poll leaves the job in flight, and dropping the future is
    /// precisely what axum does when the client disconnects.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn pending_holds_its_permit_when_the_client_disconnects() {
        use std::future::Future;
        use std::task::Poll;

        let (node, _request) = node_and_valid_request();
        let node = Arc::new(node);
        let permits = Arc::new(Semaphore::new(PENDING_MAX_CONCURRENCY));
        let state = AppState {
            node: Arc::clone(&node),
            handler_timeout: HANDLER_TIMEOUT,
            channel_body_timeout: CHANNEL_BODY_READ_TIMEOUT,
            pending_concurrency: Arc::clone(&permits),
            sign_entered: None,
            pending_entered: None,
        };

        let gate = Arc::clone(&node);
        let (held_tx, held_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let holder = std::thread::spawn(move || {
            let _guard = gate.sign_state.lock().expect("sign_state lock");
            held_tx.send(()).expect("held signal");
            release_rx.recv().expect("release signal");
        });
        held_rx.recv().expect("sign_state held");

        let mut handler = Box::pin(pending(State(state)));
        std::future::poll_fn(|cx| {
            assert!(
                handler.as_mut().poll(cx).is_pending(),
                "the snapshot must still be parked on the held sign_state"
            );
            Poll::Ready(())
        })
        .await;
        assert_eq!(permits.available_permits(), 0, "the read took the permit");
        // The disconnect.
        drop(handler);
        assert_eq!(
            permits.available_permits(),
            0,
            "a cancelled /pending released its permit while its blocking job stayed \
             parked on sign_state: the shed bound is bypassable by connect-and-drop"
        );

        release_tx.send(()).expect("release sign_state");
        holder.join().expect("holder thread");
    }

    /// `/pending` is a projection, not a control surface: `GET`-only, so it adds no way
    /// to cancel, accelerate, or otherwise influence a candidate.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn pending_is_read_only() {
        let (node, _request) = node_and_valid_request();
        let addr = spawn_app(app(Arc::new(node))).await;
        let (status, _) = spawn_blocking(move || post(addr, "/pending", "{}"))
            .await
            .expect("client task");
        assert_eq!(status, 405, "/pending must not accept a mutating verb");
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
        fn block_hash_at(&self, _height: u32) -> Result<Option<bitcoin::BlockHash>, Error> {
            self.signal_entered();
            std::thread::sleep(self.delay);
            Ok(None)
        }
        fn spends_of(
            &self,
            _scripts: &[ScriptBuf],
            _from_height: u32,
            _through_height: u32,
            _expected_parent: Option<bitcoin::BlockHash>,
        ) -> Result<crate::chain::ScanTraversal, Error> {
            self.signal_entered();
            std::thread::sleep(self.delay);
            Ok(crate::chain::ScanTraversal {
                spends: Vec::new(),
                blocks: Vec::new(),
            })
        }
        // This backend exists to stall the watchtower scan; the fire path is not
        // under test here, so its three methods are unreachable stubs.
        fn prevout(&self, _outpoint: &OutPoint) -> Result<Option<Prevout>, Error> {
            Err("SlowBackend has no chain view".into())
        }
        fn vault_unspent(
            &self,
            _scripts: &[ScriptBuf],
            _authorized: &std::collections::HashSet<Txid>,
        ) -> Result<Vec<(OutPoint, Prevout)>, Error> {
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
        crate::test_support::coord_sign(&mut second, &node.wallet_id, "concurrent-retry");
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
        crate::test_support::coord_sign(&mut retry, &node.wallet_id, "resubmit-after-408");
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
