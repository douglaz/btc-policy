//! The anti-replay log (DESIGN.md, "What the anti-replay log is — and is not").
//!
//! An in-memory map from `commitment_id` to the verdict the node recorded for
//! that exact transaction. Its jobs are idempotency and audit — it does **not**
//! defend the signature (V0-1's sighash binding does). It is keyed by
//! commitment hash, **never** by outpoint set, so an RBF replacement or a
//! rebroadcast is a fresh commitment and is never blocked as a replay.
//!
//! Entries are pruned once their expiry has passed, so retention is bounded by
//! each commitment's node-capped expiry. `now` is always a parameter, never a
//! read of the system clock, so every path is deterministically testable.

use std::collections::HashMap;

use vault_proto::SignResponse;

/// One recorded decision, retained until its commitment expires.
struct Entry {
    /// The commitment's expiry (unix seconds); the prune horizon.
    expiry: u64,
    /// The verdict to replay on an identical resubmission.
    verdict: SignResponse,
}

/// The `/sign` handler's mutable state: the anti-replay log and the Hold-timer
/// pending log, bundled under ONE lock (`Mutex<SignState>` in [`crate::Node`]).
///
/// The old sequential serve loop gave `handle_sign` end-to-end atomicity for
/// free — its check-then-update sequences over these two logs could never
/// interleave. Under axum requests are concurrent, so the two logs move under a
/// single lock held across the whole `handle_sign` call. Two SEPARATE locks are
/// forbidden: an interleaved check/update between two concurrent identical
/// requests would corrupt replay semantics, so both logs must move together.
#[derive(Default)]
pub(crate) struct SignState {
    pub(crate) replay: ReplayLog,
    pub(crate) pending: PendingLog,
    /// Seen coordinator-request nonces (ADR-0013 §2/§3). Under the same one lock
    /// so the check-then-record at ingress is atomic with the rest of `/sign`.
    pub(crate) coord_nonces: NonceLog,
}

/// In-memory anti-replay log: `commitment_id -> recorded verdict`.
#[derive(Default)]
pub(crate) struct ReplayLog {
    entries: HashMap<String, Entry>,
}

impl ReplayLog {
    /// The recorded verdict for `commitment_id` if one exists and has not yet
    /// expired at `now`. An expired entry is treated as absent (it is removed
    /// by [`ReplayLog::prune`]).
    pub(crate) fn get(&self, commitment_id: &str, now: u64) -> Option<SignResponse> {
        self.entries
            .get(commitment_id)
            .filter(|entry| entry.expiry > now)
            .map(|entry| entry.verdict.clone())
    }

    /// Record `verdict` under `commitment_id`, retained until `expiry`.
    pub(crate) fn record(&mut self, commitment_id: String, expiry: u64, verdict: SignResponse) {
        self.entries
            .insert(commitment_id, Entry { expiry, verdict });
    }

    /// Drop every entry whose expiry has passed, bounding retention time.
    pub(crate) fn prune(&mut self, now: u64) {
        self.entries.retain(|_, entry| entry.expiry > now);
    }

    /// Number of recorded verdicts. Test-only: the concurrency and no-cancel
    /// regressions assert exactly one entry is recorded (no double-accept, no
    /// ghost half-run).
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}

/// One hot-class commitment's Hold timer (ADR-0004), retained until expiry.
///
/// **Timer-only by design** — this stores when the commitment was first seen,
/// **never the PSBT**. This resolves the V0-2 commitment/tx-identity question:
/// on re-submission the node re-verifies the resubmitted PSBT in full (PIN,
/// user-sig/sighash, policy) and signs the PSBT *in hand*, never a stored one.
/// The commitment binds every field of the exact unsigned transaction,
/// including version, nLockTime, and each input's nSequence, so distinct
/// transactions cannot share a timer. On re-submission the node still verifies
/// and signs the PSBT in hand; nothing recorded here can be replayed into a
/// signature — the timer only decides *when* signing is allowed, not *what*
/// gets signed.
struct PendingEntry {
    /// Unix seconds when this node first saw the commitment; the Hold's start.
    first_seen: u64,
    /// The commitment's expiry (unix seconds); the prune horizon, exactly as
    /// [`ReplayLog`] uses it.
    expiry: u64,
}

/// In-memory Hold timers: `commitment_id -> first_seen`. A sibling of
/// [`ReplayLog`] with the same expiry-pruned, `now`-as-a-parameter discipline,
/// so every Hold path is deterministically testable.
#[derive(Default)]
pub(crate) struct PendingLog {
    entries: HashMap<String, PendingEntry>,
}

impl PendingLog {
    /// The `first_seen` recorded for `commitment_id` if a live (unexpired at
    /// `now`) pending entry exists. An expired entry reads as absent.
    pub(crate) fn first_seen(&self, commitment_id: &str, now: u64) -> Option<u64> {
        self.entries
            .get(commitment_id)
            .filter(|entry| entry.expiry > now)
            .map(|entry| entry.first_seen)
    }

    /// Start `commitment_id`'s Hold timer at `first_seen`, retained until
    /// `expiry`. The handler calls this only on genuine first sight (it reads
    /// [`PendingLog::first_seen`] first), so the timer never resets on
    /// re-submission.
    pub(crate) fn record(&mut self, commitment_id: String, first_seen: u64, expiry: u64) {
        self.entries
            .insert(commitment_id, PendingEntry { first_seen, expiry });
    }

    /// Drop every timer whose commitment has expired, bounding retention.
    pub(crate) fn prune(&mut self, now: u64) {
        self.entries.retain(|_, entry| entry.expiry > now);
    }

    /// Number of live Hold timers. Test-only (see [`ReplayLog::len`]).
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}

/// Maximum wire length of one coordinator nonce. The demo emits 32 random bytes
/// as 64 hex characters; accepting any non-empty value up to that size keeps the
/// v0 wire format permissive while making each retained key's memory bounded.
pub(crate) const MAX_COORD_NONCE_BYTES: usize = 64;

/// Maximum number of live coordinator nonces. A coordinator-authenticated flood
/// can make the node refuse new work, but cannot grow this security state without
/// bound and exhaust the signer process.
pub(crate) const MAX_COORD_NONCES: usize = 4_096;

/// Result of atomically checking freshness and consuming a coordinator nonce.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum NonceDecision {
    Accepted,
    InvalidLength,
    OutsideWindow { now: u64 },
    Replayed,
    AtCapacity,
}

/// Seen coordinator-request nonces (ADR-0013 §2/§3): `nonce -> expiry`. A sibling
/// of [`ReplayLog`] with the same expiry-pruned, `now`-as-a-parameter discipline.
///
/// A coordinator nonce is **single-use**: the coordinator issues a fresh one per
/// request, so once a nonce is recorded here a captured request cannot be replayed
/// to make the node act again. This is orthogonal to the anti-replay log — that
/// keys on the transaction commitment and serves idempotency; this keys on the
/// per-request nonce and serves freshness. Retention is bounded by expiry and a
/// fixed entry cap. The monotonic `high_water` closes a wall-clock rollback hole:
/// when an accepted request prunes a nonce, the mark advances through the greatest
/// expiry actually forgotten, so a later backwards clock step cannot make that
/// request fresh again. The mark does not copy the raw clock: a transient forward
/// excursion therefore cannot latch an unrelated bogus value merely because a
/// request was accepted. The future-expiry cap still uses the node's raw clock, so
/// rollback protection cannot widen the required `now + max_age` acceptance
/// horizon.
///
/// `high_water` advances ONLY through expiries pruned by a request accepted by the
/// complete freshness gate. Both halves of that rule matter:
///
/// * Ratcheting on a *rejected* request would let one transient forward clock
///   excursion (NTP step, VM restore, RTC fault) latch the mark at a bogus future
///   value and refuse honestly-timed requests after the clock corrects. A request
///   that fails the window, replay, or capacity check therefore leaves both the
///   mark and entries untouched.
/// * Pruning without ratcheting through every removed expiry would drop nonces the
///   mark will not remember, reopening the very rollback hole the mark exists to
///   close. So the two move together, or not at all.
#[derive(Default)]
pub(crate) struct NonceLog {
    /// `nonce -> expiry` (unix seconds); the prune horizon, exactly as the other
    /// two logs use it.
    entries: HashMap<String, u64>,
    /// Highest expiry of a coordinator nonce removed from `entries`.
    high_water: u64,
}

impl NonceLog {
    /// Apply the complete post-auth freshness decision atomically. The caller
    /// invokes this only after `coord_sig` verifies, so forged traffic cannot
    /// advance the high-water mark or consume capacity.
    pub(crate) fn check_and_record(
        &mut self,
        nonce: &str,
        expiry: u64,
        now_input: u64,
        max_age: u64,
    ) -> NonceDecision {
        // Never let the freshness lower bound read further back than an accepted
        // request has already established; a rollback cannot revive a pruned nonce.
        let effective_now = self.high_water.max(now_input);

        if nonce.is_empty() || nonce.len() > MAX_COORD_NONCE_BYTES {
            return NonceDecision::InvalidLength;
        }
        if expiry <= effective_now {
            return NonceDecision::OutsideWindow { now: effective_now };
        }
        // The retention cap is defined against the node's own clock, not the
        // rollback high-water. Using effective_now here would widen the horizon
        // after a backwards clock step.
        if expiry > now_input.saturating_add(max_age) {
            return NonceDecision::OutsideWindow { now: now_input };
        }
        // Check only live entries before mutating anything. A rejected replay or
        // capacity refusal must not ratchet time or prune state under a transient
        // clock reading.
        if self
            .entries
            .get(nonce)
            .is_some_and(|seen_expiry| *seen_expiry > effective_now)
        {
            return NonceDecision::Replayed;
        }
        let live_entries = self
            .entries
            .values()
            .filter(|seen_expiry| **seen_expiry > effective_now)
            .count();
        if live_entries >= MAX_COORD_NONCES {
            return NonceDecision::AtCapacity;
        }

        // Accepted: prune under effective time and advance the mark through every
        // expiry actually forgotten (see the type docstring). Copying
        // `effective_now` would latch a transiently bogus raw clock even when no
        // nonce with that expiry was removed.
        let mut pruned_through = self.high_water;
        self.entries.retain(|_, seen_expiry| {
            let keep = *seen_expiry > effective_now;
            if !keep {
                pruned_through = pruned_through.max(*seen_expiry);
            }
            keep
        });
        self.high_water = pruned_through;
        self.entries.insert(nonce.to_owned(), expiry);
        NonceDecision::Accepted
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_proto::{Refusal, RefusalCode};

    fn signed() -> SignResponse {
        SignResponse::Signed("cHNidP8B".into())
    }

    fn refused() -> SignResponse {
        SignResponse::Refusal(Refusal {
            code: RefusalCode::DestNotAllowed,
            check: "destination_allowlist".into(),
            detail: "nope".into(),
        })
    }

    #[test]
    fn records_and_returns_the_recorded_verdict() {
        let mut log = ReplayLog::default();
        log.record("abc".into(), 1_000, signed());
        assert_eq!(log.get("abc", 500), Some(signed()));
        // A different id is unknown.
        assert_eq!(log.get("def", 500), None);
    }

    #[test]
    fn an_expired_entry_reads_as_absent_and_prunes_away() {
        let mut log = ReplayLog::default();
        log.record("a".into(), 1_000, signed());
        log.record("b".into(), 2_000, refused());
        assert_eq!(log.entries.len(), 2);

        // At now = 1_000 the first entry has expired (expiry is exclusive).
        assert_eq!(log.get("a", 1_000), None);
        assert_eq!(log.get("b", 1_000), Some(refused()));

        // Pruning removes only the expired entry: state stays bounded.
        log.prune(1_000);
        assert_eq!(log.entries.len(), 1);
        assert!(log.get("a", 1_000).is_none());
        assert_eq!(log.get("b", 1_000), Some(refused()));

        // Once every entry has expired, pruning empties the log.
        log.prune(2_000);
        assert_eq!(log.entries.len(), 0);
    }

    #[test]
    fn nonce_log_records_rejects_replays_and_expires() {
        let mut log = NonceLog::default();
        assert_eq!(
            log.check_and_record("n1", 1_000, 500, 1_000),
            NonceDecision::Accepted
        );
        assert_eq!(
            log.check_and_record("n1", 1_000, 600, 1_000),
            NonceDecision::Replayed
        );
        // At expiry the old entry prunes. Reusing the string under a new signed
        // request with a later expiry is fresh; expiry is exclusive.
        assert_eq!(
            log.check_and_record("n1", 2_000, 1_000, 1_000),
            NonceDecision::Accepted
        );
        assert_eq!(log.entries.len(), 1);
    }

    #[test]
    fn nonce_log_time_never_regresses_after_pruning() {
        let mut log = NonceLog::default();
        assert_eq!(
            log.check_and_record("old", 1_000, 500, 1_000),
            NonceDecision::Accepted
        );
        // Authenticated time reaches the old request's expiry and prunes it.
        assert_eq!(
            log.check_and_record("new", 2_000, 1_000, 1_000),
            NonceDecision::Accepted
        );
        // A backwards wall-clock step cannot reopen the old signed request even
        // though its nonce is no longer retained.
        assert_eq!(
            log.check_and_record("old", 1_000, 600, 1_000),
            NonceDecision::OutsideWindow { now: 1_000 }
        );
    }

    #[test]
    fn a_rejected_request_never_ratchets_time_forward() {
        let mut log = NonceLog::default();
        assert_eq!(
            log.check_and_record("n1", 1_500, 1_000, 1_000),
            NonceDecision::Accepted
        );

        // The host clock steps far forward (NTP correction, VM restore). Requests
        // timed against the TRUE clock now read as expired and are refused...
        assert_eq!(
            log.check_and_record("n2", 1_600, 9_000_000, 1_000),
            NonceDecision::OutsideWindow { now: 9_000_000 }
        );
        // ...but refusing them must not record the bogus time. Once the clock is
        // corrected the node keeps working; a latched mark would expire every
        // honestly-timed request until wall time caught up, and docs/adr/0007
        // forbids restarting out of it.
        assert_eq!(
            log.check_and_record("n2", 1_600, 1_100, 1_000),
            NonceDecision::Accepted
        );

        // Advancing far enough to expire n1 prunes it and records exactly the
        // forgotten expiry, so a backwards step cannot reopen that request.
        assert_eq!(
            log.check_and_record("advance", 2_000, 1_500, 1_000),
            NonceDecision::Accepted
        );
        assert_eq!(
            log.check_and_record("n3", 1_450, 500, 1_000),
            NonceDecision::OutsideWindow { now: 1_500 }
        );
    }

    #[test]
    fn an_accepted_request_during_a_forward_clock_step_does_not_latch_raw_time() {
        let mut log = NonceLog::default();
        assert_eq!(
            log.check_and_record("old", 1_500, 1_000, 1_000),
            NonceDecision::Accepted
        );

        // The node and coordinator briefly share the same bogus future clock, so
        // the request is valid against both sides of the window and is accepted.
        assert_eq!(
            log.check_and_record("excursion", 9_000_500, 9_000_000, 1_000),
            NonceDecision::Accepted
        );
        // Only the old nonce's forgotten expiry is needed for rollback safety;
        // recording raw 9_000_000 here would wedge the corrected node.
        assert_eq!(log.high_water, 1_500);

        // Once the clock corrects, an honestly timed request remains admissible.
        assert_eq!(
            log.check_and_record("fresh", 1_600, 1_100, 1_000),
            NonceDecision::Accepted
        );
    }

    #[test]
    fn a_replay_during_a_forward_clock_step_does_not_ratchet_time() {
        let mut log = NonceLog::default();
        assert_eq!(
            log.check_and_record("old", 1_200, 500, 1_000),
            NonceDecision::Accepted
        );
        assert_eq!(
            log.check_and_record("seen", 2_000, 1_000, 1_000),
            NonceDecision::Accepted
        );
        assert_eq!(log.entries.len(), 2);

        // The clock steps forward but stays below the signed expiry. This is still
        // a replay, and refusing it must neither latch the transient clock reading
        // nor prune an entry that is still live once the clock corrects.
        assert_eq!(
            log.check_and_record("seen", 2_000, 1_500, 1_000),
            NonceDecision::Replayed
        );
        assert_eq!(log.high_water, 0);
        assert!(log.entries.contains_key("old"));

        // Once the clock corrects, the old nonce is still a replay and an
        // honestly-timed fresh request remains admissible.
        assert_eq!(
            log.check_and_record("old", 1_200, 1_100, 1_000),
            NonceDecision::Replayed
        );
        assert_eq!(
            log.check_and_record("fresh", 1_400, 1_100, 1_000),
            NonceDecision::Accepted
        );
    }

    #[test]
    fn future_expiry_cap_uses_the_raw_node_clock_after_rollback() {
        let mut log = NonceLog::default();
        assert_eq!(
            log.check_and_record("old", 1_000, 500, 1_000),
            NonceDecision::Accepted
        );
        assert_eq!(
            log.check_and_record("first", 1_500, 1_000, 1_000),
            NonceDecision::Accepted
        );

        // After a backwards clock step the high-water remains the stale lower
        // bound, but it must not widen the upper bound beyond raw now + max_age.
        assert_eq!(
            log.check_and_record("too-far", 1_700, 600, 1_000),
            NonceDecision::OutsideWindow { now: 600 }
        );
        assert_eq!(log.high_water, 1_000);
    }

    #[test]
    fn nonce_log_bounds_key_size_and_entry_count() {
        let mut log = NonceLog::default();
        assert_eq!(
            log.check_and_record("", 2_000, 1_000, 1_000),
            NonceDecision::InvalidLength
        );
        assert_eq!(
            log.check_and_record(&"x".repeat(MAX_COORD_NONCE_BYTES), 2_000, 1_000, 1_000),
            NonceDecision::Accepted
        );
        assert_eq!(
            log.check_and_record(&"x".repeat(MAX_COORD_NONCE_BYTES + 1), 2_000, 1_000, 1_000),
            NonceDecision::InvalidLength
        );
        for i in 1..MAX_COORD_NONCES {
            assert_eq!(
                log.check_and_record(&format!("n{i}"), 2_000, 1_000, 1_000),
                NonceDecision::Accepted
            );
        }
        // Even an in-window request observed during a forward clock step must not
        // ratchet the mark when capacity makes the request a refusal.
        assert_eq!(
            log.check_and_record("one-too-many", 2_000, 1_500, 1_000),
            NonceDecision::AtCapacity
        );
        assert_eq!(log.high_water, 0);
        assert_eq!(log.entries.len(), MAX_COORD_NONCES);
    }

    #[test]
    fn pending_records_first_seen_and_expires_like_the_replay_log() {
        let mut log = PendingLog::default();
        log.record("abc".into(), 500, 1_000);
        // Readable while unexpired, absent once expiry has passed.
        assert_eq!(log.first_seen("abc", 600), Some(500));
        assert_eq!(log.first_seen("abc", 1_000), None);
        assert_eq!(log.first_seen("def", 600), None);
        // Pruning at expiry drops it, keeping the map bounded.
        log.prune(1_000);
        assert_eq!(log.entries.len(), 0);
    }
}
