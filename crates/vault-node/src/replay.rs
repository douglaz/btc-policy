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
