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
}
