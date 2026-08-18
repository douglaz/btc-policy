//! The anti-replay log (DESIGN.md, "What the anti-replay log is — and is not").
//!
//! An in-memory map from a decision identity to the verdict the node recorded.
//! Transaction-determined refusals use the `commitment_id`; accepted decisions
//! use a hash of the complete candidate set (commitment ids + ingress PSBTs), so
//! a different user-signature instance or mandatory escape cannot replay an
//! unrelated acceptance. Its jobs are idempotency and audit — it does **not**
//! defend the signature (V0-1's sighash binding does). No key is an outpoint set,
//! so an RBF replacement is a fresh commitment and is never blocked as a replay.
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
/// free. Under axum requests are concurrent, so one lock protects the handler's
/// three separate holds (bead btc-policy-9zs): coordinator freshness is consumed
/// atomically in the INGRESS hold, before the out-of-lock PIN window; the COMMIT
/// hold re-decides Lockdown and the clock predicates after it; then every
/// replay/pending check-and-update runs under one continuous registration guard
/// after the out-of-lock chain preflight (the "phase 2" the older comments name).
/// An exact replay cannot enter either gap because its nonce is already
/// consumed. Two SEPARATE state locks remain forbidden: replay and pending updates
/// must move together.
#[derive(Default)]
pub(crate) struct SignState {
    pub(crate) replay: ReplayLog,
    pub(crate) pending: PendingLog,
    /// Seen coordinator-request nonces (ADR-0013 §2/§3). Under the same one lock
    /// so the check-then-record at ingress is atomic with the rest of `/sign`.
    pub(crate) coord_nonces: NonceLog,
    /// Per-coin refresh times (ADR-0013 §6). Under the same one lock so the
    /// interval check-then-record cannot interleave with a concurrent refresh.
    pub(crate) refreshes: RefreshLog,
    /// The pin-attempt budget (ADR-0013 §7). Under the same one lock so the
    /// wrong-pin check-then-charge is atomic with the rest of `/sign` — two
    /// concurrent wrong pins cannot both read `fails = k` and both write `k+1`.
    pub(crate) pin_budget: crate::pin::AttemptBudget,
}

#[cfg(test)]
impl SignState {
    /// A canonical projection of the WHOLE `/sign` handler state, for the
    /// constant-observable-ingress comparison in `channel::duress`
    /// (`normal_and_duress_ingress_op_sequences_*`).
    ///
    /// It is the `StoreShape` idea applied to the state that lives under the `/sign`
    /// lock rather than in the channel store, and it exists for the same reason: the
    /// ingress op log and `ScheduleWorkTrace` are WHITELISTS of hand-placed
    /// instrumentation, so a duress-only mutation made anywhere they do not watch
    /// appends nothing to either. This one is read off the fields, so it sees such a
    /// mutation wherever in `SignState` it lands. The one site that matters most is
    /// [`crate::pin::AttemptBudget::charge`], which takes the PIN VERDICT itself as an
    /// argument — the only place in this struct the verdict reaches at all.
    ///
    /// Nothing is masked. Every value below is pin-independent by construction for the
    /// request pairs that use it: a pair re-signs the SAME coordinator nonce over the
    /// SAME transaction pair at the same `now`, so the nonce log, the commitment-keyed
    /// replay and pending logs, and the recorded verdict all coincide; and normal and
    /// duress are the two classes `charge` treats identically (only a WRONG pin moves
    /// the budget). A difference in any row is therefore a real asymmetry, not a
    /// by-design one — unlike the channel store's pin-derived carrier ids.
    ///
    /// Every struct is destructured exhaustively, here and in
    /// [`crate::pin::AttemptBudget::shape`]. That is part of the gate, not style:
    /// adding a field must fail the build until this projection records it.
    pub(crate) fn shape(&self) -> Vec<String> {
        let SignState {
            replay,
            pending,
            coord_nonces,
            refreshes,
            pin_budget,
        } = self;

        let ReplayLog { entries } = replay;
        let mut lines = vec![format!("replay count={}", entries.len())];
        let mut rows: Vec<String> = entries
            .iter()
            .map(|(key, entry)| {
                let Entry { expiry, verdict } = entry;
                format!("replay key={key} expiry={expiry} verdict={verdict:?}")
            })
            .collect();
        rows.sort();
        lines.extend(rows);

        let PendingLog { entries } = pending;
        lines.push(format!("pending count={}", entries.len()));
        let mut rows: Vec<String> = entries
            .iter()
            .map(|(commitment_id, expiry)| format!("pending id={commitment_id} expiry={expiry}"))
            .collect();
        rows.sort();
        lines.extend(rows);

        let NonceLog {
            entries,
            high_water,
        } = coord_nonces;
        lines.push(format!(
            "coord_nonces count={} high_water={high_water}",
            entries.len()
        ));
        let mut rows: Vec<String> = entries
            .iter()
            .map(|(nonce, entry)| {
                // UNMASKED: `carrier_deadline` is fixed from the channel's monotonic
                // clock, coordinator-signed E, and node-derived effective W, so it is
                // pin-independent by construction for a request pair.
                let NonceEntry {
                    expiry,
                    carrier_deadline,
                } = entry;
                format!("coord_nonce nonce={nonce} expiry={expiry} deadline={carrier_deadline:?}")
            })
            .collect();
        rows.sort();
        lines.extend(rows);

        let RefreshLog { entries } = refreshes;
        lines.push(format!("refreshes count={}", entries.len()));
        let mut rows: Vec<String> = entries
            .iter()
            .map(|(outpoint, at)| format!("refresh outpoint={outpoint} at={at}"))
            .collect();
        rows.sort();
        lines.extend(rows);

        lines.push(pin_budget.shape());
        lines
    }
}

/// In-memory anti-replay log: `decision identity -> recorded verdict`.
#[derive(Default)]
pub(crate) struct ReplayLog {
    entries: HashMap<String, Entry>,
}

impl ReplayLog {
    /// The recorded verdict for `key` if one exists and has not yet
    /// expired at `now`. An expired entry is treated as absent (it is removed
    /// by [`ReplayLog::prune`]).
    pub(crate) fn get(&self, key: &str, now: u64) -> Option<SignResponse> {
        self.entries
            .get(key)
            .filter(|entry| entry.expiry > now)
            .map(|entry| entry.verdict.clone())
    }

    /// Record `verdict` under `key`, retained until `expiry`.
    pub(crate) fn record(&mut self, key: String, expiry: u64, verdict: SignResponse) {
        self.entries.insert(key, Entry { expiry, verdict });
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

/// The set of PENDING SPENDS: `commitment_id -> that commitment's expiry`.
///
/// Under Model B (ADR-0012) this is no longer a Hold *timer*. The Hold used to
/// live here because signing waited for a re-submission, and the log had to
/// remember when the clock started. Model B signs at ingress and there is no
/// re-submission — a spend's fire time lives on its candidate, which is what the
/// fire driver reads — so nothing needs `first_seen` any more and the log is now
/// pure membership: **is any spend pending on this vault?**
///
/// That one question is what refresh subordination asks (ADR-0012: "while any
/// normal-path spend is pending, a refresh is queued behind it"), and the expiry
/// is what bounds it: a spend kept perpetually pending to block refreshes dies
/// with its commitment. Denial, never theft.
///
/// It stores no PSBT and never has: nothing recorded here can be replayed into a
/// signature, because it decides only *whether a spend is outstanding*, never
/// *what* gets signed. That property became load-bearing a second time in bead
/// btc-policy-k0t, which projects this log — and ONLY this log — onto the read-only
/// `GET /pending` surface: see [`crate::PendingProjection`] for why an
/// `id -> expiry` map written on `class == Hot` alone, cleared only by an
/// on-the-network settlement (including a conflicting implicit-cancel transaction)
/// or commitment expiry, cannot carry a pin class.
#[derive(Default)]
pub(crate) struct PendingLog {
    /// `commitment_id -> expiry` (unix seconds); the prune horizon, exactly as
    /// [`ReplayLog`] uses it.
    entries: HashMap<String, u64>,
}

impl PendingLog {
    /// Record `commitment_id` as a pending spend until `expiry`.
    pub(crate) fn record(&mut self, commitment_id: String, expiry: u64) {
        self.entries.insert(commitment_id, expiry);
    }

    /// A spend stops being pending once a node successfully submits the finalized
    /// transaction. Removing an unknown id is intentionally a no-op: escape and
    /// refresh candidates were never pending, but share the broadcast path.
    pub(crate) fn remove(&mut self, commitment_id: &str) -> bool {
        self.entries.remove(commitment_id).is_some()
    }

    /// Drop every entry strictly after its commitment's final authorized second.
    /// Candidate fire windows include `now == expiry`, so refresh subordination
    /// must retain the spend through that same boundary.
    pub(crate) fn prune(&mut self, now: u64) {
        self.entries.retain(|_, expiry| *expiry >= now);
    }

    /// Whether ANY spend is pending at `now` — the REGISTERED half of the
    /// refresh-subordination predicate (ADR-0012). Deliberately a bare existence
    /// question, not "which coins does it touch?": the rule is coarse on purpose,
    /// because an input-overlap-granular version reopens the disjoint-refresh escape
    /// invalidation.
    ///
    /// A spend only lands here in `/sign`'s phase 2, so this alone does not cover one
    /// still inside its out-of-lock chain preflight; `Node::spend_preflight_in_flight`
    /// is the other half, and the refresh handler consults both (bead
    /// btc-policy-f91).
    pub(crate) fn has_any(&self, now: u64) -> bool {
        self.entries.values().any(|expiry| *expiry >= now)
    }

    /// Live pending commitment ids. Two readers, neither of which can act on the
    /// result: the fire driver uses these after a combine window closes solely to
    /// notice that a peer settled the exact spend and to release refresh
    /// subordination — it never reopens release or broadcast — and
    /// [`crate::Node::pending_projection`] serves the read-only `GET /pending`
    /// surface from them. Adding a reader that MUTATED on the strength of this list
    /// would be a different thing entirely; both of these only observe.
    pub(crate) fn ids(&self, now: u64) -> Vec<String> {
        self.entries
            .iter()
            .filter(|(_, expiry)| **expiry >= now)
            .map(|(commitment_id, _)| commitment_id.clone())
            .collect()
    }

    /// Number of live Hold timers. Test-only (see [`ReplayLog::len`]).
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}

/// Per-coin refresh times (ADR-0013 §6): `outpoint -> the unix second a refresh
/// touched it`. RAMDISK/node-lifetime like every other log here — a reboot wipes
/// the signing key too, so a rebooted machine is bare, not a fresh-interval signer.
///
/// It records BOTH a refresh's inputs and its outputs, and the outputs are the
/// load-bearing half. The burn an attacker would drive is a CHAIN — refresh A→B,
/// then B→C, then C→D — and every link spends a coin the previous refresh just
/// created. Keyed on inputs alone, each link would spend a never-before-seen
/// outpoint and no interval would ever fire. Starting the clock on the coins a
/// refresh CREATES is what makes the interval bound the rate.
#[derive(Default)]
pub(crate) struct RefreshLog {
    entries: HashMap<bitcoin::OutPoint, u64>,
}

impl RefreshLog {
    /// When a refresh last touched `outpoint`, if this node has seen one.
    pub(crate) fn last_refresh(&self, outpoint: &bitcoin::OutPoint) -> Option<u64> {
        self.entries.get(outpoint).copied()
    }

    /// Start the interval clock at `now` for every coin this refresh consumes and
    /// every coin it creates.
    pub(crate) fn record(&mut self, refresh: &bitcoin::Psbt, now: u64) {
        for input in &refresh.unsigned_tx.input {
            self.entries.insert(input.previous_output, now);
        }
        let txid = refresh.unsigned_tx.compute_txid();
        for vout in 0..refresh.unsigned_tx.output.len() as u32 {
            self.entries.insert(bitcoin::OutPoint::new(txid, vout), now);
        }
    }

    /// Drop entries older than the interval: past it they can no longer refuse
    /// anything, so retention is bounded by `refresh_min_interval_secs` rather
    /// than growing for the node's lifetime.
    pub(crate) fn prune(&mut self, now: u64, min_interval_secs: u64) {
        self.entries
            .retain(|_, at| now.saturating_sub(*at) < min_interval_secs);
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
/// A channel-mode Spend adds its acceptance-fixed Carrier deadline `D` (see
/// [`NonceEntry`]). `D = M + (E − W)` is at most one commitment age of process uptime,
/// and the entry cap still bounds the count.
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
    /// `nonce -> entry`; the wall expiry is the prune horizon, exactly as the other
    /// two logs use it, plus the monotonic half a channel-mode Spend adds.
    entries: HashMap<String, NonceEntry>,
    /// Highest expiry of a coordinator nonce removed from `entries`.
    high_water: u64,
}

/// One coordinator nonce and the clocks that retain it.
struct NonceEntry {
    /// The coordinator-signed expiry (unix seconds).
    expiry: u64,
    /// A channel-mode Spend's `D` in `HotClock` seconds; `None` for absent-channel
    /// Spend and Refresh. Inserted whole at acceptance, never recomputed or extended.
    carrier_deadline: Option<u64>,
}

impl NonceEntry {
    /// Resident while wall expiry OR Carrier deadline lives, so a different body cannot
    /// replace a live Carrier. A channel Refresh supplies `mono_now` to judge existing
    /// Spends but remains wall-only itself. Without a sample a deadline-bearing entry is
    /// live, fail-closed; that arm is defensive because `Node::channel` is construction-fixed.
    fn is_live(&self, effective_now: u64, mono_now: Option<u64>) -> bool {
        self.expiry > effective_now
            || match (self.carrier_deadline, mono_now) {
                (None, _) => false,
                (Some(_), None) => true,
                (Some(deadline), Some(mono)) => mono < deadline,
            }
    }
}

impl NonceLog {
    /// The rollback-guarded lower-bound clock shared by every piece of state whose
    /// lifetime is coupled to nonce freshness; Carrier residency instead uses its accepted `D`.
    pub(crate) fn effective_now(&self, now_input: u64) -> u64 {
        self.high_water.max(now_input)
    }

    /// The accepted channel-mode Spend deadline for `nonce`. Read back under the SAME
    /// `sign_state` hold, so it is the atomic transition's value, not a re-derivation.
    pub(crate) fn carrier_deadline(&self, nonce: &str) -> Option<u64> {
        self.entries.get(nonce)?.carrier_deadline
    }

    /// Read-only deadline authority: exact generation plus `high_water < E`; never lowers it.
    pub(crate) fn outer_stale_carrier_deadline(&self, nonce: &str, expiry: u64) -> Option<u64> {
        self.entries
            .get(nonce)
            .filter(|entry| self.high_water < expiry && entry.expiry == expiry)?
            .carrier_deadline
    }

    /// Apply the complete post-auth freshness decision atomically. The caller
    /// invokes this only after `coord_sig` verifies, so forged traffic cannot
    /// advance the high-water mark or consume capacity.
    ///
    /// `mono_now` evaluates existing deadlines; `record_carrier_deadline` allocates
    /// `D = M + (E − W)` from this decision's effective `W` only for channel-mode Spend.
    /// Absent-channel Spend and every Refresh record wall-only entries.
    pub(crate) fn check_and_record(
        &mut self,
        nonce: &str,
        expiry: u64,
        now_input: u64,
        max_age: u64,
        mono_now: Option<u64>,
        record_carrier_deadline: bool,
    ) -> NonceDecision {
        // Never let the freshness lower bound read further back than an accepted
        // request has already established; a rollback cannot revive a pruned nonce.
        let effective_now = self.effective_now(now_input);

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
            .is_some_and(|entry| entry.is_live(effective_now, mono_now))
        {
            return NonceDecision::Replayed;
        }
        let live_entries = self
            .entries
            .values()
            .filter(|entry| entry.is_live(effective_now, mono_now))
            .count();
        if live_entries >= MAX_COORD_NONCES {
            return NonceDecision::AtCapacity;
        }
        // Derive from this decision's `effective_now` before mutation. The remainder
        // cannot underflow; an unrepresentable sum fails CLOSED with the log untouched,
        // rather than saturating and pinning the key forever.
        let carrier_deadline = match mono_now.filter(|_| record_carrier_deadline) {
            None => None,
            Some(mono) => match mono.checked_add(expiry - effective_now) {
                Some(deadline) => Some(deadline),
                None => return NonceDecision::OutsideWindow { now: effective_now },
            },
        };

        // Accepted: prune under BOTH clocks and advance through expiries actually
        // forgotten. Copying `effective_now`, or an expiry retained by its monotonic
        // half, would ratchet a mark for state that was never removed.
        let mut pruned_through = self.high_water;
        self.entries.retain(|_, entry| {
            let keep = entry.is_live(effective_now, mono_now);
            if !keep {
                pruned_through = pruned_through.max(entry.expiry);
            }
            keep
        });
        self.high_water = pruned_through;
        self.entries.insert(
            nonce.to_owned(),
            NonceEntry {
                expiry,
                carrier_deadline,
            },
        );
        NonceDecision::Accepted
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_proto::{Refusal, RefusalCode};

    fn signed() -> SignResponse {
        SignResponse::Accepted(vault_proto::Accepted {
            commitment_id: "abc".into(),
            first_seen: 1_752_000_000,
            remaining_secs: 0,
        })
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
            log.check_and_record("n1", 1_000, 500, 1_000, None, false),
            NonceDecision::Accepted
        );
        assert_eq!(
            log.check_and_record("n1", 1_000, 600, 1_000, None, false),
            NonceDecision::Replayed
        );
        // At expiry the old entry prunes. Reusing the string under a new signed
        // request with a later expiry is fresh; expiry is exclusive.
        assert_eq!(
            log.check_and_record("n1", 2_000, 1_000, 1_000, None, false),
            NonceDecision::Accepted
        );
        assert_eq!(log.entries.len(), 1);
    }

    #[test]
    fn nonce_log_time_never_regresses_after_pruning() {
        let mut log = NonceLog::default();
        assert_eq!(
            log.check_and_record("old", 1_000, 500, 1_000, None, false),
            NonceDecision::Accepted
        );
        // Authenticated time reaches the old request's expiry and prunes it.
        assert_eq!(
            log.check_and_record("new", 2_000, 1_000, 1_000, None, false),
            NonceDecision::Accepted
        );
        // A backwards wall-clock step cannot reopen the old signed request even
        // though its nonce is no longer retained.
        assert_eq!(
            log.check_and_record("old", 1_000, 600, 1_000, None, false),
            NonceDecision::OutsideWindow { now: 1_000 }
        );
    }

    #[test]
    fn a_rejected_request_never_ratchets_time_forward() {
        let mut log = NonceLog::default();
        assert_eq!(
            log.check_and_record("n1", 1_500, 1_000, 1_000, None, false),
            NonceDecision::Accepted
        );

        // The host clock steps far forward (NTP correction, VM restore). Requests
        // timed against the TRUE clock now read as expired and are refused...
        assert_eq!(
            log.check_and_record("n2", 1_600, 9_000_000, 1_000, None, false),
            NonceDecision::OutsideWindow { now: 9_000_000 }
        );
        // ...but refusing them must not record the bogus time. Once the clock is
        // corrected the node keeps working; a latched mark would expire every
        // honestly-timed request until wall time caught up, and docs/adr/0007
        // forbids restarting out of it.
        assert_eq!(
            log.check_and_record("n2", 1_600, 1_100, 1_000, None, false),
            NonceDecision::Accepted
        );

        // Advancing far enough to expire n1 prunes it and records exactly the
        // forgotten expiry, so a backwards step cannot reopen that request.
        assert_eq!(
            log.check_and_record("advance", 2_000, 1_500, 1_000, None, false),
            NonceDecision::Accepted
        );
        assert_eq!(
            log.check_and_record("n3", 1_450, 500, 1_000, None, false),
            NonceDecision::OutsideWindow { now: 1_500 }
        );
    }

    #[test]
    fn an_accepted_request_during_a_forward_clock_step_does_not_latch_raw_time() {
        let mut log = NonceLog::default();
        assert_eq!(
            log.check_and_record("old", 1_500, 1_000, 1_000, None, false),
            NonceDecision::Accepted
        );

        // The node and coordinator briefly share the same bogus future clock, so
        // the request is valid against both sides of the window and is accepted.
        assert_eq!(
            log.check_and_record("excursion", 9_000_500, 9_000_000, 1_000, None, false),
            NonceDecision::Accepted
        );
        // Only the old nonce's forgotten expiry is needed for rollback safety;
        // recording raw 9_000_000 here would wedge the corrected node.
        assert_eq!(log.high_water, 1_500);

        // Once the clock corrects, an honestly timed request remains admissible.
        assert_eq!(
            log.check_and_record("fresh", 1_600, 1_100, 1_000, None, false),
            NonceDecision::Accepted
        );
    }

    #[test]
    fn a_replay_during_a_forward_clock_step_does_not_ratchet_time() {
        let mut log = NonceLog::default();
        assert_eq!(
            log.check_and_record("old", 1_200, 500, 1_000, None, false),
            NonceDecision::Accepted
        );
        assert_eq!(
            log.check_and_record("seen", 2_000, 1_000, 1_000, None, false),
            NonceDecision::Accepted
        );
        assert_eq!(log.entries.len(), 2);

        // The clock steps forward but stays below the signed expiry. This is still
        // a replay, and refusing it must neither latch the transient clock reading
        // nor prune an entry that is still live once the clock corrects.
        assert_eq!(
            log.check_and_record("seen", 2_000, 1_500, 1_000, None, false),
            NonceDecision::Replayed
        );
        assert_eq!(log.high_water, 0);
        assert!(log.entries.contains_key("old"));

        // Once the clock corrects, the old nonce is still a replay and an
        // honestly-timed fresh request remains admissible.
        assert_eq!(
            log.check_and_record("old", 1_200, 1_100, 1_000, None, false),
            NonceDecision::Replayed
        );
        assert_eq!(
            log.check_and_record("fresh", 1_400, 1_100, 1_000, None, false),
            NonceDecision::Accepted
        );
    }

    #[test]
    fn future_expiry_cap_uses_the_raw_node_clock_after_rollback() {
        let mut log = NonceLog::default();
        assert_eq!(
            log.check_and_record("old", 1_000, 500, 1_000, None, false),
            NonceDecision::Accepted
        );
        assert_eq!(
            log.check_and_record("first", 1_500, 1_000, 1_000, None, false),
            NonceDecision::Accepted
        );

        // After a backwards clock step the high-water remains the stale lower
        // bound, but it must not widen the upper bound beyond raw now + max_age.
        assert_eq!(
            log.check_and_record("too-far", 1_700, 600, 1_000, None, false),
            NonceDecision::OutsideWindow { now: 600 }
        );
        assert_eq!(log.high_water, 1_000);
    }

    #[test]
    fn nonce_log_bounds_key_size_and_entry_count() {
        let mut log = NonceLog::default();
        assert_eq!(
            log.check_and_record("", 2_000, 1_000, 1_000, None, false),
            NonceDecision::InvalidLength
        );
        assert_eq!(
            log.check_and_record(
                &"x".repeat(MAX_COORD_NONCE_BYTES),
                2_000,
                1_000,
                1_000,
                None,
                false
            ),
            NonceDecision::Accepted
        );
        assert_eq!(
            log.check_and_record(
                &"x".repeat(MAX_COORD_NONCE_BYTES + 1),
                2_000,
                1_000,
                1_000,
                None,
                false
            ),
            NonceDecision::InvalidLength
        );
        for i in 1..MAX_COORD_NONCES {
            assert_eq!(
                log.check_and_record(&format!("n{i}"), 2_000, 1_000, 1_000, None, false),
                NonceDecision::Accepted
            );
        }
        // Even an in-window request observed during a forward clock step must not
        // ratchet the mark when capacity makes the request a refusal.
        assert_eq!(
            log.check_and_record("one-too-many", 2_000, 1_500, 1_000, None, false),
            NonceDecision::AtCapacity
        );
        assert_eq!(log.high_water, 0);
        assert_eq!(log.entries.len(), MAX_COORD_NONCES);
    }

    /// `D = M + (E − W)`, and `W` is the decision's own `effective_now`. Deriving it
    /// from the RAW clock instead would hand a backwards clock step a longer deadline
    /// than the request was admitted under — the request is measured against the
    /// rollback-guarded bound, so its carrier must be too.
    #[test]
    fn a_carrier_deadline_is_fixed_from_effective_not_raw_wall_time() {
        const MONO: u64 = 42;
        let mut log = NonceLog::default();
        assert_eq!(
            log.check_and_record("old", 1_000, 500, 1_000, None, false),
            NonceDecision::Accepted
        );
        assert_eq!(
            log.check_and_record("advance", 2_000, 1_000, 1_000, None, false),
            NonceDecision::Accepted
        );
        assert_eq!(log.high_water, 1_000);

        // Raw wall time has rolled back to 600; the effective bound is still 1_000.
        assert_eq!(
            log.check_and_record("spend", 1_500, 600, 1_000, Some(MONO), true),
            NonceDecision::Accepted
        );
        assert_eq!(
            log.carrier_deadline("spend"),
            Some(MONO + 500),
            "the remainder is measured from the rollback-guarded bound (1_500 − 1_000), \
             not from the rolled-back raw clock (1_500 − 600)"
        );
        assert_eq!(
            log.check_and_record("later", 2_000, 1_600, 1_000, Some(MONO + 499), true),
            NonceDecision::Accepted
        );
        assert_eq!(log.high_water, 1_000);
        assert!(log.entries.contains_key("spend"));
        assert_eq!(
            log.outer_stale_carrier_deadline("spend", 1_500),
            Some(MONO + 500)
        );
        log.high_water = 1_500;
        assert_eq!(log.outer_stale_carrier_deadline("spend", 1_500), None);
    }

    /// The full liveness matrix for one channel-mode entry: wall-live/monotonic-dead,
    /// wall-dead/monotonic-live, and the `< D` / `== D` / `> D` boundary. The key is
    /// occupied while EITHER clock holds it and is released — replaced in place, never
    /// duplicated — the moment both have ended.
    #[test]
    fn a_channel_mode_nonce_is_occupied_until_both_clocks_end_it() {
        const MONO: u64 = 7;
        const DEADLINE: u64 = MONO + 500;
        let mut log = NonceLog::default();
        assert_eq!(
            log.check_and_record("n", 1_000, 500, 1_000, Some(MONO), true),
            NonceDecision::Accepted
        );

        // Wall-live, monotonic long dead: the wall half alone still holds the key.
        assert_eq!(
            log.check_and_record("n", 1_200, 900, 1_000, Some(DEADLINE + 1), true),
            NonceDecision::Replayed
        );
        // Wall-dead, monotonic live (`< D`): the monotonic half alone still holds it.
        assert_eq!(
            log.check_and_record("n", 1_600, 1_000, 1_000, Some(DEADLINE - 1), true),
            NonceDecision::Replayed
        );
        // The same entry with NO sample at all: `is_live`'s defensive arm, unreachable while
        // `Node::channel` is fixed at construction, must still refuse to free the key.
        assert!(log.entries["n"].is_live(1_000, None));
        assert_eq!(
            log.high_water, 0,
            "neither refusal forgot or ratcheted anything"
        );

        // Exactly `D`: the first second both clocks call it dead. The entry is REPLACED
        // by the new body, and the mark ratchets through the expiry actually removed.
        assert_eq!(
            log.check_and_record("n", 1_600, 1_000, 1_000, Some(DEADLINE), true),
            NonceDecision::Accepted
        );
        assert_eq!(log.entries.len(), 1);
        assert_eq!(log.entries["n"].expiry, 1_600);
        assert_eq!(log.high_water, 1_000);

        // `> D` is the same verdict as `== D`; the boundary is closed on one side only.
        assert_eq!(
            log.check_and_record("n", 2_400, 1_800, 2_000, Some(DEADLINE + 600 + 50), true),
            NonceDecision::Accepted
        );
        assert_eq!(log.entries["n"].expiry, 2_400);
    }

    /// Capacity counts monotonic liveness too, and the refusal stays non-mutating: a
    /// log full of wall-expired entries whose deadlines are still live refuses the next
    /// request without consuming its nonce, pruning anything, or ratcheting the mark.
    /// (The channel-side half — that such a refusal derives no carrier and relays
    /// nothing — is `an_at_capacity_channel_request_skips_carrier_derivation`; the
    /// refusal path it exercises is this one.)
    #[test]
    fn capacity_counts_monotonically_live_entries_and_refuses_without_mutating() {
        const MONO: u64 = 10;
        const DEADLINE: u64 = MONO + 500;
        let mut log = NonceLog::default();
        for i in 0..MAX_COORD_NONCES {
            assert_eq!(
                log.check_and_record(&format!("n{i}"), 1_000, 500, 1_000, Some(MONO), true),
                NonceDecision::Accepted
            );
        }
        assert_eq!(
            log.check_and_record(
                "one-too-many",
                2_000,
                1_100,
                1_000,
                Some(DEADLINE - 1),
                true
            ),
            NonceDecision::AtCapacity
        );
        assert_eq!(log.entries.len(), MAX_COORD_NONCES);
        assert_eq!(log.high_water, 0);
        assert_eq!(log.carrier_deadline("one-too-many"), None);

        // Once the deadlines pass, the same request is admitted and every forgotten
        // expiry lands on the mark.
        assert_eq!(
            log.check_and_record("one-too-many", 2_000, 1_100, 1_000, Some(DEADLINE), true),
            NonceDecision::Accepted
        );
        assert_eq!(log.entries.len(), 1);
        assert_eq!(log.high_water, 1_000);
    }

    /// An unrepresentable deadline is a refusal, not a saturated deadline that would
    /// pin the key forever, and it happens BEFORE anything mutates: the entry that this
    /// request would have pruned is still there afterwards.
    #[test]
    fn an_unrepresentable_carrier_deadline_refuses_without_mutating() {
        let mut log = NonceLog::default();
        assert_eq!(
            log.check_and_record("old", 600, 500, 1_000, None, false),
            NonceDecision::Accepted
        );
        assert_eq!(
            log.check_and_record("overflow", 1_600, 700, 1_000, Some(u64::MAX), true),
            NonceDecision::OutsideWindow { now: 700 }
        );
        assert!(log.entries.contains_key("old"));
        assert_eq!(log.entries.len(), 1);
        assert_eq!(log.high_water, 0);

        // The same request under a representable monotonic reading is admitted.
        assert_eq!(
            log.check_and_record("overflow", 1_600, 700, 1_000, Some(u64::MAX - 900), true),
            NonceDecision::Accepted
        );
        assert_eq!(log.carrier_deadline("overflow"), Some(u64::MAX));
    }

    #[test]
    fn a_pending_spend_blocks_refreshes_until_its_commitment_expires() {
        let mut log = PendingLog::default();
        assert!(!log.has_any(600), "nothing pending on a fresh node");
        log.record("abc".into(), 1_000);
        assert!(log.has_any(600), "a live pending spend blocks refreshes");
        // The block is bounded by the commitment's own expiry: a spend held
        // perpetually pending to starve refreshes dies with it (denial, not theft).
        assert!(
            log.has_any(1_000),
            "the spend remains pending in its final fire second"
        );
        // The following second closes the fire window and drops the entry.
        log.prune(1_001);
        assert!(!log.has_any(1_001));
        assert_eq!(log.entries.len(), 0);
    }
}
