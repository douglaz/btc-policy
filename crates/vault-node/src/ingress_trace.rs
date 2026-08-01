//! Test-only, in-process record of the ORDER of observable operations one `/sign`
//! ingress pass performs — the op-order part of the deterministic gate for ADR-0012's
//! constant-observable-ingress rule:
//!
//! > a node performs the identical operations in the identical order … A normal
//! > spend schedules its own fire through the same mechanism the escape uses, so
//! > there is no write, timer install, or lock acquisition that duress performs and
//! > normal does not.
//!
//! [`pin::verify_pin`](crate::pin::verify_pin)'s own counting seam
//! ([`CountingEvaluator`](crate::pin::test_util::CountingEvaluator)) proves the PIN
//! COMPARE is symmetric — exactly two Argon2 evaluations, Normal then Duress, for
//! every pin class. It says nothing about the rest of the handler, which is where
//! the pin verdict actually flows: into the arm hook, into
//! [`ChannelState::apply_cached_schedule`](crate::channel::ChannelState::apply_cached_schedule),
//! and into [`register_pair`](crate::register_pair)'s arm directive. This module is
//! that broader half, and it is deliberately built the same way: a counting seam
//! whose output is compared for equality, not a clock whose noise floor exceeds the
//! effect it is meant to detect.
//!
//! **Why a SEQUENCE and not a set of counters.**
//! [`ScheduleWorkTrace`](crate::channel::ScheduleWorkTrace) already counts the
//! channel store's locks, candidate visits, and schedule writes and asserts the two
//! pins agree. Counters cannot see reordering — a duress path that took the same
//! locks in a different order, or interleaved a write differently, has a different
//! observable work shape and identical counts. Recording an ordered log makes the
//! assertion `normal == duress` over a `Vec`, which catches an added op, a dropped
//! op, and a moved op alike.
//!
//! **What the log alone cannot see, and what covers it.** Every op here is recorded
//! at the ingress path's CALL SITE, so this log is a WHITELIST: it answers "what did
//! this pass do at the places we instrumented", not "what did this pass do" and not
//! "what did this pass cost". Two things escape it and ARE covered elsewhere in
//! `channel::duress::IngressWork` — the tests compare all of its fields together, never
//! this log on its own. A third escapes it and is covered NOWHERE; it is named below,
//! because a boundary statement that lists only the gaps it closed is the overclaim
//! this module exists to stop making.
//!
//! * MEMORY-HARD COST. An extra `carrier_kdf.derive` bolted on somewhere else runs a full
//!   memory-hard evaluation and appends nothing here. Verified by construction: with a
//!   duress-only extra derivation inserted into `Node::fire_arm_hook`, the captured op
//!   logs come back BYTE-IDENTICAL under both pins. That is the ~199 ms effect the
//!   demoted wall-clock probe existed for, so the record also carries the two
//!   evaluation counters that already exist —
//!   [`Node::carrier_derivation_count`](crate::Node::carrier_derivation_count) and
//!   [`CountingEvaluator`](crate::pin::test_util::CountingEvaluator).
//! * UNINSTRUMENTED WRITES. A duress-only `store.carriers_by_nonce.insert(...)`
//!   dropped into `ChannelState::record_arm_intent` leaves this log — and the
//!   hand-placed `ScheduleWorkTrace` counters, which are a whitelist for the same
//!   reason — byte-identical under both pins. So the record also carries two canonical
//!   projections read off FIELDS rather than off any instrumentation:
//!   `channel::duress::StoreShape` over the whole channel store (pin-masked, since a
//!   carrier id is a digest of the PIN), and `channel::duress::SignStateShape` over the
//!   whole `/sign` handler state — the replay, pending, coordinator-nonce and refresh
//!   logs plus the attempt budget, which is the one piece of state the pin VERDICT is
//!   passed into. That makes net-state coverage generic across both halves of the
//!   node's mutable state. Writes to the vault-authorized set, to the PEER OUTBOX
//!   ([`Node::outbox`](crate::Node), which is neither of those two structs), and to the
//!   remaining handler locals stay covered only at this log's instrumented call sites.
//!   For the two shared structures that is a COMPLETE whitelist and is maintained as
//!   one: every production write to `Node::outbox` records [`IngressOp::OutboxPush`]
//!   and every write to `Node::authorized` records [`IngressOp::AuthorizedInsert`],
//!   including on the paths where the write is pin-uniform by construction (the
//!   `/sign` delivery-horizon refusal, which returns before the pin is evaluated) and
//!   on the pin-less refresh handler. Both are instrumented anyway, because a
//!   whitelist with silent exceptions reads as coverage it does not have. What the
//!   log still cannot see for the outbox is CONTENTS — only presence and position.
//!   Deliberately: the staged `TaggedRequest` is the coordinator's request
//!   verbatim, PIN included, so like a carrier id it differs by pin BY CONSTRUCTION and
//!   would have to be masked before it could be compared at all.
//!
//! * NON-MEMORY-HARD COST — the residual, and it is gated by nothing. A duress-only
//!   extra ECDSA verify, an extra PSBT serialize, or an O(candidates) scan appends no op
//!   here, leaves no net state in either projection, and moves neither evaluation
//!   counter. Verified by construction, and this one is NOT a near miss: a duress-only
//!   arithmetic grind inserted into `Node::fire_arm_hook`, heavy enough to take the seven
//!   cases from 0.05 s to 4.94 s of real CPU, left every one of them GREEN. That is
//!   ~25× the ~199 ms Argon2 effect the demoted wall clock existed to catch, and nothing
//!   deterministic saw it. The wall-clock skew that was once the only thing in its way is
//!   now advisory (its noise floor exceeded the effect it was aimed at), so this class
//!   has no gate at all. `docs/THREAT-MODEL.md` R10 records the same boundary; keep the
//!   two in agreement.
//!
//! Instrument new sites here for ORDER; the two evaluation counters cover MEMORY-HARD
//! cost only, and the two projections cover channel-store and `/sign`-state net state.
//! A new write to `Node::outbox`, `Node::authorized`, `Node::alerts`, or
//! `ChannelState`'s `freshness_counts` / `ingress_guards` MUST record its op — none of
//! those reach either projection, so an uninstrumented write to any of them is invisible
//! to the whole record. `Node::alerts` is the one to watch hardest: it is served
//! verbatim over `GET /events`, which SILENCE names as an observable, so a duress-only
//! alert write from ingress would pass all seven deterministic cases while being
//! pin-readable over HTTP — with only the live harness's `/events` body comparison in
//! its way. Nothing on the `/sign` path writes any of these today (the sole alert push
//! is `record_freshness_reject`, on the `/channel` peer path); this rule is what keeps
//! that true.
//!
//! **Why this can never become the leak it tests for.** The log lives in a
//! thread-local, is `#[cfg(test)]`, and is written only while a test has explicitly
//! opened a [`capture`] window. Nothing reaches `Node`, no handler reads it, and no
//! response, projection, or `/events` field is derived from it. A pin-dependent
//! counter readable over HTTP would BE the duress oracle ADR-0012 forbids; an
//! in-process test seam is what the pin module already established as the safe shape.
//!
//! **Why a thread-local rather than a field on [`Node`](crate::Node).** Every op below
//! is performed synchronously on its caller's thread — the peer fan-out that could
//! cross threads happens after the handler returns, from the outbox. The captures here
//! all drive `handle_sign_after_lock`, but that is not the only emitter: `ReplayWrite`,
//! `NodeSignature` and `CandidateRegister` sit in helpers (`record_verdict`,
//! `add_node_signatures`, `register_pair`) that `handle_refresh_after_lock` also calls,
//! and that handler records its own `AuthorizedLock`/`AuthorizedInsert`/`OutboxPush`
//! for the same reason the `/sign` path does, so a capture opened around a REFRESH
//! pass records all of those. Refresh is synchronous
//! on its caller's thread as well, so the thread-local argument holds for it unchanged —
//! but do not read this log as `/sign`-only when wiring one up. A thread-local scopes a
//! capture to exactly one
//! ingress pass without widening `Node`'s production shape by a field, and parallel
//! `cargo test` threads cannot contaminate each other's captures.
//!
//! **Capture boundary.** "One ingress pass" here ends when the synchronous handler
//! returns. Production then drains the outbox in [`crate::propagate_outbox`] and its
//! spawned peer sends can continue after the HTTP response. Those post-handler
//! scheduler and peer effects are outside this deterministic record; the live attack
//! scenarios exercise peer propagation, while their wall-clock comparison remains an
//! advisory signal. Do not cite this record as an end-to-end timing gate.

use std::cell::RefCell;

/// One observable operation an ingress pass performs. The variants are the three
/// categories ADR-0012 names — LOCK ACQUISITIONS, WRITES, and TIMER INSTALLS — plus
/// the memory-hard carrier derivation and each per-PSBT signing pass. The derivation
/// is the unbounded-cost term that dominated what the wall-clock probe could measure;
/// the signing markers preserve operation order at the granularity the handler calls.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum IngressOp {
    /// The one `/sign` lock is taken. Recorded twice per accepted request: phase 1
    /// (auth + pin + intent) and phase 2 (validate + register), around the
    /// out-of-lock chain preflight.
    SignStateLock,
    /// The `/sign` lock is released at one of the handler's two EXPLICIT `drop`s: the
    /// wrong-pin/lockout backoff (so a flood never pins the lock while it sleeps) and
    /// the hand-off to the out-of-lock chain preflight.
    ///
    /// So the log is asymmetric about lock RELEASE, and deliberately: an early `return`
    /// between the phase-1 acquisition and either site drops the guard implicitly and
    /// records nothing, so acquisitions can outnumber releases. That is sound for the
    /// property under test — the two pins must produce the IDENTICAL sequence, and a
    /// pin that took a different early return already differs in the ops leading up to
    /// it. Do not read a missing `SignStateUnlock` as a leaked lock.
    SignStateUnlock,
    /// One in-flight-spend slot is claimed for the preflight (refresh subordination).
    PreflightEnter,
    /// The out-of-lock prevout fetch runs.
    ChainPreflight,
    /// The memory-hard arm-carrier identity is derived (channel mode only).
    CarrierDerive,
    /// The duress arm-hook runs. Unconditional and constant-time-selected: it is the
    /// LAST verdict-dependent step on the hot path, so its presence — not its
    /// internal bit — is what must match.
    ArmHook,
    /// The arm INTENT is written under the channel store lock (store lock + safety
    /// overlay rewrite + intent-map write + nonce memo write).
    ArmIntentWrite,
    /// The request is pushed to the peer outbox under the outbox lock. Recorded at
    /// EVERY production write to [`Node::outbox`](crate::Node) — `stage_spend_carrier`,
    /// the pre-pin delivery-horizon refusal, and the refresh handler — because the
    /// outbox reaches neither whole-struct projection, so this op is the only thing
    /// that sees it at all.
    OutboxPush,
    /// This node claims its own holder slot for the staged carrier.
    CarrierPropagated,
    /// The replay log is pruned.
    ReplayPrune,
    /// A verdict is written to the replay log.
    ReplayWrite,
    /// A replay-cached acceptance re-applies its schedule (the branch that carries
    /// the `verdict == Duress` bit on the cached path).
    CachedScheduleApply,
    /// A replay-cached acceptance re-attaches its candidate pair to the carrier.
    IntentPairWrite,
    /// The pending (Hold) log is pruned.
    PendingPrune,
    /// The refresh-interval log is pruned.
    RefreshPrune,
    /// The channel candidate store is pruned.
    ChannelStorePrune,
    /// A hot-budget reservation is attempted under the channel store lock.
    HotBudgetReserve,
    /// A hot-budget reservation is released again.
    HotBudgetRelease,
    /// This node adds its signature to one PSBT (spend, escape, or one ladder rung).
    NodeSignature,
    /// The candidate pair is registered with its fire window and arm directive — the
    /// TIMER INSTALL for the spend's Hold and the escape's delayed slot.
    CandidateRegister,
    /// The vault-authorized txid set lock is taken.
    AuthorizedLock,
    /// One txid is inserted into the vault-authorized set. Recorded at every
    /// production write to that set — the `/sign` spend + escape + ladder-rung
    /// inserts and the refresh handler's — for the same reason as
    /// [`IngressOp::OutboxPush`]: the set is outside both projections.
    AuthorizedInsert,
    /// The hot-class Hold timer is installed in the pending log.
    HoldTimerInstall,
}

thread_local! {
    /// `None` = not capturing. Every non-capturing `record` is one thread-local read
    /// and a `None` test, so instrumenting the handler costs the rest of the suite
    /// nothing and cannot grow without bound.
    static TRACE: RefCell<Option<Vec<IngressOp>>> = const { RefCell::new(None) };
}

/// Append `op` to the open capture, if any.
pub(crate) fn record(op: IngressOp) {
    TRACE.with(|trace| {
        if let Some(log) = trace.borrow_mut().as_mut() {
            log.push(op);
        }
    });
}

/// Run `f` with recording enabled and return its value alongside the ordered ops it
/// performed.
///
/// Captures do not nest: opening one replaces any log already open, and the previous
/// log is NOT restored. Every call site is a test driving one handler call directly,
/// so nesting would be a mistake in the test rather than a case to support.
///
/// A panic inside `f` leaves the window open rather than closing it, and that is
/// deliberately not guarded. The window is thread-local and this line reopens one
/// unconditionally, so the only thread that could ever observe the abandoned log is the
/// panicking one, which libtest is in the middle of ending — and any later `capture` on
/// a reused thread discards it before recording. Nothing can inherit a partial log, so
/// a drop guard would buy no property this record depends on.
pub(crate) fn capture<T>(f: impl FnOnce() -> T) -> (T, Vec<IngressOp>) {
    TRACE.with(|trace| *trace.borrow_mut() = Some(Vec::new()));
    let value = f();
    let ops = TRACE.with(|trace| trace.borrow_mut().take().unwrap_or_default());
    (value, ops)
}
