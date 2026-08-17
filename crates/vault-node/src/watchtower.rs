//! Watchtower duty (ADR-0001, as revised by ADR-0012): every node watches its OWN
//! chain view and queues a structured [`Alert`] for two events —
//!
//!  - **RecoveryPathSpend**: a spend that took the timelocked recovery branch.
//!  - **UnrecognizedSpend**: a spend of a vault UTXO this node never **validated
//!    AND policy-ACCEPTED**.
//!
//! **Recognition is by ACCEPTANCE, not by signing** (ADR-0012's required fix). The
//! two neighbouring criteria are both wrong:
//!
//!  - "*I co-signed it*" is too narrow. In a `t`-of-`n` only `t` nodes sign any
//!    given spend, so the other `n−t` would false-alarm on entirely honest
//!    traffic. This is what V0-6 did.
//!  - "*I evaluated it*" is too broad, and dangerously so. A spend a node
//!    policy-REFUSED was evaluated — so under that rule an attacker who fans a
//!    theft out to the honest nodes would have it marked recognized everywhere and
//!    **suppress its own alert**.
//!
//! Acceptance is the line that works: every node validates every request, so a
//! legitimate spend is accepted by all `n` and alerts nowhere, while a theft the
//! honest nodes refuse is in nobody's accepted set and alerts everywhere — whether
//! or not the attacker fanned it out. Alerts are pulled by the coordinator
//! (ADR-0002); nodes never push.
//!
//! The classification [`scan`] is a callable pass, deterministic and driven by a
//! caller (the tests). In the running daemon a thin loop drives it: each node is
//! its own watchtower (ADR-0001), so [`spawn_driver`] spawns ONE background
//! task that runs a pass every [`SCAN_INTERVAL`], advancing a height cursor so
//! each pass scans only new blocks and writing into the same alert queue
//! `GET /events` reads.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bitcoin::{BlockHash, ScriptBuf, Txid, Witness};
use serde::Serialize;

use crate::chain::{ChainBackend, SpendSeen};
use crate::Error;

/// Default bound on the in-memory alert queue.
pub const DEFAULT_ALERT_CAP: usize = 1024;

/// The `(height, hash)` blocks a scan pass traversed and proved active — ascending,
/// contiguous, rooted on the cursor anchor. The watchtower binds its cursor anchors
/// to exactly this chain (see [`ChainBackend::spends_of`] / [`scan_pass`]).
type ScannedBlocks = Vec<(u32, BlockHash)>;

/// The two watchtower events (DESIGN.md, "Watchtower"). Serialized
/// SCREAMING_SNAKE for the pull wire, like the refusal codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AlertKind {
    /// A spend took the recovery branch — stolen recovery keys, or a legitimate
    /// recovery; either way the user must be told (DESIGN.md, Wallet Topology).
    RecoveryPathSpend,
    /// A vault UTXO was spent by a transaction this node never validated and
    /// policy-accepted (see the module docs — NOT "never co-signed").
    UnrecognizedSpend,
}

/// One queued watchtower alert. Node-local for now (kept out of vault-proto until
/// the coordinator pull loop needs the type — V0-7). Serde-native via display
/// strings, so no `bitcoin` serde feature is pulled in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Alert {
    pub kind: AlertKind,
    /// Txid of the spending transaction (lowercase hex).
    pub spend_txid: String,
    /// The vault outpoint that was spent (`txid:vout`).
    pub outpoint: String,
    /// scriptPubKey of the spent output (lowercase hex).
    pub script: String,
}

impl Alert {
    fn from_spend(kind: AlertKind, spend: &SpendSeen) -> Alert {
        Alert {
            kind,
            spend_txid: spend.spend_txid.to_string(),
            outpoint: spend.outpoint.to_string(),
            script: spend.script.to_hex_string(),
        }
    }
}

/// The one channel-diagnostic event kind (V0-8a, codex I2). Its own SCREAMING_SNAKE
/// tag so an operator tells it apart from the watchtower alerts in `/events`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FreshnessKind {
    ChannelFreshnessReject,
}

/// A channel freshness-rejection event, surfaced through the SAME `/events` path
/// so an operator sees WHICH peer's clock is off (and the running count + a
/// clock-skew hint) before it is silently ejected from the combine set. It carries
/// NO transaction fields — the watchtower alert JSON is left untouched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FreshnessEvent {
    pub kind: FreshnessKind,
    /// The authenticated peer whose envelope failed the freshness window.
    pub peer_node_id: u16,
    /// Running per-peer count of freshness rejections (monotonic).
    pub reject_count: u64,
    /// `envelope_timestamp - now` (positive ⇒ peer clock ahead, negative ⇒ behind).
    pub skew_secs: i64,
}

/// One queued event: either a watchtower [`Alert`] (unchanged JSON) or a channel
/// [`FreshnessEvent`]. `#[serde(untagged)]` serializes each variant AS its inner
/// value, so an existing watchtower alert keeps its exact `{kind, spend_txid,
/// outpoint, script}` shape while a freshness event serializes to its own object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum Event {
    Watchtower(Alert),
    ChannelFreshness(FreshnessEvent),
}

impl Event {
    /// Test-only downcast to the watchtower [`Alert`].
    #[cfg(test)]
    pub(crate) fn watchtower(&self) -> &Alert {
        match self {
            Event::Watchtower(a) => a,
            Event::ChannelFreshness(_) => panic!("expected a watchtower alert"),
        }
    }
}

/// Classify each observed spend into the alerts to queue.
///
/// Precedence (DESIGN.md, "Watchtower"): a spend that took the recovery BRANCH is a
/// `RecoveryPathSpend` even though the node never authorized it — the recovery path
/// uses recovery keys, not node keys, so the acceptance test would otherwise
/// mislabel it as unrecognized. Any other spend the backend surfaced is a spend of
/// a vault UTXO (the backend was only asked for the vault script set); it is an
/// `UnrecognizedSpend` unless its txid is in `authorized_txids` — the node's
/// validated-AND-policy-ACCEPTED set (see the module docs).
///
/// The recovery branch shares the vault's scriptPubKey (ADR-0013 §1: recovery is an
/// alternate branch inside the SAME `wsh(...)`), so it CANNOT be told from a normal
/// spend by the prevout script. The branch is read from the spending WITNESS
/// instead ([`is_recovery_branch`]) — the on-chain, branch-identifiable signal.
fn classify(spends: &[SpendSeen], authorized_txids: &HashSet<Txid>) -> Vec<Alert> {
    let mut alerts = Vec::new();
    for spend in spends {
        if is_recovery_branch(&spend.witness) {
            alerts.push(Alert::from_spend(AlertKind::RecoveryPathSpend, spend));
        } else if !authorized_txids.contains(&spend.spend_txid) {
            alerts.push(Alert::from_spend(AlertKind::UnrecognizedSpend, spend));
        }
    }
    alerts
}

/// Whether a P2WSH vault-script spend took the RECOVERY branch, read from its
/// witness. The vault template's top-level `or_i(NORMAL, RECOVERY)` compiles to
/// `OP_IF <normal> OP_ELSE <recovery> OP_ENDIF`, so the witness carries an explicit
/// branch selector as the element immediately BEFORE the witness script (the last
/// element): a non-empty `01` selects the normal (IF) branch, an EMPTY push selects
/// the recovery (ELSE) branch. So a recovery spend is exactly one whose
/// second-from-last witness element is empty.
///
/// A witness too short to carry a P2WSH selector + script (< 2 elements) is not a
/// vault-branch spend of this shape and reads as non-recovery — the safe default,
/// since it still alerts as `UnrecognizedSpend` when it is not in the authorized
/// set. `spends_of` only ever returns spends of the vault script, so every witness
/// reaching here belongs to a spend of the two-branch `wsh(...)`.
fn is_recovery_branch(witness: &Witness) -> bool {
    witness
        .second_to_last()
        .is_some_and(|selector| selector.is_empty())
}

/// One callable watchtower scan: capture the current tip, then ask `backend` for
/// spends of the vault scripts through that height and classify them against the
/// node's authorized set. The daemon's cursor pass uses [`scan_through`] directly
/// with its already-captured terminal height.
/// two-branch `wsh(...)` shares one scriptPubKey across the normal and recovery
/// branches (ADR-0013 §1), so `vault_scripts` alone covers a recovery spend too —
/// the branch is read from each spend's witness ([`classify`] / [`is_recovery_branch`]).
pub fn scan(
    backend: &dyn ChainBackend,
    vault_scripts: &[ScriptBuf],
    authorized_txids: &HashSet<Txid>,
    from_height: u32,
) -> Result<Vec<Alert>, Error> {
    let through_height = backend.tip_height()?;
    // A one-shot scan carries no cursor, so it roots on nothing (`None`) and discards
    // the traversed chain — only [`scan_pass`] retains anchors across passes.
    let (alerts, _blocks) = scan_through(
        backend,
        vault_scripts,
        authorized_txids,
        from_height,
        through_height,
        None,
    )?;
    Ok(alerts)
}

/// Scan one fixed inclusive block range. Pinning the terminal height keeps the
/// spend set on the same captured prefix whose hash [`scan_pass`] validates before
/// publishing alerts or advancing its cursor.
fn scan_through(
    backend: &dyn ChainBackend,
    vault_scripts: &[ScriptBuf],
    authorized_txids: &HashSet<Txid>,
    from_height: u32,
    through_height: u32,
    expected_parent: Option<BlockHash>,
) -> Result<(Vec<Alert>, ScannedBlocks), Error> {
    let traversal =
        backend.spends_of(vault_scripts, from_height, through_height, expected_parent)?;
    Ok((
        classify(&traversal.spends, authorized_txids),
        traversal.blocks,
    ))
}

/// Interval between watchtower scan passes in the daemon driver. A `const`, not a
/// config knob — small so a regtest spend surfaces quickly (DESIGN.md keeps the
/// v0 watchtower deliberately minimal).
pub const SCAN_INTERVAL: Duration = Duration::from_secs(10);

/// Outcome of one [`scan_pass`]: how many new alerts it queued. The next scan
/// height now lives in the [`ScanCursor`] the caller carries, not here.
#[derive(Debug)]
pub(crate) struct ScanOutcome {
    pub(crate) new_alerts: usize,
}

/// Bound on how deep a reorg the watchtower cursor can rewind across (deliverable
/// 9y5.3-a). Recovering a `D`-block reorg requires the `D` replaced blocks PLUS
/// their still-active fork-point anchor, so the cursor retains at most
/// `MAX_REORG_DEPTH + 1` hashes. A reorg no deeper than this rewinds to the fork
/// point and re-scans, while a deeper reorg fails loud and resets to genesis
/// (re-scanning the whole chain, alert-deduped) rather than silently advancing past
/// blocks it never re-classified or wedging the cursor forever.
///
/// 100 blocks is far beyond any reorg a live network produces post-finality (a
/// handful of blocks is already extraordinary), yet bounds the retained state to a
/// few KiB and one `getblockhash` per new block. It is a `const`, not a config
/// knob: it is a safety floor on how far back the watchtower can recover, not
/// policy.
pub const MAX_REORG_DEPTH: u32 = 100;

/// The reorg-aware watchtower scan cursor (deliverable 9y5.3-a). It carries not
/// just the next height to scan but a bounded trailing window of the block HASHES
/// it last scanned, so each pass can confirm its scanned range still matches the
/// chain before advancing. The bare monotonic height it replaces tracked no hash
/// and never rewound, so a spend that a reorg moved to (or first surfaced at) a
/// height at or below the cursor was silently missed.
#[derive(Clone)]
pub(crate) struct ScanCursor {
    /// `(height, block_hash)` for a trailing window of already-scanned blocks,
    /// oldest first, at most `MAX_REORG_DEPTH + 1` entries and CONTIGUOUS at the
    /// top of the scanned range. `anchors.back()` is the newest block this cursor
    /// has confirmed-scanned; `anchors.front()` is the deepest fork point it can
    /// retain.
    anchors: VecDeque<(u32, BlockHash)>,
    /// The next height to scan from (one past the newest scanned block, or the
    /// configured start floor before anything has been scanned).
    next_from: u32,
}

impl ScanCursor {
    /// A cursor that begins scanning at `from_height` with no recorded history.
    /// The daemon driver starts at 0; [`Node::watchtower_tick`](crate::Node::watchtower_tick)
    /// builds a throwaway one per call to keep its single-pass `from_height` API.
    pub(crate) fn starting_at(from_height: u32) -> ScanCursor {
        ScanCursor {
            anchors: VecDeque::new(),
            next_from: from_height,
        }
    }

    /// A cursor that begins at genesis — the daemon driver's start state.
    pub(crate) fn new() -> ScanCursor {
        ScanCursor::starting_at(0)
    }
}

/// Confirm the cursor's scanned range still matches the chain, rewinding to the
/// fork point on a reorg, and return the height the pass should (re-)scan from.
///
/// Block headers chain — each commits to its parent — so if ANY block within the
/// retained window was re-orged out, the NEWEST anchor's hash changes too. One
/// `block_hash_at` at the newest anchor therefore detects any in-window reorg. On
/// a mismatch it walks the window newest→oldest for the highest anchor whose hash
/// still matches (the fork point / last common block), drops every anchor above
/// it, and returns `fork + 1`. A reorg deeper than the whole retained window (no
/// anchor matches) cannot locate its fork point, so — rather than WEDGE a sealed
/// node's cursor forever — it resets to genesis and returns `0`, re-scanning the
/// whole chain (the alert queue dedups already-surfaced spends, so the redundant
/// re-scan is harmless and no re-orged spend is missed). This mirrors the driver's
/// panic-recovery reset and still fails LOUD; it never silently advances, because a
/// full re-scan re-classifies every block.
fn reconcile_cursor(backend: &dyn ChainBackend, cursor: &mut ScanCursor) -> Result<u32, Error> {
    let Some(&(anchor_height, anchor_hash)) = cursor.anchors.back() else {
        // Nothing scanned yet — no reorg is possible; start at the configured floor.
        return Ok(cursor.next_from);
    };
    if backend.block_hash_at(anchor_height)? == Some(anchor_hash) {
        return Ok(cursor.next_from);
    }
    // Reorg detected at the newest anchor. Find the deepest still-matching anchor.
    let mut fork = None;
    for &(height, hash) in cursor.anchors.iter().rev() {
        if backend.block_hash_at(height)? == Some(hash) {
            fork = Some(height);
            break;
        }
    }
    match fork {
        Some(fork_height) => {
            while cursor.anchors.back().is_some_and(|&(h, _)| h > fork_height) {
                cursor.anchors.pop_back();
            }
            cursor.next_from = fork_height + 1;
            eprintln!(
                "watchtower: reorg detected — rewinding scan cursor to fork point at height \
                 {fork_height}; re-scanning from {} (spends re-classified, dedup guards \
                 already-alerted ones)",
                cursor.next_from
            );
            Ok(cursor.next_from)
        }
        None => {
            // Reorg deeper than the retained window: the fork point is unknown, so
            // advancing could silently skip re-orged blocks. Rather than WEDGE the
            // cursor forever (a sealed node has no operator to repair it, and the
            // reconcile would keep failing every pass), reset to genesis and re-scan
            // the whole chain. The alert queue dedups already-surfaced spends, so the
            // redundant re-scan is harmless and no re-orged spend is missed; this
            // mirrors the driver's panic-recovery reset. Still LOUD.
            let oldest = cursor
                .anchors
                .front()
                .map(|&(h, _)| h)
                .unwrap_or(anchor_height);
            eprintln!(
                "watchtower: reorg deeper than the {MAX_REORG_DEPTH}-block recovery bound \
                 (no retained anchor from height {oldest} up to {anchor_height} still matches \
                 the chain); resetting the scan cursor to genesis and re-scanning from 0 \
                 (alert dedup guards already-surfaced spends) rather than wedging the cursor or \
                 silently advancing past re-orged blocks"
            );
            cursor.anchors.clear();
            cursor.next_from = 0;
            Ok(0)
        }
    }
}

/// Record the block hashes of the heights this pass scanned into the cursor's
/// trailing window, keeping it contiguous and bounded to `MAX_REORG_DEPTH + 1`.
/// The extra anchor is the unchanged fork point needed to recover exactly
/// `MAX_REORG_DEPTH` replaced blocks. Only the top window's worth of heights are
/// retained (a deeper rewind is refused anyway).
///
/// The hashes come from `blocks` — the `(height, hash)` chain [`ChainBackend::spends_of`]
/// PROVED active on this same pass (rooted on the cursor anchor, internally chained,
/// ending on the still-active tip). Binding anchors to that traversal, rather than
/// re-reading each height, closes the reorg that would otherwise race the second read
/// and slip a mixed-fork anchor into the window (v0-exit 9y5.3 review, [P1] BOTH).
fn extend_anchors(
    cursor: &mut ScanCursor,
    blocks: &[(u32, BlockHash)],
    from: u32,
    tip: u32,
) -> Result<(), Error> {
    if tip < from {
        // The chain is shorter than the cursor (a reorg that also dropped height):
        // reconcile already trimmed the window to the fork, and there are no new
        // blocks to record.
        return Ok(());
    }
    // Nothing below the deepest retained fork point is rewindable, so never retain it.
    let lo = from.max(tip.saturating_sub(MAX_REORG_DEPTH));
    // A jump of more than a window past the last anchor would leave a gap in the
    // retained hashes; drop the now-unreachable older anchors so the window stays
    // contiguous (a later deep reorg into the gap then fails loud, as it must).
    if cursor.anchors.back().is_some_and(|&(h, _)| lo > h + 1) {
        cursor.anchors.clear();
    }
    // Start strictly above the newest retained anchor, so this is idempotent: if a
    // prior pass's `extend` half-completed and returned `Err` (a reorg raced the
    // scan), re-running never re-pushes an already-retained height and so never
    // duplicates an anchor.
    let start = cursor.anchors.back().map_or(lo, |&(h, _)| (h + 1).max(lo));
    for &(height, hash) in blocks.iter().filter(|&&(h, _)| h >= start) {
        // Defence-in-depth: `blocks` is spends_of's contiguous [from, tip] chain and
        // `start >= from`, so the retained suffix is contiguous with the window. Refuse
        // rather than record a gapped cursor if that ever fails to hold.
        if let Some(&(back, _)) = cursor.anchors.back() {
            if height != back + 1 {
                return Err(format!(
                    "watchtower: validated block at height {height} is not contiguous with the \
                     retained anchor at {back}; refusing to record a gapped cursor"
                )
                .into());
            }
        }
        cursor.anchors.push_back((height, hash));
    }
    while cursor.anchors.len() > MAX_REORG_DEPTH as usize + 1 {
        cursor.anchors.pop_front();
    }
    Ok(())
}

/// One watchtower scan pass, shared by the daemon driver and the callable
/// [`Node::watchtower_tick`](crate::Node::watchtower_tick) so tests and production
/// run ONE code path.
///
/// First [`reconcile_cursor`] confirms the cursor's scanned range still matches the
/// chain (rewinding to the fork point on a reorg, or — for one deeper than the
/// retained window — failing loud and resetting to genesis to re-scan). Then it
/// captures the tip hash, snapshots the authorized
/// set, and runs the [`scan`] classification over `vault_scripts` from the
/// reconciled height, passing the newest anchor as the parent the range must chain
/// onto. Before queuing alerts or advancing, it records the scan's OWN validated
/// `(height, hash)` chain into a candidate cursor and re-checks the captured tip hash.
/// A same-height reorg that raced the scan therefore discards the candidate cursor
/// and retries from the old position; it can never bind old-fork scan results to
/// new-fork anchors and silently skip the new fork. Only a stable pass queues the
/// alerts and advances to `tip + 1`. The complementary half of that guarantee lives
/// in [`ChainBackend::spends_of`]: the per-height reads are not an atomic snapshot,
/// so the backend itself proves the blocks it traversed are ROOTED on the caller's
/// anchor, chain together, AND end on the still-active block — closing both the
/// A→B→A that returns to the captured tip hash and the taller fork that rebuilds in
/// the reconcile→scan gap (v0-exit 9y5.3 [P1]). The anchors are that proven chain,
/// so the pass never re-reads a hash a reorg could have swapped between the two reads.
/// When the cursor is already caught up the scan range is empty and it stays caught
/// up — never a re-scan from 0.
///
/// The authorized set is snapshotted (and its lock released) before the
/// possibly-slow backend fetch, so a concurrent `/sign` is never blocked on chain
/// I/O. `vault_scripts` covers both descriptor branches (they share one
/// scriptPubKey); a recovery spend is told apart by its witness (see [`scan`]).
pub(crate) fn scan_pass(
    backend: &dyn ChainBackend,
    vault_scripts: &[ScriptBuf],
    authorized: &Mutex<HashSet<Txid>>,
    alerts: &Mutex<AlertQueue>,
    cursor: &mut ScanCursor,
) -> Result<ScanOutcome, Error> {
    let from_height = reconcile_cursor(backend, cursor)?;
    let tip = backend.tip_height()?;
    // A height-SHRINKING reorg can land between reconcile_cursor's anchor match and this
    // tip read: reconcile matched the newest anchor (so it did NOT rewind), but the chain
    // is now shorter than that anchor. Committing `next_from = tip + 1` below — while
    // `extend_anchors` no-ops because `tip < from_height` — would drop `next_from` BELOW
    // the retained anchor, breaking the cursor invariant `next_from == anchors.back() + 1`.
    // The root-linkage check (check 0) would then refuse EVERY later pass forever once the
    // taller fork reactivates: the scan would start below the newest anchor and its first
    // block could never name that anchor as its parent (v0-exit 9y5.3 review, [P1] Fable).
    // Do NOT advance — leave the cursor untouched so the NEXT pass's `reconcile_cursor`
    // sees the now-shorter chain (its anchor read returns a mismatch or `None`) and rewinds
    // to the real fork point. The caught-up case (`tip == anchor_height`) is unaffected.
    if cursor
        .anchors
        .back()
        .is_some_and(|&(anchor_height, _)| tip < anchor_height)
    {
        return Ok(ScanOutcome { new_alerts: 0 });
    }
    let tip_hash = backend.block_hash_at(tip)?.ok_or_else(|| {
        format!(
            "watchtower: active tip at height {tip} vanished before the scan; refusing to advance"
        )
    })?;
    let authorized = authorized.lock().expect("authorized lock poisoned").clone();
    // The newest anchor (AFTER reconcile's rewind/reset) is the parent the scanned
    // range must chain onto. Passing it makes the scan refuse a taller-fork reorg that
    // lands between the pre-scan anchor check and this scan, whose new `from_height`
    // block does not chain onto the anchor (v0-exit 9y5.3 [P1]). `None` on the first
    // scan or a post-reset genesis re-scan, which have no anchor to root on.
    let expected_parent = cursor.anchors.back().map(|&(_, hash)| hash);
    let (new_alerts, scanned_blocks) = scan_through(
        backend,
        vault_scripts,
        &authorized,
        from_height,
        tip,
        expected_parent,
    )?;
    // Build the prospective anchors transactionally. If recording them fails, or
    // the captured tip changed while the scan was in flight, the live cursor stays
    // at its reconciled pre-scan position and the next pass re-scans the range. The
    // anchors are the very `(height, hash)` chain `spends_of` just proved active — not
    // a second, race-prone re-read.
    let mut advanced = cursor.clone();
    extend_anchors(&mut advanced, &scanned_blocks, from_height, tip)?;
    if backend.block_hash_at(tip)? != Some(tip_hash) {
        return Err(format!(
            "watchtower: active block hash at captured tip height {tip} changed while scanning; \
             refusing to bind scan results to a different fork or advance the cursor"
        )
        .into());
    }
    advanced.next_from = tip.saturating_add(1);
    debug_assert_eq!(
        advanced.next_from,
        advanced
            .anchors
            .back()
            .map_or(advanced.next_from, |&(h, _)| h + 1),
        "cursor invariant: next_from must be exactly one past the newest anchor"
    );

    let mut queue = alerts.lock().expect("alerts lock poisoned");
    let mut queued = 0;
    for alert in new_alerts {
        if queue.push(alert) {
            queued += 1;
        }
    }
    drop(queue);
    *cursor = advanced;
    Ok(ScanOutcome { new_alerts: queued })
}

/// Spawn the daemon watchtower driver (ADR-0001, V0-6b): ONE background tokio
/// task that runs a [`scan_pass`] every [`SCAN_INTERVAL`], carrying a reorg-aware
/// [`ScanCursor`] between passes so it advances instead of re-scanning from 0 —
/// yet rewinds and re-classifies across a reorg instead of silently missing a
/// re-orged spend. `authorized` and `alerts` are the node's shared watchtower
/// state — the same handles the `/sign` server writes/reads, so a spend the node
/// ACCEPTS is recognized and alerts surface through `GET /events`.
///
/// Each pass's [`scan_pass`] calls blocking bitcoind JSON-RPC (`chain.rs`), so
/// it runs on `spawn_blocking`: a slow RPC never stalls the async runtime and so
/// never delays `/events`. The first tick fires immediately. A failed pass is
/// logged and the cursor left unadvanced, so the next pass retries the same
/// range and no block is skipped on a transient backend error. Must be called
/// from within a tokio runtime (the daemon calls it from `#[tokio::main]`).
pub fn spawn_driver(
    backend: Arc<dyn ChainBackend + Send + Sync>,
    vault_scripts: Vec<ScriptBuf>,
    authorized: Arc<Mutex<HashSet<Txid>>>,
    alerts: Arc<Mutex<AlertQueue>>,
) {
    let vault_scripts = Arc::new(vault_scripts);
    tokio::spawn(async move {
        let mut cursor = ScanCursor::new();
        let mut ticker = tokio::time::interval(SCAN_INTERVAL);
        loop {
            ticker.tick().await; // the first tick completes immediately
            let backend = Arc::clone(&backend);
            let vault_scripts = Arc::clone(&vault_scripts);
            let authorized = Arc::clone(&authorized);
            let alerts = Arc::clone(&alerts);
            // The cursor is owned by the blocking pass and handed back, so its reorg
            // history survives across passes exactly as the old bare height did.
            let pass = tokio::task::spawn_blocking(move || {
                let outcome = scan_pass(
                    backend.as_ref(),
                    &vault_scripts,
                    &authorized,
                    &alerts,
                    &mut cursor,
                );
                (cursor, outcome)
            })
            .await;
            match pass {
                Ok((returned, Ok(_outcome))) => cursor = returned,
                Ok((returned, Err(e))) => {
                    // Cursor left unadvanced (a transient backend error) so the next
                    // pass retries the same range and skips nothing. A too-deep reorg
                    // is NOT an error here — `reconcile_cursor` resets that cursor to
                    // genesis and returns Ok, so the pass re-scans rather than sticking.
                    cursor = returned;
                    eprintln!(
                        "watchtower scan pass failed (next from {}): {e}",
                        cursor.next_from
                    );
                }
                Err(join_error) => {
                    // The panic consumed the cursor with the task. Reset to genesis:
                    // the alert queue dedups, so the redundant re-scan is harmless and
                    // no spend is missed. (A panic in the scan pass is not expected.)
                    cursor = ScanCursor::new();
                    eprintln!("watchtower scan task panicked (cursor reset to 0): {join_error}");
                }
            }
            // Schedule from pass completion, preserving the old
            // sleep-at-loop-end cadence. `MissedTickBehavior::Delay` alone
            // still permits one immediately-ready tick after a slow pass.
            ticker.reset();
        }
    });
}

/// One peer's published freshness diagnostic — the publication key and what it
/// carried. See [`AlertQueue::record_freshness`], which owns both rules.
struct PublishedFreshness {
    /// The ingress freshness high-water the publication was keyed by.
    ingress_high_water: u64,
    /// The highest `reject_count` accepted by publication state. It may exceed
    /// the last surfaced count after an equal-high-water, no-resurrection update.
    reject_count: u64,
}

/// Bounded, in-memory alert queue with a monotonic cursor (ADR-0002). Each alert
/// gets a strictly increasing sequence number; `since` returns everything past a
/// cursor with no loss and no duplication. Bounded so a noisy chain cannot grow
/// it without limit — the oldest alerts and their dedupe keys drop first
/// (acceptable for the v0 in-memory queue; DESIGN.md). A re-scan of the same
/// retained on-chain spend never enqueues a duplicate.
pub struct AlertQueue {
    /// (sequence, dedupe key, event), oldest first.
    entries: VecDeque<(u64, String, Event)>,
    /// Next sequence to assign; `next_seq - 1` is the current cursor.
    next_seq: u64,
    /// Events already queued (dedupe key), so repeated ticks are idempotent — a
    /// watchtower polls the chain, so it re-sees old spends.
    seen: HashSet<String>,
    /// What has already been PUBLISHED per peer. A freshness entry can be
    /// cap-evicted from `entries` between two concurrent handlers' publications, so
    /// the retained entry alone can neither key publication nor keep `reject_count`
    /// monotonic; this queue-independent record can. Bounded by manifest membership
    /// `n` (one key per peer), never pruned — it IS the durable record. ABSENCE
    /// means nothing has been published for that peer: high-water 0 is a real clock
    /// value, so it cannot double as that sentinel.
    published_freshness: HashMap<u16, PublishedFreshness>,
    cap: usize,
}

impl AlertQueue {
    pub fn new(cap: usize) -> AlertQueue {
        AlertQueue {
            entries: VecDeque::new(),
            next_seq: 1,
            seen: HashSet::new(),
            published_freshness: HashMap::new(),
            cap,
        }
    }

    /// Enqueue `alert` unless this exact spend was already alerted. Returns
    /// whether it was newly enqueued. Watchtower alerts are drop-on-dup: re-seeing
    /// a spend must NOT re-alert.
    pub fn push(&mut self, alert: Alert) -> bool {
        let key = format!("{}:{}", alert.spend_txid, alert.outpoint);
        if !self.seen.insert(key.clone()) {
            return false;
        }
        self.append(key, Event::Watchtower(alert));
        true
    }

    /// Record a channel freshness-rejection event (V0-8a), keyed by `(peer,
    /// ingress_high_water)` — the ingress guard's MONOTONIC freshness high-water
    /// (`IngressGuards::check_and_consume`), not the receipt wall clock. It keys
    /// publication only; the `/events` schema is unchanged.
    ///
    /// Concurrent channel handlers read that high-water and allocate their per-peer
    /// count under different locks, then take this queue's lock separately, so
    /// either can arrive reordered. Per key, on the queue-independent record above
    /// rather than on the retained entry:
    ///
    ///  - a LOWER high-water is an older concurrent observation: dropped.
    ///  - an EQUAL high-water updates count/skew in the RETAINED entry at its
    ///    existing sequence. It never calls `append`, so it evicts nothing — and an
    ///    entry already cap-evicted is NOT resurrected.
    ///  - only a STRICTLY HIGHER high-water appends (reinserting after eviction, at
    ///    a new sequence a cursor-polling client re-sees). It is the one path that
    ///    contends for queue capacity, and it keeps at most one entry per peer.
    ///
    /// The deliberate consequence: one latched-high-water outage — a forward clock
    /// excursion latches `high_water`, so every honest peer reads stale until real
    /// time catches up — publishes AT MOST ONCE per peer, and once that entry is
    /// cap-evicted the same outage's retries do not republish it. Protecting
    /// unrelated on-chain evidence beats diagnostic persistence: refreshing to the
    /// newest sequence instead cost one more `RECOVERY_PATH_SPEND` /
    /// `UNRECOGNIZED_SPEND` alert its slot on every retry from a full queue.
    ///
    /// `reject_count` stays monotonic per peer under every ordering — it is only
    /// ever published at the per-peer maximum.
    pub fn record_freshness(&mut self, event: FreshnessEvent, ingress_high_water: u64) {
        let key = format!("freshness:{}", event.peer_node_id);
        let publish_count = match self.published_freshness.get_mut(&event.peer_node_id) {
            Some(published) if ingress_high_water < published.ingress_high_water => return,
            Some(published) if ingress_high_water == published.ingress_high_water => {
                if event.reject_count <= published.reject_count {
                    return;
                }
                published.reject_count = event.reject_count;
                if let Some((_, _, retained)) = self.entries.iter_mut().find(|(_, k, _)| *k == key)
                {
                    *retained = Event::ChannelFreshness(event);
                }
                return;
            }
            Some(published) => {
                published.ingress_high_water = ingress_high_water;
                published.reject_count = published.reject_count.max(event.reject_count);
                published.reject_count
            }
            None => {
                self.published_freshness.insert(
                    event.peer_node_id,
                    PublishedFreshness {
                        ingress_high_water,
                        reject_count: event.reject_count,
                    },
                );
                event.reject_count
            }
        };
        if let Some(pos) = self.entries.iter().position(|(_, k, _)| *k == key) {
            self.entries.remove(pos);
        }
        self.seen.insert(key.clone());
        self.append(
            key,
            Event::ChannelFreshness(FreshnessEvent {
                reject_count: publish_count,
                ..event
            }),
        );
    }

    /// Assign the next sequence, enqueue, and cap-evict the oldest.
    fn append(&mut self, key: String, event: Event) {
        let seq = self.next_seq;
        self.next_seq += 1;
        self.entries.push_back((seq, key, event));
        while self.entries.len() > self.cap {
            if let Some((_, evicted_key, _)) = self.entries.pop_front() {
                self.seen.remove(&evicted_key);
            }
        }
    }

    /// Every retained alert with sequence strictly greater than `since`, plus the
    /// new cursor to carry into the next pull. The cursor is the high-water mark,
    /// so it advances even when nothing newer is returned — a client that keeps
    /// passing the returned cursor never re-fetches and never misses (within the
    /// bound).
    pub fn since(&self, since: u64) -> (Vec<Event>, u64) {
        let events = self
            .entries
            .iter()
            .filter(|(seq, _, _)| *seq > since)
            .map(|(_, _, event)| event.clone())
            .collect();
        (events, self.cursor())
    }

    /// The current high-water cursor: the sequence a fresh pull returns up to.
    pub fn cursor(&self) -> u64 {
        self.next_seq - 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::mock::MockBackend;
    use bitcoin::hashes::Hash;
    use std::thread;
    use std::time::Instant;

    fn txid(byte: u8) -> Txid {
        Txid::from_byte_array([byte; 32])
    }

    fn script(byte: u8) -> ScriptBuf {
        ScriptBuf::from(vec![byte; 4])
    }

    /// A witness that took the NORMAL (or_i IF) branch: a non-empty `01` selector
    /// sits immediately before the witness script.
    fn normal_witness() -> Witness {
        Witness::from_slice(&[vec![0x30u8; 71], vec![0x01u8], vec![0xABu8; 32]])
    }

    /// A witness that took the RECOVERY (or_i ELSE) branch: an EMPTY selector sits
    /// immediately before the witness script — the branch-identifiable signal.
    fn recovery_witness() -> Witness {
        Witness::from_slice(&[vec![0x30u8; 71], Vec::new(), vec![0xABu8; 32]])
    }

    fn spend_with(spend_byte: u8, script_byte: u8, witness: Witness) -> SpendSeen {
        SpendSeen {
            spend_txid: txid(spend_byte),
            outpoint: bitcoin::OutPoint::new(txid(0xF0 | script_byte), 0),
            script: script(script_byte),
            witness,
        }
    }

    /// A normal-branch spend (the default for the cursor/dedup/driver tests, which
    /// are about queue mechanics, not branch classification).
    fn spend(spend_byte: u8, script_byte: u8) -> SpendSeen {
        spend_with(spend_byte, script_byte, normal_witness())
    }

    // -- classification (task test 1) ---------------------------------------

    #[test]
    fn a_recovery_branch_spend_alerts_recovery_path_spend() {
        let vault = script(0x01);
        // A spend of the vault script whose WITNESS took the recovery (or_i ELSE)
        // branch — the empty selector before the witness script. Prevout script is
        // the ordinary vault script (both branches share it).
        let backend = MockBackend {
            spends: vec![spend_with(0xAA, 0x01, recovery_witness())],
            ..Default::default()
        };
        let alerts = scan(&backend, &[vault], &HashSet::new(), 0).expect("scan");
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].kind, AlertKind::RecoveryPathSpend);
    }

    #[test]
    fn a_vault_spend_the_node_never_accepted_alerts_unrecognized_spend() {
        let vault = script(0x01);
        let backend = MockBackend {
            spends: vec![spend(0xAA, 0x01)],
            ..Default::default()
        };
        // Empty authorized set: the node accepted nothing, so this normal-branch
        // spend is unknown to it.
        let alerts = scan(&backend, &[vault], &HashSet::new(), 0).expect("scan");
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].kind, AlertKind::UnrecognizedSpend);
        assert_eq!(alerts[0].spend_txid, txid(0xAA).to_string());
    }

    #[test]
    fn an_accepted_vault_spend_raises_no_alert() {
        let vault = script(0x01);
        let backend = MockBackend {
            spends: vec![spend(0xAA, 0x01)],
            ..Default::default()
        };
        // The node's authorized set holds this normal-branch spend's txid: it is
        // expected, not an alert.
        let accepted: HashSet<Txid> = [txid(0xAA)].into_iter().collect();
        let alerts = scan(&backend, &[vault], &accepted, 0).expect("scan");
        assert!(
            alerts.is_empty(),
            "a spend the node accepted must raise nothing, got {alerts:?}"
        );
    }

    #[test]
    fn recovery_is_classified_by_branch_not_by_the_authorized_set() {
        // Guard the precedence: the recovery branch is read from the witness FIRST,
        // so even a recovery-branch spend whose txid is (implausibly) in the
        // authorized set is a RecoveryPathSpend — the recovery exit is never
        // silently swallowed as an accepted normal spend, and an empty authorized
        // set never downgrades it to UnrecognizedSpend.
        let vault = script(0x01);
        let backend = MockBackend {
            spends: vec![spend_with(0xAA, 0x01, recovery_witness())],
            ..Default::default()
        };
        let authorized: HashSet<Txid> = [txid(0xAA)].into_iter().collect();
        let alerts = scan(&backend, &[vault], &authorized, 0).expect("scan");
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].kind, AlertKind::RecoveryPathSpend);
    }

    #[test]
    fn a_block_above_the_captured_terminal_height_is_not_published_early() {
        let vault = script(0x01);
        let backend = MockBackend {
            tip: 2,
            spend_block: 2,
            spends: vec![spend(0xAA, 0x01)],
            ..Default::default()
        };

        let (alerts, _blocks) = scan_through(&backend, &[vault], &HashSet::new(), 0, 1, None)
            .expect("fixed-prefix scan");
        assert!(
            alerts.is_empty(),
            "a spend above the captured tip belongs to the next pass, not this cursor advance"
        );
    }

    // -- cursor semantics (task test 2) -------------------------------------

    fn alert(n: u8) -> Alert {
        Alert::from_spend(AlertKind::UnrecognizedSpend, &spend(n, 0x01))
    }

    #[test]
    fn since_zero_returns_all_and_since_last_returns_only_newer() {
        let mut queue = AlertQueue::new(DEFAULT_ALERT_CAP);
        assert!(queue.push(alert(1)));
        assert!(queue.push(alert(2)));
        assert!(queue.push(alert(3)));

        let (all, cursor) = queue.since(0);
        assert_eq!(all.len(), 3, "since=0 returns every alert");
        assert_eq!(cursor, 3);

        // A pull from the last cursor with nothing new returns empty, same cursor.
        let (none, cursor2) = queue.since(cursor);
        assert!(none.is_empty(), "since=<last> with no new alerts is empty");
        assert_eq!(cursor2, cursor);

        // A fresh alert is returned only to a pull from the prior cursor.
        assert!(queue.push(alert(4)));
        let (newer, cursor3) = queue.since(cursor);
        assert_eq!(newer.len(), 1, "since=<last> returns only the newer alert");
        assert_eq!(newer[0].watchtower().spend_txid, txid(4).to_string());
        assert_eq!(cursor3, 4);
    }

    #[test]
    fn successive_pulls_lose_nothing_and_duplicate_nothing() {
        let mut queue = AlertQueue::new(DEFAULT_ALERT_CAP);
        for n in 1..=5 {
            assert!(queue.push(alert(n)));
        }
        // First pull takes 1..=3 (simulate by pulling, then pushing more).
        let (first, cursor) = queue.since(0);
        assert_eq!(first.len(), 5);
        for n in 6..=8 {
            assert!(queue.push(alert(n)));
        }
        let (second, _) = queue.since(cursor);
        // No loss: every pushed alert is delivered exactly once across pulls.
        assert_eq!(first.len() + second.len(), 8);
        // No duplication: the two pulls share no txid.
        let seen: HashSet<_> = first.iter().map(|a| &a.watchtower().spend_txid).collect();
        assert!(
            second
                .iter()
                .all(|a| !seen.contains(&a.watchtower().spend_txid)),
            "an alert returned in the first pull must never repeat in the second"
        );
    }

    #[test]
    fn the_same_spend_is_never_enqueued_twice() {
        let mut queue = AlertQueue::new(DEFAULT_ALERT_CAP);
        assert!(queue.push(alert(1)), "first sight enqueues");
        assert!(
            !queue.push(alert(1)),
            "a re-scan of the same spend is dropped"
        );
        let (all, _) = queue.since(0);
        assert_eq!(all.len(), 1, "the queue holds the spend once");
    }

    #[test]
    fn evicting_an_alert_evicts_its_dedupe_key() {
        let mut queue = AlertQueue::new(1);
        assert!(queue.push(alert(1)));
        assert!(queue.push(alert(2)));
        assert_eq!(
            queue.seen.len(),
            1,
            "dedupe keys must stay bounded with retained alerts"
        );

        assert!(
            queue.push(alert(1)),
            "an evicted alert's key is eligible again on a later scan"
        );
        let (retained, _) = queue.since(0);
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].watchtower().spend_txid, txid(1).to_string());
    }

    // -- freshness diagnostics (btc-policy-qzo) ------------------------------

    fn freshness(reject_count: u64, skew_secs: i64) -> FreshnessEvent {
        FreshnessEvent {
            kind: FreshnessKind::ChannelFreshnessReject,
            peer_node_id: 7,
            reject_count,
            skew_secs,
        }
    }

    /// Peer 7's retained diagnostic as `(sequence, reject_count, skew_secs)`, or
    /// `None` when the queue holds none — the entry, not the published record.
    fn retained(queue: &AlertQueue) -> Option<(u64, u64, i64)> {
        queue
            .entries
            .iter()
            .find_map(|(seq, key, event)| match event {
                Event::ChannelFreshness(f) if key == "freshness:7" => {
                    Some((*seq, f.reject_count, f.skew_secs))
                }
                _ => None,
            })
    }

    #[test]
    fn freshness_publication_keys_on_the_peer_and_the_ingress_high_water() {
        let mut queue = AlertQueue::new(DEFAULT_ALERT_CAP);
        // Concurrent handlers read the ingress high-water and allocate their count
        // under different locks, so publication arrives reordered in both. Each row
        // is `(high-water, count, skew)` applied in order, then the retained
        // `(sequence, count, skew)` and the cursor it must leave.
        let table = [
            ("first publication appends", 100, 1, -400, (1, 1, -400), 1),
            ("equal updates in place", 100, 3, -402, (1, 3, -402), 1),
            ("equal, older count drops", 100, 2, -401, (1, 3, -402), 1),
            ("lower high-water drops", 99, 9, -9, (1, 3, -402), 1),
            ("higher high-water appends", 101, 4, -500, (2, 4, -500), 2),
            ("equal again, older count", 101, 2, -1, (2, 4, -500), 2),
            ("higher keeps max count", 102, 3, -600, (3, 4, -600), 3),
        ];
        for (name, high_water, count, skew, want, want_cursor) in table {
            queue.record_freshness(freshness(count, skew), high_water);
            assert_eq!(retained(&queue), Some(want), "{name}");
            assert_eq!(queue.cursor(), want_cursor, "{name}");
        }
        assert_eq!(
            queue.entries.len(),
            1,
            "one retained freshness entry per peer, whatever the ordering"
        );
    }

    #[test]
    fn an_evicted_freshness_entry_revives_only_at_a_higher_ingress_high_water() {
        // The eviction race under one latched high-water: the diagnostic is
        // published, cap-evicted by unrelated evidence, and the outage keeps
        // producing rejects. Re-appending each one would cost another alert its
        // slot, so an equal high-water never resurrects it.
        let mut queue = AlertQueue::new(1);
        queue.record_freshness(freshness(2, -400), 100);
        // A single watchtower alert (cap == 1) evicts the freshness entry.
        assert!(queue.push(alert(1)));
        assert_eq!(retained(&queue), None, "the diagnostic was cap-evicted");

        // Neither an older concurrent publication nor a NEWER count at the same
        // latched high-water re-enters.
        queue.record_freshness(freshness(1, -399), 100);
        queue.record_freshness(freshness(3, -401), 100);
        assert_eq!(retained(&queue), None, "no equal-high-water resurrection");
        assert_eq!(
            queue.since(0).0.len(),
            1,
            "the watchtower alert keeps the only slot"
        );

        // Forward progress: a strictly higher high-water reinserts, carrying the
        // monotonic count (3 was allocated during the outage, never published).
        queue.record_freshness(freshness(3, -402), 101);
        assert_eq!(retained(&queue), Some((3, 3, -402)));
    }

    #[test]
    fn a_latched_high_water_peer_stops_displacing_watchtower_evidence() {
        // A full queue, a peer whose every reject carries ONE latched ingress
        // high-water, and unrelated on-chain alerts arriving between them. The old
        // refresh-to-newest behavior kept the diagnostic squatting one slot after
        // every reject; once evicted, this outage must stop occupying a slot.
        let mut queue = AlertQueue::new(4);
        for n in 1..=3 {
            assert!(queue.push(alert(n)));
        }
        for (n, count) in (4..=9u8).zip(1..) {
            queue.record_freshness(freshness(count, -400), 100);
            assert!(queue.push(alert(n)));
        }
        let retained_alerts: Vec<String> = queue
            .since(0)
            .0
            .iter()
            .filter_map(|event| match event {
                Event::Watchtower(a) => Some(a.spend_txid.clone()),
                Event::ChannelFreshness(_) => None,
            })
            .collect();
        assert_eq!(
            retained_alerts,
            (6..=9u8).map(|n| txid(n).to_string()).collect::<Vec<_>>(),
            "an evicted latched-high-water diagnostic must stop occupying a slot"
        );
    }

    #[test]
    fn an_equal_high_water_update_publishes_once_to_a_cursor_client() {
        let mut queue = AlertQueue::new(DEFAULT_ALERT_CAP);
        queue.record_freshness(freshness(1, -400), 100);
        let cursor = queue.since(0).1;

        // The in-place update is visible to a full pull but does NOT re-deliver to
        // a client already past that sequence: one latched-high-water outage
        // publishes at most once per peer.
        queue.record_freshness(freshness(2, -401), 100);
        assert_eq!(retained(&queue), Some((1, 2, -401)));
        let (nothing, after) = queue.since(cursor);
        assert!(nothing.is_empty(), "no new sequence at an equal high-water");
        assert_eq!(after, cursor, "the cursor does not move");

        // A strictly higher high-water reinserts, so the client sees the peer again.
        queue.record_freshness(freshness(3, -500), 101);
        let (again, moved) = queue.since(cursor);
        assert_eq!(moved, cursor + 1);
        assert!(matches!(
            again.as_slice(),
            [Event::ChannelFreshness(FreshnessEvent {
                reject_count: 3,
                ..
            })]
        ));
    }

    #[test]
    fn an_out_of_order_freshness_publication_never_regresses_the_count() {
        let mut queue = AlertQueue::new(DEFAULT_ALERT_CAP);
        queue.record_freshness(freshness(2, -400), 100);
        let cursor = queue.cursor();
        queue.record_freshness(freshness(1, -400), 100);

        let (events, after) = queue.since(0);
        assert_eq!(after, cursor, "an obsolete publication is not appended");
        assert!(matches!(
            events.as_slice(),
            [Event::ChannelFreshness(FreshnessEvent {
                reject_count: 2,
                ..
            })]
        ));
    }

    // -- the daemon driver (V0-6b) ------------------------------------------

    #[tokio::test]
    async fn the_driver_task_scans_and_surfaces_an_alert_without_an_explicit_tick() {
        // A backend reporting an unauthorized vault spend; the driver — nothing
        // else — must surface it through the shared queue.
        let vault = script(0x01);
        let backend = MockBackend {
            spends: vec![spend(0xAA, 0x01)],
            tip: 1,
            ..Default::default()
        };
        let authorized = Arc::new(Mutex::new(HashSet::new()));
        let alerts = Arc::new(Mutex::new(AlertQueue::new(DEFAULT_ALERT_CAP)));

        spawn_driver(
            Arc::new(backend),
            vec![vault],
            Arc::clone(&authorized),
            Arc::clone(&alerts),
        );

        // The first tick fires immediately; poll (bounded) until it appears — no
        // test ever calls scan/tick, proving the driver drives.
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(event) = alerts.lock().expect("alerts lock").since(0).0.first() {
                let alert = event.watchtower();
                assert_eq!(alert.kind, AlertKind::UnrecognizedSpend);
                assert_eq!(alert.spend_txid, txid(0xAA).to_string());
                return;
            }
            assert!(
                Instant::now() < deadline,
                "the driver task must surface the alert without an explicit tick"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[test]
    fn the_height_cursor_advances_so_the_second_pass_scans_only_new_blocks() {
        // The spend sits in block 5 and the chain tip is 5.
        let vault = script(0x01);
        let mut backend = MockBackend {
            spends: vec![spend(0xAA, 0x01)],
            tip: 5,
            spend_block: 5,
            ..Default::default()
        };
        let authorized = Mutex::new(HashSet::new());
        let alerts = Mutex::new(AlertQueue::new(DEFAULT_ALERT_CAP));
        let scripts = std::slice::from_ref(&vault);
        // One persistent cursor across both passes, exactly as the daemon driver
        // carries it.
        let mut cursor = ScanCursor::new();

        // First pass scans 0..=5, alerts the spend, advances the cursor to 6.
        let outcome =
            scan_pass(&backend, scripts, &authorized, &alerts, &mut cursor).expect("first pass");
        assert_eq!(cursor.next_from, 6);
        assert_eq!(outcome.new_alerts, 1);
        assert_eq!(alerts.lock().expect("alerts lock").since(0).0.len(), 1);

        // A new empty block arrives; the second pass scans only the new range.
        backend.tip = 6;
        let outcome =
            scan_pass(&backend, scripts, &authorized, &alerts, &mut cursor).expect("second pass");
        assert_eq!(cursor.next_from, 7);
        assert_eq!(outcome.new_alerts, 0);

        // The cursor advanced (0 then 6, never a re-scan from 0), and the spend
        // in the already-scanned block 5 is not re-alerted — via the height
        // advance, not the queue's dedup (the backend returns nothing past it).
        assert_eq!(
            *backend.scanned_from.lock().expect("scanned_from lock"),
            vec![0, 6]
        );
        assert_eq!(alerts.lock().expect("alerts lock").since(0).0.len(), 1);
    }

    // -- reorg-aware cursor (deliverable 9y5.3-a) ---------------------------

    #[test]
    fn a_reorg_rewinds_the_cursor_and_reclassifies_a_spend_the_reorg_surfaced() {
        let vault = script(0x01);
        // Pass 1: a quiet chain to height 10. The cursor records the block hashes of
        // 0..=10 and advances to 11.
        let mut backend = MockBackend {
            tip: 10,
            ..Default::default()
        };
        let authorized = Mutex::new(HashSet::new());
        let alerts = Mutex::new(AlertQueue::new(DEFAULT_ALERT_CAP));
        let scripts = std::slice::from_ref(&vault);
        let mut cursor = ScanCursor::new();

        let outcome =
            scan_pass(&backend, scripts, &authorized, &alerts, &mut cursor).expect("pass 1");
        assert_eq!(cursor.next_from, 11);
        assert_eq!(outcome.new_alerts, 0);

        // A reorg replaces blocks 8..=10, and an unrecognized vault spend now sits at
        // height 8 — at/below the old cursor. A bare monotonic height (11) would scan
        // 11.. and MISS it; the reorg-aware cursor must rewind to the fork and catch it.
        backend.reorg_at(8);
        backend.spends = vec![spend(0xAA, 0x01)];
        backend.spend_block = 8;

        let outcome =
            scan_pass(&backend, scripts, &authorized, &alerts, &mut cursor).expect("pass 2");
        assert_eq!(
            outcome.new_alerts, 1,
            "the reorg's spend must be classified once the cursor rewinds to the fork"
        );
        // Pass 2 re-scanned from the fork point (8), not the stale 11 — the rewind.
        assert_eq!(
            *backend.scanned_from.lock().expect("scanned_from lock"),
            vec![0, 8],
            "the second pass must re-scan from the fork point, proving the rewind"
        );
        let (queued, _) = alerts.lock().expect("alerts lock").since(0);
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].watchtower().kind, AlertKind::UnrecognizedSpend);
        assert_eq!(queued[0].watchtower().spend_txid, txid(0xAA).to_string());
        // The cursor caught back up past the (unchanged-height) tip.
        assert_eq!(cursor.next_from, 11);
    }

    #[test]
    fn a_matching_anchor_never_triggers_a_spurious_rewind() {
        // A steady chain that only grows: the newest anchor keeps matching, so no
        // pass ever rewinds — the cursor advances monotonically and re-scans nothing.
        let vault = script(0x01);
        let mut backend = MockBackend {
            tip: 3,
            ..Default::default()
        };
        let authorized = Mutex::new(HashSet::new());
        let alerts = Mutex::new(AlertQueue::new(DEFAULT_ALERT_CAP));
        let scripts = std::slice::from_ref(&vault);
        let mut cursor = ScanCursor::new();

        scan_pass(&backend, scripts, &authorized, &alerts, &mut cursor).expect("pass 1");
        backend.tip = 4;
        scan_pass(&backend, scripts, &authorized, &alerts, &mut cursor).expect("pass 2");
        backend.tip = 5;
        scan_pass(&backend, scripts, &authorized, &alerts, &mut cursor).expect("pass 3");

        assert_eq!(
            *backend.scanned_from.lock().expect("scanned_from lock"),
            vec![0, 4, 5],
            "each pass scans only the new range; a matching anchor never rewinds"
        );
    }

    #[test]
    fn a_reorg_racing_scan_and_anchor_collection_never_advances_the_cursor() {
        let vault = script(0x01);
        let backend = MockBackend {
            tip: 10,
            // `spends_of` completes against epoch 0, then this mock changes the
            // active hashes from height 8 onward before anchor collection.
            scan_reorg_from: Some(8),
            ..Default::default()
        };
        let authorized = Mutex::new(HashSet::new());
        let alerts = Mutex::new(AlertQueue::new(DEFAULT_ALERT_CAP));
        let scripts = std::slice::from_ref(&vault);
        let mut cursor = ScanCursor::new();

        let err = scan_pass(&backend, scripts, &authorized, &alerts, &mut cursor)
            .expect_err("a fork change during the scan must invalidate the pass");
        assert!(
            err.to_string().contains("changed while scanning"),
            "the race must fail loud with its cause: {err}"
        );
        assert_eq!(
            cursor.next_from, 0,
            "old-fork scan results must never advance past new-fork blocks"
        );
        assert!(
            cursor.anchors.is_empty(),
            "new-fork hashes must not be committed for an old-fork scan"
        );
        assert!(
            alerts.lock().expect("alerts lock").since(0).0.is_empty(),
            "alerts from a scan whose fork changed are not published"
        );

        scan_pass(&backend, scripts, &authorized, &alerts, &mut cursor)
            .expect("the next pass re-scans the now-stable fork");
        assert_eq!(cursor.next_from, 11);
        assert_eq!(
            *backend.scanned_from.lock().expect("scanned_from lock"),
            vec![0, 0],
            "the failed pass retries from the old cursor rather than skipping the new fork"
        );
    }

    /// The taller-fork variant of the race (v0-exit 9y5.3 [P1], BOTH reviewers): a reorg
    /// forks BELOW the cursor and rebuilds TALLER, committing in the reconcile→scan gap —
    /// after reconcile matched the old anchor but before the scan reads the new blocks.
    /// The scan's own mid-scan guards (chain-together, terminal-active) both pass on the
    /// new fork alone, and `scan_pass`'s post-scan tip re-check compares the new-fork hash
    /// to itself and passes; pre-fix the pass bound the mixed window and advanced past the
    /// reorged range, missing its spends forever. The root/boundary check now refuses it.
    #[test]
    fn a_taller_fork_reorg_in_the_reconcile_scan_gap_is_refused_not_silently_skipped() {
        let vault = script(0x01);
        // Pass 1: a quiet chain to height 10; the cursor records 0..=10 and advances to 11.
        let mut backend = MockBackend {
            tip: 10,
            ..Default::default()
        };
        let authorized = Mutex::new(HashSet::new());
        let alerts = Mutex::new(AlertQueue::new(DEFAULT_ALERT_CAP));
        let scripts = std::slice::from_ref(&vault);
        let mut cursor = ScanCursor::new();

        scan_pass(&backend, scripts, &authorized, &alerts, &mut cursor).expect("pass 1");
        assert_eq!(cursor.next_from, 11);

        // Arm a taller-fork reorg that commits the instant this pass reads the tip: it
        // forks at 5 (blocks 6.. differ) and rebuilds to 11, with a vault spend now at
        // height 7 on the new fork. Reconcile still matched the old anchor at 10 first.
        backend.reorg_from_on_tip_read = Some(6);
        backend.reorg_new_tip = Some(11);
        backend.spends = vec![spend(0xAA, 0x01)];
        backend.spend_block = 7;

        // Pass 2 must REFUSE: the new-fork block at `from_height` (11) does not chain onto
        // the old anchor at 10. Pre-fix this pass advanced to 12, skipping 6..=11 forever.
        let err = scan_pass(&backend, scripts, &authorized, &alerts, &mut cursor)
            .expect_err("a taller-fork reorg in the reconcile->scan gap must be refused");
        assert!(
            err.to_string().contains("does not chain onto"),
            "the refusal must name the broken root linkage: {err}"
        );
        assert_eq!(
            cursor.next_from, 11,
            "the cursor must NOT advance past the reorged range on a refused pass"
        );

        // The next pass reconciles: block 10 now reads the new fork, so it rewinds to the
        // fork point (5), re-scans 6..=11, and classifies the spend the reorg surfaced.
        let outcome =
            scan_pass(&backend, scripts, &authorized, &alerts, &mut cursor).expect("recovery pass");
        assert_eq!(
            outcome.new_alerts, 1,
            "the new fork's spend must be classified once the cursor rewinds to the fork"
        );
        assert_eq!(
            cursor.next_from, 12,
            "the cursor caught up to the taller tip + 1"
        );
        let (queued, _) = alerts.lock().expect("alerts lock").since(0);
        assert_eq!(queued.len(), 1);
        assert_eq!(
            queued[0].watchtower().kind,
            AlertKind::UnrecognizedSpend,
            "the surfaced spend is an unrecognized-spend alert"
        );
    }

    /// A height-SHRINKING reorg racing the reconcile→tip gap must NOT wedge the cursor
    /// (v0-exit 9y5.3 review, [P1] Fable). Reconcile matches the newest anchor (chain
    /// still tall), then the chain shrinks below it before the tip read. Committing
    /// `next_from = tip + 1` there would drop `next_from` below the retained anchor and
    /// the root-linkage check would then refuse every later pass forever. The pass must
    /// instead leave the cursor untouched so the next reconcile rewinds.
    #[test]
    fn a_shrinking_reorg_in_the_reconcile_scan_gap_does_not_wedge_the_cursor() {
        let vault = script(0x01);
        let mut backend = MockBackend {
            tip: 10,
            ..Default::default()
        };
        let authorized = Mutex::new(HashSet::new());
        let alerts = Mutex::new(AlertQueue::new(DEFAULT_ALERT_CAP));
        let scripts = std::slice::from_ref(&vault);
        let mut cursor = ScanCursor::new();

        scan_pass(&backend, scripts, &authorized, &alerts, &mut cursor).expect("pass 1");
        assert_eq!(cursor.next_from, 11);

        // A shorter fork (forks at 5, rebuilds only to height 8) commits the instant the
        // pass reads the tip — after reconcile matched the old anchor at 10.
        backend.reorg_from_on_tip_read = Some(6);
        backend.reorg_new_tip = Some(8);

        // Pass 2: the chain is now shorter than the newest anchor (8 < 10), so the pass
        // does NOT advance. The cursor invariant `next_from == anchors.back() + 1` holds.
        let outcome = scan_pass(&backend, scripts, &authorized, &alerts, &mut cursor)
            .expect("the shrinking-gap pass returns without advancing, never an error");
        assert_eq!(outcome.new_alerts, 0);
        assert_eq!(
            cursor.next_from, 11,
            "a shrink race must not drop next_from below the retained anchor"
        );
        assert_eq!(
            cursor.next_from,
            cursor.anchors.back().expect("anchors").0 + 1,
            "the cursor invariant is preserved: next_from is one past the newest anchor"
        );

        // Pass 3: the shorter chain is stable, so reconcile now detects the reorg (block 10
        // is gone), rewinds to the fork, and re-scans — the cursor recovers, never wedges.
        scan_pass(&backend, scripts, &authorized, &alerts, &mut cursor)
            .expect("the next pass reconciles the shorter chain rather than wedging");
        assert_eq!(
            cursor.next_from, 9,
            "reconcile rewound to the fork and re-scanned up to the new (shorter) tip"
        );
    }

    #[test]
    fn exactly_max_reorg_depth_retains_the_fork_anchor_and_rewinds() {
        let vault = script(0x01);
        let mut backend = MockBackend {
            tip: MAX_REORG_DEPTH,
            ..Default::default()
        };
        let authorized = Mutex::new(HashSet::new());
        let alerts = Mutex::new(AlertQueue::new(DEFAULT_ALERT_CAP));
        let scripts = std::slice::from_ref(&vault);
        let mut cursor = ScanCursor::new();

        scan_pass(&backend, scripts, &authorized, &alerts, &mut cursor).expect("initial pass");
        assert_eq!(
            cursor.anchors.len(),
            MAX_REORG_DEPTH as usize + 1,
            "the replaced blocks plus their fork point must all be retained"
        );

        // Replace heights 1..=MAX_REORG_DEPTH: exactly MAX_REORG_DEPTH blocks,
        // with genesis (height 0) as the still-matching fork point.
        backend.reorg_at(1);
        scan_pass(&backend, scripts, &authorized, &alerts, &mut cursor)
            .expect("the documented maximum-depth reorg must be recoverable");
        assert_eq!(
            *backend.scanned_from.lock().expect("scanned_from lock"),
            vec![0, 1],
            "the cursor rewinds to one past the retained fork point"
        );
    }

    #[test]
    fn a_reorg_deeper_than_the_retained_window_resets_to_genesis_and_rescans() {
        let vault = script(0x01);
        let mut backend = MockBackend {
            tip: 5,
            ..Default::default()
        };
        let authorized = Mutex::new(HashSet::new());
        let alerts = Mutex::new(AlertQueue::new(DEFAULT_ALERT_CAP));
        let scripts = std::slice::from_ref(&vault);
        let mut cursor = ScanCursor::new();

        scan_pass(&backend, scripts, &authorized, &alerts, &mut cursor).expect("pass 1");

        // Every retained anchor is re-orged out — a reorg deeper than the whole
        // trailing window, so no fork point is recoverable.
        backend.reorg_at(0);

        scan_pass(&backend, scripts, &authorized, &alerts, &mut cursor)
            .expect("a too-deep reorg resets to genesis and re-scans, never wedges or errors");
        // The cursor reset to genesis and re-scanned the whole chain from 0 rather
        // than wedging (which would permanently stall a sealed node) or silently
        // advancing past the re-orged blocks: the second recorded scan starts at 0.
        assert_eq!(
            *backend.scanned_from.lock().expect("scanned_from lock"),
            vec![0, 0],
            "the too-deep reorg must re-scan the whole chain from genesis"
        );
        // Having re-scanned, it re-anchored on the NEW chain and advanced past the
        // tip, so it self-heals in one pass instead of re-scanning from 0 forever.
        assert_eq!(cursor.next_from, backend.tip + 1);
        assert_eq!(
            cursor.anchors.back().map(|&(h, _)| h),
            Some(backend.tip),
            "the newest anchor is the re-scanned tip on the recovered chain"
        );
    }

    #[test]
    fn the_shared_state_is_safe_under_a_concurrent_signer_and_scanner() {
        // Two threads on the SAME shared handles. The scanner is the driver's
        // work — read the authorized set, write the alert queue. The main thread drives
        // the exact shared-state touchpoints of the other two routes: `/sign`
        // writes the authorized set (`authorized.lock().insert`, lib.rs step 11)
        // and `/events` reads the queue (`alerts.lock().since`, `Node::events`).
        // Every access goes through a `Mutex`, so the two threads serialize with
        // no data race — a `RefCell` here would not even compile across threads,
        // and that this does (and stays consistent under contention) is the proof.
        let vault = script(0x01);
        let authorized = Arc::new(Mutex::new(HashSet::new()));
        let alerts = Arc::new(Mutex::new(AlertQueue::new(DEFAULT_ALERT_CAP)));

        let scanner = {
            let authorized = Arc::clone(&authorized);
            let alerts = Arc::clone(&alerts);
            let vault = vault.clone();
            // The spend's txid (0xFF) is one the signer below never records
            // (it inserts only 0x00..=0x07), so it is always unrecognized and the
            // final count is race-independent.
            thread::spawn(move || {
                let backend = MockBackend {
                    spends: vec![spend(0xFF, 0x01)],
                    tip: 1,
                    ..Default::default()
                };
                let scripts = std::slice::from_ref(&vault);
                for _ in 0..8 {
                    // A fresh cursor each pass deliberately re-scans from 0, so the
                    // queue's dedup — not the height advance — is what is under test.
                    let mut cursor = ScanCursor::new();
                    scan_pass(&backend, scripts, &authorized, &alerts, &mut cursor)
                        .expect("scan pass");
                }
            })
        };

        // Concurrently exercise the `/sign` write path and the `/events` read path.
        for n in 0..8u32 {
            authorized
                .lock()
                .expect("authorized lock")
                .insert(txid((n % 251) as u8));
            let _ = alerts.lock().expect("alerts lock").since(0);
        }
        scanner.join().expect("scanner thread must not panic");

        // The one unrecognized spend surfaced exactly once across repeated passes and
        // the concurrent signer — locking + dedup held.
        let (queued, _) = alerts.lock().expect("alerts lock").since(0);
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].watchtower().spend_txid, txid(0xFF).to_string());
    }
}
