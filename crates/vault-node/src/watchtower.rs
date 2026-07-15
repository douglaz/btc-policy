//! Watchtower duty (ADR-0001): every node watches its OWN chain view and queues
//! a structured [`Alert`] for two events —
//!
//!  - **RecoveryPathSpend**: a spend that took the timelocked recovery branch.
//!  - **UnrecognizedSpend**: a spend of a vault UTXO whose txid this node never
//!    co-signed (a node knows every spend it participated in from its sign log,
//!    so an unrecognized one is by definition out-of-band).
//!
//! A co-signed spend of the vault raises nothing — it is exactly what the node
//! authorized. Alerts are pulled by the coordinator (ADR-0002); nodes never push.
//!
//! The classification [`scan`] is a callable pass, deterministic and driven by a
//! caller (the tests). In the running daemon a thin loop drives it: each node is
//! its own watchtower (ADR-0001), so [`spawn_driver`] spawns ONE background
//! thread that runs a pass every [`SCAN_INTERVAL`], advancing a height cursor so
//! each pass scans only new blocks and writing into the same alert queue
//! `GET /events` reads.

use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use bitcoin::{ScriptBuf, Txid};
use serde::Serialize;

use crate::chain::{ChainBackend, SpendSeen};
use crate::Error;

/// Default bound on the in-memory alert queue.
pub const DEFAULT_ALERT_CAP: usize = 1024;

/// The two watchtower events (DESIGN.md, "Watchtower"). Serialized
/// SCREAMING_SNAKE for the pull wire, like the refusal codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AlertKind {
    /// A spend took the recovery branch — stolen recovery keys, or a legitimate
    /// recovery; either way the user must be told (DESIGN.md, Wallet Topology).
    RecoveryPathSpend,
    /// A vault UTXO was spent by a transaction this node never co-signed.
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

/// Classify each observed spend into the alerts to queue.
///
/// Precedence (DESIGN.md, "Watchtower"): a spend of a recovery-branch script is a
/// `RecoveryPathSpend` even though the node never co-signed it — the recovery path
/// uses recovery keys, not node keys, so the sign-log test would otherwise
/// mislabel it. Any other spend the backend surfaced is a spend of a vault UTXO
/// (the backend was only asked for these two script sets); it is an
/// `UnrecognizedSpend` unless its txid is in `signed_txids`, the node's sign log.
///
/// This keys recovery off a DISTINCT prevout script set — correct for v0, whose
/// recovery set is empty. In v1 the real (Liana-style) recovery branch shares the
/// vault's scriptPubKey, so the branch must be read from the spending witness, not
/// the prevout script; see [`SpendSeen::script`].
fn classify(
    spends: &[SpendSeen],
    recovery_scripts: &HashSet<ScriptBuf>,
    signed_txids: &HashSet<Txid>,
) -> Vec<Alert> {
    let mut alerts = Vec::new();
    for spend in spends {
        if recovery_scripts.contains(&spend.script) {
            alerts.push(Alert::from_spend(AlertKind::RecoveryPathSpend, spend));
        } else if !signed_txids.contains(&spend.spend_txid) {
            alerts.push(Alert::from_spend(AlertKind::UnrecognizedSpend, spend));
        }
    }
    alerts
}

/// One watchtower scan pass: ask `backend` for spends of the vault and recovery
/// scripts at or after `from_height`, then classify them against the sign log.
/// The first-light vault has no recovery branch, so `recovery_scripts` is empty
/// there; the classification is exercised directly in the tests.
pub fn scan(
    backend: &dyn ChainBackend,
    vault_scripts: &[ScriptBuf],
    recovery_scripts: &[ScriptBuf],
    signed_txids: &HashSet<Txid>,
    from_height: u32,
) -> Result<Vec<Alert>, Error> {
    let mut watched = vault_scripts.to_vec();
    watched.extend_from_slice(recovery_scripts);
    let spends = backend.spends_of(&watched, from_height)?;
    let recovery: HashSet<ScriptBuf> = recovery_scripts.iter().cloned().collect();
    Ok(classify(&spends, &recovery, signed_txids))
}

/// Interval between watchtower scan passes in the daemon driver. A `const`, not a
/// config knob — small so a regtest spend surfaces quickly (DESIGN.md keeps the
/// v0 watchtower deliberately minimal).
pub const SCAN_INTERVAL: Duration = Duration::from_secs(10);

/// Outcome of one [`scan_pass`]: how many new alerts it queued and the cursor to
/// carry into the next pass.
pub(crate) struct ScanOutcome {
    pub(crate) new_alerts: usize,
    pub(crate) next_from: u32,
}

/// One scan pass, shared by the daemon driver and the callable
/// [`Node::watchtower_tick`](crate::Node::watchtower_tick) so tests and
/// production run ONE code path: read the tip, snapshot the sign log, run the
/// [`scan`] classification over `vault_scripts` at or after `from_height`, and
/// queue the new alerts. Returns the new-alert count and the next cursor —
/// `tip + 1`, so the following pass skips the blocks this one covered (the height
/// advance is the primary de-duplication; the queue guards the small overlap a
/// racing block can leave). When the cursor is already caught up, the scan range
/// is empty and the cursor remains caught up — never a re-scan from 0.
///
/// The sign log is snapshotted (and its lock released) before the possibly-slow
/// backend fetch, so a concurrent `/sign` is never blocked on chain I/O. The
/// vault has no recovery branch in v0, so the recovery script set is empty here
/// (see [`scan`]).
pub(crate) fn scan_pass(
    backend: &dyn ChainBackend,
    vault_scripts: &[ScriptBuf],
    sign_log: &Mutex<HashSet<Txid>>,
    alerts: &Mutex<AlertQueue>,
    from_height: u32,
) -> Result<ScanOutcome, Error> {
    let tip = backend.tip_height()?;
    let signed = sign_log.lock().expect("sign_log lock poisoned").clone();
    let new_alerts = scan(backend, vault_scripts, &[], &signed, from_height)?;
    let mut queue = alerts.lock().expect("alerts lock poisoned");
    let mut queued = 0;
    for alert in new_alerts {
        if queue.push(alert) {
            queued += 1;
        }
    }
    Ok(ScanOutcome {
        new_alerts: queued,
        next_from: tip + 1,
    })
}

/// Spawn the daemon watchtower driver (ADR-0001, V0-6b): ONE background thread
/// that runs a [`scan_pass`] every [`SCAN_INTERVAL`], carrying a height cursor
/// between passes so it advances instead of re-scanning from 0. `sign_log` and
/// `alerts` are the node's shared watchtower state — the same handles the `/sign`
/// server writes/reads, so a spend the node co-signs is recognized and alerts
/// surface through `GET /events`.
///
/// The first pass runs immediately (before the first sleep). A failed pass is
/// logged and the cursor is left unadvanced, so the next pass retries the same
/// range and no block is skipped on a transient backend error.
pub fn spawn_driver(
    backend: Box<dyn ChainBackend + Send>,
    vault_scripts: Vec<ScriptBuf>,
    sign_log: Arc<Mutex<HashSet<Txid>>>,
    alerts: Arc<Mutex<AlertQueue>>,
) {
    thread::spawn(move || {
        let mut from_height = 0u32;
        loop {
            match scan_pass(
                backend.as_ref(),
                &vault_scripts,
                &sign_log,
                &alerts,
                from_height,
            ) {
                Ok(outcome) => from_height = outcome.next_from,
                Err(e) => eprintln!("watchtower scan pass failed (cursor {from_height}): {e}"),
            }
            thread::sleep(SCAN_INTERVAL);
        }
    });
}

/// Bounded, in-memory alert queue with a monotonic cursor (ADR-0002). Each alert
/// gets a strictly increasing sequence number; `since` returns everything past a
/// cursor with no loss and no duplication. Bounded so a noisy chain cannot grow
/// it without limit — the oldest alerts and their dedupe keys drop first
/// (acceptable for the v0 in-memory queue; DESIGN.md). A re-scan of the same
/// retained on-chain spend never enqueues a duplicate.
pub struct AlertQueue {
    /// (sequence, dedupe key, alert), oldest first.
    entries: VecDeque<(u64, String, Alert)>,
    /// Next sequence to assign; `next_seq - 1` is the current cursor.
    next_seq: u64,
    /// Spends already alerted (`spend_txid:outpoint`), so repeated ticks are
    /// idempotent — a watchtower polls the chain, so it re-sees old spends.
    seen: HashSet<String>,
    cap: usize,
}

impl AlertQueue {
    pub fn new(cap: usize) -> AlertQueue {
        AlertQueue {
            entries: VecDeque::new(),
            next_seq: 1,
            seen: HashSet::new(),
            cap,
        }
    }

    /// Enqueue `alert` unless this exact spend was already alerted. Returns
    /// whether it was newly enqueued.
    pub fn push(&mut self, alert: Alert) -> bool {
        let key = format!("{}:{}", alert.spend_txid, alert.outpoint);
        if !self.seen.insert(key.clone()) {
            return false;
        }
        let seq = self.next_seq;
        self.next_seq += 1;
        self.entries.push_back((seq, key, alert));
        while self.entries.len() > self.cap {
            if let Some((_, evicted_key, _)) = self.entries.pop_front() {
                self.seen.remove(&evicted_key);
            }
        }
        true
    }

    /// Every retained alert with sequence strictly greater than `since`, plus the
    /// new cursor to carry into the next pull. The cursor is the high-water mark,
    /// so it advances even when nothing newer is returned — a client that keeps
    /// passing the returned cursor never re-fetches and never misses (within the
    /// bound).
    pub fn since(&self, since: u64) -> (Vec<Alert>, u64) {
        let alerts = self
            .entries
            .iter()
            .filter(|(seq, _, _)| *seq > since)
            .map(|(_, _, alert)| alert.clone())
            .collect();
        (alerts, self.cursor())
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
    use std::time::Instant;

    fn txid(byte: u8) -> Txid {
        Txid::from_byte_array([byte; 32])
    }

    fn script(byte: u8) -> ScriptBuf {
        ScriptBuf::from(vec![byte; 4])
    }

    fn spend(spend_byte: u8, script_byte: u8) -> SpendSeen {
        SpendSeen {
            spend_txid: txid(spend_byte),
            outpoint: bitcoin::OutPoint::new(txid(0xF0 | script_byte), 0),
            script: script(script_byte),
        }
    }

    // -- classification (task test 1) ---------------------------------------

    #[test]
    fn a_recovery_path_spend_alerts_recovery_path_spend() {
        let vault = script(0x01);
        let recovery = script(0x02);
        // The backend reports a spend of the recovery-branch script.
        let backend = MockBackend {
            spends: vec![spend(0xAA, 0x02)],
            ..Default::default()
        };
        let alerts = scan(&backend, &[vault], &[recovery], &HashSet::new(), 0).expect("scan");
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].kind, AlertKind::RecoveryPathSpend);
    }

    #[test]
    fn a_vault_spend_never_co_signed_alerts_unrecognized_spend() {
        let vault = script(0x01);
        let backend = MockBackend {
            spends: vec![spend(0xAA, 0x01)],
            ..Default::default()
        };
        // Empty sign log: the node co-signed nothing, so this spend is unknown.
        let alerts = scan(&backend, &[vault], &[], &HashSet::new(), 0).expect("scan");
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].kind, AlertKind::UnrecognizedSpend);
        assert_eq!(alerts[0].spend_txid, txid(0xAA).to_string());
    }

    #[test]
    fn a_co_signed_vault_spend_raises_no_alert() {
        let vault = script(0x01);
        let backend = MockBackend {
            spends: vec![spend(0xAA, 0x01)],
            ..Default::default()
        };
        // The node's sign log holds this spend's txid: it is expected, not an
        // alert.
        let signed: HashSet<Txid> = [txid(0xAA)].into_iter().collect();
        let alerts = scan(&backend, &[vault], &[], &signed, 0).expect("scan");
        assert!(
            alerts.is_empty(),
            "a spend the node co-signed must raise nothing, got {alerts:?}"
        );
    }

    #[test]
    fn a_recovery_spend_alerts_recovery_even_though_it_was_never_co_signed() {
        // Guard the precedence: the recovery branch is never co-signed, so an
        // empty sign log must NOT downgrade it to UnrecognizedSpend.
        let recovery = script(0x02);
        let backend = MockBackend {
            spends: vec![spend(0xAA, 0x02)],
            ..Default::default()
        };
        let alerts = scan(&backend, &[], &[recovery], &HashSet::new(), 0).expect("scan");
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].kind, AlertKind::RecoveryPathSpend);
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
        assert_eq!(newer[0].spend_txid, txid(4).to_string());
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
        let seen: HashSet<_> = first.iter().map(|a| &a.spend_txid).collect();
        assert!(
            second.iter().all(|a| !seen.contains(&a.spend_txid)),
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
        assert_eq!(retained[0].spend_txid, txid(1).to_string());
    }

    // -- the daemon driver (V0-6b) ------------------------------------------

    #[test]
    fn the_driver_thread_scans_and_surfaces_an_alert_without_an_explicit_tick() {
        // A backend reporting an un-co-signed vault spend; the driver — nothing
        // else — must surface it through the shared queue.
        let vault = script(0x01);
        let backend = MockBackend {
            spends: vec![spend(0xAA, 0x01)],
            tip: 1,
            ..Default::default()
        };
        let sign_log = Arc::new(Mutex::new(HashSet::new()));
        let alerts = Arc::new(Mutex::new(AlertQueue::new(DEFAULT_ALERT_CAP)));

        spawn_driver(
            Box::new(backend),
            vec![vault],
            Arc::clone(&sign_log),
            Arc::clone(&alerts),
        );

        // The first pass runs immediately; poll (bounded) until it appears — no
        // test ever calls scan/tick, proving the driver drives.
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(alert) = alerts.lock().expect("alerts lock").since(0).0.first() {
                assert_eq!(alert.kind, AlertKind::UnrecognizedSpend);
                assert_eq!(alert.spend_txid, txid(0xAA).to_string());
                return;
            }
            assert!(
                Instant::now() < deadline,
                "the driver thread must surface the alert without an explicit tick"
            );
            thread::sleep(Duration::from_millis(10));
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
        let sign_log = Mutex::new(HashSet::new());
        let alerts = Mutex::new(AlertQueue::new(DEFAULT_ALERT_CAP));
        let scripts = std::slice::from_ref(&vault);

        // First pass scans 0..=5, alerts the spend, advances the cursor to 6.
        let outcome = scan_pass(&backend, scripts, &sign_log, &alerts, 0).expect("first pass");
        assert_eq!(outcome.next_from, 6);
        assert_eq!(outcome.new_alerts, 1);
        assert_eq!(alerts.lock().expect("alerts lock").since(0).0.len(), 1);

        // A new empty block arrives; the second pass scans only the new range.
        backend.tip = 6;
        let outcome = scan_pass(&backend, scripts, &sign_log, &alerts, outcome.next_from)
            .expect("second pass");
        assert_eq!(outcome.next_from, 7);
        assert_eq!(outcome.new_alerts, 0);

        // The cursor advanced (0 then 6, never a re-scan from 0), and the spend
        // in the already-scanned block 5 is not re-alerted — via the height
        // advance, not the queue's dedup (the backend returns nothing past it).
        assert_eq!(*backend.scanned_from.borrow(), vec![0, 6]);
        assert_eq!(alerts.lock().expect("alerts lock").since(0).0.len(), 1);
    }

    #[test]
    fn the_shared_state_is_safe_under_a_concurrent_signer_and_scanner() {
        // Two threads on the SAME shared handles. The scanner is the driver's
        // work — read the sign log, write the alert queue. The main thread drives
        // the exact shared-state touchpoints of the other two routes: `/sign`
        // writes the sign log (`sign_log.lock().insert`, lib.rs handler step 8)
        // and `/events` reads the queue (`alerts.lock().since`, `Node::events`).
        // Every access goes through a `Mutex`, so the two threads serialize with
        // no data race — a `RefCell` here would not even compile across threads,
        // and that this does (and stays consistent under contention) is the proof.
        let vault = script(0x01);
        let sign_log = Arc::new(Mutex::new(HashSet::new()));
        let alerts = Arc::new(Mutex::new(AlertQueue::new(DEFAULT_ALERT_CAP)));

        let scanner = {
            let sign_log = Arc::clone(&sign_log);
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
                    scan_pass(&backend, scripts, &sign_log, &alerts, 0).expect("scan pass");
                }
            })
        };

        // Concurrently exercise the `/sign` write path and the `/events` read path.
        for n in 0..8u32 {
            sign_log
                .lock()
                .expect("sign_log lock")
                .insert(txid((n % 251) as u8));
            let _ = alerts.lock().expect("alerts lock").since(0);
        }
        scanner.join().expect("scanner thread must not panic");

        // The one unrecognized spend surfaced exactly once across repeated passes and
        // the concurrent signer — locking + dedup held.
        let (queued, _) = alerts.lock().expect("alerts lock").since(0);
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].spend_txid, txid(0xFF).to_string());
    }
}
