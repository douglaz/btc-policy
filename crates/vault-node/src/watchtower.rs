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
//! The scan is a callable pass, not a background thread, so callers can drive it
//! deterministically.

use std::collections::{HashSet, VecDeque};

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
}
