//! The per-node chain backend (DESIGN.md, "Per-node chain backend"; ADR-0001).
//!
//! A deliberately small trait the node uses for two jobs:
//!
//!  1. **broadcast** — push a fully-signed transaction to the network. V0-4's
//!     node-distributed duress broadcast (ADR-0008) needs each node able to
//!     broadcast on its own; this task provides the primitive, nothing more.
//!  2. **spends_of** — the watchtower scan (ADR-0001): spends of the vault's
//!     watched scriptPubKeys, as seen by THIS node's own chain view.
//!
//! v0 ships the trait seam plus one minimal `bitcoind`-RPC impl for regtest. The
//! Core/Electrum/BIP158 choice and the lying-coordinator prevout enforcement stay
//! v1 (T6): the backend is **not** wired into the policy fee/ownership checks
//! here — those still trust each input's `witness_utxo`, exactly as in v0. Being a
//! trait, unit tests use a mock and never need bitcoind.

use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::str::FromStr;
use std::time::Duration;

use bitcoin::consensus::encode::serialize_hex;
use bitcoin::hex::{DisplayHex, FromHex};
use bitcoin::{consensus, Amount, OutPoint, ScriptBuf, Transaction, TxOut, Txid, Witness};
use serde_json::{json, Value};

use crate::Error;

/// One on-chain spend of a watched scriptPubKey, from the watchtower scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpendSeen {
    /// Txid of the transaction that spent the watched output.
    pub spend_txid: Txid,
    /// The watched output that was consumed (the vault UTXO).
    pub outpoint: OutPoint,
    /// scriptPubKey of the spent output — one of the queried `scripts`.
    ///
    /// The vault descriptor puts recovery as an alternate BRANCH inside the SAME
    /// `wsh(...)` (ADR-0013 §1; DESIGN.md, Wallet Topology — recovery is "an
    /// alternate spend path over the same coins"), so a recovery spend and a
    /// normal spend share this prevout scriptPubKey and CANNOT be told apart by
    /// it. The distinguishing signal is [`Self::witness`] (which script branch the
    /// spend satisfied), not this script.
    pub script: ScriptBuf,
    /// The witness stack of the input that spent the watched output. The
    /// watchtower reads it to tell a recovery-branch spend from a normal-branch
    /// spend (they share `script`): the template's top-level `or_i` puts an
    /// explicit branch selector immediately before the witness script, so the
    /// second-from-last element is `01` for the normal branch and EMPTY for the
    /// recovery branch (see `watchtower::is_recovery_branch`).
    pub witness: Witness,
}

/// One prevout as this node sees it across its confirmed chain AND its own
/// mempool (ADR-0012, "build over the mempool UTXO set, not confirmed-only").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prevout {
    /// The output being spent.
    pub txout: TxOut,
    /// Whether the transaction that created this output is confirmed. An
    /// UNCONFIRMED prevout is spendable by a vault transaction only when its
    /// parent is vault-authorized (see [`assemble_package`]).
    pub confirmed: bool,
}

/// The outcome of a full package mempool-acceptance test (ADR-0012: "the
/// assembled package passes the node backend's full package-mempool-acceptance
/// test, not merely relay-standard").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackageVerdict {
    /// Every transaction in the package is acceptable to this node's mempool.
    Accepted,
    /// At least one is not; the reason is the backend's, verbatim.
    Rejected(String),
}

/// A node's own view of the chain (DESIGN.md, "Per-node chain backend"). Serves
/// broadcast, the watchtower scan (ADR-0001), and V0-8b's package-gated combine.
/// Kept small on purpose so unit tests substitute a mock.
pub trait ChainBackend {
    /// Push a fully-signed, consensus-serialized transaction to the network,
    /// returning its txid. A malformed transaction is an `Err`, never a panic.
    fn broadcast(&self, raw_tx: &[u8]) -> Result<Txid, Error>;

    /// The height of this node's chain tip. The watchtower driver (V0-6b) reads
    /// it to advance its scan cursor past already-scanned blocks instead of
    /// re-scanning from height 0 every pass.
    fn tip_height(&self) -> Result<u32, Error>;

    /// Spends of any of `scripts` observed in blocks at or after `from_height`,
    /// against this node's own chain data.
    fn spends_of(&self, scripts: &[ScriptBuf], from_height: u32) -> Result<Vec<SpendSeen>, Error>;

    /// The unspent output at `outpoint` as this node sees it, **including its own
    /// mempool**. `None` ⇒ this node cannot see the output (unknown or already
    /// spent). Confirmed-only would strand the common case: spend-change and
    /// refresh outputs are usually still unconfirmed (ADR-0012).
    fn prevout(&self, outpoint: &OutPoint) -> Result<Option<Prevout>, Error>;

    /// Every currently-unspent output paying one of `scripts` in this node's
    /// confirmed UTXO set, plus unconfirmed outputs whose parent txid is in the
    /// node's validated-and-policy-accepted `authorized` set. This is the
    /// fire-time whole-vault denominator for ADR-0012/0013 coverage. External
    /// unconfirmed deposits are deliberately excluded (toxic-deposit safe).
    fn vault_unspent(
        &self,
        scripts: &[ScriptBuf],
        authorized: &HashSet<Txid>,
    ) -> Result<Vec<(OutPoint, Prevout)>, Error>;

    /// Raw consensus bytes of `txid` iff it is in this node's mempool. This is the
    /// ancestor lookup used after the first package level: a mempool parent's own
    /// inputs are already spent, so `gettxout` cannot inspect them. Membership in
    /// the mempool distinguishes another unconfirmed ancestor from a confirmed
    /// parent without requiring `-txindex`.
    fn mempool_transaction(&self, txid: &Txid) -> Result<Option<Vec<u8>>, Error>;

    /// Whether `txid` is confirmed in this node's active chain. A candidate may
    /// move from the mempool into a block before this node's redundant fire pass;
    /// recognizing that confirmation is what lets the node settle its local Hold
    /// instead of mistaking already-spent inputs for a package-assembly failure.
    fn transaction_confirmed(&self, txid: &Txid) -> Result<bool, Error>;

    /// Test whether the candidate package would be accepted into this node's
    /// mempool. [`assemble_package`] supplies the new candidate alone after
    /// verifying that every unconfirmed ancestor is already present and
    /// vault-authorized; Core evaluates that full in-mempool ancestry when testing
    /// the candidate. Broadcast is gated on this.
    fn test_package_accept(&self, raw_txs: &[Vec<u8>]) -> Result<PackageVerdict, Error>;
}

/// Cap on the unconfirmed ancestors one broadcast package may absorb (ADR-0012:
/// "package/ancestor limits cap how many unconfirmed chains one escape can
/// absorb — deep/numerous unconfirmed value may need a follow-up sweep"). Sits
/// just under Core's default 25-ancestor mempool limit, which the package would
/// hit anyway; exceeding it is a clean `Err` (no broadcast), never a hang or a
/// package the backend will reject after the fact.
pub const MAX_PACKAGE_ANCESTORS: usize = 24;

/// Assemble the mempool-acceptance package for `tx` after validating every
/// unconfirmed ancestor it chains off (ADR-0012, "build over the mempool UTXO
/// set"). The returned package contains `tx` alone: every discovered ancestor is
/// already in this node's mempool by construction, and Core's package policy
/// rejects packages that re-list multi-generation/already-present ancestry. A
/// singleton `testmempoolaccept` still evaluates the candidate against that full
/// mempool ancestor set.
///
/// `authorized` is this node's validated-AND-policy-ACCEPTED transaction set. It
/// is what separates the two kinds of unconfirmed parent, and the distinction is
/// load-bearing:
///
/// - a **vault-authorized** unconfirmed parent (this vault's own spend-change or
///   refresh) may be chained onto, because it cannot be pulled out from under the
///   child: replacing it needs a conflicting vault spend, which needs the user key
///   AND `t`-of-`n` node signatures a post-wrench attacker cannot obtain. So the
///   parent confirms, so the child confirms.
/// - an **external** unconfirmed deposit is EXCLUDED (an `Err` here, so nothing is
///   broadcast). Its parent is not vault-authorized and can be replaced at will —
///   a "toxic deposit" an attacker double-spends to poison whatever chains off it.
///   A genuine deposit arriving at this moment is a straggler: it is swept by the
///   next escape or recovered via the timelock. Funds-safe either way.
///
/// A confirmed prevout needs no ancestor. `Err` means "do not broadcast" — an
/// unknown prevout, an excluded external deposit, or an over-deep chain — and is
/// always a refusal to act, never a panic.
pub fn assemble_package(
    backend: &dyn ChainBackend,
    tx: &Transaction,
    authorized: &HashSet<Txid>,
) -> Result<Vec<Vec<u8>>, Error> {
    let mut seen = HashSet::new();
    validate_ancestors(backend, tx, authorized, &mut seen, true)?;
    Ok(vec![consensus::serialize(tx)])
}

/// Walk `tx`'s unconfirmed authorized ancestors. `seen` dedups diamond ancestry
/// and bounds both recursion depth and total ancestry checked. The raw ancestors
/// are read to continue validation, not returned to `testmempoolaccept`: their
/// successful mempool lookup proves they are already part of the chain view Core
/// will evaluate for the singleton candidate.
fn validate_ancestors(
    backend: &dyn ChainBackend,
    tx: &Transaction,
    authorized: &HashSet<Txid>,
    seen: &mut HashSet<Txid>,
    inputs_are_unspent: bool,
) -> Result<(), Error> {
    for input in &tx.input {
        let outpoint = input.previous_output;
        let parent_txid = outpoint.txid;
        let raw = if inputs_are_unspent {
            // Only the candidate's own inputs are unspent in this node's mempool
            // view, so gettxout can tell confirmed from unconfirmed here.
            let prevout = backend.prevout(&outpoint)?.ok_or_else(|| {
                format!(
                    "prevout {outpoint} is unknown to this node's chain view (unknown or spent)"
                )
            })?;
            if prevout.confirmed {
                continue;
            }
            backend.mempool_transaction(&parent_txid)?.ok_or_else(|| {
                format!("unconfirmed parent {parent_txid} disappeared from this node's mempool")
            })?
        } else {
            // `tx` is itself in the mempool, so its inputs are spent there and
            // gettxout would return null. An input's parent that is also in the
            // mempool is an unconfirmed ancestor; absence means that parent is
            // confirmed (Core admits no orphan inputs to its mempool).
            let Some(raw) = backend.mempool_transaction(&parent_txid)? else {
                continue;
            };
            raw
        };
        if !authorized.contains(&parent_txid) {
            return Err(format!(
                "input {outpoint} chains off unconfirmed transaction {parent_txid}, which this \
                 node never validated and policy-accepted: an external unconfirmed deposit is \
                 excluded because its parent can be replaced out from under this spend"
            )
            .into());
        }
        if !seen.insert(parent_txid) {
            continue;
        }
        if seen.len() > MAX_PACKAGE_ANCESTORS {
            return Err(format!(
                "package for {} exceeds the {MAX_PACKAGE_ANCESTORS}-ancestor bound; the \
                 unconfirmed chain must confirm before this spend can broadcast",
                tx.compute_txid()
            )
            .into());
        }
        let parent: Transaction = consensus::deserialize(&raw)
            .map_err(|e| format!("parent {parent_txid} is malformed: {e}"))?;
        validate_ancestors(backend, &parent, authorized, seen, false)?;
    }
    Ok(())
}

/// Minimal bitcoind JSON-RPC backend over loopback (regtest). Mirrors the demo's
/// RPC client style (`crates/vault-cli/src/bitcoind.rs`) — no HTTP crate lands in
/// the node. Talks to an already-running bitcoind; spawning one is the caller's
/// job (the demo already does, and the opt-in integration test does its own).
pub struct BitcoindBackend {
    rpc_addr: SocketAddr,
    /// base64 of `<user>:<password>` (or `__cookie__:<pw>`), exactly as the
    /// `Authorization: Basic` header carries it.
    auth: String,
}

impl BitcoindBackend {
    /// `auth` is the base64 of `<user>:<password>` (regtest cookie auth). The
    /// caller reads bitcoind's `.cookie` and base64-encodes it.
    pub fn new(rpc_addr: SocketAddr, auth: String) -> BitcoindBackend {
        BitcoindBackend { rpc_addr, auth }
    }

    /// One JSON-RPC call with its structured `result`/`error` fields intact.
    /// Most callers use [`Self::call`], while confirmation lookup needs Core's
    /// numeric not-found code to distinguish absence from a backend failure.
    fn call_reply(&self, method: &str, params: Value) -> Result<Value, Error> {
        let request = json!({
            "jsonrpc": "1.0",
            "id": "vault-node",
            "method": method,
            "params": params,
        });
        let body = post_json(self.rpc_addr, &request.to_string(), &self.auth)?;
        serde_json::from_str(&body)
            .map_err(|e| format!("bitcoind {method}: unparseable reply: {e}").into())
    }

    fn call(&self, method: &str, params: Value) -> Result<Value, Error> {
        let reply = self.call_reply(method, params)?;
        if !reply["error"].is_null() {
            return Err(format!("bitcoind {method}: {}", reply["error"]).into());
        }
        Ok(reply["result"].clone())
    }

    /// Fail startup unless Core's transaction index is present and caught up AND
    /// the node has left initial block download. Escape-class union coverage must
    /// distinguish a paired spend that confirmed from one absent from the mempool;
    /// `getrawtransaction(txid, true)` cannot make that distinction reliably without
    /// `-txindex=1`, and neither lookup is reliable against a stale IBD chain view.
    pub fn verify_required_indexes(&self) -> Result<(), Error> {
        // `getindexinfo`'s `synced` only means the txindex has caught up to THIS
        // node's current tip. During initial block download that tip still lags the
        // network, so the index can report `synced` over a stale chain view — the
        // confirmed vault-UTXO scan would then miss outputs in not-yet-downloaded
        // blocks (understating the coverage denominator) and `transaction_confirmed`
        // would misread an already-mined paired spend as absent. `initialblockdownload`
        // is the authoritative "chain view is current" signal, so require it cleared
        // before this node consumes its key's one process generation.
        let chain = self.call("getblockchaininfo", json!([]))?;
        if chain.get("initialblockdownload").and_then(Value::as_bool) != Some(false) {
            return Err(
                "bitcoind is still in initial block download: refusing to start until the chain \
                 view is current (escape coverage and confirmation lookup would be computed \
                 against a stale tip)"
                    .into(),
            );
        }
        let indexes = self.call("getindexinfo", json!([]))?;
        let txindex = indexes.get("txindex").and_then(Value::as_object).ok_or(
            "bitcoind must run with -txindex=1: escape-class union coverage requires confirmed \
             transaction lookup",
        )?;
        if txindex.get("synced").and_then(Value::as_bool) != Some(true) {
            return Err(
                "bitcoind txindex is not synced: refusing to start until escape-class \
                 confirmation lookup is reliable"
                    .into(),
            );
        }
        Ok(())
    }

    /// Scan the confirmed vault UTXO set and return the block hash the scan was
    /// evaluated against. `vault_unspent` uses that hash to detect a confirmation
    /// racing the later authorized-mempool enumeration; without reconciliation, an
    /// authorized output that confirms between those two reads appears in neither.
    fn scan_confirmed_vault_unspent(
        &self,
        scripts: &[ScriptBuf],
    ) -> Result<(String, HashMap<OutPoint, Prevout>), Error> {
        let scan_objects: Vec<Value> = scripts
            .iter()
            .map(|script| {
                json!({
                    "desc": format!("raw({})", script.as_bytes().to_lower_hex_string())
                })
            })
            .collect();
        let scan = self.call("scantxoutset", json!(["start", scan_objects]))?;
        if scan["success"].as_bool() != Some(true) {
            return Err("scantxoutset: scan did not complete successfully".into());
        }
        let bestblock = scan["bestblock"]
            .as_str()
            .ok_or("scantxoutset: bestblock is not a hash")?
            .to_string();
        let unspents = scan["unspents"]
            .as_array()
            .ok_or("scantxoutset: unspents is not an array")?;
        let watched: HashSet<&ScriptBuf> = scripts.iter().collect();
        let mut found = HashMap::new();
        for entry in unspents {
            let txid = entry["txid"]
                .as_str()
                .ok_or("scantxoutset: unspent has no txid")?;
            let vout = entry["vout"]
                .as_u64()
                .ok_or("scantxoutset: unspent has no vout")?;
            let vout = u32::try_from(vout).map_err(|_| "scantxoutset: vout exceeds u32")?;
            let outpoint = OutPoint::new(
                Txid::from_str(txid).map_err(|e| format!("scantxoutset: bad txid: {e}"))?,
                vout,
            );
            if let Some(prevout) = self.prevout(&outpoint)? {
                if watched.contains(&prevout.txout.script_pubkey) && prevout.confirmed {
                    found.insert(outpoint, prevout);
                }
            }
        }
        Ok((bestblock, found))
    }

    /// The node's current mempool txid set. Coverage snapshots compare the complete
    /// set before and after enumeration: any membership change can alter whether
    /// `gettxout(..., true)` exposes a confirmed vault output.
    fn mempool_txids(&self) -> Result<HashSet<Txid>, Error> {
        let mempool = self.call("getrawmempool", json!([]))?;
        let entries = mempool
            .as_array()
            .ok_or("getrawmempool: expected an array")?;
        entries
            .iter()
            .map(|entry| {
                let txid = entry
                    .as_str()
                    .ok_or("getrawmempool: entry is not a txid string")?;
                Txid::from_str(txid)
                    .map_err(|e| format!("getrawmempool: bad txid {txid}: {e}").into())
            })
            .collect()
    }

    /// The node's current mempool txid set together with Core's monotonic
    /// `mempool_sequence`. The sequence increments on EVERY mempool add and remove,
    /// so an unchanged sequence across two reads proves nothing entered or left in
    /// between — including a transient transaction that both enters and leaves
    /// between the reads, which comparing the txid-set endpoints alone would miss.
    fn mempool_snapshot(&self) -> Result<(HashSet<Txid>, u64), Error> {
        // `getrawmempool false true`: the non-verbose txid list plus the sequence.
        let reply = self.call("getrawmempool", json!([false, true]))?;
        let sequence = reply
            .get("mempool_sequence")
            .and_then(Value::as_u64)
            .ok_or("getrawmempool: missing mempool_sequence")?;
        let entries = reply
            .get("txids")
            .and_then(Value::as_array)
            .ok_or("getrawmempool: txids is not an array")?;
        let txids = entries
            .iter()
            .map(|entry| {
                let txid = entry
                    .as_str()
                    .ok_or("getrawmempool: txid entry is not a string")?;
                Txid::from_str(txid)
                    .map_err(|e| format!("getrawmempool: bad txid {txid}: {e}").into())
            })
            .collect::<Result<HashSet<Txid>, Error>>()?;
        Ok((txids, sequence))
    }

    /// Fetch raw transaction bytes without taking another complete mempool
    /// snapshot. Callers either already proved membership from their own snapshot
    /// or tolerate a concurrent eviction/confirmation as `None` and reconcile it.
    fn raw_transaction_if_available(&self, txid: &Txid) -> Result<Option<Vec<u8>>, Error> {
        let reply = self.call_reply("getrawtransaction", json!([txid.to_string()]))?;
        if !reply["error"].is_null() {
            if reply["error"]["code"].as_i64() == Some(-5) {
                return Ok(None);
            }
            return Err(format!("bitcoind getrawtransaction: {}", reply["error"]).into());
        }
        let hex = reply["result"]
            .as_str()
            .ok_or("getrawtransaction: expected a hex string")?;
        Ok(Some(
            Vec::<u8>::from_hex(hex).map_err(|e| format!("getrawtransaction: bad hex: {e}"))?,
        ))
    }
}

impl ChainBackend for BitcoindBackend {
    fn broadcast(&self, raw_tx: &[u8]) -> Result<Txid, Error> {
        // Validate locally so a malformed tx is a clean Err instead of garbage on
        // the wire: deserialize, then hand bitcoind the canonical hex.
        let tx: Transaction =
            consensus::deserialize(raw_tx).map_err(|e| format!("malformed transaction: {e}"))?;
        let result = self.call("sendrawtransaction", json!([serialize_hex(&tx)]))?;
        let txid = result
            .as_str()
            .ok_or("sendrawtransaction: expected a txid string")?;
        Txid::from_str(txid)
            .map_err(|e| format!("sendrawtransaction returned a bad txid: {e}").into())
    }

    fn tip_height(&self) -> Result<u32, Error> {
        Ok(self
            .call("getblockcount", json!([]))?
            .as_u64()
            .ok_or("getblockcount: not a number")? as u32)
    }

    fn spends_of(&self, scripts: &[ScriptBuf], from_height: u32) -> Result<Vec<SpendSeen>, Error> {
        // Scan blocks from `from_height` to the tip; a watched script is spent
        // when some input's prevout carries it. `getblock` verbosity 3 (Core v25+)
        // inlines each input's `prevout`, so no per-input `getrawtransaction` is
        // needed. Bounded work on regtest; the Core/Electrum/filter tradeoff for
        // real networks is v1 (T6).
        let watched: HashSet<&ScriptBuf> = scripts.iter().collect();
        let tip = self.tip_height()?;
        let mut seen = Vec::new();
        for height in from_height..=tip {
            let hash = self.call("getblockhash", json!([height]))?;
            let block = self.call("getblock", json!([hash, 3]))?;
            let txs = block["tx"].as_array().ok_or("getblock: tx not an array")?;
            for tx in txs {
                let spend_txid = tx["txid"].as_str().ok_or("getblock: tx has no txid")?;
                for vin in tx["vin"].as_array().into_iter().flatten() {
                    // A coinbase input spends nothing and carries a `coinbase`
                    // field in place of a prevout; skip only genuine coinbase
                    // inputs. EVERY other input must carry its prevout (getblock
                    // verbosity 3 inlines it): a missing/malformed prevout here
                    // would silently drop a possibly-watched spend and make the
                    // watchtower miss its alert, so surface it as an error, never
                    // a false negative.
                    if vin.get("coinbase").is_some() {
                        continue;
                    }
                    let prevout = vin.get("prevout").ok_or(
                        "getblock: non-coinbase input has no prevout (verbosity 3 required)",
                    )?;
                    let spk_hex = prevout["scriptPubKey"]["hex"]
                        .as_str()
                        .ok_or("getblock: prevout has no scriptPubKey hex")?;
                    let spk = ScriptBuf::from_hex(spk_hex)
                        .map_err(|e| format!("getblock: bad prevout scriptPubKey: {e}"))?;
                    if !watched.contains(&spk) {
                        continue;
                    }
                    let prev_txid = vin["txid"].as_str().ok_or("getblock: input has no txid")?;
                    let vout = vin["vout"].as_u64().ok_or("getblock: input has no vout")? as u32;
                    // The spending witness (verbosity 3 inlines `txinwitness` for
                    // segwit inputs), so the watchtower can tell WHICH branch of the
                    // two-branch `wsh(...)` this spend took — a recovery spend and a
                    // normal spend share the prevout script and differ only here. A
                    // non-segwit input has no `txinwitness`; that never matches a
                    // vault P2WSH, so an empty witness (classified as non-recovery)
                    // is the safe default.
                    let mut witness_items = Vec::new();
                    for item in vin
                        .get("txinwitness")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                    {
                        let hex = item
                            .as_str()
                            .ok_or("getblock: txinwitness item is not a string")?;
                        witness_items.push(
                            Vec::<u8>::from_hex(hex)
                                .map_err(|e| format!("getblock: bad txinwitness item: {e}"))?,
                        );
                    }
                    seen.push(SpendSeen {
                        spend_txid: Txid::from_str(spend_txid)
                            .map_err(|e| format!("getblock: bad spend txid: {e}"))?,
                        outpoint: OutPoint::new(
                            Txid::from_str(prev_txid)
                                .map_err(|e| format!("getblock: bad prevout txid: {e}"))?,
                            vout,
                        ),
                        script: spk,
                        witness: Witness::from_slice(&witness_items),
                    });
                }
            }
        }
        Ok(seen)
    }

    fn prevout(&self, outpoint: &OutPoint) -> Result<Option<Prevout>, Error> {
        // `include_mempool = true` is the whole point: an unconfirmed vault
        // spend-change or refresh output is the COMMON case (ADR-0012), and
        // `gettxout` would not see it otherwise. A spent or unknown output comes
        // back as JSON null.
        let result = self.call(
            "gettxout",
            json!([outpoint.txid.to_string(), outpoint.vout, true]),
        )?;
        if result.is_null() {
            return Ok(None);
        }
        let spk_hex = result["scriptPubKey"]["hex"]
            .as_str()
            .ok_or("gettxout: no scriptPubKey hex")?;
        let btc = result["value"].as_f64().ok_or("gettxout: no value")?;
        // `confirmations = 0` is exactly bitcoind's "in the mempool, not mined".
        let confirmations = result["confirmations"]
            .as_u64()
            .ok_or("gettxout: no confirmations")?;
        Ok(Some(Prevout {
            txout: TxOut {
                script_pubkey: ScriptBuf::from_hex(spk_hex)
                    .map_err(|e| format!("gettxout: bad scriptPubKey: {e}"))?,
                value: Amount::from_btc(btc).map_err(|e| format!("gettxout: bad value: {e}"))?,
            },
            confirmed: confirmations > 0,
        }))
    }

    fn vault_unspent(
        &self,
        scripts: &[ScriptBuf],
        authorized: &HashSet<Txid>,
    ) -> Result<Vec<(OutPoint, Prevout)>, Error> {
        // Confirmed balance: scan the node's own UTXO set for the exact vault
        // script(s), then re-read each result through `gettxout(..., true)` so an
        // output already spent by a mempool transaction is not double-counted.
        //
        // SCALING (deferred to the V0-4b-harness bead): `scantxoutset` is a full
        // UTXO-set scan — fast on regtest/small chains (the demo + tests), but minutes
        // on a large mainnet chain. Because this runs synchronously inside the
        // fire-time `escape_sweep_admissible` coverage check, a multi-minute scan can
        // outlast the bounded `[T, T + combine_slack_secs]` combine window and stop the
        // SWEEP from broadcasting. This does NOT weaken safety — Lockdown at `T` is
        // unconditional and independent of the sweep, so funds still freeze → recovery,
        // never theft — but near-term mainnet operation of the sweep needs a
        // wallet/indexed vault-UTXO lookup here (a backend capability, out of this
        // core bead's scope; see challenges-round-3).
        let watched: HashSet<&ScriptBuf> = scripts.iter().collect();
        // There is no atomic chain+mempool JSON-RPC snapshot. Take bounded full
        // passes instead, bracketing each with Core's monotonic `mempool_sequence`
        // (bumped on EVERY add and remove). An unchanged sequence AND an unchanged
        // tip across the pass prove the scan/gettxout reads saw one consistent
        // chain+mempool view — including that no transaction transiently entered and
        // left between the two reads (an ABA that comparing the txid-set endpoints
        // alone would miss). A changed sequence or tip retries once; a second
        // unstable pass fails closed (no sweep; Lockdown already latched) rather than
        // admit an escape against an understated coverage denominator.
        for attempt in 0..2 {
            // Snapshot the FULL mempool, not just its intersection with the
            // authorized set. An unauthorized mempool transaction can temporarily
            // suppress a confirmed vault output from `gettxout(..., true)`; any such
            // membership motion during the pass bumps the sequence below and forces a
            // retry, whether the suppressor stays or is evicted before the pass ends,
            // so an understated confirmed denominator is never accepted.
            let (mempool_before, sequence_before) = self.mempool_snapshot()?;
            let (scan_tip, mut found) = self.scan_confirmed_vault_unspent(scripts)?;

            // Authorized-unconfirmed balance: only transactions this node accepted may
            // contribute. Reading just those txids avoids scanning unrelated mempool
            // traffic and structurally excludes external unconfirmed deposits.
            for txid in mempool_before.intersection(authorized) {
                let Some(raw) = self.raw_transaction_if_available(txid)? else {
                    continue;
                };
                let tx: Transaction = consensus::deserialize(&raw).map_err(|e| {
                    format!("authorized mempool transaction {txid} is malformed: {e}")
                })?;
                for (vout, output) in tx.output.iter().enumerate() {
                    if !watched.contains(&output.script_pubkey) {
                        continue;
                    }
                    let vout = u32::try_from(vout).map_err(|_| {
                        format!("authorized transaction {txid} has too many outputs")
                    })?;
                    let outpoint = OutPoint::new(*txid, vout);
                    if let Some(prevout) = self.prevout(&outpoint)? {
                        if !prevout.confirmed {
                            found.insert(outpoint, prevout);
                        }
                    }
                }
            }
            let tip_after = self
                .call("getbestblockhash", json!([]))?
                .as_str()
                .ok_or("getbestblockhash: expected a block hash")?
                .to_string();
            let (_, sequence_after) = self.mempool_snapshot()?;
            if scan_tip == tip_after && sequence_before == sequence_after {
                let mut found: Vec<_> = found.into_iter().collect();
                found.sort_by_key(|(outpoint, _)| *outpoint);
                return Ok(found);
            }

            if attempt == 1 {
                return Err("chain tip or mempool membership changed again while \
                     reconciling the vault UTXO snapshot"
                    .into());
            }
        }
        unreachable!("the bounded snapshot loop always returns or errors")
    }

    fn mempool_transaction(&self, txid: &Txid) -> Result<Option<Vec<u8>>, Error> {
        // Query membership explicitly instead of probing an English RPC error or
        // relying on `-txindex`. A confirmed parent is absent here; an unconfirmed
        // ancestor is present and getrawtransaction can always read mempool data.
        if !self.mempool_txids()?.contains(txid) {
            return Ok(None);
        }
        self.raw_transaction_if_available(txid)
    }

    fn transaction_confirmed(&self, txid: &Txid) -> Result<bool, Error> {
        // Production startup verifies a fully-synced `-txindex=1`, so this can
        // distinguish a mined transaction from one that is merely absent.
        // Preserve Core's structured -5 "not found" result as ordinary `false`;
        // every other RPC failure remains an error and leaves the candidate for a
        // later retry.
        let reply = self.call_reply("getrawtransaction", json!([txid.to_string(), true]))?;
        if !reply["error"].is_null() {
            if reply["error"]["code"].as_i64() == Some(-5) {
                return Ok(false);
            }
            return Err(format!("bitcoind getrawtransaction: {}", reply["error"]).into());
        }
        let result = reply["result"]
            .as_object()
            .ok_or("getrawtransaction: expected a verbose transaction object")?;
        Ok(result
            .get("confirmations")
            .and_then(Value::as_u64)
            .is_some_and(|confirmations| confirmations > 0))
    }

    fn test_package_accept(&self, raw_txs: &[Vec<u8>]) -> Result<PackageVerdict, Error> {
        if raw_txs.is_empty() {
            return Err("cannot package-test an empty package".into());
        }
        let hexes: Vec<String> = raw_txs
            .iter()
            .map(|raw| raw.to_lower_hex_string())
            .collect();
        let result = self.call("testmempoolaccept", json!([hexes]))?;
        let entries = result
            .as_array()
            .ok_or("testmempoolaccept: expected an array")?;
        for entry in entries {
            if entry["allowed"].as_bool() == Some(true) {
                continue;
            }
            let reason = entry["reject-reason"].as_str().unwrap_or("unknown");
            // An ancestor we carried into the package is ALREADY in this node's
            // mempool — that is the normal case for a vault-authorized
            // unconfirmed parent, and bitcoind reports it as a per-entry
            // rejection. It means the parent is present and valid, which is
            // exactly what the package needs, so it is not a reason to withhold
            // the broadcast.
            if reason == "txn-already-in-mempool" {
                continue;
            }
            let txid = entry["txid"].as_str().unwrap_or("?");
            return Ok(PackageVerdict::Rejected(format!("{txid}: {reason}")));
        }
        Ok(PackageVerdict::Accepted)
    }
}

/// Read/write deadline on one bitcoind JSON-RPC call. Fixed loopback-regtest
/// value, never a config knob; the connect deadline below is shorter.
const RPC_TIMEOUT: Duration = Duration::from_secs(60);

/// One HTTP/1.1 POST to bitcoind's JSON-RPC over loopback, `Connection: close`,
/// returning the response body. A single loopback JSON-RPC peer does not buy an
/// HTTP crate its keep (same reasoning as the /sign server).
fn post_json(addr: SocketAddr, body: &str, auth: &str) -> Result<String, Error> {
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))
        .map_err(|e| format!("connect {addr}: {e}"))?;
    stream.set_read_timeout(Some(RPC_TIMEOUT))?;
    stream.set_write_timeout(Some(RPC_TIMEOUT))?;
    let request = format!(
        "POST / HTTP/1.1\r\n\
         Host: {addr}\r\n\
         Content-Type: application/json\r\n\
         Authorization: Basic {auth}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes())?;
    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .map_err(|e| format!("read from {addr}: {e}"))?;
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| format!("malformed HTTP response from {addr}"))?;
    Ok(String::from_utf8_lossy(&raw[split + 4..]).into_owned())
}

#[cfg(test)]
pub(crate) mod mock {
    //! A mock chain backend for the unit tests — no bitcoind, no sockets.

    use std::collections::{HashMap, HashSet};
    use std::sync::{Arc, Barrier, Mutex};

    use bitcoin::{consensus, OutPoint, ScriptBuf, Transaction, Txid};

    use super::{ChainBackend, PackageVerdict, Prevout, SpendSeen};
    use crate::Error;

    /// Records every broadcast and replays a canned spend set to the scan. Each
    /// spend's `script` is what the watchtower classifies against.
    ///
    /// For the watchtower-driver tests the mock models block height: `tip` is the
    /// reported chain tip and `spend_block` is the height the canned spends sit
    /// at, so `spends_of` returns them only when the requested `from_height`
    /// still covers that block. The defaults (`tip = 0`, `spend_block = 0`) make
    /// a `from_height = 0` scan return every canned spend, matching the simple
    /// classification/cursor tests. `scanned_from` records each `from_height` the
    /// driver asked for, so a test can prove the cursor advanced instead of
    /// re-scanning from 0.
    ///
    /// Interior mutability is a `Mutex` (not a `RefCell`) so the mock is
    /// `Send + Sync`: the async watchtower driver (V0-6b) runs each scan pass on
    /// `spawn_blocking`, which requires a `Send + Sync` backend.
    /// `prevouts`/`raw_txs` are the canned chain+mempool view the package
    /// assembler reads; an outpoint absent from `prevouts` reads as unknown.
    /// `package_rejection` forces the backend to refuse every package (the
    /// "backend rejects the package → no broadcast, no panic" case), and
    /// `packages_tested` records each package so a test can prove the gate ran
    /// BEFORE the broadcast.
    #[derive(Default)]
    pub(crate) struct MockBackend {
        pub spends: Vec<SpendSeen>,
        pub broadcasts: Mutex<Vec<Vec<u8>>>,
        pub tip: u32,
        pub spend_block: u32,
        pub scanned_from: Mutex<Vec<u32>>,
        pub prevouts: HashMap<OutPoint, Prevout>,
        pub raw_txs: HashMap<Txid, Vec<u8>>,
        pub confirmed_txs: HashSet<Txid>,
        pub package_rejection: Option<String>,
        /// Forces `broadcast` to fail AFTER package acceptance (the "quorum +
        /// admissibility + package-accept all pass, but `sendrawtransaction` itself
        /// errors" branch). Distinct from `package_rejection`, which fails earlier at
        /// `test_package_accept`. Lets a test exercise the `broadcast_package` `Err`
        /// arm and prove Lockdown at `T` is still unconditional there.
        pub broadcast_error: Option<String>,
        pub packages_tested: Mutex<Vec<Vec<Vec<u8>>>>,
        /// Optional deterministic pause around package acceptance. A concurrency
        /// test uses this to land a duress arm after finalization but before the
        /// final broadcast-authorization boundary.
        pub package_test_entered: Option<Arc<Barrier>>,
        pub package_test_continue: Option<Arc<Barrier>>,
    }

    impl ChainBackend for MockBackend {
        fn broadcast(&self, raw_tx: &[u8]) -> Result<Txid, Error> {
            // Parse like the real backend so a malformed tx surfaces an error
            // (no panic) — and so the returned txid is the real one.
            let tx: Transaction = consensus::deserialize(raw_tx)
                .map_err(|e| format!("malformed transaction: {e}"))?;
            // A forced broadcast failure never records the transaction — mirroring a
            // real backend whose `sendrawtransaction` rejected it.
            if let Some(reason) = &self.broadcast_error {
                return Err(reason.clone().into());
            }
            self.broadcasts
                .lock()
                .expect("broadcasts lock")
                .push(raw_tx.to_vec());
            Ok(tx.compute_txid())
        }

        fn tip_height(&self) -> Result<u32, Error> {
            Ok(self.tip)
        }

        fn spends_of(
            &self,
            _scripts: &[ScriptBuf],
            from_height: u32,
        ) -> Result<Vec<SpendSeen>, Error> {
            self.scanned_from
                .lock()
                .expect("scanned_from lock")
                .push(from_height);
            // The canned spends live in `spend_block`; a scan whose cursor has
            // advanced past it sees nothing, so a re-alert can only come from a
            // cursor that failed to advance (never dedup).
            if from_height <= self.spend_block {
                Ok(self.spends.clone())
            } else {
                Ok(Vec::new())
            }
        }

        fn prevout(&self, outpoint: &OutPoint) -> Result<Option<Prevout>, Error> {
            Ok(self.prevouts.get(outpoint).cloned())
        }

        fn vault_unspent(
            &self,
            scripts: &[ScriptBuf],
            authorized: &HashSet<Txid>,
        ) -> Result<Vec<(OutPoint, Prevout)>, Error> {
            let watched: HashSet<&ScriptBuf> = scripts.iter().collect();
            let mut found: Vec<_> = self
                .prevouts
                .iter()
                .filter(|(outpoint, prevout)| {
                    watched.contains(&prevout.txout.script_pubkey)
                        && (prevout.confirmed || authorized.contains(&outpoint.txid))
                })
                .map(|(outpoint, prevout)| (*outpoint, prevout.clone()))
                .collect();
            found.sort_by_key(|(outpoint, _)| *outpoint);
            Ok(found)
        }

        fn mempool_transaction(&self, txid: &Txid) -> Result<Option<Vec<u8>>, Error> {
            Ok(self.raw_txs.get(txid).cloned())
        }

        fn transaction_confirmed(&self, txid: &Txid) -> Result<bool, Error> {
            Ok(self.confirmed_txs.contains(txid))
        }

        fn test_package_accept(&self, raw_txs: &[Vec<u8>]) -> Result<PackageVerdict, Error> {
            self.packages_tested
                .lock()
                .expect("packages_tested lock")
                .push(raw_txs.to_vec());
            if let Some(entered) = &self.package_test_entered {
                entered.wait();
            }
            if let Some(proceed) = &self.package_test_continue {
                proceed.wait();
            }
            Ok(match &self.package_rejection {
                Some(reason) => PackageVerdict::Rejected(reason.clone()),
                None => PackageVerdict::Accepted,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::mock::MockBackend;
    use super::{assemble_package, BitcoindBackend, ChainBackend, Prevout, MAX_PACKAGE_ANCESTORS};

    use bitcoin::absolute::LockTime;
    use bitcoin::consensus::encode::serialize;
    use bitcoin::hashes::Hash;
    use bitcoin::hex::DisplayHex;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
    use std::collections::HashSet;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    /// A tiny scripted JSON-RPC peer for exercising the real bitcoind backend's
    /// cross-call snapshot ordering without launching bitcoind.
    fn scripted_rpc(
        replies: Vec<(&'static str, serde_json::Value)>,
    ) -> (std::net::SocketAddr, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind scripted RPC");
        let addr = listener.local_addr().expect("scripted RPC address");
        let handle = std::thread::spawn(move || {
            for (expected_method, result) in replies {
                let (mut stream, _) = listener.accept().expect("accept RPC call");
                let mut request = Vec::new();
                let (header_end, content_len) = loop {
                    let mut chunk = [0u8; 4096];
                    let read = stream.read(&mut chunk).expect("read RPC request");
                    assert!(read > 0, "RPC request ended before its headers");
                    request.extend_from_slice(&chunk[..read]);
                    let Some(header_end) = request.windows(4).position(|w| w == b"\r\n\r\n") else {
                        continue;
                    };
                    let header_end = header_end + 4;
                    let headers =
                        std::str::from_utf8(&request[..header_end]).expect("HTTP headers");
                    let content_len = headers
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().expect("content length"))
                        })
                        .expect("Content-Length");
                    break (header_end, content_len);
                };
                while request.len() < header_end + content_len {
                    let mut chunk = [0u8; 4096];
                    let read = stream.read(&mut chunk).expect("read RPC body");
                    assert!(read > 0, "RPC request ended before its body");
                    request.extend_from_slice(&chunk[..read]);
                }
                let body: serde_json::Value =
                    serde_json::from_slice(&request[header_end..header_end + content_len])
                        .expect("JSON-RPC request");
                assert_eq!(body["method"], expected_method);
                let response = serde_json::json!({
                    "result": result,
                    "error": serde_json::Value::Null,
                    "id": "vault-node",
                })
                .to_string();
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    response.len(),
                    response
                )
                .expect("write RPC response");
            }
        });
        (addr, handle)
    }

    /// A minimal but well-formed 1-in/1-out transaction to broadcast.
    fn sample_tx() -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([9; 32]), 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                script_pubkey: ScriptBuf::new(),
                value: Amount::from_sat(1_000),
            }],
        }
    }

    // -- package assembly over the authorized set (§5) -----------------------

    /// A transaction spending `parents` (each an outpoint) and paying `value`.
    /// `tag` makes otherwise-identical txs distinct.
    fn tx_spending(parents: &[OutPoint], value: u64, tag: u32) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::from_consensus(tag),
            input: parents
                .iter()
                .map(|outpoint| TxIn {
                    previous_output: *outpoint,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                })
                .collect(),
            output: vec![TxOut {
                script_pubkey: ScriptBuf::new(),
                value: Amount::from_sat(value),
            }],
        }
    }

    fn prevout(confirmed: bool) -> Prevout {
        Prevout {
            txout: TxOut {
                script_pubkey: ScriptBuf::new(),
                value: Amount::from_sat(100_000),
            },
            confirmed,
        }
    }

    #[test]
    fn required_index_check_accepts_a_synced_txindex() {
        let (addr, server) = scripted_rpc(vec![
            (
                "getblockchaininfo",
                serde_json::json!({ "initialblockdownload": false }),
            ),
            (
                "getindexinfo",
                serde_json::json!({
                    "txindex": { "synced": true, "best_block_height": 321 }
                }),
            ),
        ]);
        let backend = BitcoindBackend::new(addr, String::new());

        backend
            .verify_required_indexes()
            .expect("a current, synced txindex satisfies the production backend contract");
        server.join().expect("scripted RPC completed");
    }

    #[test]
    fn required_index_check_rejects_a_missing_or_unsynced_txindex() {
        for (result, expected) in [
            (serde_json::json!({}), "-txindex=1"),
            (
                serde_json::json!({ "txindex": { "synced": false } }),
                "not synced",
            ),
        ] {
            let (addr, server) = scripted_rpc(vec![
                (
                    "getblockchaininfo",
                    serde_json::json!({ "initialblockdownload": false }),
                ),
                ("getindexinfo", result),
            ]);
            let backend = BitcoindBackend::new(addr, String::new());
            let error = backend
                .verify_required_indexes()
                .expect_err("an unavailable confirmation index must fail startup")
                .to_string();
            assert!(
                error.contains(expected),
                "unexpected index failure for {expected}: {error}"
            );
            server.join().expect("scripted RPC completed");
        }
    }

    /// A `synced` txindex over a chain view that is still in initial block download
    /// must NOT pass: the tip lags the network, so the confirmed vault-UTXO scan and
    /// `transaction_confirmed` would both read a stale view. The check must reject
    /// BEFORE consulting `getindexinfo` (only `getblockchaininfo` is scripted).
    #[test]
    fn required_index_check_rejects_a_backend_in_initial_block_download() {
        let (addr, server) = scripted_rpc(vec![(
            "getblockchaininfo",
            serde_json::json!({ "initialblockdownload": true }),
        )]);
        let backend = BitcoindBackend::new(addr, String::new());
        let error = backend
            .verify_required_indexes()
            .expect_err("an IBD chain view must fail startup")
            .to_string();
        assert!(
            error.contains("initial block download"),
            "the IBD failure must name its reason: {error}"
        );
        server.join().expect("scripted RPC completed");
    }

    /// An authorized transaction can confirm after `scantxoutset` snapshots the UTXO
    /// set but before the authorized-mempool pass reaches it. It is then absent from
    /// both reads unless the changed tip triggers a confirmed-set reconciliation.
    #[test]
    fn vault_unspent_reconciles_an_authorized_confirmation_racing_the_scan() {
        let script = ScriptBuf::from_bytes(vec![0x51]);
        let txid = Txid::from_byte_array([0xA5; 32]);
        let old_tip = "11".repeat(32);
        let new_tip = "22".repeat(32);
        let script_hex = script.as_bytes().to_lower_hex_string();
        let mut authorized_tx = sample_tx();
        authorized_tx.output[0].script_pubkey = script.clone();
        let authorized_tx_hex = serialize(&authorized_tx).to_lower_hex_string();
        let confirmed_output = serde_json::json!({
            "scriptPubKey": {"hex": script_hex},
            "value": 0.001,
            "confirmations": 1,
        });
        let (addr, server) = scripted_rpc(vec![
            // Snapshot 1 starts while the authorized transaction is in the mempool.
            (
                "getrawmempool",
                serde_json::json!({"txids": [txid.to_string()], "mempool_sequence": 1}),
            ),
            (
                "scantxoutset",
                serde_json::json!({"success": true, "bestblock": old_tip, "unspents": []}),
            ),
            // It confirms while the authorized pass reads its output.
            ("getrawtransaction", serde_json::json!(authorized_tx_hex)),
            ("gettxout", confirmed_output.clone()),
            ("getbestblockhash", serde_json::json!(new_tip)),
            (
                "getrawmempool",
                serde_json::json!({"txids": [], "mempool_sequence": 2}),
            ),
            // Snapshot 2 retries the complete view at the new stable tip.
            (
                "getrawmempool",
                serde_json::json!({"txids": [], "mempool_sequence": 2}),
            ),
            (
                "scantxoutset",
                serde_json::json!({
                    "success": true,
                    "bestblock": "22".repeat(32),
                    "unspents": [{"txid": txid.to_string(), "vout": 0}],
                }),
            ),
            ("gettxout", confirmed_output),
            ("getbestblockhash", serde_json::json!("22".repeat(32))),
            (
                "getrawmempool",
                serde_json::json!({"txids": [], "mempool_sequence": 2}),
            ),
        ]);
        let backend = BitcoindBackend::new(addr, String::new());
        let authorized: HashSet<Txid> = [txid].into_iter().collect();

        let unspent = backend
            .vault_unspent(std::slice::from_ref(&script), &authorized)
            .expect("reconciled vault balance");
        server.join().expect("scripted RPC completed");
        assert_eq!(unspent.len(), 1);
        assert_eq!(unspent[0].0, OutPoint::new(txid, 0));
        assert_eq!(unspent[0].1.txout.value, Amount::from_sat(100_000));
        assert!(unspent[0].1.confirmed);
    }

    /// An authorized mempool transaction can be evicted after `gettxout(..., true)`
    /// suppresses its confirmed input but before the authorized pass enumerates its
    /// unconfirmed output. With a stable tip, tip-only reconciliation misses that
    /// transition and undercounts both sides. Authorized-mempool membership snapshots
    /// must force a complete retry, which restores the now-unspent confirmed input.
    #[test]
    fn vault_unspent_reconciles_authorized_mempool_eviction_without_a_tip_change() {
        let script = ScriptBuf::from_bytes(vec![0x51]);
        let parent_txid = Txid::from_byte_array([0xB4; 32]);
        let authorized_txid = Txid::from_byte_array([0xC5; 32]);
        let tip = "33".repeat(32);
        let script_hex = script.as_bytes().to_lower_hex_string();
        let mut authorized_tx = sample_tx();
        authorized_tx.output[0].script_pubkey = script.clone();
        let authorized_tx_hex = serialize(&authorized_tx).to_lower_hex_string();
        let scan = serde_json::json!({
            "success": true,
            "bestblock": tip,
            "unspents": [{"txid": parent_txid.to_string(), "vout": 0}],
        });
        let confirmed_parent = serde_json::json!({
            "scriptPubKey": {"hex": script_hex},
            "value": 0.001,
            "confirmations": 1,
        });
        let (addr, server) = scripted_rpc(vec![
            // Snapshot 1: the authorized child initially spends the confirmed parent.
            (
                "getrawmempool",
                serde_json::json!({"txids": [authorized_txid.to_string()], "mempool_sequence": 10}),
            ),
            ("scantxoutset", scan.clone()),
            ("gettxout", serde_json::Value::Null),
            // Evicted while its outputs are enumerated; the tip does not change, but
            // the eviction bumps the sequence, so the pass is not accepted.
            ("getrawtransaction", serde_json::json!(authorized_tx_hex)),
            ("gettxout", serde_json::Value::Null),
            ("getbestblockhash", serde_json::json!("33".repeat(32))),
            (
                "getrawmempool",
                serde_json::json!({"txids": [], "mempool_sequence": 11}),
            ),
            // Snapshot 2 is stable and sees the confirmed parent unspent again.
            (
                "getrawmempool",
                serde_json::json!({"txids": [], "mempool_sequence": 11}),
            ),
            ("scantxoutset", scan),
            ("gettxout", confirmed_parent),
            ("getbestblockhash", serde_json::json!("33".repeat(32))),
            (
                "getrawmempool",
                serde_json::json!({"txids": [], "mempool_sequence": 11}),
            ),
        ]);
        let backend = BitcoindBackend::new(addr, String::new());
        let authorized: HashSet<Txid> = [authorized_txid].into_iter().collect();

        let unspent = backend
            .vault_unspent(std::slice::from_ref(&script), &authorized)
            .expect("eviction-reconciled vault balance");
        server.join().expect("scripted RPC completed");
        assert_eq!(unspent.len(), 1);
        assert_eq!(unspent[0].0, OutPoint::new(parent_txid, 0));
        assert_eq!(unspent[0].1.txout.value, Amount::from_sat(100_000));
        assert!(unspent[0].1.confirmed);
    }

    /// An unauthorized mempool spend suppresses its confirmed vault prevout from
    /// `gettxout(..., true)` just like an authorized spend does. If it is evicted
    /// during the snapshot, comparing only the authorized intersection sees no
    /// change and accepts an understated balance. Full-mempool reconciliation must
    /// retry and restore the now-unspent confirmed output.
    #[test]
    fn vault_unspent_reconciles_unauthorized_mempool_eviction() {
        let script = ScriptBuf::from_bytes(vec![0x51]);
        let parent_txid = Txid::from_byte_array([0xD6; 32]);
        let unauthorized_txid = Txid::from_byte_array([0xE7; 32]);
        let tip = "44".repeat(32);
        let script_hex = script.as_bytes().to_lower_hex_string();
        let scan = serde_json::json!({
            "success": true,
            "bestblock": tip,
            "unspents": [{"txid": parent_txid.to_string(), "vout": 0}],
        });
        let confirmed_parent = serde_json::json!({
            "scriptPubKey": {"hex": script_hex},
            "value": 0.001,
            "confirmations": 1,
        });
        let (addr, server) = scripted_rpc(vec![
            // Snapshot 1: an UNAUTHORIZED mempool tx suppresses the confirmed
            // parent. The authorized set is empty throughout this test.
            (
                "getrawmempool",
                serde_json::json!({"txids": [unauthorized_txid.to_string()], "mempool_sequence": 20}),
            ),
            ("scantxoutset", scan.clone()),
            ("gettxout", serde_json::Value::Null),
            ("getbestblockhash", serde_json::json!("44".repeat(32))),
            // Eviction with no tip change bumps the sequence, so the complete pass
            // is not accepted even though the authorized intersection never changed.
            (
                "getrawmempool",
                serde_json::json!({"txids": [], "mempool_sequence": 21}),
            ),
            // Snapshot 2 is stable and sees the confirmed parent unspent again.
            (
                "getrawmempool",
                serde_json::json!({"txids": [], "mempool_sequence": 21}),
            ),
            ("scantxoutset", scan),
            ("gettxout", confirmed_parent),
            ("getbestblockhash", serde_json::json!("44".repeat(32))),
            (
                "getrawmempool",
                serde_json::json!({"txids": [], "mempool_sequence": 21}),
            ),
        ]);
        let backend = BitcoindBackend::new(addr, String::new());

        let unspent = backend
            .vault_unspent(std::slice::from_ref(&script), &HashSet::new())
            .expect("unauthorized-eviction-reconciled vault balance");
        server.join().expect("scripted RPC completed");
        assert_eq!(unspent.len(), 1);
        assert_eq!(unspent[0].0, OutPoint::new(parent_txid, 0));
        assert_eq!(unspent[0].1.txout.value, Amount::from_sat(100_000));
        assert!(unspent[0].1.confirmed);
    }

    /// The ABA the txid-set endpoints alone cannot see: a transaction is absent at
    /// the first snapshot, ENTERS and suppresses a confirmed vault output from
    /// `gettxout(..., true)` while the scan runs, then LEAVES before the second
    /// snapshot. Both endpoint sets are empty and the tip never moves, so a
    /// set-only comparison would accept the understated (here, empty) balance.
    /// Core's `mempool_sequence` still advances across the enter+leave, so the pass
    /// is retried and the now-unspent confirmed output is restored.
    #[test]
    fn vault_unspent_retries_when_a_transient_mempool_tx_races_the_scan() {
        let script = ScriptBuf::from_bytes(vec![0x51]);
        let parent_txid = Txid::from_byte_array([0xF8; 32]);
        let tip = "88".repeat(32);
        let script_hex = script.as_bytes().to_lower_hex_string();
        let scan = serde_json::json!({
            "success": true,
            "bestblock": tip,
            "unspents": [{"txid": parent_txid.to_string(), "vout": 0}],
        });
        let confirmed_parent = serde_json::json!({
            "scriptPubKey": {"hex": script_hex},
            "value": 0.001,
            "confirmations": 1,
        });
        let (addr, server) = scripted_rpc(vec![
            // Snapshot 1: empty mempool. A transient tx then enters, suppresses the
            // confirmed parent, and leaves — all before snapshot 2, so BOTH sets are
            // empty. Only the sequence records the enter (+1) and leave (+1).
            (
                "getrawmempool",
                serde_json::json!({"txids": [], "mempool_sequence": 50}),
            ),
            ("scantxoutset", scan.clone()),
            ("gettxout", serde_json::Value::Null),
            ("getbestblockhash", serde_json::json!("88".repeat(32))),
            (
                "getrawmempool",
                serde_json::json!({"txids": [], "mempool_sequence": 52}),
            ),
            // Snapshot 2 is stable and sees the confirmed parent unspent again.
            (
                "getrawmempool",
                serde_json::json!({"txids": [], "mempool_sequence": 52}),
            ),
            ("scantxoutset", scan),
            ("gettxout", confirmed_parent),
            ("getbestblockhash", serde_json::json!("88".repeat(32))),
            (
                "getrawmempool",
                serde_json::json!({"txids": [], "mempool_sequence": 52}),
            ),
        ]);
        let backend = BitcoindBackend::new(addr, String::new());

        let unspent = backend
            .vault_unspent(std::slice::from_ref(&script), &HashSet::new())
            .expect("transient-reconciled vault balance");
        server.join().expect("scripted RPC completed");
        assert_eq!(unspent.len(), 1);
        assert_eq!(unspent[0].0, OutPoint::new(parent_txid, 0));
        assert_eq!(unspent[0].1.txout.value, Amount::from_sat(100_000));
        assert!(unspent[0].1.confirmed);
    }

    #[test]
    fn vault_unspent_rejects_an_incomplete_confirmed_scan() {
        let script = ScriptBuf::from_bytes(vec![0x51]);
        let (addr, server) = scripted_rpc(vec![
            (
                "getrawmempool",
                serde_json::json!({"txids": [], "mempool_sequence": 30}),
            ),
            (
                "scantxoutset",
                serde_json::json!({
                    "success": false,
                    "bestblock": "55".repeat(32),
                    "unspents": [],
                }),
            ),
        ]);
        let backend = BitcoindBackend::new(addr, String::new());

        let error = backend
            .vault_unspent(std::slice::from_ref(&script), &HashSet::new())
            .expect_err("an aborted scan must fail closed");
        server.join().expect("scripted RPC completed");
        assert!(
            error.to_string().contains("scan did not complete"),
            "the incomplete-scan reason must be preserved: {error}"
        );
    }

    #[test]
    fn vault_unspent_fetches_raw_transactions_only_for_the_mempool_intersection() {
        let script = ScriptBuf::from_bytes(vec![0x51]);
        let current_txid = Txid::from_byte_array([0x66; 32]);
        let current_raw = serialize(&sample_tx()).to_lower_hex_string();
        let tip = "77".repeat(32);
        let (addr, server) = scripted_rpc(vec![
            (
                "getrawmempool",
                serde_json::json!({"txids": [current_txid.to_string()], "mempool_sequence": 40}),
            ),
            (
                "scantxoutset",
                serde_json::json!({"success": true, "bestblock": tip, "unspents": []}),
            ),
            ("getrawtransaction", serde_json::json!(current_raw)),
            ("getbestblockhash", serde_json::json!("77".repeat(32))),
            (
                "getrawmempool",
                serde_json::json!({"txids": [current_txid.to_string()], "mempool_sequence": 40}),
            ),
        ]);
        let backend = BitcoindBackend::new(addr, String::new());
        let mut authorized: HashSet<Txid> = (0..128)
            .map(|tag| Txid::from_byte_array([tag; 32]))
            .collect();
        authorized.insert(current_txid);

        let unspent = backend
            .vault_unspent(std::slice::from_ref(&script), &authorized)
            .expect("stable snapshot");
        server.join().expect("scripted RPC completed");
        assert!(unspent.is_empty());
    }

    #[test]
    fn a_spend_over_confirmed_prevouts_packages_as_itself_alone() {
        let tx = sample_tx();
        let mut backend = MockBackend::default();
        backend
            .prevouts
            .insert(tx.input[0].previous_output, prevout(true));

        let package = assemble_package(&backend, &tx, &HashSet::new()).expect("confirmed prevout");
        assert_eq!(
            package,
            vec![serialize(&tx)],
            "a confirmed prevout needs no ancestor in the package"
        );
    }

    #[test]
    fn a_spend_over_a_vault_authorized_unconfirmed_parent_tests_the_child_against_the_mempool() {
        // The common case (ADR-0012): the spend chains off this vault's own
        // unconfirmed spend-change, which cannot be replaced without t-of-n.
        let parent = tx_spending(
            &[OutPoint::new(Txid::from_byte_array([1; 32]), 0)],
            90_000,
            1,
        );
        let parent_txid = parent.compute_txid();
        let child = tx_spending(&[OutPoint::new(parent_txid, 0)], 80_000, 2);

        let mut backend = MockBackend::default();
        backend
            .prevouts
            .insert(child.input[0].previous_output, prevout(false));
        backend.raw_txs.insert(parent_txid, serialize(&parent));
        let authorized: HashSet<Txid> = [parent_txid].into_iter().collect();

        let package = assemble_package(&backend, &child, &authorized).expect("authorized parent");
        assert_eq!(
            package,
            vec![serialize(&child)],
            "the parent is already in the mempool; Core tests the child against it"
        );
        // Deliberately no `prevout` entry for the parent's input. In real Core it
        // is spent by this mempool parent, so gettxout returns null; ancestry must
        // use mempool membership instead.
    }

    /// The toxic-deposit rule: an unconfirmed parent this node never authorized
    /// can be replaced out from under the spend, so the spend is not broadcast at
    /// all. Excluded, not merely deprioritized.
    #[test]
    fn a_spend_over_an_external_unconfirmed_deposit_is_excluded() {
        let deposit_txid = Txid::from_byte_array([0xEE; 32]);
        let child = tx_spending(&[OutPoint::new(deposit_txid, 0)], 80_000, 3);

        let mut backend = MockBackend::default();
        backend
            .prevouts
            .insert(child.input[0].previous_output, prevout(false));
        backend
            .raw_txs
            .insert(deposit_txid, serialize(&sample_tx()));

        // The authorized set is empty: this node never validated that deposit.
        let error = assemble_package(&backend, &child, &HashSet::new())
            .expect_err("an external unconfirmed deposit must not be chained onto");
        assert!(
            error.to_string().contains("external unconfirmed deposit"),
            "the exclusion must name its reason: {error}"
        );
    }

    #[test]
    fn a_multi_level_authorized_chain_is_fully_validated_but_not_relisted() {
        let grandparent = tx_spending(
            &[OutPoint::new(Txid::from_byte_array([1; 32]), 0)],
            90_000,
            10,
        );
        let gp_txid = grandparent.compute_txid();
        let parent = tx_spending(&[OutPoint::new(gp_txid, 0)], 85_000, 11);
        let parent_txid = parent.compute_txid();
        let child = tx_spending(&[OutPoint::new(parent_txid, 0)], 80_000, 12);

        let mut backend = MockBackend::default();
        backend
            .prevouts
            .insert(parent.input[0].previous_output, prevout(false));
        backend
            .prevouts
            .insert(child.input[0].previous_output, prevout(false));
        backend.raw_txs.insert(gp_txid, serialize(&grandparent));
        backend.raw_txs.insert(parent_txid, serialize(&parent));
        let authorized: HashSet<Txid> = [gp_txid, parent_txid].into_iter().collect();

        let package = assemble_package(&backend, &child, &authorized).expect("authorized chain");
        assert_eq!(
            package,
            vec![serialize(&child)],
            "already-present multi-generation ancestors must not be re-listed in Core's package"
        );
    }

    #[test]
    fn an_unknown_prevout_refuses_to_package_rather_than_guessing() {
        let tx = sample_tx();
        // No prevout registered: this node cannot see the output at all.
        let error = assemble_package(&MockBackend::default(), &tx, &HashSet::new())
            .expect_err("an unknown prevout must not be packaged");
        assert!(error.to_string().contains("unknown to this node"));
    }

    #[test]
    fn an_over_deep_unconfirmed_chain_is_bounded_rather_than_recursing_forever() {
        // A chain longer than the ancestor bound: every link is authorized and
        // unconfirmed, so only the bound stops the walk.
        let mut backend = MockBackend::default();
        let mut authorized = HashSet::new();
        let root = OutPoint::new(Txid::from_byte_array([1; 32]), 0);
        let mut previous = root;
        let mut last_tx = None;
        for i in 0..(MAX_PACKAGE_ANCESTORS as u32 + 5) {
            let tx = tx_spending(&[previous], 90_000, i);
            let txid = tx.compute_txid();
            backend.prevouts.insert(previous, prevout(false));
            backend.raw_txs.insert(txid, serialize(&tx));
            authorized.insert(txid);
            previous = OutPoint::new(txid, 0);
            last_tx = Some(tx);
        }
        // The chain's own root prevout is confirmed; everything above is not.
        backend.prevouts.insert(root, prevout(true));

        let error = assemble_package(&backend, &last_tx.expect("chain built"), &authorized)
            .expect_err("an over-deep chain must be refused, not packaged");
        assert!(
            error.to_string().contains("ancestor bound"),
            "the bound must name itself: {error}"
        );
    }

    #[test]
    fn broadcast_records_the_raw_tx_and_returns_its_txid() {
        let backend = MockBackend::default();
        let tx = sample_tx();
        let raw = serialize(&tx);
        let txid = backend.broadcast(&raw).expect("valid tx broadcasts");
        assert_eq!(txid, tx.compute_txid());
        assert_eq!(
            backend
                .broadcasts
                .lock()
                .expect("broadcasts lock")
                .as_slice(),
            &[raw],
            "the backend must record the exact raw tx it was handed"
        );
    }

    #[test]
    fn a_malformed_tx_surfaces_the_backend_error_without_panicking() {
        let backend = MockBackend::default();
        // Not a valid consensus-serialized transaction.
        let result = backend.broadcast(&[0xde, 0xad, 0xbe, 0xef]);
        assert!(
            result.is_err(),
            "a malformed tx must be an Err, not a panic"
        );
        assert!(
            backend
                .broadcasts
                .lock()
                .expect("broadcasts lock")
                .is_empty(),
            "a rejected tx is never recorded as broadcast"
        );
    }
}
