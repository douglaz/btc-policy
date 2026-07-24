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
//! v0 ships the trait seam plus one minimal `bitcoind`-RPC impl for regtest.
//! Vault-node's `/sign` preflight uses [`ChainBackend::prevouts`] to verify confirmed
//! inputs before pure policy evaluation; unconfirmed authorized parents remain
//! subject to the fire-time package checks. Being a trait, unit tests use a mock
//! and never need bitcoind.

use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::str::FromStr;
use std::sync::Mutex;
use std::time::Duration;

use bitcoin::consensus::encode::serialize_hex;
use bitcoin::hex::{DisplayHex, FromHex};
use bitcoin::{
    consensus, Amount, BlockHash, OutPoint, ScriptBuf, Transaction, TxOut, Txid, Witness,
};
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

    /// The block hash at `height` in this node's ACTIVE chain, or `None` if no
    /// block occupies that height (beyond the tip, or pruned). The reorg-aware
    /// watchtower cursor ([`watchtower::ScanCursor`](crate::watchtower::ScanCursor))
    /// reads it to confirm the block it last scanned at a height still matches the
    /// chain; a mismatch is a reorg, and the cursor rewinds to the fork point
    /// rather than silently advancing past re-orged blocks it never re-classified.
    fn block_hash_at(&self, height: u32) -> Result<Option<BlockHash>, Error>;

    /// Spends of any of `scripts` observed in the inclusive block range
    /// `from_height..=through_height`, against this node's own chain data. Fixing the
    /// terminal height lets the watchtower bind alerts and cursor anchors to the same
    /// captured chain prefix even if a new block arrives mid-pass.
    fn spends_of(
        &self,
        scripts: &[ScriptBuf],
        from_height: u32,
        through_height: u32,
    ) -> Result<Vec<SpendSeen>, Error>;

    /// The unspent output at `outpoint` as this node sees it, **including its own
    /// mempool**. `None` ⇒ this node cannot see the output (unknown or already
    /// spent). Confirmed-only would strand the common case: spend-change and
    /// refresh outputs are usually still unconfirmed (ADR-0012).
    fn prevout(&self, outpoint: &OutPoint) -> Result<Option<Prevout>, Error>;

    /// Resolve several prevouts as one logical preflight. Backends may override
    /// this to batch transport; the default preserves the small trait seam for
    /// mocks and alternate backends while aborting on the first error.
    fn prevouts(&self, outpoints: &[OutPoint]) -> Result<Vec<Option<Prevout>>, Error> {
        outpoints
            .iter()
            .map(|outpoint| self.prevout(outpoint))
            .collect()
    }

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

    /// Refresh any backend-side confirmed-vault cache outside the fire/combine path.
    /// The default is a no-op for mocks and indexed backends; the Core backend warms
    /// a cold `scantxoutset` snapshot and advances it by a bounded block delta.
    fn refresh_vault_unspent_cache(&self, _scripts: &[ScriptBuf]) -> Result<(), Error> {
        Ok(())
    }

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
    /// Confirmed vault-UTXO cache maintained only by
    /// [`ChainBackend::refresh_vault_unspent_cache`], never by the fire/combine hot
    /// path. A cold cache is warmed with `scantxoutset` in a dedicated blocking task;
    /// after that, bounded block deltas advance it. `vault_unspent` either consumes a
    /// cache at the current tip or fails fast, so no whole-set scan can consume the
    /// escape's finite combine window.
    scan_cache: Mutex<Option<VaultUnspentCache>>,
}

/// The cached confirmed vault-UTXO scan (deliverable 9y5.3-c). `candidates` is
/// mempool-agnostic active-chain membership; each entry is re-checked through
/// batched `gettxout(..., include_mempool)` on use, so a confirmed output a mempool
/// tx has since spent is still dropped.
#[derive(Clone)]
struct VaultUnspentCache {
    bestblock: BlockHash,
    height: u32,
    scripts: Vec<ScriptBuf>,
    candidates: HashSet<OutPoint>,
}

/// Maximum active-chain blocks one background cache refresh parses. A node that
/// starts far behind advances over successive passes; until it catches the tip the
/// fire path fails fast rather than doing unbounded catch-up inside the combine
/// window. The cold full scan and any reorg fallback also run only in that background
/// task.
const MAX_VAULT_SCAN_DELTA_BLOCKS: u32 = 32;

impl BitcoindBackend {
    /// `auth` is the base64 of `<user>:<password>` (regtest cookie auth). The
    /// caller reads bitcoind's `.cookie` and base64-encodes it.
    pub fn new(rpc_addr: SocketAddr, auth: String) -> BitcoindBackend {
        BitcoindBackend {
            rpc_addr,
            auth,
            scan_cache: Mutex::new(None),
        }
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

    fn parse_prevout(result: &Value) -> Result<Option<Prevout>, Error> {
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

    /// Parse one successful whole-UTXO-set scan into a cache anchored to the block
    /// hash Core says it observed. This is called only by the background refresher.
    fn full_confirmed_scan(&self, scripts: &[ScriptBuf]) -> Result<VaultUnspentCache, Error> {
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
        let bestblock_text = scan["bestblock"]
            .as_str()
            .ok_or("scantxoutset: bestblock is not a hash")?;
        let bestblock = BlockHash::from_str(bestblock_text)
            .map_err(|e| format!("scantxoutset: bad bestblock hash: {e}"))?;
        let unspents = scan["unspents"]
            .as_array()
            .ok_or("scantxoutset: unspents is not an array")?;
        let mut candidates = HashSet::with_capacity(unspents.len());
        for entry in unspents {
            let txid = entry["txid"]
                .as_str()
                .ok_or("scantxoutset: unspent has no txid")?;
            let vout = entry["vout"]
                .as_u64()
                .ok_or("scantxoutset: unspent has no vout")?;
            let vout = u32::try_from(vout).map_err(|_| "scantxoutset: vout exceeds u32")?;
            candidates.insert(OutPoint::new(
                Txid::from_str(txid).map_err(|e| format!("scantxoutset: bad txid: {e}"))?,
                vout,
            ));
        }
        let header = self.call("getblockheader", json!([bestblock.to_string(), true]))?;
        let height = header["height"]
            .as_u64()
            .ok_or("getblockheader: no block height")?;
        let height =
            u32::try_from(height).map_err(|_| "getblockheader: block height exceeds u32")?;
        if self.block_hash_at(height)? != Some(bestblock) {
            return Err(
                "scantxoutset: best block is no longer active; discarding the cold cache".into(),
            );
        }
        Ok(VaultUnspentCache {
            bestblock,
            height,
            scripts: scripts.to_vec(),
            candidates,
        })
    }

    /// Advance a warm confirmed-vault cache through at most
    /// [`MAX_VAULT_SCAN_DELTA_BLOCKS`] active blocks. Transactions add watched
    /// outputs and remove every spent outpoint. Parent linkage plus a terminal
    /// active-hash re-read makes the update transactional across a racing reorg.
    fn advance_confirmed_scan(
        &self,
        mut cache: VaultUnspentCache,
    ) -> Result<VaultUnspentCache, Error> {
        let tip = self.tip_height()?;
        if tip <= cache.height {
            return Ok(cache);
        }
        let through = tip.min(cache.height.saturating_add(MAX_VAULT_SCAN_DELTA_BLOCKS));
        let watched: HashSet<ScriptBuf> = cache.scripts.iter().cloned().collect();
        let mut parent = cache.bestblock;
        for height in cache.height + 1..=through {
            let hash = self.block_hash_at(height)?.ok_or_else(|| {
                format!("vault scan delta: active block at height {height} vanished")
            })?;
            let block = self.call("getblock", json!([hash.to_string(), 2]))?;
            let expected_parent = parent.to_string();
            if block["previousblockhash"].as_str() != Some(expected_parent.as_str()) {
                return Err(format!(
                    "vault scan delta: block {hash} at height {height} does not chain to \
                     cached parent {parent}; discarding the raced update"
                )
                .into());
            }
            let txs = block["tx"]
                .as_array()
                .ok_or("vault scan delta: getblock tx is not an array")?;
            for tx in txs {
                for vin in tx["vin"].as_array().into_iter().flatten() {
                    let (Some(txid), Some(vout)) = (vin["txid"].as_str(), vin["vout"].as_u64())
                    else {
                        // Coinbase has no previous outpoint.
                        continue;
                    };
                    let vout = u32::try_from(vout)
                        .map_err(|_| "vault scan delta: input vout exceeds u32")?;
                    cache.candidates.remove(&OutPoint::new(
                        Txid::from_str(txid)
                            .map_err(|e| format!("vault scan delta: bad input txid: {e}"))?,
                        vout,
                    ));
                }
                let txid_text = tx["txid"]
                    .as_str()
                    .ok_or("vault scan delta: transaction has no txid")?;
                let txid = Txid::from_str(txid_text)
                    .map_err(|e| format!("vault scan delta: bad transaction txid: {e}"))?;
                let outputs = tx["vout"]
                    .as_array()
                    .ok_or("vault scan delta: transaction vout is not an array")?;
                for (vout, output) in outputs.iter().enumerate() {
                    let script_hex = output["scriptPubKey"]["hex"]
                        .as_str()
                        .ok_or("vault scan delta: output has no scriptPubKey hex")?;
                    let script = ScriptBuf::from_hex(script_hex)
                        .map_err(|e| format!("vault scan delta: bad output scriptPubKey: {e}"))?;
                    if watched.contains(&script) {
                        let vout = u32::try_from(vout)
                            .map_err(|_| "vault scan delta: output index exceeds u32")?;
                        cache.candidates.insert(OutPoint::new(txid, vout));
                    }
                }
            }
            parent = hash;
        }
        if self.block_hash_at(through)? != Some(parent) {
            return Err(format!(
                "vault scan delta: terminal block {parent} at height {through} is no longer active"
            )
            .into());
        }
        cache.bestblock = parent;
        cache.height = through;
        Ok(cache)
    }

    /// The current confirmed-UTXO membership paying `scripts`, read only from the
    /// background-maintained cache. Cold or stale is an immediate error — never a
    /// synchronous `scantxoutset` on the fire/combine path.
    fn confirmed_candidates(
        &self,
        scripts: &[ScriptBuf],
    ) -> Result<(BlockHash, Vec<OutPoint>), Error> {
        let tip_text = self
            .call("getbestblockhash", json!([]))?
            .as_str()
            .ok_or("getbestblockhash: expected a block hash")?
            .to_string();
        let tip = BlockHash::from_str(&tip_text)
            .map_err(|e| format!("getbestblockhash: bad hash: {e}"))?;
        let cache = self.scan_cache.lock().expect("scan cache lock poisoned");
        let cached = cache
            .as_ref()
            .filter(|cache| cache.scripts == scripts && cache.bestblock == tip)
            .ok_or_else(|| {
                "confirmed vault cache is cold or behind the active tip; refusing the fire-time \
                 coverage check without running scantxoutset on the combine path"
                    .to_string()
            })?;
        let mut candidates: Vec<_> = cached.candidates.iter().copied().collect();
        candidates.sort();
        Ok((tip, candidates))
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

    fn block_hash_at(&self, height: u32) -> Result<Option<BlockHash>, Error> {
        // `getblockhash` errors with code -8 ("Block height out of range") for a
        // height above the active tip. That is the reorg-shortened-chain case the
        // cursor must read as "no block here" (→ rewind), NOT a backend failure, so
        // fold -8 to `None` and surface every other RPC error.
        let reply = self.call_reply("getblockhash", json!([height]))?;
        if !reply["error"].is_null() {
            if reply["error"]["code"].as_i64() == Some(-8) {
                return Ok(None);
            }
            return Err(format!("bitcoind getblockhash: {}", reply["error"]).into());
        }
        let hash = reply["result"]
            .as_str()
            .ok_or("getblockhash: expected a hash string")?;
        Ok(Some(
            BlockHash::from_str(hash).map_err(|e| format!("getblockhash: bad hash: {e}"))?,
        ))
    }

    fn spends_of(
        &self,
        scripts: &[ScriptBuf],
        from_height: u32,
        through_height: u32,
    ) -> Result<Vec<SpendSeen>, Error> {
        // Scan blocks through the caller's captured terminal height; a watched script is spent
        // when some input's prevout carries it. `getblock` verbosity 3 (Core v25+)
        // inlines each input's `prevout`, so no per-input `getrawtransaction` is
        // needed. Bounded work on regtest; the Core/Electrum/filter tradeoff for
        // real networks is v1 (T6).
        let watched: HashSet<&ScriptBuf> = scripts.iter().collect();
        let mut seen = Vec::new();
        // Mid-scan reorg guard (deliverable 9y5.3-a): the per-height reads below are
        // NOT an atomic chain snapshot, so a reorg that swaps the active block at some
        // height while this loop straddles it could read a fork this node no longer
        // follows and silently miss the spends of the one it does. TWO checks together
        // make the traversed range provably a prefix of the ACTIVE chain:
        //
        //  1. consecutive scanned blocks must CHAIN (`block[h].previousblockhash ==
        //     block[h-1].hash`), so a MIXED-fork straddle breaks the linkage; and
        //  2. after the loop, the LAST block actually traversed must STILL be the
        //     active block at its height (below). Headers chain backwards, so that one
        //     re-read proves every earlier traversed block is its ancestor and so also
        //     active.
        //
        // Check 2 is what closes the case check 1 cannot see: a loop that read a single
        // foreign fork END-TO-END is internally consistent, and an A→B→A that returns to
        // the original tip also slips past `scan_pass`'s post-scan tip-hash check, so
        // without it a whole scan could be bound to a fork the node has abandoned.
        //
        // Either failure is an error, so the pass discards its results and retries from
        // an unadvanced cursor rather than binding one fork's spends and skipping the
        // active chain's.
        let mut last_scanned: Option<(u32, String)> = None;
        for height in from_height..=through_height {
            let hash = self
                .call("getblockhash", json!([height]))?
                .as_str()
                .ok_or("getblockhash: expected a hash string")?
                .to_string();
            let block = self.call("getblock", json!([hash, 3]))?;
            if let Some((_, prev)) = &last_scanned {
                let parent = block["previousblockhash"]
                    .as_str()
                    .ok_or("getblock: block has no previousblockhash (verbosity 3 required)")?;
                if parent != prev {
                    return Err(format!(
                        "getblock: block at height {height} does not chain onto the \
                         previously scanned block (a reorg raced the scan); refusing to \
                         bind a mixed-fork scan and re-scanning next pass"
                    )
                    .into());
                }
            }
            last_scanned = Some((height, hash));
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
        // Check 2 (see above): the newest block this loop actually READ must still be
        // the active block at its height. A scan that ran entirely on a fork the node
        // has since abandoned fails here instead of returning that fork's spends as if
        // they were the active chain's.
        if let Some((height, hash)) = last_scanned {
            let active = self.call("getblockhash", json!([height]))?;
            if active.as_str() != Some(hash.as_str()) {
                return Err(format!(
                    "getblockhash: block {hash} scanned at height {height} is no longer the \
                     active block there (a reorg raced the scan); refusing to bind an \
                     abandoned fork's spends and re-scanning next pass"
                )
                .into());
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
        Self::parse_prevout(&result)
    }

    fn prevouts(&self, outpoints: &[OutPoint]) -> Result<Vec<Option<Prevout>>, Error> {
        if outpoints.is_empty() {
            return Ok(Vec::new());
        }
        // One HTTP request and one fixed RPC timeout for the complete PSBT
        // preflight. The hostile coordinator therefore cannot
        // multiply a slow/down backend's network timeout by the number of inputs
        // while `/sign` holds its serialization lock.
        let requests: Vec<Value> = outpoints
            .iter()
            .enumerate()
            .map(|(id, outpoint)| {
                json!({
                    "jsonrpc": "1.0",
                    "id": id,
                    "method": "gettxout",
                    "params": [outpoint.txid.to_string(), outpoint.vout, true],
                })
            })
            .collect();
        let body = post_json(
            self.rpc_addr,
            &Value::Array(requests).to_string(),
            &self.auth,
        )?;
        let replies: Vec<Value> = serde_json::from_str(&body)
            .map_err(|e| format!("bitcoind gettxout batch: unparseable reply: {e}"))?;
        if replies.len() != outpoints.len() {
            return Err(format!(
                "bitcoind gettxout batch: expected {} replies, got {}",
                outpoints.len(),
                replies.len()
            )
            .into());
        }
        let mut ordered = vec![None; outpoints.len()];
        for reply in replies {
            let id = reply["id"]
                .as_u64()
                .and_then(|id| usize::try_from(id).ok())
                .filter(|id| *id < outpoints.len())
                .ok_or("bitcoind gettxout batch: missing or out-of-range reply id")?;
            if ordered[id].is_some() {
                return Err(format!("bitcoind gettxout batch: duplicate reply id {id}").into());
            }
            if !reply["error"].is_null() {
                return Err(
                    format!("bitcoind gettxout batch item {id}: {}", reply["error"]).into(),
                );
            }
            ordered[id] = Some(Self::parse_prevout(&reply["result"])?);
        }
        ordered
            .into_iter()
            .enumerate()
            .map(|(id, result)| {
                result
                    .ok_or_else(|| format!("bitcoind gettxout batch: missing reply id {id}").into())
            })
            .collect()
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
        // SCALING (deliverable 9y5.3-c): the confirmed scan is absent from this hot
        // path. A dedicated background task warms the cold `scantxoutset` snapshot
        // and advances it by at most `MAX_VAULT_SCAN_DELTA_BLOCKS` blocks per pass.
        // Here [`Self::confirmed_candidates`] accepts only a cache already at the
        // active tip; cold/stale fails immediately (no sweep; Lockdown already
        // latched) rather than consuming the finite combine window.
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
            // The confirmed-set candidates from the current-tip cache, then one
            // batched `gettxout(..., include_mempool=true)` re-validation that drops any
            // confirmed output a mempool transaction has since spent — exactly as
            // before the cache existed; the cache only skips the whole-set scan.
            let (scan_tip, candidates) = self.confirmed_candidates(scripts)?;
            let mut found: HashMap<OutPoint, Prevout> = HashMap::new();
            let confirmed_prevouts = self.prevouts(&candidates)?;
            if confirmed_prevouts.len() != candidates.len() {
                return Err(format!(
                    "chain backend returned {} confirmed-candidate prevouts for {} outpoints",
                    confirmed_prevouts.len(),
                    candidates.len()
                )
                .into());
            }
            for (outpoint, prevout) in candidates.iter().zip(confirmed_prevouts) {
                if let Some(prevout) = prevout {
                    if watched.contains(&prevout.txout.script_pubkey) && prevout.confirmed {
                        found.insert(*outpoint, prevout);
                    }
                }
            }

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
            let tip_after_text = self
                .call("getbestblockhash", json!([]))?
                .as_str()
                .ok_or("getbestblockhash: expected a block hash")?
                .to_string();
            let tip_after = BlockHash::from_str(&tip_after_text)
                .map_err(|e| format!("getbestblockhash: bad hash: {e}"))?;
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

    fn refresh_vault_unspent_cache(&self, scripts: &[ScriptBuf]) -> Result<(), Error> {
        let cached = self
            .scan_cache
            .lock()
            .expect("scan cache lock poisoned")
            .as_ref()
            .filter(|cache| cache.scripts == scripts)
            .cloned();
        let refreshed = match cached {
            Some(cache) if self.block_hash_at(cache.height)? == Some(cache.bestblock) => {
                self.advance_confirmed_scan(cache)?
            }
            // Cold start or a reorg below the cache anchor. A full scan is unavoidable,
            // but this method is called only from the dedicated background task.
            Some(_) | None => self.full_confirmed_scan(scripts)?,
        };
        *self.scan_cache.lock().expect("scan cache lock poisoned") = Some(refreshed);
        Ok(())
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
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Barrier, Mutex};

    use bitcoin::hashes::Hash;
    use bitcoin::{consensus, BlockHash, OutPoint, ScriptBuf, Transaction, Txid};

    use super::{ChainBackend, PackageVerdict, Prevout, SpendSeen};
    use crate::Error;

    /// A deterministic per-height block hash for the mock's chain view. `epoch`
    /// distinguishes chain histories: the default view is epoch 0, and
    /// [`MockBackend::reorg_at`] rewrites a suffix to epoch 1 so a hash that was
    /// recorded before the reorg no longer matches — exactly what the reorg-aware
    /// cursor keys off. Encoding the height keeps every height's hash distinct.
    pub(crate) fn mock_block_hash(height: u32, epoch: u8) -> BlockHash {
        let mut bytes = [0u8; 32];
        bytes[..4].copy_from_slice(&height.to_le_bytes());
        bytes[4] = epoch;
        BlockHash::from_byte_array(bytes)
    }

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
        /// Per-height block-hash overrides for the reorg-cursor tests. A height
        /// absent here reads its deterministic epoch-0 [`mock_block_hash`];
        /// [`Self::reorg_at`] inserts epoch-1 hashes to model a reorg.
        pub block_hashes: HashMap<u32, BlockHash>,
        /// If set, the first completed `spends_of` switches every hash at and above
        /// this height to a distinct epoch. This models the scan/hash-collection
        /// reorg race without mutating the mock through `&self`.
        pub scan_reorg_from: Option<u32>,
        pub scan_completed: AtomicBool,
        pub scanned_from: Mutex<Vec<u32>>,
        pub prevouts: HashMap<OutPoint, Prevout>,
        /// Every `prevout` lookup, in order, so the preflight tests can prove a
        /// backend failure aborts rather than multiplying one timeout per input.
        pub prevout_lookups: Mutex<Vec<OutPoint>>,
        /// Optional failure injected after recording a `prevout` lookup.
        pub prevout_error: Option<String>,
        /// Optional one-shot pause on the first prevout lookup. Handler-level tests
        /// use it to prove the duress intent exists and `sign_state` is free while
        /// chain preflight is blocked.
        pub prevout_fetch_entered: Option<Arc<Barrier>>,
        pub prevout_fetch_continue: Option<Arc<Barrier>>,
        pub prevout_fetch_paused: AtomicBool,
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

    impl MockBackend {
        /// The block hash this mock reports at `height`: an override if present,
        /// else the deterministic epoch-0 hash.
        fn block_hash_of(&self, height: u32) -> BlockHash {
            self.block_hashes.get(&height).copied().unwrap_or_else(|| {
                let raced = self.scan_completed.load(Ordering::Relaxed)
                    && self
                        .scan_reorg_from
                        .is_some_and(|from_height| height >= from_height);
                mock_block_hash(height, if raced { 2 } else { 0 })
            })
        }

        /// Rewrite the active chain from `from_height` up to the current `tip` to a
        /// distinct (epoch-1) history, modelling a reorg whose fork point is
        /// `from_height - 1`. Every block hash at or above `from_height` then
        /// differs from what a pre-reorg scan recorded, so the cursor detects the
        /// reorg and rewinds. Set `tip` first if the reorg also changes the height.
        pub(crate) fn reorg_at(&mut self, from_height: u32) {
            for height in from_height..=self.tip {
                self.block_hashes.insert(height, mock_block_hash(height, 1));
            }
        }
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

        fn block_hash_at(&self, height: u32) -> Result<Option<BlockHash>, Error> {
            // No block occupies a height above the tip — the reorg-shortened-chain
            // signal the cursor reads as a mismatch.
            if height > self.tip {
                return Ok(None);
            }
            Ok(Some(self.block_hash_of(height)))
        }

        fn spends_of(
            &self,
            _scripts: &[ScriptBuf],
            from_height: u32,
            through_height: u32,
        ) -> Result<Vec<SpendSeen>, Error> {
            self.scanned_from
                .lock()
                .expect("scanned_from lock")
                .push(from_height);
            // The canned spends live in `spend_block`; a scan whose cursor has
            // advanced past it sees nothing, so a re-alert can only come from a
            // cursor that failed to advance (never dedup).
            let result = if from_height <= self.spend_block && self.spend_block <= through_height {
                self.spends.clone()
            } else {
                Vec::new()
            };
            if self.scan_reorg_from.is_some() {
                self.scan_completed.store(true, Ordering::Relaxed);
            }
            Ok(result)
        }

        fn prevout(&self, outpoint: &OutPoint) -> Result<Option<Prevout>, Error> {
            self.prevout_lookups
                .lock()
                .expect("prevout_lookups lock")
                .push(*outpoint);
            if self
                .prevout_fetch_paused
                .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                if let Some(entered) = &self.prevout_fetch_entered {
                    entered.wait();
                }
                if let Some(proceed) = &self.prevout_fetch_continue {
                    proceed.wait();
                }
            }
            if let Some(reason) = &self.prevout_error {
                return Err(reason.clone().into());
            }
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
    use super::{
        assemble_package, BitcoindBackend, ChainBackend, Prevout, MAX_PACKAGE_ANCESTORS,
        MAX_VAULT_SCAN_DELTA_BLOCKS,
    };

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
                let response = if let Some(batch) = body.as_array() {
                    assert!(
                        batch
                            .iter()
                            .all(|request| request["method"] == expected_method),
                        "unexpected JSON-RPC batch: {body}"
                    );
                    if let Some(raw) = result.get("__raw_batch") {
                        raw.clone()
                    } else {
                        let results = result.as_array().cloned().unwrap_or_else(|| vec![result]);
                        assert_eq!(
                            results.len(),
                            batch.len(),
                            "scripted batch needs one result per request"
                        );
                        results
                            .into_iter()
                            .enumerate()
                            .map(|(id, result)| {
                                serde_json::json!({
                                    "result": result,
                                    "error": serde_json::Value::Null,
                                    "id": id,
                                })
                            })
                            .collect::<Vec<_>>()
                            .into()
                    }
                } else {
                    assert_eq!(body["method"], expected_method);
                    serde_json::json!({
                        "result": result,
                        "error": serde_json::Value::Null,
                        "id": "vault-node",
                    })
                }
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

    fn cold_cache_replies(
        scan: serde_json::Value,
        bestblock: &str,
        height: u32,
    ) -> Vec<(&'static str, serde_json::Value)> {
        vec![
            ("scantxoutset", scan),
            ("getblockheader", serde_json::json!({"height": height})),
            ("getblockhash", serde_json::json!(bestblock)),
        ]
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

    #[test]
    fn production_prevout_batch_reorders_ids_and_preserves_null_entries() {
        let first = OutPoint::new(Txid::from_byte_array([0x11; 32]), 0);
        let second = OutPoint::new(Txid::from_byte_array([0x22; 32]), 1);
        let script = ScriptBuf::from_bytes(vec![0x51]);
        let (addr, server) = scripted_rpc(vec![(
            "gettxout",
            serde_json::json!({
                "__raw_batch": [
                    {"result": null, "error": null, "id": 1},
                    {
                        "result": {
                            "scriptPubKey": {"hex": script.as_bytes().to_lower_hex_string()},
                            "value": 0.001,
                            "confirmations": 3
                        },
                        "error": null,
                        "id": 0
                    }
                ]
            }),
        )]);
        let backend = BitcoindBackend::new(addr, String::new());

        let prevouts = backend
            .prevouts(&[first, second])
            .expect("the production batch parser accepts out-of-order ids");
        server.join().expect("scripted RPC completed");
        assert_eq!(prevouts.len(), 2);
        assert_eq!(
            prevouts[0]
                .as_ref()
                .map(|prevout| &prevout.txout.script_pubkey),
            Some(&script)
        );
        assert!(prevouts[0]
            .as_ref()
            .is_some_and(|prevout| prevout.confirmed));
        assert_eq!(prevouts[1], None);
    }

    #[test]
    fn production_prevout_batch_refuses_duplicate_reply_ids() {
        let first = OutPoint::new(Txid::from_byte_array([0x33; 32]), 0);
        let second = OutPoint::new(Txid::from_byte_array([0x44; 32]), 1);
        let (addr, server) = scripted_rpc(vec![(
            "gettxout",
            serde_json::json!({
                "__raw_batch": [
                    {"result": null, "error": null, "id": 0},
                    {"result": null, "error": null, "id": 0}
                ]
            }),
        )]);
        let backend = BitcoindBackend::new(addr, String::new());

        let error = backend
            .prevouts(&[first, second])
            .expect_err("duplicate batch ids must fail closed")
            .to_string();
        server.join().expect("scripted RPC completed");
        assert!(error.contains("duplicate reply id 0"), "{error}");
    }

    /// A fire-time read never chases a stale cache. The background refresher advances
    /// the cold scan by block delta, after which the same hot-path read succeeds.
    #[test]
    fn vault_unspent_fails_fast_until_the_background_delta_reaches_the_tip() {
        let script = ScriptBuf::from_bytes(vec![0x51]);
        let txid = Txid::from_byte_array([0xA5; 32]);
        let old_tip = "11".repeat(32);
        let new_tip = "22".repeat(32);
        let script_hex = script.as_bytes().to_lower_hex_string();
        let confirmed_output = serde_json::json!({
            "scriptPubKey": {"hex": script_hex},
            "value": 0.001,
            "confirmations": 1,
        });
        let scan = serde_json::json!({
            "success": true,
            "bestblock": old_tip,
            "unspents": []
        });
        let mut replies = cold_cache_replies(scan, &old_tip, 0);
        replies.extend([
            // Fire-time: one mempool snapshot plus one best-tip read, then fail fast.
            (
                "getrawmempool",
                serde_json::json!({"txids": [], "mempool_sequence": 1}),
            ),
            ("getbestblockhash", serde_json::json!(new_tip)),
            // Background delta: anchor is still active, then one new block adds the
            // watched output and the terminal active-hash re-read commits it.
            ("getblockhash", serde_json::json!(old_tip)),
            ("getblockcount", serde_json::json!(1)),
            ("getblockhash", serde_json::json!(new_tip)),
            (
                "getblock",
                serde_json::json!({
                    "previousblockhash": old_tip,
                    "tx": [{
                        "txid": txid.to_string(),
                        "vin": [{"coinbase": "00"}],
                        "vout": [{"scriptPubKey": {"hex": script_hex}}]
                    }]
                }),
            ),
            ("getblockhash", serde_json::json!(new_tip)),
            // Fire-time after refresh: current cache, one batched prevout lookup, and
            // a stable chain+mempool bracket.
            (
                "getrawmempool",
                serde_json::json!({"txids": [], "mempool_sequence": 2}),
            ),
            ("getbestblockhash", serde_json::json!(new_tip)),
            ("gettxout", confirmed_output),
            ("getbestblockhash", serde_json::json!(new_tip)),
            (
                "getrawmempool",
                serde_json::json!({"txids": [], "mempool_sequence": 2}),
            ),
        ]);
        let (addr, server) = scripted_rpc(replies);
        let backend = BitcoindBackend::new(addr, String::new());
        let scripts = std::slice::from_ref(&script);

        backend
            .refresh_vault_unspent_cache(scripts)
            .expect("cold cache warm");
        let stale = backend
            .vault_unspent(scripts, &HashSet::new())
            .expect_err("the hot path must not perform its own catch-up");
        assert!(stale.to_string().contains("cold or behind"), "{stale}");
        backend
            .refresh_vault_unspent_cache(scripts)
            .expect("bounded one-block delta");
        let unspent = backend
            .vault_unspent(scripts, &HashSet::new())
            .expect("reconciled vault balance");
        server.join().expect("scripted RPC completed");
        assert_eq!(unspent.len(), 1);
        assert_eq!(unspent[0].0, OutPoint::new(txid, 0));
        assert_eq!(unspent[0].1.txout.value, Amount::from_sat(100_000));
        assert!(unspent[0].1.confirmed);
    }

    #[test]
    fn one_cache_refresh_applies_at_most_the_bounded_block_delta() {
        let script = ScriptBuf::from_bytes(vec![0x51]);
        let hash_at = |height: u32| format!("{height:064x}");
        let genesis = hash_at(0);
        let scan = serde_json::json!({"success": true, "bestblock": genesis, "unspents": []});
        let mut replies = cold_cache_replies(scan, &genesis, 0);
        replies.push(("getblockhash", serde_json::json!(genesis)));
        replies.push(("getblockcount", serde_json::json!(33)));
        for height in 1..=MAX_VAULT_SCAN_DELTA_BLOCKS {
            let hash = hash_at(height);
            let parent = hash_at(height - 1);
            replies.push(("getblockhash", serde_json::json!(hash)));
            replies.push((
                "getblock",
                serde_json::json!({"previousblockhash": parent, "tx": []}),
            ));
        }
        replies.push((
            "getblockhash",
            serde_json::json!(hash_at(MAX_VAULT_SCAN_DELTA_BLOCKS)),
        ));
        // The active tip is still one block beyond the bounded update, so fire-time
        // coverage refuses without fetching or parsing block 33.
        replies.push((
            "getrawmempool",
            serde_json::json!({"txids": [], "mempool_sequence": 1}),
        ));
        replies.push(("getbestblockhash", serde_json::json!(hash_at(33))));
        let (addr, server) = scripted_rpc(replies);
        let backend = BitcoindBackend::new(addr, String::new());
        let scripts = std::slice::from_ref(&script);

        backend
            .refresh_vault_unspent_cache(scripts)
            .expect("cold cache warm");
        backend
            .refresh_vault_unspent_cache(scripts)
            .expect("bounded delta");
        let stale = backend
            .vault_unspent(scripts, &HashSet::new())
            .expect_err("one pass must not exceed the delta bound");
        server.join().expect("scripted RPC completed");
        assert!(stale.to_string().contains("cold or behind"), "{stale}");
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
        let mut replies = cold_cache_replies(scan, &tip, 0);
        replies.extend([
            // Snapshot 1: the authorized child initially spends the confirmed parent.
            (
                "getrawmempool",
                serde_json::json!({"txids": [authorized_txid.to_string()], "mempool_sequence": 10}),
            ),
            ("getbestblockhash", serde_json::json!(tip)),
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
            ("getbestblockhash", serde_json::json!(tip)),
            ("gettxout", confirmed_parent),
            ("getbestblockhash", serde_json::json!("33".repeat(32))),
            (
                "getrawmempool",
                serde_json::json!({"txids": [], "mempool_sequence": 11}),
            ),
        ]);
        let (addr, server) = scripted_rpc(replies);
        let backend = BitcoindBackend::new(addr, String::new());
        let authorized: HashSet<Txid> = [authorized_txid].into_iter().collect();

        backend
            .refresh_vault_unspent_cache(std::slice::from_ref(&script))
            .expect("cold cache warm");
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
        let mut replies = cold_cache_replies(scan, &tip, 0);
        replies.extend([
            // Snapshot 1: an UNAUTHORIZED mempool tx suppresses the confirmed
            // parent. The authorized set is empty throughout this test.
            (
                "getrawmempool",
                serde_json::json!({"txids": [unauthorized_txid.to_string()], "mempool_sequence": 20}),
            ),
            ("getbestblockhash", serde_json::json!(tip)),
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
            ("getbestblockhash", serde_json::json!(tip)),
            ("gettxout", confirmed_parent),
            ("getbestblockhash", serde_json::json!("44".repeat(32))),
            (
                "getrawmempool",
                serde_json::json!({"txids": [], "mempool_sequence": 21}),
            ),
        ]);
        let (addr, server) = scripted_rpc(replies);
        let backend = BitcoindBackend::new(addr, String::new());

        backend
            .refresh_vault_unspent_cache(std::slice::from_ref(&script))
            .expect("cold cache warm");
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
        let mut replies = cold_cache_replies(scan, &tip, 0);
        replies.extend([
            // Snapshot 1: empty mempool. A transient tx then enters, suppresses the
            // confirmed parent, and leaves — all before snapshot 2, so BOTH sets are
            // empty. Only the sequence records the enter (+1) and leave (+1).
            (
                "getrawmempool",
                serde_json::json!({"txids": [], "mempool_sequence": 50}),
            ),
            ("getbestblockhash", serde_json::json!(tip)),
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
            ("getbestblockhash", serde_json::json!(tip)),
            ("gettxout", confirmed_parent),
            ("getbestblockhash", serde_json::json!("88".repeat(32))),
            (
                "getrawmempool",
                serde_json::json!({"txids": [], "mempool_sequence": 52}),
            ),
        ]);
        let (addr, server) = scripted_rpc(replies);
        let backend = BitcoindBackend::new(addr, String::new());

        backend
            .refresh_vault_unspent_cache(std::slice::from_ref(&script))
            .expect("cold cache warm");
        let unspent = backend
            .vault_unspent(std::slice::from_ref(&script), &HashSet::new())
            .expect("transient-reconciled vault balance");
        server.join().expect("scripted RPC completed");
        assert_eq!(unspent.len(), 1);
        assert_eq!(unspent[0].0, OutPoint::new(parent_txid, 0));
        assert_eq!(unspent[0].1.txout.value, Amount::from_sat(100_000));
        assert!(unspent[0].1.confirmed);
    }

    /// Deliverable 9y5.3-c: a second `vault_unspent` call with an UNCHANGED tip
    /// reuses the cached confirmed-set candidates and SKIPS `scantxoutset`. The
    /// scripted peer offers no second `scantxoutset`, so the test passing at all is
    /// the proof the whole-set scan was not re-run — the bound that keeps a
    /// multi-minute mainnet scan from repeating on every combine-window tick.
    #[test]
    fn vault_unspent_reuses_the_confirmed_scan_while_the_tip_is_unchanged() {
        let script = ScriptBuf::from_bytes(vec![0x51]);
        let parent_txid = Txid::from_byte_array([0x5A; 32]);
        let tip = "aa".repeat(32);
        let script_hex = script.as_bytes().to_lower_hex_string();
        let scan = serde_json::json!({
            "success": true,
            "bestblock": tip,
            "unspents": [{"txid": parent_txid.to_string(), "vout": 0}],
        });
        let confirmed = serde_json::json!({
            "scriptPubKey": {"hex": script_hex},
            "value": 0.001,
            "confirmations": 3,
        });
        let mut replies = cold_cache_replies(scan, &tip, 0);
        replies.extend([
            // Calls 1 and 2 both consume the already-warm cache. Neither can issue
            // `scantxoutset`; only the stable chain+mempool bracket repeats.
            (
                "getrawmempool",
                serde_json::json!({"txids": [], "mempool_sequence": 1}),
            ),
            ("getbestblockhash", serde_json::json!(tip)),
            ("gettxout", confirmed.clone()),
            ("getbestblockhash", serde_json::json!(tip)),
            (
                "getrawmempool",
                serde_json::json!({"txids": [], "mempool_sequence": 1}),
            ),
            (
                "getrawmempool",
                serde_json::json!({"txids": [], "mempool_sequence": 1}),
            ),
            ("getbestblockhash", serde_json::json!(tip)),
            ("gettxout", confirmed),
            ("getbestblockhash", serde_json::json!(tip)),
            (
                "getrawmempool",
                serde_json::json!({"txids": [], "mempool_sequence": 1}),
            ),
        ]);
        let (addr, server) = scripted_rpc(replies);
        let backend = BitcoindBackend::new(addr, String::new());
        let scripts = std::slice::from_ref(&script);

        backend
            .refresh_vault_unspent_cache(scripts)
            .expect("cold cache warm");
        let first = backend
            .vault_unspent(scripts, &HashSet::new())
            .expect("first scan");
        let second = backend
            .vault_unspent(scripts, &HashSet::new())
            .expect("cached scan (no scantxoutset)");
        server.join().expect("scripted RPC completed");
        assert_eq!(
            first, second,
            "the cached pass returns the identical balance"
        );
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].0, OutPoint::new(parent_txid, 0));
        assert!(first[0].1.confirmed);
    }

    #[test]
    fn vault_unspent_rejects_an_incomplete_confirmed_scan() {
        let script = ScriptBuf::from_bytes(vec![0x51]);
        let (addr, server) = scripted_rpc(vec![(
            "scantxoutset",
            serde_json::json!({
                "success": false,
                "bestblock": "55".repeat(32),
                "unspents": [],
            }),
        )]);
        let backend = BitcoindBackend::new(addr, String::new());

        let error = backend
            .refresh_vault_unspent_cache(std::slice::from_ref(&script))
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
        let scan = serde_json::json!({"success": true, "bestblock": tip, "unspents": []});
        let mut replies = cold_cache_replies(scan, &tip, 0);
        replies.extend([
            (
                "getrawmempool",
                serde_json::json!({"txids": [current_txid.to_string()], "mempool_sequence": 40}),
            ),
            ("getbestblockhash", serde_json::json!(tip)),
            ("getrawtransaction", serde_json::json!(current_raw)),
            ("getbestblockhash", serde_json::json!(tip)),
            (
                "getrawmempool",
                serde_json::json!({"txids": [current_txid.to_string()], "mempool_sequence": 40}),
            ),
        ]);
        let (addr, server) = scripted_rpc(replies);
        let backend = BitcoindBackend::new(addr, String::new());
        let mut authorized: HashSet<Txid> = (0..128)
            .map(|tag| Txid::from_byte_array([tag; 32]))
            .collect();
        authorized.insert(current_txid);

        backend
            .refresh_vault_unspent_cache(std::slice::from_ref(&script))
            .expect("cold cache warm");
        let unspent = backend
            .vault_unspent(std::slice::from_ref(&script), &authorized)
            .expect("stable snapshot");
        server.join().expect("scripted RPC completed");
        assert!(unspent.is_empty());
    }

    // -- the watchtower scan's mid-scan reorg guard (9y5.3-a) ----------------

    /// One empty block, verbosity-3 shaped, for the scripted scan below.
    fn scanned_block(parent: Option<&str>) -> serde_json::Value {
        match parent {
            Some(parent) => {
                serde_json::json!({"previousblockhash": parent, "tx": []})
            }
            None => serde_json::json!({"tx": []}),
        }
    }

    /// The control: a scan whose blocks chain and whose newest block is still the
    /// active one at its height returns its spends. Without this the two rejection
    /// tests below could pass for the wrong reason (any error at all).
    #[test]
    fn a_stable_scan_returns_its_spends() {
        let first = "a1".repeat(32);
        let second = "a2".repeat(32);
        let (addr, server) = scripted_rpc(vec![
            ("getblockhash", serde_json::json!(first)),
            ("getblock", scanned_block(None)),
            ("getblockhash", serde_json::json!(second)),
            ("getblock", scanned_block(Some(&"a1".repeat(32)))),
            // The terminal re-read: block 2 is still the active block there.
            ("getblockhash", serde_json::json!("a2".repeat(32))),
        ]);
        let backend = BitcoindBackend::new(addr, String::new());
        let seen = backend
            .spends_of(&[ScriptBuf::from_bytes(vec![0x51])], 1, 2)
            .expect("a stable scan");
        server.join().expect("scripted RPC completed");
        assert!(seen.is_empty(), "the scripted blocks carry no spends");
    }

    /// A reorg that swaps the active block PART-WAY through the scan: block 2 comes
    /// back from a different fork and so does not chain onto block 1. Binding that
    /// mixed read would classify one fork's spends and silently skip the other's.
    #[test]
    fn a_mixed_fork_scan_is_refused_rather_than_bound() {
        let (addr, server) = scripted_rpc(vec![
            ("getblockhash", serde_json::json!("a1".repeat(32))),
            ("getblock", scanned_block(None)),
            ("getblockhash", serde_json::json!("b2".repeat(32))),
            // B's block 2 chains onto B's block 1, not the A block just scanned.
            ("getblock", scanned_block(Some(&"b1".repeat(32)))),
        ]);
        let backend = BitcoindBackend::new(addr, String::new());
        let error = backend
            .spends_of(&[ScriptBuf::from_bytes(vec![0x51])], 1, 2)
            .expect_err("a mixed-fork scan must not be bound")
            .to_string();
        server.join().expect("scripted RPC completed");
        assert!(
            error.contains("does not chain onto"),
            "the refusal must name the broken linkage: {error}"
        );
    }

    /// A scan that ran END-TO-END on a fork the node has since abandoned is
    /// internally consistent — every block chains — so only the terminal re-read
    /// catches it. This is the A→B→A case that also returns the original tip hash
    /// and so slips past the watchtower's own post-scan tip check.
    #[test]
    fn a_scan_bound_to_an_abandoned_fork_is_refused() {
        let (addr, server) = scripted_rpc(vec![
            ("getblockhash", serde_json::json!("b1".repeat(32))),
            ("getblock", scanned_block(None)),
            ("getblockhash", serde_json::json!("b2".repeat(32))),
            ("getblock", scanned_block(Some(&"b1".repeat(32)))),
            // The chain returned to A before the terminal re-read.
            ("getblockhash", serde_json::json!("a2".repeat(32))),
        ]);
        let backend = BitcoindBackend::new(addr, String::new());
        let error = backend
            .spends_of(&[ScriptBuf::from_bytes(vec![0x51])], 1, 2)
            .expect_err("an abandoned fork's spends must not be bound")
            .to_string();
        server.join().expect("scripted RPC completed");
        assert!(
            error.contains("no longer the active block"),
            "the refusal must name the abandoned fork: {error}"
        );
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
