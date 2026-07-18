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

use std::collections::HashSet;
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

    fn mempool_transaction(&self, txid: &Txid) -> Result<Option<Vec<u8>>, Error> {
        // Query membership explicitly instead of probing an English RPC error or
        // relying on `-txindex`. A confirmed parent is absent here; an unconfirmed
        // ancestor is present and getrawtransaction can always read mempool data.
        let mempool = self.call("getrawmempool", json!([]))?;
        let entries = mempool
            .as_array()
            .ok_or("getrawmempool: expected an array")?;
        let txid_text = txid.to_string();
        if !entries
            .iter()
            .any(|entry| entry.as_str() == Some(txid_text.as_str()))
        {
            return Ok(None);
        }
        let result = self.call("getrawtransaction", json!([txid_text]))?;
        let hex = result
            .as_str()
            .ok_or("getrawtransaction: expected a hex string")?;
        Ok(Some(
            Vec::<u8>::from_hex(hex).map_err(|e| format!("getrawtransaction: bad hex: {e}"))?,
        ))
    }

    fn transaction_confirmed(&self, txid: &Txid) -> Result<bool, Error> {
        // The v0 bitcoind backend is launched with `-txindex=1` by the demo, so it
        // can distinguish a mined transaction from one that is merely absent.
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
    use std::sync::Mutex;

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
        pub packages_tested: Mutex<Vec<Vec<Vec<u8>>>>,
    }

    impl ChainBackend for MockBackend {
        fn broadcast(&self, raw_tx: &[u8]) -> Result<Txid, Error> {
            // Parse like the real backend so a malformed tx surfaces an error
            // (no panic) — and so the returned txid is the real one.
            let tx: Transaction = consensus::deserialize(raw_tx)
                .map_err(|e| format!("malformed transaction: {e}"))?;
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
    use super::{assemble_package, ChainBackend, Prevout, MAX_PACKAGE_ANCESTORS};

    use bitcoin::absolute::LockTime;
    use bitcoin::consensus::encode::serialize;
    use bitcoin::hashes::Hash;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
    use std::collections::HashSet;

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
