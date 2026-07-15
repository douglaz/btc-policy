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
use bitcoin::{consensus, OutPoint, ScriptBuf, Transaction, Txid};
use serde_json::{json, Value};

use crate::Error;

/// One on-chain spend of a watched scriptPubKey, from the watchtower scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpendSeen {
    /// Txid of the transaction that spent the watched output.
    pub spend_txid: Txid,
    /// The watched output that was consumed (the vault UTXO).
    pub outpoint: OutPoint,
    /// scriptPubKey of the spent output — one of the queried `scripts`. In v0 the
    /// watchtower classifies against a DISTINCT recovery-script set, so this tells
    /// a recovery-branch spend from a vault-path spend. NOTE for v1 (T6): the real
    /// design puts recovery as an alternate branch inside the SAME `wsh(...)`
    /// descriptor (DESIGN.md, Wallet Topology — recovery is "an alternate spend
    /// path over the same coins"), so a recovery spend and a normal spend share
    /// this prevout scriptPubKey and cannot be told apart by it; the spending
    /// witness (which branch/keys) is the distinguishing signal. v0's recovery set
    /// is empty (first light has no recovery branch), so this is not yet exercised.
    pub script: ScriptBuf,
}

/// A node's own view of the chain (DESIGN.md, "Per-node chain backend"). Serves
/// broadcast (V0-4) and the watchtower scan (ADR-0001). Kept small on purpose so
/// unit tests substitute a mock.
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

    /// One JSON-RPC call, returning the `result` field or surfacing bitcoind's
    /// `error`.
    fn call(&self, method: &str, params: Value) -> Result<Value, Error> {
        let request = json!({
            "jsonrpc": "1.0",
            "id": "vault-node",
            "method": method,
            "params": params,
        });
        let body = post_json(self.rpc_addr, &request.to_string(), &self.auth)?;
        let reply: Value = serde_json::from_str(&body)
            .map_err(|e| format!("bitcoind {method}: unparseable reply: {e}"))?;
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
                    seen.push(SpendSeen {
                        spend_txid: Txid::from_str(spend_txid)
                            .map_err(|e| format!("getblock: bad spend txid: {e}"))?,
                        outpoint: OutPoint::new(
                            Txid::from_str(prev_txid)
                                .map_err(|e| format!("getblock: bad prevout txid: {e}"))?,
                            vout,
                        ),
                        script: spk,
                    });
                }
            }
        }
        Ok(seen)
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

    use std::cell::RefCell;

    use bitcoin::{consensus, ScriptBuf, Transaction, Txid};

    use super::{ChainBackend, SpendSeen};
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
    #[derive(Default)]
    pub(crate) struct MockBackend {
        pub spends: Vec<SpendSeen>,
        pub broadcasts: RefCell<Vec<Vec<u8>>>,
        pub tip: u32,
        pub spend_block: u32,
        pub scanned_from: RefCell<Vec<u32>>,
    }

    impl ChainBackend for MockBackend {
        fn broadcast(&self, raw_tx: &[u8]) -> Result<Txid, Error> {
            // Parse like the real backend so a malformed tx surfaces an error
            // (no panic) — and so the returned txid is the real one.
            let tx: Transaction = consensus::deserialize(raw_tx)
                .map_err(|e| format!("malformed transaction: {e}"))?;
            self.broadcasts.borrow_mut().push(raw_tx.to_vec());
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
            self.scanned_from.borrow_mut().push(from_height);
            // The canned spends live in `spend_block`; a scan whose cursor has
            // advanced past it sees nothing, so a re-alert can only come from a
            // cursor that failed to advance (never dedup).
            if from_height <= self.spend_block {
                Ok(self.spends.clone())
            } else {
                Ok(Vec::new())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::mock::MockBackend;
    use super::ChainBackend;

    use bitcoin::absolute::LockTime;
    use bitcoin::consensus::encode::serialize;
    use bitcoin::hashes::Hash;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};

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

    #[test]
    fn broadcast_records_the_raw_tx_and_returns_its_txid() {
        let backend = MockBackend::default();
        let tx = sample_tx();
        let raw = serialize(&tx);
        let txid = backend.broadcast(&raw).expect("valid tx broadcasts");
        assert_eq!(txid, tx.compute_txid());
        assert_eq!(
            backend.broadcasts.borrow().as_slice(),
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
            backend.broadcasts.borrow().is_empty(),
            "a rejected tx is never recorded as broadcast"
        );
    }
}
