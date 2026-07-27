//! Opt-in integration test for the bitcoind `ChainBackend` impl. Like the demo
//! e2e test it spawns a real regtest bitcoind, so it is `#[ignore]`d by default:
//!
//!   nix develop -c cargo test -p vault-node -- --ignored
//!
//! It exercises the backend against live chain data: `test_package_accept`
//! parses Core's real `testmempoolaccept` response, `broadcast` pushes a
//! fully-signed tx, `transaction_confirmed` distinguishes mempool from chain,
//! and `spends_of` finds that spend of a watched scriptPubKey. Setup RPCs
//! (wallet, mining) use a tiny in-test JSON-RPC client; the backend itself is the
//! code under test.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::str::FromStr;
use std::time::{Duration, Instant};

use bitcoin::base64::prelude::{Engine as _, BASE64_STANDARD};
use bitcoin::consensus::encode::deserialize_hex;
use bitcoin::{OutPoint, ScriptBuf, Transaction, Txid};
use serde_json::{json, Value};

use vault_node::chain::{BitcoindBackend, ChainBackend, PackageVerdict};

type Error = Box<dyn std::error::Error + Send + Sync + 'static>;

#[test]
#[ignore = "spawns a regtest bitcoind; run with --ignored"]
fn bitcoind_backend_broadcasts_and_scans_on_regtest() {
    run().expect("bitcoind backend integration");
}

fn run() -> Result<(), Error> {
    let temp = TempDir::new()?;
    let rpc_port = free_port()?;
    let mut node = Bitcoind::start(temp.path.join("d"), rpc_port)?;
    node.create_wallet("it")?;

    // Fund a fresh watched address, mine it in.
    let miner = node.call_str("getnewaddress", json!([]))?;
    node.call("generatetoaddress", json!([101, miner]))?;
    let watched_addr = node.call_str("getnewaddress", json!(["", "bech32"]))?;
    let watched_spk = ScriptBuf::from_hex(
        node.call("getaddressinfo", json!([watched_addr]))?["scriptPubKey"]
            .as_str()
            .ok_or("scriptPubKey")?,
    )?;
    let funding_txid = node.call_str("sendtoaddress", json!([watched_addr, 1.0]))?;
    node.call("generatetoaddress", json!([1, miner]))?;

    // Locate the funding output paying the watched script.
    let funding = node.call("getrawtransaction", json!([funding_txid, true]))?;
    let vout = funding["vout"]
        .as_array()
        .ok_or("vout")?
        .iter()
        .position(|o| o["scriptPubKey"]["hex"].as_str() == Some(&watched_spk.to_hex_string()))
        .ok_or("funding paid no watched output")? as u32;
    let funding_outpoint = OutPoint::new(Txid::from_str(&funding_txid)?, vout);

    // Build + sign two RBF rungs over that outpoint WITHOUT broadcasting them —
    // the backend broadcasts the base and then its higher-fee replacement.
    let dest = node.call_str("getnewaddress", json!([]))?;
    let raw = node.call_str(
        "createrawtransaction",
        json!([[{"txid": funding_txid, "vout": vout, "sequence": 4_294_967_293u64}], {dest.clone(): 0.999}]),
    )?;
    let signed = node.call("signrawtransactionwithwallet", json!([raw]))?;
    let signed_hex = signed["hex"].as_str().ok_or("signed hex")?;
    let base_tx: Transaction = deserialize_hex(signed_hex)?;
    let base_bytes = bitcoin::consensus::encode::serialize(&base_tx);
    let replacement_raw = node.call_str(
        "createrawtransaction",
        json!([[{"txid": funding_txid, "vout": vout, "sequence": 4_294_967_293u64}], {dest: 0.998}]),
    )?;
    let replacement_signed = node.call("signrawtransactionwithwallet", json!([replacement_raw]))?;
    let replacement_hex = replacement_signed["hex"]
        .as_str()
        .ok_or("replacement signed hex")?;
    let replacement_tx: Transaction = deserialize_hex(replacement_hex)?;
    let replacement_bytes = bitcoin::consensus::encode::serialize(&replacement_tx);

    // --- package acceptance + resident-rung replacement ---
    let backend = BitcoindBackend::new(node.rpc_addr, node.auth.clone());
    assert_eq!(
        backend.test_package_accept(std::slice::from_ref(&base_bytes))?,
        PackageVerdict::Accepted,
        "the live Core response parses and admits the base rung before broadcast"
    );
    let base_txid = backend.broadcast(&base_bytes)?;
    assert_eq!(
        base_txid,
        base_tx.compute_txid(),
        "base broadcast returns its txid"
    );
    assert!(
        backend.prevout(&funding_outpoint)?.is_none(),
        "Core hides an outpoint once the resident base rung spends it"
    );
    assert_eq!(
        backend.test_package_accept(std::slice::from_ref(&replacement_bytes))?,
        PackageVerdict::Accepted,
        "Core package-tests the higher rung as a valid replacement despite the hidden prevout"
    );
    let spend_txid = backend.broadcast(&replacement_bytes)?;
    assert_eq!(
        spend_txid,
        replacement_tx.compute_txid(),
        "the higher rung replaces the resident base"
    );
    assert!(
        backend.mempool_transaction(&base_txid)?.is_none(),
        "the replaced base rung leaves the mempool"
    );
    assert!(
        backend.mempool_transaction(&spend_txid)?.is_some(),
        "the higher replacement rung is now resident"
    );
    assert!(
        !backend.transaction_confirmed(&spend_txid)?,
        "mempool admission is not confirmation"
    );
    node.call("generatetoaddress", json!([1, miner]))?;
    assert!(
        backend.transaction_confirmed(&spend_txid)?,
        "the backend finds the peer copy after it moves from mempool to chain"
    );

    // --- spends_of ---
    let traversal = backend.spends_of(
        std::slice::from_ref(&watched_spk),
        0,
        backend.tip_height()?,
        None,
    )?;
    let seen = traversal
        .spends
        .iter()
        .find(|s| s.script == watched_spk)
        .expect("the watched script's spend must be seen");
    assert_eq!(seen.spend_txid, spend_txid);
    assert_eq!(seen.outpoint, funding_outpoint);

    // --- multi-generation package topology ---
    // Core's package policy is stricter than ordinary mempool ancestry. Build a
    // real grandparent -> parent -> child chain with the first two generations
    // already in this node's mempool, then probe the exact package shapes the
    // backend may produce.
    let chain_funding_addr = node.call_str("getnewaddress", json!([]))?;
    let chain_funding_txid = node.call_str("sendtoaddress", json!([chain_funding_addr, 1.0]))?;
    node.call("generatetoaddress", json!([1, miner]))?;
    let chain_funding = node.call("getrawtransaction", json!([chain_funding_txid, true]))?;
    let chain_vout = chain_funding["vout"]
        .as_array()
        .ok_or("chain funding vout")?
        .iter()
        .position(|output| output["value"].as_f64() == Some(1.0))
        .ok_or("chain funding output")? as u32;

    let grandparent_dest = node.call_str("getnewaddress", json!([]))?;
    let grandparent_raw = node.call_str(
        "createrawtransaction",
        json!([[{"txid": chain_funding_txid, "vout": chain_vout}], {grandparent_dest: 0.999}]),
    )?;
    let grandparent_hex = node.call("signrawtransactionwithwallet", json!([grandparent_raw]))?
        ["hex"]
        .as_str()
        .ok_or("grandparent hex")?
        .to_string();
    let grandparent: Transaction = deserialize_hex(&grandparent_hex)?;
    node.call("sendrawtransaction", json!([grandparent_hex]))?;

    let parent_dest = node.call_str("getnewaddress", json!([]))?;
    let parent_raw = node.call_str(
        "createrawtransaction",
        json!([[{"txid": grandparent.compute_txid().to_string(), "vout": 0}], {parent_dest: 0.998}]),
    )?;
    let parent_hex = node.call("signrawtransactionwithwallet", json!([parent_raw]))?["hex"]
        .as_str()
        .ok_or("parent hex")?
        .to_string();
    let parent: Transaction = deserialize_hex(&parent_hex)?;
    node.call("sendrawtransaction", json!([parent_hex]))?;

    let child_dest = node.call_str("getnewaddress", json!([]))?;
    let child_raw = node.call_str(
        "createrawtransaction",
        json!([[{"txid": parent.compute_txid().to_string(), "vout": 0}], {child_dest: 0.997}]),
    )?;
    let child_hex = node.call("signrawtransactionwithwallet", json!([child_raw]))?["hex"]
        .as_str()
        .ok_or("child hex")?
        .to_string();
    let child: Transaction = deserialize_hex(&child_hex)?;

    let deep_package = [
        bitcoin::consensus::encode::serialize(&grandparent),
        bitcoin::consensus::encode::serialize(&parent),
        bitcoin::consensus::encode::serialize(&child),
    ];
    assert!(
        matches!(
            backend.test_package_accept(&deep_package)?,
            PackageVerdict::Rejected(_)
        ),
        "Core rejects a re-listed multi-generation mempool chain"
    );
    let direct_parent_package = [
        bitcoin::consensus::encode::serialize(&parent),
        bitcoin::consensus::encode::serialize(&child),
    ];
    assert!(
        matches!(
            backend.test_package_accept(&direct_parent_package)?,
            PackageVerdict::Rejected(_)
        ),
        "Core also rejects an already-present direct parent in this package shape"
    );
    assert_eq!(
        backend.test_package_accept(&[bitcoin::consensus::encode::serialize(&child)])?,
        PackageVerdict::Accepted,
        "the singleton child is evaluated successfully against the full in-mempool ancestry"
    );
    Ok(())
}

// --- a minimal regtest bitcoind harness (setup RPCs only) ------------------

struct Bitcoind {
    child: Child,
    datadir: PathBuf,
    rpc_addr: SocketAddr,
    auth: String,
    endpoint: String,
}

impl Bitcoind {
    fn start(datadir: PathBuf, rpc_port: u16) -> Result<Bitcoind, Error> {
        std::fs::create_dir_all(&datadir)?;
        let child = Command::new("bitcoind")
            .arg("-regtest")
            .arg(format!("-datadir={}", datadir.display()))
            .arg(format!("-rpcport={rpc_port}"))
            .args([
                "-listen=0",
                "-server=1",
                "-txindex=1",
                "-fallbackfee=0.0002",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("spawn bitcoind (is the dev shell active?): {e}"))?;
        let mut node = Bitcoind {
            child,
            datadir,
            rpc_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, rpc_port)),
            auth: String::new(),
            endpoint: "/".into(),
        };
        let cookie = node.datadir.join("regtest").join(".cookie");
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(60) {
            if let Ok(text) = std::fs::read_to_string(&cookie) {
                node.auth = BASE64_STANDARD.encode(text.trim());
                if node.call("getblockchaininfo", json!([])).is_ok() {
                    return Ok(node);
                }
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        Err("bitcoind did not become ready".into())
    }

    fn create_wallet(&mut self, name: &str) -> Result<(), Error> {
        self.call("createwallet", json!([name]))?;
        self.endpoint = format!("/wallet/{name}");
        Ok(())
    }

    fn call(&self, method: &str, params: Value) -> Result<Value, Error> {
        let request = json!({ "jsonrpc": "1.0", "id": "it", "method": method, "params": params });
        let body = post(
            self.rpc_addr,
            &self.endpoint,
            &request.to_string(),
            &self.auth,
        )?;
        let reply: Value =
            serde_json::from_str(&body).map_err(|e| format!("{method}: unparseable reply: {e}"))?;
        if !reply["error"].is_null() {
            return Err(format!("{method}: {}", reply["error"]).into());
        }
        Ok(reply["result"].clone())
    }

    fn call_str(&self, method: &str, params: Value) -> Result<String, Error> {
        Ok(self
            .call(method, params)?
            .as_str()
            .ok_or_else(|| format!("{method}: expected a string result"))?
            .to_string())
    }
}

impl Drop for Bitcoind {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn post(addr: SocketAddr, endpoint: &str, body: &str, auth: &str) -> Result<String, Error> {
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))?;
    stream.set_read_timeout(Some(Duration::from_secs(60)))?;
    let request = format!(
        "POST {endpoint} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\n\
         Authorization: Basic {auth}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes())?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw)?;
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("malformed HTTP response")?;
    Ok(String::from_utf8_lossy(&raw[split + 4..]).into_owned())
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new() -> Result<TempDir, Error> {
        let path = std::env::temp_dir().join(format!("vault-node-it-{}", std::process::id()));
        std::fs::create_dir_all(&path)?;
        Ok(TempDir { path })
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn free_port() -> Result<u16, Error> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    Ok(listener.local_addr()?.port())
}
