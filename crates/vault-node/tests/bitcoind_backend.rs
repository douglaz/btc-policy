//! Opt-in integration test for the bitcoind `ChainBackend` impl. Like the demo
//! e2e test it spawns a real regtest bitcoind, so it is `#[ignore]`d by default:
//!
//!   nix develop -c cargo test -p vault-node -- --ignored
//!
//! It exercises the two backend methods against live chain data: `broadcast`
//! pushes a fully-signed tx, and `spends_of` finds that spend of a watched
//! scriptPubKey. Setup RPCs (wallet, mining) use a tiny in-test JSON-RPC client;
//! the backend itself is the code under test.

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

use vault_node::chain::{BitcoindBackend, ChainBackend};

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

    // Build + sign a spend of that outpoint WITHOUT broadcasting it — the
    // backend does the broadcast.
    let dest = node.call_str("getnewaddress", json!([]))?;
    let raw = node.call_str(
        "createrawtransaction",
        json!([[{"txid": funding_txid, "vout": vout}], {dest: 0.999}]),
    )?;
    let signed = node.call("signrawtransactionwithwallet", json!([raw]))?;
    let signed_hex = signed["hex"].as_str().ok_or("signed hex")?;
    let signed_tx: Transaction = deserialize_hex(signed_hex)?;
    let raw_bytes = bitcoin::consensus::encode::serialize(&signed_tx);

    // --- broadcast ---
    let backend = BitcoindBackend::new(node.rpc_addr, node.auth.clone());
    let spend_txid = backend.broadcast(&raw_bytes)?;
    assert_eq!(
        spend_txid,
        signed_tx.compute_txid(),
        "broadcast returns the txid"
    );
    node.call("generatetoaddress", json!([1, miner]))?;

    // --- spends_of ---
    let spends = backend.spends_of(std::slice::from_ref(&watched_spk), 0)?;
    let seen = spends
        .iter()
        .find(|s| s.script == watched_spk)
        .expect("the watched script's spend must be seen");
    assert_eq!(seen.spend_txid, spend_txid);
    assert_eq!(seen.outpoint, funding_outpoint);
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
