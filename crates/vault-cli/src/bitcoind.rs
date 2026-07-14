//! Private regtest bitcoind for the demo: spawn, cookie-auth JSON-RPC,
//! kill + cleanup on drop.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use bitcoin::base64::prelude::{Engine as _, BASE64_STANDARD};
use serde_json::{json, Value};

use crate::http::{self, Error};

const RPC_TIMEOUT: Duration = Duration::from_secs(60);
const STARTUP_TIMEOUT: Duration = Duration::from_secs(60);

pub struct Bitcoind {
    child: Child,
    datadir: PathBuf,
    rpc_addr: SocketAddr,
    /// base64("__cookie__:<password>") once the cookie file appears.
    auth: String,
    /// JSON-RPC endpoint path; "/wallet/<name>" after create_wallet.
    endpoint: String,
}

impl Bitcoind {
    /// Spawn bitcoind on a private regtest chain and wait until RPC answers.
    pub fn start(datadir: PathBuf, rpc_port: u16) -> Result<Bitcoind, Error> {
        std::fs::create_dir_all(&datadir)?;
        let child = Command::new("bitcoind")
            .arg("-regtest")
            .arg(format!("-datadir={}", datadir.display()))
            .arg(format!("-rpcport={rpc_port}"))
            .arg("-listen=0")
            .arg("-server=1")
            .arg("-txindex=1")
            .arg("-fallbackfee=0.0001")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("cannot spawn bitcoind (is the dev shell active?): {e}"))?;
        let mut bitcoind = Bitcoind {
            child,
            datadir,
            rpc_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, rpc_port)),
            auth: String::new(),
            endpoint: "/".into(),
        };
        bitcoind.wait_ready()?;
        Ok(bitcoind)
    }

    fn wait_ready(&mut self) -> Result<(), Error> {
        let cookie_path = self.datadir.join("regtest").join(".cookie");
        let started = Instant::now();
        while started.elapsed() < STARTUP_TIMEOUT {
            if let Some(status) = self.child.try_wait()? {
                return Err(format!("bitcoind exited during startup: {status}").into());
            }
            if let Ok(cookie) = std::fs::read_to_string(&cookie_path) {
                self.auth = BASE64_STANDARD.encode(cookie.trim());
                if self.call("getblockchaininfo", json!([])).is_ok() {
                    return Ok(());
                }
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        Err("bitcoind did not become ready in time".into())
    }

    pub fn create_wallet(&mut self, name: &str) -> Result<(), Error> {
        self.call("createwallet", json!([name]))?;
        self.endpoint = format!("/wallet/{name}");
        Ok(())
    }

    pub fn call(&self, method: &str, params: Value) -> Result<Value, Error> {
        let request = json!({
            "jsonrpc": "1.0",
            "id": "first-light",
            "method": method,
            "params": params,
        });
        let response = http::post_json(
            self.rpc_addr,
            &self.endpoint,
            &request.to_string(),
            Some(&self.auth),
            RPC_TIMEOUT,
        )?;
        let reply: Value = serde_json::from_str(&response.body).map_err(|e| {
            format!(
                "bitcoind {method}: HTTP {} with unparseable body: {e}",
                response.status
            )
        })?;
        let error = &reply["error"];
        if !error.is_null() {
            return Err(format!("bitcoind {method}: {error}").into());
        }
        Ok(reply["result"].clone())
    }

    /// A `call` result that must be a string (txid, address, hex...).
    pub fn call_str(&self, method: &str, params: Value) -> Result<String, Error> {
        let result = self.call(method, params)?;
        result
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| format!("bitcoind {method}: expected a string result").into())
    }
}

impl Drop for Bitcoind {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
