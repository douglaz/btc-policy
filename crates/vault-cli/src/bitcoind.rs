//! Private regtest bitcoind for the demo: spawn, cookie-auth JSON-RPC,
//! kill + cleanup on drop.

use std::cell::Cell;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use bitcoin::base64::prelude::{Engine as _, BASE64_STANDARD};
use serde_json::{json, Value};

use crate::http::{self, Error};

const RPC_TIMEOUT: Duration = Duration::from_secs(60);
const STARTUP_TIMEOUT: Duration = Duration::from_secs(60);

/// bitcoind's `RPC_INVALID_ADDRESS_OR_KEY`: the code both `getmempoolentry` and
/// `getrawtransaction` return for a txid they do not know. The one JSON-RPC error
/// that means "absent" rather than "broken".
const RPC_INVALID_ADDRESS_OR_KEY: i64 = -5;

/// bitcoind's `RPC_INVALID_PARAMETER`, the code it also returns for "Scan already
/// in progress". Deliberately paired with a message match in
/// [`Bitcoind::scan_txoutset`]: `-8` covers genuinely malformed descriptors too,
/// and retrying those would spin until the deadline instead of failing fast.
const RPC_INVALID_PARAMETER: i64 = -8;

/// How long [`Bitcoind::scan_txoutset`] waits out another `scantxoutset`.
///
/// A UTXO-set scan on a regtest chain of a few hundred blocks is milliseconds, but
/// up to five watchtower drivers plus this process can queue on the one scan slot,
/// and a driver's scan spans several descriptors. Long enough to outlast that
/// queue, short enough to still fail rather than hang if a scan wedges.
const SCAN_CONTENTION_TIMEOUT: Duration = Duration::from_secs(30);

pub struct Bitcoind {
    child: Child,
    datadir: PathBuf,
    rpc_addr: SocketAddr,
    /// base64("__cookie__:<password>") once the cookie file appears.
    auth: String,
    /// JSON-RPC endpoint path; "/wallet/<name>" after create_wallet.
    endpoint: String,
    /// Every `sendrawtransaction` this process has issued.
    ///
    /// The coordinator is a **pure relay**: under Model B the NODES combine and
    /// broadcast, and vault-cli must never push a vault transaction — if it could,
    /// a post-wrench coordinator could too. [`Bitcoind::broadcasts`] is what the
    /// demo asserts on, so "the coordinator does not broadcast" is checked against
    /// what this process actually did at runtime, not against a reading of the
    /// source. It counts every call, including the demo's own chain setup, so the
    /// assertion can only pass at zero.
    sendrawtransaction_calls: Cell<usize>,
}

impl Bitcoind {
    /// Spawn bitcoind on a private regtest chain and wait until RPC answers.
    pub fn start(datadir: PathBuf, rpc_port: u16) -> Result<Bitcoind, Error> {
        Self::start_with_args(datadir, rpc_port, &[])
    }

    /// Spawn bitcoind with scenario-specific policy arguments in addition to the
    /// shared regtest configuration.
    pub fn start_with_args(
        datadir: PathBuf,
        rpc_port: u16,
        extra_args: &[&str],
    ) -> Result<Bitcoind, Error> {
        std::fs::create_dir_all(&datadir)?;
        let mut command = Command::new("bitcoind");
        command
            .arg("-regtest")
            .arg(format!("-datadir={}", datadir.display()))
            .arg(format!("-rpcport={rpc_port}"))
            .arg("-listen=0")
            .arg("-server=1")
            .arg("-txindex=1")
            .arg("-fallbackfee=0.0001")
            .args(extra_args)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let child = command
            .spawn()
            .map_err(|e| format!("cannot spawn bitcoind (is the dev shell active?): {e}"))?;
        let mut bitcoind = Bitcoind {
            child,
            datadir,
            rpc_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, rpc_port)),
            auth: String::new(),
            endpoint: "/".into(),
            sendrawtransaction_calls: Cell::new(0),
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

    /// The JSON-RPC socket address, so each node's watchtower can scan this same
    /// regtest bitcoind (V0-6b).
    pub fn rpc_addr(&self) -> SocketAddr {
        self.rpc_addr
    }

    /// base64 of the regtest cookie (`__cookie__:<password>`), populated once
    /// `start` has read the cookie file. Handed to each node's watchtower config.
    pub fn auth(&self) -> &str {
        &self.auth
    }

    /// How many times this process has called `sendrawtransaction`. The demo
    /// asserts this is ZERO: the nodes broadcast, never the coordinator.
    pub fn broadcasts(&self) -> usize {
        self.sendrawtransaction_calls.get()
    }

    pub fn call(&self, method: &str, params: Value) -> Result<Value, Error> {
        match self.call_inner(method, params)? {
            Ok(result) => Ok(result),
            Err(error) => Err(format!("bitcoind {method}: {error}").into()),
        }
    }

    /// A `call` whose "no such transaction" answer is an ordinary ABSENCE rather
    /// than a failure: `Ok(None)` for exactly [`RPC_INVALID_ADDRESS_OR_KEY`], `Err`
    /// for everything else.
    ///
    /// bitcoind reports "this txid is not in the mempool" and "no such transaction"
    /// as JSON-RPC *errors*, so a lookup written as `call(..).is_ok()` cannot tell
    /// absent from broken — a dead daemon, an auth failure, or a timeout all read
    /// as "the transaction is not there". That defaulting is exactly what the
    /// callers must never do: they turn a `false` here into "nothing was stolen"
    /// and "the coerced spend never broadcast". So the error code is inspected
    /// before it is flattened into a string, and only the absence code is a `None`.
    pub fn call_optional(&self, method: &str, params: Value) -> Result<Option<Value>, Error> {
        match self.call_inner(method, params)? {
            Ok(result) => Ok(Some(result)),
            Err(error) => {
                if error.get("code").and_then(Value::as_i64) == Some(RPC_INVALID_ADDRESS_OR_KEY) {
                    Ok(None)
                } else {
                    Err(format!("bitcoind {method}: {error}").into())
                }
            }
        }
    }

    /// `scantxoutset "start"`, retried while bitcoind answers "Scan already in
    /// progress".
    ///
    /// Core serializes the UTXO-set scan PROCESS-WIDE, and every scenario here runs
    /// against one regtest daemon that three to five live watchtower drivers are
    /// also scanning (`vault-node/src/chain.rs`). Whichever caller loses the race
    /// gets `-8`, which [`Bitcoind::call`] flattens into an ordinary `Err`. That
    /// matters far more than a lost scan: the harness's callers are the no-theft
    /// ground truth, so an RPC collision propagating out of `assert_no_theft` is
    /// reported as *a duress safety assertion did not hold* — a red launch gate
    /// naming the wrong cause. Contention is not an answer about where the funds
    /// are, so it is waited out rather than surfaced.
    ///
    /// Only the contention error is retried. Every other error, including a `-8`
    /// from a descriptor this harness built wrong, still fails immediately.
    pub fn scan_txoutset(&self, descriptors: Value) -> Result<Value, Error> {
        let deadline = Instant::now() + SCAN_CONTENTION_TIMEOUT;
        loop {
            let error = match self.call_inner("scantxoutset", json!(["start", descriptors]))? {
                Ok(result) => return Ok(result),
                Err(error) => error,
            };
            let contended = error.get("code").and_then(Value::as_i64)
                == Some(RPC_INVALID_PARAMETER)
                && error
                    .get("message")
                    .and_then(Value::as_str)
                    .is_some_and(|message| message.contains("Scan already in progress"));
            if !contended || Instant::now() >= deadline {
                return Err(format!("bitcoind scantxoutset: {error}").into());
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    /// One JSON-RPC round trip. The outer `Result` is the TRANSPORT (a broken or
    /// unparseable exchange); the inner one is bitcoind's own structured `error`
    /// object, kept intact so [`Bitcoind::call_optional`] can read its code.
    fn call_inner(&self, method: &str, params: Value) -> Result<Result<Value, Value>, Error> {
        if method == "sendrawtransaction" {
            self.sendrawtransaction_calls
                .set(self.sendrawtransaction_calls.get() + 1);
        }
        let request = json!({
            "jsonrpc": "1.0",
            "id": "first-light",
            "method": method,
            "params": params,
        });
        let request_body = request.to_string();
        let response = http::post_json(
            self.rpc_addr,
            &self.endpoint,
            request_body.as_bytes(),
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
            return Ok(Err(error.clone()));
        }
        Ok(Ok(reply["result"].clone()))
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
