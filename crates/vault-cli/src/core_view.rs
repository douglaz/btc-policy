//! The closed read-only Core capability the stage-1 composer reads through (bead
//! btc-policy-m3a-core-view-inventory-rha).
//!
//! [`CoreView`] is a TYPED seam: eight reads and nothing else — no public or generic
//! method string, no batch, no wallet endpoint, no broadcast, no mutation, no cache, no
//! async task and no background work. [`CoreRpc`] is the one concrete adapter, and every
//! one of its methods funnels through [`CoreRpc::rpc`], the single place a method name
//! exists and the single place a credential is materialized. The adapter stores the
//! cookie PATH; each call reads it through child A's no-follow/regular/owner-only
//! [`crate::sealed::read_secret`], encodes it, and drops it before returning. There is no
//! username/password argument, environment source or adjacent default.
//!
//! **DORMANT, UNBOUNDED-AT-REST and LOSSY-AT-REST.** The funnel posts through
//! [`crate::http`], whose read-to-close carries no whole-response cap, whose decode
//! REPLACES invalid UTF-8 bytes, and which keeps TWO UNWIPED copies of the encoded
//! credential that every allocation on this side of the call holds in [`Zeroizing`]:
//! `http::post_head`'s own `auth_header` and the request head it interpolates that
//! header into (`http.rs:32-44`). This module owns only the LOGICAL envelope over already
//! decoded text; the byte-level deadline, cap, framing and strict decoding belong to
//! `btc-policy-http-bounded-ingress-response-qhe`, which replaces that one call site.
//! Nothing dispatches here until it does.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use bitcoin::base64::prelude::{Engine as _, BASE64_STANDARD};
use bitcoin::consensus::encode::deserialize_hex;
use bitcoin::{Amount, BlockHash, OutPoint, ScriptBuf, Transaction, Txid};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::http::{self, Error};

/// The only endpoint this adapter speaks: Core's ROOT JSON-RPC path. `/wallet/<name>`
/// is a wallet capability the composer must not hold.
const ROOT_PATH: &str = "/";

/// The fixed id every request carries and every reply must echo back.
const RPC_ID: &str = "btc-vault-core-view";

/// The socket timeout handed to the legacy transport, sized for a full-chain
/// `scantxoutset`. It bounds one READ, not the whole exchange: a peer that answers a byte
/// at a time holds the call open, which is part of what UNBOUNDED-AT-REST means above. The
/// real per-exchange deadline arrives with qhe, along with the call site it bounds.
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(600);

/// bitcoind's `RPC_INVALID_ADDRESS_OR_KEY`: block-qualified `getrawtransaction` reports a
/// txid ABSENT FROM THAT BLOCK with it; missing block DATA is a different, terminal code.
const RPC_INVALID_ADDRESS_OR_KEY: i64 = -5;

/// bitcoind's `RPC_INVALID_PARAMETER`: `getblockhash` reports a height past its chain
/// with it. `scantxoutset` shares the code for contention, which is why absence is
/// declared PER CALL below rather than globally.
const RPC_INVALID_PARAMETER: i64 = -8;

/// What "absent" means for one exchange. A missing answer is never a generic success
/// substitute here, so each call site states which single form it accepts.
enum Absent {
    /// Neither a null result nor any error code is an answer.
    Never,
    /// `result: null` IS the answer — `gettxout` alone.
    NullResult,
    /// This one JSON-RPC error code is the answer.
    Code(i64),
}

/// One `getblockchaininfo`.
pub(crate) struct ChainInfo {
    /// The object the SHARED public-Signet-aware validator consumes
    /// ([`vault_node::chain::verify_chain_identity`]), so this crate adds no second
    /// chain-identity implementation.
    pub(crate) identity: Value,
    pub(crate) initial_block_download: bool,
    pub(crate) best_block: BlockHash,
}

/// One `scantxoutset` record. The confirmed height is retained because it is what
/// resolves the full parent without `-txindex`.
pub(crate) struct ScanCoin {
    pub(crate) outpoint: OutPoint,
    pub(crate) value: Amount,
    pub(crate) script: ScriptBuf,
    pub(crate) height: u32,
}

/// A completed `scantxoutset`, bound to the tip it scanned.
pub(crate) struct Scan {
    pub(crate) best_block: BlockHash,
    pub(crate) coins: Vec<ScanCoin>,
}

/// A NON-NULL `gettxout`, with the three facts a bracket cross-checks and the tip it
/// was answered at.
pub(crate) struct TxOutView {
    pub(crate) best_block: BlockHash,
    pub(crate) confirmations: u64,
    pub(crate) value: Amount,
    pub(crate) script: ScriptBuf,
    pub(crate) coinbase: bool,
}

/// Core's two mandatory relay floors, already converted to integer sat/kvB.
pub(crate) struct Floors {
    pub(crate) incremental_relay: u64,
    pub(crate) mempool_min: u64,
}

/// The closed eight-method read-only capability. Every method is a typed READ.
pub(crate) trait CoreView {
    fn chain_info(&self) -> Result<ChainInfo, Error>;
    fn best_block_hash(&self) -> Result<BlockHash, Error>;
    fn scan_vault_script(&self, script: &ScriptBuf) -> Result<Scan, Error>;
    /// `None` is Core's own null result: the outpoint is not in the UTXO set.
    fn txout(&self, outpoint: OutPoint) -> Result<Option<TxOutView>, Error>;
    /// `None` is a height this chain does not have.
    fn block_hash(&self, height: u32) -> Result<Option<BlockHash>, Error>;
    /// `None` is Core's own "not in that block". Missing block DATA is not this absence.
    fn block_transaction(&self, txid: Txid, block: BlockHash)
        -> Result<Option<Transaction>, Error>;
    /// Integer sat/kvB, the same unit as [`Floors`], which the caller maxes it against.
    /// `None` is Core's honest "no estimate", never a failure substitute.
    fn fee_estimate(&self) -> Result<Option<u64>, Error>;
    fn fee_floors(&self) -> Result<Floors, Error>;
}

/// The one concrete adapter: loopback, root path, per-call cookie.
pub(crate) struct CoreRpc {
    addr: SocketAddr,
    /// The cookie's PATH, never its contents.
    cookie: PathBuf,
}

impl CoreRpc {
    /// Loopback only, and the credential by explicitly named path.
    pub(crate) fn new(addr: SocketAddr, cookie: PathBuf) -> Result<Self, Error> {
        if !addr.ip().is_loopback() {
            return Err(format!("core RPC address {addr} is not loopback").into());
        }
        Ok(CoreRpc { addr, cookie })
    }

    /// THE funnel. Every method above names its RPC here and nowhere else, and the
    /// credential exists only for this exchange.
    fn rpc(&self, method: &str, params: Value, absent: Absent) -> Result<Value, Error> {
        let read = crate::sealed::read_secret(&self.cookie)?;
        let credential = Zeroizing::new(read.trim().to_string());
        // Core writes its cookie as ONE line, so a CR or LF in it means the FILE is
        // malformed. It could not split this request head: the next line base64-encodes
        // the credential, so no raw byte of it ever reaches a header.
        if credential.contains(['\r', '\n']) {
            return Err("the Core cookie is not CR/LF-free, so it is malformed".into());
        }
        let auth = Zeroizing::new(BASE64_STANDARD.encode(credential.as_bytes()));
        let body = json!({"jsonrpc": "1.0", "id": RPC_ID, "method": method, "params": params});
        let sent = http::post_json(
            self.addr,
            ROOT_PATH,
            body.to_string().as_bytes(),
            Some(auth.as_str()),
            EXCHANGE_TIMEOUT,
        )
        // Which TYPED exchange exhausted its bound, not merely which socket did.
        .map_err(|e| format!("core {method}: {e}"))?;
        reply(&sent.body, sent.status, method, absent)
    }
}

/// Core's reply over ALREADY DECODED text: exactly one JSON value with no trailing junk,
/// this request's fixed id echoed, and result/error/status coherent. Absence surfaces as
/// [`Value::Null`], only in the one form the call site declared. No credential is a
/// PARAMETER here, and a refusal carries Core's numeric code, never its reflectable text.
fn reply(text: &str, status: u16, method: &str, absent: Absent) -> Result<Value, Error> {
    let refuse =
        |detail: String| -> Error { format!("core {method} (HTTP {status}): {detail}").into() };
    let mut values = serde_json::Deserializer::from_str(text).into_iter::<Value>();
    let Some(Ok(reply)) = values.next() else {
        return Err(refuse("the response body is not one JSON value".into()));
    };
    if values.next().is_some() {
        return Err(refuse("the response body carries a second value".into()));
    }
    if reply.get("id").and_then(Value::as_str) != Some(RPC_ID) {
        return Err(refuse("the reply does not echo this request's id".into()));
    }
    let error = reply.get("error").filter(|error| !error.is_null());
    let result = reply.get("result").filter(|result| !result.is_null());
    // Both declared absences are STATUS-coherent forms: Core carries `-5`/`-8` on an
    // error status, and `gettxout`'s null is a `result` member that is PRESENT and null.
    // A coded error under a 200, or no `result` member at all, is an incoherent envelope.
    let coded = error.and_then(|e| e.get("code")).and_then(Value::as_i64);
    let has_result = reply.get("result").is_some();
    match (error, result) {
        (Some(_), Some(_)) => Err(refuse(
            "the reply carries both a result and an error".into(),
        )),
        (Some(_), None) => match absent {
            Absent::Code(code) if status != 200 && coded == Some(code) => Ok(Value::Null),
            _ => Err(refuse(format!("refused: code {coded:?}"))),
        },
        (None, Some(_)) if status != 200 => {
            Err(refuse("a result arrived with a non-200 status".into()))
        }
        (None, Some(result)) => Ok(result.clone()),
        (None, None) => match absent {
            Absent::NullResult if status == 200 && has_result => Ok(Value::Null),
            _ => Err(refuse(
                "the reply carries neither a result nor an error".into(),
            )),
        },
    }
}

fn missing(what: &str) -> Error {
    format!("core reply: {what}").into()
}

/// One string field, parsed by the type that owns its encoding.
fn parsed<T: FromStr>(value: Option<&Value>, what: &str) -> Result<T, Error>
where
    T::Err: std::fmt::Display,
{
    let text = value
        .and_then(Value::as_str)
        .ok_or_else(|| missing(&format!("{what} is not a string")))?;
    T::from_str(text).map_err(|e| missing(&format!("{what} does not parse: {e}")))
}

/// One hex-encoded scriptPubKey.
fn as_script(value: Option<&Value>, what: &str) -> Result<ScriptBuf, Error> {
    let hex = value
        .and_then(Value::as_str)
        .ok_or_else(|| missing(&format!("{what} is not a string")))?;
    ScriptBuf::from_hex(hex).map_err(|e| missing(&format!("{what} does not parse: {e}")))
}

fn as_u64(value: Option<&Value>, what: &str) -> Result<u64, Error> {
    value
        .and_then(Value::as_u64)
        .ok_or_else(|| missing(&format!("{what} is not a non-negative integer")))
}

/// A Core BTC number through the repository's CHECKED conversion — negative, over-precise
/// and overflowing values fail, never hand-multiplied. Residual: serde_json narrows the
/// literal to `f64` first, so what is checked is the double IT produced, not the spelling.
fn as_btc(value: Option<&Value>, what: &str) -> Result<Amount, Error> {
    let btc = value
        .and_then(Value::as_f64)
        .ok_or_else(|| missing(&format!("{what} is not a number")))?;
    Amount::from_btc(btc).map_err(|e| missing(&format!("{what} is not a usable amount: {e}")))
}

impl CoreView for CoreRpc {
    fn chain_info(&self) -> Result<ChainInfo, Error> {
        let info = self.rpc("getblockchaininfo", json!([]), Absent::Never)?;
        let ibd = info
            .get("initialblockdownload")
            .and_then(Value::as_bool)
            .ok_or_else(|| missing("getblockchaininfo has no boolean initialblockdownload"))?;
        let best_block = parsed(info.get("bestblockhash"), "getblockchaininfo bestblockhash")?;
        Ok(ChainInfo {
            identity: info,
            initial_block_download: ibd,
            best_block,
        })
    }

    fn best_block_hash(&self) -> Result<BlockHash, Error> {
        let hash = self.rpc("getbestblockhash", json!([]), Absent::Never)?;
        parsed(Some(&hash), "getbestblockhash")
    }

    fn scan_vault_script(&self, script: &ScriptBuf) -> Result<Scan, Error> {
        let params = json!(["start", [format!("raw({script:x})")]]);
        let scan = self.rpc("scantxoutset", params, Absent::Never)?;
        if scan.get("success").and_then(Value::as_bool) != Some(true) {
            return Err(missing("scantxoutset did not report success"));
        }
        let best_block = parsed(scan.get("bestblock"), "scantxoutset bestblock")?;
        let records = scan
            .get("unspents")
            .and_then(Value::as_array)
            .ok_or_else(|| missing("scantxoutset has no unspents array"))?;
        let mut coins = Vec::with_capacity(records.len());
        for record in records {
            let height = as_u64(record.get("height"), "scantxoutset height")?;
            coins.push(ScanCoin {
                outpoint: OutPoint {
                    txid: parsed(record.get("txid"), "scantxoutset txid")?,
                    vout: u32::try_from(as_u64(record.get("vout"), "scantxoutset vout")?)
                        .map_err(|_| missing("scantxoutset vout does not fit u32"))?,
                },
                value: as_btc(record.get("amount"), "scantxoutset amount")?,
                script: as_script(record.get("scriptPubKey"), "scantxoutset scriptPubKey")?,
                height: u32::try_from(height)
                    .map_err(|_| missing("scantxoutset height does not fit u32"))?,
            });
        }
        Ok(Scan { best_block, coins })
    }

    fn txout(&self, outpoint: OutPoint) -> Result<Option<TxOutView>, Error> {
        let params = json!([outpoint.txid.to_string(), outpoint.vout, true]);
        let view = self.rpc("gettxout", params, Absent::NullResult)?;
        if view.is_null() {
            return Ok(None);
        }
        Ok(Some(TxOutView {
            best_block: parsed(view.get("bestblock"), "gettxout bestblock")?,
            confirmations: as_u64(view.get("confirmations"), "gettxout confirmations")?,
            value: as_btc(view.get("value"), "gettxout value")?,
            script: as_script(
                view.get("scriptPubKey").and_then(|spk| spk.get("hex")),
                "gettxout scriptPubKey.hex",
            )?,
            coinbase: view
                .get("coinbase")
                .and_then(Value::as_bool)
                .ok_or_else(|| missing("gettxout has no boolean coinbase"))?,
        }))
    }

    fn block_hash(&self, height: u32) -> Result<Option<BlockHash>, Error> {
        let absent = Absent::Code(RPC_INVALID_PARAMETER);
        let hash = self.rpc("getblockhash", json!([height]), absent)?;
        match hash.is_null() {
            true => Ok(None),
            false => Ok(Some(parsed(Some(&hash), "getblockhash")?)),
        }
    }

    fn block_transaction(
        &self,
        txid: Txid,
        block: BlockHash,
    ) -> Result<Option<Transaction>, Error> {
        // BLOCK-QUALIFIED, always: this is what makes `-txindex` unnecessary.
        let params = json!([txid.to_string(), false, block.to_string()]);
        let raw = self.rpc(
            "getrawtransaction",
            params,
            Absent::Code(RPC_INVALID_ADDRESS_OR_KEY),
        )?;
        if raw.is_null() {
            return Ok(None);
        }
        let hex = raw
            .as_str()
            .ok_or_else(|| missing("getrawtransaction is not a hex string"))?;
        let tx = deserialize_hex::<Transaction>(hex)
            .map_err(|e| missing(&format!("getrawtransaction does not decode: {e}")))?;
        Ok(Some(tx))
    }

    fn fee_estimate(&self) -> Result<Option<u64>, Error> {
        let params = json!([6, "CONSERVATIVE"]);
        let estimate = self.rpc("estimatesmartfee", params, Absent::Never)?;
        // The RESULT ITSELF must be an object. An array, string, number or boolean is a
        // malformed reply and terminal, never "no estimate" — `Value::get` answers `None`
        // for every one of them, so without this gate they would all read as the honest
        // absence and price the pair off the node floors alone.
        let estimate = estimate
            .as_object()
            .ok_or_else(|| missing("estimatesmartfee is not an object"))?;
        // ONLY an absent or null `feerate` MEMBER of that object is "no estimate"; a
        // present malformed one fails through [`as_btc`], and so does any error above.
        match estimate.get("feerate").filter(|rate| !rate.is_null()) {
            None => Ok(None),
            Some(rate) => Ok(Some(
                as_btc(Some(rate), "estimatesmartfee feerate")?.to_sat(),
            )),
        }
    }

    fn fee_floors(&self) -> Result<Floors, Error> {
        let info = self.rpc("getmempoolinfo", json!([]), Absent::Never)?;
        Ok(Floors {
            incremental_relay: as_btc(
                info.get("incrementalrelayfee"),
                "getmempoolinfo incrementalrelayfee",
            )?
            .to_sat(),
            mempool_min: as_btc(info.get("mempoolminfee"), "getmempoolinfo mempoolminfee")?
                .to_sat(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::consensus::encode::serialize_hex;
    use bitcoin::transaction::Version;
    use bitcoin::{Sequence, TxIn, TxOut, Witness};
    use std::io::{Read as _, Write as _};
    use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::sync::{Arc, Mutex};

    /// The cookie every fixture writes. Non-obvious, so a diagnostic that leaked it
    /// could not match by accident.
    const COOKIE: &str = "__cookie__:5f3aQ-not-a-real-password-9b2";

    /// One WHOLE request off a TCP stream: headers, then exactly the body length they
    /// declare. A single `read` is allowed to return a prefix even of a small loopback
    /// write, and [`Wire::methods`] parses the body as JSON — so reading once would make
    /// this fixture pass by luck rather than by framing.
    fn whole_request(stream: &mut std::net::TcpStream) -> String {
        let mut raw = Vec::new();
        let mut byte = [0u8; 1];
        let head = loop {
            match stream.read(&mut byte) {
                Ok(1) => raw.push(byte[0]),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                _ => panic!("the request head never finished: {raw:?}"),
            }
            if raw.ends_with(b"\r\n\r\n") {
                break String::from_utf8_lossy(&raw).into_owned();
            }
        };
        let len: usize = head
            .lines()
            .find_map(|line| line.strip_prefix("Content-Length: "))
            .expect("a declared Content-Length")
            .trim()
            .parse()
            .expect("a numeric Content-Length");
        let mut body = vec![0u8; len];
        stream.read_exact(&mut body).expect("the declared body");
        raw.extend_from_slice(&body);
        String::from_utf8_lossy(&raw).into_owned()
    }

    /// A loopback stand-in for Core that RECORDS each raw request and answers from a
    /// script, so the adapter's own bytes — path, auth header, method, id, params —
    /// are read off the wire rather than off the source.
    struct Wire {
        addr: SocketAddr,
        requests: Arc<Mutex<Vec<String>>>,
    }

    impl Wire {
        fn serving(replies: Vec<(u16, String)>) -> Wire {
            let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
            let addr = listener.local_addr().expect("addr");
            let requests = Arc::new(Mutex::new(Vec::new()));
            let recorded = Arc::clone(&requests);
            std::thread::spawn(move || {
                for (status, body) in replies {
                    let Ok((mut stream, _)) = listener.accept() else {
                        return;
                    };
                    recorded
                        .lock()
                        .expect("lock")
                        .push(whole_request(&mut stream));
                    let head = format!(
                        "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(head.as_bytes());
                    let _ = stream.write_all(body.as_bytes());
                }
            });
            Wire { addr, requests }
        }

        fn seen(&self) -> Vec<String> {
            self.requests.lock().expect("lock").clone()
        }

        /// The `params` of ONE recorded request, parsed off its body the way
        /// [`Wire::methods`] parses the rest of it.
        fn params(&self, index: usize) -> Value {
            let raw = self.seen()[index].clone();
            let body = raw.split("\r\n\r\n").nth(1).unwrap_or_default().to_string();
            let request: Value = serde_json::from_str(&body).expect("a JSON request");
            request["params"].clone()
        }

        /// The `method` field of each recorded request, in order.
        fn methods(&self) -> Vec<String> {
            self.seen()
                .iter()
                .map(|raw| {
                    let body = raw.split("\r\n\r\n").nth(1).unwrap_or_default().to_string();
                    let request: Value = serde_json::from_str(&body).expect("a JSON request");
                    assert_eq!(request["id"], json!(RPC_ID), "every request carries the id");
                    assert!(raw.starts_with("POST / HTTP/1.1\r\n"), "root path: {raw}");
                    request["method"].as_str().expect("a method").to_string()
                })
                .collect()
        }
    }

    /// An owner-only cookie file, as `read_secret` requires.
    fn cookie_file(dir: &Path, body: &str) -> PathBuf {
        let path = dir.join("core.cookie");
        std::fs::write(&path, body).expect("write");
        let mode = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&path, mode).expect("mode");
        path
    }

    fn hash(byte: u8) -> BlockHash {
        BlockHash::from_str(&format!("{byte:02x}").repeat(32)).expect("a block hash")
    }

    fn script() -> ScriptBuf {
        ScriptBuf::from_hex(&format!("0014{}", "11".repeat(20))).expect("a script")
    }

    /// A previous transaction the adapter can decode, and the txid it hashes to.
    fn parent() -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000_000),
                script_pubkey: script(),
            }],
        }
    }

    /// One successful reply body carrying `result`.
    fn ok(result: Value) -> (u16, String) {
        (
            200,
            json!({"result": result, "error": null, "id": RPC_ID}).to_string(),
        )
    }

    /// The eight canned replies, in the order the eight reads are issued below.
    fn eight() -> Vec<(u16, String)> {
        let tx = parent();
        vec![
            ok(json!({
                "chain": "regtest",
                "initialblockdownload": false,
                "bestblockhash": hash(0xaa).to_string(),
            })),
            ok(json!(hash(0xaa).to_string())),
            ok(json!({
                "success": true,
                "bestblock": hash(0xaa).to_string(),
                "unspents": [{
                    "txid": tx.compute_txid().to_string(),
                    "vout": 0,
                    "scriptPubKey": format!("{:x}", script()),
                    "amount": 0.5,
                    "height": 3,
                }],
            })),
            ok(json!({
                "bestblock": hash(0xaa).to_string(),
                "confirmations": 7,
                "value": 0.5,
                "scriptPubKey": {"hex": format!("{:x}", script())},
                "coinbase": false,
            })),
            ok(json!(hash(0xbb).to_string())),
            ok(json!(serialize_hex(&tx))),
            ok(json!({"feerate": 0.00002, "blocks": 6})),
            ok(json!({"incrementalrelayfee": 0.00001, "mempoolminfee": 0.000015})),
        ]
    }

    /// The refusal `what` must earn, over a success type that does not print itself —
    /// `Floors`, `CoreRpc` and the frozen authorization all deliberately lack `Debug`.
    fn refusal<T>(result: Result<T, Error>, what: &str) -> String {
        match result {
            Ok(_) => panic!("{what} must be refused"),
            Err(error) => error.to_string(),
        }
    }

    fn adapter(wire: &Wire, cookie: &Path) -> CoreRpc {
        CoreRpc::new(wire.addr, cookie.to_path_buf()).expect("a loopback adapter")
    }

    /// 1. The capability is CLOSED: driving every method of the seam issues exactly
    ///    eight named reads, each a POST to the ROOT path under a Basic auth header
    ///    carrying the cookie, and each answer arrives typed. No wallet path, no
    ///    method string a caller chose, and nothing that could mutate or broadcast.
    #[test]
    fn the_seam_issues_exactly_the_eight_closed_reads_at_the_root_path_under_basic_auth() {
        let temp = crate::fed::TempDir::new("core-view").expect("temp dir");
        let cookie = cookie_file(&temp.path, COOKIE);
        let wire = Wire::serving(eight());
        let core = adapter(&wire, &cookie);
        let tx = parent();
        let outpoint = OutPoint {
            txid: tx.compute_txid(),
            vout: 0,
        };

        let info = core.chain_info().expect("getblockchaininfo");
        assert!(!info.initial_block_download);
        assert_eq!(info.best_block, hash(0xaa));
        assert_eq!(info.identity["chain"], json!("regtest"));
        assert_eq!(core.best_block_hash().expect("tip"), hash(0xaa));
        let scan = core.scan_vault_script(&script()).expect("scantxoutset");
        assert_eq!(scan.best_block, hash(0xaa));
        assert_eq!(scan.coins.len(), 1);
        assert_eq!(scan.coins[0].outpoint, outpoint);
        assert_eq!(scan.coins[0].value, Amount::from_sat(50_000_000));
        assert_eq!(scan.coins[0].script, script());
        assert_eq!(scan.coins[0].height, 3);
        let view = core.txout(outpoint).expect("gettxout").expect("non-null");
        assert_eq!(view.best_block, hash(0xaa));
        assert_eq!((view.confirmations, view.coinbase), (7, false));
        assert_eq!(view.value, Amount::from_sat(50_000_000));
        assert_eq!(view.script, script());
        assert_eq!(core.block_hash(3).expect("getblockhash"), Some(hash(0xbb)));
        let full = core
            .block_transaction(tx.compute_txid(), hash(0xbb))
            .expect("getrawtransaction")
            .expect("present");
        assert_eq!(full, tx);
        // 0.00002 BTC/kvB is 2000 sat/kvB, through the checked conversion.
        assert_eq!(core.fee_estimate().expect("estimatesmartfee"), Some(2_000));
        let floors = core.fee_floors().expect("getmempoolinfo");
        assert_eq!(
            (floors.incremental_relay, floors.mempool_min),
            (1_000, 1_500)
        );

        assert_eq!(
            wire.methods(),
            [
                "getblockchaininfo",
                "getbestblockhash",
                "scantxoutset",
                "gettxout",
                "getblockhash",
                "getrawtransaction",
                "estimatesmartfee",
                "getmempoolinfo",
            ]
        );
        let auth = BASE64_STANDARD.encode(COOKIE.as_bytes());
        for raw in wire.seen() {
            assert!(
                raw.contains(&format!("Authorization: Basic {auth}\r\n")),
                "every exchange authenticates: {raw}"
            );
            for banned in ["/wallet/", "sendrawtransaction", "importdescriptors"] {
                assert!(!raw.contains(banned), "{banned} reached the wire: {raw}");
            }
        }
        // The block-qualified form is what makes `-txindex` unnecessary: the third
        // positional argument is the block the scan already named.
        let raw = &wire.seen()[5];
        assert!(raw.contains(&hash(0xbb).to_string()), "{raw}");
        // `gettxout`'s own third positional argument is `include_mempool`, and it is the
        // ONLY reason a vault coin spent by an unconfirmed transaction reads back null
        // and refuses the whole inventory rather than being composed over as if unspent.
        // No inventory class can observe it — [`CoreView::txout`] takes an `OutPoint` and
        // nothing else, so the flag never reaches that seam — which is why it is read off
        // the wire here.
        assert_eq!(
            wire.params(3),
            json!([outpoint.txid.to_string(), 0, true]),
            "gettxout must ask WITH the mempool: {}",
            wire.seen()[3]
        );
    }

    /// 2. Every LOGICAL envelope defect over already decoded text is refused. Each row
    ///    is one deviation from the row above it, and the first row is the control.
    #[test]
    fn every_logical_envelope_defect_over_decoded_text_is_refused() {
        let id = RPC_ID;
        let good = json!({"result": 7, "error": null, "id": id}).to_string();
        assert_eq!(
            reply(&good, 200, "gettxout", Absent::Never).expect("the control"),
            json!(7)
        );
        let rows: [(&str, String, u16, &str); 8] = [
            (
                "not JSON at all",
                "not json".into(),
                200,
                "not one JSON value",
            ),
            ("an empty body", String::new(), 200, "not one JSON value"),
            (
                "a second value after the first",
                format!("{good}{good}"),
                200,
                "a second value",
            ),
            (
                "a foreign id",
                json!({"result": 7, "error": null, "id": "other"}).to_string(),
                200,
                "does not echo",
            ),
            (
                "a numeric id where the request sent a string",
                json!({"result": 7, "error": null, "id": 1}).to_string(),
                200,
                "does not echo",
            ),
            (
                "both a result and an error",
                json!({"result": 7, "error": {"code": -1}, "id": id}).to_string(),
                200,
                "both a result and an error",
            ),
            (
                "neither a result nor an error",
                json!({"id": id}).to_string(),
                200,
                "neither a result nor an error",
            ),
            (
                "a result under a non-200 status",
                good.clone(),
                500,
                "non-200 status",
            ),
        ];
        for (what, body, status, needle) in rows {
            let error = reply(&body, status, "gettxout", Absent::Never)
                .err()
                .unwrap_or_else(|| panic!("{what} must be refused"))
                .to_string();
            assert!(error.contains(needle), "{what}: {error}");
            assert!(
                error.contains("gettxout"),
                "{what} names its method: {error}"
            );
        }
    }

    /// 3. A missing answer is never a generic success: each absence is accepted only in
    ///    the ONE form its own call declared, and every other form refuses.
    #[test]
    fn each_absence_is_answered_only_in_the_one_form_its_call_declared() {
        let id = RPC_ID;
        let null_result = json!({"result": null, "error": null, "id": id}).to_string();
        let coded = |code: i64| {
            json!({"result": null, "error": {"code": code, "message": "no"}, "id": id}).to_string()
        };
        // `gettxout`'s null result IS its answer; the same body refuses everywhere else.
        assert!(reply(&null_result, 200, "gettxout", Absent::NullResult)
            .expect("a null gettxout")
            .is_null());
        for absent in [Absent::Never, Absent::Code(-5)] {
            let error = reply(&null_result, 200, "x", absent)
                .expect_err("a null result is no generic success")
                .to_string();
            assert!(error.contains("neither a result nor an error"), "{error}");
        }
        // A declared error code IS the answer; a different code, and the same code
        // where none was declared, are refusals.
        assert!(reply(&coded(-8), 500, "getblockhash", Absent::Code(-8))
            .expect("an out-of-range height")
            .is_null());
        assert!(
            reply(&coded(-5), 500, "getrawtransaction", Absent::Code(-5))
                .expect("unknown history")
                .is_null()
        );
        for (what, body, absent) in [
            ("a foreign code", coded(-1), Absent::Code(-8)),
            ("contention on the scan", coded(-8), Absent::Never),
            ("an absence nobody declared", coded(-5), Absent::NullResult),
        ] {
            let error = reply(&body, 500, "x", absent)
                .err()
                .unwrap_or_else(|| panic!("{what} must be refused"))
                .to_string();
            assert!(error.contains("refused:"), "{what}: {error}");
        }
        // Both absences are STATUS-coherent forms, and each row below is the accepted
        // form above it with ONE coherence property removed. A coded refusal rides an
        // error status — MEASURED against a live daemon, `-8` and `-5` both ride a 500,
        // asserted by the live suite rather than claimed here — so the same code under a
        // 200 is an incoherent envelope, not the declared absence.
        for (what, code, method) in [
            ("an out-of-range height", -8, "getblockhash"),
            ("unknown history", -5, "getrawtransaction"),
        ] {
            let error = reply(&coded(code), 200, method, Absent::Code(code))
                .err()
                .unwrap_or_else(|| panic!("{what} under a 200 must be refused"))
                .to_string();
            assert!(error.contains("refused:"), "{what}: {error}");
        }
        // And `gettxout`'s absence is a `result` member that is PRESENT and null, so a
        // body carrying no `result` at all is refused rather than read as that answer.
        let error = reply(
            &json!({"id": id}).to_string(),
            200,
            "gettxout",
            Absent::NullResult,
        )
        .expect_err("a body with no result member is no declared absence")
        .to_string();
        assert!(error.contains("neither a result nor an error"), "{error}");
    }

    /// 4. **Adapter fee class 4A-primary, decoder half.** Every Core BTC number goes
    ///    through the CHECKED `Amount` conversion, so a negative, over-precise,
    ///    non-numeric or overflowing feerate fails instead of being rounded into a
    ///    plausible integer; the `estimatesmartfee` RESULT must itself be an object; and
    ///    only an absent or null `feerate` MEMBER of that object is "no estimate". The
    ///    other half of 4A-primary — estimate-versus-floor precedence and the sat/kvB to
    ///    sat/vB ceiling — is `inventory.rs`, which is where the rate is taken.
    ///    The SEPARATE **adapter class 4A-precision** below pins the one precision
    ///    residual this conversion does not reach, so the guarantee is stated at the
    ///    width the code actually holds; `m40` is that class's row, not this one's.
    #[test]
    fn core_btc_numbers_convert_through_the_checked_amount_path_or_fail() {
        let temp = crate::fed::TempDir::new("core-view-fees").expect("temp dir");
        let cookie = cookie_file(&temp.path, COOKIE);
        let estimates = [
            json!({"feerate": 0.00001}),
            json!({"feerate": null, "errors": ["insufficient data"]}),
            json!({"blocks": 6}),
        ];
        let wire = Wire::serving(estimates.iter().cloned().map(ok).collect());
        let core = adapter(&wire, &cookie);
        assert_eq!(core.fee_estimate().expect("a rate"), Some(1_000));
        for what in ["an explicit null feerate", "an absent feerate"] {
            assert_eq!(core.fee_estimate().expect(what), None, "{what}");
        }

        let broken = [
            ("a negative rate", json!({"feerate": -0.00001})),
            ("an over-precise rate", json!({"feerate": 0.000000001})),
            ("a rate past a u64 of satoshis", json!({"feerate": 1e12})),
            ("a rate that is not a number", json!({"feerate": "0.00001"})),
        ];
        let wire = Wire::serving(broken.iter().map(|(_, body)| ok(body.clone())).collect());
        let core = adapter(&wire, &cookie);
        for (what, _) in broken {
            let error = core
                .fee_estimate()
                .err()
                .unwrap_or_else(|| panic!("{what} must fail"))
                .to_string();
            assert!(
                error.contains("estimatesmartfee feerate"),
                "{what}: {error}"
            );
        }

        // The RESULT ITSELF is required to be an object, and this is not pedantry about
        // schemas: `Value::get("feerate")` answers `None` on an array, a string, a number
        // and a boolean alike, so every one of these would otherwise be read as the
        // HONEST ABSENCE and price the pair off the node floors — a coherent envelope
        // carrying a nonsense payload, silently downgraded to "this node has no estimate".
        // The two rows above it are the positive controls that keep the gate from simply
        // banning absence: an object whose `feerate` is null, and one with no `feerate`
        // member at all, both still mean "no estimate". `m44` bypasses the gate and the
        // non-object rows go red while those two stay green.
        let non_object = [
            ("an array result", json!([0.00001])),
            ("a string result", json!("0.00001")),
            ("a numeric result", json!(0.00001)),
            ("a boolean result", json!(false)),
            ("an empty array result", json!([])),
        ];
        let wire = Wire::serving(
            non_object
                .iter()
                .map(|(_, body)| ok(body.clone()))
                .collect(),
        );
        let core = adapter(&wire, &cookie);
        for (what, _) in non_object {
            let error = refusal(core.fee_estimate(), what);
            assert!(
                error.contains("estimatesmartfee is not an object"),
                "{what}: {error}"
            );
        }
        // The adjacent green controls, one adapter each so no row consumes another's
        // reply: an object IS the shape, and both honest absences survive the gate.
        let absent = [
            ("a null feerate member", json!({"feerate": null})),
            ("an absent feerate member", json!({"blocks": 6})),
            ("an empty object result", json!({})),
        ];
        for (what, body) in absent {
            let wire = Wire::serving(vec![ok(body)]);
            let core = adapter(&wire, &cookie);
            assert_eq!(core.fee_estimate().expect(what), None, "{what}");
        }

        // Both mempool floors are MANDATORY; neither defaults to zero.
        let floors = [
            json!({"mempoolminfee": 0.00001}),
            json!({"incrementalrelayfee": 0.00001}),
            json!({"incrementalrelayfee": 0.00001, "mempoolminfee": "cheap"}),
        ];
        let wire = Wire::serving(floors.iter().cloned().map(ok).collect());
        let core = adapter(&wire, &cookie);
        for missing in ["incrementalrelayfee", "mempoolminfee", "mempoolminfee"] {
            let error = refusal(core.fee_floors(), "a missing floor");
            assert!(error.contains(missing), "{missing}: {error}");
        }
    }

    /// 4A-precision. The RESIDUAL of an f64-typed JSON number, MEASURED rather than
    ///    assumed, because the guarantee above must be stated at the width it actually
    ///    holds. A class of its OWN, and that is what makes `m40` mean anything: while
    ///    these rows sat inside 4A-primary, the mutation that rounds before the checked
    ///    conversion aborted that shared class on its `estimatesmartfee` row, so nothing
    ///    below ever ran under it — red or green — and by this repo's rule they were
    ///    asserting nothing. `m40` now reddens THIS class, on the first `over` row.
    ///    It is deliberately NOT called 4B: M3b owns fee class 4B.
    ///
    ///    The boundary is the DOUBLE THE PARSER HANDS OVER, not the decimal literal:
    ///    `as_btc` sees only `Value::as_f64`, so a spelling is refused exactly when that
    ///    double is not a whole satoshi, and extra digits that vanish in the narrowing
    ///    are accepted (`absorbed` below). Reading the literal instead needs the
    ///    `arbitrary_precision` feature, a dependency change outside this bead. The
    ///    accepted class is WIDER than "digits below f64 resolution", and the `edge` row
    ///    below is the measurement that says so rather than a claim about it. It cannot
    ///    redirect value — every scanned amount is cross-checked byte-for-byte against
    ///    the consensus-decoded full parent (`inventory.rs`), and a floor moved by under
    ///    one satoshi per kvB changes only what the pair pays to relay. This is a
    ///    MEASURED residual, not a claim of exact lexical precision, and closing it is
    ///    unpriced scope.
    #[test]
    fn the_measured_f64_sub_resolution_lexical_residual_is_pinned_at_its_true_width() {
        for over in ["0.000000001", "0.000000005", "0.123456789"] {
            let value: Value = serde_json::from_str(over).expect("a number");
            let error = refusal(as_btc(Some(&value), "a rate"), over);
            assert!(error.contains("not a usable amount"), "{over}: {error}");
        }
        // The EDGE, both halves asserted so the width above is code rather than prose.
        // This literal exceeds 1e-8 by 1e-25, well under the 8.3e-25 half-ULP there, so
        // rounded correctly it IS the one-satoshi double and would be accepted; Rust's own
        // `f64::from_str` returns exactly that. serde_json's concise-float path lands one
        // ULP lower, and THAT — a parser's rounding, not f64 resolution — is the only
        // reason the value below is refused. Pinning it is deliberate: if a serde_json
        // release corrects the rounding, this row goes red because the residual widened.
        let edge = "0.0000000100000000000000001";
        assert_eq!(
            edge.parse::<f64>().expect("a number").to_bits(),
            1e-8f64.to_bits(),
            "correctly rounded, {edge} is the one-satoshi double"
        );
        let value: Value = serde_json::from_str(edge).expect("a number");
        assert_eq!(
            value.as_f64().expect("a number").to_bits() + 1,
            1e-8f64.to_bits(),
            "serde_json narrows {edge} one ULP low"
        );
        let error = refusal(as_btc(Some(&value), "a rate"), edge);
        assert!(error.contains("not a usable amount"), "{edge}: {error}");
        let absorbed: Value =
            serde_json::from_str("0.00000001000000000000000000000000001").expect("a number");
        assert_eq!(
            as_btc(Some(&absorbed), "a rate").expect("the measured residual"),
            Amount::from_sat(1),
            "digits under f64 resolution are gone before as_btc sees the value"
        );
    }

    /// 5. The adapter stores a PATH, not a credential: the cookie is re-read on every
    ///    call, refused when a CR or LF says the cookie FILE is malformed, and never
    ///    printed. Removing the file between two calls stops the second — a cached
    ///    credential would sail through it.
    #[test]
    fn the_cookie_is_read_per_call_never_stored_and_never_printed() {
        let temp = crate::fed::TempDir::new("core-view-cookie").expect("temp dir");
        let cookie = cookie_file(&temp.path, COOKIE);
        let wire = Wire::serving(vec![ok(json!(hash(0xaa).to_string())); 2]);
        let core = adapter(&wire, &cookie);
        assert_eq!(core.best_block_hash().expect("the control"), hash(0xaa));
        std::fs::remove_file(&cookie).expect("remove");
        let error = core
            .best_block_hash()
            .expect_err("a removed cookie stops the next call")
            .to_string();
        assert!(error.contains("cannot open secret file"), "{error}");

        // Child A's own rules, applied to this file too: a loose mode is refused.
        let loose = cookie_file(&temp.path, COOKIE);
        std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o644)).expect("mode");
        let error = CoreRpc::new(wire.addr, loose.clone())
            .expect("adapter")
            .best_block_hash()
            .expect_err("a world-readable cookie is refused")
            .to_string();
        assert!(error.contains("mode 0644"), "{error}");

        // A CR/LF-bearing cookie is MALFORMED and is refused before any request is
        // written. It is not refused because a header could not be formed from it — the
        // base64 the next line applies carries those bytes into a perfectly well-formed
        // `Authorization: Basic …`, which is why the check reads the RAW credential. No
        // diagnostic on any of these paths — including a refusal from Core itself —
        // carries the secret.
        let split = cookie_file(&temp.path, "__cookie__:a\r\nX-Injected: 1");
        let wire = Wire::serving(vec![(
            401,
            json!({"result": null, "error": {"code": -32601}, "id": RPC_ID}).to_string(),
        )]);
        let injected = CoreRpc::new(wire.addr, split)
            .expect("adapter")
            .best_block_hash()
            .expect_err("CR/LF is refused")
            .to_string();
        let held = "a CR/LF cookie reached the wire";
        assert!(injected.contains("not CR/LF-free"), "{held}: {injected}");
        assert!(wire.seen().is_empty(), "no request may be written");
        let refused = adapter(&wire, &cookie_file(&temp.path, COOKIE))
            .best_block_hash()
            .expect_err("Core refused")
            .to_string();
        for leak in [injected, refused, error] {
            assert!(
                !leak.contains("5f3aQ"),
                "a diagnostic printed the cookie: {leak}"
            );
        }

        // 5b. "No credential is a PARAMETER here" is not "no credential can appear here",
        //     so the stronger claim is the one pinned. A hostile or misbound local proxy
        //     that REFLECTS the request head it just received would otherwise put the
        //     cookie into an operator's terminal, scrollback, log files and pasted
        //     diagnostics — that third-party exposure is what the credential-free
        //     requirement guards, and "a reflector already holds the cookie" does not
        //     answer it. `reply` therefore carries Core's numeric CODE and none of its
        //     peer-controlled text. `m36` restores the verbatim echo and this goes red.
        let auth = BASE64_STANDARD.encode(COOKIE.as_bytes());
        let reflected = json!({
            "result": null,
            "error": {"code": -32600, "message": format!("bad auth: Basic {auth}")},
            "id": RPC_ID,
        });
        let wire = Wire::serving(vec![(401, reflected.to_string())]);
        let echoed = refusal(
            adapter(&wire, &cookie_file(&temp.path, COOKIE)).best_block_hash(),
            "a reflecting Core",
        );
        assert!(
            !echoed.contains(&auth) && !echoed.contains("5f3aQ"),
            "a reflecting Core put the credential in the diagnostic: {echoed}"
        );
        // The refusal still SAYS something: the method, the HTTP status and Core's code.
        assert!(
            echoed.contains("core getbestblockhash (HTTP 401): refused: code Some(-32600)"),
            "redaction must not cost the numeric code: {echoed}"
        );
    }

    /// 6b. A transport failure names the TYPED EXCHANGE that exhausted its bound, not
    ///     merely the socket: "which typed exchange" is what a diagnostic must answer when
    ///     the bounded reads are all posted to the same address. Deadlines and caps
    ///     themselves belong to qhe; naming the exchange does not.
    #[test]
    fn a_transport_failure_names_the_typed_exchange_that_exhausted_its_bound() {
        let temp = crate::fed::TempDir::new("core-view-transport").expect("temp dir");
        let cookie = cookie_file(&temp.path, COOKIE);
        // A port nothing is listening on: the exchange fails before any reply exists.
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let dead = listener.local_addr().expect("addr");
        drop(listener);
        let core = CoreRpc::new(dead, cookie).expect("a loopback adapter");
        for (method, refusal) in [
            (
                "getbestblockhash",
                refusal(core.best_block_hash(), "a dead socket"),
            ),
            (
                "scantxoutset",
                refusal(core.scan_vault_script(&script()), "a dead socket"),
            ),
            (
                "getmempoolinfo",
                refusal(core.fee_floors(), "a dead socket"),
            ),
        ] {
            let unnamed = "a transport failure did not name its exchange";
            assert!(
                refusal.contains(&format!("core {method}:")),
                "{unnamed}: {refusal}"
            );
            assert!(refusal.contains("connect"), "and what failed: {refusal}");
        }
    }

    /// 6. A non-loopback Core is refused at construction, before any socket, cookie
    ///    read or request exists. This adapter has no remote transport.
    #[test]
    fn a_non_loopback_core_address_is_refused_before_any_socket() {
        let remote = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), 8332));
        let remote = CoreRpc::new(remote, PathBuf::from("/nonexistent/cookie"));
        let error = refusal(remote, "a routable Core address");
        assert!(error.contains("is not loopback"), "{error}");
        let local = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8332));
        CoreRpc::new(local, PathBuf::from("/nonexistent/cookie")).expect("loopback is the control");
    }

    /// 7. The BYTE boundary is qhe's, not this parser's, and the residual is stated
    ///    rather than implied: this reply arrives already decoded, so a byte the legacy
    ///    helper replaced with U+FFFD is indistinguishable here from one Core sent. The
    ///    logical envelope still holds, and the corrupted value still fails its own
    ///    typed decode rather than passing as something else.
    #[test]
    fn the_byte_level_decode_boundary_belongs_to_qhe() {
        let lossy = json!({"result": "\u{fffd}\u{fffd}", "error": null, "id": RPC_ID}).to_string();
        let value = reply(&lossy, 200, "getbestblockhash", Absent::Never).expect("logically valid");
        assert_eq!(value, json!("\u{fffd}\u{fffd}"));
        let error = parsed::<BlockHash>(Some(&value), "getbestblockhash")
            .expect_err("a replaced byte is not a block hash")
            .to_string();
        assert!(error.contains("does not parse"), "{error}");
    }

    /// Drive one read against a scripted Wire and return the refusal it must earn. Each
    /// row of class 8 gets its own adapter, so a row cannot pass by consuming a reply a
    /// neighbouring row was meant to see.
    fn payload<T>(body: Value, drive: impl Fn(&CoreRpc) -> Result<T, Error>, what: &str) -> String {
        let temp = crate::fed::TempDir::new("core-view-payload").expect("temp dir");
        let cookie = cookie_file(&temp.path, COOKIE);
        let wire = Wire::serving(vec![ok(body)]);
        refusal(drive(&adapter(&wire, &cookie)), what)
    }

    /// 8. A COHERENT envelope carrying an incoherent PAYLOAD is refused by every one of
    ///    the eight typed decoders. Class 2 owns the envelope and class 4 owns the two fee
    ///    reads; this owns the other six, where a missing or wrongly typed field would
    ///    otherwise be read as a default. The `gettxout` rows matter most: `coinbase`
    ///    defaulting to `false` would silently disable maturity for every scanned coin
    ///    (`m41`), and a `scantxoutset` that did not report success would let an ABORTED
    ///    partial scan stand in for the confirmed set (`m42`) — an under-covered Escape,
    ///    which is the one outcome `inventory.rs` exists to prevent.
    #[test]
    fn every_typed_decoder_refuses_a_malformed_payload_under_a_coherent_envelope() {
        // Borrowed, because every row below reuses them and `json!` would otherwise move.
        let good_hash = &hash(0xaa).to_string();
        let tx = parent();
        let txid = &tx.compute_txid().to_string();
        let spk = &format!("{:x}", script());

        // getblockchaininfo — neither mandatory field may default.
        let info = |extra: Value| -> Value {
            let mut base = json!({"chain": "regtest"});
            for (key, value) in extra.as_object().expect("an object") {
                base[key] = value.clone();
            }
            base
        };
        for (what, body, needle) in [
            (
                "no initialblockdownload",
                info(json!({"bestblockhash": good_hash})),
                "has no boolean initialblockdownload",
            ),
            (
                "a stringly initialblockdownload",
                info(json!({"initialblockdownload": "false", "bestblockhash": good_hash})),
                "has no boolean initialblockdownload",
            ),
            (
                "no bestblockhash",
                info(json!({"initialblockdownload": false})),
                "getblockchaininfo bestblockhash is not a string",
            ),
            (
                "a bestblockhash that is not a hash",
                info(json!({"initialblockdownload": false, "bestblockhash": "zz"})),
                "getblockchaininfo bestblockhash does not parse",
            ),
        ] {
            let error = payload(body, |core| core.chain_info(), what);
            assert!(error.contains(needle), "{what}: {error}");
        }

        // getbestblockhash — the whole result is the field.
        for (what, body, needle) in [
            (
                "a numeric tip",
                json!(7),
                "getbestblockhash is not a string",
            ),
            ("a tip that is not a hash", json!("zz"), "does not parse"),
        ] {
            let error = payload(body, |core| core.best_block_hash(), what);
            assert!(error.contains(needle), "{what}: {error}");
        }

        // scantxoutset — the success gate, the array, and every record field.
        let record = |extra: Value| -> Value {
            let mut base = json!({
                "txid": txid, "vout": 0, "scriptPubKey": spk, "amount": 0.5, "height": 3,
            });
            for (key, value) in extra.as_object().expect("an object") {
                base[key] = value.clone();
            }
            json!({"success": true, "bestblock": good_hash, "unspents": [base]})
        };
        for (what, body, needle) in [
            (
                "a scan that did not succeed",
                json!({"success": false, "bestblock": good_hash, "unspents": []}),
                "scantxoutset did not report success",
            ),
            (
                "a scan with no success field at all",
                json!({"bestblock": good_hash, "unspents": []}),
                "scantxoutset did not report success",
            ),
            (
                "no unspents array",
                json!({"success": true, "bestblock": good_hash}),
                "scantxoutset has no unspents array",
            ),
            (
                "an unspents object where an array belongs",
                json!({"success": true, "bestblock": good_hash, "unspents": {}}),
                "scantxoutset has no unspents array",
            ),
            (
                "no bestblock to bind the scan to",
                json!({"success": true, "unspents": []}),
                "scantxoutset bestblock is not a string",
            ),
            (
                "a txid that is not a string",
                record(json!({"txid": 7})),
                "scantxoutset txid is not a string",
            ),
            (
                "a vout past u32",
                record(json!({"vout": 4_294_967_296u64})),
                "scantxoutset vout does not fit u32",
            ),
            (
                "a negative vout",
                record(json!({"vout": -1})),
                "scantxoutset vout is not a non-negative integer",
            ),
            (
                "a height past u32",
                record(json!({"height": 4_294_967_296u64})),
                "scantxoutset height does not fit u32",
            ),
            (
                "a negative height",
                record(json!({"height": -1})),
                "scantxoutset height is not a non-negative integer",
            ),
            (
                "an amount that is not a number",
                record(json!({"amount": "0.5"})),
                "scantxoutset amount is not a number",
            ),
            (
                "a scriptPubKey that is not hex",
                record(json!({"scriptPubKey": "zz"})),
                "scantxoutset scriptPubKey does not parse",
            ),
        ] {
            let error = payload(body, |core| core.scan_vault_script(&script()), what);
            assert!(error.contains(needle), "{what}: {error}");
        }

        // gettxout — a NON-NULL view must carry all five facts a bracket cross-checks.
        let outpoint = OutPoint {
            txid: tx.compute_txid(),
            vout: 0,
        };
        let view = |extra: Value| -> Value {
            let mut base = json!({
                "bestblock": good_hash,
                "confirmations": 7,
                "value": 0.5,
                "scriptPubKey": {"hex": spk},
                "coinbase": false,
            });
            for (key, value) in extra.as_object().expect("an object") {
                match value.is_null() {
                    true => {
                        base.as_object_mut().expect("an object").remove(key);
                    }
                    false => base[key] = value.clone(),
                }
            }
            base
        };
        for (what, body, needle) in [
            (
                "no coinbase flag",
                view(json!({"coinbase": null})),
                "gettxout has no boolean coinbase",
            ),
            (
                "a stringly coinbase flag",
                view(json!({"coinbase": "false"})),
                "gettxout has no boolean coinbase",
            ),
            (
                "no confirmation count",
                view(json!({"confirmations": null})),
                "gettxout confirmations is not a non-negative integer",
            ),
            (
                "a negative confirmation count",
                view(json!({"confirmations": -1})),
                "gettxout confirmations is not a non-negative integer",
            ),
            (
                "no bestblock",
                view(json!({"bestblock": null})),
                "gettxout bestblock is not a string",
            ),
            (
                "a value that is not a number",
                view(json!({"value": "0.5"})),
                "gettxout value is not a number",
            ),
            (
                "no scriptPubKey hex",
                view(json!({"scriptPubKey": {}})),
                "gettxout scriptPubKey.hex is not a string",
            ),
            (
                "a scriptPubKey hex that is not hex",
                view(json!({"scriptPubKey": {"hex": "zz"}})),
                "gettxout scriptPubKey.hex does not parse",
            ),
        ] {
            let error = payload(body, |core| core.txout(outpoint), what);
            assert!(error.contains(needle), "{what}: {error}");
        }

        // getblockhash — a present, non-null result is a hash or nothing.
        for (what, body, needle) in [
            (
                "a numeric height answer",
                json!(7),
                "getblockhash is not a string",
            ),
            (
                "an answer that is not a hash",
                json!("zz"),
                "getblockhash does not parse",
            ),
        ] {
            let error = payload(body, |core| core.block_hash(3), what);
            assert!(error.contains(needle), "{what}: {error}");
        }

        // getrawtransaction — the full parent is consensus-decoded or refused.
        for (what, body, needle) in [
            (
                "a numeric raw transaction",
                json!(7),
                "getrawtransaction is not a hex string",
            ),
            (
                "hex that is not a transaction",
                json!("00"),
                "getrawtransaction does not decode",
            ),
            (
                "a raw transaction that is not hex",
                json!("zz"),
                "getrawtransaction does not decode",
            ),
        ] {
            let error = payload(
                body,
                |core| core.block_transaction(tx.compute_txid(), hash(0xbb)),
                what,
            );
            assert!(error.contains(needle), "{what}: {error}");
        }
    }

    /// 9. PRUNED history fails CLOSED. A node without the block's data answers a
    ///    block-qualified `getrawtransaction` with `RPC_MISC_ERROR` — Core's own message
    ///    is "Block not available (pruned data)" — and that is NOT the `-5` this call
    ///    declares absent. So it is a terminal refusal, never the "no such history"
    ///    absence `inventory.rs` holds against the closing tip and could retry. The `-5`
    ///    Core really does use for a txid absent from a block it DOES have is the
    ///    adjacent control, and neither refusal carries the peer's text.
    #[test]
    fn pruned_block_data_is_terminal_not_the_declared_block_qualified_absence() {
        let temp = crate::fed::TempDir::new("core-view-pruned").expect("temp dir");
        let cookie = cookie_file(&temp.path, COOKIE);
        let coded = |code: i64, message: &str| {
            (
                500,
                json!({"result": null, "error": {"code": code, "message": message}, "id": RPC_ID})
                    .to_string(),
            )
        };
        let wire = Wire::serving(vec![
            coded(-1, "Block not available (pruned data)"),
            coded(-5, "No such transaction found in the provided block"),
        ]);
        let core = adapter(&wire, &cookie);
        let tx = parent();

        let error = refusal(
            core.block_transaction(tx.compute_txid(), hash(0xbb)),
            "missing block data",
        );
        assert!(
            error.contains("core getrawtransaction (HTTP 500): refused: code Some(-1)"),
            "pruned block data must be terminal, with Core's code: {error}"
        );
        assert!(
            !error.contains("pruned data"),
            "and without Core's reflectable text: {error}"
        );

        // The control: the one code this call declares IS the absence, and only it.
        assert_eq!(
            core.block_transaction(tx.compute_txid(), hash(0xbb))
                .expect("the declared absence"),
            None
        );
    }
}
