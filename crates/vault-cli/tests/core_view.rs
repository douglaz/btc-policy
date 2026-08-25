//! Opt-in LIVE-bitcoind suite for the stage-1 Core seam and the inventory it feeds (bead
//! btc-policy-m3a-core-view-inventory-rha). Every LIVE class here spawns real daemons the
//! way the backend suite does, so all of them are `#[ignore]`d and opted into together:
//!
//!   nix develop -c cargo test --locked -p vault-cli --test core_view -- --ignored --test-threads=1
//!
//! ONE class is deliberately outside that set. Class 19, at the foot of this file, drives
//! the same real `CoreRpc` against a SCRIPTED HOSTILE listener rather than a daemon, so it
//! is neither slow nor opt-in and runs in the ordinary `cargo test --workspace` gate. It
//! lives here because this is the only target that can reach `CoreRpc` and `prepare_view`
//! together, not because it needs bitcoind.
//!
//! What the live classes prove that the in-process ones cannot: that the eight closed reads answer
//! a REAL Core over real cookie auth; that a full previous transaction resolves through
//! `getblockhash` plus a BLOCK-QUALIFIED `getrawtransaction` on a daemon running with NO
//! `-txindex` at all; that Core's own `-8`/`-5` refusals are the absences this adapter
//! maps them to; that a nonempty inventory PREPARES against live chain state, with its
//! preflighted sizes and its integer sat/vB rate taken from the daemon's own floors; that
//! coinbase maturity turns at exactly 100 confirmations against real chain state; that a
//! real node still in initial block download is refused; and that a live default-signet
//! daemon's own challenge is what the sealed public-signet code means while a custom
//! signet sharing `chain:"signet"` with it is not.
//!
//! What it deliberately does NOT claim: nothing here composes final output values,
//! attaches a full parent or `SIGHASH_ALL`, or runs a real signer. Those are
//! `btc-policy-m3b-spend-composition-nq8`, and this suite would be lying if it implied
//! otherwise. The pair it builds is the FROZEN SKELETON at caller-supplied amounts.
//!
//! `vault-cli` is a BINARY crate, so an integration test cannot link its modules; they
//! are included here at their own paths instead. That pulls in each module's unit tests
//! as well, which run in this target too — harmless duplication, and the `--ignored`
//! invocation above selects only the live tests below.

#![allow(dead_code, unused_imports)]

#[path = "../src/http.rs"]
mod http;
// The order below is declaration only; Rust resolves the cycle between these itself.
#[path = "../src/core_view.rs"]
mod core_view;
#[path = "../src/fed.rs"]
mod fed;
#[path = "../src/inventory.rs"]
mod inventory;
#[path = "../src/sealed.rs"]
mod sealed;
#[path = "../src/setup.rs"]
mod setup;
#[path = "../src/signer.rs"]
mod signer;

use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bitcoin::base64::prelude::{Engine as _, BASE64_STANDARD};
use bitcoin::{Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction};
use miniscript::{Descriptor, DescriptorPublicKey};
use serde_json::{json, Value};

use crate::core_view::{CoreRpc, CoreView};
use crate::http::Error;
use crate::inventory::{pair, prepare_view, PreparedView};
use crate::sealed::LiveVault;

/// One bitcoind this test owns: spawned on its own port and datadir, killed on drop.
struct Node {
    child: Child,
    chain: &'static str,
    datadir: PathBuf,
    addr: SocketAddr,
    auth: String,
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
    listener.local_addr().expect("addr").port()
}

impl Node {
    /// A daemon on `chain` with `extra` arguments and NOTHING else — in particular no
    /// `-txindex`, which is the point of the regtest legs below.
    fn start(chain: &'static str, datadir: PathBuf, extra: &[&str]) -> Node {
        std::fs::create_dir_all(&datadir).expect("datadir");
        let port = free_port();
        let child = Command::new("bitcoind")
            .arg(format!("-chain={chain}"))
            .arg(format!("-datadir={}", datadir.display()))
            .arg(format!("-rpcport={port}"))
            .args(["-connect=0", "-listen=0", "-server=1"])
            .args(extra)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn bitcoind (is the dev shell active?)");
        let mut node = Node {
            child,
            chain,
            datadir,
            addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)),
            auth: String::new(),
        };
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(60) {
            if let Ok(text) = std::fs::read_to_string(node.cookie()) {
                node.auth = BASE64_STANDARD.encode(text.trim());
                if node.rpc("getblockchaininfo", json!([])).is_ok() {
                    return node;
                }
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        panic!("bitcoind on {chain} did not become ready");
    }

    fn cookie(&self) -> PathBuf {
        self.datadir.join(self.chain).join(".cookie")
    }

    /// The suite's OWN RPC client, for chain setup. The code under test is
    /// [`CoreRpc`]; nothing here shares its funnel.
    fn rpc(&self, method: &str, params: Value) -> Result<Value, Error> {
        let body = json!({"jsonrpc": "1.0", "id": "suite", "method": method, "params": params});
        let response = http::post_json(
            self.addr,
            "/",
            body.to_string().as_bytes(),
            Some(&self.auth),
            Duration::from_secs(60),
        )?;
        let reply: Value = serde_json::from_str(&response.body)?;
        match reply.get("error").filter(|e| !e.is_null()) {
            Some(error) => Err(format!("{method}: {error}").into()),
            None => Ok(reply["result"].clone()),
        }
    }

    /// The raw HTTP status Core answers one call with. [`core_view::reply`] accepts a
    /// coded absence only under a NON-200, so which status Core really uses is a fact
    /// this suite MEASURES against a live daemon rather than a number a comment asserts.
    fn status(&self, method: &str, params: Value) -> u16 {
        let body = json!({"jsonrpc": "1.0", "id": "suite", "method": method, "params": params});
        http::post_json(
            self.addr,
            "/",
            body.to_string().as_bytes(),
            Some(&self.auth),
            Duration::from_secs(60),
        )
        .expect("a reply")
        .status
    }

    fn call(&self, method: &str, params: Value) -> Value {
        self.rpc(method, params)
            .unwrap_or_else(|e| panic!("bitcoind {method}: {e}"))
    }

    fn generate(&self, blocks: u64, to: &str) {
        self.call("generatetoaddress", json!([blocks, to]));
    }

    /// The adapter under test, pointed at this daemon's real cookie file.
    fn adapter(&self) -> CoreRpc {
        CoreRpc::new(self.addr, self.cookie()).expect("a loopback adapter")
    }
}

/// A sealed vault from the PRODUCTION ceremony, and the three scripts a caller hands the
/// seam. The seam itself takes only the definite descriptor and the network — this suite
/// carries the whole `LiveVault` because that is what loads the ceremony's artifacts, not
/// because `inventory.rs` depends on it.
struct Vault {
    _ceremony: setup::tests::Ceremony,
    _temp: fed::TempDir,
    vault: LiveVault,
    destination: ScriptBuf,
    change: ScriptBuf,
    escape: ScriptBuf,
}

impl Vault {
    /// `[destination, supplied vault change, base Escape]`, the seam's own order.
    fn scripts(&self) -> [&ScriptBuf; 3] {
        [&self.destination, &self.change, &self.escape]
    }

    fn prepare(&self, core: &dyn CoreView) -> Result<PreparedView, Error> {
        prepare_view(
            core,
            self.vault.network,
            &self.vault.descriptor,
            self.scripts(),
        )
    }
}

fn sealed_vault() -> Vault {
    let ceremony = setup::tests::ceremony_through_endorse(3, 2);
    ceremony.finalize().expect("finalize");
    let artifacts = ceremony.sealed("backup");
    let vault = LiveVault::load_artifacts(&artifacts).expect("the sealed set");
    let temp = fed::TempDir::new("core-view-live").expect("temp dir");
    let escape = vault.check_params.escape.as_ref().expect("an escape");
    Vault {
        destination: definite(&vault.check_params.allowed[0], 0),
        change: vault.descriptor.script_pubkey(),
        escape: definite(escape, 0),
        _ceremony: ceremony,
        _temp: temp,
        vault,
    }
}

/// The refusal `what` must earn, over a success type that does not print itself:
/// [`PreparedView`] deliberately carries no `Debug`.
fn refusal<T>(result: Result<T, Error>, what: &str) -> String {
    match result {
        Ok(_) => panic!("{what} must be refused"),
        Err(error) => error.to_string(),
    }
}

fn address(script: &ScriptBuf, network: Network) -> String {
    bitcoin::Address::from_script(script.as_script(), network)
        .expect("an address")
        .to_string()
}

fn definite(descriptor: &Descriptor<DescriptorPublicKey>, index: u32) -> ScriptBuf {
    descriptor
        .at_derivation_index(index)
        .expect("definite")
        .script_pubkey()
}

/// The vault's own address, and a throwaway one to bury blocks against.
fn addresses(vault: &LiveVault) -> (String, String) {
    let hot = &vault.check_params.allowed[0];
    (
        address(&vault.descriptor.script_pubkey(), vault.network),
        address(&definite(hot, 9), vault.network),
    )
}

/// A regtest daemon with NO `-txindex`, holding exactly one mature coinbase coin paying
/// the sealed vault. Blocks after the first are buried against a throwaway address, so
/// the vault's confirmed set stays at one coin.
fn funded(temp: &fed::TempDir, vault: &LiveVault, confirmations: u64) -> Node {
    let node = Node::start(
        "regtest",
        temp.path.join(format!("regtest-{confirmations}")),
        &["-fallbackfee=0.0002"],
    );
    let (vault_address, throwaway) = addresses(vault);
    node.generate(1, &vault_address);
    node.generate(confirmations - 1, &throwaway);
    assert!(
        node.call("getindexinfo", json!([]))
            .as_object()
            .is_some_and(|indexes| indexes.is_empty()),
        "this daemon must run with NO transaction index"
    );
    node
}

/// LIVE-1. The eight closed reads answer a real Core, with the full previous
/// transaction resolved through the scan's retained height and a BLOCK-QUALIFIED
/// `getrawtransaction` on a daemon that has no transaction index — and Core's own
/// `-8` and `-5` refusals arriving as the two absences this adapter declares.
#[test]
#[ignore = "spawns a regtest bitcoind; run with --ignored"]
fn the_closed_eight_reads_answer_a_live_core_without_txindex() {
    let sealed = sealed_vault();
    let temp = fed::TempDir::new("core-view-eight").expect("temp dir");
    let node = funded(&temp, &sealed.vault, 101);
    let core = node.adapter();

    let info = core.chain_info().expect("getblockchaininfo");
    assert!(
        !info.initial_block_download,
        "a mined regtest chain is current"
    );
    vault_node::chain::verify_chain_identity(&info.identity, Network::Regtest)
        .expect("the sealed network is this daemon's own chain");
    let tip = core.best_block_hash().expect("getbestblockhash");
    assert_eq!(
        tip, info.best_block,
        "both tip reads agree on a still chain"
    );

    let vault_spk = sealed.vault.descriptor.script_pubkey();
    let scan = core.scan_vault_script(&vault_spk).expect("scantxoutset");
    assert_eq!(
        scan.best_block, tip,
        "the scan is bound to the tip it scanned"
    );
    assert_eq!(scan.coins.len(), 1, "exactly the one funded coin");
    let coin = &scan.coins[0];
    assert_eq!(coin.script, vault_spk);
    assert_eq!(coin.value, Amount::from_int_btc(50), "a regtest coinbase");
    assert_eq!(coin.height, 1);

    let view = core
        .txout(coin.outpoint)
        .expect("gettxout")
        .expect("unspent");
    assert_eq!(view.best_block, tip);
    assert_eq!((view.value, view.coinbase), (coin.value, true));
    assert_eq!(view.confirmations, 101);
    assert_eq!(view.script, vault_spk);

    let block = core
        .block_hash(coin.height)
        .expect("getblockhash")
        .expect("a block");
    let parent = core
        .block_transaction(coin.outpoint.txid, block)
        .expect("getrawtransaction")
        .expect("the full parent");
    assert_eq!(
        parent.compute_txid(),
        coin.outpoint.txid,
        "recomputed, not trusted"
    );
    assert_eq!(parent.output[coin.outpoint.vout as usize].value, coin.value);

    // Core's two absences, live. A height this chain does not have is `-8`; the same
    // txid qualified by a block that does not contain it is `-5`.
    assert_eq!(core.block_hash(9_999_999).expect("out of range"), None);
    let elsewhere = core.block_hash(2).expect("getblockhash").expect("a block");
    let absent = core
        .block_transaction(coin.outpoint.txid, elsewhere)
        .expect("a block-qualified miss is an absence, not a failure");
    assert_eq!(absent, None);

    // ...and the HTTP statuses those two absences ride on, MEASURED. The status term in
    // `reply` is what makes a coded absence status-coherent, so the numbers it is
    // calibrated against belong in a live assertion, not in a comment nobody re-checks.
    let statuses = [
        ("getblockhash", json!([9_999_999])),
        (
            "getrawtransaction",
            json!([coin.outpoint.txid.to_string(), false, elsewhere.to_string()]),
        ),
    ]
    .map(|(method, params)| node.status(method, params));
    assert_eq!(
        statuses,
        [500, 500],
        "Core's own statuses for the -8 and -5 refusals"
    );

    // Regtest has no fee history, so the estimate is genuinely absent — the fallback
    // path the rate is taken from — while both mandatory floors are present. This is
    // also the live `estimatesmartfee` OBJECT: a real daemon answers an object whose
    // `feerate` member is missing, which is exactly the shape the adapter's new
    // result-must-be-an-object gate has to keep accepting.
    let raw_estimate = node.call("estimatesmartfee", json!([6, "CONSERVATIVE"]));
    assert!(
        raw_estimate.is_object() && raw_estimate.get("feerate").is_none(),
        "a live no-estimate reply is an object with no feerate member: {raw_estimate}"
    );
    assert_eq!(core.fee_estimate().expect("estimatesmartfee"), None);
    // The floors are asserted as a ROUND TRIP against the BTC/kvB numbers this daemon
    // itself reports, not against a literal: Core's default relay floors have moved
    // between releases (this one answers 100 sat/kvB where older ones answered 1000), so
    // a pinned constant would couple this leg to a toolchain bump while proving less. The
    // measurement is still recorded — the assertion message carries what was observed.
    let reported = node.call("getmempoolinfo", json!([]));
    let sat_kvb = |field: &str| -> u64 {
        let btc = reported[field].as_f64().unwrap_or_else(|| {
            panic!("bitcoind reported no numeric {field}: {reported}");
        });
        Amount::from_btc(btc)
            .expect("a usable BTC/kvB floor")
            .to_sat()
    };
    let floors = core.fee_floors().expect("getmempoolinfo");
    assert_eq!(
        (floors.incremental_relay, floors.mempool_min),
        (sat_kvb("incrementalrelayfee"), sat_kvb("mempoolminfee")),
        "the adapter's sat/kvB floors are this daemon's own: {reported}"
    );
    // `fee_floors` requires both fields to be PRESENT and to parse as a usable `Amount`;
    // it does NOT require either to be positive, so read this as an observation about
    // this daemon and not as an adapter invariant. It is asserted because it is what
    // keeps the round trip above from passing vacuously on `0 == 0`.
    assert!(
        floors.incremental_relay > 0 && floors.mempool_min > 0,
        "{reported}"
    );

    // PRUNED history fails CLOSED, proved against Core's real code path rather than a
    // canned reply. A pruned node's block index entry has no data, and `submitheader`
    // creates exactly that state without needing a chain big enough to prune: Core then
    // answers a block-qualified `getrawtransaction` with RPC_MISC_ERROR "Block not
    // available (pruned data)" — NOT the `-5` this call declares absent — so the adapter
    // refuses terminally instead of reporting history that merely is not there.
    let dataless = headers_only_block(&node, info.best_block);
    let error = refusal(
        core.block_transaction(coin.outpoint.txid, dataless),
        "a block whose data this node does not have",
    );
    assert!(
        error.contains("core getrawtransaction (HTTP 500): refused: code Some(-1)"),
        "pruned block data must be terminal, with Core's own code: {error}"
    );
    assert!(
        !error.contains("pruned data"),
        "and without its text: {error}"
    );
}

/// A block Core knows the HEADER of and holds no DATA for, submitted on top of `tip`.
/// This is the same `BLOCK_HAVE_DATA`-missing state a pruned node is in for an old
/// block, and it is reachable on a small regtest chain, which real pruning is not:
/// `pruneblockchain` only ever discards whole block FILES below the one being written,
/// so a chain of a few hundred blocks has nothing it can prune.
fn headers_only_block(node: &Node, tip: bitcoin::BlockHash) -> bitcoin::BlockHash {
    use bitcoin::hashes::Hash as _;
    let parent = node.call("getblockheader", json!([tip.to_string()]));
    let time = parent["time"].as_u64().expect("a parent timestamp") + 1;
    let version = parent["version"].as_i64().expect("a parent version");
    let mut header = bitcoin::block::Header {
        // The PARENT's version, so this header cannot trip a version-gated soft fork.
        version: bitcoin::block::Version::from_consensus(
            i32::try_from(version).expect("a version"),
        ),
        prev_blockhash: tip,
        merkle_root: bitcoin::TxMerkleNode::from_byte_array([7u8; 32]),
        time: u32::try_from(time).expect("a timestamp"),
        // Regtest's own difficulty: the target is enormous, so a valid nonce is a few
        // tries away rather than a mining run.
        bits: bitcoin::CompactTarget::from_consensus(0x207f_ffff),
        nonce: 0,
    };
    for nonce in 0..10_000u32 {
        header.nonce = nonce;
        if header.validate_pow(header.target()).is_ok() {
            let hex = bitcoin::consensus::encode::serialize_hex(&header);
            node.call("submitheader", json!([hex]));
            let index = node.call("getblockheader", json!([header.block_hash().to_string()]));
            assert_eq!(
                index["nTx"],
                json!(0),
                "this header must reach Core with no block data behind it: {index}"
            );
            return header.block_hash();
        }
    }
    panic!("no regtest-valid nonce in 10,000 tries");
}

/// LIVE-2. A NONEMPTY inventory prepares against that same live view: the canonical coin
/// set, the canonical script triple with the vault change the seam derived for itself,
/// both preflighted maximum finalized sizes, the integer sat/vB rate taken from the
/// daemon's own floors, and the verified full parent Core itself returned — reachable
/// only through the completed-inventory accessor.
///
/// The pair built here is the FROZEN SKELETON at amounts this test chose. It is not a
/// composition: no output value is derived, no full parent or `SIGHASH_ALL` is attached,
/// and no signer runs. M3b owns all four.
#[test]
#[ignore = "spawns a regtest bitcoind; run with --ignored"]
fn a_live_core_prepares_the_nonempty_inventory_and_its_preflighted_pair() {
    let sealed = sealed_vault();
    let temp = fed::TempDir::new("core-view-inventory").expect("temp dir");
    let node = funded(&temp, &sealed.vault, 101);
    let view = sealed.prepare(&node.adapter()).expect("the live inventory");

    // The one funded coin, canonically, and the script triple the seam owns.
    assert_eq!(view.utxos().len(), 1, "exactly the one funded coin");
    let utxo = &view.utxos()[0];
    let coin = Amount::from_int_btc(50);
    assert_eq!(utxo.txout.value, coin, "a regtest coinbase");
    assert_eq!(utxo.txout.script_pubkey, sealed.change);
    assert_eq!(
        view.scripts(),
        &[
            sealed.destination.clone(),
            sealed.change.clone(),
            sealed.escape.clone()
        ]
    );

    // Both preflighted sizes, measured independently with the node's own bound, and the
    // live rate: regtest has no estimate, so the floors alone price it.
    let weight = sealed
        .vault
        .descriptor
        .max_weight_to_satisfy()
        .expect("weight")
        .to_wu();
    let [primary_vsize, escape_vsize] = view.preflight_vsizes();
    let floors = node.adapter().fee_floors().expect("getmempoolinfo");
    let expected = floors
        .incremental_relay
        .max(floors.mempool_min)
        .div_ceil(1000);
    assert_eq!(
        view.sat_per_vb(),
        expected,
        "the live floors, ceiled to integer sat/vB"
    );

    // The frozen skeleton, at amounts THIS TEST chose, over the prepared inputs.
    let amounts = [
        Amount::from_sat(1_000_000),
        Amount::from_sat(1_000_000),
        Amount::from_sat(2_000_000),
    ];
    let [spend, escape] = pair(&view, amounts).expect("the preflighted pair");
    assert_eq!(spend.unsigned_tx.output.len(), 2, "destination and change");
    assert_eq!(escape.unsigned_tx.output.len(), 1, "one escape output");
    for (label, psbt, vsize) in [
        ("primary", &spend, primary_vsize),
        ("escape", &escape, escape_vsize),
    ] {
        let tx = &psbt.unsigned_tx;
        assert_eq!(tx.input.len(), 1, "{label}");
        assert_eq!(tx.input[0].previous_output, utxo.outpoint, "{label}");
        assert_eq!(tx.input[0].sequence, Sequence::MAX, "{label}");
        assert_eq!(
            view.finalized_vsize(tx).expect("vsize"),
            vsize,
            "{label} keeps its preflighted size"
        );
        assert_eq!(
            vault_node::maximum_finalized_vsize_for(weight, tx).expect("vsize"),
            vsize,
            "{label}, measured independently"
        );
        for input in &psbt.inputs {
            assert_eq!(input.witness_utxo.as_ref(), Some(&utxo.txout), "{label}");
            assert!(input.witness_script.is_some(), "{label}");
            // M3b's two attachments are NOT this child's, live or otherwise.
            assert!(input.non_witness_utxo.is_none(), "{label}");
            assert!(input.sighash_type.is_none(), "{label}");
        }
    }

    // The verified full parent is Core's own, reachable only through the accessor.
    let parent: Transaction = view
        .inventory()
        .full_parent(utxo.outpoint.txid)
        .expect("the verified full parent");
    assert_eq!(parent.compute_txid(), utxo.outpoint.txid);
    assert_eq!(parent.output[utxo.outpoint.vout as usize].value, coin);
    let raw = node.call(
        "getrawtransaction",
        json!([utxo.outpoint.txid.to_string(), false, view_block(&node, 1)]),
    );
    assert_eq!(
        bitcoin::consensus::encode::serialize_hex(&parent),
        raw.as_str().expect("hex"),
        "byte-for-byte what this daemon returned"
    );

    // Nothing here broadcasts: the coin is still unspent in Core's own UTXO set.
    let params = json!([utxo.outpoint.txid.to_string(), utxo.outpoint.vout, true]);
    assert!(
        !node.call("gettxout", params).is_null(),
        "no broadcast may have happened"
    );
    assert_eq!(node.call("getmempoolinfo", json!([]))["size"], json!(0));
}

/// The hash of the block at `height`, as this daemon reports it.
fn view_block(node: &Node, height: u64) -> String {
    node.call("getblockhash", json!([height]))
        .as_str()
        .expect("a block hash")
        .to_string()
}

/// LIVE-3. Coinbase maturity turns at exactly 100 confirmations against real chain
/// state: at 99 the whole inventory is refused, and one block later the same vault
/// prepares. Equality passes.
#[test]
#[ignore = "spawns a regtest bitcoind; run with --ignored"]
fn a_coinbase_vault_coin_is_refused_at_99_confirmations_and_prepares_at_100() {
    let sealed = sealed_vault();
    let temp = fed::TempDir::new("core-view-maturity").expect("temp dir");
    let node = funded(&temp, &sealed.vault, 99);
    let error = refusal(
        sealed.prepare(&node.adapter()),
        "a 99-confirmation coinbase",
    );
    assert!(error.contains("immature coinbase at 99 of 100"), "{error}");

    let (_, throwaway) = addresses(&sealed.vault);
    node.generate(1, &throwaway);
    sealed
        .prepare(&node.adapter())
        .expect("exactly 100 confirmations is mature");
}

/// LIVE-4. A real backend still in initial block download is refused before anything is
/// scanned: a fresh regtest daemon reports `initialblockdownload: true` until its first
/// block, and its confirmed vault view is not something to prepare against.
#[test]
#[ignore = "spawns a regtest bitcoind; run with --ignored"]
fn a_backend_in_initial_block_download_is_refused_before_the_scan() {
    let sealed = sealed_vault();
    let temp = fed::TempDir::new("core-view-ibd").expect("temp dir");
    let node = Node::start("regtest", temp.path.join("ibd"), &["-fallbackfee=0.0002"]);
    let core = node.adapter();
    assert!(
        core.chain_info()
            .expect("getblockchaininfo")
            .initial_block_download,
        "a fresh regtest chain is in initial block download"
    );
    let error = refusal(sealed.prepare(&core), "an IBD backend");
    assert!(error.contains("initial block download"), "{error}");

    let (vault_address, throwaway) = addresses(&sealed.vault);
    node.generate(1, &vault_address);
    node.generate(100, &throwaway);
    assert!(
        !core
            .chain_info()
            .expect("getblockchaininfo")
            .initial_block_download
    );
    sealed
        .prepare(&core)
        .expect("the same backend prepares once its chain view is current");
}

/// LIVE-5. The cookie is a PATH the adapter re-reads per call, under child A's
/// owner-only rules, and no live refusal — including one Core itself issues — prints it.
#[test]
#[ignore = "spawns a regtest bitcoind; run with --ignored"]
fn the_live_cookie_is_re_read_per_call_and_no_refusal_prints_it() {
    let temp = fed::TempDir::new("core-view-cookie").expect("temp dir");
    let node = Node::start(
        "regtest",
        temp.path.join("cookie"),
        &["-fallbackfee=0.0002"],
    );
    let core = node.adapter();
    core.best_block_hash().expect("the control");
    let secret = std::fs::read_to_string(node.cookie()).expect("the live cookie");
    let password = secret.trim().to_string();

    // Child A's rules apply to Core's own cookie file: loosening its mode stops the
    // NEXT call, which a credential cached at construction would sail through.
    let loose = std::fs::Permissions::from_mode(0o644);
    std::fs::set_permissions(node.cookie(), loose).expect("mode");
    let error = core
        .best_block_hash()
        .expect_err("a world-readable cookie is refused")
        .to_string();
    assert!(error.contains("mode 0644"), "{error}");
    std::fs::set_permissions(node.cookie(), std::fs::Permissions::from_mode(0o600)).expect("mode");
    core.best_block_hash()
        .expect("restoring the mode restores the call");

    // A credential this daemon does not know: Core answers 401, and the diagnostic
    // names neither the offered password nor the real one.
    let wrong = temp.path.join("wrong.cookie");
    std::fs::write(&wrong, "__cookie__:wrong-XcVb0192").expect("write");
    std::fs::set_permissions(&wrong, std::fs::Permissions::from_mode(0o600)).expect("mode");
    let refused = CoreRpc::new(node.addr, wrong)
        .expect("adapter")
        .best_block_hash()
        .expect_err("Core rejects an unknown credential")
        .to_string();
    for leak in [password.as_str(), "wrong-XcVb0192"] {
        assert!(
            !refused.contains(leak),
            "a diagnostic printed a credential: {refused}"
        );
        assert!(
            !error.contains(leak),
            "a diagnostic printed a credential: {error}"
        );
    }
}

/// LIVE-6. The default PUBLIC signet daemon's own `signet_challenge` is what the sealed
/// network code means, and a custom signet — same `chain:"signet"`, different chain — is
/// refused. Both daemons are offline and unsynced; only their identity is read.
#[test]
#[ignore = "spawns two offline signet bitcoind instances; run with --ignored"]
fn a_live_default_signet_is_bound_to_its_challenge_and_a_custom_one_is_refused() {
    let temp = fed::TempDir::new("core-view-signet").expect("temp dir");
    let public = Node::start("signet", temp.path.join("public"), &[]);
    let identity = public
        .adapter()
        .chain_info()
        .expect("getblockchaininfo")
        .identity;
    assert_eq!(identity["chain"], json!("signet"));
    assert_eq!(
        identity["signet_challenge"].as_str(),
        Some(vault_node::chain::PUBLIC_SIGNET_CHALLENGE),
        "the live default-signet daemon's own challenge"
    );
    vault_node::chain::verify_chain_identity(&identity, Network::Signet)
        .expect("a vault sealed to the public signet accepts it");

    // OP_TRUE: a valid script, and emphatically not the public signet's.
    let custom = Node::start("signet", temp.path.join("custom"), &["-signetchallenge=51"]);
    let identity = custom
        .adapter()
        .chain_info()
        .expect("getblockchaininfo")
        .identity;
    assert_eq!(
        identity["chain"],
        json!("signet"),
        "it still calls itself signet"
    );
    let error = vault_node::chain::verify_chain_identity(&identity, Network::Signet)
        .expect_err("a custom signet must be refused")
        .to_string();
    assert!(error.contains("CUSTOM signet"), "{error}");
}

/// The Core cookie password class 19 selects, and the exact text the hostile endpoint
/// echoes back at it. A txid is 32 bytes, so a 64-hex password IS a syntactically valid
/// one — nothing downstream can reject it as malformed, which is the whole premise.
const REFLECTED: &str = "9f2b7c41e8d05a36bb14fe902c7d83a51609e4bd77cf2a08e35db461cc9017fa";

/// One WHOLE request off a stream: the head, then exactly the body length it declares. A
/// single `read` may return a prefix even on loopback, so reading once would make this
/// fixture pass by luck rather than by framing.
fn whole_request(stream: &mut std::net::TcpStream) -> String {
    use std::io::Read as _;
    let mut raw = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte) {
            Ok(1) => raw.push(byte[0]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            _ => panic!("the request head never finished: {raw:?}"),
        }
        if raw.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let len: usize = String::from_utf8_lossy(&raw)
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

/// A HOSTILE loopback endpoint: it answers Core's SUCCESS envelope from a script of
/// `result` values, echoes back whichever request id it was sent, and records every raw
/// request — head and body — so the credential it received can be read off the wire
/// rather than assumed. It spawns no daemon, which is why class 19 is not `#[ignore]`d.
fn hostile(results: Vec<Value>) -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
    let addr = listener.local_addr().expect("addr");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&requests);
    std::thread::spawn(move || {
        for result in results {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let raw = whole_request(&mut stream);
            let body = raw.split("\r\n\r\n").nth(1).expect("a request body");
            let request: Value = serde_json::from_str(body).expect("a JSON request");
            recorded.lock().expect("lock").push(raw.clone());
            let reply =
                json!({"result": result, "error": Value::Null, "id": request["id"]}).to_string();
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                reply.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(reply.as_bytes());
        }
    });
    (addr, requests)
}

/// 19. A hostile loopback Core cannot REFLECT the credential it was just handed into an
///     inventory diagnostic through a VALID typed identifier. Classes 18a/18b close the
///     `getblockchaininfo` half of this channel; this is the other half, and the one a
///     redaction of error TEXT does not reach: the endpoint here answers an entirely
///     well-formed, correctly typed, HTTP 200 `scantxoutset` whose `txid` is the exact
///     64-hex cookie password it read out of the `Authorization: Basic` head it was sent.
///     That value is decoded, sorted and carried through the seam as a real `Txid` — the
///     bracket even asks Core about it — and what must never come back out is the
///     identifier itself. Driven through the REAL `CoreRpc` over a real owner-only cookie
///     file, so what is exercised is the adapter/inventory boundary and not a helper.
///     `m50` restores one raw interpolation and this class goes red.
#[test]
fn a_hostile_core_cannot_reflect_the_cookie_password_through_a_valid_typed_identifier() {
    let sealed = sealed_vault();
    let temp = fed::TempDir::new("core-view-reflection").expect("temp dir");
    let secret = format!("__cookie__:{REFLECTED}");
    let cookie = temp.path.join("core.cookie");
    // Written the way Core writes one: a single line with a trailing newline.
    std::fs::write(&cookie, format!("{secret}\n")).expect("write");
    std::fs::set_permissions(&cookie, std::fs::Permissions::from_mode(0o600)).expect("mode");
    let credential = BASE64_STANDARD.encode(&secret);

    let echoed: bitcoin::Txid = REFLECTED
        .parse()
        .expect("a 64-hex password is a valid txid");
    assert_eq!(
        echoed.to_string(),
        REFLECTED,
        "and it prints back unchanged"
    );

    let tip = "11".repeat(32);
    let vault_spk = sealed.vault.descriptor.script_pubkey();
    let identity = json!({
        "chain": "regtest",
        "initialblockdownload": false,
        "bestblockhash": tip,
    });
    let record = json!({
        "txid": REFLECTED,
        "vout": 0,
        "amount": 0.001,
        "scriptPubKey": format!("{vault_spk:x}"),
        "height": 411,
    });
    let scan = |unspents: Value| json!({"success": true, "bestblock": tip, "unspents": unspents});

    let worlds: [(&str, Vec<Value>, &str); 2] = [
        // The reflected txid arrives TWICE, so the duplicate-record refusal runs.
        (
            "a duplicated reflected scan record",
            vec![identity.clone(), scan(json!([record, record]))],
            "scantxoutset reported one outpoint twice",
        ),
        // It arrives once and is honest all the way to a `gettxout` that answers null
        // under an unmoved tip, so the whole-inventory coverage refusal runs.
        (
            "a reflected scan record whose coin is gone from the UTXO set",
            vec![identity, scan(json!([record])), Value::Null, json!(tip)],
            "spent in the mempool or otherwise unavailable",
        ),
    ];
    for (what, replies, remedy) in worlds {
        let calls = replies.len();
        let (addr, requests) = hostile(replies);
        let core = CoreRpc::new(addr, cookie.clone()).expect("a loopback adapter");
        let error = refusal(sealed.prepare(&core), what);

        // The endpoint really was handed the credential, on the wire. Without this,
        // "it did not leak" would also be true of an endpoint that never had it.
        let seen = requests.lock().expect("lock").clone();
        assert_eq!(seen.len(), calls, "{what}: {seen:?}");
        assert!(
            seen[0].contains(&format!("Authorization: Basic {credential}\r\n")),
            "the hostile endpoint must see the Basic auth head: {what}"
        );
        // Where the bracket got past the scan, the peer's own value went back OUT as a
        // live typed identifier — preserved internally, and withheld only at the
        // operator boundary. Where it did not, nothing after the scan names it either.
        let forwarded = seen.iter().skip(2).any(|raw| raw.contains(REFLECTED));
        assert_eq!(forwarded, calls > 2, "{what}: {seen:?}");

        // The refusal carries neither the password nor the encoded credential. This
        // stands AHEAD of the remedy check on purpose: an assertion aborts its class,
        // `m50` restores the interpolation that also rewords the refusal, and a remedy
        // check reached first would swallow the mutation and leave the leak unobserved.
        for leak in [REFLECTED, credential.as_str()] {
            assert!(
                !error.contains(leak),
                "{what} reflected the credential into the diagnostic: {error}"
            );
        }
        // And redaction did not empty it: what went wrong is still there, in this seam's
        // own words.
        assert!(error.contains(remedy), "{what}: {error}");
    }
}
