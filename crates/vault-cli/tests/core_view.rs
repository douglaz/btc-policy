//! Opt-in LIVE-bitcoind suite for the stage-1 Core seam and the inventory it feeds (bead
//! btc-policy-m3a-core-view-inventory-rha). Every LIVE class here spawns real daemons the
//! way the backend suite does, so all of them are `#[ignore]`d and opted into together:
//!
//!   nix develop -c cargo test --locked -p vault-cli --test core_view -- --ignored --test-threads=1
//!
//! Two groups are deliberately outside that set and run in the ordinary
//! `cargo test --workspace` gate. Class 19 drives the same real `CoreRpc` against a
//! SCRIPTED HOSTILE listener rather than a daemon, so it is neither slow nor opt-in; it
//! lives here because this is the only target that can reach `CoreRpc` and `prepare_view`
//! together. And the M3b COMPOSITION classes at the foot of this file
//! (`btc-policy-m3b-spend-composition-nq8`) answer a typed in-process fake Core. They are
//! here by the owner's DELIBERATE choice, not by necessity: every new M3b test is kept
//! under `tests/`, which is what keeps it outside the production-only line budget, and this
//! target includes the composer, the inventory, the sealed vault and the real
//! `SoftwareSigner` together. An in-crate `#[cfg(test)]` module inside `compose.rs` could
//! reach the same items; it would only move them to the wrong side of that budget, which is
//! why `compose.rs` carries none. LIVE-7 is the single M3b class that
//! is NOT in that group: it is `#[ignore]`d with the live suite above and needs a daemon.
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
//! The LIVE-1 to LIVE-6 classes claim none of M3b's work: the pair each of them builds is
//! the FROZEN SKELETON at caller-supplied amounts, with no derived output value, no full
//! parent, no `SIGHASH_ALL` and no signer. LIVE-7 is the one that does — it composes real
//! values against a real daemon, attaches every verified full parent and explicit
//! `SIGHASH_ALL`, signs through the real `SoftwareSigner`, and proves Core's UTXO set and
//! mempool are untouched afterwards.
//!
//! `vault-cli` is a BINARY crate, so an integration test cannot link its modules; they
//! are included here at their own paths instead. That pulls in each module's unit tests
//! as well, which run in this target too — harmless duplication, and the `--ignored`
//! invocation above selects only the live tests below.

#![allow(dead_code, unused_imports)]

#[path = "../src/http.rs"]
mod http;
// The order below is declaration only; Rust resolves the cycle between these itself.
#[path = "../src/compose.rs"]
mod compose;
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
    /// The owner-only user scalar file LIVE-7 hands the real [`signer::SoftwareSigner`].
    user_key: PathBuf,
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
    let user_key = owner_only_user_key(&temp);
    Vault {
        destination: definite(&vault.check_params.allowed[0], 0),
        change: vault.descriptor.script_pubkey(),
        escape: definite(escape, 0),
        _ceremony: ceremony,
        _temp: temp,
        vault,
        user_key,
    }
}

/// The user scalar the ceremony fixture seals into the vault descriptor (`keypair(1)` in
/// `setup.rs`), written the way the real signer demands it: one owner-only regular file.
fn owner_only_user_key(temp: &fed::TempDir) -> PathBuf {
    let path = temp.path.join("user.secret");
    std::fs::write(&path, format!("{}\n", "01".repeat(32))).expect("write");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("mode");
    path
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

// =====================================================================================
// M3b — the dormant deterministic Spend + mandatory base-Escape composition
// (bead btc-policy-m3b-spend-composition-nq8).
//
// Every NUMBERED class below runs IN PROCESS, and so does the unnumbered dormancy class: a
// typed fake answers M3a's eight closed reads, M3a's own `prepare_view` and `pair` run for
// real, and what is under test is `compose_spend` — the final output values, the sealed
// Escape floor, dust and coverage, every verified full parent, explicit `SIGHASH_ALL`, the
// final Hot/Escape verdict, and the frozen authorization the real `SoftwareSigner` then
// accepts. `LIVE-7`, at the very foot of this file, is the ONE exception: like the LIVE
// classes above it is `#[ignore]`d and spawns a real regtest daemon, and it runs in CI's
// core-view leg rather than in `cargo test --workspace`. M3a's own classes — the frozen
// skeleton, the inventory bracket, adapter class 4A-primary and 4A-precision — live in
// `src/inventory.rs` and `src/core_view.rs` and are deliberately not restated here.
//
// The NUMBERS below are the bead's, not a local sequence: M3b owns exactly classes 1
// (integration), 3, 4B, 5 (integration), 6, 7, 8, 9 and 16, so an audit against the bead
// resolves one-to-one. Everything from 10 through 15 is M3a's own — 10, 11, 12, 13, 14, 15,
// 15b and 15c in `src/inventory.rs` — and appears nowhere here; 16 is the slot M3a's list
// leaves between 15c and 17. The dormancy class at the end is required evidence but carries
// no number, because the bead assigns it none, and `LIVE-7` carries the live sequence's.
// =====================================================================================

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::sync::OnceLock;

use bitcoin::{BlockHash, EcdsaSighashType, Psbt, TxIn, TxOut, Txid, Witness};
use policy_core::TxClass;

use crate::compose::{base_escape_script, compose_spend};
use crate::core_view::{ChainInfo, Floors, Scan, ScanCoin, TxOutView};
use crate::signer::{SoftwareSigner, UserAuthorization, UserSigner};

/// One vault coin, and the scanned confirmation height every fake coin carries.
const COIN: u64 = 1_000_000;
const HEIGHT: u32 = 411;

/// A still, honest, read-only chain: one tip that never moves, a confirmed non-coinbase
/// vault set, and the fee signals the composition classes need. Every call is recorded
/// in order, so a class can pin what was issued and what never was.
struct Chain {
    tip: BlockHash,
    coins: Vec<ScanCoin>,
    parents: BTreeMap<Txid, Transaction>,
    /// `estimatesmartfee`, in sat/kvB. `None` is Core's honest "no estimate".
    estimate: Option<u64>,
    /// `(incrementalrelayfee, mempoolminfee)`, in sat/kvB.
    floors: (u64, u64),
    log: RefCell<Vec<String>>,
}

fn block(byte: u8) -> BlockHash {
    use bitcoin::hashes::Hash as _;
    BlockHash::from_byte_array([byte; 32])
}

/// A previous transaction paying `value` to `spk`, made unique by `tag`.
fn prevtx(tag: u32, spk: &ScriptBuf, value: u64) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::from_consensus(tag),
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            script_pubkey: spk.clone(),
            value: Amount::from_sat(value),
        }],
    }
}

impl Chain {
    /// A vault funded by one confirmed coin per entry of `values`, each from its own
    /// parent.
    fn holding(vault_spk: &ScriptBuf, values: &[u64]) -> Chain {
        let mut coins = Vec::new();
        let mut parents = BTreeMap::new();
        for (tag, value) in values.iter().enumerate() {
            let parent = prevtx(tag as u32, vault_spk, *value);
            let txid = parent.compute_txid();
            coins.push(ScanCoin {
                outpoint: OutPoint { txid, vout: 0 },
                value: Amount::from_sat(*value),
                script: vault_spk.clone(),
                height: HEIGHT,
            });
            parents.insert(txid, parent);
        }
        Chain {
            tip: block(0x11),
            coins,
            parents,
            estimate: None,
            // 1000 sat/kvB on both floors is 1 sat/vB after M3a's ceiling conversion. A
            // round fixture number, not a claim about any daemon's default.
            floors: (1_000, 1_000),
            log: RefCell::new(Vec::new()),
        }
    }

    fn note(&self, call: &str) {
        self.log.borrow_mut().push(call.to_string());
    }

    fn calls(&self) -> Vec<String> {
        self.log.borrow().clone()
    }
}

impl CoreView for Chain {
    fn chain_info(&self) -> Result<ChainInfo, Error> {
        self.note("getblockchaininfo");
        Ok(ChainInfo {
            identity: json!({"chain": "regtest"}),
            initial_block_download: false,
            best_block: self.tip,
        })
    }

    fn best_block_hash(&self) -> Result<BlockHash, Error> {
        self.note("getbestblockhash");
        Ok(self.tip)
    }

    fn scan_vault_script(&self, _script: &ScriptBuf) -> Result<Scan, Error> {
        self.note("scantxoutset");
        let coins = self
            .coins
            .iter()
            .map(|coin| ScanCoin {
                outpoint: coin.outpoint,
                value: coin.value,
                script: coin.script.clone(),
                height: coin.height,
            })
            .collect();
        Ok(Scan {
            best_block: self.tip,
            coins,
        })
    }

    fn txout(&self, outpoint: OutPoint) -> Result<Option<TxOutView>, Error> {
        self.note("gettxout");
        let coin = self
            .coins
            .iter()
            .find(|coin| coin.outpoint == outpoint)
            .ok_or("the fake holds no such coin")?;
        Ok(Some(TxOutView {
            best_block: self.tip,
            confirmations: 6,
            value: coin.value,
            script: coin.script.clone(),
            coinbase: false,
        }))
    }

    fn block_hash(&self, _height: u32) -> Result<Option<BlockHash>, Error> {
        self.note("getblockhash");
        Ok(Some(block(0x77)))
    }

    fn block_transaction(
        &self,
        txid: Txid,
        _block: BlockHash,
    ) -> Result<Option<Transaction>, Error> {
        self.note("getrawtransaction");
        Ok(self.parents.get(&txid).cloned())
    }

    fn fee_estimate(&self) -> Result<Option<u64>, Error> {
        self.note("estimatesmartfee");
        Ok(self.estimate)
    }

    fn fee_floors(&self) -> Result<Floors, Error> {
        self.note("getmempoolinfo");
        Ok(Floors {
            incremental_relay: self.floors.0,
            mempool_min: self.floors.1,
        })
    }
}

/// ONE sealed artifact set and ONE owner-only user-key file for every composition class:
/// provisioning a federation is expensive and identical for all of them, so each class
/// RE-LOADS the artifacts the production ceremony wrote rather than re-running it. A
/// `OnceLock` never drops, so these directories deliberately outlive the test binary.
struct Composing {
    _ceremony: setup::tests::Ceremony,
    _temp: fed::TempDir,
    artifacts: PathBuf,
    user_key: PathBuf,
}

fn composing() -> &'static Composing {
    static COMPOSING: OnceLock<Composing> = OnceLock::new();
    COMPOSING.get_or_init(|| {
        let ceremony = setup::tests::ceremony_through_endorse(3, 2);
        ceremony.finalize().expect("finalize");
        let artifacts = ceremony.sealed("backup");
        let temp = fed::TempDir::new("compose").expect("temp dir");
        let user_key = owner_only_user_key(&temp);
        Composing {
            _ceremony: ceremony,
            _temp: temp,
            artifacts,
            user_key,
        }
    })
}

/// The three scripts a composition ends up paying, all read out of the sealed vault.
struct Wallets {
    change: ScriptBuf,
    escape: ScriptBuf,
    hot: ScriptBuf,
}

/// A freshly loaded sealed vault, so a class may move `escape_feerate_floor` or
/// `escape_coverage_pct` without leaking into the next one.
fn sealed_composer() -> (LiveVault, Wallets) {
    let vault = LiveVault::load_artifacts(&composing().artifacts).expect("the sealed set");
    let escape = vault.check_params.escape.as_ref().expect("an escape");
    let wallets = Wallets {
        change: vault.descriptor.script_pubkey(),
        escape: definite(escape, 0),
        hot: definite(&vault.check_params.allowed[0], 0),
    };
    (vault, wallets)
}

/// The hot-allowlist address at `index`, as an operator would type it.
fn hot_address(vault: &LiveVault, index: u32) -> String {
    address(
        &definite(&vault.check_params.allowed[0], index),
        vault.network,
    )
}

fn composed(vault: &LiveVault, chain: &Chain, destination: &str, amount: u64) -> UserAuthorization {
    compose_spend(vault, chain, destination, Amount::from_sat(amount))
        .unwrap_or_else(|e| panic!("the composition must succeed: {e}"))
}

fn compose_refusal(
    vault: &LiveVault,
    chain: &Chain,
    destination: &str,
    amount: u64,
    what: &str,
) -> String {
    match compose_spend(vault, chain, destination, Amount::from_sat(amount)) {
        Ok(_) => panic!("{what} must be refused"),
        Err(error) => error.to_string(),
    }
}

/// The composition, put through the REAL M2 signer: it re-derives every input from its
/// ATTACHED full previous transaction, re-runs `policy_core`, and returns the signed group
/// in `[primary, escape, rung…]` order. An empty ladder is therefore exactly two members.
fn authorized(vault: &LiveVault, req: &UserAuthorization) -> (String, Vec<Psbt>) {
    let mut signer =
        SoftwareSigner::load_file(vault, &composing().user_key).expect("the sealed user key");
    signer
        .authorize(req)
        .unwrap_or_else(|e| panic!("the real signer must accept this composition: {e}"))
        .into_parts()
}

/// Σ inputs − Σ outputs, over the PSBT's own canonical prevouts.
fn fee_of(psbt: &Psbt) -> u64 {
    let held: u64 = psbt
        .inputs
        .iter()
        .map(|map| map.witness_utxo.as_ref().expect("a prevout").value.to_sat())
        .sum();
    let paid: u64 = psbt
        .unsigned_tx
        .output
        .iter()
        .map(|out| out.value.to_sat())
        .sum();
    held - paid
}

fn value_of(psbt: &Psbt, output: usize) -> u64 {
    psbt.unsigned_tx.output[output].value.to_sat()
}

/// Both preflighted maximum finalized sizes for a vault holding `values`, taken from M3a
/// itself. The composer never supplies them, so the fees below are hand-computed from
/// M3a's numbers rather than measured with the composer's own arithmetic.
fn preflight(vault: &LiveVault, w: &Wallets, values: &[u64]) -> [u64; 2] {
    let chain = Chain::holding(&w.change, values);
    prepare_view(
        &chain,
        vault.network,
        &vault.descriptor,
        [&w.hot, &w.change, &w.escape],
    )
    .expect("a scratch view")
    .preflight_vsizes()
}

/// 1. The whole composition, end to end, accepted by the REAL `SoftwareSigner`: exactly
///    two members and an empty ladder, the requested amount paid EXACTLY, mandatory vault
///    change, a one-output base Escape sweeping the same coins, every input map of BOTH
///    PSBTs carrying its verified full previous transaction and an EXPLICIT ECDSA
///    `SIGHASH_ALL`, and no BIP32 origin invented anywhere.
#[test]
fn the_composed_pair_carries_every_full_parent_and_explicit_sighash_all_and_m2_accepts_it() {
    let (vault, w) = sealed_composer();
    // The Escape floor `LiveVault` carries, pinned where the fees below depend on it: at
    // the sealed 1 sat/vB it never raises M3a's own rate, so each shape pays exactly its
    // own vsize. Class 8 pins the other field M3b added against its own arithmetic.
    assert_eq!(vault.escape_feerate_floor, 1, "the sealed escape floor");
    let [primary_vsize, escape_vsize] = preflight(&vault, &w, &[COIN, COIN / 2]);
    let chain = Chain::holding(&w.change, &[COIN, COIN / 2]);
    let amount = 250_000;
    let request = composed(&vault, &chain, &hot_address(&vault, 0), amount);
    let (display, members) = authorized(&vault, &request);
    assert_eq!(members.len(), 2, "an empty ladder is exactly two members");
    let (primary, escape) = (&members[0], &members[1]);

    let total = COIN + COIN / 2;
    let primary_fee = primary_vsize;
    let escape_fee = escape_vsize;
    assert_eq!(value_of(primary, 0), amount, "the exact requested amount");
    assert_eq!(value_of(primary, 1), total - amount - primary_fee);
    assert_eq!(
        primary.unsigned_tx.output.len(),
        2,
        "destination and change"
    );
    assert_eq!(
        primary.unsigned_tx.output[0].script_pubkey, w.hot,
        "the parsed destination"
    );
    assert_eq!(primary.unsigned_tx.output[1].script_pubkey, w.change);
    assert_eq!(escape.unsigned_tx.output.len(), 1, "one escape output");
    assert_eq!(escape.unsigned_tx.output[0].script_pubkey, w.escape);
    assert_eq!(value_of(escape, 0), total - escape_fee);
    assert_eq!(fee_of(primary), primary_fee);
    assert_eq!(fee_of(escape), escape_fee);

    // The same ordered coins under both shapes, and BOTH of M3b's attachments on EVERY
    // input map of BOTH transactions — with no BIP32 origin invented for any of them.
    let spent: Vec<OutPoint> = primary
        .unsigned_tx
        .input
        .iter()
        .map(|input| input.previous_output)
        .collect();
    let swept: Vec<OutPoint> = escape
        .unsigned_tx
        .input
        .iter()
        .map(|input| input.previous_output)
        .collect();
    assert_eq!(spent.len(), 2, "both prepared coins");
    assert_eq!(spent, swept, "both shapes spend the same ordered set");
    for (label, psbt) in [("primary", primary), ("escape", escape)] {
        for (index, map) in psbt.inputs.iter().enumerate() {
            let outpoint = psbt.unsigned_tx.input[index].previous_output;
            let parent = map
                .non_witness_utxo
                .as_ref()
                .unwrap_or_else(|| panic!("{label} input {index} has no full parent"));
            assert_eq!(parent.compute_txid(), outpoint.txid, "{label} {index}");
            assert_eq!(
                map.sighash_type,
                Some(EcdsaSighashType::All.into()),
                "{label} input {index} must declare SIGHASH_ALL explicitly"
            );
            assert!(
                map.bip32_derivation.is_empty(),
                "{label} input {index} invented a BIP32 origin"
            );
            assert_eq!(map.partial_sigs.len(), 1, "{label} {index} is user-signed");
        }
        for out in &psbt.outputs {
            assert!(out.bip32_derivation.is_empty(), "{label} output origin");
        }
    }

    // The two derived classes, and the operator display the signer rendered from them.
    let classify = |psbt: &Psbt| {
        policy_core::classify(psbt, &vault.check_params)
            .expect("a class")
            .class
    };
    assert_eq!(classify(primary), TxClass::Hot);
    assert_eq!(classify(escape), TxClass::Escape);
    assert!(
        display.contains("primary hot-destination transaction"),
        "{display}"
    );
    assert!(
        display.contains("escape-destination transaction"),
        "{display}"
    );
}

/// 3. The base Escape script is derivation index 0 of the FIRST canonical branch of the
///    sealed escape descriptor, multipath or not, with NO address-index state: the same
///    vault composes to the same script every time. A genuine BIP389 `<0;1>` descriptor is
///    the case that matters, because its two branches produce different scripts and only
///    one of them is the base.
#[test]
fn the_base_escape_is_index_zero_of_the_first_canonical_branch_and_repeats() {
    let (vault, w) = sealed_composer();
    let sealed = vault.check_params.escape.as_ref().expect("an escape");
    assert_eq!(
        base_escape_script(sealed).expect("the sealed escape"),
        w.escape,
        "the sealed single-path escape derives its own index 0"
    );

    // The SAME key, respelled as a real multipath descriptor. `into_single_descriptors`
    // expands it to two, and the composer must take the first. The trailing `#checksum`
    // is dropped rather than recomputed: miniscript accepts a descriptor without one, and
    // carrying the old one over a respelled body is what a checksum exists to catch.
    let single = sealed.to_string();
    let single = single
        .split_once('#')
        .map_or(single.clone(), |(body, _)| body.to_string());
    let multi: Descriptor<DescriptorPublicKey> = single
        .replace("/*)", "/<0;1>/*)")
        .parse()
        .expect("a multipath escape descriptor");
    assert_eq!(
        multi
            .clone()
            .into_single_descriptors()
            .expect("branches")
            .len(),
        2,
        "this fixture must really be multipath: {multi}"
    );
    // Both branches, spelled out independently rather than read back through the same
    // expansion the production helper uses.
    let branch = |n: u32| -> ScriptBuf {
        let text = single.replace("/*)", &format!("/{n}/*)"));
        let descriptor: Descriptor<DescriptorPublicKey> = text.parse().expect("a branch");
        definite(&descriptor, 0)
    };
    let derived = base_escape_script(&multi).expect("the multipath escape");
    assert_eq!(derived, branch(0), "the FIRST canonical branch, at index 0");
    assert_ne!(derived, branch(1), "the second branch is not the base");
    assert_eq!(
        base_escape_script(&multi).expect("again"),
        derived,
        "no address index state: the same descriptor composes the same script"
    );
}

/// 4B. The primary is priced at M3a's own integer sat/vB rate; the base Escape is priced at
///     `primary_rate.max(sealed escape_feerate_floor)`. Each is then multiplied by ITS OWN
///     preflighted vsize, so the two fees differ by shape as well as by rate. Adapter class
///     4A-primary owns how that primary rate is derived from Core's signals — including the
///     ABSENT-estimate fallback, which is why every row here states an explicit estimate
///     rather than restating that case; this class owns only what the composer does with the
///     rate afterwards.
///
///     The last row is the ZERO one, and it is pinned rather than incidental: a node whose
///     estimate and both floors are all zero hands the composer a zero sat/vB rate, and with
///     a zero sealed floor BOTH shapes pay nothing. The composer and the REAL signer accept
///     that pair. It is the bead's named liveness/non-relay residual — a pair that may not
///     relay redirects no value — and neither this class nor `compose.rs` invents a positive
///     floor to make it go away.
#[test]
fn the_sealed_escape_floor_maxes_the_primary_rate_and_each_shape_pays_its_own_size() {
    let (mut vault, w) = sealed_composer();
    let [primary_vsize, escape_vsize] = preflight(&vault, &w, &[COIN]);
    assert!(
        escape_vsize < primary_vsize,
        "one output is the smaller shape"
    );
    // (estimate sat/kvB, both node floors sat/kvB, sealed floor sat/vB) -> (primary, escape)
    let rows: [(Option<u64>, u64, u64, u64, u64); 5] = [
        // A sealed floor UNDER the primary rate never lowers it.
        (Some(6_000), 1_000, 2, 6, 6),
        // A sealed floor OVER it raises the escape alone.
        (Some(1_000), 1_000, 9, 1, 9),
        // Equality: the max is that same number either way.
        (Some(4_000), 1_000, 4, 4, 4),
        // A zero sealed floor is the node's own liveness rate, not a policy of its own.
        (Some(3_000), 1_000, 0, 3, 3),
        // And that rate is itself ZERO when the node reports zero on every signal: both
        // shapes pay nothing, and the pair still composes and signs.
        (Some(0), 0, 0, 0, 0),
    ];
    let amount = 100_000;
    for (estimate, node_floor, sealed_floor, primary_rate, escape_rate) in rows {
        let mut chain = Chain::holding(&w.change, &[COIN]);
        chain.estimate = estimate;
        chain.floors = (node_floor, node_floor);
        vault.escape_feerate_floor = sealed_floor;
        // Isolated from the coverage predicate, which these rows are not about.
        vault.escape_coverage_pct = 0;
        let request = composed(&vault, &chain, &hot_address(&vault, 0), amount);
        let (_, members) = authorized(&vault, &request);
        let row = format!("{estimate:?}/{node_floor}/{sealed_floor}");
        let (primary_fee, escape_fee) = (primary_rate * primary_vsize, escape_rate * escape_vsize);
        assert_eq!(fee_of(&members[0]), primary_fee, "primary fee {row}");
        assert_eq!(fee_of(&members[1]), escape_fee, "escape fee {row}");
        assert_eq!(value_of(&members[0], 0), amount, "exact amount {row}");
        assert_eq!(
            value_of(&members[0], 1),
            COIN - amount - primary_fee,
            "{row}"
        );
        assert_eq!(value_of(&members[1], 0), COIN - escape_fee, "sweep {row}");
    }
}

/// 5. A preparation that FAILS composes nothing: no final pair is built, no full parent or
///    `SIGHASH_ALL` is attached, no policy verdict is taken and no authorization exists.
///    The refusal that comes back is M3a's own, and the recorded call log shows the bracket
///    stopped where M3a stopped it. The honest world is the adjacent control.
#[test]
fn nothing_is_composed_attached_checked_or_authorized_before_prepare_view_succeeds() {
    let (vault, w) = sealed_composer();
    let control = Chain::holding(&w.change, &[COIN]);
    composed(&vault, &control, &hot_address(&vault, 0), 100_000);

    let empty = Chain::holding(&w.change, &[]);
    let error = compose_refusal(
        &vault,
        &empty,
        &hot_address(&vault, 0),
        100_000,
        "a vault with no confirmed coin",
    );
    assert!(error.contains("no confirmed coin to spend"), "{error}");
    assert_eq!(
        empty.calls(),
        ["getblockchaininfo", "scantxoutset"],
        "the composition may not read past the refused preparation"
    );
    // And the refusal is M3a's, not any of the composer's own — none of which ran.
    for later in [
        "dust minimum",
        "under the sealed",
        "it was priced at",
        "classifies as",
        "full previous transaction",
    ] {
        assert!(!error.contains(later), "a composition step ran: {error}");
    }
}

/// 6. Every fee and value step is CHECKED, and each of the four ways the arithmetic can
///    fail is refused rather than wrapped: the input sum, both rate × vsize products, and
///    both subtractions.
#[test]
fn the_input_sum_both_fee_products_and_both_subtractions_are_checked() {
    let (mut vault, w) = sealed_composer();
    let destination = hot_address(&vault, 0);
    let half = u64::MAX / 2 + 1;

    // Σ inputs overflows u64.
    let chain = Chain::holding(&w.change, &[half, half]);
    let error = compose_refusal(
        &vault,
        &chain,
        &destination,
        1_000,
        "an overflowing input set",
    );
    assert!(error.contains("input values overflow"), "{error}");

    // primary rate × primary vsize overflows. Ten coins make the shape big enough that
    // the largest rate M3a's ceiling conversion can produce does not fit.
    let mut fast = Chain::holding(&w.change, &[COIN; 10]);
    fast.floors = (u64::MAX, u64::MAX);
    let error = compose_refusal(
        &vault,
        &fast,
        &destination,
        1_000,
        "an unpayable primary rate",
    );
    assert!(error.contains("primary fee overflows"), "{error}");

    // The sealed Escape floor is applied with the same checked multiplication.
    vault.escape_feerate_floor = u64::MAX;
    let chain = Chain::holding(&w.change, &[COIN]);
    let error = compose_refusal(
        &vault,
        &chain,
        &destination,
        1_000,
        "an unpayable escape floor",
    );
    assert!(error.contains("base escape fee overflows"), "{error}");

    // total − amount − primary fee underflows: the vault does not hold what was asked for.
    vault.escape_feerate_floor = 1;
    let error = compose_refusal(
        &vault,
        &chain,
        &destination,
        COIN + 1,
        "more than the vault holds",
    );
    assert!(
        error.contains("does not hold the requested amount"),
        "{error}"
    );
    let error = compose_refusal(
        &vault,
        &chain,
        &destination,
        COIN,
        "the whole vault with no fee",
    );
    assert!(
        error.contains("does not hold the requested amount"),
        "{error}"
    );

    // total − escape fee underflows: the sealed floor outruns the whole vault.
    vault.escape_feerate_floor = COIN;
    let error = compose_refusal(
        &vault,
        &chain,
        &destination,
        1_000,
        "an escape fee over the vault",
    );
    assert!(
        error.contains("does not hold the base escape's own fee"),
        "{error}"
    );
}

/// 7. The existing 10% whole-fee cap is `policy_core`'s alone, and it binds BOTH
///    transactions: exactly at the cap passes and one satoshi of held value below it
///    refuses, for the primary AND for the base Escape. The coverage predicate is set aside
///    for this class so that what moves is the fee cap and nothing else.
#[test]
fn the_whole_fee_cap_binds_both_transactions_at_equality_and_one_satoshi_over() {
    let (mut vault, w) = sealed_composer();
    let [primary_vsize, escape_vsize] = preflight(&vault, &w, &[COIN]);
    vault.escape_coverage_pct = 0;
    let destination = hot_address(&vault, 0);
    let amount = 1_000;

    // The PRIMARY at its cap: the fee is exactly a tenth of the value held.
    let at_cap = 10 * primary_vsize;
    let chain = Chain::holding(&w.change, &[at_cap]);
    let (_, members) = authorized(&vault, &composed(&vault, &chain, &destination, amount));
    assert_eq!(fee_of(&members[0]) * 100, 10 * at_cap, "exactly at the cap");
    let over_cap_total = at_cap - 1;
    let chain = Chain::holding(&w.change, &[over_cap_total]);
    let error = compose_refusal(
        &vault,
        &chain,
        &destination,
        amount,
        "a primary one over the cap",
    );
    assert!(error.contains("fee_cap"), "{error}");
    for derived in [primary_vsize, over_cap_total] {
        assert!(
            !error.contains(&format!("{derived} sat")),
            "a policy refusal echoed a Core-derived value: {error}"
        );
    }

    // The BASE ESCAPE at its own cap, reached through the sealed floor so the primary
    // stays comfortably inside. Its whole fee is what the cap reads, not its increase.
    vault.escape_feerate_floor = 10;
    let at_cap = 100 * escape_vsize;
    let chain = Chain::holding(&w.change, &[at_cap]);
    let (_, members) = authorized(&vault, &composed(&vault, &chain, &destination, amount));
    assert_eq!(fee_of(&members[1]) * 100, 10 * at_cap, "exactly at the cap");
    assert!(
        fee_of(&members[0]) * 100 < 10 * at_cap,
        "the primary is inside it"
    );
    let over_cap_total = at_cap - 1;
    let chain = Chain::holding(&w.change, &[over_cap_total]);
    let error = compose_refusal(
        &vault,
        &chain,
        &destination,
        amount,
        "an escape one over the cap",
    );
    assert!(error.contains("fee_cap"), "{error}");
    for derived in [10 * escape_vsize, over_cap_total] {
        assert!(
            !error.contains(&format!("{derived} sat")),
            "a policy refusal echoed a Core-derived value: {error}"
        );
    }
}

/// 8. The sealed coverage percentage binds the base Escape's ONE output against the whole
///    selected input value, in widened arithmetic: equality passes, one satoshi below
///    refuses, and a sealed 100% refuses any pair whose escape pays a fee at all. Isolated
///    from the fee cap, which these totals leave slack for.
#[test]
fn the_sealed_coverage_percentage_passes_at_equality_and_refuses_one_satoshi_below() {
    let (mut vault, w) = sealed_composer();
    let [_, escape_vsize] = preflight(&vault, &w, &[COIN]);
    let destination = hot_address(&vault, 0);
    let amount = 1_000;
    assert_eq!(
        vault.escape_coverage_pct, 95,
        "the sealed fixture percentage"
    );

    // At 95%, a total of twenty escape fees leaves exactly nineteen — 95% — swept.
    let exact = 20 * escape_vsize;
    let chain = Chain::holding(&w.change, &[exact]);
    let (_, members) = authorized(&vault, &composed(&vault, &chain, &destination, amount));
    assert_eq!(
        value_of(&members[1], 0) * 100,
        exact * u64::from(vault.escape_coverage_pct),
        "exactly at the sealed coverage"
    );
    let chain = Chain::holding(&w.change, &[exact - 1]);
    let error = compose_refusal(
        &vault,
        &chain,
        &destination,
        amount,
        "one satoshi under coverage",
    );
    assert!(error.contains("under the sealed"), "{error}");
    for reflected in [
        (exact - 1).to_string(),
        (exact - 1 - escape_vsize).to_string(),
    ] {
        assert!(
            !error.contains(&reflected),
            "a Core-derived value crossed the diagnostic boundary: {error}"
        );
    }

    // A sealed 100% demands a fee-free sweep, which no positive feerate can compose.
    vault.escape_coverage_pct = 100;
    let chain = Chain::holding(&w.change, &[COIN]);
    let error = compose_refusal(
        &vault,
        &chain,
        &destination,
        amount,
        "a sealed 100% coverage",
    );
    assert!(error.contains("under the sealed"), "{error}");
    // ...and the same world at the sealed 95% is the adjacent control.
    vault.escape_coverage_pct = 95;
    composed(&vault, &chain, &destination, amount);
}

/// 9. All three concrete outputs must clear THEIR OWN script's default dust minimum, and
///    equality passes. This is rust-bitcoin/Core DEFAULT policy only: it says nothing about
///    a node running a custom `-dustrelayfee`.
#[test]
fn each_of_the_three_outputs_clears_its_own_script_dust_minimum_with_equality_passing() {
    let (mut vault, w) = sealed_composer();
    let [primary_vsize, escape_vsize] = preflight(&vault, &w, &[COIN]);
    let destination = hot_address(&vault, 0);
    let chain = Chain::holding(&w.change, &[COIN]);

    // The DESTINATION, at its script's own minimum and one satoshi under it.
    let dust = w.hot.minimal_non_dust().to_sat();
    let (_, members) = authorized(&vault, &composed(&vault, &chain, &destination, dust));
    assert_eq!(value_of(&members[0], 0), dust, "equality passes");
    let error = compose_refusal(&vault, &chain, &destination, dust - 1, "a dust destination");
    assert!(
        error.contains("dust minimum") && error.contains("destination"),
        "{error}"
    );

    // The MANDATORY vault change, which is a different script and therefore a different
    // minimum. There is no absorption: the amount is preserved and the change refuses.
    let change_dust = w.change.minimal_non_dust().to_sat();
    assert_ne!(change_dust, dust, "the two scripts must differ in dust");
    let exact = COIN - primary_vsize - change_dust;
    let (_, members) = authorized(&vault, &composed(&vault, &chain, &destination, exact));
    assert_eq!(value_of(&members[0], 1), change_dust, "equality passes");
    assert_eq!(
        value_of(&members[0], 0),
        exact,
        "the amount is never absorbed"
    );
    let error = compose_refusal(&vault, &chain, &destination, exact + 1, "dust vault change");
    assert!(
        error.contains("dust minimum") && error.contains("vault change"),
        "{error}"
    );
    // A changeless drain is the same refusal at zero, not a permitted topology.
    let error = compose_refusal(
        &vault,
        &chain,
        &destination,
        COIN - primary_vsize,
        "a drain",
    );
    assert!(
        error.contains("dust minimum") && error.contains("vault change"),
        "{error}"
    );

    // The BASE ESCAPE's sweep. Its boundary is proved by WHICH refusal each side earns: a
    // sweep sitting exactly at 294 sat necessarily leaves the rest of the vault as fee, and
    // no whole-fee cap admits that — so equality clears the DUST predicate and is stopped
    // by `policy_core` instead, while one satoshi below never reaches it.
    vault.escape_coverage_pct = 0;
    vault.escape_feerate_floor = 1_000;
    let escape_dust = w.escape.minimal_non_dust().to_sat();
    let escape_fee = 1_000 * escape_vsize;
    let chain = Chain::holding(&w.change, &[escape_dust + escape_fee]);
    let error = compose_refusal(
        &vault,
        &chain,
        &destination,
        1_000,
        "a sweep at its dust floor",
    );
    assert!(error.contains("fee_cap"), "{error}");
    assert!(
        !error.contains("dust minimum"),
        "equality clears dust: {error}"
    );
    let chain = Chain::holding(&w.change, &[escape_dust + escape_fee - 1]);
    let error = compose_refusal(&vault, &chain, &destination, 1_000, "a dust sweep");
    assert!(
        error.contains("dust minimum") && error.contains("base escape"),
        "{error}"
    );
    assert!(
        !error.contains(&(escape_dust - 1).to_string()),
        "a Core-derived value crossed the diagnostic boundary: {error}"
    );
}

/// 9 (continued). Several exact amounts over the same vault, each preserved to the
///     satoshi, with the mandatory change and the sweep falling out of the subtractions.
#[test]
fn the_requested_amount_is_preserved_exactly_at_every_size_the_vault_can_pay() {
    let (vault, w) = sealed_composer();
    let held = 10_000_000;
    let [primary_vsize, escape_vsize] = preflight(&vault, &w, &[held]);
    let destination = hot_address(&vault, 0);
    // The last row is exactly the sealed per-transaction Hot budget; one satoshi more is
    // `policy_core`'s refusal, not this composer's, and M2 owns that class.
    for amount in [294u64, 1_000, 54_321, 999_999, 1_000_000] {
        let chain = Chain::holding(&w.change, &[held]);
        let (_, members) = authorized(&vault, &composed(&vault, &chain, &destination, amount));
        assert_eq!(value_of(&members[0], 0), amount, "{amount}");
        assert_eq!(
            value_of(&members[0], 1),
            held - amount - primary_vsize,
            "{amount}"
        );
        assert_eq!(value_of(&members[1], 0), held - escape_vsize, "{amount}");
    }
}

/// 16. The destination is parsed and BOUND TO THE SEALED NETWORK before any Core call is
///     issued, and the final policy verdict is the sole authority over what the pair may
///     pay: an unrecognized script, one beyond the sealed derivation bound, and an escape
///     address offered as the PRIMARY destination are all refused, while another allowed
///     index composes.
#[test]
fn a_foreign_network_refuses_before_core_and_the_final_policy_verdict_is_authority() {
    let (vault, w) = sealed_composer();
    let chain = Chain::holding(&w.change, &[COIN]);
    // A signet/testnet address for the very same key: valid, and not this vault's network.
    let elsewhere = address(&w.hot, Network::Signet);
    let error = compose_refusal(
        &vault,
        &chain,
        &elsewhere,
        100_000,
        "a foreign-network address",
    );
    assert!(error.contains("not an address on the sealed"), "{error}");
    assert!(
        chain.calls().is_empty(),
        "no Core read may be issued: {:?}",
        chain.calls()
    );
    let error = compose_refusal(
        &vault,
        &chain,
        "not an address",
        100_000,
        "a malformed address",
    );
    assert!(error.contains("does not parse"), "{error}");
    assert!(chain.calls().is_empty(), "{:?}", chain.calls());

    // A script no sealed descriptor derives.
    use bitcoin::hashes::Hash as _;
    let stranger = ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([7u8; 20]));
    let stranger = address(&stranger, vault.network);
    let error = compose_refusal(&vault, &chain, &stranger, 100_000, "an unknown destination");
    assert!(error.contains("destination_allowlist"), "{error}");

    // The hot wallet BEYOND the sealed derivation bound, and one inside it.
    let bound = vault.check_params.max_derivation_index;
    let beyond = hot_address(&vault, bound + 1);
    let error = compose_refusal(
        &vault,
        &chain,
        &beyond,
        100_000,
        "a destination past the bound",
    );
    assert!(error.contains("destination_allowlist"), "{error}");
    let inside = hot_address(&vault, bound);
    let (_, members) = authorized(&vault, &composed(&vault, &chain, &inside, 100_000));
    assert_eq!(
        members[0].unsigned_tx.output[0].script_pubkey,
        definite(&vault.check_params.allowed[0], bound),
        "another allowed index composes"
    );

    // The escape address as the PRIMARY destination: allowlisted, so `evaluate` passes it,
    // and refused on the derived CLASS instead. The pair a node can combine is a Hot
    // primary with its mandatory Escape, not two escapes over the same coins.
    let escape_as_primary = address(&w.escape, vault.network);
    let error = compose_refusal(
        &vault,
        &chain,
        &escape_as_primary,
        100_000,
        "an escape primary",
    );
    assert!(error.contains("classifies as Escape"), "{error}");
}

/// DORMANCY EVIDENCE — required by the bead, and deliberately UNNUMBERED: it is not one of
///     the numbered M3b acceptance classes. The seam is dormant by construction: the
///     composer has no production caller and the CLI dispatch names none of the three
///     dormant modules. The governed evidence driver separately audits the complete call
///     graph, item visibility and real CLI behaviour.
#[test]
fn the_composer_has_no_production_caller_or_cli_dispatch() {
    // No production Rust outside `compose.rs` names `compose_spend`.
    let mut callers = Vec::new();
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates")
        .to_path_buf();
    let mut pending = vec![root];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).expect("readable") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let rel = path.display().to_string();
                let production = rel.contains("/src/") && !rel.ends_with("/src/compose.rs");
                if production
                    && std::fs::read_to_string(&path)
                        .expect("utf-8")
                        .contains("compose_spend")
                {
                    callers.push(rel);
                }
            }
        }
    }
    assert!(
        callers.is_empty(),
        "compose_spend has production callers: {callers:?}"
    );

    // ...and the CLI dispatch itself names none of the dormant three.
    let main = include_str!("../src/main.rs");
    let dispatch = main.split("fn main()").nth(1).expect("the dispatch");
    for banned in ["compose", "inventory", "core_view", "CoreRpc"] {
        assert!(
            !dispatch.contains(banned),
            "the CLI dispatch reaches {banned}"
        );
    }
}

/// LIVE-7. The whole composition against a REAL daemon with no `-txindex`: real values
/// derived from the live chain, every verified full previous transaction attached with an
/// explicit `SIGHASH_ALL`, the real `SoftwareSigner` accepting it, both derived classes
/// proved — and Core's own UTXO set and mempool untouched when it is over, because nothing
/// here broadcasts.
#[test]
#[ignore = "spawns a regtest bitcoind; run with --ignored"]
fn a_live_core_composes_a_real_valued_pair_that_the_real_signer_authorizes() {
    let sealed = sealed_vault();
    let temp = fed::TempDir::new("core-view-compose").expect("temp dir");
    let node = funded(&temp, &sealed.vault, 101);
    let coin = Amount::from_int_btc(50).to_sat();

    // The sizes and the rate the live daemon itself prices this pair at, read through M3a.
    let view = sealed.prepare(&node.adapter()).expect("the live inventory");
    let [primary_vsize, escape_vsize] = view.preflight_vsizes();
    let rate = view.sat_per_vb();
    let outpoint = view.utxos()[0].outpoint;
    drop(view);

    let amount = 750_000;
    let destination = address(&sealed.destination, sealed.vault.network);
    let request = compose_spend(
        &sealed.vault,
        &node.adapter(),
        &destination,
        Amount::from_sat(amount),
    )
    .expect("the live composition");
    let mut signer =
        SoftwareSigner::load_file(&sealed.vault, &sealed.user_key).expect("the sealed user key");
    let (display, members) = signer
        .authorize(&request)
        .expect("the real signer must accept the live composition")
        .into_parts();
    assert_eq!(members.len(), 2, "an empty ladder is exactly two members");

    let escape_rate = rate.max(sealed.vault.escape_feerate_floor);
    let (primary_fee, escape_fee) = (rate * primary_vsize, escape_rate * escape_vsize);
    assert_eq!(
        value_of(&members[0], 0),
        amount,
        "the exact requested amount"
    );
    assert_eq!(value_of(&members[0], 1), coin - amount - primary_fee);
    assert_eq!(value_of(&members[1], 0), coin - escape_fee);
    assert_eq!(fee_of(&members[0]), primary_fee);
    assert_eq!(fee_of(&members[1]), escape_fee);
    assert_eq!(
        members[0].unsigned_tx.output[0].script_pubkey,
        sealed.destination
    );
    assert_eq!(
        members[0].unsigned_tx.output[1].script_pubkey,
        sealed.change
    );
    assert_eq!(
        members[1].unsigned_tx.output[0].script_pubkey,
        sealed.escape
    );

    // Every input map of BOTH transactions carries the full parent Core itself returned,
    // and declares SIGHASH_ALL outright.
    let raw = node.call(
        "getrawtransaction",
        json!([outpoint.txid.to_string(), false, view_block(&node, 1)]),
    );
    for (label, psbt) in [("primary", &members[0]), ("escape", &members[1])] {
        assert_eq!(psbt.inputs.len(), 1, "{label}");
        let map = &psbt.inputs[0];
        let parent = map.non_witness_utxo.as_ref().expect("the full parent");
        assert_eq!(
            bitcoin::consensus::encode::serialize_hex(parent),
            raw.as_str().expect("hex"),
            "{label} carries byte-for-byte what this daemon returned"
        );
        assert_eq!(
            map.sighash_type,
            Some(EcdsaSighashType::All.into()),
            "{label}"
        );
        assert!(map.bip32_derivation.is_empty(), "{label}");
        assert_eq!(map.partial_sigs.len(), 1, "{label} is user-signed");
    }
    let classify = |psbt: &Psbt| {
        policy_core::classify(psbt, &sealed.vault.check_params)
            .expect("a class")
            .class
    };
    assert_eq!(classify(&members[0]), TxClass::Hot);
    assert_eq!(classify(&members[1]), TxClass::Escape);
    assert!(
        display.contains("primary hot-destination transaction"),
        "{display}"
    );

    // Nothing broadcast: the funding coin is still unspent and the mempool is still empty.
    let params = json!([outpoint.txid.to_string(), outpoint.vout, true]);
    assert!(
        !node.call("gettxout", params).is_null(),
        "no broadcast may have happened"
    );
    assert_eq!(node.call("getmempoolinfo", json!([]))["size"], json!(0));
}
