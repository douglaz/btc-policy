//! Opt-in integration test for the bitcoind `ChainBackend` impl. Like the demo
//! e2e test it spawns a real regtest bitcoind, so it is `#[ignore]`d by default:
//!
//!   nix develop -c cargo test -p vault-node -- --ignored
//!
//! It exercises the backend against live chain data: `test_package_accept`
//! parses Core's real `testmempoolaccept` response, `broadcast` pushes a
//! fully-signed tx, `transaction_confirmed` distinguishes mempool from chain,
//! and `spends_of` finds that spend of a watched scriptPubKey. A second test
//! proves the node-owned watch-only descriptor wallet's vault-unspent view is
//! identical to the `scantxoutset`-derived one against real Core, and a third
//! proves the reorg repair — the re-import into a wallet that already holds the
//! descriptors — against real Core too (bead btc-policy-hn8). Setup RPCs (wallet,
//! mining) use a tiny in-test JSON-RPC client; the backend itself is the code
//! under test.

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

#[test]
#[ignore = "spawns a regtest bitcoind; run with --ignored"]
fn descriptor_wallet_vault_view_matches_the_scan_on_regtest() {
    run_vault_view().expect("descriptor-wallet vault view integration");
}

#[test]
#[ignore = "spawns a regtest bitcoind; run with --ignored"]
fn a_reorg_below_the_wallet_anchor_is_repaired_by_re_import_on_regtest() {
    run_reorg_repair().expect("descriptor-wallet reorg repair integration");
}

/// The bead's central claim, against LIVE Core rather than a scripted transport
/// (bead btc-policy-hn8): for one chain+mempool state that includes a confirmed
/// unspent vault output, a confirmed vault output a mempool transaction has spent,
/// and an unconfirmed authorized vault output, the view served from the node-owned
/// watch-only descriptor wallet is IDENTICAL to the one served from `scantxoutset`.
///
/// The two phases read the same state: phase A runs before any vault wallet exists
/// on the backend (so the scan serves, and seeds the wallet), phase B runs on a
/// fresh backend handle — a restart — and is served by the wallet. Nothing mines or
/// spends between them. Equality alone cannot tell a wallet-served refresh from a
/// silent fallback to the scan, so each phase also asserts `full_scan_count`.
///
/// A final phase then builds the one state where `listunspent` alone would be WRONG
/// — a vault output whose only known spender is a wallet transaction that is neither
/// confirmed nor in the mempool — and proves the wallet-derived view still holds it.
fn run_vault_view() -> Result<(), Error> {
    let temp = TempDir::new("vault-view")?;
    let rpc_port = free_port()?;
    let mut node = Bitcoind::start(temp.path.join("v"), rpc_port)?;
    node.create_wallet("it")?;
    let miner = node.call_str("getnewaddress", json!([]))?;
    node.call("generatetoaddress", json!([101, miner]))?;

    // One watched "vault" script, funded three times and confirmed.
    let vault_addr = node.call_str("getnewaddress", json!(["", "bech32"]))?;
    let vault_spk = ScriptBuf::from_hex(
        node.call("getaddressinfo", json!([vault_addr.clone()]))?["scriptPubKey"]
            .as_str()
            .ok_or("scriptPubKey")?,
    )?;
    let kept = fund(&node, &vault_addr, &vault_spk, 0.5)?;
    let to_be_spent = fund(&node, &vault_addr, &vault_spk, 1.0)?;
    let orphan_spent = fund(&node, &vault_addr, &vault_spk, 0.75)?;
    node.call("generatetoaddress", json!([1, miner]))?;

    // A mempool transaction that spends one vault output and pays the vault back:
    // `to_be_spent` becomes mempool-spent (Core hides it from `gettxout`), and its
    // output is an UNCONFIRMED vault output that only counts because the node
    // authorized the transaction.
    let raw = node.call_str(
        "createrawtransaction",
        json!([
            [{"txid": to_be_spent.txid.to_string(), "vout": to_be_spent.vout}],
            {vault_addr.clone(): 0.999},
        ]),
    )?;
    let signed = node.call("signrawtransactionwithwallet", json!([raw]))?;
    let signed_hex = signed["hex"].as_str().ok_or("signed hex")?.to_string();
    let pending: Transaction = deserialize_hex(&signed_hex)?;
    node.call("sendrawtransaction", json!([signed_hex]))?;
    let pending_txid = pending.compute_txid();
    let authorized = std::collections::HashSet::from([pending_txid]);
    let pending_vout = pending
        .output
        .iter()
        .position(|output| output.script_pubkey == vault_spk)
        .ok_or("the pending transaction pays the vault")? as u32;

    let scripts = std::slice::from_ref(&vault_spk);
    // Phase A — no vault wallet exists yet, so the scan serves and seeds one.
    let scan_backend = BitcoindBackend::new(node.rpc_addr, node.auth.clone());
    scan_backend.refresh_vault_unspent_cache(scripts)?;
    let from_scan = scan_backend.vault_unspent(scripts, &authorized)?;
    assert_eq!(
        scan_backend.full_scan_count(),
        1,
        "the cold start is the one pass that scans the whole UTXO set"
    );

    let wallets = node.call("listwallets", json!([]))?;
    let owned: Vec<String> = wallets
        .as_array()
        .ok_or("listwallets")?
        .iter()
        .filter_map(|name| name.as_str())
        .filter(|name| name.starts_with("vaultnode-"))
        .map(str::to_string)
        .collect();
    assert_eq!(
        owned.len(),
        1,
        "the cold scan seeds exactly one node-owned wallet: {wallets}"
    );
    let vault_wallet = owned[0].clone();

    // Phase B — a restart: a fresh backend handle over the SAME chain state, now
    // served by the wallet the cold start left behind.
    let wallet_backend = BitcoindBackend::new(node.rpc_addr, node.auth.clone());
    wallet_backend.refresh_vault_unspent_cache(scripts)?;
    let from_wallet = wallet_backend.vault_unspent(scripts, &authorized)?;
    // The point of the bead: a restart against an existing wallet reads no UTXO set.
    // Without this the phase could silently regress to the fallback and still match.
    assert_eq!(
        wallet_backend.full_scan_count(),
        0,
        "a restart against an existing wallet must not scan the whole UTXO set"
    );

    assert_eq!(
        from_wallet, from_scan,
        "the wallet-derived and scan-derived vault views must agree on live chain data"
    );
    let outpoints: Vec<OutPoint> = from_wallet.iter().map(|(outpoint, _)| *outpoint).collect();
    assert!(
        outpoints.contains(&kept),
        "the untouched confirmed vault output must be counted: {outpoints:?}"
    );
    assert!(
        outpoints.contains(&OutPoint::new(pending_txid, pending_vout)),
        "the authorized unconfirmed vault output must be counted: {outpoints:?}"
    );
    assert!(
        !outpoints.contains(&to_be_spent),
        "the output a mempool transaction already spent must NOT be counted: {outpoints:?}"
    );
    assert!(
        outpoints.contains(&orphan_spent),
        "the third confirmed vault output is still unspent here: {outpoints:?}"
    );
    assert_eq!(outpoints.len(), 3, "and nothing else: {outpoints:?}");

    // Idempotency: a third startup neither re-creates the wallet nor duplicates it.
    let restart = BitcoindBackend::new(node.rpc_addr, node.auth.clone());
    restart.refresh_vault_unspent_cache(scripts)?;
    assert_eq!(
        restart.vault_unspent(scripts, &authorized)?,
        from_wallet,
        "a later restart reads the same view from the same wallet"
    );
    assert_eq!(
        restart.full_scan_count(),
        0,
        "and it reads it without a scan"
    );
    let wallets = node.call("listwallets", json!([]))?;
    assert_eq!(
        wallets
            .as_array()
            .ok_or("listwallets")?
            .iter()
            .filter(|name| name.as_str().is_some_and(|n| n.starts_with("vaultnode-")))
            .count(),
        1,
        "restarts must not accumulate wallets: {wallets}"
    );

    // --- the case `listunspent` alone gets WRONG -----------------------------
    // A wallet transaction that spends a vault output can end up neither confirmed
    // NOR in the mempool, and Core's wallet keeps hiding its inputs while the chain
    // holds them unspent. Reproduced here as an orphaned, now non-final spend: give
    // it an `nLockTime` two blocks ahead, mine to it, mine the spend in, then
    // invalidate the block that made it final. Core drops it from the mempool
    // (`IsFinalTx` refuses it at the restored height) and the wallet keeps it as an
    // unconfirmed, unabandoned spend.
    //
    // Ordering is what makes this leg load-bearing rather than decorative. The vault
    // wallet must already exist so that it LEARNS the spend, and `wallet_backend`
    // must refresh WHILE the spend is confirmed, so the output it consumed is pruned
    // from that backend's candidate set. After the reorg the output is then in none
    // of the other sources — `listunspent` hides it, the carried cache no longer
    // holds it, and its own deposit confirmed long before the fork point that
    // `listsinceblock` reports from — so only expanding the unconfirmed debit's
    // inputs can restore it.
    let tip = node
        .call("getblockcount", json!([]))?
        .as_u64()
        .ok_or("tip")? as u32;
    let lock_height = tip + 2;
    let raw = node.call_str(
        "createrawtransaction",
        json!([
            [{"txid": orphan_spent.txid.to_string(), "vout": orphan_spent.vout}],
            {vault_addr.clone(): 0.749},
            lock_height,
        ]),
    )?;
    let orphan_hex = node.call("signrawtransactionwithwallet", json!([raw]))?["hex"]
        .as_str()
        .ok_or("orphan signed hex")?
        .to_string();
    // Two blocks: the first confirms the pending mempool spend, the second makes the
    // orphan-to-be final. Then mine the spend in and refresh over that state.
    node.call("generatetoaddress", json!([2, miner]))?;
    node.call("sendrawtransaction", json!([orphan_hex]))?;
    node.call("generatetoaddress", json!([1, miner]))?;
    node.call("syncwithvalidationinterfacequeue", json!([]))?;
    wallet_backend.refresh_vault_unspent_cache(scripts)?;
    assert!(
        !wallet_backend
            .vault_unspent(scripts, &authorized)?
            .iter()
            .any(|(outpoint, _)| *outpoint == orphan_spent),
        "the confirmed spend must remove its input from the view first"
    );

    // Now orphan both blocks. The spend leaves the mempool and stays in the wallet.
    let undone = node.call("getblockhash", json!([lock_height]))?;
    node.call("invalidateblock", json!([undone]))?;
    node.call("syncwithvalidationinterfacequeue", json!([]))?;
    // The precondition, stated against live Core rather than assumed: the node's own
    // wallet hides the output, while the chain says it is unspent and confirmed.
    let hidden = node.wallet_call(
        &vault_wallet,
        "listunspent",
        json!([1, 9_999_999, [], true, {"include_immature_coinbase": true}]),
    )?;
    assert!(
        !hidden
            .as_array()
            .ok_or("listunspent")?
            .iter()
            .any(|entry| entry["txid"].as_str() == Some(&orphan_spent.txid.to_string())),
        "this phase is only meaningful while the wallet hides the output: {hidden}"
    );
    assert!(
        wallet_backend
            .prevout(&orphan_spent)?
            .is_some_and(|prevout| prevout.confirmed),
        "the chain must hold the orphan-spent output as confirmed and unspent"
    );
    wallet_backend.refresh_vault_unspent_cache(scripts)?;
    let mut recovered: Vec<OutPoint> = wallet_backend
        .vault_unspent(scripts, &authorized)?
        .iter()
        .map(|(outpoint, _)| *outpoint)
        .collect();
    recovered.sort();
    let mut expected = vec![
        kept,
        orphan_spent,
        OutPoint::new(pending_txid, pending_vout),
    ];
    expected.sort();
    assert_eq!(
        recovered, expected,
        "the wallet-derived view must restore an output whose only spender left the \
         mempool — `listunspent` hides it, so dropping it would understate the \
         protected balance from this node's private wallet history"
    );
    // That reorg unseated the cache anchor but not the wallet's completion anchor, so
    // the wallet reconciled it: a whole-set scan here would be the regression the
    // marker boundary exists to avoid.
    assert_eq!(
        wallet_backend.full_scan_count(),
        0,
        "and it reconciles all of that without a whole-set scan"
    );
    Ok(())
}

/// The reorg repair, against LIVE Core (bead btc-policy-hn8). A reorg below the
/// wallet's completion anchor can resurrect a vault output created BEFORE that
/// wallet's birthday — spent, in a block the reorg dropped, by a transaction that
/// paid the vault nothing, so the wallet neither watched the output nor holds that
/// transaction and no wallet-only read can ever surface it again.
/// `refresh_vault_unspent_cache` answers by latching the wallet out, re-deriving the
/// birthday from a fresh `scantxoutset`, and re-importing the SAME descriptors into
/// the wallet that already holds them.
///
/// That re-import is the heaviest assumption this change makes about Core, and the
/// unit suite cannot test it: it replays canned JSON, so it proves what the code
/// does with a granted import, not that Core grants one. If Core REFUSED a duplicate
/// descriptor, `wallet_reimport_pending` would never clear — every later pass would
/// pay a whole-set scan forever while the wallet stayed blind to the restored
/// output. If Core accepted it but did NOT rescan the earlier history, the wallet
/// would silently under-report the coverage denominator. This test fails on either.
///
/// Block times are mocked a day apart, and that is what makes the birthday
/// load-bearing rather than decorative: Core rescans an import from
/// `timestamp - 2h`, so on a chain mined in real time EVERY import covers the whole
/// chain and no wallet can be blind to anything.
fn run_reorg_repair() -> Result<(), Error> {
    // Two eras far enough apart that an import dated in the second cannot reach the
    // first. Absolute, because mining requires a block time above the median of the
    // last eleven and regtest's genesis is dated 2011.
    const OLD_ERA: u64 = 1_600_000_000;
    const NEW_ERA: u64 = OLD_ERA + 86_400;

    let temp = TempDir::new("vault-repair")?;
    let rpc_port = free_port()?;
    let mut node = Bitcoind::start(temp.path.join("r"), rpc_port)?;
    // Before the funding wallet exists: Core's wallet ignores a connected block dated
    // before its own birth time, so a wallet created at real time would see none of
    // the era-one blocks and hold no coins to spend.
    node.call("setmocktime", json!([OLD_ERA]))?;
    node.create_wallet("it")?;
    let miner = node.call_str("getnewaddress", json!([]))?;
    node.call("generatetoaddress", json!([101, miner]))?;

    // Era one: a vault output the wallet's birthday will sit above.
    let vault_addr = node.call_str("getnewaddress", json!(["", "bech32"]))?;
    let vault_spk = ScriptBuf::from_hex(
        node.call("getaddressinfo", json!([vault_addr.clone()]))?["scriptPubKey"]
            .as_str()
            .ok_or("scriptPubKey")?,
    )?;
    let older = fund(&node, &vault_addr, &vault_spk, 0.5)?;
    node.call("generatetoaddress", json!([1, miner]))?;
    // The funding wallet owns this address too, so keep its coin selection off the
    // output this test spends by hand; it must survive until the era-two spend.
    node.call(
        "lockunspent",
        json!([false, [{"txid": older.txid.to_string(), "vout": older.vout}]]),
    )?;

    // Era two: the vault's only LIVE output at cold-start time, so the scan derives
    // the birthday from its block and the import starts a day above `older`.
    node.call("setmocktime", json!([NEW_ERA]))?;
    let birthday_output = fund(&node, &vault_addr, &vault_spk, 0.25)?;
    node.call("generatetoaddress", json!([1, miner]))?;

    // Bury era two ten blocks deep, so no era-one time is left in the tip's
    // median-time-past window (eleven blocks). Core dates an import's
    // `timestamp: "now"` at that MTP, not at wall-clock time, so above a shallower
    // era-two segment the completion marker's own import would rescan from an era-ONE
    // median and hand the wallet the history this test needs it to lack.
    //
    // Then spend `older` to an address the vault does not watch, two blocks above the
    // fork point to come. `nLockTime` is what keeps the reorg's resurrection from
    // being undone: at the restored tip Core refuses to re-admit the spend to the
    // mempool, so the output stays visibly unspent to the chain while the wallet that
    // never saw it stays blind.
    node.call("generatetoaddress", json!([10, miner]))?;
    let fork_height = node
        .call("getblockcount", json!([]))?
        .as_u64()
        .ok_or("tip")? as u32;
    let raw = node.call_str(
        "createrawtransaction",
        json!([
            [{"txid": older.txid.to_string(), "vout": older.vout}],
            {miner.clone(): 0.499},
            fork_height,
        ]),
    )?;
    let spend_hex = node.call("signrawtransactionwithwallet", json!([raw]))?["hex"]
        .as_str()
        .ok_or("spend signed hex")?
        .to_string();
    node.call("sendrawtransaction", json!([spend_hex]))?;
    node.call("generatetoaddress", json!([1, miner]))?;
    node.call("syncwithvalidationinterfacequeue", json!([]))?;

    // Cold start: the scan seeds a wallet whose birthday is era two's first block.
    let scripts = std::slice::from_ref(&vault_spk);
    let authorized = std::collections::HashSet::new();
    let backend = BitcoindBackend::new(node.rpc_addr, node.auth.clone());
    backend.refresh_vault_unspent_cache(scripts)?;
    assert_eq!(
        backend
            .vault_unspent(scripts, &authorized)?
            .iter()
            .map(|(outpoint, _)| *outpoint)
            .collect::<Vec<_>>(),
        vec![birthday_output],
        "only the era-two output is live at cold start"
    );
    assert_eq!(
        backend.full_scan_count(),
        1,
        "the cold start is the one pass that scans the whole UTXO set"
    );
    let wallets = node.call("listwallets", json!([]))?;
    let vault_wallet = wallets
        .as_array()
        .ok_or("listwallets")?
        .iter()
        .filter_map(|name| name.as_str())
        .find(|name| name.starts_with("vaultnode-"))
        .ok_or("the cold scan seeds a node-owned wallet")?
        .to_string();
    // The precondition, stated against live Core rather than assumed: this wallet's
    // history begins above `older`'s block, so it has never heard of that output.
    assert!(
        node.wallet_call(
            &vault_wallet,
            "gettransaction",
            json!([older.txid.to_string()])
        )
        .is_err(),
        "the import must not have rescanned era one, or the reorg below is not blind"
    );

    // The reorg: drop the fork block and the spend above it. `older` is unspent on
    // the active chain again, and the wallet cannot see it.
    let fork = node.call("getblockhash", json!([fork_height]))?;
    node.call("invalidateblock", json!([fork]))?;
    node.call("syncwithvalidationinterfacequeue", json!([]))?;
    assert!(
        backend
            .prevout(&older)?
            .is_some_and(|prevout| prevout.confirmed),
        "the reorg must restore the older output as confirmed and unspent — and out of \
         the mempool: this reads `gettxout` with `include_mempool`, so a spend Core \
         re-admitted would still hide it here"
    );
    let hidden = node.wallet_call(
        &vault_wallet,
        "listunspent",
        json!([1, 9_999_999, [], true, {"include_immature_coinbase": true}]),
    )?;
    let wallet_holds = |unspents: &Value, outpoint: &OutPoint| -> Result<bool, Error> {
        Ok(unspents
            .as_array()
            .ok_or("listunspent")?
            .iter()
            .any(|entry| {
                entry["txid"].as_str() == Some(&outpoint.txid.to_string())
                    && entry["vout"].as_u64() == Some(u64::from(outpoint.vout))
            }))
    };
    assert!(
        !wallet_holds(&hidden, &older)?,
        "this phase is only meaningful while the wallet is blind to the restored \
         output: {hidden}"
    );
    assert!(
        wallet_holds(&hidden, &birthday_output)?,
        "and while the wallet is otherwise healthy: {hidden}"
    );

    // The repair pass: latch, re-derive the birthday by scan, re-import into the
    // wallet that already holds these descriptors.
    backend.refresh_vault_unspent_cache(scripts)?;
    assert_eq!(
        backend.full_scan_count(),
        2,
        "a reorg below the wallet's completion anchor pays exactly one more whole-set \
         scan — the one that re-derives the birthday"
    );
    let repaired = node.wallet_call(
        &vault_wallet,
        "listunspent",
        json!([1, 9_999_999, [], true, {"include_immature_coinbase": true}]),
    )?;
    assert!(
        wallet_holds(&repaired, &older)?,
        "Core must accept the re-import of a descriptor the wallet already holds AND \
         rescan from the earlier birthday; its own wallet has to hold the restored \
         output now: {repaired}"
    );

    // A restart carries no cache, so this view comes from the repaired wallet alone.
    // No scan here proves the repair also re-anchored the wallet's completion marker.
    let restart = BitcoindBackend::new(node.rpc_addr, node.auth.clone());
    restart.refresh_vault_unspent_cache(scripts)?;
    assert_eq!(
        restart.full_scan_count(),
        0,
        "the repaired wallet must verify on a fresh handle, without another scan"
    );
    let mut restored: Vec<OutPoint> = restart
        .vault_unspent(scripts, &authorized)?
        .iter()
        .map(|(outpoint, _)| *outpoint)
        .collect();
    restored.sort();
    let mut expected = vec![older, birthday_output];
    expected.sort();
    assert_eq!(
        restored, expected,
        "the repaired wallet must serve the restored pre-birthday output as well as \
         the one it always watched"
    );
    assert_eq!(
        node.call("listwallets", json!([]))?
            .as_array()
            .ok_or("listwallets")?
            .iter()
            .filter(|name| name.as_str().is_some_and(|n| n.starts_with("vaultnode-")))
            .count(),
        1,
        "the repair re-imports into the existing wallet; it must not create another"
    );
    Ok(())
}

/// Pay `amount` to `addr` and return the outpoint that carries `spk`.
fn fund(node: &Bitcoind, addr: &str, spk: &ScriptBuf, amount: f64) -> Result<OutPoint, Error> {
    let txid = node.call_str("sendtoaddress", json!([addr, amount]))?;
    let tx = node.call("getrawtransaction", json!([txid, true]))?;
    let vout = tx["vout"]
        .as_array()
        .ok_or("vout")?
        .iter()
        .position(|output| output["scriptPubKey"]["hex"].as_str() == Some(&spk.to_hex_string()))
        .ok_or("funding paid no watched output")? as u32;
    Ok(OutPoint::new(Txid::from_str(&txid)?, vout))
}

fn run() -> Result<(), Error> {
    let temp = TempDir::new("backend")?;
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
    // The BATCHED residency read (bead btc-policy-nvr) against live Core — the one path
    // the unit tests cannot cover, because the mock deliberately answers per txid rather
    // than composing one `getrawmempool` snapshot with one `getrawtransaction`. Asked for
    // the whole ladder cheapest-first, it must skip the replaced base and return the
    // resident higher rung with its real bytes.
    assert_eq!(
        backend.mempool_resident(&[base_txid, spend_txid])?,
        Some((spend_txid, replacement_bytes.clone())),
        "the batched read skips the replaced base and returns the resident rung"
    );
    assert_eq!(
        backend.mempool_resident(&[spend_txid])?,
        Some((spend_txid, replacement_bytes.clone())),
        "a single-element batch behaves like the per-txid lookup"
    );
    assert_eq!(
        backend.mempool_resident(&[base_txid])?,
        None,
        "a batch of only non-resident txids is an ordinary absence, not an error"
    );
    assert_eq!(
        backend.mempool_resident(&[])?,
        None,
        "an empty batch reads nothing and answers None"
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

    /// A call against one named wallet's endpoint, for asserting what Core's own
    /// wallet reports independently of the backend under test.
    fn wallet_call(&self, wallet: &str, method: &str, params: Value) -> Result<Value, Error> {
        let request = json!({ "jsonrpc": "1.0", "id": "it", "method": method, "params": params });
        let body = post(
            self.rpc_addr,
            &format!("/wallet/{wallet}"),
            &request.to_string(),
            &self.auth,
        )?;
        let reply: Value = serde_json::from_str(&body)
            .map_err(|e| format!("{method} on {wallet}: unparseable reply: {e}"))?;
        if !reply["error"].is_null() {
            return Err(format!("{method} on {wallet}: {}", reply["error"]).into());
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
    /// `tag` keeps two tests in one binary from sharing — and so from deleting —
    /// each other's datadir when they run on different threads.
    fn new(tag: &str) -> Result<TempDir, Error> {
        let path = std::env::temp_dir().join(format!("vault-node-it-{}-{tag}", std::process::id()));
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
