//! Real-signet spend driver (bead btc-policy-9y5.8, deliverable 1).
//!
//! The two `demo` acts prove the vault on a private regtest chain the harness
//! spawns, funds by mining, and time-warps. This driver proves the SAME federation
//! against a real, external `signet` node: it provisions the ceremony, spawns the
//! five `vault-node` daemons pointed at the live signet bitcoind, waits for the vault
//! coin to appear in the real UTXO set (funded out of band from a signet faucet), and
//! drives ONE coordinator-authenticated honest spend that the federation combines and
//! broadcasts to signet — confirming in a real block, on real block timing, with a
//! real (short) Hold. Nothing here mines or warps the clock; the whole point is the
//! parts the regtest demos cannot exercise.
//!
//! It is deliberately a thin orchestration over the SAME `fed` primitives the demos
//! use (`NodeDevice::provision`, `Manifest::assemble`, `NodeProcess::spawn`, the
//! `Coordinator`, `build_spend`), so the federation this proves is the federation
//! `btc-vault setup` provisions, not a signet-only reimplementation.

use std::net::SocketAddr;
use std::str::FromStr;
use std::time::{Duration, Instant};

use base64::prelude::{Engine as _, BASE64_STANDARD};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Amount, Network, PublicKey, ScriptBuf, Transaction};
use miniscript::Descriptor;
use serde_json::{json, Value};

use crate::fed::{
    build_spend, commitment_expiry, free_ports, locate_btc_vault, locate_vault_node,
    sign_all_inputs, summarize, Actor, CeremonyParams, Coordinator, Manifest, NodeDevice,
    NodeParams, NodeProcess, NodeSpawn, TempDir, Utxo, Wallet,
};
use crate::http::{self, Error};

const NODE_COUNT: usize = 5;
const QUORUM: usize = 3;
const NORMAL_PIN: &str = "246802";
const DURESS_PIN: &str = "135791";
const POLICY_VERSION: u32 = 1;
const MAX_COMMITMENT_AGE_SECS: u64 = 172_800;
const COMMITMENT_TTL_SECS: u64 = 3_600;
const MAX_DERIVATION_INDEX: u32 = 100;
const HOT_INDEX: u32 = 5;
/// A real, non-zero Hold — the property regtest cannot exercise on real time. Kept
/// short so the run does not span hours; the fire tick + combine + broadcast still
/// land well inside the combine window after it elapses.
const HOLD_SECS: u64 = 120;
const COMBINE_SLACK_SECS: u64 = 120;
/// Fee for the honest spend and its escape (signet feerates are trivial).
const FEE: Amount = Amount::from_sat(2_000);

/// The signet chain this driver drives. Overridable by env for a different node.
fn signet_rpc_addr() -> SocketAddr {
    std::env::var("SIGNET_RPC_ADDR")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 38342)))
}

/// base64("user:pass") for the signet node's JSON-RPC basic auth.
fn signet_auth() -> String {
    let creds = std::env::var("SIGNET_RPC_AUTH").unwrap_or_else(|_| "vault:vaultsignetpass".into());
    BASE64_STANDARD.encode(creds)
}

/// The bitcoind wallet already holding faucet funds, used ONLY to send the vault its
/// coin. The federation never touches it.
fn funding_wallet() -> String {
    std::env::var("SIGNET_FUND_WALLET").unwrap_or_else(|_| "faucet".into())
}

/// One JSON-RPC round trip to the signet node, `path` selecting the wallet endpoint.
fn rpc(path: &str, method: &str, params: Value) -> Result<Value, Error> {
    let body = json!({"jsonrpc": "1.0", "id": "signet-spend", "method": method, "params": params})
        .to_string();
    let auth = signet_auth();
    let response = http::post_json(
        signet_rpc_addr(),
        path,
        body.as_bytes(),
        Some(&auth),
        Duration::from_secs(30),
    )?;
    let parsed: Value = serde_json::from_str(&response.body)
        .map_err(|e| format!("signet {method}: unparseable reply: {e}"))?;
    if !parsed["error"].is_null() {
        return Err(format!("signet {method}: {}", parsed["error"]).into());
    }
    Ok(parsed["result"].clone())
}

fn node_rpc(method: &str, params: Value) -> Result<Value, Error> {
    rpc("/", method, params)
}

fn wallet_rpc(method: &str, params: Value) -> Result<Value, Error> {
    rpc(&format!("/wallet/{}", funding_wallet()), method, params)
}

/// The per-vault policy this driver seals, in the shape the ceremony and node configs
/// share. Mirrors the demo's, with a real non-zero Hold + generous Hot budget.
fn node_params() -> NodeParams {
    NodeParams {
        hold_secs: HOLD_SECS,
        duress_delay_secs: 0,
        epsilon_secs: 60,
        combine_slack_secs: COMBINE_SLACK_SECS,
        max_commitment_age_secs: MAX_COMMITMENT_AGE_SECS,
        delivery_horizon_secs: 60,
        max_derivation_index: MAX_DERIVATION_INDEX,
        policy_version: POLICY_VERSION,
        max_msg_bytes: vault_node::channel::DEFAULT_MAX_MSG_BYTES,
        hot_budget: vault_node::HotBudget {
            max_per_tx_sat: 1_000_000_000,
            max_per_window_sat: 1_000_000_000,
            window_secs: MAX_COMMITMENT_AGE_SECS,
        },
        normal_pin: NORMAL_PIN.to_string(),
        duress_pin: DURESS_PIN.to_string(),
        pin_m_cost_kib: 8,
        escape_feerate_floor: 1,
    }
}

/// Everything the ceremony produces plus the live handles the run needs.
struct SignetFederation {
    secp: Secp256k1<bitcoin::secp256k1::All>,
    user: Actor,
    coordinator: Coordinator,
    nodes: Vec<NodeProcess>,
    descriptor: Descriptor<PublicKey>,
    witness_script: ScriptBuf,
    vault_spk: ScriptBuf,
    hot_spk: ScriptBuf,
    escape_spk: ScriptBuf,
    #[allow(dead_code)]
    temp: TempDir,
}

impl SignetFederation {
    fn wallet_id(&self) -> [u8; 32] {
        crate::fed::wallet_id(&self.descriptor)
    }

    /// Provision the ceremony and spawn five nodes pointed at the SIGNET backend.
    /// No chain writes happen here — this is validatable before the vault is funded.
    fn bring_up() -> Result<SignetFederation, Error> {
        let secp = Secp256k1::new();
        let mut urandom = std::fs::File::open("/dev/urandom")?;
        let temp = TempDir::new("signet-spend")?;

        let user = Actor::random(&secp, &mut urandom)?;
        let coordinator = Coordinator::random(&secp, &mut urandom)?;
        let coord_auth_pubkey = coordinator.pubkey.to_string();
        let hot_wallet = Wallet::random(&secp, &mut urandom)?;
        let escape_wallet = Wallet::random(&secp, &mut urandom)?;
        let hot_spk = hot_wallet.address_spk(&secp, HOT_INDEX)?;
        let escape_spk = escape_wallet.address_spk(&secp, 0)?;
        let recovery_keys: Vec<PublicKey> = (0..policy_core::RECOVERY_KEYS)
            .map(|_| Ok(Actor::random(&secp, &mut urandom)?.pubkey))
            .collect::<Result<_, Error>>()?;

        let ports = free_ports(NODE_COUNT)?;
        let btc_vault = locate_btc_vault()?;
        let devices_dir = temp.path.join("devices");
        let devices: Vec<NodeDevice> = ports
            .iter()
            .enumerate()
            .map(|(index, port)| {
                NodeDevice::provision(&btc_vault, devices_dir.join(format!("node{index}")), *port)
            })
            .collect::<Result<_, Error>>()?;

        let node_allowlist = vec![
            hot_wallet.descriptor.clone(),
            escape_wallet.descriptor.clone(),
        ];
        let ceremony_hot_allowlist: Vec<String> = node_allowlist
            .iter()
            .filter(|descriptor| **descriptor != escape_wallet.descriptor)
            .cloned()
            .collect();
        let params = node_params();

        println!("[1/4] setup ceremony: assembling the descriptor + manifest");
        let manifest = Manifest::assemble(
            &btc_vault,
            &coordinator.pubkey,
            &devices,
            &CeremonyParams {
                hot_allowlist: &ceremony_hot_allowlist,
                escape_descriptor: &escape_wallet.descriptor,
                threshold: QUORUM,
                user_key: user.pubkey,
                recovery_keys: &recovery_keys,
            },
            &params,
        )?;
        let descriptor_str = manifest.descriptor().to_string();
        let descriptor = Descriptor::<PublicKey>::from_str(&descriptor_str)?;
        let vault_spk = descriptor.script_pubkey();
        let witness_script = descriptor.explicit_script()?;
        let vault_address = descriptor.address(Network::Signet)?;
        for line in manifest.independence_report().lines() {
            if line.starts_with("VERDICT") {
                println!("      escape/recovery independence — {line}");
            }
        }
        println!("      vault descriptor: {descriptor_str}");
        println!("      SIGNET vault address: {vault_address}");

        println!("[2/4] starting {NODE_COUNT} vault-node daemons against the signet node");
        let node_bin = locate_vault_node()?;
        let nodes_dir = temp.path.join("nodes");
        std::fs::create_dir_all(&nodes_dir)?;
        let rpc_addr = signet_rpc_addr();
        let auth = signet_auth();
        // The startup vault-unspent warm reads the node-owned descriptor wallet (bead
        // btc-policy-hn8), so normal restarts issue no `scantxoutset`. A node's FIRST
        // bring-up against a backend still seeds its own wallet with a scan — ~10s on
        // this signet's 72M-UTXO set, with Core serializing scans process-wide. Five
        // fresh nodes started concurrently would therefore queue behind each other.
        // Keep raising the readiness deadline above the default 15s and spawn them ONE
        // AT A TIME for that one-time initialization. Nodes serve `/healthz`
        // independently and connect to peers lazily, so an early node waiting for
        // later peers is not a concern.
        //
        // The `importdescriptors` that follows that scan adds nothing measurable HERE:
        // this driver spawns before `fund_vault`, so the scan finds no vault output and
        // the birthday it derives is the tip itself — Core rescans from the tip, not
        // from the vault's history. A deployment brought up against an ALREADY funded
        // vault rescans from its oldest live output instead, and that is the case this
        // deadline would have to grow for.
        std::env::set_var("VAULT_NODE_READY_TIMEOUT_SECS", "120");
        let mut nodes = Vec::new();
        for (index, device) in devices.iter().enumerate() {
            let mut node = NodeProcess::spawn(
                &node_bin,
                &nodes_dir,
                NodeSpawn {
                    index,
                    device,
                    allowlist: &node_allowlist,
                    escape_descriptor: &escape_wallet.descriptor,
                    coord_auth_pubkey: &coord_auth_pubkey,
                    bitcoind_rpc_addr: rpc_addr,
                    bitcoind_auth: &auth,
                    manifest: &manifest,
                    params: &params,
                },
            )?;
            node.wait_ready()?;
            println!(
                "      node {} listening on 127.0.0.1:{} (channel ON, backend = signet {rpc_addr})",
                node.number(),
                node.port
            );
            nodes.push(node);
        }

        Ok(SignetFederation {
            secp,
            user,
            coordinator,
            nodes,
            descriptor,
            witness_script,
            vault_spk,
            hot_spk,
            escape_spk,
            temp,
        })
    }
}

/// Send the vault its coin from the funding wallet and wait for one confirmation.
/// Returns the confirmed vault UTXO (outpoint + txout) the spend will consume.
fn fund_vault(fed: &SignetFederation, amount: Amount) -> Result<Utxo, Error> {
    let vault_address = fed.descriptor.address(Network::Signet)?.to_string();
    let balance = wallet_rpc("getbalance", json!([]))?.as_f64().unwrap_or(0.0);
    println!(
        "[3/4] funding the vault: wallet '{}' balance {balance} tBTC",
        funding_wallet()
    );
    if balance < amount.to_btc() {
        return Err(format!(
            "funding wallet '{}' holds {balance} tBTC, needs at least {} — fund it from a signet \
             faucet first (address via `getnewaddress`)",
            funding_wallet(),
            amount.to_btc()
        )
        .into());
    }
    let txid = wallet_rpc("sendtoaddress", json!([vault_address, amount.to_btc()]))?
        .as_str()
        .ok_or("sendtoaddress returned no txid")?
        .to_string();
    println!("      vault funding tx {txid} broadcast; waiting for a signet block…");
    wait_for_confirmation(&txid, 1)?;
    let raw = node_rpc("getrawtransaction", json!([txid, true]))?;
    let hex = raw["hex"].as_str().ok_or("funding tx has no hex")?;
    let tx: Transaction = bitcoin::consensus::encode::deserialize_hex(hex)?;
    let (vout, txout) = tx
        .output
        .iter()
        .enumerate()
        .find(|(_, out)| out.script_pubkey == fed.vault_spk)
        .ok_or("funding tx pays no vault output")?;
    let outpoint = bitcoin::OutPoint::new(tx.compute_txid(), vout as u32);
    println!("      vault funded: {} at {outpoint}", txout.value);
    Ok(Utxo {
        outpoint,
        txout: txout.clone(),
    })
}

/// Poll the signet node until `txid` has at least `target` confirmations. Real block
/// timing, so this can take ~10 minutes per confirmation.
fn wait_for_confirmation(txid: &str, target: i64) -> Result<(), Error> {
    let deadline = Instant::now() + Duration::from_secs(45 * 60);
    let mut announced = false;
    while Instant::now() < deadline {
        if let Ok(tx) = node_rpc("getrawtransaction", json!([txid, true])) {
            let confs = tx["confirmations"].as_i64().unwrap_or(0);
            if confs >= target {
                return Ok(());
            }
            if !announced {
                println!("      seen in mempool/chain ({confs} conf); waiting for {target}…");
                announced = true;
            }
        }
        std::thread::sleep(Duration::from_secs(15));
    }
    Err(format!("{txid} did not reach {target} confirmation(s) in time").into())
}

/// Wait for the federation to broadcast `txid` (poll the signet mempool/chain).
fn wait_for_broadcast(txid: &str) -> Result<(), Error> {
    let deadline = Instant::now() + Duration::from_secs(HOLD_SECS + COMBINE_SLACK_SECS + 120);
    while Instant::now() < deadline {
        if node_rpc("getmempoolentry", json!([txid])).is_ok() {
            return Ok(());
        }
        if let Ok(tx) = node_rpc("getrawtransaction", json!([txid, true])) {
            if tx["confirmations"].as_i64().unwrap_or(0) >= 0 {
                return Ok(());
            }
        }
        std::thread::sleep(Duration::from_secs(3));
    }
    Err(format!("no node broadcast {txid} before the combine window closed").into())
}

/// Drive one honest spend: hot-wallet payment + escape variant, user-signed, normal
/// PIN, relayed to a single node; the federation propagates, holds for `HOLD_SECS`,
/// combines at T, and broadcasts to signet, where it confirms in a real block.
pub fn run_signet_spend() -> Result<(), Error> {
    println!("== btc-policy signet spend (bead 9y5.8 deliverable 1) ==");
    let fed = SignetFederation::bring_up()?;

    // Fund a hair under the Hot budget so the honest hot payment is well inside caps.
    let fund = Amount::from_sat(
        std::env::var("SIGNET_FUND_SATS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(200_000),
    );
    let vault_utxo = fund_vault(&fed, fund)?;

    println!("[4/4] driving one honest federated spend (Hold {HOLD_SECS}s, real signet blocks)");
    let vault_value = vault_utxo.txout.value;
    let hot_pay = vault_value / 2;
    let change = vault_value
        .checked_sub(hot_pay)
        .and_then(|rest| rest.checked_sub(FEE))
        .ok_or("vault balance cannot cover the spend")?;
    let sweep = vault_value
        .checked_sub(FEE)
        .ok_or("vault balance cannot cover the escape")?;

    let mut honest = build_spend(
        &vault_utxo,
        &fed.witness_script,
        &[
            (fed.hot_spk.clone(), hot_pay),
            (fed.vault_spk.clone(), change),
        ],
    )?;
    let mut escape = build_spend(
        &vault_utxo,
        &fed.witness_script,
        &[(fed.escape_spk.clone(), sweep)],
    )?;
    sign_all_inputs(&fed.secp, &mut honest, &fed.user, &fed.witness_script)?;
    sign_all_inputs(&fed.secp, &mut escape, &fed.user, &fed.witness_script)?;

    let body = vault_proto::SignRequest {
        psbt: honest.to_string(),
        escape_psbt: escape.to_string(),
        escape_bumps: Vec::new(),
        pin: NORMAL_PIN.into(),
        nonce: String::new(),
        expiry: commitment_expiry(COMMITMENT_TTL_SECS)?,
        policy_version: POLICY_VERSION,
        coord_sig: String::new(),
    };
    let wallet_id = fed.wallet_id();
    let request = fed.coordinator.authorize(&fed.secp, &wallet_id, body)?;

    let entry = &fed.nodes[0];
    match entry.sign(&request)? {
        vault_proto::SignResponse::Accepted(accepted) => println!(
            "      node {} @127.0.0.1:{} ACCEPTED {} — Hold now running on real time",
            entry.number(),
            entry.port,
            &accepted.commitment_id[..16]
        ),
        other => {
            return Err(format!(
                "node {} did not accept: {}",
                entry.number(),
                summarize(&other)
            )
            .into())
        }
    }

    let expected = honest.unsigned_tx.compute_txid().to_string();
    println!("      waiting out the {HOLD_SECS}s Hold, then the federation combine…");
    wait_for_broadcast(&expected)?;
    println!("      a NODE broadcast {expected} to signet ({QUORUM}-of-{NODE_COUNT} combined, no coordinator help)");
    wait_for_confirmation(&expected, 1)?;
    let confirmed = node_rpc("getrawtransaction", json!([expected, true]))?;
    let confs = confirmed["confirmations"].as_i64().unwrap_or(0);
    let blockhash = confirmed["blockhash"].as_str().unwrap_or("?");
    println!("\nSIGNET SPEND COMPLETE — honest spend {expected} confirmed on signet");
    println!("  confirmations: {confs}  block: {blockhash}");
    println!("  the live 5-node federation combined + broadcast against a real signet node");
    Ok(())
}
