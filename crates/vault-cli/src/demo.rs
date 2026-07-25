//! The two regtest demos (DESIGN.md, "The demo"). Both drive the SAME live 3-of-5
//! federation over the real Model-B spend path (ADR-0012), with the node-to-node
//! channel ON and every request coordinator-authenticated.
//!
//! # `demo first-light` — the internal checkpoint
//!
//! The smallest end-to-end run of the real spend path.
//!
//! **Act one — honest spend.** The coordinator composes the spend AND its
//! mandatory escape, the user signs both, and the coordinator relays one
//! coordinator-signed request to every node. Each node authenticates it, validates
//! both transactions, signs both partials at ingress, and answers a fixed
//! acknowledgement carrying **no signature at all**. At the Hold's expiry (zero
//! here) the nodes release their partials to each other over the channel, combine
//! `3`-of-`5`, package-validate, and **the nodes broadcast** — the coordinator
//! only watches the chain until the spend confirms.
//!
//! **Act two — theft refusal.** A correctly user-signed spend to a
//! non-allowlisted destination, with the real PIN, is refused by every node with a
//! structured `DEST_NOT_ALLOWED`.
//!
//! # `demo theft-refused` — the named v0 acceptance artifact
//!
//! DESIGN.md's ship-once two-act demo, on its own clean regtest federation.
//!
//! **Curtain-up — the Hold, working.** An ordinary hot spend the user *did*
//! authorize is held by every node and, at the Hold's expiry (time-warped on
//! regtest), released, combined, and broadcast by the federation. This is act two's
//! positive control, not decoration: act two's headline is an ABSENCE, and on a
//! federation that could not complete a held spend at all that absence would be
//! true for a reason with nothing to do with the claw-back.
//!
//! **Act one — theft refused.** The same structured refusal, driven directly
//! against the funded vault coin: an attacker holding the user's key AND the real
//! PIN sweeps to an address no allowlist descriptor derives, and every honest node
//! refuses with `DEST_NOT_ALLOWED`.
//!
//! **Act two — theft caught mid-Hold, clawed back.** The attacker's *allowlisted*
//! spend passes every policy check and is ACCEPTED — as a PENDING candidate, held
//! for the Hold the user can act inside. Inside that window the user answers with
//! an escape-class sweep of the attacked coin, which the nodes derive from its
//! OUTPUTS and fire IMMEDIATELY under either pin. The coins land in the user's
//! escape wallet, and the attacker's spend never reaches the mempool or a block.
//!
//! The exit code communicates the scorecard: `0` only when both acts — and the
//! control they rest on — behaved as specified, with a per-row PASS/FAIL line like
//! the adversarial harness.
//!
//! # Two properties both runs assert about the COORDINATOR itself
//!
//! Because they are what "pure relay" means operationally (§2):
//!
//!  - every `/sign` response is checked to carry no node signature — the response
//!    type has no variant that could;
//!  - vault-cli issues **zero** `sendrawtransaction` calls over the whole run
//!    ([`Bitcoind::broadcasts`]), so a post-wrench coordinator holds nothing it
//!    could broadcast even if it wanted to.

use std::fs::File;
use std::process::ExitCode;
use std::str::FromStr;
use std::time::{Duration, Instant};

use bitcoin::consensus::encode::deserialize_hex;
use bitcoin::secp256k1::{All, Secp256k1};
use bitcoin::{Amount, Network, Psbt, PublicKey, ScriptBuf, Transaction};
use miniscript::Descriptor;
use serde_json::json;
use vault_proto::{RefusalCode, SignRequest, SignResponse};

use crate::bitcoind::Bitcoind;
use crate::fed::{
    build_spend, build_spend_n, commitment_expiry, free_ports, locate_vault_node, p2wpkh_spk,
    sign_all_inputs, summarize, unix_now, utxo_paying, wallet_id, Actor, Coordinator, Manifest,
    NodeParams, NodeProcess, NodeSpawn, TempDir, Utxo, Wallet,
};
use crate::http::Error;

const NORMAL_PIN: &str = "246802";
const DURESS_PIN: &str = "135791";
const NODE_COUNT: usize = 5;
const QUORUM: usize = 3;
/// First light's Hold. Zero keeps it one-shot: a hot-class spend's fire event is
/// its ingress, so the nodes release, combine, and broadcast at once rather than
/// making the demo wait out a real 24h Hold.
const FIRST_LIGHT_HOLD_SECS: u64 = 0;
/// `theft-refused`'s Hold — the regtest time-warp of the real 24h one. Act two's
/// whole subject is the PENDING window, so this cannot be zero: it is the interval
/// in which the user sees a spend they never authorized and answers it. Long enough
/// that the escape-class sweep (a handful of seconds: relay, 1 Hz fire tick,
/// combine, broadcast, confirm) lands well inside it with margin to spare.
const CLAWBACK_HOLD_SECS: u64 = 60;
/// Inclusive combine/re-broadcast window after a candidate's fire time. At the
/// node's own floor — twice the vault-cache refresh interval — because act two
/// waits this window out in full before it may call the attacker's spend absent.
const CLAWBACK_COMBINE_SLACK_SECS: u64 = 20;
/// First light's combine window. Nothing waits it out, so it sits at a roomy value.
const FIRST_LIGHT_COMBINE_SLACK_SECS: u64 = 60;
/// Margin on top of a candidate's Hold + combine window before its absence from the
/// chain is read as evidence. Carrier fan-out and the fire tick are asynchronous, so
/// one node's `first_seen` is only a lower bound for the rest.
const FIRE_OBSERVATION_MARGIN_SECS: u64 = 15;
/// How long the coordinator waits for the FEDERATION to broadcast. Generous
/// relative to the node's 1s fire interval, so a timeout means the nodes genuinely
/// failed to combine rather than that we were impatient.
const NODE_BROADCAST_TIMEOUT: Duration = Duration::from_secs(30);
/// The baked policy identifier every commitment carries (policy never changes).
const POLICY_VERSION: u32 = 1;
/// Node-enforced cap on coordinator-proposed expiry (DESIGN.md config schema).
const MAX_COMMITMENT_AGE_SECS: u64 = 172_800;
/// The expiry the coordinator proposes on each spend: an hour out, well inside
/// the node's cap.
const COMMITMENT_TTL_SECS: u64 = 3_600;
/// Bound on the node's own-descriptor / allowlist derivation scans.
const MAX_DERIVATION_INDEX: u32 = 100;
/// The (non-zero) index the honest spend pays the hot wallet at — a freshly
/// derived address, proving the allowlist is a descriptor, not a fixed address.
const HOT_INDEX: u32 = 5;
/// Coins sent into the vault.
const FUND: Amount = Amount::from_sat(1_000_000_000);
/// The coin `theft-refused`'s curtain-up control spends. It rides its own coin so
/// the two acts work on an untouched vault coin.
const CONTROL_FUND: Amount = Amount::from_sat(20_000_000);
/// A second, small vault coin, funded only by `theft-refused`. An escape-class
/// spend completes IMMEDIATELY, so the node requires its mandatory escape to be a
/// DISTINCT, disjoint residual candidate for the `T`-time sweep (`vault-node`,
/// `escape_class_residual`) — which needs a vault coin the sweep itself does not
/// spend. It is the residual reserve, never the coin under attack.
const RESIDUAL_FUND: Amount = Amount::from_sat(50_000_000);
/// First light's act one pays this to the hot wallet; the rest returns to the
/// vault. `theft-refused`'s act two reuses it as the attacker's allowlisted take.
const HOT_SPEND: Amount = Amount::from_sat(400_000_000);
/// Flat demo fee — far under the 10% cap.
const FEE: Amount = Amount::from_sat(10_000);
/// The demo's **Hot budget** (ADR-0014), sealed into the manifest and configured
/// on every node. Set generously relative to `HOT_SPEND` so the honest act-one
/// spend is well under both caps: the demo proves the vault WORKS, and a cap
/// tuned to bite here would only prove the demo was mis-provisioned. A real vault
/// that sizes for the full `c = t−1` compromised-signer tolerance sets
/// `HOT_MAX_PER_WINDOW` no higher than the tolerable per-window loss divided by `t`.
/// With no compromised signer (`c = 0`), production `n = 2t−1` gives the tighter
/// `(2 − 1/t)·V < 2V` pure-censorship bound (ADR-0014 consequences).
const HOT_MAX_PER_TX: Amount = Amount::from_sat(600_000_000);
const HOT_MAX_PER_WINDOW: Amount = Amount::from_sat(900_000_000);
/// The velocity window. Equal to `MAX_COMMITMENT_AGE_SECS`, the floor the node
/// enforces at load: the window must cover every candidate throughout its
/// node-authorized completion lifetime.
const HOT_WINDOW_SECS: u64 = MAX_COMMITMENT_AGE_SECS;

/// The demo's per-vault policy numbers, in the one shape the ceremony and the
/// generated node configs both read. `hold_secs` and `combine_slack_secs` are the
/// only two the two demos disagree about — first light has nothing to hold, while
/// `theft-refused` act two exists entirely inside the Hold.
fn node_params(hold_secs: u64, combine_slack_secs: u64) -> NodeParams {
    NodeParams {
        hold_secs,
        // Neither demo enters duress, so the hostage window and its margin stay at
        // the node's own defaults; `attack` is where they are tuned.
        duress_delay_secs: 0,
        epsilon_secs: 60,
        combine_slack_secs,
        max_commitment_age_secs: MAX_COMMITMENT_AGE_SECS,
        delivery_horizon_secs: 60,
        max_derivation_index: MAX_DERIVATION_INDEX,
        policy_version: POLICY_VERSION,
        max_msg_bytes: vault_node::channel::DEFAULT_MAX_MSG_BYTES,
        hot_budget: vault_node::HotBudget {
            max_per_tx_sat: HOT_MAX_PER_TX.to_sat(),
            max_per_window_sat: HOT_MAX_PER_WINDOW.to_sat(),
            window_secs: HOT_WINDOW_SECS,
        },
        normal_pin: NORMAL_PIN.to_string(),
        duress_pin: DURESS_PIN.to_string(),
        // The demos measure nothing about pin latency, so they enrol at the fixture
        // minimum and stay fast.
        pin_m_cost_kib: 8,
        escape_feerate_floor: 1,
    }
}

// ---------------------------------------------------------------------------
// The federation both demos drive

/// A live regtest federation: a funded 3-of-5 vault, five `vault-node` daemons, and
/// the one coordinator provisioned as their trust root.
///
/// Factored out of `first-light` when `theft-refused` arrived, for the reason
/// `fed.rs` exists for `attack`: the two demos are only evidence about the same
/// product if the federation they drive is the same one. A second, demo-local
/// bring-up could drift into a weaker vault — a looser cap, a stale manifest field —
/// and every assertion made against it would be about that weaker vault instead.
struct Federation {
    secp: Secp256k1<All>,
    user: Actor,
    /// The coordinator auth keypair (ADR-0013 §2): ONE root, generated once,
    /// provisioned into every node's per-vault config (and therefore the channel
    /// manifest), and signing every request the acts relay.
    coordinator: Coordinator,
    /// Declared BEFORE `bitcoind`, which is declared before `temp`: struct fields
    /// drop in declaration order, so the daemons die first, then the chain they
    /// poll, then the directory holding both — including on the error path.
    nodes: Vec<NodeProcess>,
    bitcoind: Bitcoind,
    mining_address: String,
    descriptor: Descriptor<PublicKey>,
    witness_script: ScriptBuf,
    vault_spk: ScriptBuf,
    /// The vault's first funded coin.
    vault_utxo: Utxo,
    hot_spk: ScriptBuf,
    escape_spk: ScriptBuf,
    /// A raw key that derives from no descriptor — the theft destination.
    attacker_spk: ScriptBuf,
    params: NodeParams,
    #[allow(dead_code)]
    temp: TempDir,
}

impl Federation {
    /// Generate throwaway keys, start a private regtest bitcoind, fund the vault,
    /// run the setup ceremony, and start `NODE_COUNT` daemons. Prints steps 1–3 of
    /// each demo's 4; step 4 is the acts.
    ///
    /// Deliberate demo deviation from DESIGN.md D4/T1 (on-node key birth, no machine
    /// ever holds two node keys, nothing at rest): this one process births every
    /// throwaway regtest key and writes node seckeys into temp-dir TOML. The v0
    /// provisioning task (T1) removes this.
    fn bring_up(tag: &str, params: NodeParams) -> Result<Federation, Error> {
        let secp = Secp256k1::new();

        // RAII cleanup: locals drop in reverse order, so declaring temp dir →
        // bitcoind → node processes tears down nodes first, then bitcoind, then
        // removes the temp dir — even on the error path.
        println!("[1/4] generating throwaway keys (user, {NODE_COUNT} nodes, destinations)");
        let temp = TempDir::new(tag)?;
        let mut urandom = File::open("/dev/urandom")?;
        let user = Actor::random(&secp, &mut urandom)?;
        let node_actors: Vec<Actor> = (0..NODE_COUNT)
            .map(|_| Actor::random(&secp, &mut urandom))
            .collect::<Result<_, _>>()?;
        // Regtest provisioning — no SSH; the real ceremony is later V0-9.
        let coordinator = Coordinator::random(&secp, &mut urandom)?;
        let coord_auth_pubkey = coordinator.pubkey.to_string();
        // Hot and escape wallets are ranged xpub descriptors, so every spend pays a
        // freshly derived address instead of a reused fixed one (DESIGN.md,
        // "Destination allowlist"). The honest spend pays the hot wallet at a
        // non-zero index; every escape sweeps to the escape wallet's index 0.
        //
        // Escape-key independence is a HARD assumption (ADR-0012 threat model): a
        // shared-seed escape turns the claw-back into theft outright. This wallet is
        // born from its own seed.
        let hot_wallet = Wallet::random(&secp, &mut urandom)?;
        let escape_wallet = Wallet::random(&secp, &mut urandom)?;
        let hot_spk = hot_wallet.address_spk(&secp, HOT_INDEX)?;
        let escape_spk = escape_wallet.address_spk(&secp, 0)?;
        let attacker_spk = p2wpkh_spk(&Actor::random(&secp, &mut urandom)?);

        // The demo vault: user key AND 3-of-5 node keys on the normal branch, OR the
        // timelocked recovery branch — `older(4224679)` + a 2-of-3 recovery keyset
        // (ADR-0013 §1, V0-10). The recovery keys are throwaway regtest keys, UNUSED
        // on the normal path both demos exercise: they prove the recovery branch does
        // not disturb the normal spend, and `demo recovery-drill` exercises the exit.
        let node_pubkeys: Vec<String> = node_actors.iter().map(|a| a.pubkey.to_string()).collect();
        let recovery_pubkeys: Vec<String> = (0..policy_core::RECOVERY_KEYS)
            .map(|_| Ok(Actor::random(&secp, &mut urandom)?.pubkey.to_string()))
            .collect::<Result<_, Error>>()?;
        let descriptor_str = policy_core::vault_descriptor_string(
            &user.pubkey.to_string(),
            QUORUM,
            &node_pubkeys,
            &recovery_pubkeys,
        );
        let descriptor = Descriptor::<PublicKey>::from_str(&descriptor_str)?;
        let vault_spk = descriptor.script_pubkey();
        let witness_script = descriptor.explicit_script()?;
        let vault_address = descriptor.address(Network::Regtest)?;

        println!("[2/4] starting private regtest bitcoind, funding the vault");
        let ports = free_ports(1 + NODE_COUNT)?;
        let mut bitcoind = Bitcoind::start(temp.path.join("bitcoind"), ports[0])?;
        bitcoind.create_wallet(tag)?;
        let mining_address = bitcoind.call_str("getnewaddress", json!([]))?;
        bitcoind.call("generatetoaddress", json!([101, mining_address]))?;
        let funding_txid = bitcoind.call_str(
            "sendtoaddress",
            json!([vault_address.to_string(), FUND.to_btc()]),
        )?;
        bitcoind.call("generatetoaddress", json!([1, mining_address]))?;
        let funding_hex = bitcoind.call_str("getrawtransaction", json!([funding_txid]))?;
        let funding_tx: Transaction = deserialize_hex(&funding_hex)?;
        let vault_utxo = utxo_paying(&funding_tx, &vault_spk)?;
        println!(
            "      vault {} funded with {} at {}",
            vault_address, vault_utxo.txout.value, vault_utxo.outpoint
        );

        println!("[3/4] running the setup ceremony, starting {NODE_COUNT} vault-node processes");
        // The effective per-vault policy, printed rather than left implicit: it is
        // what a reader (or a CI artifact) needs to interpret every line below.
        println!(
            "      config: {QUORUM}-of-{NODE_COUNT}, hold {}s, combine slack {}s, hot budget \
             {}/{} sat per tx/window over {}s, commitment TTL {COMMITMENT_TTL_SECS}s, policy v{}",
            params.hold_secs,
            params.combine_slack_secs,
            params.hot_budget.max_per_tx_sat,
            params.hot_budget.max_per_window_sat,
            params.hot_budget.window_secs,
            params.policy_version,
        );
        let node_bin = locate_vault_node()?;
        let nodes_dir = temp.path.join("nodes");
        std::fs::create_dir_all(&nodes_dir)?;
        let node_ports: Vec<u16> = ports[1..=NODE_COUNT].to_vec();
        // The ONE destination allowlist, written once. Every node gets exactly this in
        // its config, and the ceremony's sealed `hot_allowlist` is DERIVED from it by
        // the same rule `Node::load` applies — drop the escape descriptor, which is an
        // allowlist entry so its sweep passes the destination check but is never a hot
        // destination. Two hand-maintained copies would let a later edit to one of them
        // seal a `manifest_hash` no node can reproduce, and every node would then fail
        // startup on the manifest check.
        let node_allowlist = [
            hot_wallet.descriptor.as_str(),
            escape_wallet.descriptor.as_str(),
        ];
        let ceremony_hot_allowlist: Vec<String> = node_allowlist
            .iter()
            .filter(|descriptor| **descriptor != escape_wallet.descriptor.as_str())
            .map(|descriptor| (*descriptor).to_string())
            .collect();
        // The setup ceremony (ADR-0013 §4): assemble the manifest over every node's
        // keys + endpoints, hash it, and endorse each channel key with that node's own
        // signing key. Every byte is computed by the node's own code (see
        // `vault_node::channel::ceremony`), so the federation this provisions agrees
        // with itself by construction rather than by luck.
        let manifest = Manifest::assemble(
            &wallet_id(&descriptor),
            &coordinator.pubkey,
            &node_actors,
            &node_ports,
            &params.ceremony(&ceremony_hot_allowlist, &escape_wallet.descriptor),
        )?;
        let mut nodes = Vec::new();
        for (index, actor) in node_actors.iter().enumerate() {
            nodes.push(NodeProcess::spawn(
                &node_bin,
                &nodes_dir,
                NodeSpawn {
                    index,
                    port: node_ports[index],
                    actor,
                    descriptor: &descriptor_str,
                    allowlist: &node_allowlist,
                    escape_descriptor: &escape_wallet.descriptor,
                    // The one coordinator auth root, provisioned identically into
                    // every node's per-vault config (ADR-0013 §2/§4).
                    coord_auth_pubkey: &coord_auth_pubkey,
                    // Each node drives its own watchtower AND its own broadcast
                    // against this regtest bitcoind (ADR-0001; ADR-0012 Model B).
                    bitcoind_rpc_addr: bitcoind.rpc_addr(),
                    bitcoind_auth: bitcoind.auth(),
                    manifest: &manifest,
                    params: &params,
                },
            )?);
        }
        for node in &mut nodes {
            node.wait_ready()?;
            println!(
                "      node {} listening on 127.0.0.1:{} (channel ON)",
                node.number(),
                node.port
            );
        }

        Ok(Federation {
            secp,
            user,
            coordinator,
            nodes,
            bitcoind,
            mining_address,
            descriptor,
            witness_script,
            vault_spk,
            vault_utxo,
            hot_spk,
            escape_spk,
            attacker_spk,
            params,
            temp,
        })
    }

    fn wallet_id(&self) -> [u8; 32] {
        wallet_id(&self.descriptor)
    }

    /// Fund the vault with one more confirmed coin.
    fn fund(&self, amount: Amount) -> Result<Utxo, Error> {
        let address = self.descriptor.address(Network::Regtest)?;
        let txid = self.bitcoind.call_str(
            "sendtoaddress",
            json!([address.to_string(), amount.to_btc()]),
        )?;
        self.mine(1)?;
        let hex = self.bitcoind.call_str("getrawtransaction", json!([txid]))?;
        let tx: Transaction = deserialize_hex(&hex)?;
        utxo_paying(&tx, &self.vault_spk)
    }

    fn mine(&self, blocks: u32) -> Result<(), Error> {
        self.bitcoind
            .call("generatetoaddress", json!([blocks, self.mining_address]))?;
        Ok(())
    }

    /// The user signs the spend AND its escape variant, every time — the
    /// two-transaction ceremony (ADR-0008).
    fn user_signs(&self, spend: &mut Psbt, escape: &mut Psbt) -> Result<(), Error> {
        sign_all_inputs(&self.secp, spend, &self.user, &self.witness_script)?;
        sign_all_inputs(&self.secp, escape, &self.user, &self.witness_script)
    }

    /// The coordinator authenticates a request body: a fresh single-use nonce and a
    /// signature over the canonical bytes, so the node admits it past the auth gate
    /// (ADR-0013 §2).
    fn authorize(&self, body: SignRequest) -> Result<SignRequest, Error> {
        self.coordinator
            .authorize(&self.secp, &self.wallet_id(), body)
    }

    /// User-sign both halves, then coordinator-authenticate the pair.
    fn request(&self, spend: &Psbt, escape: &Psbt, pin: &str) -> Result<SignRequest, Error> {
        let mut spend = spend.clone();
        let mut escape = escape.clone();
        self.user_signs(&mut spend, &mut escape)?;
        self.authorize(body(&spend, &escape, pin)?)
    }

    /// Relay to every node, re-authenticating per node with a FRESH nonce.
    ///
    /// An accepted request propagates: the first node hands the coordinator-signed
    /// carrier to its peers, so by the time this loop reaches node 3 that node may
    /// already hold the candidate. Re-using one nonce would then be answered as a
    /// replay — dup suppression working correctly, but not the per-node
    /// acknowledgement the acts read.
    fn relay_all_fresh(&self, request: &SignRequest) -> Result<Vec<SignResponse>, Error> {
        let mut responses = Vec::new();
        for node in &self.nodes {
            let fresh = self.authorize(request.clone())?;
            responses.push(node.sign(&fresh)?);
        }
        Ok(responses)
    }

    /// Wait for `txid` to appear in the regtest mempool. This is the coordinator
    /// waiting on the FEDERATION: nothing here can make the spend happen, so a
    /// timeout means the nodes did not combine and broadcast.
    fn wait_for_mempool(&self, txid: &str) -> Result<(), Error> {
        let deadline = Instant::now() + NODE_BROADCAST_TIMEOUT;
        while Instant::now() < deadline {
            if self.bitcoind.call("getmempoolentry", json!([txid])).is_ok() {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        Err(format!(
            "no node broadcast {txid} within {}s: the federation did not combine",
            NODE_BROADCAST_TIMEOUT.as_secs()
        )
        .into())
    }

    /// Whether `txid` is in the mempool or a block.
    ///
    /// bitcoind reports "not in the mempool" and "no such transaction" as JSON-RPC
    /// *errors*, so a lookup written as `call(..).is_ok()` cannot tell absent from
    /// broken — a dead daemon or a timeout would read as "the attacker's spend never
    /// landed". `call_optional` flattens ONLY the absence code to `None`.
    fn in_mempool_or_chain(&self, txid: &str) -> Result<bool, Error> {
        if self
            .bitcoind
            .call_optional("getmempoolentry", json!([txid]))?
            .is_some()
        {
            return Ok(true);
        }
        Ok(self
            .bitcoind
            .call_optional("getrawtransaction", json!([txid, true]))?
            .is_some())
    }

    /// Σ value of the UTXOs paying `spk`. Callers mine first, so anything the
    /// federation broadcast is on-chain rather than resting in the mempool.
    ///
    /// A missing `total_amount` is a broken scan, NOT an empty one. Defaulting it to
    /// zero would make a degraded bitcoind report "the attacker got nothing" from the
    /// call that IS the no-theft ground truth.
    fn unspent_paying(&self, spk: &ScriptBuf) -> Result<Amount, Error> {
        let scan = self
            .bitcoind
            .scan_txoutset(json!([format!("raw({})", spk.to_hex_string())]))?;
        let total = scan
            .get("total_amount")
            .and_then(serde_json::Value::as_f64)
            .ok_or_else(|| format!("scantxoutset returned no total_amount: {scan}"))?;
        Ok(Amount::from_sat((total * 100_000_000.0).round() as u64))
    }

    /// Wait until `deadline` (unix seconds) has passed.
    fn wait_past(&self, deadline: u64) -> Result<(), Error> {
        while unix_now()? <= deadline {
            std::thread::sleep(Duration::from_millis(250));
        }
        Ok(())
    }

    /// The pure-relay property, measured rather than asserted from the source: this
    /// process pushed no transaction at any point in the run.
    fn assert_pure_relay(&self) -> Result<(), Error> {
        if self.bitcoind.broadcasts() != 0 {
            return Err(format!(
                "the coordinator issued {} sendrawtransaction call(s): under Model B the NODES \
                 broadcast and vault-cli is a pure relay",
                self.bitcoind.broadcasts()
            )
            .into());
        }
        println!(
            "  pure relay OK — vault-cli issued 0 sendrawtransaction calls; every broadcast came \
             from a node"
        );
        Ok(())
    }
}

/// The unauthenticated request body over two ALREADY user-signed transactions.
fn body(spend: &Psbt, escape: &Psbt, pin: &str) -> Result<SignRequest, Error> {
    Ok(SignRequest {
        psbt: spend.to_string(),
        escape_psbt: escape.to_string(),
        pin: pin.into(),
        nonce: String::new(),
        expiry: commitment_expiry(COMMITMENT_TTL_SECS)?,
        policy_version: POLICY_VERSION,
        coord_sig: String::new(),
    })
}

// ---------------------------------------------------------------------------
// demo first-light

pub fn run_first_light() -> Result<(), Error> {
    let fed = Federation::bring_up(
        "first-light",
        node_params(FIRST_LIGHT_HOLD_SECS, FIRST_LIGHT_COMBINE_SLACK_SECS),
    )?;

    println!("[4/4] running the two acts");
    let spend_tx = first_light_act_one(&fed)?;

    println!("\n== act two: theft attempt — stolen user key, non-allowlisted destination ==");
    let change_utxo = utxo_paying(&spend_tx, &fed.vault_spk)?;
    let refusals = theft_to_unknown_address_is_refused(&fed, &change_utxo)?;
    println!("  ACT TWO OK — {refusals}/{NODE_COUNT} nodes refused with DEST_NOT_ALLOWED");

    // The honest spend confirmed anyway — the nodes broadcast it.
    fed.assert_pure_relay()?;
    println!("\nFIRST LIGHT COMPLETE — honest spend confirmed via NODE broadcast, theft refused by every node");
    Ok(())
}

/// Act one — honest spend: hot-wallet payment + escape variant, user-signed,
/// normal PIN; all nodes sign; 3 signatures are combined and the spend
/// confirms on-chain. Returns the confirmed transaction.
fn first_light_act_one(fed: &Federation) -> Result<Transaction, Error> {
    println!("\n== act one: honest spend to the hot wallet ==");
    let vault_utxo = &fed.vault_utxo;
    let vault_value = vault_utxo.txout.value;
    let change = vault_value
        .checked_sub(HOT_SPEND)
        .and_then(|rest| rest.checked_sub(FEE))
        .ok_or("vault balance cannot cover the demo spend")?;
    let sweep = vault_value
        .checked_sub(FEE)
        .ok_or("vault balance cannot cover the escape sweep")?;

    let mut honest = build_spend(
        vault_utxo,
        &fed.witness_script,
        &[
            (fed.hot_spk.clone(), HOT_SPEND),
            (fed.vault_spk.clone(), change),
        ],
    )?;
    let mut escape = build_spend(
        vault_utxo,
        &fed.witness_script,
        &[(fed.escape_spk.clone(), sweep)],
    )?;
    fed.user_signs(&mut honest, &mut escape)?;
    let body = body(&honest, &escape, NORMAL_PIN)?;

    // Before the honest relay: the trust root itself. This same, otherwise
    // PERFECTLY valid spend — allowlisted destination, real user signature, real
    // PIN — signed by a coordinator outside the nodes' configured root — must be
    // refused by every node (ADR-0013 §2). Nothing but the coordinator identity
    // differs, so COORD_AUTH_INVALID (never DEST_NOT_ALLOWED or BAD_PIN) is proof
    // the configured root is what refused it.
    foreign_coordinator_is_refused(fed, &body)?;

    // The real coordinator relays to exactly ONE node. The federation does the
    // rest: that node propagates the coordinator-signed request to its peers, each
    // of which re-runs its own gates and signs at ingress (§3). This is deliberate
    // — a spend that confirms after reaching one node is the demonstration that
    // selective delivery buys a post-wrench coordinator nothing, and it is the
    // property V0-4b needs so a duress request that reaches one node arms the rest.
    // A node that has already learned the request from a peer answers the
    // coordinator's own copy as a replayed nonce, which is the dup suppression
    // working; relaying to one node keeps that off the demo's happy path.
    let request = fed.authorize(body)?;
    let entry = &fed.nodes[0];
    match entry.sign(&request)? {
        SignResponse::Accepted(accepted) => {
            println!(
                "  node {} @127.0.0.1:{} → ACCEPTED {} (no signature returned)",
                entry.number(),
                entry.port,
                &accepted.commitment_id[..16],
            );
        }
        other => {
            return Err(format!(
                "node {} did not accept the honest spend: {}",
                entry.number(),
                summarize(&other)
            )
            .into())
        }
    }
    println!(
        "  relayed to node {} ONLY — the coordinator holds one acknowledgement and ZERO node \
         signatures, so it cannot finalize anything",
        entry.number()
    );

    // The nodes now do the rest by themselves: the request reaches the whole
    // federation by propagation, each node signs at ingress, and at the Hold's
    // expiry each releases its partials to its peers. The first node to hold t of
    // them per input combines, package-validates, and broadcasts. The coordinator
    // only WATCHES — and the spend cannot confirm at all unless at least QUORUM
    // nodes learned the request, which is propagation proving itself.
    let expected_txid = honest.unsigned_tx.compute_txid();
    fed.wait_for_mempool(&expected_txid.to_string())?;
    println!(
        "  a NODE broadcast {expected_txid} — {QUORUM}-of-{NODE_COUNT} signed it after the \
         request propagated from one node, with no coordinator help"
    );

    fed.mine(1)?;
    let raw = fed.bitcoind.call(
        "getrawtransaction",
        json!([expected_txid.to_string(), true]),
    )?;
    let confirmations = raw["confirmations"].as_i64().unwrap_or(0);
    if confirmations < 1 {
        return Err(format!("node-broadcast spend {expected_txid} did not confirm").into());
    }
    let tx: Transaction = deserialize_hex(
        raw["hex"]
            .as_str()
            .ok_or("getrawtransaction: no hex for the confirmed spend")?,
    )?;
    println!(
        "  ACT ONE OK — honest spend {expected_txid} confirmed ({confirmations} confirmation), \
         broadcast by a node"
    );
    Ok(tx)
}

/// The coordinator trust root, demonstrated against the live federation: a
/// request signed by a coordinator that is NOT the one provisioned into the
/// nodes' configured trust root is refused by EVERY node with
/// `COORD_AUTH_INVALID` (ADR-0013 §2). `body` is an otherwise-valid spend, so this
/// isolates coordinator authentication as the sole reason for the refusal — the
/// property V0-8b's Model-B spend path authenticates against.
fn foreign_coordinator_is_refused(fed: &Federation, body: &SignRequest) -> Result<(), Error> {
    // A coordinator the vault was never sealed to: a different key, but one that
    // signs the canonical bytes just as correctly as the real one.
    let foreign = Coordinator::random(&fed.secp, &mut File::open("/dev/urandom")?)?;
    // Sign under the REAL vault id but a foreign KEY: the node rejects on the key,
    // isolating coordinator authentication (not the wallet_id bind) as the cause.
    let request = foreign.authorize(&fed.secp, &fed.wallet_id(), body.clone())?;
    let mut refusals = 0;
    for node in &fed.nodes {
        match node.sign(&request)? {
            SignResponse::Refusal(refusal) if refusal.code == RefusalCode::CoordAuthInvalid => {
                refusals += 1;
            }
            other => {
                return Err(format!(
                    "node {} did not refuse a foreign coordinator with COORD_AUTH_INVALID: {}",
                    node.number(),
                    summarize(&other)
                )
                .into())
            }
        }
    }
    println!(
        "  trust root OK — {refusals}/{NODE_COUNT} nodes refused a coordinator \
         outside their configured trust root with COORD_AUTH_INVALID"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// The shared refusal act

/// Theft refused — `first-light`'s act two and `theft-refused`'s act one: a
/// CORRECTLY user-signed spend of a vault coin to a destination no allowlist
/// descriptor derives, sent with the real PIN.
///
/// The attacker holds everything the user holds — the key AND the PIN, the worst
/// case — so the destination allowlist alone must stop this, and every node must say
/// so in a structured, machine-readable refusal rather than by silence or by a
/// generic error. The request is a genuine coordinator-authenticated one too: it
/// must pass the coord-auth gate to REACH the policy refusal, or the demo would be
/// showing the wrong check.
///
/// Returns the number of nodes that refused, which is `NODE_COUNT` on every path
/// that returns `Ok` — a single node answering anything else is an error.
fn theft_to_unknown_address_is_refused(fed: &Federation, coin: &Utxo) -> Result<usize, Error> {
    let loot = coin
        .txout
        .value
        .checked_sub(FEE)
        .ok_or("the vault coin cannot cover the theft")?;
    let theft = build_spend(
        coin,
        &fed.witness_script,
        &[(fed.attacker_spk.clone(), loot)],
    )?;
    let escape = build_spend(coin, &fed.witness_script, &[(fed.escape_spk.clone(), loot)])?;
    let request = fed.request(&theft, &escape, NORMAL_PIN)?;

    let mut refusals = 0;
    for node in &fed.nodes {
        match node.sign(&request)? {
            SignResponse::Refusal(refusal) if refusal.code == RefusalCode::DestNotAllowed => {
                println!(
                    "  node {} @127.0.0.1:{} → REFUSED {}",
                    node.number(),
                    node.port,
                    serde_json::to_string(&refusal)?
                );
                refusals += 1;
            }
            other => {
                return Err(format!(
                    "node {} did not refuse the theft with DEST_NOT_ALLOWED: {}",
                    node.number(),
                    summarize(&other)
                )
                .into())
            }
        }
    }
    Ok(refusals)
}

// ---------------------------------------------------------------------------
// demo theft-refused

/// One act's verdict, for the scorecard.
struct ActResult {
    name: &'static str,
    outcome: Result<String, String>,
}

/// The v0 acceptance artifact. Every row is attempted even if an earlier one fails,
/// so the scorecard reports the whole run rather than only its first casualty; the
/// exit code is `0` only when all of them passed as specified.
pub fn run_theft_refused() -> ExitCode {
    let fed = match Federation::bring_up(
        "theft-refused",
        node_params(CLAWBACK_HOLD_SECS, CLAWBACK_COMBINE_SLACK_SECS),
    ) {
        Ok(fed) => fed,
        Err(e) => {
            eprintln!("\nTHEFT-REFUSED FAILED — the federation did not come up: {e}");
            return ExitCode::FAILURE;
        }
    };

    println!("[4/4] running the control and the two acts");
    let acts = [
        ActResult {
            name: "curtain-up: the Hold releases an authorized spend",
            outcome: hold_releases_an_authorized_spend(&fed).map_err(|e| e.to_string()),
        },
        ActResult {
            name: "act one: theft refused",
            outcome: theft_refused_act_one(&fed).map_err(|e| e.to_string()),
        },
        ActResult {
            name: "act two: caught mid-Hold, clawed back",
            outcome: theft_refused_act_two(&fed).map_err(|e| e.to_string()),
        },
    ];
    // The pure-relay measurement is a property of the WHOLE run, so it is taken
    // after both acts and reported as its own scorecard row.
    let relay = ActResult {
        name: "coordinator: pure relay",
        outcome: fed
            .assert_pure_relay()
            .map(|()| "0 sendrawtransaction calls from vault-cli".to_string())
            .map_err(|e| e.to_string()),
    };

    println!("\n──────────────────────────────────────────────────────────────");
    println!(" THEFT-REFUSED SCORECARD   ({QUORUM}-of-{NODE_COUNT} federation)");
    println!("──────────────────────────────────────────────────────────────");
    let mut failed = 0;
    for act in acts.iter().chain(std::iter::once(&relay)) {
        let (mark, detail) = match &act.outcome {
            Ok(detail) => ("PASS", detail.as_str()),
            Err(detail) => {
                failed += 1;
                ("FAIL", detail.as_str())
            }
        };
        println!(" {mark}  {:<50} {detail}", act.name);
    }
    println!("──────────────────────────────────────────────────────────────");
    if failed == 0 {
        println!(
            "\nTHEFT REFUSED — the unknown-destination sweep was refused by every node, and the \
             allowlisted one was caught mid-Hold and clawed back into the escape wallet."
        );
        ExitCode::SUCCESS
    } else {
        eprintln!("\nTHEFT-REFUSED FAILED — {failed} act(s) did not behave as specified");
        ExitCode::FAILURE
    }
}

/// Curtain-up — the Hold, working, on this exact federation.
///
/// An ordinary hot spend the user DID authorize: every node holds it, and at the
/// Hold's expiry the nodes release their partials to each other, combine
/// `3`-of-`5`, and broadcast. The coordinator only watches.
///
/// This is act two's POSITIVE CONTROL, and it is why it runs first. Act two argues
/// from an absence — the attacker's pending spend never reaches the mempool or a
/// block — and an absence is only evidence when the thing that would have produced
/// its presence is known to work here. Without this, a federation that simply never
/// completes a held spend would pass act two for the wrong reason. It rides its own
/// coin, so the vault coin the two acts work on is untouched.
fn hold_releases_an_authorized_spend(fed: &Federation) -> Result<String, Error> {
    println!("\n== curtain-up: an authorized hot spend, through the Hold ==");
    let coin = fed.fund(CONTROL_FUND)?;
    let paid = coin
        .txout
        .value
        .checked_sub(FEE)
        .ok_or("the control coin cannot cover an authorized spend")?;
    let spend = build_spend(&coin, &fed.witness_script, &[(fed.hot_spk.clone(), paid)])?;
    let escape = build_spend(
        &coin,
        &fed.witness_script,
        &[(fed.escape_spk.clone(), paid)],
    )?;
    let request = fed.request(&spend, &escape, NORMAL_PIN)?;
    let txid = spend.unsigned_tx.compute_txid().to_string();

    // The LATEST fire time across the federation, not the earliest: this waits for
    // the release to have happened everywhere, so a timeout below means the nodes
    // genuinely failed to combine rather than that one node was still holding.
    let mut fires_at = 0;
    for (node, response) in fed.nodes.iter().zip(fed.relay_all_fresh(&request)?) {
        let accepted = match response {
            SignResponse::Accepted(accepted) => accepted,
            other => {
                return Err(format!(
                    "node {} did not accept the user's own hot spend: {}",
                    node.number(),
                    summarize(&other)
                )
                .into())
            }
        };
        if accepted.remaining_secs == 0 {
            return Err(format!(
                "node {} fired the authorized hot spend at ingress instead of holding it; this \
                 control has to exercise the same {}s Hold act two's attacker spend sits in",
                node.number(),
                fed.params.hold_secs
            )
            .into());
        }
        fires_at = fires_at.max(accepted.first_seen.saturating_add(accepted.remaining_secs));
    }
    println!(
        "  every node HELD it — pending for {}s, no signature returned to the coordinator",
        fed.params.hold_secs
    );

    fed.wait_past(fires_at)?;
    fed.wait_for_mempool(&txid)?;
    fed.mine(1)?;
    let raw = fed
        .bitcoind
        .call("getrawtransaction", json!([txid, true]))?;
    let confirmations = raw["confirmations"].as_i64().unwrap_or(0);
    if confirmations < 1 {
        return Err(format!("the authorized spend {txid} did not confirm after its Hold").into());
    }
    let detail = format!(
        "{paid} to the hot wallet after a {}s Hold, broadcast by a node",
        fed.params.hold_secs
    );
    println!("  CURTAIN-UP OK — {detail} ({txid})");
    Ok(detail)
}

/// Act one — theft refused: the attacker holds the user's key and the PIN, and
/// sweeps the funded vault coin to an address no allowlist descriptor derives.
fn theft_refused_act_one(fed: &Federation) -> Result<String, Error> {
    println!(
        "\n== act one: theft attempt — stolen user key AND the real PIN, non-allowlisted \
         destination =="
    );
    let refusals = theft_to_unknown_address_is_refused(fed, &fed.vault_utxo)?;
    let detail = format!("{refusals}/{NODE_COUNT} nodes refused with DEST_NOT_ALLOWED");
    println!("  ACT ONE OK — {detail}");
    Ok(detail)
}

/// Act two — the attacker's ALLOWLISTED spend, caught mid-Hold and clawed back.
///
/// Everything the attacker sends is *valid*: a stolen user key, the real PIN, a
/// destination the hot allowlist derives, a fee under the cap, an amount under the
/// Hot budget. Every policy check passes and the federation ACCEPTS — as a PENDING
/// candidate. What stands between the attacker and the money is the Hold, and the
/// Hold exists so that a spend the user never authorized is still on this side of
/// the chain when the user notices it.
///
/// The user's answer is an escape-class sweep of the attacked coin: every
/// destination output pays the escape descriptor, which the nodes derive from the
/// OUTPUTS (never from a coordinator label) and fire IMMEDIATELY under either pin.
/// It spends the very coin the attacker's pending spend is waiting on, so once it
/// confirms that spend can never complete — the claw-back.
///
/// **Normal pin, deliberately.** DESIGN.md calls this an *instant* escape sweep,
/// and instant is exactly what distinguishes this path from the duress one: a
/// duress carrier's sweep fires at `T`, after the hostage window, and takes the
/// federation into Lockdown for the node's lifetime. Here the user is not coerced —
/// they are looking at a pending spend they did not author and want the coins out
/// now — so they send the escape-class spend under the ordinary pin and it fires at
/// ingress. The duress side of the same escape machinery is what `attack all`
/// exercises (`hold-expiry-race`, `arm-split-closed`, `duress-resubmission`).
fn theft_refused_act_two(fed: &Federation) -> Result<String, Error> {
    println!("\n== act two: the attacker's ALLOWLISTED spend, caught mid-Hold and clawed back ==");

    // What the hot wallet legitimately holds before the attacker touches anything —
    // the curtain-up control's payment. The claim below is that the attacker's spend
    // adds nothing to it, so the baseline has to be measured rather than assumed
    // zero.
    let hot_before = fed.unspent_paying(&fed.hot_spk)?;

    // The residual reserve. An escape-class spend completes immediately, so the node
    // requires its mandatory escape to be a DISTINCT, disjoint residual candidate for
    // the T-time sweep — which needs a vault coin the sweep itself does not spend.
    let residual_coin = fed.fund(RESIDUAL_FUND)?;
    println!(
        "  funded a {} residual reserve at {} (an escape-class spend fires at once, so its \
         mandatory escape must be a distinct disjoint residual)",
        residual_coin.txout.value, residual_coin.outpoint
    );

    // The attacker's spend: allowlisted destination, real user signature, real PIN,
    // under the Hot budget. Nothing about it is refusable.
    let attacked = fed.vault_utxo.clone();
    let change = attacked
        .txout
        .value
        .checked_sub(HOT_SPEND)
        .and_then(|rest| rest.checked_sub(FEE))
        .ok_or("the vault coin cannot cover the attacker's allowlisted spend")?;
    let theft = build_spend(
        &attacked,
        &fed.witness_script,
        &[
            (fed.hot_spk.clone(), HOT_SPEND),
            (fed.vault_spk.clone(), change),
        ],
    )?;
    // Its mandatory escape sweeps the WHOLE vault — both coins — which is what an
    // escape is for. It is registered and never fires here: nothing arms it.
    let theft_escape_value = attacked
        .txout
        .value
        .checked_add(residual_coin.txout.value)
        .and_then(|total| total.checked_sub(FEE))
        .ok_or("the vault balance cannot cover the attacker's mandatory escape")?;
    let theft_escape = build_spend_n(
        &[attacked.clone(), residual_coin.clone()],
        &fed.witness_script,
        &[(fed.escape_spk.clone(), theft_escape_value)],
    )?;
    let theft_request = fed.request(&theft, &theft_escape, NORMAL_PIN)?;
    let theft_txid = Psbt::from_str(&theft_request.psbt)?
        .unsigned_tx
        .compute_txid()
        .to_string();

    // The fire time comes from the NODES, not from the coordinator's clock after the
    // relay loop: `Accepted` reports it as `first_seen + remaining_secs`, fixed at
    // first acceptance. Take the EARLIEST — that is the first instant any partial
    // could be released, so it is what the claw-back has to beat.
    let mut fires_at = u64::MAX;
    let mut pending_id = None;
    for (node, response) in fed.nodes.iter().zip(fed.relay_all_fresh(&theft_request)?) {
        let accepted = match response {
            SignResponse::Accepted(accepted) => accepted,
            other => {
                return Err(format!(
                    "node {} did not accept the attacker's ALLOWLISTED spend ({}); act two needs \
                     it accepted-and-pending, because the Hold is what it demonstrates",
                    node.number(),
                    summarize(&other)
                )
                .into())
            }
        };
        if accepted.remaining_secs == 0 {
            return Err(format!(
                "node {} fired the attacker's spend at ingress (remaining_secs 0) instead of \
                 taking the {}s Hold; there would be no pending window to catch it in",
                node.number(),
                fed.params.hold_secs
            )
            .into());
        }
        println!(
            "  node {} @127.0.0.1:{} → ACCEPTED {} (PENDING, fires in {}s)",
            node.number(),
            node.port,
            &accepted.commitment_id[..16],
            accepted.remaining_secs,
        );
        fires_at = fires_at.min(accepted.first_seen.saturating_add(accepted.remaining_secs));
        pending_id = Some(accepted.commitment_id);
    }
    // `fires_at` is only a fire time if at least one node reported one; without that
    // it is still `u64::MAX` and every "before it could fire" claim below would be
    // vacuously true.
    let pending_id = pending_id.ok_or("no node acknowledged the attacker's spend")?;
    // The user SEES this pending spend because the modeled attacker (stolen user key + PIN,
    // but NOT the coordinator auth key) must relay through the user's OWN coordinator, which
    // surfaces the acknowledgements. A strictly stronger attacker who also stole the
    // coordinator auth key could feed a node directly and arm the federation via request
    // propagation, and no surface the user watches today would show it (GET /events carries
    // only on-chain watchtower alerts; there is no pending-candidate query). The Hold window
    // and the clawback below are demonstrated GENUINELY either way; only this "user notices"
    // step rests on the relay path. A node-side pending projection is future work (Fable review).
    println!(
        "  the coordinator now shows a PENDING spend the user never authorized: {} paying {} to \
         the hot wallet ({theft_txid})",
        &pending_id[..16],
        HOT_SPEND,
    );
    println!(
        "  (the user sees it because this attacker relays through the user's own coordinator; a \
         coordinator-auth-key thief would need a node-side pending projection — future work)"
    );

    // The claw-back, inside the Hold.
    let swept = attacked
        .txout
        .value
        .checked_sub(FEE)
        .ok_or("the attacked coin cannot cover the escape sweep")?;
    let residual_swept = residual_coin
        .txout
        .value
        .checked_sub(FEE)
        .ok_or("the residual reserve cannot cover its own escape")?;
    let sweep = build_spend(
        &attacked,
        &fed.witness_script,
        &[(fed.escape_spk.clone(), swept)],
    )?;
    let residual = build_spend(
        &residual_coin,
        &fed.witness_script,
        &[(fed.escape_spk.clone(), residual_swept)],
    )?;
    let sweep_request = fed.request(&sweep, &residual, NORMAL_PIN)?;
    let sweep_txid = Psbt::from_str(&sweep_request.psbt)?
        .unsigned_tx
        .compute_txid()
        .to_string();
    println!("  the user answers inside the Hold with an escape-class sweep of the attacked coin");
    for (node, response) in fed.nodes.iter().zip(fed.relay_all_fresh(&sweep_request)?) {
        let accepted = match response {
            SignResponse::Accepted(accepted) => accepted,
            other => {
                return Err(format!(
                    "node {} did not accept the user's escape sweep: {}",
                    node.number(),
                    summarize(&other)
                )
                .into())
            }
        };
        if accepted.remaining_secs != 0 {
            return Err(format!(
                "node {} deferred the escape sweep by {}s; an escape-class spend must fire NOW \
                 under either pin, which is what makes the claw-back instant",
                node.number(),
                accepted.remaining_secs
            )
            .into());
        }
        println!(
            "  node {} @127.0.0.1:{} → ACCEPTED {} (escape-class: remaining_secs 0, fires NOW)",
            node.number(),
            node.port,
            &accepted.commitment_id[..16],
        );
    }

    // The nodes combine and broadcast it; the coordinator only watches.
    fed.wait_for_mempool(&sweep_txid)?;
    let swept_at = unix_now()?;
    let lead = fires_at.saturating_sub(swept_at);
    if lead == 0 {
        return Err(format!(
            "the escape sweep did not reach the mempool until the attacker's spend was already \
             due to fire (at {fires_at}, observed at {swept_at}); this run measured nothing about \
             a MID-HOLD claw-back"
        )
        .into());
    }
    fed.mine(1)?;
    let raw = fed
        .bitcoind
        .call("getrawtransaction", json!([sweep_txid, true]))?;
    let confirmations = raw["confirmations"].as_i64().unwrap_or(0);
    if confirmations < 1 {
        return Err(format!("the escape sweep {sweep_txid} did not confirm").into());
    }
    println!(
        "  a NODE broadcast the escape sweep {sweep_txid} and it confirmed — {lead}s before the \
         attacker's spend could fire"
    );

    // The attacker's spend is now unspendable: its input belongs to the escape. Wait
    // out its whole Hold AND the combine window that follows before reading its
    // absence as evidence — the nodes' fire loop is still live until then, and a
    // spend that was going to be released has been by that deadline.
    let deadline = fires_at
        .saturating_add(fed.params.combine_slack_secs)
        .saturating_add(FIRE_OBSERVATION_MARGIN_SECS);
    println!(
        "  waiting out the attacker's Hold + combine window ({}s) before calling its spend absent",
        deadline.saturating_sub(unix_now()?)
    );
    fed.wait_past(deadline)?;
    // Mine, so anything the federation did broadcast is on-chain rather than resting
    // in a mempool the UTXO scan below cannot see.
    fed.mine(1)?;
    if fed.in_mempool_or_chain(&theft_txid)? {
        return Err(format!(
            "the attacker's spend {theft_txid} reached the mempool or a block after all"
        )
        .into());
    }

    let escaped = fed.unspent_paying(&fed.escape_spk)?;
    let hot_after = fed.unspent_paying(&fed.hot_spk)?;
    let to_attacker = fed.unspent_paying(&fed.attacker_spk)?;
    if hot_after != hot_before || to_attacker != Amount::ZERO {
        return Err(format!(
            "the theft was not clawed back: the hot wallet went from {hot_before} to {hot_after} \
             and {to_attacker} reached the attacker's own address"
        )
        .into());
    }
    if escaped != swept {
        return Err(format!(
            "the escape wallet holds {escaped}, not the {swept} the sweep of the attacked coin \
             should have delivered"
        )
        .into());
    }

    let detail = format!(
        "{escaped} in the escape wallet, not a satoshi past the {hot_before} the user authorized; \
         clawed back with {lead}s of Hold left"
    );
    println!("  ACT TWO OK — {detail}; the attacker's spend {theft_txid} never reached the mempool or a block");
    Ok(detail)
}
