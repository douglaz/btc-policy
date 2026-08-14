//! `btc-vault attack` — the adversarial regtest harness for the duress mechanism
//! (ADR-0012 / ADR-0014). The empirical counterpart to V0-4b-core's unit tests:
//! the wrench-attack answer, run live against a real `n = 2t−1` federation.
//!
//! # What this asserts, and what it deliberately does not
//!
//! The duress safety property is **not** "`t` nodes armed". With `n = 2t−1` and up
//! to `t−1` compromised, a holder set of size `t` contains only `≥ 1` honest
//! member, so a receipt count can never prove `t` honest nodes froze — a receipt
//! proves relay, not freeze. The confirmation count is a timing/liveness mechanism
//! deciding *when* the freeze and sweep commit (ADR-0012, "CORRECTION
//! (2026-07-20)").
//!
//! What actually makes a coerced spend un-completable is the **signer/partial
//! coupling plus the release-gate**:
//!
//! 1. **Coupling.** A node emits a partial for a candidate only after
//!    independently receiving and processing that candidate's own user-authorized
//!    carrier — no peer message is ever a signing oracle. Every gate that blocks
//!    arming blocks signing too, and both sit before `add_node_signatures`.
//! 2. **Release-gate.** No candidate's partial leaves the node before that
//!    candidate's authorized fire event, and arming atomically and monotonically
//!    suppresses every existing and future hot-partial release, under the same
//!    store lock that would release it.
//! 3. **Result.** No honest node ever releases a coerced partial, so only the
//!    `≤ t−1` compromised nodes hold one — never a signing quorum. The sweep may
//!    still fail (funds sit frozen → recovery); that is denial, never theft.
//!
//! So every scenario here asserts on **partials the adversary actually holds**,
//! never on how many nodes armed. The harness plays the attacker: it holds `t−1`
//! node identities as real listeners ([`crate::adversary`]), and the number of
//! honest partials that arrive there IS the releasable-partial count. Zero is the
//! property.
//!
//! # The one residual, and its bound
//!
//! The coupling does not close a hot spend submitted EARLIER with the *normal*
//! pin, legitimately pending in its Hold, when a later duress signal is censored
//! from a sub-quorum. That is the accepted "hot wallet is the risk budget"
//! residual, and [`censorship_residual_bounded`] demonstrates it is capped by the
//! V0-11 Hot budget (ADR-0014) — refused pre-signing, per-tx and per-window, with
//! unexposed reservations returned. Each honest ledger admits at most one `V`;
//! across the full `c = t−1` compromise tolerance ADR-0014's routing factor is
//! `tV`, never the vault.

use std::cell::RefCell;
use std::fmt::Write as _;
use std::panic::{catch_unwind, UnwindSafe};
use std::process::{Child, Command, ExitCode, Stdio};
use std::str::FromStr;
use std::time::{Duration, Instant};

use bitcoin::consensus::encode::deserialize_hex;
use bitcoin::hashes::Hash;
use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1::{All, Message, Secp256k1};
use bitcoin::sighash::SighashCache;
use bitcoin::{Amount, EcdsaSighashType, Network, Psbt, PublicKey, ScriptBuf, Transaction};
use miniscript::psbt::PsbtExt;
use miniscript::Descriptor;
use serde_json::{json, Value};
use vault_proto::{
    push_var, tagged_hash, RefreshRequest, RefusalCode, SignRequest, SignResponse, TaggedRequest,
};

use crate::adversary::{CompromisedNode, PartialSeen, USER_SIG_HASH_TAG};
use crate::bitcoind::Bitcoind;
use crate::fed::{
    build_spend, build_spend_n, commitment_expiry, encode_request, free_ports, locate_btc_vault,
    locate_vault_node, p2wpkh_spk, sign_all_inputs, summarize, unix_now, utxo_paying, wallet_id,
    Actor, CeremonyParams, Coordinator, Manifest, NodeDevice, NodeParams, NodeProcess, NodeSpawn,
    TempDir, Utxo, Wallet,
};
use crate::http::Error;

// ---------------------------------------------------------------------------
// Federation shape and policy numbers

/// `t` — the signing threshold. The federation is `n = 2t−1`, the shape ADR-0013
/// §1 requires in channel mode: it leaves no unfrozen signing quorum outside an
/// armed set while still tolerating every `t−1` minority that withholds.
const T: usize = 3;
const N: usize = 2 * T - 1;
/// `c` — compromised nodes the harness controls. The full soft-vault tolerance.
const C: usize = T - 1;
const NORMAL_PIN: &str = "246802";
const DURESS_PIN: &str = "135791";
const WRONG_PIN: &str = "999999";

const POLICY_VERSION: u32 = 1;
const MAX_DERIVATION_INDEX: u32 = 100;
const MAX_COMMITMENT_AGE_SECS: u64 = 3_600;
const COMMITMENT_TTL_SECS: u64 = 1_800;
const FUND: Amount = Amount::from_sat(1_000_000_000);
const FEE: Amount = Amount::from_sat(10_000);
/// A fee that clears the highest relay floor any scenario raises on bitcoind
/// (`-minrelaytxfee=0.001`, 100 sat/vB) — ~420 sat/vB over a single-input hot-spend
/// body. Every transaction whose ABSENCE from the chain is the evidence for a
/// no-theft claim has to pay it in an arm that raises the floor, or Core's own
/// refusal, not the mechanism, is what kept it off the chain.
const RELAY_CLEARING_FEE: Amount = Amount::from_sat(100_000);
/// The fee a refresh pays. A refresh is a pin-less, instant self-spend, so it has
/// neither the Hold nor the PIN that ADR-0006 relies on for its burn defense and
/// carries its OWN tight feerate cap instead (ADR-0012). `FEE` is a hot-class fee
/// and sits above that cap for a small self-spend, which would refuse every
/// refresh here for a reason unrelated to what these scenarios test.
const REFRESH_FEE: Amount = Amount::from_sat(2_000);
const HOT_INDEX: u32 = 5;

/// How long a scenario waits for something that SHOULD happen (a broadcast, a
/// lockdown). Generous relative to the node's 1 Hz drivers.
const EXPECT_TIMEOUT: Duration = Duration::from_secs(45);
/// How long a scenario waits while confirming something should NOT happen. Shorter
/// — a negative is proven by the positive control alongside it, not by waiting
/// forever.
const SETTLE: Duration = Duration::from_secs(8);
/// Margin after a hot candidate's nominal Hold + combine window. Carrier fan-out
/// is asynchronous, so one node's `first_seen` is only a lower bound for the rest.
const FIRE_OBSERVATION_MARGIN_SECS: u64 = 15;
/// Slack on top of that window for `escape_class_sequences`'s no-op control, which
/// must read a full release window past the normal pin's hypothetical fire time and
/// still be strictly before the duress `T`. It is the only margin the control has,
/// so a run that loses it reports an inconclusive window rather than a verdict.
const NO_OP_CONTROL_GUARD_SECS: u64 = 5;
/// An absence barrier requires every accepted wiretap connection to have completed,
/// and then requires the whole listener set to stay idle briefly. The stability
/// interval closes the accept-loop/handler hand-off race without adding meaningful
/// time to the already window-bounded assertions.
const WIRETAP_QUIET: Duration = Duration::from_millis(100);
const WIRETAP_DRAIN_TIMEOUT: Duration = Duration::from_secs(12);

/// Harness-only, per-node coordinator-expiry acceptance windows. These values are
/// deliberately NOT manifest inputs in production: the admission-bound scenario
/// uses disjoint windows to make a hostile coordinator route one distinct spend to
/// each honest ledger while every other honest node refuses before signing.
const ROUTE_HORIZON_BASE_SECS: u64 = 30;
const ROUTE_HORIZON_STRIDE_SECS: u64 = 30;
const ROUTE_WINDOW_WIDTH_SECS: u64 = 15;

fn route_horizon(node_id: u16) -> u64 {
    ROUTE_HORIZON_BASE_SECS
        .saturating_add(u64::from(node_id).saturating_mul(ROUTE_HORIZON_STRIDE_SECS))
}

// ---------------------------------------------------------------------------
// Scorecard

pub(crate) const SCENARIO_NAMES: &[&str] = &[
    "arm-split-closed",
    "censorship-residual-bounded",
    "selective-delivery",
    "two-spend-probe",
    "toxic-parent",
    "in-flight-refresh",
    "escape-class-sequences",
    "hold-expiry-race",
    "lockout-then-duress",
    "duress-resubmission",
    "reboot-death",
    "fire-time-failure",
    "reorg-watchtower-cursor",
    "reorg-duress-lockdown",
    "reorg-escape-resettles",
    "recovery",
];

struct Card {
    rows: Vec<Row>,
}

struct Row {
    name: &'static str,
    outcome: Result<String, String>,
    elapsed: Duration,
}

impl Card {
    fn new() -> Card {
        Card { rows: Vec::new() }
    }

    fn run(
        &mut self,
        name: &'static str,
        body: impl FnOnce() -> Result<String, Error> + UnwindSafe,
    ) {
        println!("\n=== {name} ===");
        let start = Instant::now();
        let outcome = match catch_unwind(body) {
            Ok(Ok(detail)) => {
                println!("  PASS  {detail}");
                Ok(detail)
            }
            Ok(Err(e)) => {
                println!("  FAIL  {e}");
                Err(e.to_string())
            }
            Err(payload) => {
                let detail = payload
                    .downcast_ref::<&str>()
                    .map(|message| (*message).to_string())
                    .or_else(|| payload.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "non-string panic payload".to_string());
                let detail = format!("scenario panicked: {detail}");
                println!("  FAIL  {detail}");
                Err(detail)
            }
        };
        self.rows.push(Row {
            name,
            outcome,
            elapsed: start.elapsed(),
        });
    }

    fn report(&self, requested_full_run: bool) -> ExitCode {
        let passed = self.rows.iter().filter(|r| r.outcome.is_ok()).count();
        let complete_scorecard = self.rows.len() == SCENARIO_NAMES.len()
            && SCENARIO_NAMES
                .iter()
                .all(|name| self.rows.iter().filter(|row| row.name == *name).count() == 1);
        println!("\n──────────────────────────────────────────────────────────────");
        // "up to": most scenarios take the full `c = t−1` tolerance, but the
        // above-threshold reboot-death run deliberately takes only ONE identity so
        // that `n − 1 = t + 1` honest daemons remain and a single kill still leaves
        // exactly `t` armed.
        println!(" ADVERSARIAL HARNESS SCORECARD   ({T}-of-{N} federation, up to {C} compromised)");
        println!("──────────────────────────────────────────────────────────────");
        for row in &self.rows {
            let (mark, detail) = match &row.outcome {
                Ok(detail) => ("PASS", detail.as_str()),
                Err(detail) => ("FAIL", detail.as_str()),
            };
            println!(
                " {mark}  {:<30} {:>5}s  {detail}",
                row.name,
                row.elapsed.as_secs()
            );
        }
        println!("──────────────────────────────────────────────────────────────");
        println!(" {passed}/{} scenarios held", self.rows.len());
        if self.rows.is_empty() {
            eprintln!("\nADVERSARIAL HARNESS FAILED — no scenario executed");
            ExitCode::FAILURE
        } else if requested_full_run && !complete_scorecard {
            eprintln!(
                "\nADVERSARIAL HARNESS FAILED — full-run dispatch executed {} of {} named scenarios",
                self.rows.len(),
                SCENARIO_NAMES.len()
            );
            ExitCode::FAILURE
        } else if passed == self.rows.len() {
            if complete_scorecard {
                println!(
                    "\nNo theft path, safety track held (freeze + unconditional lockdown at T), \
                     censorship residual bounded to the Hot budget. SILENCE: this harness gates \
                     the wire — response bodies, body sizes, /events — and NOT end-to-end \
                     timing, whose wall-clock skew it now reports as ADVISORY only. Pin-uniform \
                     ingress is gated by vault-node's deterministic ingress-work assertions \
                     (`channel::duress::normal_and_duress_ingress_op_sequences_*`) under \
                     `cargo test`, which this command does NOT run. A green scorecard here is \
                     not by itself evidence that silence holds."
                );
            } else {
                println!(
                    "\nSelected scenario held; the guarantees demonstrated are reported in its \
                     scorecard row."
                );
            }
            ExitCode::SUCCESS
        } else {
            eprintln!("\nADVERSARIAL HARNESS FAILED — a duress safety assertion did not hold");
            ExitCode::FAILURE
        }
    }
}

pub fn run(only: Option<&str>) -> ExitCode {
    if let Some(name) = only {
        if !SCENARIO_NAMES.contains(&name) {
            eprintln!(
                "unknown scenario {name:?}; known: {}",
                SCENARIO_NAMES.join(", ")
            );
            return ExitCode::from(2);
        }
    }
    let mut card = Card::new();
    let selected = |name: &str| only.is_none() || only == Some(name);

    if selected("arm-split-closed") {
        card.run("arm-split-closed", arm_split_closed);
    }
    if selected("censorship-residual-bounded") {
        card.run("censorship-residual-bounded", censorship_residual_bounded);
    }
    if selected("selective-delivery") {
        card.run("selective-delivery", selective_delivery);
    }
    if selected("two-spend-probe") {
        card.run("two-spend-probe", two_spend_probe);
    }
    if selected("toxic-parent") {
        card.run("toxic-parent", toxic_parent);
    }
    if selected("in-flight-refresh") {
        card.run("in-flight-refresh", in_flight_refresh);
    }
    if selected("escape-class-sequences") {
        card.run("escape-class-sequences", escape_class_sequences);
    }
    if selected("hold-expiry-race") {
        card.run("hold-expiry-race", hold_expiry_race);
    }
    if selected("lockout-then-duress") {
        card.run("lockout-then-duress", lockout_then_duress);
    }
    if selected("duress-resubmission") {
        card.run("duress-resubmission", duress_resubmission);
    }
    if selected("reboot-death") {
        card.run("reboot-death", reboot_death);
    }
    if selected("fire-time-failure") {
        card.run("fire-time-failure", fire_time_failure);
    }
    if selected("reorg-watchtower-cursor") {
        card.run("reorg-watchtower-cursor", reorg_watchtower_cursor);
    }
    if selected("reorg-duress-lockdown") {
        card.run("reorg-duress-lockdown", reorg_duress_lockdown);
    }
    if selected("reorg-escape-resettles") {
        card.run("reorg-escape-resettles", reorg_escape_resettles);
    }
    if selected("recovery") {
        card.run("recovery", recovery_exit);
    }
    card.report(only.is_none())
}

// ---------------------------------------------------------------------------
// The vault under attack

/// Per-scenario knobs. Everything else is fixed so scenarios stay comparable.
struct Setup {
    /// The Hold. Zero makes a hot spend fire at ingress; non-zero gives a real
    /// pending window to attack. Every scenario currently sets its own, so the
    /// default below is only the struct-update-syntax base.
    hold_secs: u64,
    /// The hostage-safety window. `T = min(first_seen + this, earliest live-hot
    /// fire − ε).max(now)`.
    duress_delay_secs: u64,
    epsilon_secs: u64,
    /// Inclusive combine/re-broadcast window after a candidate's fire time.
    combine_slack_secs: u64,
    hot_max_per_tx: Amount,
    hot_max_per_window: Amount,
    /// Minimum authenticated lifetime a carrier must retain for peer fan-out.
    delivery_horizon_secs: u64,
    /// How many identities the adversary runs as listeners. Nearly every scenario
    /// takes the full `C` tolerance: the wiretap is the harness's only instrument
    /// for "which partials became releasable", so even scenarios that do not attack
    /// through the compromised nodes need it present — `fire_time_failure` asserts
    /// on exact escape-candidate partials, which would read 0 vacuously without it. The
    /// exception is `reboot_death_still_sweeps_above_threshold`, which takes only
    /// `1` so that `n − 1 = t + 1` honest daemons remain and one death still leaves
    /// exactly `t` armed — the boundary at which combining is still possible.
    compromised: usize,
    /// Give each honest daemon a disjoint coordinator-expiry acceptance window so
    /// the Hot-budget scenario can exercise ADR-0014's adversarial routing factor.
    disjoint_admission_windows: bool,
    /// Argon2id enrolment memory cost (KiB) for both pin slots. The fixture minimum
    /// everywhere except the timing probes, which need one evaluation to dominate
    /// measurement noise before a latency comparison can mean anything.
    pin_m_cost_kib: u32,
    /// The fire-time panic feerate floor (sats/vB), raised only by the scenario
    /// that demonstrates a feerate-driven fire-time refusal.
    escape_feerate_floor: u64,
    /// Scenario-specific bitcoind policy. The package-admission run raises Core's
    /// relay floor so an otherwise admissible, fully signed escape is rejected by
    /// `testmempoolaccept` after its shares are released.
    bitcoind_args: &'static [&'static str],
}

impl Default for Setup {
    fn default() -> Setup {
        Setup {
            hold_secs: 0,
            duress_delay_secs: 0,
            epsilon_secs: 1,
            // At least 2x the vault-cache refresh interval (SCAN_INTERVAL = 10s), the
            // config floor: a shorter combine window can go cache-stale for its whole
            // duration and silently reduce duress to recovery (9y5.3 review).
            combine_slack_secs: 20,
            hot_max_per_tx: Amount::from_sat(600_000_000),
            hot_max_per_window: Amount::from_sat(900_000_000),
            delivery_horizon_secs: 30,
            compromised: C,
            disjoint_admission_windows: false,
            pin_m_cost_kib: FIXTURE_PIN_M_COST_KIB,
            escape_feerate_floor: DEFAULT_ESCAPE_FEERATE_FLOOR,
            bitcoind_args: &[],
        }
    }
}

/// Argon2's own minimum, matching `vault_node`'s fixture enrolment: pin evaluation
/// stays off the critical path for every scenario that is not measuring it.
const FIXTURE_PIN_M_COST_KIB: u32 = 8;
/// `vault_node`'s own `default_escape_feerate_floor` (sats/vB), restated so the
/// harness's baseline federation matches a node that omits the field.
const DEFAULT_ESCAPE_FEERATE_FLOOR: u64 = 1;

/// A live regtest vault plus the adversary's foothold in it.
struct Vault {
    secp: Secp256k1<All>,
    user: Actor,
    coordinator: Coordinator,
    recovery_keys: Vec<Actor>,
    /// The honest federation members, as real daemon processes.
    honest: Vec<NodeProcess>,
    /// The adversary's node identities.
    compromised: Vec<CompromisedNode>,
    /// Declared AFTER `honest`: struct fields drop in declaration order, and the
    /// daemons poll this backend once per second. Dropping the chain out from under
    /// a live daemon produces a burst of RPC errors in its log for no reason, which
    /// is noise in exactly the logs `log_contains` attributes refusals from.
    bitcoind: Bitcoind,
    mining_address: String,
    /// Federation signing keys in canonical `node_id` order. The adversary's
    /// wiretap uses these to prove a payload it observed is a usable share for the
    /// exact candidate, rather than merely JSON with `msg_type = partial`.
    node_pubkeys: Vec<PublicKey>,
    descriptor: Descriptor<PublicKey>,
    vault_spk: ScriptBuf,
    witness_script: ScriptBuf,
    hot_spk: ScriptBuf,
    escape_spk: ScriptBuf,
    attacker_spk: ScriptBuf,
    attacker_probe_txid: String,
    vault_utxo: Utxo,
    params: NodeParams,
    /// One pin-independent, pre-signing refusal reused by `wait_for_lockdown`.
    /// Reusing its nonce avoids registering a live candidate or consuming Hot
    /// velocity budget on every poll.
    lockdown_probe: RefCell<Option<SignRequest>>,
    disjoint_admission_windows: bool,
    /// Keep the directory LAST so node daemons and bitcoind are gone before
    /// recursive cleanup runs.
    #[allow(dead_code)]
    temp: TempDir,
}

impl Vault {
    fn build(setup: &Setup) -> Result<Vault, Error> {
        let secp = Secp256k1::new();
        // Local declaration order protects the build error path. `Vault` separately
        // declares `temp` last because struct fields drop in declaration order.
        let temp = TempDir::new("attack")?;
        let mut urandom = std::fs::File::open("/dev/urandom")?;

        let user = Actor::random(&secp, &mut urandom)?;
        let coordinator = Coordinator::random(&secp, &mut urandom)?;
        let hot_wallet = Wallet::random(&secp, &mut urandom)?;
        // Escape-key independence is a HARD assumption (ADR-0012 threat model): a
        // shared-seed escape turns duress into theft outright. This wallet is born
        // from its own seed, so the harness attacks the mechanism rather than a
        // deployment that already lost — and the ceremony below refuses to seal the
        // vault at all if it can detect an overlap.
        let escape_wallet = Wallet::random(&secp, &mut urandom)?;
        let hot_spk = hot_wallet.address_spk(&secp, HOT_INDEX)?;
        let escape_spk = escape_wallet.address_spk(&secp, 0)?;
        let attacker_spk = p2wpkh_spk(&Actor::random(&secp, &mut urandom)?);

        let recovery_keys: Vec<Actor> = (0..policy_core::RECOVERY_KEYS)
            .map(|_| Actor::random(&secp, &mut urandom))
            .collect::<Result<_, _>>()?;
        let recovery_pubkeys: Vec<PublicKey> = recovery_keys.iter().map(|a| a.pubkey).collect();

        let params = NodeParams {
            hold_secs: setup.hold_secs,
            duress_delay_secs: setup.duress_delay_secs,
            epsilon_secs: setup.epsilon_secs,
            combine_slack_secs: setup.combine_slack_secs,
            max_commitment_age_secs: MAX_COMMITMENT_AGE_SECS,
            delivery_horizon_secs: setup.delivery_horizon_secs,
            max_derivation_index: MAX_DERIVATION_INDEX,
            policy_version: POLICY_VERSION,
            max_msg_bytes: vault_node::channel::DEFAULT_MAX_MSG_BYTES,
            hot_budget: vault_node::HotBudget {
                max_per_tx_sat: setup.hot_max_per_tx.to_sat(),
                max_per_window_sat: setup.hot_max_per_window.to_sat(),
                window_secs: MAX_COMMITMENT_AGE_SECS,
            },
            normal_pin: NORMAL_PIN.to_string(),
            duress_pin: DURESS_PIN.to_string(),
            pin_m_cost_kib: setup.pin_m_cost_kib,
            escape_feerate_floor: setup.escape_feerate_floor,
        };

        // Round one of the REAL ceremony: every node births its own key in its own
        // `btc-vault setup node-keygen` process, in its own directory. This process
        // sees only the public bundles — including for the identities the adversary
        // will take over, which it takes by COMPROMISING those hosts below rather
        // than by having been handed their keys at setup.
        let ports = free_ports(1 + N)?;
        let node_ports: Vec<u16> = ports[1..=N].to_vec();
        let btc_vault = locate_btc_vault()?;
        let devices_dir = temp.path.join("devices");
        let devices: Vec<NodeDevice> = node_ports
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
            .filter(|d| **d != escape_wallet.descriptor)
            .cloned()
            .collect();
        let manifest = Manifest::assemble(
            &btc_vault,
            &coordinator.pubkey,
            &devices,
            &CeremonyParams {
                hot_allowlist: &ceremony_hot_allowlist,
                escape_descriptor: &escape_wallet.descriptor,
                threshold: T,
                user_key: user.pubkey,
                recovery_keys: &recovery_pubkeys,
            },
            &params,
        )?;
        let descriptor_str = manifest.descriptor().to_string();
        let descriptor = Descriptor::<PublicKey>::from_str(&descriptor_str)?;
        let vault_spk = descriptor.script_pubkey();
        let witness_script = descriptor.explicit_script()?;
        let vault_address = descriptor.address(Network::Regtest)?;
        let node_pubkeys = manifest.signing_pubkeys();
        let channel_pubkeys = manifest.channel_pubkeys();

        let mut bitcoind =
            Bitcoind::start_with_args(temp.path.join("bitcoind"), ports[0], setup.bitcoind_args)?;
        bitcoind.create_wallet("attack")?;
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

        // Which identities the adversary takes over is decided by `node_id`, not by
        // which device the harness happens to like: `node_id` is the canonical
        // (lexicographic) position in the frozen descriptor, so the adversary — like
        // any real attacker — gets whatever the ceremony assigned. It takes the
        // HIGHEST ids so honest node_ids stay 0..HONEST and the scenarios read
        // cleanly.
        let node_bin = locate_vault_node()?;
        let nodes_dir = temp.path.join("nodes");
        std::fs::create_dir_all(&nodes_dir)?;
        let compromised_ids: Vec<u16> = ((N - setup.compromised) as u16..N as u16).collect();

        let mut honest = Vec::new();
        let mut compromised = Vec::new();
        for (index, device) in devices.iter().enumerate() {
            let node_id = manifest.node_id_of(device);
            if compromised_ids.contains(&node_id) {
                // Taking a node means taking its HOST: the adversary reads that
                // device's own operator preimage and re-derives its key, which is
                // exactly what root on a node host yields. Nothing at setup handed
                // it over.
                let stolen = device.compromise(&secp)?;
                compromised.push(CompromisedNode::new(
                    &secp,
                    &stolen,
                    node_id,
                    device.port,
                    manifest.wallet_id(),
                    &manifest.manifest_hash,
                    &channel_pubkeys,
                )?);
            } else {
                let mut spawn_params = params.clone();
                if setup.disjoint_admission_windows {
                    let horizon = route_horizon(node_id);
                    spawn_params.delivery_horizon_secs = horizon;
                    spawn_params.max_commitment_age_secs =
                        horizon.saturating_add(ROUTE_WINDOW_WIDTH_SECS);
                }
                honest.push(NodeProcess::spawn(
                    &node_bin,
                    &nodes_dir,
                    NodeSpawn {
                        index,
                        device,
                        allowlist: &node_allowlist,
                        escape_descriptor: &escape_wallet.descriptor,
                        coord_auth_pubkey: &coordinator.pubkey.to_string(),
                        bitcoind_rpc_addr: bitcoind.rpc_addr(),
                        bitcoind_auth: bitcoind.auth(),
                        manifest: &manifest,
                        params: &spawn_params,
                    },
                )?);
            }
        }
        for node in &mut honest {
            node.wait_ready()?;
        }
        honest.sort_by_key(|n| n.node_id);
        println!(
            "      {}-of-{} vault funded with {FUND}; {} honest daemons, {} compromised identities \
             (node_ids {:?})",
            T,
            N,
            honest.len(),
            compromised.len(),
            compromised.iter().map(|c| c.node_id).collect::<Vec<_>>()
        );

        let mut vault = Vault {
            secp,
            user,
            coordinator,
            recovery_keys,
            honest,
            compromised,
            bitcoind,
            mining_address,
            node_pubkeys,
            descriptor,
            vault_spk,
            witness_script,
            hot_spk,
            escape_spk,
            attacker_spk,
            attacker_probe_txid: String::new(),
            vault_utxo,
            params,
            lockdown_probe: RefCell::new(None),
            disjoint_admission_windows: setup.disjoint_admission_windows,
            temp,
        };
        vault.prove_theft_detector_fires()?;
        vault.attacker_probe_txid = vault.prove_unauthorized_redirect_refused()?;
        Ok(vault)
    }

    /// Fund an ADDITIONAL vault UTXO and confirm it.
    ///
    /// Scenarios that need a second coin (a disjoint residual escape, a control
    /// spend that must not disturb the coin under attack) take one here rather than
    /// splitting the funded one, so the coin under attack keeps its exact value and
    /// the escape's coverage arithmetic stays simple.
    fn fund_extra(&self, amount: Amount) -> Result<Utxo, Error> {
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

    /// Wait until every honest node has had the opportunity to release a hot
    /// candidate, including its complete combine window. Lockdown does not stop the
    /// in-flight fire loop, so an absence read before this deadline is not evidence.
    fn wait_past_hot_release_window(&self, first_seen: u64) -> Result<(), Error> {
        let deadline = first_seen
            .saturating_add(self.params.hold_secs)
            .saturating_add(self.params.combine_slack_secs)
            .saturating_add(FIRE_OBSERVATION_MARGIN_SECS);
        self.wait_past(deadline)
    }

    /// The same, for the armed escape. Its fire window is `[T, T + combine_slack]`
    /// (`vault-node/src/channel.rs`, `ArmedStore::escape_window`), and a released
    /// partial is re-delivered until that deadline
    /// (`channel::retry_message_until`) — so a share that left at `T` can still
    /// arrive at the adversary's endpoint seconds later.
    ///
    /// Observing lockdown does NOT close this window: Lockdown lands at `T`, which
    /// is where the escape's window OPENS. An escape-partial absence read at
    /// lockdown-plus-a-settle is therefore taken while the release path is still
    /// live, and would report a share that simply had not arrived yet as a share
    /// that was never released.
    fn wait_past_escape_release_window(
        &self,
        first_seen: u64,
        confirmation_upper_bound: u64,
    ) -> Result<(), Error> {
        // `write_safety_overlay` uses `effective_t = max(first_seen + delay,
        // now_at_confirmation)`. The caller supplies a clock sample taken only after
        // positive evidence of the holder decision, making it an upper bound on that
        // second term. Using `first_seen + delay` alone can return before a late
        // confirmation's escape window has even opened.
        let latest_t = first_seen
            .saturating_add(self.params.duress_delay_secs)
            .max(confirmation_upper_bound);
        let deadline = latest_t
            .saturating_add(self.params.combine_slack_secs)
            .saturating_add(FIRE_OBSERVATION_MARGIN_SECS);
        self.wait_past(deadline)
    }

    fn wait_past(&self, deadline: u64) -> Result<(), Error> {
        while unix_now()? <= deadline {
            std::thread::sleep(Duration::from_millis(250));
        }
        Ok(())
    }

    /// Snapshot the coordinator-visible event surface on every honest daemon. Node 0
    /// receives the probe over `/sign`; its peers receive the propagated carrier over
    /// `/channel`, so silence evidence must cover both ingress roles.
    fn events_snapshot(&self) -> Result<Vec<(u16, Value)>, Error> {
        self.honest
            .iter()
            .map(|node| Ok((node.node_id, node.events(0)?)))
            .collect()
    }

    /// Positive control for the `/events` silence oracle. Spend a separate control
    /// coin through the recovery branch and require EVERY honest watchtower to
    /// publish the resulting alert before any pin-dependent interval is compared.
    ///
    /// **This permanently mutates the chain clock.** The recovery branch carries a
    /// ~180-day relative timelock, so maturing it means
    /// `advance_mtp_past_recovery_lock`, which pins bitcoind's clock with
    /// `setmocktime` and mines 13 blocks at the new time — and never resets it. Every
    /// later block in this federation therefore carries a timestamp ~180 days ahead
    /// of the wall clock the nodes schedule on. Call it IMMEDIATELY after `build()`,
    /// before any candidate exists, and never from a scenario whose assertions read
    /// block times or depend on further coins maturing.
    fn prove_events_endpoint_reports_alert(&self) -> Result<usize, Error> {
        const CONTROL: Amount = Amount::from_sat(20_000_000);
        let coin = self.fund_extra(CONTROL)?;
        let before = self.events_snapshot()?;
        let before_counts: Vec<(u16, usize)> = before
            .iter()
            .map(|(node_id, projection)| Ok((*node_id, events_alert_count(projection)?)))
            .collect::<Result<_, Error>>()?;
        let destination = self.bitcoind.call_str("getnewaddress", json!([]))?;
        let destination_spk = {
            let hex = self.bitcoind.call("getaddressinfo", json!([destination]))?["scriptPubKey"]
                .as_str()
                .ok_or("getaddressinfo has no scriptPubKey")?
                .to_string();
            ScriptBuf::from_hex(&hex)?
        };
        let value = coin
            .txout
            .value
            .checked_sub(FEE)
            .ok_or("the /events recovery control coin cannot cover its fee")?;
        crate::recovery::advance_mtp_past_recovery_lock(&self.bitcoind, &self.mining_address)?;
        let tx = crate::recovery::build_recovery_spend(
            &self.secp,
            coin.outpoint,
            &coin.txout,
            &self.witness_script,
            &destination_spk,
            value,
            &self.recovery_keys[..policy_core::RECOVERY_THRESHOLD],
        )?;
        let txid = self.bitcoind.call_str(
            "sendrawtransaction",
            json!([bitcoin::consensus::encode::serialize_hex(&tx)]),
        )?;
        self.mine(1)?;

        let deadline = Instant::now() + EXPECT_TIMEOUT;
        loop {
            let observed = self.events_snapshot()?;
            let observed_counts: Vec<(u16, usize)> = observed
                .iter()
                .map(|(node_id, projection)| Ok((*node_id, events_alert_count(projection)?)))
                .collect::<Result<_, Error>>()?;
            let missing: Vec<u16> = observed_counts
                .iter()
                .zip(&before_counts)
                .filter(|((node_id, count), (before_id, before_count))| {
                    node_id != before_id || count <= before_count
                })
                .map(|((node_id, _), _)| *node_id)
                .collect();
            if missing.is_empty() {
                return Ok(observed_counts.iter().map(|(_, count)| count).sum());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "/events never reported the recovery-path control spend {txid} on honest \
                     node_id(s) {missing:?}; an unchanged projection cannot prove duress silence \
                     on an ingress role whose endpoint has no positive control"
                )
                .into());
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }

    /// Fetch the transaction bitcoind actually accepted, rather than treating the
    /// locally constructed candidate as evidence of what reached regtest.
    fn raw_transaction(&self, txid: &str) -> Result<Transaction, Error> {
        let hex = self.bitcoind.call_str("getrawtransaction", json!([txid]))?;
        Ok(deserialize_hex(&hex)?)
    }

    /// Prove the wiretap can SEE a released partial, so a later zero is evidence
    /// rather than an artefact of a deaf listener.
    ///
    /// This is the control every "0 honest partials" claim rests on. It runs an
    /// ordinary NORMAL-pin hot spend on its own coin and requires that EVERY honest
    /// node push a partial for it to the adversary's endpoints — which they do,
    /// because combining is peer-to-peer and the adversary holds real federation
    /// identities. Without this, a broken listener would make every coupling
    /// assertion pass vacuously.
    ///
    /// Callers must run it while the federation is whole: it demands a share from
    /// each honest daemon, so a node already killed or partitioned makes it fail.
    fn wiretap_positive_control(&self, coin: &Utxo) -> Result<(String, usize), Error> {
        // Spend the control coin ENTIRELY to the hot wallet — no vault change — so
        // that once it confirms, the coin under attack is again the whole vault
        // balance and the escape's coverage threshold is unaffected.
        let control_value = coin.txout.value.checked_sub(FEE).ok_or_else(|| {
            format!(
                "wiretap control fee {FEE} exceeds the {} coin it spends",
                coin.txout.value
            )
        })?;
        let control = build_spend(
            coin,
            &self.witness_script,
            &[(self.hot_spk.clone(), control_value)],
        )?;
        let escape = self.escape_over(&[coin])?;
        let request = self.request(&control, &escape, NORMAL_PIN)?;
        // Fresh nonce per node, for the reason `relay_all_fresh` documents: under one
        // shared nonce the node that learns the carrier over the channel first
        // answers the coordinator's later POST with `NONCE_REPLAYED`, so what the
        // loop would measure is propagation order rather than each node's verdict.
        //
        // And keep the refusals. A control that quietly discarded them would swallow
        // a real diagnosis — a `HOT_VELOCITY_EXCEEDED` here (the Hot-budget scenario
        // sizes its control coins against exactly that ledger) means the control coin
        // is mis-sized, but the run would sail past it and die much later in
        // `wait_for_tx` with the cause attributed to something else entirely.
        let mut accepted = None;
        let mut refusals = Vec::new();
        for (index, response) in self.relay_all_fresh(&request)?.into_iter().enumerate() {
            match response {
                SignResponse::Accepted(a) => accepted = Some(a),
                SignResponse::Refusal(r) => refusals.push(format!(
                    "node {index}: {:?}/{}: {}",
                    r.code, r.check, r.detail
                )),
            }
        }
        let accepted = accepted.ok_or_else(|| {
            format!(
                "the wiretap control spend was refused by every node, so the control cannot run \
                 and no absence assertion downstream of it is trustworthy: {}",
                refusals.join("; ")
            )
        })?;
        // The live oracle for `expected_commitment_id`. Here — and only here — the
        // harness holds BOTH a node-issued commitment id and its own local
        // derivation for the same carrier, so this is where the mirror of
        // `vault_node`'s crate-private `commitment_of` can be checked at all.
        //
        // It matters because `arm_split_closed` keys an ABSENCE assertion off a
        // locally derived id (the dark carrier no node ever answered for). If the
        // derivation drifted, that lookup would return an empty partial set for a
        // commitment the nodes call something else, the SIGNING ORACLE check would
        // pass for an unrelated reason, and the same wrong id would then be
        // allowlisted out of the whole-run stray check.
        let signed_control = Psbt::from_str(&request.psbt)?;
        let derived = self.expected_commitment_id(&signed_control, request.expiry);
        if derived != accepted.commitment_id {
            return Err(format!(
                "the harness derives commitment_id {derived} for a carrier the node answered for \
                 as {}; `expected_commitment_id` has drifted from `vault_node`'s `commitment_of`, \
                 so every absence assertion keyed off a locally derived id is meaningless",
                accepted.commitment_id
            )
            .into());
        }
        let txid = control.unsigned_tx.compute_txid().to_string();
        self.wait_for_tx(
            &txid,
            EXPECT_TIMEOUT + Duration::from_secs(self.params.hold_secs),
        )?;
        self.mine(1)?;
        // POLL rather than read once. Fan-out to peers is detached and carries its
        // own retry, so a partial can legitimately land after the combining node has
        // already broadcast — and this control is read immediately after the
        // broadcast. Losing that race would abort the scenario with the actively
        // misleading claim that the wiretap is deaf.
        // EVERY honest node, not merely one. The absence claims this control licenses
        // are read per node — "node_id 3 released nothing" — while a single observed
        // partial only shows that SOME honest node's path to the adversary's endpoints
        // works. If one node's fan-out were silently broken, its permanent silence
        // would read as the freeze holding, and `assert_wiretap_decoded` cannot see it
        // (liveness and decode accounting are not per sender). Requiring all of them is
        // sound because release is a per-node gate: `release_partials` consults only
        // this node's own candidate record and is not suppressed by a peer having
        // already combined (`vault-node/src/channel.rs`).
        let seen = self
            .wait_for_honest_partials(
                &accepted.commitment_id,
                &signed_control,
                "spend",
                self.honest.len(),
                SETTLE,
            )
            .map_err(|e| {
                format!(
                    "the adversary did not observe an honest partial from every one of the {} \
                     honest nodes for a spend that completed ({txid}); the wiretap is deaf to at \
                     least one sender, so any later per-node zero-partial result would be \
                     meaningless ({e})",
                    self.honest.len()
                )
            })?;
        // Mining proves chain state, but each node's 1 Hz fire loop must also observe
        // the control as terminal before a later arm can use its pending-spend clock.
        //
        // Both markers carry the txid as well as the commitment id, exactly as the
        // node prints them. A bare `for candidate {id}` needle would also match
        // `fire: cannot check settlement for candidate {id}: …` and `broadcast
        // authorization closed for candidate {id} …` — both NON-terminal, and both
        // reachable from a transient backend error — so a node still holding the
        // control pending would read as settled and defeat this very guard.
        let settled = format!(
            "fire: candidate {} already settled on-chain ({txid})",
            accepted.commitment_id
        );
        let broadcast = format!(
            "fire: broadcast {txid} for candidate {}",
            accepted.commitment_id
        );
        let deadline = Instant::now() + SETTLE;
        loop {
            let pending: Vec<u16> = self
                .honest
                .iter()
                .filter(|node| !node.log_contains(&settled) && !node.log_contains(&broadcast))
                .map(|node| node.node_id)
                .collect();
            if pending.is_empty() {
                break;
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "control candidate {} remained locally pending at node_id(s) {pending:?} \
                     after it confirmed",
                    accepted.commitment_id
                )
                .into());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Ok((accepted.commitment_id, seen.len()))
    }

    /// The `commitment_id` a node MUST answer for `psbt` at `expiry`, derived here
    /// independently of the node.
    ///
    /// This mirrors `vault_node`'s `commitment_of`, which is crate-private — but the
    /// contract it delivers, `vault_proto::Commitment::commitment_id`, is public and
    /// is the thing actually hashed. Deriving it is what lets the silence probe
    /// CHECK the field before normalizing it away, rather than trusting that a value
    /// which legitimately differs per request cannot also differ per pin.
    fn expected_commitment_id(&self, psbt: &Psbt, expiry: u64) -> String {
        let inputs = psbt
            .unsigned_tx
            .input
            .iter()
            .map(|txin| vault_proto::CommitmentInput {
                txid: txin.previous_output.txid.to_byte_array(),
                vout: txin.previous_output.vout,
                sequence: txin.sequence.to_consensus_u32(),
            })
            .collect();
        let outputs = psbt
            .unsigned_tx
            .output
            .iter()
            .map(|txout| vault_proto::CommitmentOutput {
                script_pubkey: txout.script_pubkey.as_bytes().to_vec(),
                amount: txout.value.to_sat(),
            })
            .collect();
        let total_in = psbt
            .inputs
            .iter()
            .filter_map(|input| input.witness_utxo.as_ref())
            .fold(0u64, |acc, utxo| acc.saturating_add(utxo.value.to_sat()));
        let total_out = psbt
            .unsigned_tx
            .output
            .iter()
            .fold(0u64, |acc, txout| acc.saturating_add(txout.value.to_sat()));
        vault_proto::Commitment {
            wallet_id: wallet_id(&self.descriptor),
            version: psbt.unsigned_tx.version.0,
            lock_time: psbt.unsigned_tx.lock_time.to_consensus_u32(),
            inputs,
            outputs,
            fee: total_in.saturating_sub(total_out),
            expiry,
            policy_version: POLICY_VERSION,
        }
        .commitment_id()
    }

    /// Candidate commitments for which the adversary holds an honest partial outside
    /// `allowed`.
    ///
    /// The precise form of "nothing leaked", and the distinction matters twice
    /// over. A global "the adversary holds no partials at all" would be false the
    /// moment any legitimate candidate completes. Callers therefore allowlist exact
    /// commitment ids for their controls and intended sweeps. This intentionally does
    /// NOT classify by the channel's `spend_purpose` hint: the hint is non-authoritative,
    /// and a production role/classification bug must make the harness fail rather than
    /// filtering the leaked partial out of its own oracle.
    fn partial_commitments_outside(&self, allowed: &[&str]) -> Vec<String> {
        let mut stray = Vec::new();
        for node in &self.compromised {
            for id in node.wiretap().commitments_with_partials() {
                if allowed.contains(&id.as_str()) || stray.contains(&id) {
                    continue;
                }
                stray.push(id);
            }
        }
        stray
    }

    /// Fail if the adversary received any honest partial whose claimed commitment
    /// id is not explicitly allowed by this scenario.
    ///
    /// Exact-candidate lookups remain the binding check for the candidate under
    /// test. This global backstop catches a released partial filed under any other
    /// claimed id, which an absence lookup for only the expected id cannot see.
    fn assert_no_unexpected_partials(&self, context: &str, allowed: &[&str]) -> Result<(), Error> {
        self.assert_wiretap_decoded(context)?;
        let stray = self.partial_commitments_outside(allowed);
        if !stray.is_empty() {
            return Err(format!(
                "{context}: the adversary received honest partial(s) under unexpected claimed \
                 commitment id(s) {stray:?}"
            )
            .into());
        }
        Ok(())
    }

    /// The exact, user-signed escape candidate and commitment carried by `request`.
    fn signed_escape_candidate(&self, request: &SignRequest) -> Result<(String, Psbt), Error> {
        let candidate = Psbt::from_str(&request.escape_psbt)?;
        let commitment_id = self.expected_commitment_id(&candidate, request.expiry);
        Ok((commitment_id, candidate))
    }

    /// Distinct honest signers whose validated partial for THIS request's escape
    /// candidate reached the adversary. Candidate identity, outputs, signature and
    /// role hint are all checked; no global hint-based classification is involved.
    fn validated_escape_partials(&self, request: &SignRequest) -> Result<Vec<u16>, Error> {
        let (commitment_id, candidate) = self.signed_escape_candidate(request)?;
        self.validated_honest_partials_for(&commitment_id, &candidate, "escape")
    }

    fn wait_for_escape_partials(
        &self,
        request: &SignRequest,
        expected: usize,
        timeout: Duration,
    ) -> Result<Vec<u16>, Error> {
        let (commitment_id, candidate) = self.signed_escape_candidate(request)?;
        self.wait_for_honest_partials(&commitment_id, &candidate, "escape", expected, timeout)
    }

    // -- transaction construction ------------------------------------------

    /// A hot-class spend of `utxo`: `amount` to the hot wallet, the rest back to
    /// the vault as change.
    ///
    /// Subtraction is checked: `Card::run` reports a returned `Err` as one FAIL row,
    /// but an arithmetic panic unwinds past it and the whole run ends with no
    /// scorecard at all. A mis-sized constant should cost one row, not the report.
    fn hot_spend(&self, utxo: &Utxo, amount: Amount) -> Result<Psbt, Error> {
        self.hot_spend_fee(utxo, amount, FEE)
    }

    /// The same hot-class spend at a chosen fee. Scenarios that raise bitcoind's own
    /// relay floor need one, or the transaction cannot relay even if a node released
    /// its partial — which would silently disarm every "the coerced spend never
    /// completed" read in that run.
    fn hot_spend_fee(&self, utxo: &Utxo, amount: Amount, fee: Amount) -> Result<Psbt, Error> {
        let change = utxo
            .txout
            .value
            .checked_sub(amount)
            .and_then(|rest| rest.checked_sub(fee))
            .ok_or_else(|| {
                format!(
                    "hot spend of {amount} + {fee} fee exceeds the {} coin it spends",
                    utxo.txout.value
                )
            })?
            .to_sat();
        let mut outputs = vec![(self.hot_spk.clone(), amount)];
        if change > 0 {
            outputs.push((self.vault_spk.clone(), Amount::from_sat(change)));
        }
        build_spend(utxo, &self.witness_script, &outputs)
    }

    /// An escape-class sweep of `utxos`: every output pays the escape descriptor,
    /// which is what makes it escape-class under the node's output-derived
    /// predicate (never a coordinator label).
    fn escape_over(&self, utxos: &[&Utxo]) -> Result<Psbt, Error> {
        self.escape_over_fee(utxos, FEE)
    }

    /// The same sweep at a chosen fee. Two candidates registered against the same
    /// coin must be distinguishable, and a commitment binds the exact unsigned
    /// transaction — so varying the fee is how a scenario gets a SECOND valid
    /// escape over the same input rather than a duplicate the node refuses as
    /// already registered.
    fn escape_over_fee(&self, utxos: &[&Utxo], fee: Amount) -> Result<Psbt, Error> {
        let total: u64 = utxos.iter().map(|u| u.txout.value.to_sat()).sum();
        let owned: Vec<Utxo> = utxos
            .iter()
            .map(|u| Utxo {
                outpoint: u.outpoint,
                txout: u.txout.clone(),
            })
            .collect();
        let swept = total
            .checked_sub(fee.to_sat())
            .ok_or_else(|| format!("an escape fee of {fee} exceeds the {total} sat it sweeps"))?;
        build_spend_n(
            &owned,
            &self.witness_script,
            &[(self.escape_spk.clone(), Amount::from_sat(swept))],
        )
    }

    /// The escape that accompanies a spend of the single funded vault UTXO. For a
    /// hot-class spend the escape SUPERSEDES it (same input), so coverage is
    /// measured against the whole confirmed balance.
    fn escape_for(&self, utxo: &Utxo) -> Result<Psbt, Error> {
        self.escape_over(&[utxo])
    }

    /// Assemble the `{pin, spend, escape}` request: user-sign both transactions
    /// (freezing their exact bytes), then coordinator-authenticate.
    fn request(&self, spend: &Psbt, escape: &Psbt, pin: &str) -> Result<SignRequest, Error> {
        self.request_at(spend, escape, pin, commitment_expiry(COMMITMENT_TTL_SECS)?)
    }

    fn request_at(
        &self,
        spend: &Psbt,
        escape: &Psbt,
        pin: &str,
        expiry: u64,
    ) -> Result<SignRequest, Error> {
        let mut spend = spend.clone();
        let mut escape = escape.clone();
        sign_all_inputs(&self.secp, &mut spend, &self.user, &self.witness_script)?;
        sign_all_inputs(&self.secp, &mut escape, &self.user, &self.witness_script)?;
        self.authorize_signed(&spend, &escape, pin, expiry)
    }

    /// The same, but over PSBTs the caller already signed (or deliberately
    /// mis-signed — the corrupt-escape attack vector).
    ///
    /// **No escape fee-bump ladder here, deliberately** (bead btc-policy-9y5.7). The
    /// coordinator that ships to users composes one — see `fed::escape_fee_ladder` and
    /// its use in `demo`, which today compose unconditionally against a hardcoded
    /// ceiling — but this harness must not. (ADR-0016 DECIDES to gate that on a sealed
    /// per-vault `escape_bump_max_fee_pct`, default off; the field lands with
    /// btc-policy-mby and the wiring with btc-policy-sqn. Not built yet.) Two reasons, and both are about
    /// keeping the 16 adversarial scenarios meaningful:
    ///
    ///  - a ladder rewrites the escape's `nSequence` to signal BIP125 replacement,
    ///    which changes its txid; every scenario that waits for the exact escape it
    ///    composed would then be waiting for a transaction that was never sent;
    ///  - *which* rung the nodes fire is a function of the regtest chain's own block
    ///    fee statistics, so a scenario's on-chain expectation would turn on how many
    ///    blocks its funding happened to mine. That is precisely the "flaky live fee
    ///    timing threaded through the tight pre-T window" this bead was told not to
    ///    build; the ladder's determinism, bounds, and BIP125 validity are proved by
    ///    focused vault-node tests instead (`channel::duress::fee_bump`).
    fn authorize_signed(
        &self,
        spend: &Psbt,
        escape: &Psbt,
        pin: &str,
        expiry: u64,
    ) -> Result<SignRequest, Error> {
        self.coordinator.authorize(
            &self.secp,
            &wallet_id(&self.descriptor),
            SignRequest {
                pin: pin.to_string().into(),
                psbt: spend.to_string(),
                escape_psbt: escape.to_string(),
                escape_bumps: Vec::new(),
                nonce: String::new(),
                expiry,
                policy_version: POLICY_VERSION,
                coord_sig: String::new(),
            },
        )
    }

    fn refresh_request(&self, psbt: &Psbt) -> Result<RefreshRequest, Error> {
        let mut psbt = psbt.clone();
        sign_all_inputs(&self.secp, &mut psbt, &self.user, &self.witness_script)?;
        let mut request = RefreshRequest {
            refresh_psbt: psbt.to_string(),
            nonce: String::new(),
            expiry: commitment_expiry(COMMITMENT_TTL_SECS)?,
            policy_version: POLICY_VERSION,
            coord_sig: String::new(),
        };
        request.nonce = crate::fed::fresh_nonce()?;
        let digest = request
            .coord_request()
            .auth_digest(&wallet_id(&self.descriptor));
        let sig = self.secp.sign_ecdsa(
            &bitcoin::secp256k1::Message::from_digest(digest),
            &self.coordinator.seckey,
        );
        request.coord_sig = sig.serialize_der().to_lower_hex_string();
        Ok(request)
    }

    /// Prove the theft detector can FIRE, so a zero from it is evidence rather than
    /// an artefact of a scan that cannot see anything.
    ///
    /// [`Vault::attacker_receipts`] is the harness's no-theft ground truth, and it
    /// is an argument from absence in exactly the way the wiretap counts are — with
    /// the same failure mode. Every transaction that pays `attacker_spk` in this
    /// harness is one a scenario asserts is refused or unbuildable, so the detector
    /// never fires in a passing run; a `raw()` descriptor the node rejects, a
    /// units error, or a mempool scan that silently returns nothing would all read
    /// as "0 sat stolen" forever, and every scenario would close on a check that
    /// cannot fail. So pay a THROWAWAY script the harness never uses again and
    /// require both halves of the detector — mempool and confirmed — to report it.
    fn prove_theft_detector_fires(&self) -> Result<(), Error> {
        const CONTROL: Amount = Amount::from_sat(100_000);
        let mut urandom = std::fs::File::open("/dev/urandom")?;
        let control_spk = p2wpkh_spk(&Actor::random(&self.secp, &mut urandom)?);
        let address = bitcoin::Address::from_script(&control_spk, Network::Regtest)?;
        self.bitcoind.call_str(
            "sendtoaddress",
            json!([address.to_string(), CONTROL.to_btc()]),
        )?;
        // Unmined first: most scenarios assert no-theft without mining, so the
        // mempool half is the half that actually carries them.
        let unmined = self.receipts_for(&control_spk)?;
        if unmined != CONTROL.to_sat() {
            return Err(format!(
                "the theft detector missed an UNMINED payment of {CONTROL} to a control script \
                 (reported {unmined} sat); every scenario that asserts no theft without mining \
                 first would pass vacuously"
            )
            .into());
        }
        self.mine(1)?;
        let mined = self.receipts_for(&control_spk)?;
        if mined != CONTROL.to_sat() {
            return Err(format!(
                "the theft detector missed a CONFIRMED payment of {CONTROL} to a control script \
                 (reported {mined} sat); the confirmed-UTXO half of the no-theft ground truth is \
                 not working"
            )
            .into());
        }
        // And it must not see money that went elsewhere: a detector that reports a
        // non-zero for every script would make `assert_no_theft` fail rather than
        // pass vacuously, but it would be equally uninformative.
        if self.receipts_for(&self.attacker_spk)? != 0 {
            return Err(
                "the theft detector reports receipts for the attacker script before any \
                 scenario has run"
                    .into(),
            );
        }
        Ok(())
    }

    /// Actively try the redirect `assert_no_theft` later audits: compose a payment to
    /// the attacker's non-allowlisted script, sign those exact bytes with the stolen
    /// user key, and require every honest daemon to reject it before node signing.
    /// This is a consensus-valid user-key spend, so an allowlist/release regression
    /// could really broadcast it and make the attacker-address scan fire.
    fn prove_unauthorized_redirect_refused(&self) -> Result<String, Error> {
        // At `RELAY_CLEARING_FEE`, not `FEE`, for the reason `FireTimeGate::coerced_fee`
        // spells out: the package-acceptance run raises bitcoind's own relay floor to
        // 100 sat/vB, and an ordinary `FEE` over this ~260 vB body buys about 38. In
        // THAT arm a release/allowlist regression that really broadcast this redirect
        // would be turned away by Core, `attacker_receipts` would read 0 sat, and the
        // no-theft ground truth this probe exists to arm would be true by relay policy
        // rather than by mechanism. `check_destinations` runs ahead of `check_fee`
        // (`policy-core`), so the refusal code under test is unaffected, and the fee
        // stays far below `MAX_FEE_PERCENT` of the 10 BTC coin spent.
        let mut redirected = self.hot_spend_fee(
            &self.vault_utxo,
            Amount::from_sat(1_000),
            RELAY_CLEARING_FEE,
        )?;
        redirected.unsigned_tx.output[0].script_pubkey = self.attacker_spk.clone();
        sign_all_inputs(
            &self.secp,
            &mut redirected,
            &self.user,
            &self.witness_script,
        )?;

        let mut escape = self.escape_for(&self.vault_utxo)?;
        sign_all_inputs(&self.secp, &mut escape, &self.user, &self.witness_script)?;
        for (index, node) in self.honest.iter().enumerate() {
            let expiry = if self.disjoint_admission_windows {
                unix_now()?.saturating_add(
                    route_horizon(node.node_id).saturating_add(ROUTE_WINDOW_WIDTH_SECS / 2),
                )
            } else {
                commitment_expiry(COMMITMENT_TTL_SECS)?
            };
            let request = self.authorize_signed(&redirected, &escape, NORMAL_PIN, expiry)?;
            expect_code(
                &self.relay_to(index, &request)?,
                RefusalCode::DestNotAllowed,
                "destination_allowlist",
                &format!("unauthorized attacker-output redirect at node {index}"),
            )?;
        }
        Ok(redirected.unsigned_tx.compute_txid().to_string())
    }

    // -- relaying ----------------------------------------------------------

    /// Relay the same spend to every honest node under its OWN fresh nonce.
    ///
    /// The coordinator holds the auth key, so re-signing per recipient is ordinary
    /// relay behaviour — and it is what makes "refused at EVERY node" a real claim.
    /// Under one shared nonce the node that learns the carrier over the channel
    /// first answers the coordinator's later POST with `NONCE_REPLAYED`, which
    /// would leave the assertion measuring propagation order rather than each
    /// node's independent verdict.
    fn relay_all_fresh(&self, request: &SignRequest) -> Result<Vec<SignResponse>, Error> {
        let mut responses = Vec::new();
        for node in &self.honest {
            let fresh = self.coordinator.authorize(
                &self.secp,
                &wallet_id(&self.descriptor),
                request.clone(),
            )?;
            responses.push(node.sign(&fresh)?);
        }
        Ok(responses)
    }

    /// The refresh form of [`Vault::relay_all_fresh`], for the same reason.
    fn relay_refresh_all_fresh(
        &self,
        request: &RefreshRequest,
    ) -> Result<Vec<SignResponse>, Error> {
        let mut responses = Vec::new();
        for node in &self.honest {
            let mut fresh = request.clone();
            fresh.nonce = crate::fed::fresh_nonce()?;
            let digest = fresh
                .coord_request()
                .auth_digest(&wallet_id(&self.descriptor));
            let sig = self.secp.sign_ecdsa(
                &bitcoin::secp256k1::Message::from_digest(digest),
                &self.coordinator.seckey,
            );
            fresh.coord_sig = sig.serialize_der().to_lower_hex_string();
            responses.push(node.send(&TaggedRequest::Refresh(fresh))?);
        }
        Ok(responses)
    }

    /// Relay to exactly one honest node — the hostile coordinator's selective
    /// delivery. It cannot forge or redirect signatures, but it can choose who
    /// hears it.
    fn relay_to(&self, index: usize, request: &SignRequest) -> Result<SignResponse, Error> {
        self.honest[index].sign(request)
    }

    /// Wait for wire evidence that every honest daemon received and processed this
    /// exact carrier. Honest nodes propagate only after processing; unlike a fixed
    /// sleep this cannot race a slow localhost fan-out.
    fn wait_for_honest_relayers(
        &self,
        nonce: &str,
        expected: usize,
        timeout: Duration,
    ) -> Result<Vec<u16>, Error> {
        let deadline = Instant::now() + timeout;
        loop {
            let mut relayers: Vec<u16> = self
                .compromised
                .iter()
                .flat_map(|node| node.wiretap().relayers_of(nonce))
                .collect();
            relayers.sort_unstable();
            relayers.dedup();
            if relayers.len() >= expected {
                return Ok(relayers);
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "only {}/{} honest nodes visibly processed carrier nonce {nonce}",
                    relayers.len(),
                    expected
                )
                .into());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Furnish each already-processing honest node with the compromised minority's
    /// `t−1` holder receipts and wait for the daemon's pin-uniform holder-decision
    /// marker on every node. Returns a wall-clock upper bound on those commits.
    ///
    /// A `/channel` 200/`ACCEPTED` proves only that the authenticated envelope was
    /// decodable: policy refusals are deliberately hidden behind the same reply. It is
    /// therefore transport evidence, not holder-decision evidence. The log marker is
    /// emitted only after the production carrier memo resolves and its holder gate is
    /// observed committed, under either pin. The safety assertion remains the
    /// release-gate, not this count.
    fn confirm_with_compromised(&self, request: &SignRequest) -> Result<u64, Error> {
        let targets: Vec<usize> = (0..self.honest.len()).collect();
        self.confirm_with_compromised_at(request, &targets)
    }

    /// Confirm `request` only at the selected honest nodes. The censorship-bound
    /// scenarios deliberately route distinct normal carriers to disjoint honest
    /// ledgers; requiring every node there would erase the adversarial condition the
    /// scenario is demonstrating.
    fn confirm_with_compromised_at(
        &self,
        request: &SignRequest,
        targets: &[usize],
    ) -> Result<u64, Error> {
        if targets.is_empty() {
            return Err("holder confirmation requires at least one honest target".into());
        }
        let target_ids: Vec<u16> = targets
            .iter()
            .map(|&index| {
                self.honest
                    .get(index)
                    .map(|node| node.node_id)
                    .ok_or_else(|| format!("no honest confirmation target at index {index}"))
            })
            .collect::<Result<_, _>>()?;
        // Do not require prior honest-relay evidence here. Several scenarios
        // deliberately make the compromised peer's full authenticated carrier the
        // node's FIRST delivery; the production handler independently processes that
        // carrier before applying the sender's receipt. The post-processing marker
        // below is the positive evidence: a generic `/channel` ACCEPTED without a
        // resolved memo or committed holder decision never emits it.
        let tagged = TaggedRequest::Spend(request.clone());
        for &target_index in targets {
            let target = &self.honest[target_index];
            for compromised in &self.compromised {
                // `RATE_LIMITED` here is "not ruled on yet", not "refused": since bead
                // btc-policy-9zs a nonce claimed by a `/sign` handler inside its
                // out-of-lock PIN window answers 429 on purpose, and the production
                // sender retries. Reading the first 429 as a rejection made this
                // scenario fail on a loaded box for a reason unrelated to the safety
                // property. See `CompromisedNode::relay_request_awaiting_ruling`.
                let response = compromised.relay_request_awaiting_ruling(
                    &self.secp,
                    target.addr(),
                    target.node_id,
                    &tagged,
                )?;
                let accepted = serde_json::from_str::<Value>(&response.body)
                    .ok()
                    .and_then(|body| {
                        body.get("status")
                            .and_then(Value::as_str)
                            .map(str::to_owned)
                    })
                    .is_some_and(|status| status == "ACCEPTED");
                if response.status != 200 || !accepted {
                    return Err(format!(
                        "node_id {} rejected holder confirmation from compromised node_id {}: \
                         HTTP {} {}",
                        target.node_id, compromised.node_id, response.status, response.body
                    )
                    .into());
                }
            }
        }
        // The daemon hex-encodes the nonce in this marker so a coordinator-chosen
        // string cannot inject log lines; match the same encoding.
        let marker = format!(
            "channel: holder decision committed for request nonce {}",
            request.nonce.as_bytes().to_lower_hex_string()
        );
        let deadline = Instant::now() + EXPECT_TIMEOUT;
        loop {
            let missing: Vec<u16> = self
                .honest
                .iter()
                .filter(|node| target_ids.contains(&node.node_id))
                .filter(|node| !node.log_contains(&marker))
                .map(|node| node.node_id)
                .collect();
            if missing.is_empty() {
                break;
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "holder receipts returned generic ACCEPTED replies, but node_id(s) {missing:?} \
                     never committed the holder decision for nonce {}; the replies alone do not \
                     prove the carrier memo resolved",
                    request.nonce
                )
                .into());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let committed_by = unix_now()?;
        if committed_by >= request.expiry {
            return Err(format!(
                "holder-decision evidence for nonce {} arrived at {committed_by}, at or after its \
                 expiry {}; it cannot establish a live release/arm gate",
                request.nonce, request.expiry
            )
            .into());
        }
        Ok(committed_by)
    }

    /// Give selected honest daemons every compromised signer's valid share for one
    /// candidate. Together with the daemon's own ingress signature this makes a full
    /// `t`-share candidate resident locally. A coerced spend must still not finalize:
    /// the Armed combine/broadcast authorization, rather than an accidental lack of
    /// peer shares, is then the only thing between that daemon and a complete tx.
    ///
    /// **`ACCEPTED` here IS proof of storage, unlike on the request path.** The
    /// caveat that governs [`Vault::confirm_with_compromised_at`] — `/channel` maps
    /// every decodable policy outcome to `ACCEPTED`, so the reply proves only that
    /// the envelope decoded — applies to the SPEND/REFRESH branch, which flattens
    /// its whole policy result (`vault-node/src/lib.rs`, `match outcome`). A
    /// `msg_type` of partial does not take that branch. It is answered directly by
    /// `ChannelState::handle_partial` → `CandidateStore::accept_partial`
    /// (`vault-node/src/channel.rs`), which returns `Accepted` on exactly two paths —
    /// the share was verified and inserted, or an identical one already was — and
    /// gives every other outcome a DISTINCT reply: `UnknownCandidate` (409) for an
    /// absent or expired candidate, and `Rejected` (400) with a specific reason for a
    /// txid, `user_sig_hash`, input-index, or signature mismatch. The
    /// `status != 200 || status != "ACCEPTED"` guard below therefore fails on every
    /// non-storing outcome, which is what lets the callers claim a locally complete
    /// `t`-share candidate. Do not "strengthen" this with a log marker: the evidence
    /// is already in the reply, and there is nothing to add.
    fn furnish_compromised_partials(
        &self,
        targets: &[usize],
        commitment_id: &str,
        candidate: &Psbt,
        spend_purpose: &str,
    ) -> Result<usize, Error> {
        let user_sig_hash = self.candidate_user_sig_hash(candidate, commitment_id)?;
        let mut delivered = 0usize;
        for compromised in &self.compromised {
            let mut signed = candidate.clone();
            sign_all_inputs(
                &self.secp,
                &mut signed,
                compromised.signer(),
                &self.witness_script,
            )?;
            for &target in targets {
                let node = self
                    .honest
                    .get(target)
                    .ok_or_else(|| format!("no honest target at index {target}"))?;
                for (input, psbt_input) in signed.inputs.iter().enumerate() {
                    let signature = psbt_input
                        .partial_sigs
                        .get(&compromised.signer().pubkey)
                        .ok_or_else(|| {
                            format!(
                                "compromised node_id {} did not sign input {input} of \
                                 {commitment_id}",
                                compromised.node_id
                            )
                        })?;
                    let payload = json!({
                        "commitment_id": commitment_id,
                        "wallet_id": wallet_id(&self.descriptor).to_lower_hex_string(),
                        "txid": candidate.unsigned_tx.compute_txid().to_string(),
                        "input": input as u32,
                        "signer_node_id": compromised.node_id,
                        "sighash_type": EcdsaSighashType::All.to_u32(),
                        "spend_purpose": spend_purpose,
                        "user_sig_hash": user_sig_hash.to_lower_hex_string(),
                        "partial_sig": signature.signature.serialize_der().to_lower_hex_string(),
                    });
                    let response = compromised.relay_partial(
                        &self.secp,
                        node.addr(),
                        node.node_id,
                        &payload,
                    )?;
                    let accepted = serde_json::from_str::<Value>(&response.body)
                        .ok()
                        .and_then(|body| {
                            body.get("status")
                                .and_then(Value::as_str)
                                .map(str::to_owned)
                        })
                        .is_some_and(|status| status == "ACCEPTED");
                    if response.status != 200 || !accepted {
                        return Err(format!(
                            "honest node_id {} rejected compromised node_id {}'s partial for \
                             {commitment_id} input {input}: HTTP {} {}",
                            node.node_id, compromised.node_id, response.status, response.body
                        )
                        .into());
                    }
                    delivered += 1;
                }
            }
        }
        Ok(delivered)
    }

    // -- observation -------------------------------------------------------

    /// Every honest partial the adversary holds for `commitment_id`. This is the
    /// releasable-partial count the coupling bounds.
    fn honest_partials_for(&self, commitment_id: &str) -> Vec<u16> {
        let mut signers = Vec::new();
        for node in &self.compromised {
            signers.extend(node.wiretap().honest_signers_for(commitment_id));
        }
        signers.sort_unstable();
        signers.dedup();
        signers
    }

    /// Fail if any channel envelope was malformed or incomplete, or if any of the
    /// adversary's listeners has died. Every assertion that concludes safety from an
    /// ABSENT partial calls this first: otherwise a leaked payload that the harness
    /// failed to decode — or one sent to a port that stopped answering — would be
    /// reported as zero.
    fn assert_wiretap_decoded(&self, context: &str) -> Result<(), Error> {
        // First round-trip through every accept loop. A connection can be complete in
        // the kernel's listen backlog without having incremented `active_handlers`, so
        // liveness plus a zero counter alone can turn that queued leak into a clean
        // zero. Once the barrier is answered, drain every accepted handler and require
        // the whole listener set to remain quiet for a short continuous interval.
        for node in &self.compromised {
            node.wiretap_barrier().map_err(|e| {
                format!(
                    "{context}: the wiretap barrier for node_id {} failed, so queued channel \
                     traffic may be unaccounted: {e}",
                    node.node_id
                )
            })?;
        }
        let deadline = Instant::now() + WIRETAP_DRAIN_TIMEOUT;
        let mut quiet_since = None;
        loop {
            let dead: Vec<u16> = self
                .compromised
                .iter()
                .filter(|node| !node.listener_alive())
                .map(|node| node.node_id)
                .collect();
            if !dead.is_empty() {
                return Err(format!(
                    "{context}: the adversary's listener(s) for node_id(s) {dead:?} are no longer \
                     accepting; anything honest nodes pushed to those sealed endpoints since is \
                     lost and unaccounted, so a zero-partial count is an artefact of a deaf wiretap"
                )
                .into());
            }
            let active: Vec<(u16, usize)> = self
                .compromised
                .iter()
                .map(|node| (node.node_id, node.active_handlers()))
                .filter(|(_, count)| *count != 0)
                .collect();
            if active.is_empty() {
                let since = quiet_since.get_or_insert_with(Instant::now);
                if since.elapsed() >= WIRETAP_QUIET {
                    break;
                }
            } else {
                quiet_since = None;
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "{context}: wiretap connection handlers did not drain within \
                     {WIRETAP_DRAIN_TIMEOUT:?}; still active: {active:?}"
                )
                .into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let undecoded: usize = self
            .compromised
            .iter()
            .map(|node| node.wiretap().undecoded())
            .sum();
        if undecoded != 0 {
            return Err(format!(
                "{context}: the adversary could not decode {undecoded} channel envelope(s); an \
                 absence-based partial count is not trustworthy until they are accounted for"
            )
            .into());
        }
        Ok(())
    }

    /// Validate one observed partial exactly as a peer needs it bound: complete
    /// payload, candidate identity, wallet, txid, user-signature hash, SIGHASH_ALL,
    /// signer identity, and the ECDSA signature over this input's exact sighash.
    fn validate_observed_partial(
        &self,
        partial: &PartialSeen,
        commitment_id: &str,
        candidate: &Psbt,
        spend_purpose: &str,
    ) -> Result<(), Error> {
        if partial.commitment_id != commitment_id {
            return Err(format!(
                "partial commitment {} != expected {commitment_id}",
                partial.commitment_id
            )
            .into());
        }
        let expected_wallet_id = wallet_id(&self.descriptor);
        if partial.wallet_id != expected_wallet_id {
            return Err(format!(
                "partial for {commitment_id} carries the wrong wallet_id {}",
                partial.wallet_id.to_lower_hex_string()
            )
            .into());
        }
        let expected_txid = candidate.unsigned_tx.compute_txid();
        if partial.txid != expected_txid {
            return Err(format!(
                "partial for {commitment_id} carries txid {}, expected {expected_txid}",
                partial.txid
            )
            .into());
        }
        if partial.sender_node_id != partial.signer_node_id {
            return Err(format!(
                "partial for {commitment_id} was sent by node_id {} but names signer node_id {}",
                partial.sender_node_id, partial.signer_node_id
            )
            .into());
        }
        if partial.sighash_type != EcdsaSighashType::All.to_u32() {
            return Err(format!(
                "partial for {commitment_id} uses sighash type {}, expected SIGHASH_ALL",
                partial.sighash_type
            )
            .into());
        }
        if partial.spend_purpose != spend_purpose {
            return Err(format!(
                "partial for {commitment_id} claims purpose {}, expected {spend_purpose}",
                partial.spend_purpose
            )
            .into());
        }

        let expected_user_sig_hash = self.candidate_user_sig_hash(candidate, commitment_id)?;
        if partial.user_sig_hash != expected_user_sig_hash {
            return Err(format!(
                "partial for {commitment_id} carries the wrong user_sig_hash {}",
                partial.user_sig_hash.to_lower_hex_string()
            )
            .into());
        }

        let input = partial.input as usize;
        let psbt_input = candidate.inputs.get(input).ok_or_else(|| {
            format!(
                "partial for {commitment_id} names missing input {}",
                partial.input
            )
        })?;
        let utxo = psbt_input.witness_utxo.as_ref().ok_or_else(|| {
            format!("candidate {commitment_id} input {input} has no witness_utxo")
        })?;
        let sighash = SighashCache::new(&candidate.unsigned_tx).p2wsh_signature_hash(
            input,
            &self.witness_script,
            utxo.value,
            EcdsaSighashType::All,
        )?;
        let signer = self
            .node_pubkeys
            .get(partial.signer_node_id as usize)
            .ok_or_else(|| {
                format!(
                    "partial for {commitment_id} names unknown signer node_id {}",
                    partial.signer_node_id
                )
            })?;
        self.secp
            .verify_ecdsa(
                &Message::from_digest(sighash.to_byte_array()),
                &partial.partial_sig,
                &signer.inner,
            )
            .map_err(|e| {
                format!(
                    "partial for {commitment_id} input {input} from node_id {} has an invalid \
                     signature: {e}",
                    partial.signer_node_id
                )
            })?;
        Ok(())
    }

    fn candidate_user_sig_hash(
        &self,
        candidate: &Psbt,
        commitment_id: &str,
    ) -> Result<[u8; 32], Error> {
        let mut encoded_user_sigs = Vec::new();
        for (input, psbt_input) in candidate.inputs.iter().enumerate() {
            let user_sig = psbt_input
                .partial_sigs
                .get(&self.user.pubkey)
                .ok_or_else(|| {
                    format!("candidate {commitment_id} input {input} has no user signature")
                })?;
            push_var(&mut encoded_user_sigs, &user_sig.signature.serialize_der());
            encoded_user_sigs.push(user_sig.sighash_type.to_u32() as u8);
        }
        Ok(tagged_hash(USER_SIG_HASH_TAG, &encoded_user_sigs))
    }

    fn validated_honest_partials_for(
        &self,
        commitment_id: &str,
        candidate: &Psbt,
        spend_purpose: &str,
    ) -> Result<Vec<u16>, Error> {
        self.assert_wiretap_decoded("validating an observed partial")?;
        let mut signers = Vec::new();
        for node in &self.compromised {
            for partial in node.wiretap().honest_partials_for(commitment_id) {
                self.validate_observed_partial(&partial, commitment_id, candidate, spend_purpose)?;
                signers.push(partial.signer_node_id);
            }
        }
        signers.sort_unstable();
        signers.dedup();
        Ok(signers)
    }

    fn wait_for_honest_partials(
        &self,
        commitment_id: &str,
        candidate: &Psbt,
        spend_purpose: &str,
        expected: usize,
        timeout: Duration,
    ) -> Result<Vec<u16>, Error> {
        let deadline = Instant::now() + timeout;
        loop {
            let signers =
                self.validated_honest_partials_for(commitment_id, candidate, spend_purpose)?;
            if signers.len() >= expected {
                return Ok(signers);
            }
            if Instant::now() >= deadline {
                let node_logs = self
                    .honest
                    .iter()
                    .map(|node| format!("node_id {}: {}", node.node_id, node.log_tail()))
                    .collect::<Vec<_>>()
                    .join("; ");
                return Err(format!(
                    "only {}/{} honest partials became observable for commitment {commitment_id}; \
                     honest node logs: {node_logs}",
                    signers.len(),
                    expected
                )
                .into());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Assemble the transaction the adversary could actually broadcast for
    /// `commitment_id` — the honest share(s) its wiretap collected plus signatures
    /// from the `t−1` node keys it holds — and ask Core whether it would take it.
    ///
    /// This is the completability oracle. Every "the releasable set is `≤ t−1`, so
    /// the combine can never reach `t`" claim in this harness is an argument from
    /// absence, and it rests on an unstated premise: that a set of `t` shares WOULD
    /// have completed. Reading "each routed spend is completable out of exactly one
    /// honest ledger" off a validated-signature count alone leaves that premise
    /// unmeasured — the harness would report the same thing if its own combine were
    /// broken. Here the adversary does the whole job with the keys it really has,
    /// and `testmempoolaccept` — Core's verdict, WITHOUT a broadcast — settles it.
    ///
    /// Nothing is sent. The coin stays unspent, so a scenario can go on watching it.
    fn combine_with_compromised(
        &self,
        commitment_id: &str,
        candidate: &Psbt,
    ) -> Result<Transaction, Error> {
        let mut psbt = candidate.clone();
        // The candidate already carries the user's signature (`request_at` signs it
        // before the coordinator authorizes), so the two halves added here are the
        // honest share(s) and the adversary's own.
        //
        // Counted by DISTINCT signer: an honest node fans its partial to every peer,
        // so the same share arrives at each of the adversary's `t−1` listeners. The
        // inserts are idempotent on the pubkey, but a raw count would report `t−1`
        // honest shares where there is one, and the quorum arithmetic in the messages
        // below would be wrong.
        let mut honest: Vec<u16> = Vec::new();
        for node in &self.compromised {
            for partial in node.wiretap().honest_partials_for(commitment_id) {
                let signer = self
                    .node_pubkeys
                    .get(partial.signer_node_id as usize)
                    .ok_or_else(|| {
                        format!(
                            "observed partial for {commitment_id} names unknown signer node_id {}",
                            partial.signer_node_id
                        )
                    })?;
                let input = psbt.inputs.get_mut(partial.input as usize).ok_or_else(|| {
                    format!(
                        "observed partial for {commitment_id} names missing input {}",
                        partial.input
                    )
                })?;
                input.partial_sigs.insert(
                    *signer,
                    bitcoin::ecdsa::Signature {
                        signature: partial.partial_sig,
                        sighash_type: EcdsaSighashType::All,
                    },
                );
                if !honest.contains(&partial.signer_node_id) {
                    honest.push(partial.signer_node_id);
                }
            }
        }
        let honest = honest.len();
        if honest == 0 {
            return Err(format!(
                "no honest share for {commitment_id} reached the adversary, so there is nothing \
                 to combine — completability cannot be claimed"
            )
            .into());
        }
        for node in &self.compromised {
            sign_all_inputs(&self.secp, &mut psbt, node.signer(), &self.witness_script)?;
        }
        // The adversary's own share count is what this federation gave it, not the
        // constant `C`: `reboot_death_still_sweeps_above_threshold` runs with 1
        // compromised identity, and reporting the tolerance instead would state the
        // quorum arithmetic of a run that did not happen.
        let held = self.compromised.len();
        psbt.finalize_mut(&self.secp).map_err(|e| {
            format!("the adversary's {honest}+{held} shares do not satisfy {commitment_id}: {e:?}")
        })?;
        let tx = psbt.extract_tx()?;
        let verdict = self.bitcoind.call(
            "testmempoolaccept",
            json!([[bitcoin::consensus::encode::serialize_hex(&tx)]]),
        )?;
        let entry = verdict
            .as_array()
            .and_then(|results| results.first())
            .ok_or_else(|| format!("testmempoolaccept returned no verdict: {verdict}"))?;
        // Strictly: a missing `allowed` is a broken check, not a rejection. The
        // whole point here is that Core said yes.
        let allowed = entry
            .get("allowed")
            .and_then(Value::as_bool)
            .ok_or_else(|| {
                format!("testmempoolaccept returned no verdict for {commitment_id}: {entry}")
            })?;
        if !allowed {
            return Err(format!(
                "the combine of {honest} honest share(s) and the adversary's {held} did not \
                 produce a transaction Core would accept for {commitment_id}: {entry}"
            )
            .into());
        }
        Ok(tx)
    }

    /// Whether `txid` reached the mempool or a block.
    ///
    /// This is the oracle behind roughly a dozen "the coerced spend never
    /// broadcast" assertions and behind [`assert_no_theft`]'s probe check, so it
    /// makes the same distinction `receipts_for` and `receipts_in_mempool` make and
    /// for the same reason: bitcoind answers "I do not know this txid" with a
    /// JSON-RPC error, and collapsing every error to `false` would let a degraded
    /// or dead bitcoind report "nothing broadcast" — an RPC failure reading as
    /// safety. Only the absence code is an absence; anything else propagates.
    ///
    /// The two lookups are not atomic, so ANY successful `getrawtransaction` counts
    /// as presence — the reply is deliberately not filtered on `blockhash`. A
    /// transaction that entered the mempool between the two calls answers the first
    /// with the absence code and the second with a blockhash-less entry, and reading
    /// that as absence would report a broadcast the harness just missed as the
    /// safety property holding.
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

    fn mine(&self, blocks: u32) -> Result<(), Error> {
        self.bitcoind
            .call("generatetoaddress", json!([blocks, self.mining_address]))?;
        Ok(())
    }

    /// Wait until `txid` is in the mempool or a block.
    fn wait_for_tx(&self, txid: &str, timeout: Duration) -> Result<(), Error> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if self.in_mempool_or_chain(txid)? {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        Err(format!("transaction {txid} never reached the mempool or a block").into())
    }

    /// Wait until every honest node reports lockdown. Lockdown at `T` is
    /// UNCONDITIONAL (ADR-0012 invariant i) and is the safety track's terminal
    /// state — it does not wait for the sweep to confirm.
    fn wait_for_lockdown(&self, nodes: &[usize], timeout: Duration) -> Result<(), Error> {
        let deadline = Instant::now() + timeout;
        loop {
            let mut pending = Vec::new();
            for &index in nodes {
                if !self.is_locked_down(index)? {
                    pending.push(self.honest[index].node_id);
                }
            }
            if pending.is_empty() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                let logs: Vec<String> = nodes
                    .iter()
                    .map(|&i| {
                        format!(
                            "node_id {}: {}",
                            self.honest[i].node_id,
                            self.honest[i].log_tail()
                        )
                    })
                    .collect();
                return Err(format!(
                    "node_id(s) {pending:?} did not enter Lockdown at T; lockdown at T is \
                     unconditional (ADR-0012 invariant i). {}",
                    logs.join(" || ")
                )
                .into());
            }
            std::thread::sleep(Duration::from_millis(400));
        }
    }

    /// Probe lockdown the only way an outsider can: submit something and look for
    /// `FRAUD_SUSPECTED`. A locked-down node answers it to every spend and refresh
    /// for its remaining lifetime.
    fn is_locked_down(&self, index: usize) -> Result<bool, Error> {
        let request = {
            let mut cached = self.lockdown_probe.borrow_mut();
            if cached.is_none() {
                let spend = self.hot_spend(&self.vault_utxo, Amount::from_sat(1_000))?;
                let escape = self.escape_for(&self.vault_utxo)?;
                // Deliberately outside every node's coordinator-expiry window. This
                // refusal happens before PIN evaluation, signing, candidate
                // registration, and Hot-budget reservation, so polling Lockdown is
                // observational rather than a stream of live hot spends.
                *cached = Some(self.request_at(
                    &spend,
                    &escape,
                    NORMAL_PIN,
                    unix_now()?.saturating_sub(1),
                )?);
            }
            cached
                .as_ref()
                .expect("lockdown probe was initialized")
                .clone()
        };
        match self.relay_to(index, &request)? {
            SignResponse::Refusal(r) => Ok(r.code == RefusalCode::FraudSuspected),
            SignResponse::Accepted(_) => {
                Err("the deliberately expired Lockdown probe was unexpectedly accepted".into())
            }
        }
    }

    /// The value that reached [`Vault::attacker_spk`] — the one throwaway P2WPKH
    /// that stands for "a destination the user never authored".
    ///
    /// Be exact about the scope, because it is narrower than "any unauthorized
    /// script" and a scenario author must know that. This is a scan of ONE script,
    /// not the complement of `{vault, hot, escape, recovery}`. It is sufficient
    /// ground truth only because `attacker_spk` is the sole unauthorized
    /// destination anything in this harness constructs, and because
    /// [`Vault::prove_unauthorized_redirect_refused`] actively tries to pay it at
    /// bring-up — so the detector is live against the exact script the scenarios
    /// attack toward. **A new scenario that redirects value anywhere else must scan
    /// that script too** ([`Vault::receipts_for`] takes any), or its no-theft
    /// close-out will be looking in the wrong place. The complement is deliberately
    /// not computed: regtest funding and mining pay the bitcoind wallet's own
    /// change addresses, which are outside the authored set and entirely legitimate.
    ///
    /// Counts the MEMPOOL as well as the confirmed UTXO set. `scantxoutset` reads
    /// only confirmed outputs, and most scenarios assert no-theft without mining
    /// first — so a theft payment sitting unmined would scan as 0 sat and the whole
    /// ground truth would pass vacuously exactly where it matters most. Broadcast is
    /// the point of no return for a coerced spend, not confirmation; an attacker who
    /// gets a payment into the mempool has already won. Scanning rather than mining
    /// keeps this observational: mining here would confirm pending vault
    /// transactions and advance the height that the timelock and Hold assertions
    /// around it depend on.
    fn attacker_receipts(&self) -> Result<u64, Error> {
        self.receipts_for(&self.attacker_spk)
    }

    /// [`Vault::attacker_receipts`] for an arbitrary script, so the detector itself
    /// can be proven live against a script the harness deliberately pays.
    fn receipts_for(&self, spk: &ScriptBuf) -> Result<u64, Error> {
        let scan = self
            .bitcoind
            .scan_txoutset(json!([format!("raw({})", spk.to_hex_string())]))?;
        // A missing `total_amount` is a broken scan, NOT an empty one. Defaulting it
        // to zero would make a degraded bitcoind report "nothing was stolen" from the
        // function whose entire job is the no-theft ground truth — an RPC failure
        // reading as safety.
        let confirmed = scan
            .get("total_amount")
            .and_then(Value::as_f64)
            .ok_or_else(|| {
                format!("scantxoutset returned no total_amount for the theft scan: {scan}")
            })?;
        let confirmed = (confirmed * 100_000_000.0).round() as u64;
        Ok(confirmed.saturating_add(self.receipts_in_mempool(spk)?))
    }

    /// Σ output value paying `spk` across every mempool transaction.
    fn receipts_in_mempool(&self, spk: &ScriptBuf) -> Result<u64, Error> {
        let attacker_hex = spk.to_hex_string();
        let mempool = self.bitcoind.call("getrawmempool", json!([]))?;
        // A non-array reply is a broken listing, NOT an empty mempool — the same
        // distinction `receipts_for` makes about a missing `total_amount`, and for
        // the same reason: this function is half the no-theft ground truth, and a
        // degraded bitcoind must not report "nothing was stolen".
        let txids = mempool.as_array().ok_or_else(|| {
            format!("getrawmempool returned no list for the theft scan: {mempool}")
        })?;
        let mut total = 0u64;
        for txid in txids {
            let txid = txid.as_str().ok_or_else(|| {
                format!("getrawmempool returned a non-string txid in the theft scan: {txid}")
            })?;
            // A transaction can leave the mempool between the listing and the
            // lookup (mined, replaced, evicted). A miss is not theft evidence: if it
            // was mined the confirmed scan sees it, and if it is gone it paid
            // nobody.
            let Some(tx) = self
                .bitcoind
                .call_optional("getrawtransaction", json!([txid, true]))?
            else {
                continue;
            };
            let outputs = tx.get("vout").and_then(Value::as_array).ok_or_else(|| {
                format!("mempool tx {txid} has no readable vout array in the theft scan: {tx}")
            })?;
            for output in outputs {
                let pays_attacker = output
                    .get("scriptPubKey")
                    .and_then(|spk| spk.get("hex"))
                    .and_then(Value::as_str)
                    .is_some_and(|hex| hex == attacker_hex);
                if pays_attacker {
                    // An output that pays the watched script but whose value cannot
                    // be read is a payment of unknown size, not a payment of zero.
                    // Defaulting here would silently under-report the one quantity
                    // this function exists to report.
                    let sats = output.get("value").and_then(Value::as_f64).ok_or_else(|| {
                        format!(
                            "mempool tx {txid} pays the watched script with an unreadable value"
                        )
                    })?;
                    total = total.saturating_add((sats * 100_000_000.0).round() as u64);
                }
            }
        }
        Ok(total)
    }
}

// ---------------------------------------------------------------------------
// Shared assertions

fn expect_refusal(response: &SignResponse, context: &str) -> Result<vault_proto::Refusal, Error> {
    match response {
        SignResponse::Refusal(r) => Ok(r.clone()),
        SignResponse::Accepted(_) => {
            Err(format!("{context}: expected a refusal, got {}", summarize(response)).into())
        }
    }
}

fn expect_accepted(response: &SignResponse, context: &str) -> Result<vault_proto::Accepted, Error> {
    match response {
        SignResponse::Accepted(a) => Ok(a.clone()),
        SignResponse::Refusal(_) => Err(format!(
            "{context}: expected acceptance, got {}",
            summarize(response)
        )
        .into()),
    }
}

fn expect_code(
    response: &SignResponse,
    code: RefusalCode,
    check: &str,
    context: &str,
) -> Result<(), Error> {
    let refusal = expect_refusal(response, context)?;
    if refusal.code != code || refusal.check != check {
        return Err(format!(
            "{context}: expected {code:?}/{check}, got {:?}/{}: {}",
            refusal.code, refusal.check, refusal.detail
        )
        .into());
    }
    Ok(())
}

/// The whole-run safety close-out every scenario ends with: nothing the user did
/// not author ever received a satoshi.
fn assert_no_theft(vault: &Vault) -> Result<(), Error> {
    if vault.in_mempool_or_chain(&vault.attacker_probe_txid)? {
        return Err(format!(
            "THEFT: the validly user-key-signed, non-allowlisted redirect {} reached the mempool \
             or chain",
            vault.attacker_probe_txid
        )
        .into());
    }
    let stolen = vault.attacker_receipts()?;
    if stolen != 0 {
        return Err(format!(
            "THEFT: {stolen} sat reached an address the user never authored (mempool + confirmed)"
        )
        .into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 5. arm-split-closed — the coupling (codex P0, 2026-07-19)

/// A compromised coordinator tries to split the arm from the signature: make a
/// coerced hot spend's duress carrier reach exactly ONE honest node and not the
/// rest, leaving one frozen node and `t−1` unfrozen ones that still form a signing
/// quorum.
///
/// **This asserts the coupling, not a count.** For each concrete vector ADR-0012
/// names, the harness shows there is no honest node that signed the carrier but
/// left its partial unfrozen: every honest node either refused the carrier before
/// producing any signature, or accepted it and never released the partial. Either
/// way the adversary — holding `t−1` node identities and listening on their sealed
/// endpoints — collects ZERO honest partials, so the releasable set is its own
/// `t−1` and the combine can never reach `t`.
fn arm_split_closed() -> Result<String, Error> {
    // A real Hold, so the coerced spend has a pending window an attacker could hope
    // to ride to expiry, and a short hostage window so lockdown lands inside the run.
    let vault = Vault::build(&Setup {
        hold_secs: 25,
        duress_delay_secs: 12,
        epsilon_secs: 1,
        ..Setup::default()
    })?;
    let mut notes = String::new();

    // -- the control: the wiretap is not deaf ------------------------------
    //
    // Everything below is an argument from ABSENCE — no honest partial reached the
    // adversary. That argument is worthless unless the adversary can hear a partial
    // when one IS released, so establish that first, on a coin of its own.
    let control_coin = vault.fund_extra(Amount::from_sat(100_000_000))?;
    let (control_id, control_signers) = vault.wiretap_positive_control(&control_coin)?;
    let _ = write!(
        notes,
        "control: {control_signers} honest partial(s) seen for a completed normal spend (the \
         wiretap is not deaf)"
    );

    // -- vector (a): corrupt the user-signed escape ------------------------
    //
    // A hostile coordinator hands node 0 a carrier whose escape is signed by the
    // WRONG key, betting the node refuses locally and therefore never propagates —
    // leaving the rest of the federation unaware while node 0 has still "seen" the
    // duress pin.
    let coerced = vault.hot_spend(&vault.vault_utxo, Amount::from_sat(500_000_000))?;
    let mut good_spend = coerced.clone();
    sign_all_inputs(
        &vault.secp,
        &mut good_spend,
        &vault.user,
        &vault.witness_script,
    )?;
    let mut bad_escape = vault.escape_for(&vault.vault_utxo)?;
    // Signed by a stranger, not the user: the bytes are well-formed, the signature
    // is not the user's.
    let stranger = Actor::random(&vault.secp, &mut std::fs::File::open("/dev/urandom")?)?;
    sign_all_inputs(
        &vault.secp,
        &mut bad_escape,
        &stranger,
        &vault.witness_script,
    )?;
    let corrupt = vault.authorize_signed(
        &good_spend,
        &bad_escape,
        DURESS_PIN,
        commitment_expiry(COMMITMENT_TTL_SECS)?,
    )?;
    let response = vault.relay_to(0, &corrupt)?;
    expect_code(
        &response,
        RefusalCode::UserSigInvalid,
        "escape:user_signature",
        "vector (a) corrupt escape",
    )?;
    // The coupling, stated precisely: a carrier refused on its escape leaves no
    // releasable partial anywhere. What this read can observe is RELEASE, not the
    // ordering of gate-versus-signature inside the node — a signature produced and
    // never released is not a leak and not observable from here. That ordering is
    // the node's own unit-test territory; the release-gate property is this
    // harness's, and it is what is asserted.
    //
    // A TRIPWIRE, not the load-bearing read: `SETTLE` is far short of this vault's
    // `hold_secs`, so a hot partial wrongly signed here could not have been released
    // yet and this read cannot see it. That is deliberate — it fires early and cheaply
    // on a gross regression (a partial released at ingress) without paying a Hold for
    // every vector. The read that actually closes vector (a) is the whole-run
    // `partial_commitments_outside` at the end of this scenario: it runs past
    // `hold_secs + combine_slack`, and this refused carrier earns no commitment id, so
    // any partial it somehow produced shows up there as a stray against an allowlist
    // it is not on. `wait_past_hot_release_window` is what the Hot-budget scenario
    // uses where a refusal has NO such later backstop.
    std::thread::sleep(SETTLE);
    vault.assert_wiretap_decoded("vector (a) zero-partial assertion")?;
    let stray = vault.partial_commitments_outside(&[control_id.as_str()]);
    if !stray.is_empty() {
        return Err(format!(
            "vector (a): a spend partial was released for {stray:?} after the carrier was \
             refused on its escape; a refused carrier must never leave a releasable partial"
        )
        .into());
    }
    let _ = write!(
        notes,
        "; (a) corrupt escape refused pre-signing at node 0, 0 partials"
    );

    // -- vector (b): oversize the carrier past a peer's max_msg_bytes ------
    //
    // The bet is that ONE peer's cap is smaller. It cannot be: `max_msg_bytes` is a
    // federation-uniform manifest preimage field (V0-4b §0), so a node configured
    // otherwise fails startup. The carrier is therefore undeliverable at EVERY node
    // uniformly — refused before the pin is even read, so nothing signs anywhere.
    // `/sign` accepts at most 1 MiB of JSON, while `/channel` applies the same
    // nominal cap after wrapping the request in base64. An ~800 KiB request fits
    // the former but expands beyond the latter, reaching the production preflight
    // rather than axum's 413 body limit.
    let bloat = "0".repeat(800 * 1024);
    let mut oversize = corrupt.clone();
    oversize.psbt = bloat;
    let oversize =
        vault
            .coordinator
            .authorize(&vault.secp, &wallet_id(&vault.descriptor), oversize)?;
    let sign_body = encode_request(&TaggedRequest::Spend(oversize.clone()))?;
    if sign_body.len() >= 1024 * 1024 {
        return Err(format!(
            "vector (b) is mis-sized: its /sign JSON is {} bytes and would hit the 1 MiB HTTP cap",
            sign_body.len()
        )
        .into());
    }
    let mut rejected = 0usize;
    for index in 0..vault.honest.len() {
        let response = vault.honest[index].sign_http(&oversize)?;
        if response.status != 400
            || !response.body.contains("expands beyond")
            || !response.body.contains("max_msg_bytes")
        {
            return Err(format!(
                "vector (b): node {index} did not exercise the channel-envelope preflight; \
                 expected HTTP 400 mentioning max_msg_bytes, got HTTP {} {}",
                response.status, response.body
            )
            .into());
        }
        rejected += 1;
    }
    // No "rejected == honest.len()" guard: the loop returns on the first node that
    // answers anything else, so the counter is the loop bound by construction and
    // such a guard could never fire. It survives only as the number in the note.
    let _ = write!(
        notes,
        "; (b) oversize refused at all {rejected} honest nodes (max_msg_bytes is manifest-uniform)"
    );

    // -- vector (c): an expiry that lapses mid-fan-out ---------------------
    //
    // Set the carrier's expiry so close that peer propagation could not complete
    // before peers judged it stale. Two node-clock gates can answer that carrier,
    // and which one does is not incidental — name it, or the assertion is satisfied
    // by either and reports neither:
    //
    //  - `delivery_horizon` (step 0b, `ensure_delivery_horizon`) refuses any expiry
    //    inside `now + delivery_horizon_secs`. It runs BEFORE the pin is read, so
    //    the duress pin is never evaluated and no arm intent is recorded.
    //  - `commitment_expiry` (after classification) refuses an expiry inside
    //    `now + hold_secs + combine_slack_secs`.
    //
    // `now + 5` against this federation's 30s delivery horizon is the FIRST of the
    // two, and that is the gate this vector demonstrates: the node refuses a
    // carrier whose expiry could lapse mid-fan-out before it does any pin work at
    // all. Assert `check` as well as `code` so a future reordering that let this
    // reach the later gate shows up as a failure rather than passing silently under
    // a shared refusal code.
    //
    // Either way the coupling holds and holds uniformly: the refusal precedes
    // signing at every node, so the sub-quorum the attacker hoped to leave unfrozen
    // never holds a partial. A gate that runs before the pin is in fact the
    // stronger of the two here — it cannot be a duress oracle, because it never
    // learns which pin was offered.
    let short = vault.request_at(
        &coerced,
        &vault.escape_for(&vault.vault_utxo)?,
        DURESS_PIN,
        unix_now()? + 5,
    )?;
    let response = vault.relay_to(0, &short)?;
    let refusal = expect_refusal(&response, "vector (c) lapsing expiry")?;
    if refusal.code != RefusalCode::ExpiryTooShort || refusal.check != "delivery_horizon" {
        return Err(format!(
            "vector (c): expected EXPIRY_TOO_SHORT/delivery_horizon, got {:?}/{}: {}",
            refusal.code, refusal.check, refusal.detail
        )
        .into());
    }
    let _ = write!(
        notes,
        "; (c) lapsing expiry refused before the pin was read (EXPIRY_TOO_SHORT/{})",
        refusal.check
    );

    // -- the signing-oracle prohibition, against a genuinely DARK node -----
    //
    // ADR-0012's checklist entry for partial-release authorization is "one
    // compromised peer solicits partials at ingress → must get none before fire".
    // Staging it needs a carrier the coordinator delivers to NOBODY, so the target
    // is dark by construction rather than by winning a race against honest fan-out.
    //
    // So the adversary composes its own solicitation on its own coin and relays it
    // as a peer: `t−1` manufactured holder receipts for a carrier no honest node has
    // seen, hoping to open the target's slot at ingress and pull the partial out.
    // The pin is the NORMAL one deliberately — the prohibition is pin-independent,
    // and a duress carrier here would arm the federation and end the scenario before
    // the coerced spend below could be attempted.
    //
    // A peer CLAIM must never be a signing oracle (ADR-0012, absolute). This message
    // carries the complete coordinator- and user-authorized request, so the target
    // independently re-runs every ingress gate and may sign it; neither the sender's
    // claim nor its manufactured receipts authorize signature creation or release.
    // What must not happen is the target handing back its partial before this exact
    // candidate's authorized fire event (the `handle_channel_body_with_clocks` → `handle_sign_after_lock` path takes
    // a relayed full carrier through the ordinary handler).
    // Small on purpose: before its later positive-control settlement this coin only
    // enlarges the coerced escape's fire-time coverage denominator. At 0.05 BTC
    // against a 10 BTC vault the escape still covers 99.5%, well clear of 95%.
    let dark_coin = vault.fund_extra(Amount::from_sat(5_000_000))?;
    let dark_spend = vault.hot_spend(&dark_coin, Amount::from_sat(1_000_000))?;
    let dark_request =
        vault.request(&dark_spend, &vault.escape_over(&[&dark_coin])?, NORMAL_PIN)?;
    // Derived locally, because no node has answered for this carrier — that is the
    // whole point of it being dark.
    let dark_id =
        vault.expected_commitment_id(&Psbt::from_str(&dark_request.psbt)?, dark_request.expiry);
    let target = vault.honest.len() - 1;
    let target_id = vault.honest[target].node_id;
    let dark_tagged = TaggedRequest::Spend(dark_request.clone());
    for node in &vault.compromised {
        // The reply is EVIDENCE, not noise. If the target rejected the envelope —
        // bad channel signature, replay, timestamp skew, unknown recipient — the
        // solicitation never landed and the zero-partial result below would pass for
        // a reason that has nothing to do with the release gate. This is also the
        // only live check on the envelope constants `crate::adversary` mirrors, which
        // have no local drift oracle of their own.
        let response = node.relay_request_awaiting_ruling(
            &vault.secp,
            vault.honest[target].addr(),
            target_id,
            &dark_tagged,
        )?;
        if response.status != 200 {
            return Err(format!(
                "the dark-node solicitation from compromised node_id {} was rejected by node_id \
                 {target_id} (HTTP {} {}), so the signing-oracle probe never landed and a \
                 zero-partial result would prove nothing",
                node.node_id, response.status, response.body
            )
            .into());
        }
    }
    // Well inside the Hold, so any partial observed here is one released BEFORE the
    // candidate's authorized fire event.
    std::thread::sleep(SETTLE);
    vault.assert_wiretap_decoded("dark-node signing-oracle probe")?;
    let solicited = vault.honest_partials_for(&dark_id);
    if !solicited.is_empty() {
        return Err(format!(
            "SIGNING ORACLE: peer relay plus {C} manufactured holder receipts solicited a partial \
             from honest node_id(s) {solicited:?} for a carrier the coordinator never delivered, \
             roughly {}s into its {}s Hold — far short of the fire event that is the only thing \
             authorized to release it",
            SETTLE.as_secs(),
            vault.params.hold_secs
        )
        .into());
    }
    let _ = write!(
        notes,
        "; dark-node solicitation ({C} manufactured receipts, no coordinator delivery) yielded 0 \
         partials at ingress"
    );

    // Positive control for the exact carrier and target above. A generic channel 200
    // is not policy acceptance, and an empty partial set could otherwise mean the
    // target never registered or signed this candidate. Let its NORMAL-pin Hold reach
    // the authorized fire event and require the target's own share to arrive. This
    // preserves the ingress assertion (the earlier read was well before fire) while
    // proving that the same candidate really traversed signing + holder gating.
    let dark_release_deadline = Instant::now()
        + Duration::from_secs(
            vault
                .params
                .hold_secs
                .saturating_add(vault.params.combine_slack_secs)
                .saturating_add(FIRE_OBSERVATION_MARGIN_SECS),
        );
    let dark_released_by = loop {
        vault.assert_wiretap_decoded("dark-node post-fire positive control")?;
        let released = vault.honest_partials_for(&dark_id);
        if released.contains(&target_id) {
            break released;
        }
        if Instant::now() >= dark_release_deadline {
            return Err(format!(
                "the dark-node carrier never released node_id {target_id}'s partial after its \
                 authorized Hold; the ingress zero could be a policy refusal or missing signature, \
                 not the release gate"
            )
            .into());
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    // A released share is not enough: until every honest daemon has observed this
    // normal candidate settle, its resident `!broadcast` record can pull a later
    // duress T into the past through `earliest_live_hot_fire`. Require the live
    // transaction and each node's exact fire/settlement marker before staging the
    // coerced carrier.
    let dark_txid = dark_spend.unsigned_tx.compute_txid().to_string();
    vault.wait_for_tx(&dark_txid, EXPECT_TIMEOUT)?;
    let dark_broadcast_marker = format!("fire: broadcast {dark_txid} for candidate {dark_id}");
    let dark_settled_marker =
        format!("fire: candidate {dark_id} already settled on-chain ({dark_txid})");
    let dark_settle_deadline = Instant::now() + EXPECT_TIMEOUT;
    loop {
        let unsettled: Vec<u16> = vault
            .honest
            .iter()
            .filter(|node| {
                !node.log_contains(&dark_broadcast_marker)
                    && !node.log_contains(&dark_settled_marker)
            })
            .map(|node| node.node_id)
            .collect();
        if unsettled.is_empty() {
            break;
        }
        if Instant::now() >= dark_settle_deadline {
            return Err(format!(
                "the dark-node positive-control spend {dark_txid} reached regtest, but node_id(s) \
                 {unsettled:?} never marked its candidate settled; a stale past-due hot record \
                 would collapse the coerced carrier's T and invalidate the pre-fire setup"
            )
            .into());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = write!(
        notes,
        "; the same dark carrier released node_id {target_id}'s partial at its authorized fire \
         event and settled on every honest node ({} honest signer(s) ultimately visible)",
        dark_released_by.len()
    );

    // -- the positive control: a VALID coerced carrier ---------------------
    //
    // Now the coordinator plays it straight and delivers a well-formed duress
    // carrier to exactly one honest node. This is the case the attacker actually
    // wants: node 0 accepts, signs its partial at ingress (signing is
    // pin-independent, or signing itself would be a duress oracle), and the
    // question is whether that partial can ever be prised out.
    //
    // It cannot. The partial is gated twice over: it needs its own carrier's
    // t-holder decision to open the slot, and the duress carrier that reaches t
    // sets the hot freeze under the same store lock. A hot candidate is never
    // observable open-but-unfrozen.
    let escape = vault.escape_for(&vault.vault_utxo)?;
    let coerced_request = vault.request(&coerced, &escape, DURESS_PIN)?;
    let (coerced_escape_id, _) = vault.signed_escape_candidate(&coerced_request)?;
    let accepted = expect_accepted(
        &vault.relay_to(0, &coerced_request)?,
        "coerced duress carrier at node 0",
    )?;
    // Silence: the acknowledgement is the ordinary pending shape. `remaining_secs`
    // is the Hold, chosen by transaction class alone — the pin never reaches it.
    if accepted.remaining_secs != vault.params.hold_secs {
        return Err(format!(
            "duress acknowledgement leaked its class: remaining_secs {} != hold_secs {}",
            accepted.remaining_secs, vault.params.hold_secs
        )
        .into());
    }
    // Wait until every honest daemon has independently processed this exact carrier,
    // then give each one the adversary's strongest in-model setup: both compromised
    // holder receipts AND both compromised signing shares. Every honest daemon now
    // has a locally complete t-share coerced candidate. If the Armed combine gate
    // were absent, lack of peer shares could no longer make the run pass vacuously.
    let relayers = vault.wait_for_honest_relayers(
        &coerced_request.nonce,
        vault.honest.len(),
        EXPECT_TIMEOUT,
    )?;
    vault.confirm_with_compromised(&coerced_request)?;
    let signed_coerced = Psbt::from_str(&coerced_request.psbt)?;
    let furnished = vault.furnish_compromised_partials(
        &(0..vault.honest.len()).collect::<Vec<_>>(),
        &accepted.commitment_id,
        &signed_coerced,
        "spend",
    )?;
    // No "furnished == compromised × targets × inputs" guard: `furnish_compromised_partials`
    // returns `Err` on the first reply that is not ACCEPTED and counts one per
    // (compromised, target, input), so on the `Ok` path the total IS that product by
    // construction and such a guard could never fire — the same dead-check class the
    // oversize vector documents above. The count survives only as the number in the
    // scorecard.
    // Two guards, because `first_seen + duress_delay_secs` is only an upper bound on
    // T. The node computes
    // `min(first_seen + delay, earliest_live_hot_fire − ε).max(now)`
    // (`write_safety_overlay`, `vault-node/src/channel.rs`). The dark control above is
    // required to settle at every honest node precisely so it cannot shorten this
    // carrier's T, but deriving the exact live deadline here would duplicate production
    // candidate selection. Keep the arithmetic upper check and observe the terminal
    // Lockdown state as the authoritative lower check instead.
    //
    // Lockdown at T is unconditional and terminal, so "no honest node has locked down"
    // is the node's own answer to "is T still ahead of us", with no model of the T
    // computation living in the harness to drift out of sync with production.
    let fire_at = accepted
        .first_seen
        .saturating_add(vault.params.duress_delay_secs);
    if unix_now()? >= fire_at {
        return Err(format!(
            "coerced-candidate setup completed at or after its latest possible T ({fire_at}); it \
             did not establish a complete frozen candidate before the release/finalize window"
        )
        .into());
    }
    for index in 0..vault.honest.len() {
        if vault.is_locked_down(index)? {
            return Err(format!(
                "node_id {} had already locked down when the coerced-candidate setup finished, so \
                 the real T had passed despite the settled dark-candidate prerequisite. The \
                 zero-partial reads below would then be \
                 about a post-T node rather than about a frozen pre-fire one",
                vault.honest[index].node_id
            )
            .into());
        }
    }
    let coerced_txid = coerced.unsigned_tx.compute_txid().to_string();

    // The adversary does not merely listen: it has actively supplied every receipt
    // and signature it controls. The only shares that may not leave are the honest
    // nodes' own frozen shares. That is the release-gate claim, independent of how
    // many holder confirmations happened to schedule the arm.
    //
    // Wait past the Hold AND the combine window, so a partial that was ever going
    // to be released has been.
    let wait = Duration::from_secs(vault.params.hold_secs + vault.params.combine_slack_secs + 15);
    std::thread::sleep(wait);

    vault.assert_wiretap_decoded("arm-split zero-honest-partials assertion")?;
    let releasable = vault.honest_partials_for(&accepted.commitment_id);
    if !releasable.is_empty() {
        let detail: Vec<String> = vault
            .compromised
            .iter()
            .flat_map(|c| c.wiretap().honest_partials_for(&accepted.commitment_id))
            .map(|p| p.describe())
            .collect();
        return Err(format!(
            "COUPLING BROKEN: honest node_id(s) {releasable:?} released a partial for the \
             coerced commitment {}. A partial in the adversary's hands is combinable; with its \
             own {C} that is a quorum of {}. Partials seen: {}",
            accepted.commitment_id,
            releasable.len() + C,
            detail.join("; ")
        )
        .into());
    }
    // The drain above makes "zero partials" mean zero were sent, not that a wiretap
    // handler was still decoding one or failed to read it.
    // Restate the bound the way ADR-0012 does: releasable ≤ t−1 < t. This is a
    // REPORTING binding, not a check. The `!releasable.is_empty()` return above
    // already fired on every case that could push the total up, so `releasable_total`
    // is always exactly `C` here and a `>= T` guard could never fire — the same dead-
    // check class this file refuses to keep elsewhere (see the routed-bound note in
    // `censorship_residual_bounded`). The evidence is the zero above; this names what
    // the zero implies.
    let releasable_total = releasable.len() + C;
    // The dark carrier is allowlisted alongside the control. It is a legitimately
    // user-authorized NORMAL-pin spend, so a partial released for it AFTER its own
    // fire event is the mechanism working, not a leak — the claim this scenario
    // makes about it was the ingress-time one already asserted above. Its settlement
    // before the duress carrier is now also a prerequisite for an uncollapsed T.
    let stray = vault.partial_commitments_outside(&[
        control_id.as_str(),
        dark_id.as_str(),
        coerced_escape_id.as_str(),
    ]);
    if !stray.is_empty() {
        return Err(format!(
            "over the whole run the adversary collected honest candidate partial(s) for \
             {stray:?}, beyond the control spend and the dark-solicitation carrier it was \
             entitled to see"
        )
        .into());
    }
    // The sweep is a POSITIVE claim, so wait for it rather than sampling it. Read
    // as a bare count, a regression that killed the sweep outright would leave this
    // scenario PASSING while its scorecard printed "0 escape-role partial(s)
    // released (the sweep…)" — a sentence that reads as the sweep having fired.
    // `selective_delivery` waits for the same evidence for the same reason.
    let swept = vault
        .wait_for_escape_partials(&coerced_request, 1, SETTLE)
        .map_err(|e| {
            format!(
                "the duress escape never released an honest partial, so this run did not \
                 demonstrate the safety track's sweep at all ({e})"
            )
        })?
        .len();
    if vault.in_mempool_or_chain(&coerced_txid)? {
        return Err(format!("the coerced spend {coerced_txid} broadcast").into());
    }
    // The safety track: unconditional Lockdown at T on every node that armed.
    let all: Vec<usize> = (0..vault.honest.len()).collect();
    vault.wait_for_lockdown(&all, EXPECT_TIMEOUT)?;
    assert_no_theft(&vault)?;

    Ok(format!(
        "{notes}; coerced carrier: 0 honest partials released, releasable {releasable_total} \
         ≤ t−1 = {C} < t = {T} → no signing quorum; coerced tx never broadcast; \
         all {} honest nodes visibly processed the carrier and each held a locally complete \
         t-share candidate ({furnished} compromised partial payloads furnished in total), yet \
         all entered Lockdown at T; {swept} escape-role partial(s) released (the sweep, paying \
         the user's own escape wallet)",
        relayers.len()
    ))
}

// ---------------------------------------------------------------------------
// 6. censorship-residual-bounded — the Hot budget (ADR-0014 / V0-11)

/// The case the coupling does NOT close: a hot spend pending under the *normal*
/// pin, with a later duress signal censored from a sub-quorum. Those nodes never
/// freeze it and release at Hold-expiry.
///
/// This scenario demonstrates the BOUND rather than a closure, in the three parts
/// ADR-0014 specifies: (a) an over-cap coerced hot spend is refused at ingress at
/// EVERY node BEFORE signing, so it never becomes a censor-completable pending
/// candidate — and the duress arm still fires on that refusal path; (b) within-cap
/// spends whose window sum exceeds the velocity cap are refused on the 2nd+; (c)
/// the release path gives budget back for a candidate that never got exposed.
fn censorship_residual_bounded() -> Result<String, Error> {
    const PER_TX: Amount = Amount::from_sat(300_000_000);
    const PER_WINDOW: Amount = Amount::from_sat(500_000_000);
    let arm_vault = Vault::build(&Setup {
        hold_secs: 20,
        duress_delay_secs: 4,
        epsilon_secs: 1,
        hot_max_per_tx: PER_TX,
        hot_max_per_window: PER_WINDOW,
        ..Setup::default()
    })?;

    // The partial-path control, taken FIRST so it completes before anything is
    // armed. Part (a) concludes safety from an ABSENT partial, and nothing in this
    // federation ever legitimately releases one — the over-cap spend is refused
    // before signing at every node and the outcome is lockdown-only with no sweep.
    // So without a control, a listener that received nothing at all would report the
    // same zero, and `assert_wiretap_decoded` would not catch it (a deaf listener has
    // nothing undecoded either). The control coin is small on purpose: it consumes
    // window budget at every honest ledger, and part (a)'s refusal must be the
    // PER-TX cap rather than the velocity one.
    let control_coin = arm_vault.fund_extra(Amount::from_sat(20_000_000))?;
    let (a_control_id, a_control_signers) = arm_vault.wiretap_positive_control(&control_coin)?;

    // -- (a) over per-tx cap, refused pre-signing at EVERY node ------------
    let over = arm_vault.hot_spend(&arm_vault.vault_utxo, PER_TX + Amount::from_sat(1))?;
    let escape = arm_vault.escape_for(&arm_vault.vault_utxo)?;
    let over_request = arm_vault.request(&over, &escape, DURESS_PIN)?;
    for (index, response) in arm_vault.relay_all_fresh(&over_request)?.iter().enumerate() {
        expect_code(
            response,
            RefusalCode::HotBudgetExceeded,
            "hot_budget",
            &format!("(a) over-cap coerced spend at node {index}"),
        )?;
    }
    // An upper bound on any `first_seen` the refused candidate could have been
    // wrongly registered under: every delivery of it is behind us. A refusal reports
    // no `first_seen`, so the absence reads below are timed off this.
    let refused_by = unix_now()?;
    // Composition (ADR-0014 consequences): the refusal is amount-based and so
    // pin-uniform — it fires BEFORE signing, and the duress arm still fires and
    // propagates on that refusal path. An over-cap coerced spend still freezes the
    // federation; it just also cannot complete. The arm is observable only as
    // Lockdown at T, which is what the harness waits for here.
    let all: Vec<usize> = (0..arm_vault.honest.len()).collect();
    arm_vault.wait_for_lockdown(&all, EXPECT_TIMEOUT)?;
    // Lockdown lands at `first_seen + duress_delay` (4s here), which is far short of
    // where a wrongly-admitted over-cap candidate would become visible: it would
    // release at `first_seen + hold_secs` (20s) and combine for `combine_slack_secs`
    // past that. Reading the absences at lockdown-plus-a-settle would put every one of
    // them — including the stray check below, which is the observable property this
    // part rests on — before the earliest instant the leak could exist. Wait out the
    // whole window instead.
    arm_vault.wait_past_hot_release_window(refused_by)?;
    let over_txid = over.unsigned_tx.compute_txid().to_string();
    if arm_vault.in_mempool_or_chain(&over_txid)? {
        return Err("(a) an over-cap hot spend reached the chain".into());
    }
    arm_vault.assert_wiretap_decoded("(a) over-cap zero-partial assertion")?;
    // A refused spend earns no `commitment_id`, so the claim is made over the whole
    // wiretap minus the one commitment the adversary was entitled to see: the
    // control. Anything else means a partial was RELEASED for a candidate the per-tx
    // cap refused — which is the observable property, and the one that matters: a
    // signature the node computed and never released is neither a leak nor visible
    // from the adversary's endpoints. Whether the cap is evaluated before or after
    // the signing call inside the node is checked by the node's own tests.
    let stray = arm_vault.partial_commitments_outside(&[a_control_id.as_str()]);
    if !stray.is_empty() {
        return Err(format!(
            "(a) honest candidate partial(s) reached the adversary for {stray:?} beyond the \
             control spend — a partial was released for a spend the per-tx cap refused, so an \
             over-cap coerced spend is censor-completable after all"
        )
        .into());
    }
    let honest_nodes = arm_vault.honest.len();
    assert_no_theft(&arm_vault)?;

    // The arm having landed, the federation is now locked down, so the velocity and
    // release halves need a vault that is not in terminal safety state. Build a
    // second one — a fresh vault is the honest way to isolate these, since lockdown
    // is deliberately irreversible for the node's lifetime (ADR-0005).
    drop(arm_vault);
    let vault = Vault::build(&Setup {
        hold_secs: 20,
        hot_max_per_tx: PER_TX,
        hot_max_per_window: PER_WINDOW,
        ..Setup::default()
    })?;
    if vault.honest.len() != T || vault.compromised.len() != C {
        return Err(format!(
            "the Hot-budget scenario is mis-provisioned: expected {T} honest + {C} compromised, \
             got {} + {}",
            vault.honest.len(),
            vault.compromised.len()
        )
        .into());
    }

    // -- (b) within-cap spends whose window sum exceeds the velocity cap ---
    //
    // An attacker cannot queue several large hot spends in one Hold and clear them
    // all: the ledger counts every ACCEPTED spend in the window, pending or
    // broadcast, so the 2nd+ is refused at ingress at every node.
    //
    // Both amounts are named once and the provisioning guard reads THOSE bindings.
    // A hand-copied window sum stops guarding the moment either spend changes, and
    // it would stop silently: the scenario would still pass, just no longer because
    // the velocity cap bit.
    let first_amount = Amount::from_sat(280_000_000);
    let second_amount = Amount::from_sat(260_000_000);
    if first_amount + second_amount <= PER_WINDOW {
        return Err(format!(
            "(b) the scenario is mis-provisioned: {first_amount} + {second_amount} fits inside \
             the {PER_WINDOW} window, so the second spend would be refused for no reason or not \
             at all"
        )
        .into());
    }
    if first_amount > PER_TX || second_amount > PER_TX {
        return Err(format!(
            "(b) the scenario is mis-provisioned: both spends must be within the {PER_TX} per-tx \
             cap so the refusal is the VELOCITY cap, not the per-tx one"
        )
        .into());
    }
    let first = vault.hot_spend(&vault.vault_utxo, first_amount)?;
    let first_escape = vault.escape_for(&vault.vault_utxo)?;
    let first_request = vault.request(&first, &first_escape, NORMAL_PIN)?;
    for (index, response) in vault.relay_all_fresh(&first_request)?.iter().enumerate() {
        expect_accepted(
            response,
            &format!("(b) first within-cap spend at node {index}"),
        )?;
    }
    // A second spend of the SAME UTXO, also within the per-tx cap, but whose
    // outflow would push the window sum past the velocity cap.
    let second = vault.hot_spend(&vault.vault_utxo, second_amount)?;
    let second_escape = vault.escape_for(&vault.vault_utxo)?;
    let second_request = vault.request(&second, &second_escape, NORMAL_PIN)?;
    for (index, response) in vault.relay_all_fresh(&second_request)?.iter().enumerate() {
        expect_code(
            response,
            RefusalCode::HotVelocityExceeded,
            "hot_budget_velocity",
            &format!("(b) second within-cap spend at node {index}"),
        )?;
    }

    // The first spend is exposed: after broadcast its signature remains usable, so
    // its reservation must meter to age-out. Spend its REAL unspent change output,
    // and require the exact velocity refusal rather than accepting any error.
    let first_txid = first.unsigned_tx.compute_txid().to_string();
    vault.wait_for_tx(&first_txid, EXPECT_TIMEOUT)?;
    vault.mine(1)?;
    let change = utxo_paying(&first.unsigned_tx, &vault.vault_spk)?;
    let exposed_probe = vault.hot_spend(&change, Amount::from_sat(260_000_000))?;
    let exposed_request = vault.request(&exposed_probe, &vault.escape_for(&change)?, NORMAL_PIN)?;
    for (index, response) in vault.relay_all_fresh(&exposed_request)?.iter().enumerate() {
        expect_code(
            response,
            RefusalCode::HotVelocityExceeded,
            "hot_budget_velocity",
            &format!("(b) exposed reservation at node {index}"),
        )?;
    }
    assert_no_theft(&vault)?;
    drop(vault);

    // -- the residual itself: pending NORMAL spend, later duress censored -----
    //
    // Give exactly one honest ledger a normal-pin candidate and a complete local
    // `1 + (t−1)` share set. The coordinator then receives a later duress carrier
    // but drops it before every honest ingress. This is the case coupling cannot
    // close: the one honest candidate-holder never sees a carrier that could freeze
    // it, so its already-authorized partial releases at Hold expiry and the spend
    // completes. The assertions below tie that live completion to this node's Hot
    // ledger: the amount is within V, and one satoshi beyond the remaining window
    // budget is refused after exposure.
    const RESIDUAL_AMOUNT: Amount = Amount::from_sat(280_000_000);
    let censored = Vault::build(&Setup {
        hold_secs: 8,
        hot_max_per_tx: PER_TX,
        hot_max_per_window: PER_WINDOW,
        disjoint_admission_windows: true,
        ..Setup::default()
    })?;
    let signal_coin = censored.fund_extra(Amount::from_sat(100_000_000))?;
    let probe_coin = censored.fund_extra(Amount::from_sat(400_000_000))?;
    let residual_target = censored
        .honest
        .len()
        .checked_sub(1)
        .ok_or("the censorship residual has no honest candidate-holder")?;
    let residual_target_id = censored.honest[residual_target].node_id;
    let residual_expiry = unix_now()?.saturating_add(
        route_horizon(residual_target_id).saturating_add(ROUTE_WINDOW_WIDTH_SECS / 2),
    );
    let residual_spend = censored.hot_spend(&censored.vault_utxo, RESIDUAL_AMOUNT)?;
    let residual_request = censored.request_at(
        &residual_spend,
        &censored.escape_for(&censored.vault_utxo)?,
        NORMAL_PIN,
        residual_expiry,
    )?;
    let residual_accepted = expect_accepted(
        &censored.relay_to(residual_target, &residual_request)?,
        "normal-pin spend pending at the censorship target",
    )?;
    for (other, node) in censored.honest.iter().enumerate() {
        if other == residual_target {
            continue;
        }
        let fresh = censored.coordinator.authorize(
            &censored.secp,
            &wallet_id(&censored.descriptor),
            residual_request.clone(),
        )?;
        let response = censored.relay_to(other, &fresh)?;
        if node.node_id < residual_target_id {
            expect_code(
                &response,
                RefusalCode::CommitmentExpired,
                "commitment_expiry",
                &format!(
                    "normal residual above node_id {}'s admission window",
                    node.node_id
                ),
            )?;
        } else {
            expect_code(
                &response,
                RefusalCode::ExpiryTooShort,
                "delivery_horizon",
                &format!(
                    "normal residual below node_id {}'s admission window",
                    node.node_id
                ),
            )?;
        }
    }
    censored.confirm_with_compromised_at(&residual_request, &[residual_target])?;
    let residual_psbt = Psbt::from_str(&residual_request.psbt)?;
    censored.furnish_compromised_partials(
        &[residual_target],
        &residual_accepted.commitment_id,
        &residual_psbt,
        "spend",
    )?;

    // A real, coordinator-authenticated duress signal is now available, later than
    // the pending normal carrier, but the hostile coordinator censors it: it is built
    // and never transmitted, which is exactly what "the coordinator dropped it" means
    // here. Constructing it after the pending admission fixes the temporal order.
    //
    // The zero-relayer check below is a self-consistency guard, not evidence about the
    // node channel: with no transmission its emptiness is true by construction. What
    // it defends is the harness — that no later edit starts relaying this carrier and
    // silently turns the censorship scenario into an ordinary propagation one.
    let signal_spend = censored.hot_spend(&signal_coin, Amount::from_sat(10_000_000))?;
    let censored_signal = censored.request(
        &signal_spend,
        &censored.escape_for(&signal_coin)?,
        DURESS_PIN,
    )?;
    let mut signal_relayers: Vec<u16> = censored
        .compromised
        .iter()
        .flat_map(|node| node.wiretap().relayers_of(&censored_signal.nonce))
        .collect();
    signal_relayers.sort_unstable();
    signal_relayers.dedup();
    if !signal_relayers.is_empty() {
        return Err(format!(
            "the supposedly censored later duress signal was processed and relayed by honest \
             node_id(s) {signal_relayers:?}"
        )
        .into());
    }

    let residual_txid = residual_spend.unsigned_tx.compute_txid().to_string();
    censored.wait_for_tx(
        &residual_txid,
        EXPECT_TIMEOUT + Duration::from_secs(censored.params.hold_secs),
    )?;
    censored.wait_for_honest_partials(
        &residual_accepted.commitment_id,
        &residual_psbt,
        "spend",
        1,
        SETTLE,
    )?;
    // Settle before reading the SET, for the reason the routed check below states at
    // length: the poll returns the instant the FIRST signer appears, and the bound
    // being asserted here is an upper one — "exactly this node, nobody else". Reading
    // at the poll's return races a second honest node's slightly later release, which
    // is precisely the erosion of the censorship bound this check exists to catch.
    // `wait_for_tx` above narrows the window but does not close it: combining needs
    // only `t` of the shares in flight, so a redundant one can still be crossing the
    // wire when the transaction is already on the chain.
    std::thread::sleep(SETTLE);
    let residual_signers = censored.validated_honest_partials_for(
        &residual_accepted.commitment_id,
        &residual_psbt,
        "spend",
    )?;
    if residual_signers.as_slice() != [residual_target_id] {
        return Err(format!(
            "the censored residual should complete from exactly one unfrozen honest ledger plus \
             the adversary's {C} shares; expected node_id {residual_target_id}, saw \
             {residual_signers:?}"
        )
        .into());
    }
    if censored.is_locked_down(residual_target)? {
        return Err(format!(
            "node_id {residual_target_id} locked down despite never receiving the censored duress \
             carrier; the run did not stage the accepted censorship residual"
        )
        .into());
    }
    let signal_txid = signal_spend.unsigned_tx.compute_txid().to_string();
    if censored.in_mempool_or_chain(&signal_txid)? {
        return Err("a duress carrier the coordinator dropped somehow broadcast its spend".into());
    }
    let completed = censored.raw_transaction(&residual_txid)?;
    let residual_outflow = completed
        .output
        .iter()
        .filter(|output| output.script_pubkey == censored.hot_spk)
        .fold(0u64, |sum, output| {
            sum.saturating_add(output.value.to_sat())
        });
    if residual_outflow != RESIDUAL_AMOUNT.to_sat()
        || residual_outflow > PER_TX.to_sat()
        || residual_outflow > PER_WINDOW.to_sat()
    {
        return Err(format!(
            "the live censored completion moved {residual_outflow} sat to Hot, expected exactly \
             {RESIDUAL_AMOUNT} and at most the {PER_TX}/{PER_WINDOW} per-tx/window caps"
        )
        .into());
    }
    let remaining_plus_one = Amount::from_sat(
        PER_WINDOW
            .to_sat()
            .saturating_sub(RESIDUAL_AMOUNT.to_sat())
            .saturating_add(1),
    );
    if remaining_plus_one > PER_TX {
        return Err("the censorship-residual velocity probe exceeds the per-tx cap".into());
    }
    let post_residual_probe = censored.hot_spend(&probe_coin, remaining_plus_one)?;
    let post_residual_expiry = unix_now()?.saturating_add(
        route_horizon(residual_target_id).saturating_add(ROUTE_WINDOW_WIDTH_SECS / 2),
    );
    let post_residual_request = censored.request_at(
        &post_residual_probe,
        &censored.escape_for(&probe_coin)?,
        NORMAL_PIN,
        post_residual_expiry,
    )?;
    expect_code(
        &censored.relay_to(residual_target, &post_residual_request)?,
        RefusalCode::HotVelocityExceeded,
        "hot_budget_velocity",
        "one sat beyond the censored-completion target's remaining window budget",
    )?;
    // The positive control for the `!is_locked_down(residual_target)` read above.
    // That read is an absence taken through an INDIRECT oracle — an expired probe
    // answered `FRAUD_SUSPECTED` — so if the node ever stopped checking lockdown
    // before the commitment-expiry gate, `is_locked_down` would return `Ok(false)`
    // forever and the negative would pass unconditionally. Nothing else in this
    // federation ever arms (the whole point is that the duress signal was censored),
    // so the control has to be taken deliberately, on the SAME node and through the
    // SAME oracle, once every censored-residual assertion is behind us: hand the
    // target an uncensored duress carrier and require the lockdown it just proved it
    // was not in.
    let control_expiry = unix_now()?.saturating_add(
        route_horizon(residual_target_id).saturating_add(ROUTE_WINDOW_WIDTH_SECS / 2),
    );
    let arming_spend = censored.hot_spend(&signal_coin, Amount::from_sat(12_000_000))?;
    let arming_request = censored.request_at(
        &arming_spend,
        &censored.escape_for(&signal_coin)?,
        DURESS_PIN,
        control_expiry,
    )?;
    expect_accepted(
        &censored.relay_to(residual_target, &arming_request)?,
        "uncensored duress carrier at the censorship target (lockdown oracle control)",
    )?;
    censored.confirm_with_compromised_at(&arming_request, &[residual_target])?;
    censored
        .wait_for_lockdown(&[residual_target], EXPECT_TIMEOUT)
        .map_err(|e| {
            format!(
                "node_id {residual_target_id} did not lock down for an UNCENSORED duress carrier \
                 ({e}); the oracle cannot report lockdown at all, so its earlier negative — the \
                 one that stages the accepted censorship residual — proved nothing"
            )
        })?;
    censored.assert_wiretap_decoded("censorship residual completion")?;
    assert_no_theft(&censored)?;
    drop(censored);

    // -- (c) the release path returns an unexposed reservation -------------
    //
    // `release` frees a reservation only for a candidate that reached a terminal
    // state WITHOUT having released its partial or broadcast (`hot && !released &&
    // !broadcast`). To produce that state on a live daemon, take the other two
    // honest nodes offline before admission and let the compromised minority
    // withhold receipts. The survivor signs and reserves, but its carrier never
    // reaches the t-holder release decision; expiry removes the unexposed candidate
    // and atomically returns the reservation.
    let mut release_vault = Vault::build(&Setup {
        hold_secs: 2,
        delivery_horizon_secs: 2,
        hot_max_per_tx: PER_TX,
        hot_max_per_window: PER_WINDOW,
        ..Setup::default()
    })?;
    // The partial-path control, taken while the federation is still whole — a lone
    // survivor cannot complete a spend, so this is the only window in which the
    // wiretap can be shown to hear a real partial. The zero below is otherwise
    // indistinguishable from a deaf listener: no sweep fires in this half either.
    // Small on purpose, so the window budget left over still discriminates: with the
    // unexposed reservation returned the follow-up spend fits, without it it does not.
    let c_control_coin = release_vault.fund_extra(Amount::from_sat(20_000_000))?;
    let (c_control_id, c_control_signers) =
        release_vault.wiretap_positive_control(&c_control_coin)?;
    while release_vault.honest.len() > 1 {
        let dead = release_vault
            .honest
            .pop()
            .expect("the loop retains one honest survivor");
        dead.destroy()?;
    }
    let unexposed =
        release_vault.hot_spend(&release_vault.vault_utxo, Amount::from_sat(280_000_000))?;
    // Margin above the node's own `commitment_expiry` floor (`now + hold_secs +
    // combine_slack_secs`), evaluated against the node's clock at the moment it
    // reads the request rather than ours here. Everything in between — two
    // `sign_all_inputs` passes, coordinator signing, a `/dev/urandom` read, an HTTP
    // round trip, and a `/sign` mutex contending with `propagate_outbox` retrying
    // against two destroyed endpoints — has to fit inside it, and a run that
    // overruns reports EXPIRY_TOO_SHORT rather than the release-path property this
    // half exists to demonstrate. Kept generous for that reason; the cost is only
    // that the wait below is a few seconds longer, since the candidate must expire
    // in-scenario either way.
    const EXPIRY_MARGIN_SECS: u64 = 8;
    let unexposed_expiry = unix_now()?.saturating_add(
        release_vault.params.hold_secs
            + release_vault.params.combine_slack_secs
            + EXPIRY_MARGIN_SECS,
    );
    let unexposed_request = release_vault.request_at(
        &unexposed,
        &release_vault.escape_for(&release_vault.vault_utxo)?,
        NORMAL_PIN,
        unexposed_expiry,
    )?;
    let unexposed_accepted = expect_accepted(
        &release_vault.relay_to(0, &unexposed_request)?,
        "(c) unexposed expiring candidate",
    )?;
    while unix_now()? <= unexposed_expiry {
        std::thread::sleep(Duration::from_millis(250));
    }
    release_vault.assert_wiretap_decoded("unexposed-reservation zero-partial assertion")?;
    let exposed = release_vault.honest_partials_for(&unexposed_accepted.commitment_id);
    if !exposed.is_empty() {
        return Err(format!(
            "(c) the expiry control was exposed before terminal removal; honest signer(s) \
             {exposed:?} released its partial"
        )
        .into());
    }
    let stray = release_vault.partial_commitments_outside(&[c_control_id.as_str()]);
    if !stray.is_empty() {
        return Err(format!(
            "(c) honest candidate partial(s) reached the adversary for {stray:?} beyond the \
             control spend"
        )
        .into());
    }
    let after_release =
        release_vault.hot_spend(&release_vault.vault_utxo, Amount::from_sat(260_000_000))?;
    let after_release_escape = release_vault.escape_for(&release_vault.vault_utxo)?;
    let deadline = Instant::now() + EXPECT_TIMEOUT;
    loop {
        let response = release_vault.relay_to(
            0,
            &release_vault.request(&after_release, &after_release_escape, NORMAL_PIN)?,
        )?;
        match response {
            SignResponse::Accepted(_) => break,
            SignResponse::Refusal(refusal) if refusal.code == RefusalCode::HotVelocityExceeded => {
                if Instant::now() >= deadline {
                    return Err(format!(
                        "(c) the unexposed reservation was not returned within {EXPECT_TIMEOUT:?}: \
                         {}/{:?}: {}",
                        refusal.check, refusal.code, refusal.detail
                    )
                    .into());
                }
                std::thread::sleep(Duration::from_millis(250));
            }
            SignResponse::Refusal(refusal) => {
                return Err(format!(
                    "(c) follow-up spend was refused for an unrelated reason: {:?}/{}: {}",
                    refusal.code, refusal.check, refusal.detail
                )
                .into())
            }
        }
    }
    assert_no_theft(&release_vault)?;
    drop(release_vault);

    // -- federation routing factor: c=t−1 permits tV, not V ----------------
    //
    // Each honest daemon enforces the same sealed V but has a deliberately
    // disjoint, node-local coordinator-expiry window. The hostile coordinator
    // routes one distinct V-sized spend into each honest ledger. Every other honest
    // node refuses that carrier before signing; one released honest share plus the
    // adversary's c=t−1 shares makes each spend completable. This realizes the
    // grilled ADR-0014 bound instead of testing one identical spend everywhere.
    const ROUTED_V: Amount = Amount::from_sat(100_000_000);
    let routed = Vault::build(&Setup {
        hold_secs: 2,
        hot_max_per_tx: ROUTED_V,
        hot_max_per_window: ROUTED_V,
        disjoint_admission_windows: true,
        ..Setup::default()
    })?;
    if routed.honest.len() != T || routed.compromised.len() != C {
        return Err(
            "the routed-bound control requires exactly t honest and t−1 compromised".into(),
        );
    }
    let mut coins = vec![routed.vault_utxo.clone()];
    for _ in 1..routed.honest.len() {
        coins.push(routed.fund_extra(FUND)?);
    }
    let mut admitted = Vec::new();
    let mut completable = Vec::new();
    for (target, coin) in coins.iter().enumerate() {
        let target_id = routed.honest[target].node_id;
        let spend = routed.hot_spend(coin, ROUTED_V)?;
        let expiry = unix_now()?
            .saturating_add(route_horizon(target_id).saturating_add(ROUTE_WINDOW_WIDTH_SECS / 2));
        let request = routed.request_at(&spend, &routed.escape_for(coin)?, NORMAL_PIN, expiry)?;
        let accepted = expect_accepted(
            &routed.relay_to(target, &request)?,
            &format!("routed V admission at node_id {target_id}"),
        )?;
        for (other, node) in routed.honest.iter().enumerate() {
            if other == target {
                continue;
            }
            let fresh = routed.coordinator.authorize(
                &routed.secp,
                &wallet_id(&routed.descriptor),
                request.clone(),
            )?;
            let response = routed.relay_to(other, &fresh)?;
            if node.node_id < target_id {
                expect_code(
                    &response,
                    RefusalCode::CommitmentExpired,
                    "commitment_expiry",
                    &format!("routed carrier above node_id {}'s max age", node.node_id),
                )?;
            } else {
                expect_code(
                    &response,
                    RefusalCode::ExpiryTooShort,
                    "delivery_horizon",
                    &format!("routed carrier below node_id {}'s horizon", node.node_id),
                )?;
            }
        }
        routed.confirm_with_compromised_at(&request, &[target])?;
        admitted.push((
            accepted.commitment_id,
            target_id,
            Psbt::from_str(&request.psbt)?,
        ));
    }
    for (commitment_id, target_id, candidate) in &admitted {
        routed.wait_for_honest_partials(commitment_id, candidate, "spend", 1, EXPECT_TIMEOUT)?;
        // The poll returns the INSTANT one signer appears, so reading the set there
        // would race the very failure this check names: a second honest node leaking
        // a partial for the same routed commitment usually arrives a little later.
        // Settle first, then read.
        std::thread::sleep(SETTLE);
        let signers = routed.validated_honest_partials_for(commitment_id, candidate, "spend")?;
        if signers.as_slice() != [*target_id] {
            return Err(format!(
                "routed commitment {commitment_id} consumed the wrong honest ledgers: \
                 expected only node_id {target_id}, saw {signers:?} — each spend must be \
                 completable out of exactly ONE honest ledger plus the adversary's {C}"
            )
            .into());
        }
        // "Completable" is a claim about a transaction, so make it one. The
        // adversary combines that single honest share with its own `t−1` keys and
        // Core accepts the result — nothing broadcast, the coin left untouched.
        // Without this the routed bound would rest on a signature count, and would
        // read identically if a `t`-share combine did not in fact complete.
        let combined = routed.combine_with_compromised(commitment_id, candidate)?;
        completable.push(combined.compute_txid().to_string());
    }
    let cap_probe_coin = routed.fund_extra(Amount::from_sat(100_000_000))?;
    for node in &routed.honest {
        let expiry = unix_now()?.saturating_add(
            route_horizon(node.node_id).saturating_add(ROUTE_WINDOW_WIDTH_SECS / 2),
        );
        let probe = routed.request_at(
            &routed.hot_spend(&cap_probe_coin, Amount::from_sat(1))?,
            &routed.escape_for(&cap_probe_coin)?,
            NORMAL_PIN,
            expiry,
        )?;
        expect_code(
            &node.sign(&probe)?,
            RefusalCode::HotVelocityExceeded,
            "hot_budget_velocity",
            &format!("node_id {} ledger after admitting V", node.node_id),
        )?;
    }
    // `admitted.len()` is `coins.len()` is `honest.len()` is `T` by construction, so
    // there is deliberately no "routed_total == tV" comparison here: it would be the
    // same expression on both sides and could never fire. The real evidence for the
    // ADR-0014 bound is what the two loops above established — each spend draws on
    // exactly ONE honest ledger (`signers == [target_id]`) and Core accepts the
    // resulting `1 + (t−1)`-share combine, so each really is completable; and every
    // ledger then refuses a further ONE-SAT hot spend, so no ledger admitted more
    // than V. tV is the arithmetic consequence, not an independent measurement.
    let routed_total = (admitted.len() as u64).saturating_mul(ROUTED_V.to_sat());
    assert_no_theft(&routed)?;

    Ok(format!(
        "(a) over-cap refused HOT_BUDGET_EXCEEDED pre-signing at all {honest_nodes} honest nodes \
         and still armed (control: {a_control_signers} honest partial(s) heard, so the zero is \
         evidence); (b) window sum capped at {} sat and an exposed reservation stayed \
         metered; live residual: normal-pin spend pending at node_id {residual_target_id}, later \
         duress carrier censored before every honest ingress, then exactly {residual_outflow} sat \
         completed from that one unfrozen honest ledger plus the adversary's {C} shares and the \
         next sat beyond its remaining window budget was refused; (c) an expired-unexposed \
         reservation returned (control: {c_control_signers} \
         honest partial(s) heard); adversarial cross-node routing \
         put one V into each of the {T} honest ledgers, all {} completable (one honest share plus \
         the adversary's {C} keys, accepted by testmempoolaccept, never broadcast), and every \
         ledger then refused a further \
         1-sat hot spend, so the federation admitted tV = {routed_total} sat and no ledger more \
         than V = {} sat",
        PER_WINDOW.to_sat(),
        completable.len(),
        ROUTED_V.to_sat()
    ))
}

// ---------------------------------------------------------------------------
// 7. partition / selective delivery

/// Deliver the duress carrier to a subset of nodes. Safety does **not** depend on
/// every node arming — it depends on the coupling. The assertion here is exactly
/// that: no honest node releases a coerced partial no matter how many armed, even
/// though the coordinator told only one of them.
///
/// The complementary half of the partition story — driving the reachable armed set
/// BELOW `t`, so the outcome is lockdown-only and recovery is the exit — is not
/// staged here, because it needs nodes destroyed rather than merely un-addressed.
/// [`reboot_death`] drives the set below `t` and asserts lockdown-only with no
/// sweep; [`recovery_exit`] then takes that same outcome out through the V0-10
/// timelock. This scenario deliberately keeps all `t` honest nodes alive, which is
/// why it can also require the sweep to fire as its partial-path control.
fn selective_delivery() -> Result<String, Error> {
    let vault = Vault::build(&Setup {
        hold_secs: 25,
        duress_delay_secs: 5,
        epsilon_secs: 1,
        ..Setup::default()
    })?;

    // Prove every honest daemon's partial fan-out reaches the adversary before an
    // absence is attributed to that daemon. An armed escape only needs `t` shares
    // and can finish its bounded fire window before every redundant honest release
    // arrives, so it is a sweep control, not a reliable per-node transport control.
    let control_coin = vault.fund_extra(Amount::from_sat(100_000_000))?;
    let (control_id, control_signers) = vault.wiretap_positive_control(&control_coin)?;

    let coerced = vault.hot_spend(&vault.vault_utxo, Amount::from_sat(400_000_000))?;
    let escape = vault.escape_for(&vault.vault_utxo)?;
    let request = vault.request(&coerced, &escape, DURESS_PIN)?;

    // The coordinator relays to ONE honest node and drops the rest. Node-to-node
    // propagation is what closes this: the node it reached fans the carrier to
    // every peer, so the federation learns of it without the coordinator's help.
    // The coordinator relays `/sign`, never `/channel` (ADR-0010), so it has no
    // move here.
    let accepted = expect_accepted(
        &vault.relay_to(0, &request)?,
        "selective delivery to node 0",
    )?;
    let coerced_txid = coerced.unsigned_tx.compute_txid().to_string();

    // Node 0 is the coordinator's direct recipient, so one observed relay is true by
    // construction. Require every other honest identity to appear on the wire too.
    let relayers =
        vault.wait_for_honest_relayers(&request.nonce, vault.honest.len(), EXPECT_TIMEOUT)?;

    // The adversary's own identities withhold every receipt — a t−1 minority
    // refusing to participate, which the n = 2t−1 shape is chosen to tolerate.
    std::thread::sleep(Duration::from_secs(
        vault.params.hold_secs + vault.params.combine_slack_secs + 15,
    ));

    // Corroborate the propagation story from the wire: the node the coordinator
    // reached relayed the carrier onward to the adversary's endpoints too, which is
    // why one delivery is enough for the federation to learn of it.
    //
    // This corroborates propagation, but it is NOT the deaf-listener control for the
    // partial assertion: a request exercises a different decoder path. The completed
    // normal spend above already proved every honest node's partial path.
    vault.assert_wiretap_decoded("selective-delivery zero-partial assertion")?;
    let releasable = vault.honest_partials_for(&accepted.commitment_id);
    if !releasable.is_empty() {
        return Err(format!(
            "honest node_id(s) {releasable:?} released a coerced partial under selective \
             delivery — safety must rest on the coupling, not on how many armed"
        )
        .into());
    }
    // Corroborating, NOT the headline: the escape sweeps the same `vault_utxo` the
    // coerced spend does, so once the sweep is in the mempool Core rejects the coerced
    // tx as a conflict whatever the release gate did. The released-partial oracle above
    // is what carries the claim; this only catches a completion that beat the sweep.
    if vault.in_mempool_or_chain(&coerced_txid)? {
        return Err("the coerced spend broadcast under selective delivery".into());
    }
    let all: Vec<usize> = (0..vault.honest.len()).collect();
    vault.wait_for_lockdown(&all, EXPECT_TIMEOUT)?;
    // The sweep supplies a later positive control for the escape-partial role. It
    // needs one honest share to prove that distinct role reached the same decoder;
    // the normal control above already proved the per-sender paths for all nodes.
    let escape_control_signers = vault.wait_for_escape_partials(&request, 1, SETTLE)?;
    vault.assert_wiretap_decoded("selective-delivery partial-path control")?;
    // The exact-id read above is keyed on the commitment id the harness expects for
    // the coerced candidate. A partial the adversary can USE is bound to the
    // transaction sighash, not to that metadata (`validate_observed_partial`), so a
    // node that released a usable spend signature while advertising some other
    // well-formed commitment id would be filed under that id and the exact read would
    // miss it. Close it globally: over this whole run the only candidate the adversary
    // is entitled to hold honest partials for is the user's own escape.
    let (escape_id, _) = vault.signed_escape_candidate(&request)?;
    let stray = vault.partial_commitments_outside(&[control_id.as_str(), escape_id.as_str()]);
    if !stray.is_empty() {
        return Err(format!(
            "the adversary collected honest candidate partial(s) for {stray:?} beyond the escape \
             sweep it was entitled to see; a coerced share advertised under another commitment id \
             is still combinable against the transaction it signs"
        )
        .into());
    }
    assert_no_theft(&vault)?;

    Ok(format!(
        "control: all {control_signers} honest normal-spend partials proved every wiretap \
         release path; carrier delivered to 1 of {} honest nodes; all {} honest relayers \
         observed on the channel; {} later escape partial(s) proved the sweep role; 0 coerced \
         partials released; Lockdown at T everywhere; no theft",
        vault.honest.len(),
        relayers.len(),
        escape_control_signers.len()
    ))
}

// ---------------------------------------------------------------------------
// Timing-probe instrumentation

/// What one Argon2 evaluation should cost, so that the node's OWN observed ingress
/// latency can be checked against the `2 x one_argon2` floor every pin class must
/// clear ([`assert_pin_cost_reached_the_node`], the surviving hard control). The same
/// measurement supplies the reporting reference for the advisory skew
/// ([`pin_latency_advisory`]), which decides nothing. This target only guides
/// calibration and makes no claim about runner jitter.
const PIN_COST_TARGET: Duration = Duration::from_millis(200);
/// The probe cost the calibration measures at before scaling. Small enough to be
/// cheap on a slow debug build, large enough to time reliably.
const PIN_COST_PROBE_KIB: u32 = 8 * 1024;
/// Ceiling on the enrolled cost. Well under `vault_node`'s own 256 MiB digest
/// ceiling, and bounded so a slow machine cannot scale itself into swapping — every
/// node in the federation allocates this much while evaluating a pin.
const PIN_COST_MAX_KIB: u32 = 128 * 1024;
/// The floor a measured evaluation must clear for `2 x one_argon2` to sit clear of a
/// loopback round trip, which is what makes the enrolment control able to separate a
/// correctly-configured node from one still at `Params::MIN_M_COST`. Only an
/// implausibly fast machine misses it at the ceiling above, and failing loudly beats
/// running a control that cannot distinguish the two.
const PIN_COST_FLOOR: Duration = Duration::from_millis(50);
/// `vault-node`'s base `/sign` handler deadline (`server::HANDLER_TIMEOUT`, private
/// there). Production adds the configured maximum PIN backoff; this harness enrols
/// the default schedule, which is a single zero, so the base value is the whole
/// budget a request has.
const NODE_HANDLER_DEADLINE: Duration = Duration::from_secs(10);
/// Memory-hard evaluations one spend request costs outside the node's `sign_state` lock:
/// both enrolled PIN slots (`pin::verify_pin` evaluates both unconditionally) plus
/// the `arm_carrier_id` derivation, whose work factor is the elementwise MAX of the
/// two slots (`vault-node/src/pin.rs`, `CarrierKdf::new`).
const PIN_EVALUATIONS_PER_SIGN: u32 = 3;
/// Replication keeps one unusually fast/slow enrolment from setting the floor for
/// the whole live run. Odd so the median is one observed duration.
const PIN_CALIBRATION_SAMPLES: usize = 5;

/// Choose an Argon2id enrolment cost at which ONE evaluation is expensive enough to
/// dominate measurement noise, and return it with the cost actually measured there.
///
/// The fixture enrolment cost is Argon2's minimum — tens of microseconds per
/// evaluation. No node-side latency floor can tell a fixture left at that cost apart
/// from one enrolled at the calibrated cost, because the whole difference sits under
/// the loopback round trip. That harness-configuration mismatch is what
/// [`assert_pin_cost_reached_the_node`] exists to catch, and this calibration is what
/// gives it a floor to check against. The cost is derived per machine rather than
/// hard-coded because the same constant means entirely different things in a release
/// build and an unoptimized one.
fn calibrate_pin_cost() -> Result<(u32, Duration), Error> {
    // Argon2id's cost is ~linear in `m_cost` at fixed `t`/`p`, so a replicated
    // median measurement scales to the target without trusting one scheduler turn.
    let probe = median_pin_evaluation(PIN_COST_PROBE_KIB);
    let scale = PIN_COST_TARGET.as_secs_f64() / probe.as_secs_f64().max(f64::MIN_POSITIVE);
    let scaled = (f64::from(PIN_COST_PROBE_KIB) * scale).ceil();
    let m_cost_kib = if scaled >= f64::from(PIN_COST_MAX_KIB) {
        PIN_COST_MAX_KIB
    } else {
        (scaled as u32).max(PIN_COST_PROBE_KIB)
    };
    let measured = median_pin_evaluation(m_cost_kib);
    if measured < PIN_COST_FLOOR {
        return Err(format!(
            "pin-cost calibration failed: one Argon2 evaluation is {measured:?} at {m_cost_kib} \
             KiB (ceiling {PIN_COST_MAX_KIB} KiB), under the {PIN_COST_FLOOR:?} floor the \
             enrolment control needs to stand clear of a loopback round trip. If {m_cost_kib} is the \
             ceiling, raise PIN_COST_MAX_KIB (vault_node accepts up to 256 MiB); otherwise the \
             cost scaled non-linearly and PIN_COST_TARGET needs re-deriving."
        )
        .into());
    }
    // And the ceiling, for the same reason the floor exists: a cost derived per
    // machine can land somewhere the comparison stops meaning anything. A machine
    // slow enough to clamp at `PIN_COST_MAX_KIB` and still measure hundreds of
    // milliseconds per evaluation puts `PIN_EVALUATIONS_PER_SIGN` of them, plus peer
    // `/channel` relay contention on the same lock, against the node's handler
    // deadline — and the silence scenarios then fail as a bare `HTTP 408` from the
    // first probe, with none of the attribution every other guard here provides.
    // Say it here, where the cause is still in hand.
    let per_request = measured * PIN_EVALUATIONS_PER_SIGN;
    if per_request >= NODE_HANDLER_DEADLINE {
        return Err(format!(
            "pin-cost calibration failed: one Argon2 evaluation is {measured:?} at {m_cost_kib} \
             KiB, so the {PIN_EVALUATIONS_PER_SIGN} evaluations one /sign request costs come to \
             {per_request:?} against the node's {NODE_HANDLER_DEADLINE:?} handler deadline — \
             before any peer-relay contention on the same lock. The probes would time out as \
             HTTP 408 rather than measure a pin-independent latency. Lower PIN_COST_TARGET (this \
             machine is slower per KiB than the target assumes) or run a release build."
        )
        .into());
    }
    Ok((m_cost_kib, measured))
}

/// Time one Argon2id evaluation at `m_cost_kib`. Enrolment and verification run the
/// same KDF over the same params, so an enrolment is a faithful stand-in for the
/// per-slot verification the node performs at ingress.
fn time_one_pin_evaluation(m_cost_kib: u32) -> Duration {
    let start = Instant::now();
    let phc = vault_node::argon2id_normal_phc_at(NORMAL_PIN, m_cost_kib);
    let elapsed = start.elapsed();
    debug_assert!(!phc.is_empty());
    elapsed
}

fn median_pin_evaluation(m_cost_kib: u32) -> Duration {
    let mut samples: Vec<Duration> = (0..PIN_CALIBRATION_SAMPLES)
        .map(|_| time_one_pin_evaluation(m_cost_kib))
        .collect();
    samples.sort_unstable();
    samples[PIN_CALIBRATION_SAMPLES / 2]
}

/// A full short-circuit regression costs one extra Argon2 evaluation. The reference
/// stays below one evaluation while leaving more runner headroom than a half-cost
/// threshold on machines that hit the calibration ceiling.
///
/// This is a REPORTING reference, not a gate — see [`pin_latency_advisory`]. It is also
/// only HALF of what makes the advisory speak: this says how big an effect would be
/// interesting, and [`within_pin_spread`] says how big this run's own noise already is.
fn pin_latency_reference(one_argon2: Duration) -> Duration {
    one_argon2 * 3 / 4
}

/// How much THIS RUN's timings already vary WITHIN one pin — the widest
/// max-minus-min of the two same-pin sample sets.
///
/// A same-pin spread is noise by construction: those samples differ in nothing the
/// silence property cares about, so whatever separates them is the box. Reporting a
/// between-pin skew as interesting when it is smaller than that would be reporting
/// noise as signal — which is the failure this whole bead is about, arriving in the
/// report instead of in a gate. The measured CI spread on identical code was 2 ms –
/// 680 ms against a 149 ms single-evaluation reference, so a reference-only comparison
/// prints an alarm-shaped line on a large fraction of healthy runs and teaches the next
/// reader to skip it.
///
/// It is a floor on this run's noise, not an estimate of its distribution: with 4–8
/// samples per pin the tail is unobserved, and the advisory claims no statistical power
/// from it ([`pin_latency_advisory`]). Zero for a single sample, which is correct — a
/// one-shot pair supplies no evidence about its own noise, so the caller passes the
/// replicated spread measured beside it.
///
/// It also RISES WITH THE SAMPLE COUNT, while the difference of medians it is compared
/// against does not — so `two-spend-probe` (8 per pin) sets a higher bar for speaking
/// than `escape-class-sequences` (4), as a consequence of their sample budgets rather
/// than of any decision about them. That is the safe direction for a report: more
/// samples means more of this box's behaviour at FIXED pin actually observed, and the
/// only thing the bar decides is whether a line is shouted. Both numbers print either
/// way. A count-invariant spread (an IQR, or the spread of split-half medians) would
/// make the two scenarios' reports comparable, but at four samples per pin it would be
/// estimating a quantile from two points, and it would still buy no detection power for
/// a signal that gates nothing — so the mismatch is stated here rather than papered
/// over with a statistic that looks more principled than its inputs are.
fn within_pin_spread(normal: &[Duration], duress: &[Duration]) -> Duration {
    let spread = |samples: &[Duration]| match (samples.iter().min(), samples.iter().max()) {
        (Some(min), Some(max)) => *max - *min,
        _ => Duration::ZERO,
    };
    spread(normal).max(spread(duress))
}

/// Report one normal-vs-duress median-latency comparison. **Advisory: it never fails
/// a scenario.**
///
/// # Why this is not a gate (bead btc-policy-c9r)
///
/// It used to be one, and it could not do the job. The leak these comparisons exist
/// to catch is ONE EXTRA ARGON2 EVALUATION — about 199 ms at this harness's enrolled
/// cost. Two consecutive CI runs of the SAME commit measured, for `two-spend-probe`,
/// a skew of 223.9 ms with duress slower and then 680.1 ms with NORMAL slower; for
/// `escape-class-sequences`, 2.27 ms and then 317.6 ms. The sign flips between runs
/// and the spread is 2 ms – 680 ms on identical code. A measurement whose noise
/// exceeds the effect it is looking for cannot detect that effect: the false
/// positives were the visible half, and a real 199 ms leak sitting inside that same
/// spread would have passed just as easily. For SILENCE — the invariant that protects
/// the person holding the duress PIN — a false negative is the worst failure
/// available, so gating on this measurement was worse than not gating at all.
///
/// # Why advisory rather than a variance-derived GATE
///
/// (The trip condition below IS derived from measured variance. What is out of reach is
/// making that a PASS/FAIL bound with stated statistical power — this section is about
/// the gate, the next one about the report.)
///
/// The alternative was to keep it as a gate with a bound derived from measured
/// variance and enough samples to state real statistical power. That is not reachable
/// here. The sample count is capped by the scenario's own duress delay — each sample
/// costs `PIN_EVALUATIONS_PER_SIGN` memory-hard evaluations, and
/// `escape-class-sequences` refuses outright any calibration whose sampled requests
/// would not fit before `T`, because a loop that ran past `T` would manufacture a
/// false violation in that scenario's other, hard assertions. Separating a 199 ms
/// shift from a distribution with a ~680 ms tail needs sample counts an order of
/// magnitude beyond that budget, and they would have to be re-measured per runner
/// besides. Widening the constant instead is the
/// one fix the bead explicitly forbids: a bound loose enough never to fire is
/// decoration.
///
/// # What it takes for this to speak, and why it is two conditions
///
/// The skew must exceed BOTH the single-evaluation reference AND
/// [`within_pin_spread`] — how far this run's own SAME-PIN samples already spread. The
/// reference alone would not do: it is ~149 ms while the measured CI spread on
/// identical code was 2 ms – 680 ms, so a reference-only line prints on a large
/// fraction of healthy runs. An advisory that cries out on green runs is not a
/// conservative advisory, it is one nobody reads, and re-creating the false-positive
/// problem in report form gets to the same place bead c9r started from. Requiring the
/// between-pin skew to be larger than the noise the same run demonstrably produces is
/// the honest form of the question, and it is measured, not chosen.
///
/// This buys no detection power and does not make it a gate: with 4–8 samples per pin
/// the spread is a floor on the noise rather than a description of it, and both numbers
/// are printed unconditionally so a reader can judge the run for themselves rather than
/// trust the verdict.
///
/// # What gates the property instead
///
/// A deterministic, in-process counting seam, following the shape
/// `pin::PinEvaluator`/`CountingEvaluator` already established for the pin compare.
/// `vault-node`'s ingress work record compares six things, and each answers a
/// question the others cannot:
///
/// * The `/sign` ACKNOWLEDGEMENT, field for field. It is the one part of the record the
///   attacker actually receives, so it is also the only one that is not in-process; the
///   node-side comparison needs no normalization, which makes it stricter than the body
///   equality this scenario can perform (`pin_invariant_body`).
/// * The ORDERED op sequence — `/sign` lock acquisitions, replay/pending/refresh-log
///   writes, outbox pushes, signatures, candidate registration, the Hold timer
///   install — so an op added, dropped, or merely MOVED on one pin's path fails the
///   comparison.
/// * A canonical PIN-MASKED PROJECTION OF THE WHOLE CHANNEL STORE. The op sequence and
///   the schedule counters are whitelists of hand-placed instrumentation; this one is
///   read off the store's fields, so a duress-only write landing anywhere in it — the
///   first clause of the ADR-0012 rule — fails the comparison even though nobody
///   instrumented that site.
/// * The same whole-struct projection of the `/sign` HANDLER STATE: replay, pending,
///   coordinator-nonce and refresh logs plus the PIN ATTEMPT BUDGET, which is the one
///   piece of state the pin VERDICT itself is passed into (`AttemptBudget::charge`).
/// * The MEMORY-HARD WORK the pass performed: every Argon2 PIN evaluation, in order,
///   and every arm-carrier derivation. This is what makes the replacement cover the
///   ~199 ms effect this timing probe was aimed at, and it is not redundant with the
///   op log: an extra `carrier_kdf.derive` bolted onto one pin's path costs a full
///   evaluation while appending nothing to that log.
/// * `ChannelState::schedule_work_trace`'s per-request delta, for the store's internal
///   lock, visit, allocation, and timer-window counts.
///
/// All six are asserted identical for a normal-pin and a duress-pin request across
/// the first carrier, an already-armed node, fresh and replay-cached escape-class
/// spends, a replay-cached Hot resubmission, a Hot-budget refusal, and a LOCKED-OUT
/// node — the attacker's cheapest probe, and the path where §0's fail-closed rule makes
/// a refused duress request still derive its carrier, run the arm hook, and stage for
/// peers (`channel::duress::normal_and_duress_ingress_op_sequences_*`). They have no
/// noise floor and cannot false-negative for the operations, state, and memory-hard
/// seams they record, so this signal's remaining job is to be reported, not to decide.
fn pin_latency_advisory(
    label: &str,
    skew: Duration,
    reference: Duration,
    observed_noise: Duration,
    normal_median: Duration,
    duress_median: Duration,
    samples: usize,
) -> String {
    if skew > reference && skew > observed_noise {
        // Distinct from `FAIL` on purpose: a future reader must not take this for a
        // detected silence break. Nothing here concluded that duress did extra work.
        println!(
            "  ADVISORY (not a failure)  {label}: skew {skew:?} over BOTH this run's own \
             within-pin spread ({observed_noise:?}) and the {reference:?} single-evaluation \
             reference ({normal_median:?} normal vs {duress_median:?} duress over {samples} \
             sample(s)). This is a LOADED-BOX NOISE REPORT, and this harness draws no silence \
             conclusion from it. The gate for pin-uniform ingress is vault-node's deterministic \
             ingress-work assertion \
             (`channel::duress::normal_and_duress_ingress_op_sequences_*`), which runs in \
             `cargo test`, not here. See `pin_latency_advisory`."
        );
        format!(
            "ADVISORY {label} skew {skew:?} over both the {observed_noise:?} within-pin spread \
             and the {reference:?} reference ({normal_median:?} normal vs {duress_median:?} \
             duress, {samples} samples) — reported as noise, NOT a detected silence break"
        )
    } else {
        format!(
            "advisory {label} skew {skew:?} (within-pin spread {observed_noise:?}, \
             single-evaluation reference {reference:?}; {normal_median:?} normal vs \
             {duress_median:?} duress, {samples} samples)"
        )
    }
}

/// Prove the calibrated PIN cost actually REACHED the daemon. **Still a hard gate**
/// while the skew comparisons it used to guard are advisory ([`pin_latency_advisory`]).
///
/// What it detects is a HARNESS CONFIGURATION regression, not a timing one: if
/// `pin_m_cost_kib` never reached the generated node configs, both slots stay at
/// `Params::MIN_M_COST` while the scorecard still prints "one Argon2 = 200 ms" from a
/// cost measured in this CLI process. The reported reference would not describe the
/// nodes under test, and nothing else in the run would notice that scenario-setup
/// mismatch.
///
/// The NODE-SIDE term survives the noise that disqualified the skew comparison,
/// because node contention moves it in only one direction. `verify_pin` evaluates BOTH slots
/// unconditionally, in separate `let` bindings the compiler cannot short-circuit
/// (`vault-node/src/pin.rs`), so every pin class costs at least two evaluations at the
/// enrolled cost — including the wrong-pin class, which returns early only AFTER both
/// have run. Two evaluations is therefore a floor the node cannot be under unless it
/// is enrolled somewhere else, node contention only pushes an observed median further
/// ABOVE that floor, and everything else on the path (HTTP round trip, PSBT decode,
/// signature verification, carrier derivation) only adds to it. The reference is
/// calibrated earlier in the CLI process, so load concentrated only during that
/// calibration can still inflate the floor; the replicated median reduces that remote
/// false-failure mode but does not make a wall-clock control infallible.
fn assert_pin_cost_reached_the_node(
    context: &str,
    medians: &[(&str, Duration)],
    one_argon2: Duration,
    m_cost_kib: u32,
) -> Result<(), Error> {
    let floor = one_argon2 * 2;
    for (class, median) in medians {
        if *median < floor {
            return Err(format!(
                "{context}: the {class}-pin median ingress latency is {median:?}, under the \
                 {floor:?} floor of the two unconditional Argon2 evaluations every pin class \
                 costs at {m_cost_kib} KiB (one evaluation measures {one_argon2:?} here). The \
                 harness federation is not enrolled at the calibrated cost, so the reported \
                 Argon2 reference does not describe the node — check that `pin_m_cost_kib` \
                 reaches the generated node config"
            )
            .into());
        }
    }
    Ok(())
}

/// What a probe's two request-dependent response fields must independently be, so
/// that blanking them cannot blank a leak.
struct ResponseCover {
    /// The commitment id the submitted transaction and its authorized expiry
    /// derive, computed by the caller via [`Vault::expected_commitment_id`].
    ///
    /// Held as a value rather than as `(&Psbt, expiry)` so [`pin_invariant_body`]
    /// is a pure function of a response body and its cover — which is what makes
    /// the silence oracle unit-testable without standing up a live federation.
    commitment_id: String,
    /// The unix-second interval the request was in flight. `first_seen` is the
    /// node's own ingress clock, so it must land inside it.
    ///
    /// No slack is ADDED: the node runs on this machine and stamps ingress from the
    /// same wall clock, so `sent_at <= first_seen <= received_at` holds by
    /// construction for a fresh (non-replayed) candidate, and the interval is exactly
    /// what the round trip observed. Slack is not free here — a tolerance of `k`
    /// seconds is exactly `k` seconds of room for a duress bit to ride as `now`
    /// versus `now − 1`, which is same-width and would therefore pass both the
    /// normalized body comparison and the size check.
    ///
    /// It is NOT a zero-width bound, and calling it one would overstate what this
    /// checks. `unix_now` truncates to whole seconds while the bracketed request costs
    /// at least the pin's Argon2 evaluations, so a round trip that crosses a second
    /// boundary — the common case at the calibrated cost — leaves the accepted set
    /// `{n, n+1}`. That residual second is the wall clock's resolution, not a
    /// tolerance this harness chose, and narrowing it would mean timestamping in
    /// units the response does not carry. What the check does rule out is the case it
    /// exists for: a `first_seen` that is not this node's ingress clock at all.
    sent_at: u64,
    received_at: u64,
}

/// Strip the response fields that legitimately differ between two DISTINCT
/// requests, leaving everything a duress bit could ride on.
///
/// A probe's two requests are necessarily different transactions submitted at
/// different instants, so `commitment_id` (a hash of the exact transaction) and
/// `first_seen` (this node's wall clock) differ for reasons that have nothing to do
/// with the pin. Every OTHER field is compared verbatim — including fields this
/// harness does not know about, since a leak added later would most plausibly
/// arrive as a field nobody thought to name here. That is what makes the comparison
/// whole-surface rather than a checklist.
///
/// But "differs per request" is not "may hold anything". Blanking these two
/// unconditionally would let a same-width PIN-dependent value sit in either one and
/// pass both the normalized comparison and the size check — the exact shape of leak
/// the whole-body comparison exists to catch. So each is CHECKED against what it
/// must independently be before it is normalized: the commitment id against the
/// candidate the harness submitted, and `first_seen` against the interval the
/// request was actually in flight.
fn pin_invariant_body(body: &str, cover: &ResponseCover) -> Result<String, Error> {
    let mut value: Value = serde_json::from_str(body)?;
    if let Some(accepted) = value.get("accepted") {
        let expected = &cover.commitment_id;
        let observed = accepted
            .get("commitment_id")
            .and_then(Value::as_str)
            .ok_or("an accepted /sign response carries no commitment_id")?;
        if observed != expected {
            return Err(format!(
                "SILENCE BREAK: the node bound this candidate to commitment {observed}, but its \
                 transaction and expiry derive {expected}. The field is normalized away as \
                 request-dependent, so a pin-dependent value here would otherwise be invisible"
            )
            .into());
        }
        let first_seen = accepted
            .get("first_seen")
            .and_then(Value::as_u64)
            .ok_or("an accepted /sign response carries no first_seen")?;
        let (low, high) = (cover.sent_at, cover.received_at);
        if first_seen < low || first_seen > high {
            return Err(format!(
                "SILENCE BREAK: first_seen {first_seen} is outside the {low}..={high} interval \
                 the request was in flight; it must be this node's ingress clock, and it is \
                 normalized away on that basis"
            )
            .into());
        }
    }
    normalize_request_dependent(&mut value);
    Ok(serde_json::to_string(&value)?)
}

/// The two `/sign` response paths that legitimately differ per REQUEST, and the
/// only two [`pin_invariant_body`] blanks. Naming the exact paths rather than the
/// field names is what keeps the comparison whole-surface: a field called
/// `commitment_id` appearing anywhere ELSE in a future response has never been
/// checked against anything, so blanking it by name would hand a same-width
/// pin-dependent value a place to sit where both the body comparison and the size
/// check pass. Everything outside these two paths is compared verbatim.
const REQUEST_DEPENDENT_PATHS: &[[&str; 2]] =
    &[["accepted", "commitment_id"], ["accepted", "first_seen"]];

/// Validate an `/events` projection's SHAPE and return how many alerts it carries.
///
/// The silence probes assert `/events` is unchanged across a duress-only interval,
/// which is a genuine negative — a queued duress alert would show up both as an
/// entry in `alerts` and as a moved `cursor`. But two identical projections are
/// equally consistent with an endpoint that answers the same thing no matter what,
/// so the shape is checked and the alert count is reported: an operator reading the
/// scorecard should be able to see whether the compared window was empty, rather
/// than having to assume it was not.
fn events_alert_count(projection: &Value) -> Result<usize, Error> {
    let alerts = projection
        .get("alerts")
        .and_then(Value::as_array)
        .ok_or_else(|| format!("/events answered without an alerts array: {projection}"))?;
    if projection.get("cursor").and_then(Value::as_u64).is_none() {
        return Err(format!("/events answered without a cursor: {projection}").into());
    }
    Ok(alerts.len())
}

/// The `spend_txid` of every alert in an `/events` projection — used by the reorg
/// watchtower scenario to prove the specific re-orged spend was re-classified, not
/// merely that some alert count moved.
fn alert_spend_txids(projection: &Value) -> Vec<String> {
    projection
        .get("alerts")
        .and_then(Value::as_array)
        .map(|alerts| {
            alerts
                .iter()
                .filter_map(|alert| {
                    alert
                        .get("spend_txid")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Blank exactly [`REQUEST_DEPENDENT_PATHS`], and only where the value above
/// already checked them. A path that is absent (a refusal body carries neither
/// field) is left alone rather than created, so refusal bodies are compared
/// byte-for-byte.
fn normalize_request_dependent(value: &mut Value) {
    for [parent, leaf] in REQUEST_DEPENDENT_PATHS {
        if let Some(field) = value.get_mut(parent).and_then(|p| p.get_mut(leaf)) {
            *field = Value::String(format!("<{leaf}>"));
        }
    }
}

// ---------------------------------------------------------------------------
// 3. two-spend-probe — silence

/// An attacker probing with two spends cannot read the duress bit. Ingress is
/// constant-observable: identical operations in identical order under both pins,
/// with the pin choosing only the contents of a same-shaped schedule record.
///
/// The probe hard-gates the complete ingress acknowledgement body, its size, and the
/// `/events` projection under the normal and duress pins. It still measures and
/// reports latency, including the amount-based Hot-budget refusal path, but that noisy
/// wall-clock signal is advisory; the deterministic node tests hard-gate ingress work
/// shape across both pins.
/// `/pending` is request-varying, so its stronger whole-body equality checks live in
/// the deterministic node tests that hold every input except pin/arm state equal.
///
/// Every accepted-path timing request is a FRESH candidate pair, never a
/// resubmission. The amount-refusal samples intentionally reuse one over-cap pair
/// behind fresh coordinator envelopes because no refused candidate is registered.
/// An accepted resubmission hits the anti-replay log's idempotent-accepted early return
/// (`handle_sign_after_lock`), which answers from cache without reaching candidate
/// registration or signing. It still records the arm intent and re-applies the cached
/// schedule; the deterministic cached-resubmission test covers that shape separately.
/// Sampling only replays would leave the fresh registration and signing path untested.
fn two_spend_probe() -> Result<String, Error> {
    const SAMPLES: usize = 8;
    const REFUSAL_SAMPLES: usize = 8;
    const PRE_T_GUARD_SECS: u64 = 10;

    // Enrol the pins at a measurable cost so the hard configuration control below
    // can prove that cost reached the node. The same measurement supplies a useful
    // reference for the advisory latency report, but never a silence verdict.
    let (pin_m_cost_kib, one_argon2) = calibrate_pin_cost()?;

    // A long hostage window: everything measured here happens BEFORE T, which is
    // the interval silence is claimed for. After T the lockdown is meant to be
    // visible — that is the user's "the system locked itself" story, not a leak.
    let vault = Vault::build(&Setup {
        hold_secs: 120,
        duress_delay_secs: 90,
        epsilon_secs: 1,
        hot_max_per_tx: Amount::from_sat(300_000_000),
        hot_max_per_window: Amount::from_sat(900_000_000),
        pin_m_cost_kib,
        ..Setup::default()
    })?;
    let timed_requests = u32::try_from(SAMPLES.saturating_add(REFUSAL_SAMPLES).saturating_mul(2))?;
    let measured_pin_work = one_argon2 * PIN_EVALUATIONS_PER_SIGN * timed_requests;
    let pre_t_window = Duration::from_secs(
        vault
            .params
            .duress_delay_secs
            .saturating_sub(PRE_T_GUARD_SECS),
    )
    .saturating_sub(SETTLE);
    if measured_pin_work >= pre_t_window {
        return Err(format!(
            "two-spend timing calibration cannot fit before T: {timed_requests} post-duress \
             requests × {PIN_EVALUATIONS_PER_SIGN} measured Argon2 evaluations consume \
             {measured_pin_work:?}, but only {pre_t_window:?} remains after the fixed events settle \
             and {PRE_T_GUARD_SECS}s guard. Lower PIN_COST_TARGET or lengthen this scenario's \
             duress delay"
        )
        .into());
    }
    let events_control_alerts = vault.prove_events_endpoint_reports_alert()?;
    // The events control proves the `/events` ingress path only; the global partial
    // backstop at the end reads the PARTIAL wiretap, a DIFFERENT transport. Without a
    // control on that path the backstop passes vacuously against a deaf partial
    // listener — a released coerced share would go unseen and still read as "0
    // released". Prove the partial path audible now, while the federation is whole and
    // before any arm, with an ordinary normal-pin spend on its own coin that every
    // honest node pushes a share for (`wiretap_positive_control` requires all of
    // them); whitelist its id at the backstop. Its coin is a separate `fund_extra`
    // UTXO spent entirely to hot, so the vault balance the probes and escapes measure
    // is untouched, and its ~100M outflow leaves ample room under this scenario's 900M
    // velocity window, well below the 300M per-tx cap.
    let partial_control_coin = vault.fund_extra(Amount::from_sat(100_000_000))?;
    let (partial_control_id, partial_control_signers) =
        vault.wiretap_positive_control(&partial_control_coin)?;

    // Keep first-touch allocation and page faults out of the one-shot comparison.
    // This is an ordinary normal-pin candidate on the same daemon and exercises the
    // same Argon2, parsing, signing, registration, and fan-out path before either
    // measured request. Let its detached fan-out settle as well so it does not load
    // only the following normal sample.
    let warmup_spend = vault.hot_spend(&vault.vault_utxo, Amount::from_sat(3_000_001))?;
    let warmup_escape =
        vault.escape_over_fee(&[&vault.vault_utxo], FEE + Amount::from_sat(50_000))?;
    let warmup = vault.request(&warmup_spend, &warmup_escape, NORMAL_PIN)?;
    let warmup_accepted =
        expect_accepted(&vault.honest[0].sign(&warmup)?, "normal-pin timing warm-up")?;
    std::thread::sleep(SETTLE);

    // Two DISTINCT candidate pairs over the same coin — the attacker's probe pair.
    // Each needs its own escape as well as its own spend: a commitment binds the
    // exact unsigned transaction, so re-pairing one escape with a second spend is
    // refused as already registered, which would end the probe before it measured
    // anything.
    let probe_a = vault.hot_spend(&vault.vault_utxo, Amount::from_sat(100_000_000))?;
    let probe_b = vault.hot_spend(&vault.vault_utxo, Amount::from_sat(100_000_001))?;
    let escape_a = vault.escape_for(&vault.vault_utxo)?;
    let escape_b = vault.escape_over_fee(&[&vault.vault_utxo], FEE + Amount::from_sat(1_000))?;

    let normal = vault.request(&probe_a, &escape_a, NORMAL_PIN)?;
    let normal_signed = Psbt::from_str(&normal.psbt)?;
    let normal_sent_at = unix_now()?;
    let normal_probe = vault.honest[0].sign_timed(&normal)?;
    let normal_cover = ResponseCover {
        commitment_id: vault.expected_commitment_id(&normal_signed, normal.expiry),
        sent_at: normal_sent_at,
        received_at: unix_now()?,
    };
    let normal_accepted = expect_accepted(&normal_probe.response, "normal-pin probe")?;

    // Snapshot `/events` AFTER the normal-pin request and compare after the duress
    // traffic. Snapshotting before it would fold any change caused by ordinary
    // normal-pin traffic into the duress verdict below and report it as a duress
    // leak — an attribution error that would fire on a projection that is in fact
    // pin-independent.
    //
    // Settle FIRST, by the same interval the after-shot waits. Without it the two
    // ends of the comparison are asymmetric: an asynchronous alert caused by the
    // normal request but emitted a moment later would land inside the window and be
    // attributed to duress — precisely the error this placement exists to avoid.
    std::thread::sleep(SETTLE);
    let events_before = vault.events_snapshot()?;

    let duress = vault.request(&probe_b, &escape_b, DURESS_PIN)?;
    let duress_signed = Psbt::from_str(&duress.psbt)?;
    let duress_sent_at = unix_now()?;
    let duress_probe = vault.honest[0].sign_timed(&duress)?;
    let duress_cover = ResponseCover {
        commitment_id: vault.expected_commitment_id(&duress_signed, duress.expiry),
        sent_at: duress_sent_at,
        received_at: unix_now()?,
    };
    let duress_accepted = expect_accepted(&duress_probe.response, "duress-pin probe")?;
    let mut allowed_escape_ids = vec![vault.expected_commitment_id(&escape_b, duress.expiry)];
    let mut latest_hot_first_seen = warmup_accepted
        .first_seen
        .max(normal_accepted.first_seen)
        .max(duress_accepted.first_seen);
    // This is the only sample that crosses Idle -> arm-intent on the directly
    // addressed node; later duress samples run after propagation has already armed the
    // federation. It is kept separate from the replicated steady-state medians below
    // because it is a different STATE, not because it decides anything: like them it is
    // advisory. First-carrier schedule/deadline work added only to the duress path is
    // gated deterministically by
    // `channel::duress::normal_and_duress_ingress_op_sequences_match_on_a_first_carrier`,
    // and what this one-shot adds is a live end-to-end sample of that transition.
    let first_arm_skew = normal_probe.elapsed.abs_diff(duress_probe.elapsed);

    // Response cover: the COMPLETE body, not a chosen field or its length.
    // `remaining_secs` is the Hold under both pins and the real fire-time and
    // Armed-vs-Scheduled are never exposed before T — but asserting only that field
    // and the byte count would pass any leak carried in a field the probe forgot to
    // name or in a same-width value. Both bodies are normalized for the fields that
    // legitimately differ per REQUEST rather than per PIN (see `pin_invariant_body`)
    // and must then be equal.
    let normal_body = pin_invariant_body(&normal_probe.body, &normal_cover)?;
    let duress_body = pin_invariant_body(&duress_probe.body, &duress_cover)?;
    if normal_body != duress_body {
        return Err(format!(
            "SILENCE BREAK: the /sign response differs by pin beyond its request-dependent \
             fields: {normal_body} normal vs {duress_body} duress"
        )
        .into());
    }
    let (normal_size, duress_size) = (normal_probe.body.len(), duress_probe.body.len());
    if normal_size != duress_size {
        return Err(format!(
            "SILENCE BREAK: response size differs by pin ({normal_size} normal vs {duress_size} \
             duress bytes)"
        )
        .into());
    }
    // `/events` is the coordinator's pull surface. Compare an interval containing
    // ONLY the duress probe: the baseline above was taken after the normal control,
    // and this snapshot happens before the mixed timing samples below. Waiting a
    // little lets asynchronous propagation surface any duress-specific event while
    // staying well before T.
    std::thread::sleep(SETTLE);
    let events_after = vault.events_snapshot()?;
    if events_before != events_after {
        return Err(format!(
            "SILENCE BREAK: /events changed on an honest daemon across a duress-only interval: \
             {events_before:?} → {events_after:?}"
        )
        .into());
    }
    let events_alerts: usize = events_after
        .iter()
        .map(|(_, projection)| events_alert_count(projection))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .sum();
    // The replicated steady-state samples, which carry a HARD gate and an ADVISORY
    // signal and must not be read as one thing. Hard, per sample: the normalized
    // response BODY and its byte count under the two pins. Advisory: the latency each
    // sample took, reported by `pin_latency_advisory` and deciding nothing, because a
    // wall clock here cannot resolve the one extra Argon2 evaluation a short-circuiting
    // compare would cost — that regression is gated deterministically in `vault-node`
    // instead.
    //
    // BAD_PIN stays out of BOTH halves, and for a reason that survives the demotion:
    // after its two unconditional digest evaluations a wrong pin correctly returns
    // before PSBT policy, signing, candidate registration, and Hot-budget accounting,
    // so the design promises that refusal class neither the same body nor the same
    // end-to-end latency as a valid PIN. The pin-uniform refusal this scenario DOES
    // compare is HOT_BUDGET_EXCEEDED, below, which is decided on the amount alone.
    //
    // Every sample is a FRESH candidate pair — a new spend amount and a new escape
    // fee, so each is a distinct commitment. Resubmitting the pairs above would be
    // answered from the anti-replay log's idempotent-accepted branch, which returns
    // before candidate registration and signing. It still records the arm intent and
    // re-applies the cached schedule under either pin, but it does not exercise the
    // fresh registration work these samples mean to compare.
    //
    // Sampled INTERLEAVED so machine load, page-cache warmth, and scheduler drift
    // hit both pins equally, and ALTERNATED by parity so neither pin is
    // systematically the first request of a pair: a fixed within-pair order leaves a
    // constant bias (cache warmth, connection reuse) that the median cannot remove.
    //
    // Each sample also keeps its NORMALIZED BODY and byte count, not just `elapsed`.
    // The one-shot pair above is the only body comparison that runs while the
    // federation is still Idle; by the time these samples run, propagation has
    // committed the arm, so a leak that appears only in an ARMED node's `/sign`
    // response — the state where the node has the most to hide — would otherwise
    // never be compared at all. The responses are already in hand, so this costs
    // nothing beyond the comparison itself.
    struct PinSample {
        elapsed: Duration,
        /// Normalized by `pin_invariant_body`, so what remains is only what a duress
        /// bit could ride on.
        body: String,
        /// The RAW body length, deliberately not the normalized one: a same-width
        /// pin-dependent value inside a normalized field survives the body
        /// comparison and is caught only here.
        size: usize,
        escape_id: String,
        first_seen: u64,
    }
    let mut normal_timings = Vec::with_capacity(SAMPLES);
    let mut duress_timings = Vec::with_capacity(SAMPLES);
    for sample in 0..SAMPLES {
        let index = sample as u64;
        // `class` labels the sample; `pin` is never interpolated into a message —
        // these are the enrolled PINs, and an error path is not a place to print one.
        let take =
            |amount: u64, fee_bump: u64, pin: &str, class: &str| -> Result<PinSample, Error> {
                let spend = vault.hot_spend(&vault.vault_utxo, Amount::from_sat(amount))?;
                let escape = vault
                    .escape_over_fee(&[&vault.vault_utxo], FEE + Amount::from_sat(fee_bump))?;
                let request = vault.request(&spend, &escape, pin)?;
                let signed = Psbt::from_str(&request.psbt)?;
                let sent_at = unix_now()?;
                let timed = vault.honest[0].sign_timed(&request)?;
                let cover = ResponseCover {
                    commitment_id: vault.expected_commitment_id(&signed, request.expiry),
                    sent_at,
                    received_at: unix_now()?,
                };
                let accepted =
                    expect_accepted(&timed.response, &format!("{class} timing sample {sample}"))?;
                Ok(PinSample {
                    elapsed: timed.elapsed,
                    body: pin_invariant_body(&timed.body, &cover)?,
                    size: timed.body.len(),
                    escape_id: vault.expected_commitment_id(&escape, request.expiry),
                    first_seen: accepted.first_seen,
                })
            };
        let normal_sample = || {
            take(
                1_000_000 + index * 2 + 1,
                100_000 + index * 1_000,
                NORMAL_PIN,
                "normal",
            )
        };
        let duress_sample = || {
            take(
                2_000_000 + index * 2 + 1,
                200_000 + index * 1_000,
                DURESS_PIN,
                "duress",
            )
        };
        let (normal, duress) = if sample % 2 == 0 {
            let normal = normal_sample()?;
            let duress = duress_sample()?;
            (normal, duress)
        } else {
            let duress = duress_sample()?;
            let normal = normal_sample()?;
            (normal, duress)
        };
        if normal.body != duress.body {
            return Err(format!(
                "SILENCE BREAK: on steady-state sample {sample} — with the federation already \
                 armed — the /sign response differs by pin beyond its request-dependent fields: \
                 {} normal vs {} duress",
                normal.body, duress.body
            )
            .into());
        }
        if normal.size != duress.size {
            return Err(format!(
                "SILENCE BREAK: on steady-state sample {sample} — with the federation already \
                 armed — response size differs by pin ({} normal vs {} duress bytes)",
                normal.size, duress.size
            )
            .into());
        }
        allowed_escape_ids.push(duress.escape_id.clone());
        latest_hot_first_seen = latest_hot_first_seen
            .max(normal.first_seen)
            .max(duress.first_seen);
        normal_timings.push(normal.elapsed);
        duress_timings.push(duress.elapsed);
    }
    normal_timings.sort_unstable();
    duress_timings.sort_unstable();
    let normal_median = normal_timings[SAMPLES / 2];
    let duress_median = duress_timings[SAMPLES / 2];
    let skew = normal_median.abs_diff(duress_median);
    // The reference stays below one measured Argon2 evaluation at the cost these pins
    // are enrolled at — derived, not fixed, because a fixed millisecond value is only
    // meaningful relative to what an evaluation actually costs on this machine and
    // in this build profile. Replicated calibration prevents one scheduler outlier
    // from tightening or loosening the whole run.
    let reference = pin_latency_reference(one_argon2);
    // This control REMAINS a hard gate while the skew comparisons below are advisory,
    // and the asymmetry is deliberate — but it is a difference of KIND, not a claim
    // that this measurement is noise-free. What it detects is a CONFIGURATION
    // regression: `pin_m_cost_kib` never reaching the generated node configs, leaving
    // both slots at `Params::MIN_M_COST` while the reported Argon2 reference describes
    // the calibrated cost. That is a three-orders-of-magnitude effect, not the ~199 ms
    // one the skew comparison could not resolve. Contention at the node only pushes an
    // observed median further ABOVE the floor; contention during the CLI-side
    // calibration can still inflate the floor itself, which is a real residual
    // false-failure mode and is stated where the arithmetic lives (see
    // `assert_pin_cost_reached_the_node`).
    assert_pin_cost_reached_the_node(
        "two-spend probe",
        &[("normal", normal_median), ("duress", duress_median)],
        one_argon2,
        pin_m_cost_kib,
    )?;
    // Advisory, not gates — see `pin_latency_advisory` for why wall-clock skew cannot
    // decide this property and what gates it instead. Each report is scored against
    // this run's OWN within-pin spread as well as the single-evaluation reference, so a
    // loaded box does not print an alarm-shaped line on a green run.
    let observed_noise = within_pin_spread(&normal_timings, &duress_timings);
    // The one-shot first-arm pair has no spread of its own — two samples that differ in
    // the pin cannot say how much the box moves at fixed pin. It borrows the replicated
    // steady-state spread measured moments ago on the same daemon: the honest available
    // estimate of this run's noise, and stated as borrowed rather than passed as zero,
    // which would silently make this the one reference-only report.
    let first_arm_advisory = pin_latency_advisory(
        "two-spend first-arm ingress latency (noise borrowed from the steady-state samples)",
        first_arm_skew,
        reference,
        observed_noise,
        normal_probe.elapsed,
        duress_probe.elapsed,
        1,
    );
    let median_advisory = pin_latency_advisory(
        "two-spend steady-state median ingress latency",
        skew,
        reference,
        observed_noise,
        normal_median,
        duress_median,
        SAMPLES,
    );
    // The Hot-budget refusal path, included because a refusal that leaked the pin
    // would hand the attacker the bit for free. `HOT_BUDGET_EXCEEDED` is decided on
    // the amount alone, so both its body and its work shape must be pin-independent.
    // Body equality is hard-gated here, store/handler work shape is hard-gated by the
    // deterministic refusal test, and the replicated wall-clock distribution remains
    // visible only as an advisory signal.
    let over = vault.hot_spend(&vault.vault_utxo, Amount::from_sat(400_000_000))?;
    let over_escape = vault.escape_over_fee(&[&vault.vault_utxo], FEE + Amount::from_sat(2_000))?;
    let mut refusal_normal_timings = Vec::with_capacity(REFUSAL_SAMPLES);
    let mut refusal_duress_timings = Vec::with_capacity(REFUSAL_SAMPLES);
    let mut refusal_body: Option<String> = None;
    for sample in 0..REFUSAL_SAMPLES {
        let normal_sample =
            || vault.honest[0].sign_timed(&vault.request(&over, &over_escape, NORMAL_PIN)?);
        let duress_sample =
            || vault.honest[0].sign_timed(&vault.request(&over, &over_escape, DURESS_PIN)?);
        let (over_normal_probe, over_duress_probe) = if sample % 2 == 0 {
            (normal_sample()?, duress_sample()?)
        } else {
            let duress = duress_sample()?;
            let normal = normal_sample()?;
            (normal, duress)
        };
        let a = expect_refusal(
            &over_normal_probe.response,
            &format!("over-cap normal-pin timing sample {sample}"),
        )?;
        let b = expect_refusal(
            &over_duress_probe.response,
            &format!("over-cap duress-pin timing sample {sample}"),
        )?;
        if a.code != RefusalCode::HotBudgetExceeded || b.code != RefusalCode::HotBudgetExceeded {
            return Err(format!(
                "expected HOT_BUDGET_EXCEEDED on refusal sample {sample}, got {:?} normal and {:?} \
                 duress",
                a.code, b.code
            )
            .into());
        }
        if a.code != b.code || a.check != b.check || a.detail != b.detail {
            return Err(format!(
                "SILENCE BREAK: Hot-budget refusal sample {sample} differs by pin \
                 ({:?}/{}/{} vs {:?}/{}/{})",
                a.code, a.check, a.detail, b.code, b.check, b.detail
            )
            .into());
        }
        // These are the same candidate pair with fresh coordinator envelopes; a
        // refusal has no legitimate request-dependent response field, so compare the
        // serialized body verbatim on every sample and across the whole series.
        if over_normal_probe.body != over_duress_probe.body {
            return Err(format!(
                "SILENCE BREAK: Hot-budget refusal body sample {sample} differs by pin ({} vs {})",
                over_normal_probe.body, over_duress_probe.body
            )
            .into());
        }
        if refusal_body
            .as_ref()
            .is_some_and(|body| body != &over_normal_probe.body)
        {
            return Err(format!(
                "SILENCE BREAK: Hot-budget refusal body changed across fresh envelopes on sample \
                 {sample}: {:?} vs {}",
                refusal_body, over_normal_probe.body
            )
            .into());
        }
        refusal_body.get_or_insert(over_normal_probe.body);
        refusal_normal_timings.push(over_normal_probe.elapsed);
        refusal_duress_timings.push(over_duress_probe.elapsed);
    }
    refusal_normal_timings.sort_unstable();
    refusal_duress_timings.sort_unstable();
    let refusal_normal_median = refusal_normal_timings[REFUSAL_SAMPLES / 2];
    let refusal_duress_median = refusal_duress_timings[REFUSAL_SAMPLES / 2];
    let refusal_skew = refusal_normal_median.abs_diff(refusal_duress_median);
    assert_pin_cost_reached_the_node(
        "Hot-budget refusal probe",
        &[
            ("normal", refusal_normal_median),
            ("duress", refusal_duress_median),
        ],
        one_argon2,
        pin_m_cost_kib,
    )?;
    // Advisory for the same reason as the acceptance medians above. The refusal's
    // BODY equality, asserted per sample and across fresh envelopes, stays a hard
    // gate: it is exact-byte, not statistical.
    let refusal_advisory = pin_latency_advisory(
        "two-spend HOT_BUDGET_EXCEEDED refusal median latency",
        refusal_skew,
        reference,
        within_pin_spread(&refusal_normal_timings, &refusal_duress_timings),
        refusal_normal_median,
        refusal_duress_median,
        REFUSAL_SAMPLES,
    );

    let silence_deadline = duress_accepted
        .first_seen
        .saturating_add(vault.params.duress_delay_secs);
    let silence_completed_at = unix_now()?;
    if silence_completed_at >= silence_deadline {
        return Err(format!(
            "the timing/refusal samples completed at {silence_completed_at}, at or after the \
             duress T {silence_deadline}; this run cannot attribute their observables to the \
             silence interval even though the calibration arithmetic fit"
        )
        .into());
    }

    // The control that makes every comparison above non-vacuous: the duress carrier
    // really did carry the duress bit.
    //
    // Each assertion in this scenario is an EQUALITY between a normal-pin and a
    // duress-pin observation, so all of them pass trivially if `DURESS_PIN` was
    // classified `Normal` at all — swapped enrolment slots, a `verify_pin` regression,
    // both slots derived from the same PHC. `assert_pin_cost_reached_the_node` does not
    // cover it either: the node evaluates BOTH slots unconditionally
    // (`vault-node/src/pin.rs`), so its two-evaluation floor is met by every pin class.
    // The scenario would then report "identical under both pins before T" for a vault
    // with no duress bit in it.
    //
    // Nothing before `T` can serve as that control — pre-`T` invisibility is the very
    // property under test. Lockdown at `T` is the first legitimate observable, and it
    // is unconditional (ADR-0012 invariant i), so read it here, after every silence
    // assertion has been taken.
    let all: Vec<usize> = (0..vault.honest.len()).collect();
    vault
        .wait_for_lockdown(
            &all,
            EXPECT_TIMEOUT + Duration::from_secs(vault.params.duress_delay_secs),
        )
        .map_err(|e| {
            format!(
                "the duress probe never armed this federation, so the pin-equality assertions \
                 above compared two normal-pin requests and proved nothing about silence ({e})"
            )
        })?;
    // Every accepted hot candidate above has its own Hold. Read the global partial
    // oracle only after the latest such Hold and combine window, otherwise a leaked
    // share scheduled for a later sample could arrive after the scorecard passed.
    vault.wait_past_hot_release_window(latest_hot_first_seen)?;
    let mut allowed_refs: Vec<&str> = allowed_escape_ids.iter().map(String::as_str).collect();
    // The partial-transport control released real shares under its own id — a
    // legitimate normal-pin spend to the user's hot wallet, not a leak — so whitelist
    // it alongside the run's escape ids. Any OTHER claimed id is still a stray.
    allowed_refs.push(partial_control_id.as_str());
    vault
        .assert_no_unexpected_partials("two-spend probe global partial backstop", &allowed_refs)?;
    assert_no_theft(&vault)?;

    Ok(format!(
        "identical under both pins before T: whole /sign body equal modulo its request-dependent \
         fields (remaining_secs {}, {normal_size}B) over {SAMPLES}/{SAMPLES} interleaved FRESH \
         pairs below lockout, /events \
         unchanged ({events_alerts} alert(s) either side; live /events control observed \
         {events_control_alerts} across {} honest nodes; partial wiretap proven audible by \
         {partial_control_signers} honest share(s) on a normal-pin control), \
         HOT_BUDGET_EXCEEDED refusal byte-identical; and the duress carrier is proven to have \
         carried the duress bit — all {} honest nodes locked down at T. \
         Wall-clock timing is ADVISORY ONLY (one Argon2 = {one_argon2:?} at {pin_m_cost_kib} \
         KiB): {first_arm_advisory}; {median_advisory}; {refusal_advisory}",
        normal_accepted.remaining_secs,
        vault.honest.len(),
        vault.honest.len()
    ))
}

// ---------------------------------------------------------------------------
// 1. toxic-parent

/// An escape built over an EXTERNAL unconfirmed deposit. Such a parent is not
/// vault-authorized, so it can be replaced out from under the escape (a "toxic
/// deposit" the attacker double-spends). ADR-0012 excludes those inputs from the
/// mandatory-coverage set and never chains onto them.
///
/// The safety outcome either way: the escape fires over vault-authorized inputs
/// only, or the sweep fails → Lockdown → recovery. No poisoned escape, and no
/// theft.
fn toxic_parent() -> Result<String, Error> {
    let vault = Vault::build(&Setup {
        hold_secs: 20,
        duress_delay_secs: 8,
        epsilon_secs: 1,
        ..Setup::default()
    })?;

    // The partial-path control, first. This scenario's central assertion is that NO
    // escape partial ever left an honest node, which a listener that received
    // nothing at all reports identically. A completed ordinary spend proves the
    // adversary can in fact see a released partial in this federation. Its coin is
    // spent entirely to the hot wallet, so it leaves the vault balance — and the
    // escape's coverage arithmetic below — untouched.
    let control_coin = vault.fund_extra(Amount::from_sat(100_000_000))?;
    let (control_id, control_signers) = vault.wiretap_positive_control(&control_coin)?;

    // An external party deposits into the vault and the deposit stays unconfirmed.
    // Its parent is bitcoind's wallet transaction — nothing the federation
    // authorized — so it is exactly the input an escape must not chain onto.
    let vault_address = vault.descriptor.address(Network::Regtest)?;
    let deposit_txid = vault.bitcoind.call_str(
        "sendtoaddress",
        // Explicitly opt this external parent into replacement so the harness can
        // pull it out from under the pre-signed escape before T.
        json!([vault_address.to_string(), 1.0, "", "", false, true]),
    )?;
    let deposit_hex = vault
        .bitcoind
        .call_str("getrawtransaction", json!([deposit_txid]))?;
    let deposit_tx: Transaction = deserialize_hex(&deposit_hex)?;
    let toxic = utxo_paying(&deposit_tx, &vault.vault_spk)?;

    // The coordinator composes an escape that sweeps the confirmed vault UTXO AND
    // chains onto the unconfirmed external deposit.
    let poisoned = vault.escape_over(&[&vault.vault_utxo, &toxic])?;
    let coerced = vault.hot_spend(&vault.vault_utxo, Amount::from_sat(300_000_000))?;
    let request = vault.request(&coerced, &poisoned, DURESS_PIN)?;
    let accepted = expect_accepted(
        &vault.relay_to(0, &request)?,
        "toxic-parent carrier before fire-time ancestry checks",
    )?;
    vault.wait_for_honest_relayers(&request.nonce, vault.honest.len(), EXPECT_TIMEOUT)?;
    let confirmation_upper_bound = vault.confirm_with_compromised(&request)?;

    let poisoned_txid = poisoned.unsigned_tx.compute_txid().to_string();
    let coerced_txid = coerced.unsigned_tx.compute_txid().to_string();
    let all: Vec<usize> = (0..vault.honest.len()).collect();
    vault.wait_for_lockdown(&all, EXPECT_TIMEOUT)?;
    // Not a settle — the escape's own release window. Lockdown lands at `T`, which
    // is where `[T, T + combine_slack]` opens, so reading the escape-partial
    // absence a few seconds after lockdown reads it while the release-and-retry
    // path is still live. Wait the window out before concluding zero.
    vault.wait_past_escape_release_window(accepted.first_seen, confirmation_upper_bound)?;
    // The external parent remains live in the mempool through the fire pass. That is
    // essential evidence: `escape_sweep_policy_admissible` can resolve its prevout,
    // so the run reaches `assemble_package` and must reject specifically because the
    // unconfirmed parent is absent from the node's validated-and-policy-accepted set.
    // Replacing it before T would stop at the earlier missing-prevout check and leave
    // the load-bearing authorized-ancestry gate completely untested.
    if vault.in_mempool_or_chain(&poisoned_txid)? {
        return Err(format!(
            "the poisoned escape {poisoned_txid} broadcast over external unconfirmed parent \
             {deposit_txid}"
        )
        .into());
    }
    if !vault.validated_escape_partials(&request)?.is_empty() {
        return Err(
            "an honest escape partial left before the toxic-parent fire-time gate refused it"
                .into(),
        );
    }
    vault.assert_wiretap_decoded("toxic-parent zero-partial assertion")?;
    // Attribute the refusal to THIS live external parent at the authorized-ancestry
    // gate. The wrapper and exact parent/outpoint bind the evidence to
    // `escape_sweep_pre_release_admissible` -> `chain::assemble_package`, rather than
    // to some unrelated fire-time refusal.
    let toxic_refusal = format!(
        "escape package ancestry is inadmissible before release: input {} chains off unconfirmed \
         transaction {}, which this node never validated and policy-accepted: an external \
         unconfirmed deposit is excluded",
        toxic.outpoint, deposit_txid
    );
    let toxic_refusals = vault
        .honest
        .iter()
        .filter(|node| node.log_contains(&toxic_refusal))
        .count();
    if toxic_refusals == 0 {
        return Err(format!(
            "the poisoned escape was absent, but no honest node rejected live external parent \
             {} at the authorized-ancestry gate; the run did not demonstrate toxic-parent \
             exclusion. Last log: {}",
            deposit_txid,
            vault.honest[0].log_tail()
        )
        .into());
    }

    // Now prove why the excluded class is toxic: after the gate has refused the
    // child, the external wallet can replace its still-unconfirmed parent without
    // any vault authorization. This replacement is evidence about the threat, not
    // the refusal attribution above.
    let bump = vault
        .bitcoind
        .call("bumpfee", json!([deposit_txid.clone()]))?;
    let replacement_txid = bump
        .get("txid")
        .and_then(Value::as_str)
        .ok_or("bumpfee response has no replacement txid")?
        .to_string();
    if vault
        .bitcoind
        .call_optional("getmempoolentry", json!([deposit_txid.clone()]))?
        .is_some()
    {
        return Err("the toxic external parent remained in the mempool after replacement".into());
    }
    // The coerced hot spend's own Hold has not necessarily expired yet: Lockdown
    // lands at `T`, which is well inside the Hold, and Lockdown does not stop the
    // in-flight fire loop. Reading its absence now would report a spend that simply
    // has not had its release opportunity as one the mechanism suppressed. Wait out
    // the Hold and the complete combine window first, then read.
    vault.wait_past_hot_release_window(accepted.first_seen)?;
    if vault.in_mempool_or_chain(&coerced_txid)? {
        return Err("the coerced hot spend completed despite the duress pin".into());
    }
    // And the sharper form of the same claim: not merely that nothing broadcast,
    // but that no honest node ever released a combinable share of it. Re-check the
    // wiretap immediately before the absence read — a listener that died during the
    // wait above would report this zero for the wrong reason.
    vault.assert_wiretap_decoded("toxic-parent coerced-partial absence")?;
    let releasable = vault.honest_partials_for(&accepted.commitment_id);
    if !releasable.is_empty() {
        return Err(format!(
            "honest node_id(s) {releasable:?} released a partial for the coerced spend {}; with \
             the adversary's own {C} that is a combinable quorum",
            accepted.commitment_id
        )
        .into());
    }
    vault.assert_no_unexpected_partials(
        "toxic-parent global partial backstop",
        &[control_id.as_str()],
    )?;
    vault.mine(1)?;
    if !vault.in_mempool_or_chain(&replacement_txid)? {
        return Err("the replacement external deposit did not confirm".into());
    }
    assert_no_theft(&vault)?;

    Ok(format!(
        "control: {control_signers} honest partial(s) seen for a completed normal spend (the \
         wiretap is not deaf); the poisoned escape never released an honest partial or broadcast \
         ({toxic_refusals}/{} honest nodes rejected live external parent {deposit_txid} at the \
         authorized-ancestry gate), then that parent was replaced by {replacement_txid}; coerced \
         hot spend dead \
         (0 honest partials and no broadcast, read past its whole Hold + combine window); \
         unconditional Lockdown at T; no theft",
        vault.honest.len()
    ))
}

// ---------------------------------------------------------------------------
// 2. in-flight-refresh

/// A refresh in flight when duress arms. Build-over-mempool largely dissolves this:
/// the escape chains off the refresh's OUTPUT rather than conflicting over its
/// input, and a vault-authorized parent cannot be replaced without `t`-of-`n` node
/// signatures the post-wrench attacker lacks.
///
/// The residual outcome is denial, never theft: the coerced hot spend is dead
/// (frozen partial + unconditional Lockdown at T) whether or not the sweep fires.
/// The scenario also exercises the load-bearing COARSE subordination rule —
/// any pending spend blocks all refreshes.
fn in_flight_refresh() -> Result<String, Error> {
    let vault = Vault::build(&Setup {
        hold_secs: 20,
        duress_delay_secs: 8,
        epsilon_secs: 1,
        ..Setup::default()
    })?;

    // NO `wiretap_positive_control` here, unlike its siblings, and the reason is a
    // real incompatibility rather than an oversight. The control completes an ordinary
    // hot spend, and a node keeps that candidate registered well past the broadcast —
    // so the very next refresh is answered `REFRESH_SUBORDINATED` ("a spend is pending
    // on this node") at every node that has not yet observed the broadcast. Running it
    // first was tried and made the in-flight refresh below reach only 1/3 nodes,
    // destroying the precondition this scenario exists to test. Running it later would
    // leave a second pending hot candidate alive across the coerced spend, moving both
    // the escape's coverage denominator and — through `earliest_live_hot_fire − ε` —
    // the node's own `T`.
    //
    // So the coerced-partial absence read at the end rests on the escape share alone:
    // the decoder is proven live and at least one honest sender's path is audible, but
    // not every one of them. That is a weaker control than the siblings carry, and it
    // is stated here rather than papered over.

    // A second, confirmed vault coin makes the subordination check genuinely
    // coarse: the later refresh spends this coin, disjoint from the pending hot
    // spend, while the armed escape must cover both it and the refresh child.
    let disjoint = vault.fund_extra(Amount::from_sat(200_000_000))?;

    // A pin-less refresh: vault → vault, so it can move nothing to anyone. With no
    // spend pending it is admissible.
    let refresh_value = vault
        .vault_utxo
        .txout
        .value
        .checked_sub(REFRESH_FEE)
        .ok_or_else(|| {
            format!(
                "refresh fee {REFRESH_FEE} exceeds the {} vault coin",
                vault.vault_utxo.txout.value
            )
        })?;
    let refresh_psbt = build_spend(
        &vault.vault_utxo,
        &vault.witness_script,
        &[(vault.vault_spk.clone(), refresh_value)],
    )?;
    let refresh = vault.refresh_request(&refresh_psbt)?;
    let refresh_id = vault.expected_commitment_id(&refresh_psbt, refresh.expiry);
    let mut refresh_accepted = 0usize;
    let mut refusals = Vec::new();
    for response in vault.relay_refresh_all_fresh(&refresh)? {
        match response {
            SignResponse::Accepted(_) => refresh_accepted += 1,
            SignResponse::Refusal(r) => {
                refusals.push(format!("{:?}/{}: {}", r.code, r.check, r.detail))
            }
        }
    }
    if refresh_accepted != vault.honest.len() {
        return Err(format!(
            "the in-flight refresh was accepted by only {refresh_accepted}/{} nodes: {}",
            vault.honest.len(),
            refusals.join("; ")
        )
        .into());
    }

    let refresh_txid = refresh_psbt.unsigned_tx.compute_txid().to_string();
    vault.wait_for_tx(&refresh_txid, EXPECT_TIMEOUT)?;
    let refresh_output = utxo_paying(&refresh_psbt.unsigned_tx, &vault.vault_spk)?;

    // Now the wrench, while the refresh is still unconfirmed. Both candidates spend
    // the refresh OUTPUT, not the original now-spent input. The escape additionally
    // covers the disjoint confirmed coin, so its live fire proves the authorized
    // parent-child package path rather than passing only because the coerced spend
    // conflicts with the refresh.
    let coerced = vault.hot_spend(&refresh_output, Amount::from_sat(400_000_000))?;
    let escape = vault.escape_over(&[&refresh_output, &disjoint])?;
    let request = vault.request(&coerced, &escape, DURESS_PIN)?;
    let (escape_id, _) = vault.signed_escape_candidate(&request)?;
    let mut accepted_id = None;
    for (index, response) in vault.relay_all_fresh(&request)?.iter().enumerate() {
        let accepted = expect_accepted(
            response,
            &format!("duress child of in-flight refresh at node {index}"),
        )?;
        accepted_id = Some(accepted.commitment_id);
    }

    // The COARSE subordination rule: with a spend now pending, EVERY refresh is
    // queued behind it — not merely those whose inputs overlap. An input-overlap
    // rule would let a refresh spending an escape-input-that-is-not-a-triggering-
    // spend-input finalize instantly and invalidate the armed escape.
    let second_refresh_value = disjoint
        .txout
        .value
        .checked_sub(REFRESH_FEE)
        .ok_or_else(|| {
            format!(
                "refresh fee {REFRESH_FEE} exceeds the {} disjoint coin",
                disjoint.txout.value
            )
        })?;
    let second_refresh_psbt = build_spend(
        &disjoint,
        &vault.witness_script,
        &[(vault.vault_spk.clone(), second_refresh_value)],
    )?;
    let second_refresh = vault.refresh_request(&second_refresh_psbt)?;
    let mut subordinated = 0usize;
    for (index, response) in vault
        .relay_refresh_all_fresh(&second_refresh)?
        .iter()
        .enumerate()
    {
        expect_code(
            response,
            RefusalCode::RefreshSubordinated,
            "refresh_subordination",
            &format!("coarse disjoint refresh at node {index}"),
        )?;
        subordinated += 1;
    }
    // As in `arm_split_closed` vector (b): `expect_code` returns on the first node
    // that does not subordinate, so a count comparison here would be the loop bound
    // against itself. The counter is kept for the summary line only.

    std::thread::sleep(Duration::from_secs(
        vault.params.hold_secs + vault.params.combine_slack_secs + 15,
    ));
    // Both broadcast reads below are SECONDARY, and labelled as such for the same
    // reason `duress_resubmission` labels its own: the armed escape sweeps both
    // `refresh_output` and `disjoint`, and it is separately required to have fired
    // over `refresh_output` a few lines down. Once it has, bitcoind rejects the
    // coerced spend and the disjoint refresh as conflicts no matter what the nodes
    // did, so neither read can fail on chain mechanics alone.
    //
    // The FALSIFIABLE assertions are elsewhere and are not chain-dependent: for the
    // disjoint refresh it is the `REFRESH_SUBORDINATED` refusal required at every
    // node above, and for the coerced spend it is the zero-partial read below — a
    // released partial is in the adversary's hands whether or not the transaction it
    // belongs to ever wins a mempool race. These two are kept for the case where one
    // of them does somehow land.
    let coerced_txid = coerced.unsigned_tx.compute_txid().to_string();
    if vault.in_mempool_or_chain(&coerced_txid)? {
        return Err("the coerced hot spend completed while a refresh was in flight".into());
    }
    let second_refresh_txid = second_refresh_psbt.unsigned_tx.compute_txid().to_string();
    if vault.in_mempool_or_chain(&second_refresh_txid)? {
        return Err(format!(
            "the disjoint refresh {second_refresh_txid} broadcast despite coarse subordination"
        )
        .into());
    }
    let escape_txid = escape.unsigned_tx.compute_txid().to_string();
    vault.wait_for_tx(&escape_txid, EXPECT_TIMEOUT)?;
    let fired_escape = vault.raw_transaction(&escape_txid)?;
    if !fired_escape
        .input
        .iter()
        .any(|input| input.previous_output == refresh_output.outpoint)
    {
        let actual: Vec<_> = fired_escape
            .input
            .iter()
            .map(|input| input.previous_output)
            .collect();
        return Err(format!(
            "the escape bitcoind accepted does not spend the in-flight refresh output {}: actual inputs {actual:?}",
            refresh_output.outpoint
        )
        .into());
    }

    // The escape having fired, every honest node released its ESCAPE-role partial to
    // the adversary's endpoints — this federation's deaf-listener control, free
    // because the sweep fires here anyway. Require a share from EVERY live honest
    // node, not merely one: the coerced-partial reads below are FEDERATION-WIDE
    // (`honest_partials_for` plus the global backstop), and a single observed share
    // proves only that SOME node's wiretap path is audible — one deaf sender's
    // permanent silence would then read as the freeze holding. Release is a per-node
    // gate (`release_partials` consults only the node's own candidate record; a peer
    // combining first does not suppress it), so demanding all of them is sound —
    // exactly the reasoning `wiretap_positive_control` documents. That helper cannot
    // be used directly here: its fresh control carrier would contend with the pending
    // coerced spend the disjoint refresh is already subordinated behind, so
    // strengthening the sweep's own per-node shares is the control that comes free.
    //
    // The coerced-partial claim below is read entirely from the compromised
    // wiretaps (`honest_partials_for`), so a listener that received nothing at all
    // reports "0 partials released" for a reason that has nothing to do with the
    // freeze. Escape-role and spend-role partials arrive over the same listener and
    // the same decode path, so seeing the former proves the latter would have been
    // seen had one been released. The absence check is deliberately made AFTER the
    // sweep for this reason; deferring it also gives any late partial strictly more
    // time to show up.
    vault.wait_for_escape_partials(&request, vault.honest.len(), SETTLE)?;
    vault.assert_wiretap_decoded("in-flight-refresh partial assertions")?;
    // Demand the id rather than skipping the check when it is absent: an unset id
    // means no node ever acknowledged the coerced carrier, which is a broken
    // scenario, not a pass.
    let coerced_id = accepted_id.ok_or("no node acknowledged the coerced spend")?;
    let releasable = vault.honest_partials_for(&coerced_id);
    if !releasable.is_empty() {
        return Err(format!(
            "honest node_id(s) {releasable:?} released the coerced partial during an \
             in-flight refresh"
        )
        .into());
    }
    vault.assert_no_unexpected_partials(
        "in-flight-refresh global partial backstop",
        &[refresh_id.as_str(), escape_id.as_str()],
    )?;
    let all: Vec<usize> = (0..vault.honest.len()).collect();
    vault.wait_for_lockdown(&all, EXPECT_TIMEOUT)?;
    vault.mine(1)?;
    assert_no_theft(&vault)?;

    Ok(format!(
        "unconfirmed refresh {refresh_txid} accepted by {refresh_accepted}/{} nodes; escape \
         {escape_txid} fired as its child; all {subordinated} honest nodes subordinated a disjoint \
         refresh, which never broadcast; coerced spend dead (0 partials released); Lockdown at T",
        vault.honest.len()
    ))
}

// ---------------------------------------------------------------------------
// 4. escape-class + refresh sequences

/// The two-slot record and `Idle→Armed` suppression per the transition table.
///
/// An escape-class spend completes immediately under EITHER pin — the destination
/// is the escape wallet either way, so there is nothing to defer and thus no timing
/// oracle. Under the duress pin it additionally schedules lockdown plus a residual
/// sweep at T; under the normal pin that delayed slot is a no-op.
///
/// Both halves of that record are observed on-chain rather than inferred from the
/// acknowledgement, because the acknowledgement cannot distinguish them: a node that
/// answered `remaining_secs = 0` and then broadcast nothing would look identical to
/// one that settled. So this scenario requires
///
///  - both escape-class spends to actually reach the mempool or a block;
///  - the DURESS residual to fire at `T` over inputs disjoint from the spend it
///    accompanies (their union being what coverage is measured over); and
///  - the NORMAL residual — the no-op slot — never to fire, read in the window
///    AFTER the moment `T` would have fallen had the normal pin armed but BEFORE
///    the duress `T`, with the node still un-locked-down at that point.
///
/// The four coins are laid out for exactly that: `A` and `B` are the two spends that
/// complete, and `C ∪ D` is the live duress residual, of which `D` also carries the
/// normal residual.
///
/// That overlap on `D` is forced, not incidental, and it is why the no-op control is
/// read STRICTLY BEFORE the duress `T`. Coverage is measured against the whole
/// remaining vault (`vault_node::lib` fire-time coverage, ~`:2432`), so the duress
/// residual has to sweep everything still unspent at `T` — there is no coin left over
/// to give the normal residual to itself. Before the duress `T` that costs nothing:
/// `D` is unspent, so a live normal slot would put its residual on chain and the
/// control is falsifiable. After the duress `T` it would prove nothing, since the
/// duress residual has spent `D` and the normal residual is then unbroadcastable for
/// a reason that has nothing to do with the two-slot record.
fn escape_class_sequences() -> Result<String, Error> {
    // Keep the same measurable enrolment as the dedicated silence probe: the hard
    // control below proves the configured cost reached the node, while the settlement
    // skew uses the measured evaluation only as an advisory reporting reference.
    let (pin_m_cost_kib, one_argon2) = calibrate_pin_cost()?;
    let vault = Vault::build(&Setup {
        // Match the dedicated silence probe's headroom. At the calibration ceiling
        // the 8 Argon2-heavy samples below can take seconds; T must not land
        // mid-loop and turn an otherwise valid sample into FRAUD_SUSPECTED.
        hold_secs: 120,
        duress_delay_secs: 90,
        epsilon_secs: 1,
        pin_m_cost_kib,
        ..Setup::default()
    })?;
    // The `/events` positive control, for the same reason `two_spend_probe` takes
    // one: this scenario asserts the projection is UNCHANGED across a duress-only
    // interval, and a watchtower that never started answers with a constant empty
    // projection that satisfies that comparison no matter what the pin did. Without
    // a demonstration that `/events` on THIS federation can move at all, the
    // silence claim below is an argument from absence with nothing behind it. Taken
    // here, immediately after `build()` and before any candidate exists, because it
    // permanently offsets the chain clock (see its doc comment) and its coin must be
    // gone before the coverage arithmetic below reads the vault balance.
    let events_control_alerts = vault.prove_events_endpoint_reports_alert()?;

    // The PER-NODE partial-path control, for the no-op assertion at the end of this
    // scenario: `validated_escape_partials(&normal)` must be empty, and that claim
    // ranges over every honest node. The duress sweep's own escape share proves the
    // decoder and one sender; it cannot show that a SPECIFIC node's fan-out to the
    // adversary's endpoints is audible, so without this a node whose transport was
    // silently broken would read as its no-op slot staying inert. Its coin is spent
    // ENTIRELY to hot with no vault change, so the coverage denominator the four
    // coins below are sized for is unchanged once it confirms.
    let control_coin = vault.fund_extra(Amount::from_sat(20_000_000))?;
    let (control_id, control_signers) = vault.wiretap_positive_control(&control_coin)?;

    // The four coins. `A` is the funded vault UTXO; `B` and `D` are ordinary side
    // coins, while `C` is deliberately small. The size asymmetry makes the normal
    // residual over `D` independently admissible at its hypothetical fire time:
    // paired normal spend A + residual D covers >95% of A+C+D. If C were another
    // 2 BTC coin, coverage would reject the residual even if the normal slot were
    // live, making its on-chain absence a false no-op control.
    const SIDE_COIN: Amount = Amount::from_sat(200_000_000);
    const STRAGGLER_COIN: Amount = Amount::from_sat(10_000_000);
    const ESCAPE_COVERAGE_PCT: u128 = 95;
    let coin_a = vault.vault_utxo.clone();
    let coin_b = vault.fund_extra(SIDE_COIN)?;
    let coin_c = vault.fund_extra(STRAGGLER_COIN)?;
    let coin_d = vault.fund_extra(SIDE_COIN)?;

    // A normal-pin escape-class spend: every output pays the escape descriptor, so
    // the node DERIVES escape-class from the outputs (never a coordinator label).
    // Its residual escape must have inputs DISJOINT from the completed spend.
    let escape_class = vault.escape_over(&[&coin_a])?;
    // The NORMAL residual sits alone on `D`. Nothing else spends `D` until the duress
    // residual sweeps it at the duress `T`, which is strictly later than the instant
    // this slot would have fired — so throughout the window the control is read in,
    // `D` is unspent and this transaction's absence is explainable ONLY by the slot
    // being inert. That is what makes "the delayed slot is a no-op" falsifiable: were
    // it live it would fire at `normal_at + duress_delay_secs` and appear on chain
    // while `D` was still available to it.
    let residual = vault.escape_over(&[&coin_d])?;
    let normal_delivered = coin_a
        .txout
        .value
        .to_sat()
        .saturating_add(coin_d.txout.value.to_sat())
        .saturating_sub(FEE.to_sat().saturating_mul(2));
    let normal_protected = coin_a
        .txout
        .value
        .to_sat()
        .saturating_add(coin_c.txout.value.to_sat())
        .saturating_add(coin_d.txout.value.to_sat());
    if u128::from(normal_delivered).saturating_mul(100)
        < u128::from(normal_protected).saturating_mul(ESCAPE_COVERAGE_PCT)
    {
        return Err(format!(
            "the normal-slot no-op control is mis-provisioned: its paired spend + residual deliver \
             {normal_delivered} sat over {normal_protected} protected sat, below the live 95% \
             fire-time coverage gate"
        )
        .into());
    }
    let normal = vault.request(&escape_class, &residual, NORMAL_PIN)?;
    let normal_signed = Psbt::from_str(&normal.psbt)?;
    let normal_sent_at = unix_now()?;
    let normal_timed = vault.honest[0].sign_timed(&normal)?;
    let normal_cover = ResponseCover {
        commitment_id: vault.expected_commitment_id(&normal_signed, normal.expiry),
        sent_at: normal_sent_at,
        received_at: unix_now()?,
    };
    let normal_accepted = expect_accepted(&normal_timed.response, "normal-pin escape-class spend")?;
    // The instant the normal pin's hypothetical delayed slot would fire, had it not
    // been a no-op. Everything below stays comfortably before the DURESS `T`, which
    // is later because the duress request is later.
    //
    // Anchored on the node's reported `first_seen`, not this process's send-time
    // clock: the node schedules `T` off the instant IT ingested the carrier, which
    // is at or after `normal_sent_at`. Substituting the earlier local timestamp
    // (`hold_expiry_race` names the same substitution) would place the control's
    // read BEFORE the hypothetical fire time — the unsafe direction for a no-op
    // control, since a slot that did fire would not have fired yet when it looked.
    let normal_slot_deadline = normal_accepted
        .first_seen
        .saturating_add(vault.params.duress_delay_secs);
    // Escape-class fires NOW, under either pin: `remaining_secs` is zero, not the
    // Hold. That is the property that removes the timing oracle.
    if normal_accepted.remaining_secs != 0 {
        return Err(format!(
            "escape-class spend was deferred under the normal pin (remaining_secs {}); it must \
             complete immediately under either pin",
            normal_accepted.remaining_secs
        )
        .into());
    }

    // "Settled" is a claim about the chain, not about `remaining_secs`. Require the
    // spend to actually be out there before anything downstream reads it as
    // completed.
    let escape_class_txid = escape_class.unsigned_tx.compute_txid().to_string();
    vault.wait_for_tx(&escape_class_txid, EXPECT_TIMEOUT)?;
    // Broadcast requires the normal carrier's holder decision, so this sample is an
    // upper bound on the hypothetical arm commit that determines its delayed window.
    let normal_confirmation_upper_bound = unix_now()?;

    // Let ordinary immediate-settlement work complete, then take the `/events`
    // baseline immediately before the duress request. This keeps a delayed effect
    // of normal-pin traffic out of the duress-only comparison interval.
    std::thread::sleep(SETTLE);

    // Hold the duress carrier back until a full escape release window separates the
    // two `first_seen` instants.
    //
    // The no-op control below has to read the normal residual's absence at
    // `normal_slot_deadline + combine_slack + FIRE_OBSERVATION_MARGIN`, not a couple
    // of seconds past the deadline: a live slot releases at its `T`, but the combine
    // and the broadcast follow on separate 1 Hz drivers, so a slot that DID fire can
    // reach the chain several seconds later and an early read would report it as
    // inert. That later read is only conclusive strictly BEFORE the duress `T`, and
    // the gap between the two carriers is what buys it. Pushing this one out by the
    // same window the control must observe moves the read and the duress `T` by the
    // same amount, so the sampling budget below is unchanged.
    let control_separation_secs = vault
        .params
        .combine_slack_secs
        .saturating_add(FIRE_OBSERVATION_MARGIN_SECS)
        .saturating_add(NO_OP_CONTROL_GUARD_SECS);
    vault.wait_past(
        normal_accepted
            .first_seen
            .saturating_add(control_separation_secs),
    )?;

    let events_before = vault.events_snapshot()?;

    // The same shape under the DURESS pin must settle identically — that is
    // re-review #3's escape-class-timing observable, closed.
    //
    // The duress pair spends entirely different coins from the normal pair, so all
    // four candidates are distinct commitments. Reusing either transaction verbatim
    // would be refused as already registered under a different pairing, ending the
    // comparison before it measured anything.
    //
    // `residual_b` sweeps `C ∪ D` — DISJOINT from the spend it accompanies (`B`) and
    // covering everything that will still be in the vault at `T`, since `A` and `B`
    // are swept away before then. That union is the point: it is the residual's
    // coverage denominator, and a residual over an input its own spend already
    // consumed would be inadmissible at fire time for a reason unrelated to the
    // two-slot record.
    let escape_class_b = vault.escape_over(&[&coin_b])?;
    let residual_b = vault.escape_over(&[&coin_c, &coin_d])?;
    let duress = vault.request(&escape_class_b, &residual_b, DURESS_PIN)?;
    let (duress_residual_id, _) = vault.signed_escape_candidate(&duress)?;
    let duress_signed = Psbt::from_str(&duress.psbt)?;
    let duress_sent_at = unix_now()?;
    let duress_timed = vault.honest[0].sign_timed(&duress)?;
    let duress_cover = ResponseCover {
        commitment_id: vault.expected_commitment_id(&duress_signed, duress.expiry),
        sent_at: duress_sent_at,
        received_at: unix_now()?,
    };
    let duress_accepted = expect_accepted(&duress_timed.response, "duress-pin escape-class spend")?;
    if duress_accepted.remaining_secs != normal_accepted.remaining_secs {
        return Err(format!(
            "escape-class settled differently by pin ({} normal vs {} duress)",
            normal_accepted.remaining_secs, duress_accepted.remaining_secs
        )
        .into());
    }
    let escape_class_b_txid = escape_class_b.unsigned_tx.compute_txid().to_string();
    vault.wait_for_tx(&escape_class_b_txid, EXPECT_TIMEOUT)?;
    let normal_body = pin_invariant_body(&normal_timed.body, &normal_cover)?;
    let duress_body = pin_invariant_body(&duress_timed.body, &duress_cover)?;
    if normal_body != duress_body {
        return Err(format!(
            "escape-class silence break: the complete /sign response differs by pin beyond its \
             request-dependent fields: {normal_body} normal vs {duress_body} duress"
        )
        .into());
    }
    let (normal_size, duress_size) = (normal_timed.body.len(), duress_timed.body.len());
    if normal_size != duress_size {
        return Err(format!(
            "escape-class silence break: response size differs by pin ({normal_size} normal vs \
             {duress_size} duress bytes)"
        )
        .into());
    }
    std::thread::sleep(SETTLE);
    let events_after = vault.events_snapshot()?;
    if events_before != events_after {
        return Err(format!(
            "escape-class silence break: /events changed on an honest daemon across a \
             duress-only interval: {events_before:?} → {events_after:?}"
        )
        .into());
    }
    let events_alerts: usize = events_after
        .iter()
        .map(|(_, projection)| events_alert_count(projection))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .sum();
    // Single wall-clock samples flake under concurrent bitcoind/node work. Repeat
    // the exact accepted pairs with fresh coordinator nonces, interleaved by pin and
    // alternated by parity so neither pin is systematically first, and compare
    // medians.
    //
    // These samples deliberately ride the IDEMPOTENT path, which is the honest
    // scope of this scenario's claim: an escape-class spend settles at ingress, so
    // what is compared here is the pin evaluation plus the cached-verdict return.
    // Both PIN Argon2 evaluations run before the anti-replay lookup
    // (`handle_sign_after_lock` charges the attempt budget at step 1 and consults
    // the log at step 4), so a short-circuiting pin compare is still measurable.
    // `two_spend_probe` is what covers the fresh-registration path.
    //
    // SIZED TO THE SURVIVING HARD GATE, which is `assert_pin_cost_reached_the_node`'s
    // per-pin median, not the skew. The skew is advisory now
    // (`pin_latency_advisory`), so buying more samples buys only a prettier report —
    // while the budget check below turns an over-long loop into a scenario ABORT,
    // because these Argon2-heavy requests must finish before the real duress `T`.
    // Four per pin keeps the alternating lead order balanced and supplies a replicated
    // upper median, which is all a one-sided floor with three orders of magnitude of
    // headroom needs. What the reduction from eight does cost is stated rather than
    // waved away: each sample hard-gates `expect_accepted` on the idempotent
    // resubmission, so four acceptance checks per pin went with it — a
    // repeated identical replay of a path already covered by its own deterministic
    // test, which is why the trade is worth taking. Unlike `two_spend_probe`, whose
    // per-sample BODY/SIZE equality is a distinct comparison at every count, nothing
    // here compares more as the count grows. Widening the abort threshold instead would
    // be the "loosen the constant" move bead btc-policy-c9r forbids.
    const SAMPLES: usize = 4;
    let sample_requests = u32::try_from(SAMPLES.saturating_mul(2))?;
    let measured_pin_work = one_argon2 * PIN_EVALUATIONS_PER_SIGN * sample_requests;
    // From the duress carrier's first_seen until the normal no-op window is fully
    // observable there are `duress_delay - NO_OP_CONTROL_GUARD_SECS` seconds. The
    // `/events` settle consumes a fixed part of that interval before these
    // Argon2-heavy requests start. Refuse a calibration that cannot fit by arithmetic;
    // otherwise the loop can cross the real duress T and manufacture a false
    // normal-slot violation — this abort protects the scenario's OTHER hard
    // assertions, not the advisory skew. Variable RPC/mining overhead is still caught
    // by the adjacent before/after deadline guards below.
    let sample_window = Duration::from_secs(
        vault
            .params
            .duress_delay_secs
            .saturating_sub(NO_OP_CONTROL_GUARD_SECS),
    )
    .saturating_sub(SETTLE);
    if measured_pin_work >= sample_window {
        return Err(format!(
            "escape-class timing calibration cannot fit before the no-op control: {sample_requests} \
             requests × {PIN_EVALUATIONS_PER_SIGN} measured Argon2 evaluations consume \
             {measured_pin_work:?}, but only {sample_window:?} remains after the fixed events \
             settle and the {NO_OP_CONTROL_GUARD_SECS}s guard. Lower PIN_COST_TARGET or lengthen \
             this scenario's duress delay"
        )
        .into());
    }
    let mut normal_timings = Vec::with_capacity(SAMPLES);
    let mut duress_timings = Vec::with_capacity(SAMPLES);
    for sample in 0..SAMPLES {
        let normal_sample = || -> Result<Duration, Error> {
            let request = vault.request_at(&escape_class, &residual, NORMAL_PIN, normal.expiry)?;
            let timed = vault.honest[0].sign_timed(&request)?;
            expect_accepted(
                &timed.response,
                &format!("normal escape-class timing sample {sample}"),
            )?;
            Ok(timed.elapsed)
        };
        let duress_sample = || -> Result<Duration, Error> {
            let request =
                vault.request_at(&escape_class_b, &residual_b, DURESS_PIN, duress.expiry)?;
            let timed = vault.honest[0].sign_timed(&request)?;
            expect_accepted(
                &timed.response,
                &format!("duress escape-class timing sample {sample}"),
            )?;
            Ok(timed.elapsed)
        };
        if sample % 2 == 0 {
            normal_timings.push(normal_sample()?);
            duress_timings.push(duress_sample()?);
        } else {
            duress_timings.push(duress_sample()?);
            normal_timings.push(normal_sample()?);
        }
    }
    normal_timings.sort_unstable();
    duress_timings.sort_unstable();
    let normal_median = normal_timings[SAMPLES / 2];
    let duress_median = duress_timings[SAMPLES / 2];
    let skew = normal_median.abs_diff(duress_median);
    // Below one measured Argon2 evaluation at this federation's enrolment cost — see
    // `calibrate_pin_cost`. A fixed millisecond value would say nothing about
    // whether an extra evaluation is detectable.
    let reference = pin_latency_reference(one_argon2);
    // Still a hard gate, because what it detects is a pin-enrolment CONFIGURATION
    // regression — a three-orders-of-magnitude effect — rather than the ~199 ms timing
    // skew that turned out to be unmeasurable here. It is not noise-free either; see
    // the note at the two-spend probe's call and `assert_pin_cost_reached_the_node`.
    assert_pin_cost_reached_the_node(
        "escape-class timing",
        &[("normal", normal_median), ("duress", duress_median)],
        one_argon2,
        pin_m_cost_kib,
    )?;
    // Advisory. This scenario is the one whose skew measured 2.27 ms and then
    // 317.6 ms on two consecutive CI runs of the same commit — the clearest available
    // demonstration that the measurement is noise, not signal. The cached escape-class
    // ingress shape it was covering is now gated deterministically
    // by `channel::duress::normal_and_duress_ingress_op_sequences_match_on_a_replay_cached_escape_class_spend`.
    let timing_advisory = pin_latency_advisory(
        "escape-class median settlement latency",
        skew,
        reference,
        within_pin_spread(&normal_timings, &duress_timings),
        normal_median,
        duress_median,
        SAMPLES,
    );

    // Confirm both completed spends before `T`, so the residual's coverage
    // denominator at fire time is exactly what remains in the vault: `C ∪ D`.
    vault.mine(1)?;
    // This confirmation is a PRECONDITION of the no-op control below, not just of the
    // duress sweep. `escape_sweep_policy_admissible` (`vault-node/src/lib.rs`) requires
    // the paired leg confirmed before it will release a residual sweep, so until this
    // block lands a live normal slot could not have swept EITHER. Read after
    // `normal_slot_deadline` and "the normal residual never broadcast" stops
    // distinguishing an inert slot from a live one that was merely gated — the control
    // passes vacuously.
    //
    // Nothing upstream bounds this instant: the calibration guard above bounds the
    // sampling loop's PREDICTED Argon2 work against the duress delay, not the wall
    // clock, and not the `control_separation_secs` already spent separating the two
    // carriers. So check it directly and fail loudly, exactly as the two
    // `duress_slot_deadline` guards below do for their own read window.
    let confirmed_by = unix_now()?;
    if confirmed_by >= normal_slot_deadline {
        return Err(format!(
            "the escape-class leg confirmed at {confirmed_by}, at or after the instant a live \
             normal slot would have fired ({normal_slot_deadline}). Until it confirmed, the \
             residual sweep was refused for coverage under either pin, so the no-op control below \
             could not tell an inert normal slot from a gated live one. Lower PIN_COST_TARGET or \
             lengthen this scenario's duress delay"
        )
        .into());
    }

    // -- the NORMAL pin's delayed slot is a no-op --------------------------
    //
    // A control, not an inference. Had the normal pin armed, its delayed slot would
    // have fired at `normal_slot_deadline` — strictly earlier than the duress `T`,
    // because the duress request came later. So wait past that instant and require
    // no honest node to be locked down and the normal residual to be unbroadcast.
    // Without this, "no-op" is asserted by nothing: the later lockdown is equally
    // consistent with either pin having scheduled it.
    //
    // Past the whole release window, not just past the deadline: a slot that fired at
    // `normal_slot_deadline` still has its combine and broadcast ticks to run, and the
    // separation installed before the duress request is what keeps this read inside
    // the window it must stay in.
    vault.wait_past_escape_release_window(
        normal_accepted.first_seen,
        normal_confirmation_upper_bound,
    )?;
    // The control is only meaningful strictly BEFORE the duress T; past it, a
    // lockdown is explained by either pin and the check proves nothing either way.
    // The margin is `NO_OP_CONTROL_GUARD_SECS`, deliberately installed above by
    // holding the duress carrier back — but the sampling loop runs inside the same
    // window, so say so loudly if it ever closes, rather than reporting an
    // inconclusive run as a pass or a failure.
    // The node's own ingest instant again, for the same reason: the real duress `T`
    // is measured from `first_seen`, and using the earlier send-time clock would
    // declare this window closed while it was in fact still open.
    let duress_slot_deadline = duress_accepted
        .first_seen
        .saturating_add(vault.params.duress_delay_secs);
    let now = unix_now()?;
    if now >= duress_slot_deadline {
        return Err(format!(
            "the no-op control window closed before it could be read: the duress T \
             ({duress_slot_deadline}) arrived at or before the normal pin's hypothetical fire \
             time plus its release window ({now}). The two requests need to be far enough apart \
             that a lockdown observed here could only have come from the normal pin"
        )
        .into());
    }
    // Every honest node, not just the one that took the request over `/sign`. The
    // carrier fans out to the peers, and each evaluates the pin and decides to arm
    // independently (`vault-node/src/lib.rs`), so a regression that misclassified the
    // normal pin on the `/channel` ingress path alone would lock down nodes 1..n while
    // node 0 stayed clean and this control reported a no-op.
    for index in 0..vault.honest.len() {
        if vault.is_locked_down(index)? {
            return Err(format!(
                "the NORMAL pin's delayed slot is not a no-op: node_id {} locked down by \
                 {normal_slot_deadline}, the moment a normal-pin arm would have fired — the \
                 duress T is later than this",
                vault.honest[index].node_id
            )
            .into());
        }
    }
    let residual_txid = residual.unsigned_tx.compute_txid().to_string();
    if vault.in_mempool_or_chain(&residual_txid)? {
        return Err(format!(
            "the NORMAL pin's residual sweep {residual_txid} fired; that slot must be inert, and \
             its coin is spent by nothing else in this scenario"
        )
        .into());
    }
    let observed_by = unix_now()?;
    if observed_by >= duress_slot_deadline {
        return Err(format!(
            "the no-op control window closed while reading all honest daemons and the residual: \
             the duress T ({duress_slot_deadline}) arrived by {observed_by}. Those observations \
             can no longer attribute a lockdown or residual absence to the NORMAL slot"
        )
        .into());
    }

    // -- the DURESS pin's delayed slot is live -----------------------------
    //
    // Both halves of it: unconditional Lockdown at T, and the residual sweep over
    // the union of inputs disjoint from the spend it accompanied.
    let all: Vec<usize> = (0..vault.honest.len()).collect();
    vault.wait_for_lockdown(
        &all,
        EXPECT_TIMEOUT + Duration::from_secs(vault.params.duress_delay_secs),
    )?;
    let residual_b_txid = residual_b.unsigned_tx.compute_txid().to_string();
    vault
        .wait_for_tx(
            &residual_b_txid,
            EXPECT_TIMEOUT + Duration::from_secs(vault.params.combine_slack_secs),
        )
        .map_err(|e| {
            format!(
                "the DURESS pin's residual sweep never fired ({e}); it sweeps {} and {}, \
                 disjoint from the escape-class spend and covering the whole remaining vault, \
                 so the delayed slot should have completed it at T. Last log: {}",
                coin_c.outpoint,
                coin_d.outpoint,
                vault.honest[0].log_tail()
            )
        })?;
    // And the transaction bitcoind accepted really did sweep both coins, not just
    // the locally built candidate handed to the federation.
    let fired_residual = vault.raw_transaction(&residual_b_txid)?;
    let actual_inputs: Vec<_> = fired_residual
        .input
        .iter()
        .map(|input| input.previous_output)
        .collect();
    let expected_inputs = [coin_c.outpoint, coin_d.outpoint];
    if actual_inputs.len() != expected_inputs.len()
        || expected_inputs
            .iter()
            .any(|expected| !actual_inputs.contains(expected))
    {
        return Err(format!(
            "the residual sweep bitcoind accepted did not span the union {expected_inputs:?}: actual inputs {actual_inputs:?}"
        )
        .into());
    }
    vault.mine(1)?;

    // -- the normal slot released nothing, either --------------------------
    //
    // The sweep that just fired is this federation's partial-path control: escape-role
    // partials for the duress residual reached the adversary over the same listener
    // and decoder the absence below is read from, so a zero there is evidence rather
    // than a deaf listener.
    let swept = vault.wait_for_escape_partials(&duress, 1, SETTLE)?;
    vault.assert_wiretap_decoded("escape-class no-op control")?;
    // The other half of the no-op control, and the stronger half. The on-chain read
    // above says the normal residual never CONFIRMED; this says no honest node ever
    // RELEASED a share for it. With `C = t−1` compromised identities, one honest share
    // is all the adversary needs to finalize that transaction itself
    // (`combine_with_compromised` does exactly this elsewhere), so a slot that leaked
    // a partial while the federation's own combine never ran would leave the chain
    // exactly as clean as a slot that stayed inert.
    //
    // Read once, here, rather than in the pre-`T` window: a non-selected escape is
    // unreleasable for the store's whole life — `slot_active` gates an Escape slot on
    // `armed.escape_commitment_id == candidate.commitment_id`
    // (`vault-node/src/channel.rs`) — so this absence is not time-boxed the way the
    // chain read is, and taking it last puts every partial the run ever produced in
    // hand.
    let leaked = vault.validated_escape_partials(&normal)?;
    if !leaked.is_empty() {
        return Err(format!(
            "the NORMAL pin's delayed slot is not a no-op: honest node_id(s) {leaked:?} released \
             a partial for its residual {residual_txid}. With {C} compromised identities that \
             share is externally completable, so the residual's absence from the chain is not \
             evidence the slot stayed inert"
        )
        .into());
    }
    vault.assert_no_unexpected_partials(
        "escape-class global partial backstop",
        &[
            control_id.as_str(),
            normal_accepted.commitment_id.as_str(),
            duress_accepted.commitment_id.as_str(),
            duress_residual_id.as_str(),
        ],
    )?;
    // The normal residual's CHAIN absence is deliberately not re-checked here. It
    // spends `D`, which the duress residual just swept, so past this point it is
    // unbroadcastable no matter what the normal slot did — an assertion that cannot
    // fail is not evidence, and reporting one as though it were is the failure mode
    // this scenario was rebuilt to remove. The falsifiable chain read is the pre-`T`
    // one above, taken while `D` was still spendable; the release read just above is
    // falsifiable at any time.
    assert_no_theft(&vault)?;

    Ok(format!(
        "escape-class completes immediately under both pins (both spends {escape_class_txid} and \
         {escape_class_b_txid} reached the chain, complete {normal_size}B /sign body equal modulo \
         request fields, /events unchanged ({events_alerts} alert(s) either side; live positive \
         control observed {events_control_alerts} across {} honest nodes), \
         remaining_secs 0; wall-clock timing is ADVISORY ONLY (one Argon2 = \
         {one_argon2:?} at {pin_m_cost_kib} KiB): {timing_advisory}); \
         the duress pin's delayed slot fired BOTH Lockdown at T and the \
         residual sweep {residual_b_txid} over the union of 2 inputs disjoint from its spend \
         ({} honest escape partial(s) observed); while the normal pin's slot stayed inert past a \
         full release window after the instant it would have fired and before the duress T, with \
         its coin still spendable (no lockdown on any of {} honest nodes, residual never \
         broadcast, and 0 honest partials ever released for it — against a control that heard \
         {control_signers} honest sender(s))",
        vault.honest.len(),
        swept.len(),
        vault.honest.len()
    ))
}

// ---------------------------------------------------------------------------
// ADR-0012 V0-4 implementation-semantics checklist
//
// Three of the checklist's load-bearing semantics name an adversarial regtest
// scenario each, and each is a TIMING or ORDERING property that a unit test can
// assert about the state machine but only a live federation can demonstrate end to
// end: the arm has to actually race an installed timer, an actual lockout has to be
// reached by flooding a running daemon, and an actual cached verdict has to be
// consulted. V0-4b-core owns the state machine and its unit tests; these are the
// empirical counterparts.

/// **Atomic monotonic Armed overlay.** A hot spend pending under the NORMAL pin,
/// with the duress carrier arriving in the last seconds before its Hold expires.
///
/// This is the sharpest form of the release-gate: the pending candidate already has
/// its fire window installed and its partial already signed at ingress, so arming
/// has to reach INTO that state and suppress it, not merely refuse things that
/// arrive later. If the overlay were applied only to future releases, or applied
/// non-atomically, the pending spend would slip out in the gap — a completed coerced
/// spend, which is the theft class the whole design closes.
///
/// The duress carrier is delivered to EVERY node here. Censorship is the separate,
/// deliberately-unclosed residual, and [`censorship_residual_bounded`] bounds it;
/// what is under test here is that an uncensored arm wins the race.
fn hold_expiry_race() -> Result<String, Error> {
    const HOLD: u64 = 30;
    /// How long before the pending spend's fire time the wrench lands. Short enough
    /// that the arm genuinely races the installed timer rather than arriving in
    /// comfortable time, long enough that a slow localhost round trip does not push
    /// the request past the fire itself and turn a race into a no-op.
    const WRENCH_LEAD_SECS: u64 = 4;

    let vault = Vault::build(&Setup {
        hold_secs: HOLD,
        duress_delay_secs: 5,
        epsilon_secs: 1,
        ..Setup::default()
    })?;

    // The PER-NODE partial-path control, taken while the federation is whole and
    // before anything is pending. The headline claim below — zero honest partials for
    // the PENDING commitment — ranges over every honest node, and release is a
    // per-node gate, so the single escape share this scenario later waits for shows
    // only that the decoder works and that SOME sender is audible. A node whose
    // fan-out to the adversary's endpoints were silently broken would then read
    // exactly like a node whose freeze held.
    let control_coin = vault.fund_extra(Amount::from_sat(20_000_000))?;
    let (control_id, control_signers) = vault.wiretap_positive_control(&control_coin)?;

    let coerced_coin = vault.fund_extra(Amount::from_sat(200_000_000))?;

    // The pending spend: an ordinary, fully authorized NORMAL-pin hot spend, alive
    // at every honest node with its partial signed and its fire window installed.
    let pending = vault.hot_spend(&vault.vault_utxo, Amount::from_sat(400_000_000))?;
    let pending_request =
        vault.request(&pending, &vault.escape_for(&vault.vault_utxo)?, NORMAL_PIN)?;
    let mut pending_id = None;
    // The fire time comes from the NODES, not from the coordinator's clock after the
    // relay loop: `Accepted` reports the absolute fire time as `first_seen +
    // remaining_secs` (vault-proto), fixed at first acceptance. Re-deriving it as
    // `now + HOLD` would silently subtract the whole relay latency from the intended
    // lead — and the `lead == 0` guard below, reading the same skewed value, could
    // not detect the erosion. Take the EARLIEST node's fire time: that is the first
    // instant any partial could be released, so it is what the wrench has to beat.
    let mut pending_fires_at = u64::MAX;
    for (index, response) in vault.relay_all_fresh(&pending_request)?.iter().enumerate() {
        let accepted = expect_accepted(response, &format!("pending hot spend at node {index}"))?;
        if accepted.remaining_secs == 0 {
            return Err(format!(
                "the pending spend settled at ingress (remaining_secs 0) instead of taking the \
                 {HOLD}s Hold; there would be no pending window left to race"
            )
            .into());
        }
        pending_fires_at =
            pending_fires_at.min(accepted.first_seen.saturating_add(accepted.remaining_secs));
        pending_id = Some(accepted.commitment_id);
    }
    let pending_id = pending_id.ok_or("no node acknowledged the pending spend")?;
    let pending_txid = pending.unsigned_tx.compute_txid().to_string();
    // Make the pre-arm candidate genuinely ready to finalize at Hold expiry. Each
    // node gets the compromised minority's holder receipts and valid partials while
    // the request is still NORMAL, so a missing Armed overlay cannot hide behind an
    // unconfirmed holder slot or a one-share local PSBT.
    vault.confirm_with_compromised(&pending_request)?;
    let signed_pending = Psbt::from_str(&pending_request.psbt)?;
    // As in `arm_split_closed`: no count-against-its-own-loop-bound guard here. Any
    // reply that is not ACCEPTED already returns `Err` from inside
    // `furnish_compromised_partials`, so reaching this line IS the evidence that every
    // node took every compromised share. The count survives only as a scorecard number.
    let pending_partials = vault.furnish_compromised_partials(
        &(0..vault.honest.len()).collect::<Vec<_>>(),
        &pending_id,
        &signed_pending,
        "spend",
    )?;

    // Wait until the pending spend is seconds from firing, then apply the wrench.
    // The coerced spend rides its own coin so it cannot suppress the pending one by
    // merely conflicting with it; the escape sweeps BOTH, which is also what keeps
    // the fire-time coverage denominator whole once the pending spend is frozen.
    let wrench_at = pending_fires_at.saturating_sub(WRENCH_LEAD_SECS);
    while unix_now()? < wrench_at {
        std::thread::sleep(Duration::from_millis(100));
    }
    let coerced = vault.hot_spend(&coerced_coin, Amount::from_sat(100_000_000))?;
    let escape = vault.escape_over(&[&vault.vault_utxo, &coerced_coin])?;
    let duress_request = vault.request(&coerced, &escape, DURESS_PIN)?;
    let (escape_id, _) = vault.signed_escape_candidate(&duress_request)?;
    for (index, response) in vault.relay_all_fresh(&duress_request)?.iter().enumerate() {
        expect_accepted(response, &format!("duress carrier at node {index}"))?;
    }
    // Direct acceptance establishes each node's own holder slot. Synchronously add
    // the compromised minority's t−1 authenticated receipts so every node crosses
    // the confirmation timing gate before the pending fire time. This is setup
    // evidence only; the safety assertion below remains zero released partials.
    vault.confirm_with_compromised(&duress_request)?;
    // Sample the lead AFTER the fan-out, not before it. `relay_all_fresh` is fully
    // sequential over the honest set, so a lead read before the loop is the lead the
    // FIRST node got; the last node's is whatever survived the round trips. Both the
    // guard below and the scorecard line claim a lead for the federation, so they
    // have to quote the smallest one — the same erosion the `pending_fires_at`
    // derivation above already accounts for on the other side.
    let lead = pending_fires_at.saturating_sub(unix_now()?);
    if lead == 0 {
        return Err(format!(
            "the duress carrier did not reach the federation until the pending spend's fire time; \
             this run measured nothing about the race (intended lead {WRENCH_LEAD_SECS}s)"
        )
        .into());
    }

    // Past both the pending fire time and the combine window, so a partial that was
    // ever going to be released has been. Measured from the node-reported fire time
    // for the same reason it was derived there.
    let remaining = pending_fires_at.saturating_sub(unix_now()?);
    std::thread::sleep(Duration::from_secs(
        remaining + vault.params.combine_slack_secs + 15,
    ));

    // The property: the already-pending, already-signed candidate was suppressed.
    //
    // Read this pair the way the fire-time scenarios label the identical pattern: the
    // escape sweeps BOTH coins, so once the sweep reaches the mempool Core rejects
    // either of these as a conflict no matter what the release gate did. They are the
    // outer safety net; the released-partial oracle below — zero honest partials for
    // the pending commitment, taken from the adversary's own endpoints — is the
    // property this scenario actually demonstrates.
    if vault.in_mempool_or_chain(&pending_txid)? {
        return Err(format!(
            "THE OVERLAY IS NOT ATOMIC: the pending hot spend {pending_txid} completed even \
             though the duress carrier arrived {lead}s before its fire time. A spend that was \
             already pending when the wrench landed must be frozen, not merely blocked from \
             re-registering"
        )
        .into());
    }
    let coerced_txid = coerced.unsigned_tx.compute_txid().to_string();
    if vault.in_mempool_or_chain(&coerced_txid)? {
        return Err("the coerced hot spend completed".into());
    }
    // The sweep firing is this federation's partial-path control: escape-role
    // partials arrive over the same listener and decoder that the pending-partial
    // absence below is read from.
    let escape_txid = escape.unsigned_tx.compute_txid().to_string();
    vault.wait_for_tx(&escape_txid, EXPECT_TIMEOUT)?;
    vault.wait_for_escape_partials(&duress_request, 1, SETTLE)?;
    vault.assert_wiretap_decoded("hold-expiry-race zero-partial assertion")?;
    let released = vault.honest_partials_for(&pending_id);
    if !released.is_empty() {
        return Err(format!(
            "honest node_id(s) {released:?} released the PENDING spend's partial after the arm. \
             Arming must suppress every existing hot-partial release under the same store lock \
             that would release it — a partial in the adversary's hands is combinable with its \
             own {C}"
        )
        .into());
    }
    vault.assert_no_unexpected_partials(
        "hold-expiry-race global partial backstop",
        &[control_id.as_str(), escape_id.as_str()],
    )?;
    let all: Vec<usize> = (0..vault.honest.len()).collect();
    vault.wait_for_lockdown(&all, EXPECT_TIMEOUT)?;
    vault.mine(1)?;
    assert_no_theft(&vault)?;

    Ok(format!(
        "a locally finalizable hot spend pending at all {} honest nodes ({pending_partials} \
         compromised partial payloads furnished before the arm) was frozen by a confirmed duress \
         carrier arriving {lead}s before its {HOLD}s Hold expired: 0 partials released for the \
         pending commitment (against a control that heard {control_signers} honest sender(s)), it \
         never broadcast, the sweep {escape_txid} fired over both coins, unconditional Lockdown \
         at T, no theft",
        vault.honest.len()
    ))
}

/// **Fail-closed lockout.** Flood a node with wrong pins until it is locked out,
/// then hand it the real duress carrier.
///
/// The invariant has two halves and they pull in opposite directions, which is why
/// it needs demonstrating rather than asserting. A locked-out node must SIGN
/// NOTHING — otherwise flooding would be a way to get a coerced spend signed. But a
/// valid duress pin must still ARM — otherwise flooding `t` nodes into lockout would
/// be a way to disable duress entirely, holding the federation below the
/// confirmations arming needs. So the same request must be refused and effective at
/// once.
///
/// The refusal is also uniform: a locked-out node answers a VALID duress pin exactly
/// as it answers a wrong guess, so an attacker who floods a node cannot then read the
/// victim's pin off the response.
///
/// The flood is delivered to EVERY honest node, which is both the strongest form of
/// the attack and the only deterministic one. A flood aimed at a single node does
/// not stay there: wrong-pin verdicts are staged and propagated like every other
/// verdict (so a coordinator cannot distinguish a propagated match from an
/// unpropagated wrong guess), so peers evaluate the relayed guesses against their own
/// budgets and lock out too. Flooding all of them directly makes the precondition
/// explicit instead of resting on that propagation.
fn lockout_then_duress() -> Result<String, Error> {
    /// Comfortably past `pin_attempt_budget.max_attempts` (default 5). Overshooting
    /// is free — a locked node's wrong pin does not extend its lockout — and it
    /// keeps the scenario from depending on the exact configured budget.
    const WRONG_PIN_FLOOD: usize = 8;

    let vault = Vault::build(&Setup {
        hold_secs: 30,
        duress_delay_secs: 8,
        epsilon_secs: 1,
        ..Setup::default()
    })?;
    if WRONG_PIN == NORMAL_PIN || WRONG_PIN == DURESS_PIN {
        return Err("the flood pin must not be an enrolled pin".into());
    }

    // The partial-path control, taken BEFORE the flood — it is the only window in
    // which one can be taken. Once the federation is locked out nothing signs at
    // all, by design, so this scenario's zero-partial claims have no in-scenario
    // sweep to lean on and would otherwise be indistinguishable from a deaf
    // listener.
    let control_coin = vault.fund_extra(Amount::from_sat(100_000_000))?;
    let (control_id, control_signers) = vault.wiretap_positive_control(&control_coin)?;

    // Flood every honest node. Each guess is a fully valid coordinator-authenticated
    // request under a FRESH nonce — a replay would be refused at the freshness gate
    // before ever reaching the pin, and would charge no budget.
    let bait = vault.hot_spend(&vault.vault_utxo, Amount::from_sat(1_000_000))?;
    let bait_escape = vault.escape_for(&vault.vault_utxo)?;
    let guess = vault.request(&bait, &bait_escape, WRONG_PIN)?;
    // Per node, not once for the federation. Wrong-pin verdicts propagate, so a node
    // reached later in this loop is typically already locked by the guesses aimed at
    // its peers and reports its lockout on attempt 1 — reporting node 0's count for
    // all of them would state something the run did not observe.
    let mut first_locked: Vec<usize> = Vec::with_capacity(vault.honest.len());
    let mut locked_refusal_bodies = Vec::with_capacity(vault.honest.len());
    for index in 0..vault.honest.len() {
        let mut locked_refusal_body = None;
        let mut locked_at = None;
        for attempt in 0..WRONG_PIN_FLOOD {
            let fresh = vault.coordinator.authorize(
                &vault.secp,
                &wallet_id(&vault.descriptor),
                guess.clone(),
            )?;
            let probe = vault.honest[index].sign_timed(&fresh)?;
            let refusal = expect_refusal(
                &probe.response,
                &format!("wrong-pin guess {attempt} at node {index}"),
            )?;
            if refusal.code != RefusalCode::BadPin {
                return Err(format!(
                    "wrong-pin guess {attempt} at node {index} was refused as {:?}/{}, not \
                     BAD_PIN: {}",
                    refusal.code, refusal.check, refusal.detail
                )
                .into());
            }
            if refusal.check == "pin_attempt_budget" {
                locked_refusal_body = Some(probe.body);
                if locked_at.is_none() {
                    locked_at = Some(attempt + 1);
                }
            }
        }
        let body = locked_refusal_body.ok_or_else(|| {
            format!(
                "node {index} never locked out after {WRONG_PIN_FLOOD} wrong pins, so it returned no locked-out wrong-PIN response to use as the silence control; without a real lockout at every node this scenario tests nothing"
            )
        })?;
        // Recorded in the same branch that captured `body`, so a captured body
        // always has an attempt number behind it.
        first_locked.push(locked_at.ok_or("a locked-out body was captured with no attempt count")?);
        locked_refusal_bodies.push(body);
    }

    // Now the wrench, delivered to every LOCKED-OUT node. Each refusal must be
    // byte-identical to what a wrong guess just got — that uniformity is what stops
    // an attacker from reading the pin off a flooded node.
    let coerced = vault.hot_spend(&vault.vault_utxo, Amount::from_sat(400_000_000))?;
    let escape = vault.escape_for(&vault.vault_utxo)?;
    let duress_request = vault.request(&coerced, &escape, DURESS_PIN)?;
    let coerced_id = vault.expected_commitment_id(
        &Psbt::from_str(&duress_request.psbt)?,
        duress_request.expiry,
    );
    for (index, wrong_pin_body) in locked_refusal_bodies.iter().enumerate() {
        let fresh = vault.coordinator.authorize(
            &vault.secp,
            &wallet_id(&vault.descriptor),
            duress_request.clone(),
        )?;
        let probe = vault.honest[index].sign_timed(&fresh)?;
        expect_code(
            &probe.response,
            RefusalCode::BadPin,
            "pin_attempt_budget",
            &format!("valid duress carrier at locked-out node {index}"),
        )
        .map_err(|e| {
            format!(
                "SILENCE BREAK or lockout gap: a locked-out node must answer a VALID duress pin \
                 exactly as it answers a wrong guess ({e})"
            )
        })?;
        if probe.body != *wrong_pin_body {
            return Err(format!(
                "SILENCE BREAK: locked-out node {index} returned different complete /sign bodies for a wrong PIN and the duress PIN (wrong={wrong_pin_body}, duress={})",
                probe.body
            )
            .into());
        }
    }
    // An upper bound on any `first_seen` a wrongly-registered coerced candidate could
    // carry: every delivery of it happened before this instant. A refused request
    // reports no `first_seen` of its own, so the absence reads below have to be timed
    // off this rather than off the node's own accounting.
    let carrier_delivered_by = unix_now()?;
    let coerced_txid = coerced.unsigned_tx.compute_txid().to_string();

    // The half that matters: refused-but-effective. The carrier is staged BEFORE the
    // lockout exit, so it propagates and each node self-holds and arms — observable
    // only as unconditional Lockdown at T, which is the point of an ingress that
    // leaks nothing. Every honest node in the federation is locked out at this
    // moment, so if lockout could suppress arming, duress would be disabled outright.
    let all: Vec<usize> = (0..vault.honest.len()).collect();
    vault
        .wait_for_lockdown(&all, EXPECT_TIMEOUT + Duration::from_secs(30))
        .map_err(|e| {
            format!(
                "a valid duress pin did not arm through a lockout ({e}); flooding the federation \
                 with wrong pins must not be a way to disable duress"
            )
        })?;

    // And a locked-out node signs nothing, so the outcome is pure denial: no partial
    // for the coerced candidate exists anywhere, and the sweep cannot fire either.
    // Funds sit frozen in the vault, which is the recovery exit, not theft.
    //
    // Read only past the FULL hot release window, not merely past Lockdown. Lockdown
    // lands at `first_seen + duress_delay` (8s here), while the failure this scenario
    // exists to catch — a locked-out node that nevertheless registered the coerced
    // candidate — would release at `first_seen + hold_secs` (30s) and combine for
    // `combine_slack_secs` beyond that. Reading at lockdown-plus-a-settle would take
    // every absence below ~20s before the earliest instant the leak could appear, so
    // the headline claim ("locked-out nodes signed nothing") is exactly the one that
    // could not fire. Same deadline every sibling scenario uses.
    vault.wait_past_hot_release_window(carrier_delivered_by)?;
    vault.assert_wiretap_decoded("lockout-then-duress zero-partial assertion")?;
    if vault.in_mempool_or_chain(&coerced_txid)? {
        return Err("the coerced hot spend completed against a locked-out federation".into());
    }
    let released = vault.honest_partials_for(&coerced_id);
    if !released.is_empty() {
        return Err(format!(
            "honest node_id(s) {released:?} released a coerced partial after the lockout flood; a \
             locked-out node must sign nothing"
        )
        .into());
    }
    let stray = vault.partial_commitments_outside(&[control_id.as_str()]);
    if !stray.is_empty() {
        return Err(format!(
            "the adversary collected honest candidate partial(s) for {stray:?} beyond the control \
             spend, from a federation in which every node is locked out"
        )
        .into());
    }
    assert_no_theft(&vault)?;

    Ok(format!(
        "control: {control_signers} honest partial(s) seen for a completed normal spend (the \
         wiretap is not deaf); all {} honest nodes locked out, at {first_locked:?} direct wrong \
         pins respectively (the later nodes lock earlier because wrong-pin verdicts propagate); \
         the valid duress carrier then got the IDENTICAL BAD_PIN/pin_attempt_budget \
         refusal a wrong guess gets at every one of them, and still armed — unconditional \
         Lockdown at T federation-wide. Locked-out nodes signed nothing, so the outcome is \
         denial: 0 coerced partials, coerced spend dead, funds frozen for recovery, no theft",
        vault.honest.len()
    ))
}

/// **Idempotency ordering.** A commitment already pending under the NORMAL pin,
/// resubmitted with the DURESS pin and a fresh nonce, must ARM.
///
/// This is the wrench as it most plausibly happens: the user had already sent a
/// payment when the attacker arrived, and the only thing left to coerce is a
/// resubmission of it. If the node consulted its cached verdict for the commitment
/// before processing the pin, it would answer from cache — the same `Accepted` it
/// gave the first time — and never arm. The response is deliberately identical
/// either way, so the pending spend's fate is the only evidence that the ordering is
/// right.
fn duress_resubmission() -> Result<String, Error> {
    let vault = Vault::build(&Setup {
        hold_secs: 30,
        duress_delay_secs: 8,
        epsilon_secs: 1,
        ..Setup::default()
    })?;

    // The PER-NODE partial-path control. This scenario's own comment marks the chain
    // read as secondary and names `honest_partials_for(&pending_id)` as the
    // falsifiable assertion — and that one ranges over every honest node. The escape
    // share waited for below is a decoder control and covers one sender at most, so
    // without this the falsifiable assertion is the one that could not fire for a
    // node whose transport to the adversary's endpoints had silently died.
    let control_coin = vault.fund_extra(Amount::from_sat(20_000_000))?;
    let (control_id, control_signers) = vault.wiretap_positive_control(&control_coin)?;

    // A perfectly ordinary hot spend, pending at every honest node.
    let spend = vault.hot_spend(&vault.vault_utxo, Amount::from_sat(400_000_000))?;
    let escape = vault.escape_for(&vault.vault_utxo)?;
    let normal_request = vault.request(&spend, &escape, NORMAL_PIN)?;
    let mut pending_id = None;
    // Per-node, because `first_seen` is each node's OWN ingress clock — comparing
    // node i's resubmission against node j's original would be comparing two
    // legitimately different values.
    let mut pending_first_seen = Vec::new();
    for (index, response) in vault.relay_all_fresh(&normal_request)?.iter().enumerate() {
        let accepted = expect_accepted(response, &format!("normal-pin spend at node {index}"))?;
        pending_first_seen.push(accepted.first_seen);
        pending_id = Some(accepted.commitment_id);
    }
    let pending_id = pending_id.ok_or("no node acknowledged the pending spend")?;
    let spend_txid = spend.unsigned_tx.compute_txid().to_string();

    // The SAME transaction pair, so the same commitment id and a live cached
    // verdict — only the pin and the nonce differ.
    let duress_request = vault.request_at(&spend, &escape, DURESS_PIN, normal_request.expiry)?;
    let (escape_id, _) = vault.signed_escape_candidate(&duress_request)?;
    let resubmitted_id = vault.expected_commitment_id(
        &Psbt::from_str(&duress_request.psbt)?,
        duress_request.expiry,
    );
    if resubmitted_id != pending_id {
        return Err(format!(
            "the resubmission is not the same commitment ({resubmitted_id} vs {pending_id}), so \
             it would never reach the cached verdict this scenario exists to order against"
        )
        .into());
    }
    for (index, response) in vault.relay_all_fresh(&duress_request)?.iter().enumerate() {
        let accepted = expect_accepted(response, &format!("duress resubmission at node {index}"))?;
        if accepted.commitment_id != pending_id {
            return Err(format!(
                "the duress resubmission was bound to {} rather than the pending {pending_id}",
                accepted.commitment_id
            )
            .into());
        }
        // The premise of the whole scenario is that this resubmission reaches the
        // node's CACHED verdict for an already-registered commitment — otherwise it
        // is just an ordinary fresh registration, and "the pin was processed before
        // the cache was consulted" is a claim about an ordering nothing exercised.
        // Matching `commitment_id` cannot show that: a fresh registration of the
        // same transaction pair derives the same id. `first_seen` can, and for free
        // — it is fixed at first acceptance and replayed verbatim on an idempotent
        // resubmission (`vault_proto::Accepted`), so a cache MISS would restamp it
        // to now.
        let original = pending_first_seen[index];
        if accepted.first_seen != original {
            return Err(format!(
                "the duress resubmission at node {index} was answered with first_seen {} rather \
                 than the {original} of the original acceptance, so it registered afresh instead \
                 of reaching the cached verdict this scenario exists to order the pin against",
                accepted.first_seen
            )
            .into());
        }
    }

    // The evidence. Lockdown at T proves the pin was processed BEFORE the cache was
    // consulted; the frozen pending spend proves the arm reached the candidate that
    // was already registered under the earlier verdict.
    let all: Vec<usize> = (0..vault.honest.len()).collect();
    vault
        .wait_for_lockdown(&all, EXPECT_TIMEOUT + Duration::from_secs(30))
        .map_err(|e| {
            format!(
                "the duress resubmission of an already-pending commitment did not arm ({e}); the \
                 pin/safety signal must be processed before any cached commitment verdict"
            )
        })?;
    std::thread::sleep(Duration::from_secs(
        vault.params.hold_secs + vault.params.combine_slack_secs + 5,
    ));
    // Secondary, and deliberately labelled as such. The escape sweeps `vault_utxo`,
    // which the pending spend also spends, and it fires at `T` (8s) — well before the
    // pending spend's 30s Hold would expire. So by the time this reads, a released
    // pending partial would most likely have been combined into a transaction the
    // mempool rejects as a conflict rather than one it accepts, and this check would
    // stay quiet. The overlap is forced: the escape's coverage denominator is the
    // whole vault, so it cannot avoid the pending spend's coin.
    //
    // The FALSIFIABLE assertion is the zero-partial read below — a released partial is
    // in the adversary's hands whether or not the transaction it belongs to ever wins
    // a mempool race. This check is kept for the case where the spend somehow does
    // land, not as the evidence the scenario rests on.
    if vault.in_mempool_or_chain(&spend_txid)? {
        return Err(format!(
            "the resubmitted spend {spend_txid} completed; a duress resubmission must freeze the \
             pending commitment, not return its cached normal verdict"
        )
        .into());
    }
    let escape_txid = escape.unsigned_tx.compute_txid().to_string();
    vault.wait_for_tx(&escape_txid, EXPECT_TIMEOUT)?;
    vault.wait_for_escape_partials(&duress_request, 1, SETTLE)?;
    vault.assert_wiretap_decoded("duress-resubmission zero-partial assertion")?;
    let released = vault.honest_partials_for(&pending_id);
    if !released.is_empty() {
        return Err(format!(
            "honest node_id(s) {released:?} released the pending spend's partial despite the \
             duress resubmission"
        )
        .into());
    }
    vault.assert_no_unexpected_partials(
        "duress-resubmission global partial backstop",
        &[control_id.as_str(), escape_id.as_str()],
    )?;
    vault.mine(1)?;
    assert_no_theft(&vault)?;

    Ok(format!(
        "a commitment pending under the normal pin at all {} honest nodes was resubmitted with \
         the duress pin under a fresh nonce: same commitment {pending_id}, same acknowledgement \
         shape, and it still armed — 0 partials released (the falsifiable read, against a control \
         that heard {control_signers} honest sender(s); the spend also never broadcast, though \
         its escape conflicts with it), the sweep {escape_txid} fired, unconditional Lockdown at \
         T, no theft",
        vault.honest.len()
    ))
}

// ---------------------------------------------------------------------------
// 8. process-kill / reboot-death

/// Reboot-death (ADR-0007, PICKED 2026-07-16): killing nodes costs sweep
/// redundancy, never safety.
///
/// Two deaths, deliberately separated:
///  - **process kill.** The deployment survives, yet the node still cannot come
///    back: `claim_process_generation` takes a one-shot marker on the config/key
///    inode, so a second generation is refused rather than resumed. Armed and
///    candidate state is RAM-only and cannot be reconstructed, so a resumed node
///    would be one signing without knowing what it had already frozen.
///  - **machine reboot.** The deployment goes too, so the node comes back bare —
///    no keys, no schedule, no partials — and cannot rejoin.
///
/// ADR-0012's checklist names BOTH sides of this and they are different claims, so
/// both are run: "kill one, assert the sweep still fires" is about redundancy
/// surviving, and "kill enough to drop below `t`, assert lockdown-only" is about
/// safety surviving its loss. A run that only ever drops below `t` never shows that
/// a depleted-but-sufficient armed set still completes — which is the half that
/// distinguishes reboot-death from simply breaking the federation.
fn reboot_death() -> Result<String, Error> {
    let survives = reboot_death_still_sweeps_above_threshold()?;
    let denied = reboot_death_below_threshold()?;
    Ok(format!("{survives}; {denied}"))
}

/// Arm `t+1` nodes, kill one before `T`, and require the sweep to STILL fire.
///
/// The federation shape is the knob: taking only ONE identity for the adversary
/// leaves `n − 1 = t + 1` honest daemons, so one death still leaves exactly `t`
/// armed — the boundary at which combining is possible. The adversary's remaining
/// identity withholds, as always, so the `t` survivors are the whole quorum.
fn reboot_death_still_sweeps_above_threshold() -> Result<String, Error> {
    let mut vault = Vault::build(&Setup {
        hold_secs: 90,
        // Wide enough that the kill lands before T even when a teardown takes its
        // full deadline; still well inside the Hold, so T is the duress delay rather
        // than the hot spend's own fire time.
        duress_delay_secs: 45,
        epsilon_secs: 1,
        compromised: 1,
        ..Setup::default()
    })?;
    if vault.honest.len() != T + 1 {
        return Err(format!(
            "the above-threshold reboot-death run needs t+1 = {} honest daemons, got {}",
            T + 1,
            vault.honest.len()
        )
        .into());
    }

    // The PER-NODE partial-path control, taken BEFORE the kill — `wiretap_positive_control`
    // demands a share from every honest daemon, so it can only run while the
    // federation is whole. The coerced-partial absence read at the end ranges over the
    // survivors, and with a single compromised listener here there is even less
    // redundancy in the transport than elsewhere: one dead sender path would read as
    // the freeze holding.
    let control_coin = vault.fund_extra(Amount::from_sat(20_000_000))?;
    let (control_id, control_signers) = vault.wiretap_positive_control(&control_coin)?;

    let coerced = vault.hot_spend(&vault.vault_utxo, Amount::from_sat(400_000_000))?;
    let escape = vault.escape_for(&vault.vault_utxo)?;
    let request = vault.request(&coerced, &escape, DURESS_PIN)?;
    let accepted = expect_accepted(
        &vault.relay_to(0, &request)?,
        "above-threshold reboot-death duress carrier",
    )?;
    // The escape's own commitment id, for the whole-run stray check at the end: the
    // sweep is supposed to release shares for it, so it is the one candidate besides
    // the control the adversary is entitled to observe.
    let (escape_id, _) = vault.signed_escape_candidate(&request)?;
    let coerced_txid = coerced.unsigned_tx.compute_txid().to_string();
    let escape_txid = escape.unsigned_tx.compute_txid().to_string();
    vault.wait_for_honest_relayers(&request.nonce, vault.honest.len(), EXPECT_TIMEOUT)?;
    vault.confirm_with_compromised(&request)?;

    // The kill must land BEFORE T, or this scenario tests nothing: if the sweep has
    // already fired with all `t+1` nodes alive, `wait_for_tx` below returns
    // instantly and the scorecard reports a depleted-armed-set result it never
    // exercised. `wait_for_honest_relayers` above is bounded by `EXPECT_TIMEOUT`,
    // which is the same order as this setup's `duress_delay_secs`, so on a loaded
    // machine that race is real rather than theoretical.
    //
    // Zero escape-role partials is the sharp form of the guard: no node can have
    // reached T, because a node at T releases its escape share to every peer —
    // including the adversary's sealed endpoint, which is exactly what
    // an exact candidate-partial read detects after the kill. Zero before, non-zero
    // after.
    let pre_kill_escape_partials = vault.validated_escape_partials(&request)?;
    if !pre_kill_escape_partials.is_empty() {
        return Err(format!(
            "the sweep was already under way before the kill ({} escape-role partial(s) already \
             released), so killing a node now would not test a depleted armed set at all; the \
             hostage window ({}s) is too short for this machine",
            pre_kill_escape_partials.len(),
            vault.params.duress_delay_secs
        )
        .into());
    }
    if vault.in_mempool_or_chain(&escape_txid)? {
        return Err(format!(
            "the sweep {escape_txid} broadcast with all {} nodes still alive, so the kill below \
             would prove nothing about combining at exactly t",
            vault.honest.len()
        )
        .into());
    }

    // One machine reboot: the deployment goes with it, so this node contributes no
    // partial to the combine that follows.
    let dead = vault.honest.remove(0);
    let dead_addr = dead.addr();
    let dead_id = dead.node_id;
    dead.destroy()?;
    if NodeProcess::is_serving(dead_addr) {
        return Err(format!(
            "node_id {dead_id} is still serving after its deployment was destroyed"
        )
        .into());
    }

    // Exactly `t` armed nodes remain. Lockdown is unconditional, and the sweep — the
    // part that DOES depend on the count — must still combine and broadcast.
    let survivors: Vec<usize> = (0..vault.honest.len()).collect();
    vault.wait_for_lockdown(&survivors, EXPECT_TIMEOUT + Duration::from_secs(45))?;
    vault
        .wait_for_tx(
            &escape_txid,
            EXPECT_TIMEOUT + Duration::from_secs(vault.params.combine_slack_secs),
        )
        .map_err(|e| {
            format!(
                "the sweep did not fire with {} armed nodes remaining, which is exactly the \
                 threshold t = {T}; killing one node must cost redundancy, not the sweep ({e}). \
                 Last log: {}",
                vault.honest.len(),
                vault.honest[0].log_tail()
            )
        })?;
    // The sweep firing is also this federation's partial-path control: escape-role
    // partials reached the adversary over the same listener and decoder the
    // coerced-partial absence below is read from.
    vault.wait_for_escape_partials(&request, 1, SETTLE)?;
    vault.wait_past_hot_release_window(accepted.first_seen)?;
    // SECONDARY, and labelled so — the same true-by-conflict pattern the sibling
    // scenarios call out. The armed escape sweeps `vault_utxo`, the coerced spend's
    // only input, and it has already reached the mempool by this line; Core would
    // reject the coerced spend as a conflict no matter what the release gate did. The
    // falsifiable claim is the zero-partial read below, which holds whether or not the
    // transaction a leaked share belongs to could win a mempool race.
    if vault.in_mempool_or_chain(&coerced_txid)? {
        return Err("the coerced spend completed even though the sweep fired".into());
    }
    // Immediately before the absence read, not before the wait above: a listener
    // that died — or an envelope that failed to decode — DURING the release window
    // is exactly the case that would turn a leaked partial into a false zero here.
    vault.assert_wiretap_decoded("above-threshold reboot-death partial assertions")?;
    let releasable = vault.honest_partials_for(&accepted.commitment_id);
    if !releasable.is_empty() {
        return Err(format!(
            "honest node_id(s) {releasable:?} released the coerced partial across the kill"
        )
        .into());
    }
    // The by-commitment read above only looks where the harness expects a leak. A
    // partial filed under ANY other commitment id — a regression that mis-keys the
    // candidate, say — is invisible to it and would leave a releasable honest share in
    // the adversary's hands unnoticed. The below-threshold twin runs this same
    // backstop; the allowlist is the control spend the adversary was entitled to see,
    // plus this run's own escape, whose shares the sweep is SUPPOSED to release.
    let stray = vault.partial_commitments_outside(&[control_id.as_str(), escape_id.as_str()]);
    if !stray.is_empty() {
        return Err(format!(
            "over the whole run the adversary collected honest candidate partial(s) for \
             {stray:?}, beyond the control spend and the armed escape it was entitled to see"
        )
        .into());
    }
    vault.mine(1)?;
    assert_no_theft(&vault)?;

    Ok(format!(
        "armed t+1 = {}, killed node_id {dead_id} before T → {} armed (= t) and the sweep \
         {escape_txid} still fired; coerced spend dead, 0 coerced partials and no stray \
         commitment (against a control that heard {control_signers} honest sender(s)), no theft",
        vault.honest.len() + 1,
        vault.honest.len()
    ))
}

/// With the armed set driven BELOW `t`, the sweep cannot combine and the outcome is
/// lockdown-only → recovery. That is denial, not theft, and Lockdown at `T` still
/// happens on every survivor because it is unconditional.
fn reboot_death_below_threshold() -> Result<String, Error> {
    // A wide hostage window, so the harness can drive the armed set below `t`
    // BEFORE `T` — otherwise the sweep would already have fired with a full
    // federation and the scenario would prove nothing about a depleted one.
    let mut vault = Vault::build(&Setup {
        hold_secs: 60,
        duress_delay_secs: 30,
        epsilon_secs: 1,
        ..Setup::default()
    })?;

    // The partial-path control, taken FIRST so it completes before the coerced
    // carrier is registered. Nothing sweeps in this run — that is the outcome under
    // test — so without a control the zero-coerced-partial claim below would read
    // identically from a listener that never received anything at all.
    let control_coin = vault.fund_extra(Amount::from_sat(100_000_000))?;
    let (control_id, control_signers) = vault.wiretap_positive_control(&control_coin)?;

    let coerced = vault.hot_spend(&vault.vault_utxo, Amount::from_sat(400_000_000))?;
    let escape = vault.escape_for(&vault.vault_utxo)?;
    let request = vault.request(&coerced, &escape, DURESS_PIN)?;
    let accepted = expect_accepted(&vault.relay_to(0, &request)?, "reboot-death duress carrier")?;
    let accepted_id = accepted.commitment_id.clone();
    let accepted_first_seen = accepted.first_seen;
    let (escape_id, _) = vault.signed_escape_candidate(&request)?;
    let coerced_txid = coerced.unsigned_tx.compute_txid().to_string();
    let escape_txid = escape.unsigned_tx.compute_txid().to_string();
    // Do not race a fixed sleep against the launch gate. An honest relay is emitted
    // only after that daemon independently processed the exact carrier. Once every
    // honest identity is visible on the adversary's wiretap, furnish each with the
    // compromised minority's receipts; the synchronous replies prove every node
    // crossed the holder-confirmation timing gate before any process is killed.
    vault.wait_for_honest_relayers(&request.nonce, vault.honest.len(), EXPECT_TIMEOUT)?;
    vault.confirm_with_compromised(&request)?;

    // Both kills must land BEFORE T — the same guard, and for the same reason, as
    // `reboot_death_still_sweeps_above_threshold`. Everything between here and the
    // kills is bounded well above this setup's hostage window: the relayer wait by
    // `EXPECT_TIMEOUT`, and `restart_must_be_refused` by its own 15s deadline. If T
    // has already passed, the full federation combined and swept, and the read below
    // would report that as "the escape combined with only 1 armed node(s), below the
    // threshold" — a safety violation attributed to the mechanism for a race the
    // harness lost.
    let pre_kill_escape_partials = vault.validated_escape_partials(&request)?;
    if !pre_kill_escape_partials.is_empty() || vault.in_mempool_or_chain(&escape_txid)? {
        return Err(format!(
            "the sweep was already under way before the kills ({} escape-role partial(s) \
             released) with all {} nodes alive, so driving the armed set below t now would prove \
             nothing about a depleted one; the hostage window ({}s) is too short for this machine",
            pre_kill_escape_partials.len(),
            vault.honest.len(),
            vault.params.duress_delay_secs
        )
        .into());
    }

    // -- process kill: no way back, deployment intact ----------------------
    let refusal = vault.honest[0].restart_must_be_refused()?;
    // Attribute over the whole log, not the tail the message quotes. Both process
    // generations append to one file, and the refusal is the second generation's
    // last write only as long as nothing follows it — a tail read would mis-report a
    // correct refusal that scrolled by as "some other reason". Only the second
    // generation can write this needle: the first claims the generation silently.
    if !vault.honest[0].log_contains("process generation") {
        return Err(format!(
            "a second process generation was refused for an unexpected reason: {refusal}"
        )
        .into());
    }
    // Re-take the guard after the bounded restart probe. If T landed while that
    // probe was waiting, an escape share may already have left a daemon before the
    // second kill; reporting the final state as though one survivor had been the
    // whole fire-time set would misattribute a harness race to the release gate.
    let pre_second_kill_escape_partials = vault.validated_escape_partials(&request)?;
    if !pre_second_kill_escape_partials.is_empty() || vault.in_mempool_or_chain(&escape_txid)? {
        return Err(format!(
            "the sweep reached fire time during the process-restart probe ({} escape-role \
             partial(s) released), before the second kill; this run cannot attribute the \
             lockdown-only outcome to the final one-node armed set",
            pre_second_kill_escape_partials.len()
        )
        .into());
    }
    let killed = vault.honest.remove(0);
    let killed_id = killed.node_id;
    drop(killed);

    // -- machine reboot: the deployment goes with it -----------------------
    let dead = vault.honest.remove(0);
    let dead_addr = dead.addr();
    let dead_id = dead.node_id;
    dead.destroy()?;
    std::thread::sleep(Duration::from_secs(2));
    if NodeProcess::is_serving(dead_addr) {
        return Err(format!(
            "node_id {dead_id} is still serving after its deployment was destroyed"
        )
        .into());
    }

    // The armed set is now 1, below t = 3: sweep redundancy is gone. Lockdown at T
    // is unconditional and must still land on the survivor.
    let survivors: Vec<usize> = (0..vault.honest.len()).collect();
    vault.wait_for_lockdown(&survivors, EXPECT_TIMEOUT + Duration::from_secs(30))?;

    // Lockdown-only: no sweep, and above all no coerced completion. Lockdown itself
    // does not stop the in-flight fire loop, so read only after the hot candidate's
    // Hold and complete combine window have elapsed.
    vault.wait_past_hot_release_window(accepted_first_seen)?;
    if vault.in_mempool_or_chain(&coerced_txid)? {
        return Err("a coerced spend completed after the armed set was driven below t".into());
    }
    // Secondary — but NOT arithmetic. Be exact, because the tempting shorthand is
    // false: with `t = 3` and `c = t−1 = 2`, one honest survivor plus the adversary's
    // two shares is `3 = t`, which satisfies `multi(3,·)` on the normal branch
    // (`policy-core/src/template.rs`, `and_v(v:pk(USER),multi(t,NODES))`) with the
    // user's signature already on the escape candidate. A sweep here is numerically
    // reachable; what makes it absent is that nobody assembles it. The survivor holds
    // only its own escape share — this scenario furnishes receipts, not partials — so
    // the depleted HONEST set cannot combine, which is the observation this line
    // makes. The adversary could combine, and the harness deliberately does not do it
    // for it: that transaction pays the user's own escape wallet, so it is neither
    // theft nor something an attacker would want.
    //
    // The arm's real content is above and below: Lockdown landed on the survivor
    // UNCONDITIONALLY, with the armed set below `t` and no prospect of a sweep, and
    // the coerced spend released zero partials across the kills.
    let swept = vault.in_mempool_or_chain(&escape_txid)?;
    if swept {
        return Err(format!(
            "the escape {escape_txid} combined with only {} armed node(s), below the threshold \
             {T}",
            vault.honest.len()
        )
        .into());
    }
    vault.assert_wiretap_decoded("reboot-death zero-partial assertion")?;
    let releasable = vault.honest_partials_for(&accepted_id);
    if !releasable.is_empty() {
        return Err(format!(
            "honest node_id(s) {releasable:?} released a coerced partial across the kills"
        )
        .into());
    }
    // And nothing else leaked either, beyond the control spend and the intended
    // escape. A surviving armed node may release its escape share at T even though the
    // depleted honest set cannot combine it; that share pays only the user's escape
    // wallet and is not a coerced-spend leak. The exact spend-id check above remains
    // the safety oracle.
    let stray = vault.partial_commitments_outside(&[control_id.as_str(), escape_id.as_str()]);
    if !stray.is_empty() {
        return Err(format!(
            "the adversary collected honest candidate partial(s) for {stray:?} beyond the control \
             spend"
        )
        .into());
    }
    assert_no_theft(&vault)?;

    Ok(format!(
        "control: {control_signers} honest partial(s) seen for a completed normal spend (the \
         wiretap is not deaf); node_id {killed_id} refused a second process generation on an \
         intact deployment; node_id {dead_id} died with its deployment and cannot rejoin; armed \
         set driven to {} (< t = {T}) → UNCONDITIONAL Lockdown still landed on the survivor and \
         the coerced spend released 0 honest partials across the kills; no sweep (the depleted \
         honest set cannot combine one); no theft",
        vault.honest.len()
    ))
}

// ---------------------------------------------------------------------------
// 9. coverage / feerate / package fire-time failures

/// Which fire-time admissibility gate a run cripples. Coverage and feerate are
/// checked before partial release; full package acceptance is checked after combine
/// and before broadcast. All three produce the same terminal safety outcome: the
/// safety track does not care WHY the sweep was refused.
#[derive(Clone, Copy)]
enum FireTimeGate {
    /// Coverage below `escape_coverage_pct`: fund a second vault UTXO the escape
    /// does not sweep, so the escape covers about half the denominator.
    Coverage,
    /// Fee below `escape_feerate_floor · vsize`: raise the floor far above what an
    /// ordinary escape fee buys, leaving coverage untouched.
    FeerateFloor,
    /// Core package policy after combine: raise bitcoind's relay floor above the
    /// escape's actual feerate while leaving the node's pre-release floor at 1 sat/vB.
    PackageAcceptance,
}

impl FireTimeGate {
    /// The substring the node logs when THIS gate is the one that refused. Asserting
    /// it is what makes the run attributable: without it, "the sweep did not fire"
    /// is equally consistent with the sweep failing for some unrelated reason, and
    /// the scenario would claim to exercise a gate it never reached.
    fn log_evidence(self) -> &'static str {
        match self {
            FireTimeGate::Coverage => "escape coverage below",
            FireTimeGate::FeerateFloor => "escape feerate below the panic floor",
            FireTimeGate::PackageAcceptance => "package mempool-acceptance failed",
        }
    }

    fn label(self) -> &'static str {
        match self {
            FireTimeGate::Coverage => "coverage",
            FireTimeGate::FeerateFloor => "feerate floor",
            FireTimeGate::PackageAcceptance => "package acceptance",
        }
    }

    fn refuses_before_release(self) -> bool {
        !matches!(self, FireTimeGate::PackageAcceptance)
    }

    fn bitcoind_args(self) -> &'static [&'static str] {
        // 0.001 BTC/kvB = 100 sat/vB, comfortably above the escape's actual
        // feerate while the node's independent panic floor remains 1 sat/vB.
        const HIGH_MIN_RELAY: &[&str] = &["-minrelaytxfee=0.001"];
        match self {
            FireTimeGate::PackageAcceptance => HIGH_MIN_RELAY,
            FireTimeGate::Coverage | FireTimeGate::FeerateFloor => &[],
        }
    }

    /// The fee the run's COERCED hot spend pays.
    ///
    /// The package run raises bitcoind's relay floor to 100 sat/vB to make Core
    /// refuse the combined escape. That floor applies to every transaction, not just
    /// the escape — and an ordinary `FEE`-paying hot spend over a ~240 vB P2WSH
    /// 3-of-5 body buys about 40 sat/vB, well under it. Left alone, the coerced spend
    /// in THAT arm could not relay even if every honest node released its partial and
    /// the adversary combined a complete witness: `in_mempool_or_chain(coerced)` and
    /// the mempool half of `assert_no_theft` would both be true-by-chain-policy, and
    /// the arm's only live oracle would be its partial count. So pay above the floor
    /// there. The escape keeps the ordinary fee — being under the floor is the whole
    /// point of the gate. The fee stays far below `MAX_FEE_PERCENT` of the coin spent
    /// (10% of 10 BTC), so ingress admissibility is unchanged.
    fn coerced_fee(self) -> Amount {
        match self {
            FireTimeGate::PackageAcceptance => RELAY_CLEARING_FEE,
            FireTimeGate::Coverage | FireTimeGate::FeerateFloor => FEE,
        }
    }
}

/// Escape admissibility is a FIRE-TIME sweep check, NEVER an arm gate. A
/// hostile-at-wrench coordinator that composes a compliant-but-crippled escape can
/// stop the sweep; it cannot stop the safety track.
///
/// The assertion, run once per gate: the sweep does not fire, Lockdown at T still
/// happens unconditionally, and the funds remain in the vault, recoverable via
/// V0-10. Coverage and feerate refuse before any escape share leaves; package
/// acceptance necessarily refuses after the complete witness has been combined.
///
fn fire_time_failure() -> Result<String, Error> {
    let coverage = fire_time_gate_refuses(FireTimeGate::Coverage)?;
    let feerate = fire_time_gate_refuses(FireTimeGate::FeerateFloor)?;
    let package = fire_time_gate_refuses(FireTimeGate::PackageAcceptance)?;
    Ok(format!("{coverage}; {feerate}; {package}"))
}

fn fire_time_gate_refuses(gate: FireTimeGate) -> Result<String, Error> {
    // A floor of 100_000 sat/vB is orders of magnitude above what `FEE` buys over an
    // escape's vsize, so the ordinary escape below fails it while its coverage,
    // class, signature, and fee cap all stay valid.
    const CRIPPLING_FEERATE_FLOOR: u64 = 100_000;
    let vault = Vault::build(&Setup {
        hold_secs: 20,
        duress_delay_secs: 8,
        epsilon_secs: 1,
        escape_feerate_floor: match gate {
            FireTimeGate::Coverage | FireTimeGate::PackageAcceptance => {
                DEFAULT_ESCAPE_FEERATE_FLOOR
            }
            FireTimeGate::FeerateFloor => CRIPPLING_FEERATE_FLOOR,
        },
        bitcoind_args: gate.bitcoind_args(),
        ..Setup::default()
    })?;

    // The pre-release runs conclude safety from zero observed escape partials, so
    // they need an independent positive control. The package run releases the exact
    // escape shares before Core refuses it; those shares are its stronger path control.
    let (control_id, control_signers) = if gate.refuses_before_release() {
        let control_coin = vault.fund_extra(Amount::from_sat(100_000_000))?;
        let (control_id, signers) = vault.wiretap_positive_control(&control_coin)?;
        (Some(control_id), Some(signers))
    } else {
        (None, None)
    };

    // This escape is a valid escape-class transaction AT INGRESS — every
    // output pays the escape wallet, its user signature and fee are valid, and it
    // supersedes the frozen spend's input. Only the fire-time gate refuses it.
    let crippled = vault.escape_for(&vault.vault_utxo)?;
    let coerced = vault.hot_spend_fee(
        &vault.vault_utxo,
        Amount::from_sat(400_000_000),
        gate.coerced_fee(),
    )?;
    let request = vault.request(&coerced, &crippled, DURESS_PIN)?;
    let escape_id = vault.expected_commitment_id(&crippled, request.expiry);
    let accepted = expect_accepted(
        &vault.relay_to(0, &request)?,
        &format!(
            "{}-failing carrier before fire-time admissibility",
            gate.label()
        ),
    )?;

    // For the coverage gate ONLY, enlarge the protected balance AFTER acceptance
    // but before T. This is the deposit-during-Hold case ADR-0012 calls out: a node
    // that incorrectly snapshotted the denominator at ingress would let the escape
    // through, while a fire-time enumeration sees roughly twice the swept value.
    // The feerate and package runs must not add it or their attribution becomes
    // ambiguous.
    if matches!(gate, FireTimeGate::Coverage) {
        vault.fund_extra(FUND)?;
        // OBSERVE T rather than compute a lower bound for it. `first_seen +
        // duress_delay_secs` is only where T starts: `write_safety_overlay` clamps with
        // `.max(now)` at the arm commit, so a commit that lands later pushes T out with
        // it. Aborting on the arithmetic instant would kill the ONLY arm that exercises
        // the coverage gate for a deposit that in fact beat the real fire — and since
        // the arm here is committed by `confirm_with_compromised` *below*, the
        // arithmetic bound is essentially never the true T.
        //
        // Lockdown at T is unconditional and terminal, so "no honest node has locked
        // down" is the federation's own answer. It lags T by up to one poll tick, which
        // is the right direction to err: the check is guarding against reading a
        // fire-time denominator that was already enumerated, and a tick of slack there
        // is bounded by the same margin every other fire observation in this file uses.
        for index in 0..vault.honest.len() {
            if vault.is_locked_down(index)? {
                return Err(format!(
                    "node_id {} had already locked down when the late coverage deposit \
                     confirmed, so T had passed and the sweep's denominator was fixed before the \
                     deposit landed; this run cannot distinguish a fire-time denominator from an \
                     ingress snapshot",
                    vault.honest[index].node_id
                )
                .into());
            }
        }
    }

    vault.wait_for_honest_relayers(&request.nonce, vault.honest.len(), EXPECT_TIMEOUT)?;
    vault.confirm_with_compromised(&request)?;

    // This exact carrier must be sufficient to reach terminal safety. Do not send a
    // valid control carrier: it would mask an incorrect ingress gate or a failure to
    // lock down after the selected sweep is rejected at fire time.
    let all: Vec<usize> = (0..vault.honest.len()).collect();
    vault.wait_for_lockdown(&all, EXPECT_TIMEOUT)?;
    vault.wait_past_hot_release_window(accepted.first_seen)?;
    let crippled_txid = crippled.unsigned_tx.compute_txid().to_string();
    let coerced_txid = coerced.unsigned_tx.compute_txid().to_string();
    if vault.in_mempool_or_chain(&crippled_txid)? {
        return Err(format!(
            "a crippled escape below the {} threshold fired; that is a fire-time admissibility \
             check and must have stopped it",
            gate.label()
        )
        .into());
    }
    if vault.in_mempool_or_chain(&coerced_txid)? {
        return Err("the coerced hot spend completed".into());
    }
    let signed_coerced = Psbt::from_str(&request.psbt)?;
    let coerced_signers =
        vault.validated_honest_partials_for(&accepted.commitment_id, &signed_coerced, "spend")?;
    if !coerced_signers.is_empty() {
        return Err(format!(
            "honest node_id(s) {coerced_signers:?} released the coerced hot partial after its \
             Hold expired; Lockdown must not leave the in-flight release path open"
        )
        .into());
    }
    let partial_evidence = if gate.refuses_before_release() {
        if !vault.validated_escape_partials(&request)?.is_empty() {
            return Err(format!(
                "an honest escape partial left before the fire-time {} gate refused it; the \
                 pre-release check exists precisely so a compromised t−1 set never receives a \
                 share of an inadmissible sweep",
                gate.label()
            )
            .into());
        }
        vault.assert_wiretap_decoded(&format!(
            "fire-time {} zero-partial assertion",
            gate.label()
        ))?;
        format!(
            "released 0 partials against a control that saw {} honest partial(s)",
            control_signers.expect("pre-release gate installed its positive control")
        )
    } else {
        // The package run releases its escape shares before Core refuses the complete
        // package, so those shares ARE this run's partial-transport control — but only
        // if a share from EVERY live honest node is required, matching the per-node
        // coverage/feerate `wiretap_positive_control` the pre-release branch installs.
        // A single share would prove only one sender's wiretap audible while the
        // global backstop below reads the federation as a whole; release being a
        // per-node gate, demanding all of them is sound.
        let signed_escape = Psbt::from_str(&request.escape_psbt)?;
        let signers = vault.wait_for_honest_partials(
            &escape_id,
            &signed_escape,
            "escape",
            vault.honest.len(),
            SETTLE,
        )?;
        if accepted.commitment_id == escape_id {
            return Err("spend and escape unexpectedly have the same commitment id".into());
        }
        format!(
            "released partials from {} honest signer(s) to adversarial listeners before Core \
             refused the complete package",
            signers.len()
        )
    };
    let mut allowed_partials = Vec::new();
    if let Some(control_id) = control_id.as_deref() {
        allowed_partials.push(control_id);
    }
    if !gate.refuses_before_release() {
        allowed_partials.push(escape_id.as_str());
    }
    vault.assert_no_unexpected_partials(
        &format!("fire-time {} global partial backstop", gate.label()),
        &allowed_partials,
    )?;
    // Attribute the refusal. The assertion above is an argument from absence, and an
    // absent sweep is equally consistent with the escape never reaching the gate at
    // all — in which case this run would be evidence for nothing.
    let attributed = vault
        .honest
        .iter()
        .filter(|node| node.log_contains(gate.log_evidence()))
        .count();
    if attributed == 0 {
        return Err(format!(
            "no honest node logged a {} refusal, so the sweep's absence is unattributed — this \
             run did not demonstrate the {} gate. Last log: {}",
            gate.label(),
            gate.label(),
            vault.honest[0].log_tail()
        )
        .into());
    }

    // Funds are still the vault's — frozen, and recoverable via the timelock path.
    let scan = vault
        .bitcoind
        .scan_txoutset(json!([format!("raw({})", vault.vault_spk.to_hex_string())]))?;
    // Error rather than default, for the reason `receipts_for` gives: a scan whose
    // total is unreadable is an RPC failure, and defaulting it to zero would turn
    // that failure into a definite answer about where the funds are.
    let in_vault = scan
        .get("total_amount")
        .and_then(Value::as_f64)
        .ok_or("scantxoutset answered without a total_amount")?;
    if in_vault <= 0.0 {
        return Err("the vault is empty after a failed sweep; funds must stay frozen in it".into());
    }
    assert_no_theft(&vault)?;

    Ok(format!(
        "{} gate: an ingress-valid escape {partial_evidence} and never fired ({attributed}/{} \
         honest nodes logged the refusal); that same carrier still caused unconditional Lockdown \
         at T; {in_vault} BTC remains recoverable via the timelock path",
        gate.label(),
        vault.honest.len()
    ))
}

// ---------------------------------------------------------------------------
// 9b. reorg handling (bead btc-policy-9y5.3)

/// Force a live reorg: invalidate the top `depth` blocks of the active chain and
/// mine `depth + 1` fresh ones, so every block from the fork point up carries a NEW
/// hash and the rebuilt chain strictly outweighs the old one. bitcoind's
/// `invalidateblock` marks the named block and all its descendants invalid; the
/// honest daemons' reorg-aware watchtower cursors (9y5.3-a) must rewind across it
/// rather than silently advance past re-orged blocks.
/// Mine `blocks` blocks one at a time, retrying a single block on bitcoind's
/// transient post-reorg `ProcessNewBlock, block not accepted`. Immediately after
/// `invalidateblock`, `generatetoaddress` can race the median-time-past rule when the
/// just-invalidated blocks left the last-11 timestamps clustered at ~now: the fresh
/// block's time is not yet strictly greater than MTP and Core rejects it. The rejected
/// block was NOT added, so retrying after a short pause — long enough for the wall
/// clock (and thus the block timestamp) to advance past MTP — mines an acceptable
/// block. Mining ONE at a time keeps the count exact under retry (no over-mining), and
/// the bound still surfaces a genuine, non-transient failure.
fn mine_resilient(vault: &Vault, blocks: u32) -> Result<(), Error> {
    for _ in 0..blocks {
        let mut attempt = 0u32;
        loop {
            match vault.mine(1) {
                Ok(()) => break,
                Err(e) if attempt < 15 && e.to_string().contains("block not accepted") => {
                    attempt += 1;
                    std::thread::sleep(Duration::from_secs(1));
                }
                Err(e) => return Err(e),
            }
        }
    }
    Ok(())
}

fn reorg_tip(vault: &Vault, depth: u64) -> Result<(), Error> {
    let tip = vault
        .bitcoind
        .call("getblockcount", json!([]))?
        .as_u64()
        .ok_or("getblockcount is not a number")?;
    if tip <= depth {
        return Err(format!("chain height {tip} is too short to reorg {depth} block(s)").into());
    }
    // Invalidating the fork's child drops it and every descendant — `depth` blocks.
    let fork_child = vault
        .bitcoind
        .call_str("getblockhash", json!([tip - depth + 1]))?;
    vault
        .bitcoind
        .call("invalidateblock", json!([fork_child]))?;
    // Rebuild one block longer than what was dropped, so the new chain wins outright.
    // Resilient mine: `generatetoaddress` can transiently fail the MTP rule right after
    // `invalidateblock` (see [`mine_resilient`]).
    mine_resilient(
        vault,
        u32::try_from(depth + 1).map_err(|_| "reorg depth overflow")?,
    )?;
    Ok(())
}

/// Restart the scenario's Core against the SAME datadir and RPC credentials while
/// deliberately not loading `mempool.dat`, run `action`, then stop the replacement
/// cleanly. `invalidateblock` ordinarily re-admits disconnected transactions to the
/// mempool; clearing that automatic copy is what lets the escape-reorg scenario
/// prove the NODE re-broadcasts its retained candidate, rather than merely watching
/// Core mine a transaction Core itself restored.
fn with_restarted_bitcoind_without_mempool<T>(
    vault: &Vault,
    action: impl FnOnce() -> Result<T, Error>,
) -> Result<T, Error> {
    let datadir = vault.temp.path.join("bitcoind");
    let cookie = std::fs::read_to_string(datadir.join("regtest").join(".cookie"))?;
    let (rpc_user, rpc_password) = cookie
        .trim()
        .split_once(':')
        .ok_or("bitcoind cookie is not user:password")?;
    let rpc_port = vault.bitcoind.rpc_addr().port();

    vault.bitcoind.call("stop", json!([]))?;
    let shutdown_deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if vault.bitcoind.call("getblockchaininfo", json!([])).is_err() {
            break;
        }
        if Instant::now() >= shutdown_deadline {
            return Err("bitcoind did not stop for the empty-mempool reorg restart".into());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    // The retry loop below respawns on ANY startup exit, not only the datadir-lock race, so
    // the replacement's stderr is CAPTURED (not discarded) and surfaced on the deadline
    // errors — a genuinely broken invocation (e.g. a flag a future bitcoind rejects) must be
    // diagnosable, not looped ~600x behind a hard-coded "lock" cause (Fable 9y5.4 P3).
    let replacement_stderr_path = datadir.join("replacement-bitcoind.stderr");
    let debug_log = datadir.join("regtest").join("debug.log");
    let diag = |what: &str| -> Error {
        let tail = std::fs::read_to_string(&replacement_stderr_path)
            .map(|s| {
                let lines: Vec<&str> = s.lines().collect();
                lines[lines.len().saturating_sub(12)..].join("\n")
            })
            .unwrap_or_else(|_| "(no replacement stderr captured)".to_string());
        format!(
            "empty-mempool bitcoind restart {what}. NB the loop retries on ANY startup exit, so a \
             rejected flag or bad config looks identical to the outgoing Core's datadir-lock race \
             — last replacement stderr:\n{tail}\n(full node log: {})",
            debug_log.display()
        )
        .into()
    };
    let spawn_replacement = || -> Result<Child, Error> {
        Command::new("bitcoind")
            .arg("-regtest")
            .arg(format!("-datadir={}", datadir.display()))
            .arg(format!("-rpcport={rpc_port}"))
            .arg("-listen=0")
            .arg("-server=1")
            .arg("-txindex=1")
            .arg("-fallbackfee=0.0001")
            .arg("-persistmempool=0")
            .arg("-wallet=attack")
            .arg(format!("-rpcuser={rpc_user}"))
            .arg(format!("-rpcpassword={rpc_password}"))
            .stdout(Stdio::null())
            // Capture stderr so the deadline diagnostics can show WHY it kept exiting.
            .stderr(
                std::fs::File::create(&replacement_stderr_path)
                    .map(Stdio::from)
                    .unwrap_or_else(|_| Stdio::null()),
            )
            .spawn()
            .map_err(|e| format!("cannot restart bitcoind without its mempool: {e}").into())
    };

    // Core closes its RPC listener EARLY in shutdown but releases the datadir lock
    // only when the process finally exits, after flushing chainstate — so the loop
    // above returning "unreachable" does NOT mean the datadir is free. Measured on an
    // idle regtest node with a 200-block chain: RPC stopped answering 1ms after
    // `stop`, the process lived to 193ms. A replacement spawned inside that gap dies
    // with "Cannot obtain a lock on data directory", which surfaces here only as
    // `exit status: 1`.
    //
    // 200ms is therefore a bet that was being won by ~7ms on an IDLE box, against a
    // flush whose cost grows with the chain and the machine's load; this scenario
    // lost it during a full `attack all` run. So the sleep stays as a head start for
    // the common case, but readiness is now established by RETRYING the spawn until
    // the lock is genuinely free instead of by trusting the guess. This is the launch
    // gate, and it runs on every push: a gate that goes red for a lost race is one
    // people learn to re-run rather than read.
    std::thread::sleep(Duration::from_millis(200));
    let startup_deadline = Instant::now() + Duration::from_secs(60);
    let mut child = spawn_replacement()?;
    loop {
        // `Some` means it died on startup. Retry while the outgoing Core may still
        // hold the lock; past the deadline, report the last status verbatim so a
        // genuinely broken invocation stays diagnosable rather than retried silently.
        if let Some(status) = child.try_wait()? {
            if Instant::now() >= startup_deadline {
                return Err(diag(&format!(
                    "kept exiting during startup (last: {status})"
                )));
            }
            std::thread::sleep(Duration::from_millis(100));
            child = spawn_replacement()?;
            continue;
        }
        if vault.bitcoind.call("getblockchaininfo", json!([])).is_ok() {
            break;
        }
        if Instant::now() >= startup_deadline {
            // The replacement is still RUNNING here (`try_wait` returned `None` above) but
            // never became ready. Kill and reap it before bailing, or the live child leaks
            // its datadir lock + RPC port into every later scenario of `attack all` — a
            // single readiness timeout would cascade into port collisions and blocked
            // TempDir cleanup (Fable 9y5.4 P3; the sibling error paths already reap).
            let _ = child.kill();
            let _ = child.wait();
            return Err(diag("did not become ready within 60s"));
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    let result = action();
    let stop_result = vault.bitcoind.call("stop", json!([]));
    // If the `stop` RPC failed (e.g. connection reset while Core reindexes the invalidated
    // chain), the replacement is still running, so an unconditional `child.wait()` would
    // wedge this scenario forever. Kill it on that path so the harness REPORTS the failure
    // instead of hanging (Fable pass-6 P3, harness-only).
    if stop_result.is_err() {
        let _ = child.kill();
    }
    let wait_result = child.wait();
    match result {
        Err(error) => Err(error),
        Ok(value) => {
            stop_result?;
            let status = wait_result?;
            if !status.success() {
                return Err(format!(
                    "empty-mempool bitcoind replacement exited unsuccessfully: {status}"
                )
                .into());
            }
            Ok(value)
        }
    }
}

/// Deliverable 9y5.3-a, end to end: a watchtower-alertable spend that a REORG
/// re-lands at a height AT/BELOW the scan cursor is still classified. The old cursor
/// was a bare monotonic height that only ever advanced, so a spend re-orged below it
/// was silently MISSED; the reorg-aware cursor detects the fork, rewinds, and
/// re-scans.
///
/// The only on-chain vault spend a watchtower alerts on that this harness can build
/// without the federation's own node keys is a RECOVERY-branch spend (recovery uses
/// the recovery keys). So: mature the recovery lock, advance every honest cursor well
/// past where the recovery spend will re-land, reorg the tip out from under the
/// cursors, land the recovery spend BELOW the cursors' old anchor, and require every
/// honest watchtower to surface the resulting alert.
fn reorg_watchtower_cursor() -> Result<String, Error> {
    let vault = Vault::build(&Setup::default())?;
    const CONTROL: Amount = Amount::from_sat(20_000_000);
    // Fund the recovery coin FIRST and bury it deep, so the shallow tip reorg below
    // never un-confirms the input the recovery spend spends.
    let coin = vault.fund_extra(CONTROL)?;
    // Recovery's relative TIME lock matures on median-time-past; this pins the chain
    // clock forward. The watchtower keys off height/hash, not block time, so the mock
    // clock is inert for this scenario's assertion.
    crate::recovery::advance_mtp_past_recovery_lock(&vault.bitcoind, &vault.mining_address)?;

    // Build — but do NOT broadcast — the recovery-branch spend of the control coin.
    let destination = vault.bitcoind.call_str("getnewaddress", json!([]))?;
    let destination_spk = {
        let hex = vault
            .bitcoind
            .call("getaddressinfo", json!([destination]))?["scriptPubKey"]
            .as_str()
            .ok_or("getaddressinfo has no scriptPubKey")?
            .to_string();
        ScriptBuf::from_hex(&hex)?
    };
    let value = coin
        .txout
        .value
        .checked_sub(FEE)
        .ok_or("the recovery control coin cannot cover its fee")?;
    let recovery_tx = crate::recovery::build_recovery_spend(
        &vault.secp,
        coin.outpoint,
        &coin.txout,
        &vault.witness_script,
        &destination_spk,
        value,
        &vault.recovery_keys[..policy_core::RECOVERY_THRESHOLD],
    )?;
    let recovery_txid = recovery_tx.compute_txid().to_string();

    // Advance the chain — and, after a couple of scan intervals, every honest
    // watchtower cursor — well past the height the recovery spend will re-land at.
    vault.mine(4)?;
    let anchor_tip = vault
        .bitcoind
        .call("getblockcount", json!([]))?
        .as_u64()
        .ok_or("getblockcount is not a number")?;
    // The watchtower scan interval is 10s; wait past two passes so every honest cursor
    // has scanned to `anchor_tip` and recorded it as an anchor before the reorg drops
    // the blocks below it. (The cursor would catch the spend even without this wait —
    // it rewinds on any detected fork — but the wait makes the "would-have-been-missed"
    // property concrete: the spend re-lands strictly below where the cursor had reached.)
    std::thread::sleep(Duration::from_secs(25));

    // Reorg: roll back the top two blocks, then land the recovery spend at
    // `anchor_tip - 1` — BELOW the cursor's recorded anchor, where a non-rewinding
    // cursor (scanning `anchor_tip + 1 ..`) would never see it.
    let fork_child = vault
        .bitcoind
        .call_str("getblockhash", json!([anchor_tip - 1]))?;
    vault
        .bitcoind
        .call("invalidateblock", json!([fork_child]))?;
    vault.bitcoind.call_str(
        "sendrawtransaction",
        json!([bitcoin::consensus::encode::serialize_hex(&recovery_tx)]),
    )?;
    // Resilient mines: `generatetoaddress` can transiently fail the MTP rule right after
    // `invalidateblock` (see [`mine_resilient`]). One at a time keeps the height exact.
    mine_resilient(&vault, 1)?; // the recovery spend confirms at height anchor_tip - 1
                                // Rebuild above the old anchor so the fork is unambiguous and the tip clearly moved.
    mine_resilient(&vault, 3)?;

    // Every honest watchtower must now rewind across the reorg and surface the
    // recovery-path alert — the miss the bare monotonic cursor produced.
    let deadline = Instant::now() + EXPECT_TIMEOUT;
    loop {
        let observed = vault.events_snapshot()?;
        let mut pending = Vec::new();
        for (id, projection) in &observed {
            // Require THIS node to have surfaced the SPECIFIC re-orged recovery spend
            // in its OWN projection — not merely an alert-count bump (an unrelated
            // alert could otherwise satisfy a node that actually missed the reorged
            // spend), and not merely that SOME node saw the txid. Every honest
            // watchtower must rewind and re-classify this exact spend.
            let saw_recovery = alert_spend_txids(projection)
                .iter()
                .any(|t| t == &recovery_txid);
            if !saw_recovery {
                pending.push(*id);
            }
        }
        if pending.is_empty() {
            return Ok(format!(
                "a recovery-path spend re-orged to height {} (below the cursor's anchor at {}) was \
                 re-classified by all {} honest watchtowers after the cursor rewound to the fork — \
                 the miss the bare monotonic cursor would have produced",
                anchor_tip - 1,
                anchor_tip,
                vault.honest.len()
            ));
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "after a reorg landed recovery spend {recovery_txid} below the scan cursor, honest \
                 node_id(s) {pending:?} never surfaced THAT specific spend in their own projection; \
                 the reorg-aware cursor must rewind and re-classify a spend re-orged below it"
            )
            .into());
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// Deliverable 9y5.3 (iii): the duress SAFETY track is indifferent to the chain
/// re-orging underneath it. A coerced hot spend is armed under the duress pin; while
/// the arm confirms and `T` passes, the tip is re-orged twice. Lockdown at `T` is
/// still UNCONDITIONAL, no honest node releases the coerced partial (the coupling +
/// store-locked release gate hold), the coerced spend never completes, and no value
/// reaches the attacker.
fn reorg_duress_lockdown() -> Result<String, Error> {
    // A crippling feerate floor keeps the escape from ever broadcasting, so no vault
    // transaction sits in the mempool and the tip blocks the reorg rolls back carry
    // only their coinbase — the reorg churns the chain without disturbing candidate
    // settlement. Lockdown at T is independent of the sweep, so it still lands.
    const CRIPPLING_FEERATE_FLOOR: u64 = 100_000;
    let vault = Vault::build(&Setup {
        hold_secs: 20,
        duress_delay_secs: 8,
        epsilon_secs: 1,
        escape_feerate_floor: CRIPPLING_FEERATE_FLOOR,
        ..Setup::default()
    })?;

    // Positive wiretap control so a later "0 coerced partials" is evidence rather than
    // an artefact of a deaf listener. Runs while the federation is whole.
    let control_coin = vault.fund_extra(Amount::from_sat(100_000_000))?;
    let (control_id, control_signers) = vault.wiretap_positive_control(&control_coin)?;

    // Arm a coerced hot spend under the DURESS pin, plus its mandatory escape.
    let coerced = vault.hot_spend_fee(&vault.vault_utxo, Amount::from_sat(400_000_000), FEE)?;
    let escape = vault.escape_for(&vault.vault_utxo)?;
    let request = vault.request(&coerced, &escape, DURESS_PIN)?;
    let accepted = expect_accepted(&vault.relay_to(0, &request)?, "duress carrier under reorg")?;

    // Reorg the tip out from under the federation while the carrier propagates and the
    // arm confirms, then again as `T` approaches.
    reorg_tip(&vault, 2)?;
    vault.wait_for_honest_relayers(&request.nonce, vault.honest.len(), EXPECT_TIMEOUT)?;
    vault.confirm_with_compromised(&request)?;
    reorg_tip(&vault, 2)?;

    // (iii) Lockdown at T is unconditional — it lands on every honest node across the
    // reorgs.
    let all: Vec<usize> = (0..vault.honest.len()).collect();
    vault.wait_for_lockdown(&all, EXPECT_TIMEOUT)?;
    vault.wait_past_hot_release_window(accepted.first_seen)?;

    // The coerced hot spend never completed.
    let coerced_txid = coerced.unsigned_tx.compute_txid().to_string();
    if vault.in_mempool_or_chain(&coerced_txid)? {
        return Err("the coerced hot spend completed across the reorg".into());
    }
    // No honest node released the coerced partial — the coupling + store-locked release
    // gate stayed closed for the frozen duress spend across the chain churn.
    let signed_coerced = Psbt::from_str(&request.psbt)?;
    let coerced_signers =
        vault.validated_honest_partials_for(&accepted.commitment_id, &signed_coerced, "spend")?;
    if !coerced_signers.is_empty() {
        return Err(format!(
            "honest node_id(s) {coerced_signers:?} released the coerced hot partial across the \
             reorg; the release gate must stay closed for a frozen duress spend"
        )
        .into());
    }
    // The escape was crippled and never fired, so the ONLY honest partials anywhere are
    // the control's — anything else would be an unexpected release.
    vault.assert_no_unexpected_partials(
        "reorg duress global partial backstop",
        &[control_id.as_str()],
    )?;
    assert_no_theft(&vault)?;

    Ok(format!(
        "Lockdown at T held unconditionally across two tip reorgs; 0 coerced partials released \
         (control saw {control_signers} honest partial(s)); the coerced hot spend never completed; \
         no value reached the attacker"
    ))
}

/// Deliverable 9y5.3 (ii): an armed escape that a REORG un-confirms is not stranded —
/// it re-settles within its Firing job — and the coerced spend still never completes,
/// even though the reorg briefly re-opens the swept `vault_utxo`.
///
/// The sibling [`reorg_duress_lockdown`] CRIPPLES the escape to isolate the safety
/// track; this one lets an ADMISSIBLE escape actually sweep, confirm, get its
/// confirming block re-orged out (so it is un-confirmed AGAIN, exactly the
/// deliverable's wording), and settle a second time. That the escape wins the
/// re-settlement — while the coerced hot spend, whose only input the reorg just
/// re-opened, cannot — is the property no crippled-escape or unit test covers.
///
/// To distinguish the node's OWN retry from Core's automatic disconnected-
/// transaction re-admission, the scenario invalidates the confirming block and
/// restarts the same chain with mempool persistence disabled. It requires the escape
/// to reappear in that explicitly empty mempool BEFORE mining the replacement block,
/// then requires it to confirm again. The only writer capable of that reappearance
/// is an honest node's retained Firing job.
fn reorg_escape_resettles() -> Result<String, Error> {
    // A working, admissible escape (default coverage + feerate) and a duress delay
    // wide enough that the sweep reliably fires before the reorg — mirrors the
    // reboot-death sweep recipe, minus the kill.
    let vault = Vault::build(&Setup {
        hold_secs: 90,
        duress_delay_secs: 45,
        epsilon_secs: 1,
        // Restarting Core to erase its automatic disconnected-transaction
        // re-admission takes real wall time. Keep the existing bounded semantics,
        // but give this live proof enough room to observe the node retry.
        combine_slack_secs: 30,
        ..Setup::default()
    })?;

    // Positive wiretap control so the later "0 coerced partials" is evidence, not a
    // deaf listener. Taken while the federation is whole.
    let control_coin = vault.fund_extra(Amount::from_sat(20_000_000))?;
    let (control_id, control_signers) = vault.wiretap_positive_control(&control_coin)?;

    // Arm a coerced hot spend under the DURESS pin, plus its admissible escape.
    let coerced = vault.hot_spend(&vault.vault_utxo, Amount::from_sat(400_000_000))?;
    let escape = vault.escape_for(&vault.vault_utxo)?;
    let request = vault.request(&coerced, &escape, DURESS_PIN)?;
    let accepted = expect_accepted(
        &vault.relay_to(0, &request)?,
        "duress carrier (escape reorg)",
    )?;
    let (escape_id, _) = vault.signed_escape_candidate(&request)?;
    let coerced_txid = coerced.unsigned_tx.compute_txid().to_string();
    let escape_txid = escape.unsigned_tx.compute_txid().to_string();
    vault.wait_for_honest_relayers(&request.nonce, vault.honest.len(), EXPECT_TIMEOUT)?;
    vault.confirm_with_compromised(&request)?;

    // The sweep fires at T (Lockdown is unconditional) and lands on the network.
    let all: Vec<usize> = (0..vault.honest.len()).collect();
    vault.wait_for_lockdown(&all, EXPECT_TIMEOUT + Duration::from_secs(45))?;
    vault.wait_for_tx(
        &escape_txid,
        EXPECT_TIMEOUT + Duration::from_secs(vault.params.combine_slack_secs),
    )?;
    // Confirm the escape, then ensure the honest nodes actually OBSERVE that
    // confirmation before the reorg pulls it back out — otherwise a node that had not
    // yet observed it never exercised the retained-vs-cleared candidate path, and even
    // the old remove-on-observation behavior would pass for the wrong reason.
    vault.mine(1)?;
    // First make the confirmation REAL on-chain (mining can lag), polling
    // deterministically rather than assuming a fixed sleep sufficed.
    let confirm_deadline = Instant::now() + EXPECT_TIMEOUT;
    loop {
        let confirmations = vault
            .bitcoind
            .call_optional("getrawtransaction", json!([escape_txid.clone(), true]))?
            .and_then(|tx| tx.get("confirmations").and_then(Value::as_u64))
            .unwrap_or(0);
        if confirmations >= 1 {
            break;
        }
        if Instant::now() >= confirm_deadline {
            return Err(format!(
                "escape {escape_txid} never reached 1 confirmation before the reorg step; the \
                 scenario requires a genuinely-confirmed-then-reorged escape"
            )
            .into());
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    // Then wait for an honest fire tick (1 Hz) to actually OBSERVE that confirmation
    // while still RETAINING the escape candidate, so the reorg genuinely models
    // "confirmed AND observed, then re-orged" rather than "re-orged before anyone
    // looked". The node logs exactly that state transition, so poll for the line
    // instead of sleeping a fixed margin — the old blind sleep let the scenario pass
    // for the wrong reason, since a node that never observed the confirmation would
    // still hold (and re-broadcast) its candidate under the OLD remove-on-observation
    // behavior too. This line is emitted ONLY by the retaining behavior; the old code
    // logged the settle-and-clear path here instead.
    //
    // One honest node, not all three: only the node that finalized the sweep carries
    // the escape in its fire path (the others released their escape share and never
    // reached a local quorum, so the escape is never in their due set and they log
    // nothing about it). That single node is also the one whose retained candidate the
    // re-broadcast below must come from, so its observation is the assertion that
    // matters. Bounded well inside the `combine_slack_secs` window (observation takes a
    // tick or two), so a run where nobody observes is reported as such instead of
    // silently eating the window the re-broadcast proof still needs.
    let observed_marker =
        format!("fire: armed escape {escape_id} confirmed on-chain ({escape_txid})");
    let observe_deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let observers: Vec<u16> = vault
            .honest
            .iter()
            .filter(|node| node.log_contains(&observed_marker))
            .map(|node| node.node_id)
            .collect();
        if !observers.is_empty() {
            break;
        }
        if Instant::now() >= observe_deadline {
            return Err(format!(
                "escape {escape_txid} confirmed on-chain, but no honest node logged observing that \
                 confirmation while retaining its escape candidate; re-orging it out now would prove \
                 nothing about the retained-vs-cleared candidate path"
            )
            .into());
        }
        std::thread::sleep(Duration::from_millis(250));
    }

    // Reorg the escape's confirming block out. Core ordinarily puts every
    // disconnected transaction straight back in its mempool, which would let a
    // subsequent `generatetoaddress` mine it with ZERO node retry. Restart against
    // the same invalidated chain with `-persistmempool=0`; the replacement chain and
    // mempool then contain no escape until a retained Firing job re-broadcasts it.
    let confirming_block = vault.bitcoind.call_str("getbestblockhash", json!([]))?;
    vault
        .bitcoind
        .call("invalidateblock", json!([confirming_block]))?;

    with_restarted_bitcoind_without_mempool(&vault, || {
        // `getrawtransaction` also returns transactions known only from an INACTIVE
        // block, so the generic `wait_for_tx` oracle is intentionally too broad here.
        // Poll the active mempool specifically: mining stays forbidden until the
        // node-originated copy exists.
        let rebroadcast_deadline = Instant::now() + EXPECT_TIMEOUT;
        loop {
            if vault
                .bitcoind
                .call_optional("getmempoolentry", json!([escape_txid.clone()]))?
                .is_some()
            {
                break;
            }
            if Instant::now() >= rebroadcast_deadline {
                return Err(format!(
                    "escape {escape_txid} did not reappear in the empty mempool after its \
                     confirming block was invalidated; the scenario requires a node re-broadcast \
                     before mining"
                )
                .into());
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        // Only now mine the competing replacement block. Its inclusion proves the
        // node retry happened first; Core had no persisted/disconnected copy to mine.
        // Resilient: `generatetoaddress` can transiently fail the MTP rule right after
        // the `invalidateblock` above (see [`mine_resilient`]).
        mine_resilient(&vault, 1)?;
        let confirmations = vault
            .bitcoind
            .call_optional("getrawtransaction", json!([escape_txid.clone(), true]))?
            .and_then(|tx| tx.get("confirmations").and_then(Value::as_u64))
            .unwrap_or(0);
        if confirmations == 0 {
            return Err(format!(
                "the node-rebroadcast escape {escape_txid} never re-settled after the reorg"
            )
            .into());
        }

        vault.wait_past_hot_release_window(accepted.first_seen)?;

        // The coerced hot spend never completed — not even in the window where the reorg
        // re-opened its input.
        if vault.in_mempool_or_chain(&coerced_txid)? {
            return Err(
                "the coerced hot spend completed after the reorg re-opened the swept vault input"
                    .into(),
            );
        }
        // No honest node released the coerced partial across the reorg (coupling +
        // store-locked release gate held).
        let signed_coerced = Psbt::from_str(&request.psbt)?;
        let coerced_signers = vault.validated_honest_partials_for(
            &accepted.commitment_id,
            &signed_coerced,
            "spend",
        )?;
        if !coerced_signers.is_empty() {
            return Err(format!(
                "honest node_id(s) {coerced_signers:?} released the coerced hot partial across the \
                 escape reorg; the release gate must stay closed for a frozen duress spend"
            )
            .into());
        }
        // The only honest partials anywhere are the control's and the escape the sweep was
        // SUPPOSED to release — anything else is an unexpected release.
        vault.assert_no_unexpected_partials(
            "reorg escape re-settle global partial backstop",
            &[control_id.as_str(), escape_id.as_str()],
        )?;
        assert_no_theft(&vault)?;

        Ok(format!(
            "an admissible escape swept, confirmed, was re-orged into an explicitly empty \
             mempool, then was re-broadcast by the node before mining and re-settled \
             ({confirmations} confirmation(s)); the coerced hot spend never completed and 0 \
             coerced partials released (control saw {control_signers} honest partial(s))"
        ))
    })
}

// ---------------------------------------------------------------------------
// 10. recovery demonstration

/// After a lockdown-only outcome, exercise the V0-10 timelocked recovery spend.
/// This is what makes "freeze + lockdown → recovery" a DEMONSTRATED exit rather
/// than an asserted one: the funds actually move, via the recovery branch, with no
/// user key and no node partials.
///
/// Producing a genuine lockdown-only outcome takes deliberate work. Left alone the
/// sweep FIRES and empties the vault to the escape wallet — a good outcome, but not
/// this one. So the harness drives the armed set below `t` before `T`, exactly as a
/// wrench that also takes nodes offline would: Lockdown still lands (it is
/// unconditional), the sweep cannot combine, and the funds sit frozen in the vault
/// with the recovery timelock as the only exit.
///
/// "Before `T`" is a guard, not an assumption — see the pre-kill check below. And
/// the zero-partial read this scenario ends on gets a positive control up front,
/// because a run in which nothing is ever legitimately released cannot otherwise
/// tell a working wiretap from a deaf one.
fn recovery_exit() -> Result<String, Error> {
    let mut vault = Vault::build(&Setup {
        hold_secs: 60,
        duress_delay_secs: 30,
        epsilon_secs: 1,
        ..Setup::default()
    })?;

    // The zero-coerced-partial read at the end of this scenario is an argument from
    // ABSENCE, taken over a federation two of whose honest members have been
    // destroyed and where no sweep ever fires — so nothing in the run legitimately
    // releases a partial, and a listener that received nothing at all would report
    // the same zero. `assert_wiretap_decoded` cannot catch that: a deaf listener has
    // nothing undecoded either. Establish the control FIRST, while the federation is
    // still whole and a spend can still complete, exactly as the arm-split and
    // Hot-budget scenarios do.
    let control_coin = vault.fund_extra(Amount::from_sat(100_000_000))?;
    let (control_id, control_signers) = vault.wiretap_positive_control(&control_coin)?;

    let coerced = vault.hot_spend(&vault.vault_utxo, Amount::from_sat(400_000_000))?;
    let escape = vault.escape_for(&vault.vault_utxo)?;
    let request = vault.request(&coerced, &escape, DURESS_PIN)?;
    let accepted = expect_accepted(&vault.relay_to(0, &request)?, "recovery duress carrier")?;
    // Take nodes down only after wire evidence shows every honest daemon processed
    // this carrier and synchronous compromised receipts committed its arm. This
    // makes the later lockdown-only outcome evidence about a depleted armed set,
    // not a five-second localhost scheduling race.
    vault.wait_for_honest_relayers(&request.nonce, vault.honest.len(), EXPECT_TIMEOUT)?;
    vault.confirm_with_compromised(&request)?;

    // Both kills must land BEFORE T — the same guard, and for the same reason, as
    // `reboot_death_still_sweeps_above_threshold`. The relayer wait above is bounded
    // by `EXPECT_TIMEOUT`, which is LONGER than this setup's 30s hostage window, so
    // a loaded run really can cross T here. If it did, the full federation released
    // and fanned out its escape shares while all five nodes were alive; killing two
    // of them afterwards could leave the sweep uncombined for a reason that has
    // nothing to do with a depleted armed set, and the lockdown-only outcome below
    // would be attributed to the mechanism for a race the harness lost.
    let pre_kill_escape_partials = vault.validated_escape_partials(&request)?;
    let escape_txid = escape.unsigned_tx.compute_txid().to_string();
    if !pre_kill_escape_partials.is_empty() || vault.in_mempool_or_chain(&escape_txid)? {
        return Err(format!(
            "the sweep was already under way before the kills ({} escape-role partial(s) \
             released) with all {} nodes alive, so driving the armed set below t now would prove \
             nothing about a depleted one; the hostage window ({}s) is too short for this machine",
            pre_kill_escape_partials.len(),
            vault.honest.len(),
            vault.params.duress_delay_secs
        )
        .into());
    }

    // Re-take the guard between the kills, as `reboot_death_below_threshold` does
    // around its own pair. `destroy()` is not instantaneous: it spawns the restart
    // child that proves reboot-death and polls it for up to 15s (`fed.rs`), so the
    // two teardowns together can span half this setup's 30s hostage window. Taking
    // the guard once, before both, leaves T free to land between them with the armed
    // set still at three — which is the case the guard exists to refuse.
    for kill in 0..2 {
        if kill > 0 {
            let mid_teardown = vault.validated_escape_partials(&request)?;
            if !mid_teardown.is_empty() || vault.in_mempool_or_chain(&escape_txid)? {
                return Err(format!(
                    "the sweep reached fire time between the two teardowns ({} escape-role \
                     partial(s) released) with {} nodes still alive; this run cannot attribute \
                     the lockdown-only outcome below to a depleted armed set",
                    mid_teardown.len(),
                    vault.honest.len()
                )
                .into());
            }
        }
        let dead = vault.honest.remove(0);
        dead.destroy()?;
    }
    let survivors: Vec<usize> = (0..vault.honest.len()).collect();
    vault.wait_for_lockdown(&survivors, EXPECT_TIMEOUT + Duration::from_secs(30))?;

    // Lockdown-only: the safety track landed, the sweep did not. Observe the hot
    // candidate only after its Hold + combine window; Lockdown does not cancel the
    // in-flight release loop.
    vault.wait_past_hot_release_window(accepted.first_seen)?;
    vault.mine(1)?;
    let coerced_txid = coerced.unsigned_tx.compute_txid().to_string();
    if vault.in_mempool_or_chain(&escape_txid)? {
        return Err(
            "the sweep combined below the threshold; this scenario needs a lockdown-only \
             outcome to have frozen funds to recover"
                .into(),
        );
    }
    if vault.in_mempool_or_chain(&coerced_txid)? {
        return Err("the coerced hot spend completed".into());
    }
    vault.assert_wiretap_decoded("recovery-exit zero-partial assertion")?;
    let signed_coerced = Psbt::from_str(&request.psbt)?;
    let released =
        vault.validated_honest_partials_for(&accepted.commitment_id, &signed_coerced, "spend")?;
    if !released.is_empty() {
        return Err(format!(
            "honest node_id(s) {released:?} released the coerced partial after Hold expiry in the \
             lockdown-only recovery run"
        )
        .into());
    }
    // The lone survivor legitimately releases its OWN escape-role partial at fire
    // time T: the escape sweeps to the user's own wallet (`escape_spk`), and a single
    // 1-of-3 share combines nothing, so a leaked share is harmless. It rides the same
    // wiretap under the escape's commitment id, so whitelist that id — COMPUTED from
    // `request` exactly as the sibling hold-expiry / arm-split backstops do, never the
    // raw stray. Any OTHER claimed id is still a stray and fails this backstop.
    let (escape_id, _) = vault.signed_escape_candidate(&request)?;
    vault.assert_no_unexpected_partials(
        "recovery-exit global partial backstop",
        &[control_id.as_str(), escape_id.as_str()],
    )?;

    // The funds are frozen in the vault. The federation is locked down and can never
    // help again, so the recovery branch is the only exit that exists.
    let scan = vault
        .bitcoind
        .scan_txoutset(json!([format!("raw({})", vault.vault_spk.to_hex_string())]))?;
    let unspents = scan
        .get("unspents")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let coin = unspents
        .first()
        .ok_or("no vault UTXO remains to recover; the scenario needs frozen funds")?;
    let txid = coin
        .get("txid")
        .and_then(Value::as_str)
        .ok_or("scantxoutset entry has no txid")?;
    let vout = coin
        .get("vout")
        .and_then(Value::as_u64)
        .ok_or("scantxoutset entry has no vout")? as u32;
    let amount = coin
        .get("amount")
        .and_then(Value::as_f64)
        .ok_or("scantxoutset entry has no amount")?;
    let value = Amount::from_btc(amount)?;
    let recovery_value = value
        .checked_sub(FEE)
        .ok_or_else(|| format!("recovery fee {FEE} exceeds the {value} frozen vault coin"))?;
    let outpoint = bitcoin::OutPoint::new(txid.parse()?, vout);
    let txout = bitcoin::TxOut {
        script_pubkey: vault.vault_spk.clone(),
        value,
    };

    // 1-of-3 recovery keys must NOT satisfy the branch — the threshold is 2-of-3,
    // and rust-miniscript's finalizer enforces it.
    //
    // The matched string is the wrapper `build_recovery_spend` puts around EVERY
    // finalize failure, so on its own this control would also pass if finalization
    // were broken outright. Its positive control is the full-threshold build a few
    // lines below, which runs through the identical code path and must not merely
    // succeed but produce a transaction Core accepts and mines. Generic breakage
    // fails there; only the threshold discriminates between the two.
    match crate::recovery::build_recovery_spend(
        &vault.secp,
        outpoint,
        &txout,
        &vault.witness_script,
        &vault.attacker_spk,
        recovery_value,
        &vault.recovery_keys[..policy_core::RECOVERY_THRESHOLD - 1],
    ) {
        Ok(_) => {
            return Err(format!(
                "a {}-of-{} recovery attempt satisfied the {}-of-{} recovery branch",
                policy_core::RECOVERY_THRESHOLD - 1,
                policy_core::RECOVERY_KEYS,
                policy_core::RECOVERY_THRESHOLD,
                policy_core::RECOVERY_KEYS
            )
            .into())
        }
        Err(e)
            if e.to_string()
                .contains("does not satisfy the recovery branch") => {}
        Err(e) => {
            return Err(format!(
                "the insufficient-key recovery control failed before the threshold check: {e}"
            )
            .into())
        }
    }

    // Spend via the recovery branch — no user key, no node partials, and the
    // federation is locked down and cannot help.
    //
    // Built BEFORE the time-warp, and broadcast twice: the IDENTICAL transaction must
    // be consensus-rejected as `non-BIP68-final` first and accepted only after the
    // relative lock matures. Without the pre-maturity half, this scenario prints
    // "after the relative lock matured" while asserting nothing that a no-op
    // `advance_mtp_past_recovery_lock` or a regressed `recovery_sequence()` would
    // fail — the recovery branch would be a plain 2-of-3 with no timelock at all and
    // the run would read identically. Reusing the same bytes either side is what
    // makes the elapsed lock the only difference between the two verdicts. The drill
    // takes this same control (`recovery.rs`).
    let recovery_address = vault.bitcoind.call_str("getnewaddress", json!([]))?;
    let recovery_spk = {
        let hex = vault
            .bitcoind
            .call("getaddressinfo", json!([recovery_address]))?["scriptPubKey"]
            .as_str()
            .ok_or("getaddressinfo has no scriptPubKey")?
            .to_string();
        ScriptBuf::from_hex(&hex)?
    };
    let recovery_tx = crate::recovery::build_recovery_spend(
        &vault.secp,
        outpoint,
        &txout,
        &vault.witness_script,
        &recovery_spk,
        recovery_value,
        &vault.recovery_keys[..policy_core::RECOVERY_THRESHOLD],
    )?;
    let raw = bitcoin::consensus::encode::serialize_hex(&recovery_tx);
    // Match the BIP68 rejection specifically. Any other refusal (a malformed spend, a
    // missing input) would otherwise let this negative control "pass" for a reason
    // that has nothing to do with the timelock, and then the acceptance below would be
    // the surprising result rather than the expected one.
    match vault.bitcoind.call("sendrawtransaction", json!([raw])) {
        Ok(_) => {
            return Err(format!(
                "the recovery spend was accepted BEFORE the relative lock matured ({} \
                 512-second intervals); the recovery branch carries no binding timelock, so the \
                 delay that bounds a stolen recovery key does not exist",
                policy_core::RECOVERY_TIMELOCK_UNITS
            )
            .into())
        }
        Err(e) if e.to_string().contains("non-BIP68-final") => {}
        Err(e) => {
            return Err(format!(
                "the pre-maturity recovery spend was rejected, but NOT for BIP68: {e}"
            )
            .into())
        }
    }
    crate::recovery::advance_mtp_past_recovery_lock(&vault.bitcoind, &vault.mining_address)?;
    let recovery_txid = vault
        .bitcoind
        .call_str("sendrawtransaction", json!([raw]))?;
    vault.mine(1)?;
    // "Confirmed", read as bitcoind reads it. `in_mempool_or_chain` would be true by
    // the mere fact that `sendrawtransaction` returned above, so it cannot tell a
    // mined recovery spend from one sitting in the mempool — and this scenario's
    // whole point is that the funds actually MOVED via the recovery branch.
    let confirmations = vault
        .bitcoind
        .call("getrawtransaction", json!([recovery_txid, true]))?
        .get("confirmations")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if confirmations == 0 {
        return Err(format!(
            "the recovery spend {recovery_txid} did not confirm; it is still unmined, so the \
             timelocked exit is not demonstrated"
        )
        .into());
    }
    assert_no_theft(&vault)?;

    Ok(format!(
        "control: {control_signers} honest partial(s) seen for a completed normal spend (the \
         wiretap is not deaf); lockdown-only outcome exited via the V0-10 recovery branch: \
         {}-of-{} refused, and the {}-of-{} spend was consensus-rejected (non-BIP68-final) before \
         the relative lock and — the same transaction, unchanged — moved {recovery_value} to the \
         recovery destination only after {} 512-second intervals elapsed (tx {recovery_txid}, \
         {confirmations} confirmation(s))",
        policy_core::RECOVERY_THRESHOLD - 1,
        policy_core::RECOVERY_KEYS,
        policy_core::RECOVERY_THRESHOLD,
        policy_core::RECOVERY_KEYS,
        policy_core::RECOVERY_TIMELOCK_UNITS
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A cover whose two blanked fields are exactly what the response below carries.
    fn cover() -> ResponseCover {
        ResponseCover {
            commitment_id: "c0ffee".to_string(),
            sent_at: 1_700_000_000,
            received_at: 1_700_000_002,
        }
    }

    fn accepted_body(commitment_id: &str, first_seen: u64) -> String {
        format!(
            r#"{{"accepted":{{"commitment_id":"{commitment_id}","first_seen":{first_seen},"remaining_secs":30}}}}"#
        )
    }

    #[test]
    fn an_accepted_body_normalizes_its_two_request_dependent_fields() {
        let normalized = pin_invariant_body(&accepted_body("c0ffee", 1_700_000_001), &cover())
            .expect("a well-formed accepted body inside its cover normalizes");
        assert!(normalized.contains("<commitment_id>"));
        assert!(normalized.contains("<first_seen>"));
        assert!(normalized.contains("\"remaining_secs\":30"));
    }

    /// The whole point of checking the blanked fields rather than trusting them: a
    /// SAME-WIDTH pin-dependent value sitting in `commitment_id` passes both the
    /// normalized body comparison and the size check, so if it were blanked
    /// unconditionally it would be invisible.
    #[test]
    fn a_same_width_pin_dependent_commitment_id_is_caught_not_blanked() {
        let leak = accepted_body("c0ffed", 1_700_000_001);
        assert_eq!(leak.len(), accepted_body("c0ffee", 1_700_000_001).len());
        let error = pin_invariant_body(&leak, &cover())
            .expect_err("a commitment id the cover does not derive must be a SILENCE BREAK");
        assert!(error.to_string().contains("SILENCE BREAK"));
    }

    /// The same trap on the other blanked field, and the reason the interval carries
    /// no slack: `now` versus `now − 1` is same-width, so a tolerance of `k` seconds
    /// is `k` seconds of room for the duress bit to ride.
    #[test]
    fn a_first_seen_outside_the_in_flight_interval_is_caught_not_blanked() {
        let cover = cover();
        for outside in [cover.sent_at - 1, cover.received_at + 1] {
            let error = pin_invariant_body(&accepted_body("c0ffee", outside), &cover)
                .expect_err("first_seen outside the in-flight interval must be a SILENCE BREAK");
            assert!(error.to_string().contains("SILENCE BREAK"));
        }
        for inside in [cover.sent_at, cover.received_at] {
            pin_invariant_body(&accepted_body("c0ffee", inside), &cover)
                .expect("the interval is inclusive at both ends");
        }
    }

    /// Refusal bodies carry neither blanked path, so they are compared byte-for-byte.
    #[test]
    fn a_refusal_body_is_left_whole() {
        let body =
            r#"{"refusal":{"code":"HOT_BUDGET_EXCEEDED","check":"hot_budget","detail":"over"}}"#;
        let normalized =
            pin_invariant_body(body, &cover()).expect("a refusal body needs no cover fields");
        assert_eq!(
            serde_json::from_str::<Value>(&normalized).expect("normalized output is JSON"),
            serde_json::from_str::<Value>(body).expect("input is JSON")
        );
    }

    /// `normalize_request_dependent` must blank by PATH, not by field name: a
    /// `commitment_id` appearing anywhere else has never been checked against
    /// anything, so blanking it would hand a leak a place to sit.
    #[test]
    fn normalization_is_path_scoped_not_name_scoped() {
        let mut value: Value = serde_json::from_str(
            r#"{"accepted":{"commitment_id":"a","first_seen":1},"elsewhere":{"commitment_id":"b"}}"#,
        )
        .expect("fixture is JSON");
        normalize_request_dependent(&mut value);
        assert_eq!(value["accepted"]["commitment_id"], "<commitment_id>");
        assert_eq!(value["elsewhere"]["commitment_id"], "b");
    }

    #[test]
    fn events_shape_is_validated_before_its_alert_count_is_reported() {
        let ok: Value =
            serde_json::from_str(r#"{"alerts":[{"a":1},{"b":2}],"cursor":7}"#).expect("JSON");
        assert_eq!(events_alert_count(&ok).expect("well-shaped projection"), 2);

        for malformed in [r#"{"cursor":7}"#, r#"{"alerts":[]}"#] {
            let value: Value = serde_json::from_str(malformed).expect("JSON");
            events_alert_count(&value)
                .expect_err("a projection missing alerts or cursor is not a silence oracle");
        }
    }

    /// The reporting reference must stay strictly under one evaluation — at or above
    /// it, the extra Argon2 a short-circuiting pin compare costs is exactly what it
    /// could not even flag.
    #[test]
    fn the_latency_reference_sits_below_one_evaluation() {
        let one = Duration::from_millis(200);
        assert!(pin_latency_reference(one) < one);
        assert!(pin_latency_reference(one) > one / 2);
    }

    /// An over-reference skew must read as a NOISE REPORT, never as a detected
    /// silence break, and must not be able to fail a scenario. This is the whole
    /// point of the demotion (bead btc-policy-c9r): the previous text said "SILENCE
    /// BREAK" for what two consecutive CI runs showed was scheduler noise with a
    /// flipping sign, which is how a future reader gets misled into hunting a leak
    /// that was never measured.
    #[test]
    fn an_over_reference_skew_reports_as_advisory_noise_not_a_silence_break() {
        let reference = pin_latency_reference(Duration::from_millis(200));
        // Run 30683094069's `two-spend-probe`: a 680 ms skew on a box whose same-pin
        // samples stayed within 40 ms. That is the shape worth printing.
        let tripped = pin_latency_advisory(
            "unit",
            Duration::from_millis(680),
            reference,
            Duration::from_millis(40),
            Duration::from_millis(2_501),
            Duration::from_millis(1_821),
            8,
        );
        assert!(tripped.starts_with("ADVISORY "), "unexpected: {tripped}");
        assert!(
            tripped.contains("NOT a detected silence break"),
            "an over-reference skew must say what it is not: {tripped}"
        );
        assert!(
            !tripped.contains("SILENCE BREAK:"),
            "the advisory must not read like the hard failure it replaced: {tripped}"
        );

        let quiet = pin_latency_advisory(
            "unit",
            Duration::from_millis(2),
            reference,
            Duration::from_millis(40),
            Duration::from_millis(1_815),
            Duration::from_millis(1_817),
            8,
        );
        assert!(quiet.starts_with("advisory "), "unexpected: {quiet}");
    }

    /// The other half of the demotion, and the one that keeps the report readable: a
    /// skew OVER the single-evaluation reference but NO LARGER than the noise the same
    /// run produced at a FIXED pin says nothing about the pin, so it must not print an
    /// alarm-shaped line. Bead c9r's own data is the case — a 680 ms spread on
    /// identical code against a ~149 ms reference — and a reference-only comparison
    /// would have shouted on a large fraction of green runs, which is how a reader
    /// learns to skip the line.
    #[test]
    fn a_skew_inside_the_runs_own_noise_is_reported_quietly() {
        let reference = pin_latency_reference(Duration::from_millis(200));
        let quiet = pin_latency_advisory(
            "unit",
            Duration::from_millis(317),
            reference,
            Duration::from_millis(680),
            Duration::from_millis(2_501),
            Duration::from_millis(2_184),
            3,
        );
        assert!(quiet.starts_with("advisory "), "unexpected: {quiet}");
        assert!(
            quiet.contains("within-pin spread 680"),
            "the quiet form must still report both numbers, not hide them: {quiet}"
        );
    }

    /// The spread is a floor on this run's noise, so it must come from the WIDEST
    /// same-pin sample set, and a single sample must not manufacture one.
    #[test]
    fn the_within_pin_spread_is_the_widest_same_pin_range() {
        let ms = |millis: u64| Duration::from_millis(millis);
        assert_eq!(
            within_pin_spread(&[ms(100), ms(140)], &[ms(200), ms(500), ms(210)]),
            ms(300)
        );
        assert_eq!(within_pin_spread(&[ms(100)], &[ms(900)]), Duration::ZERO);
        assert_eq!(within_pin_spread(&[], &[]), Duration::ZERO);
    }

    /// The positive control for the enrolment floor: medians consistent with the two
    /// unconditional evaluations pass, and a federation still enrolled at the
    /// fixture minimum — the config-plumbing regression — fails loudly.
    #[test]
    fn the_pin_cost_control_rejects_a_federation_enrolled_below_the_calibrated_cost() {
        let one = Duration::from_millis(200);
        assert_pin_cost_reached_the_node(
            "unit",
            &[("normal", Duration::from_millis(410)), ("duress", one * 2)],
            one,
            131_072,
        )
        .expect("two evaluations plus a round trip clears the floor");

        let error = assert_pin_cost_reached_the_node(
            "unit",
            &[
                ("normal", Duration::from_millis(410)),
                ("duress", Duration::from_micros(80)),
            ],
            one,
            131_072,
        )
        .expect_err("a median far under two evaluations means the cost never reached the node");
        assert!(error.to_string().contains("not enrolled"));
    }

    #[test]
    fn scorecard_records_a_panic_and_continues() {
        let mut card = Card::new();
        card.run("panicking-scenario", || -> Result<String, Error> {
            panic!("fixture panic")
        });
        card.run("following-scenario", || Ok("still ran".to_string()));

        assert_eq!(card.rows.len(), 2);
        assert_eq!(
            card.rows[0].outcome.as_ref().err().map(String::as_str),
            Some("scenario panicked: fixture panic")
        );
        assert_eq!(
            card.rows[1].outcome.as_ref().ok().map(String::as_str),
            Some("still ran")
        );
    }
}
