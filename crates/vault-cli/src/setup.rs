//! `btc-vault setup` — the **production setup ceremony** (ADR-0013 §4, DESIGN.md
//! D4/T1; bead btc-policy-9y5.5).
//!
//! This is the trust bootstrap. Everything else in the system is a state machine
//! defending a vault that this code decides the shape of, and a perfect state
//! machine cannot compensate for a setup machine that has seen every signer secret.
//! So the ceremony is built around one rule:
//!
//! > **No machine ever holds two node secrets.** Each node births its own key on
//! > its own host; only PUBLIC bytes travel to the coordinator.
//!
//! ## The five steps, and which machine runs each
//!
//! ```text
//!  node host i    setup node-keygen    → node-public.json   (PUBLIC)   + a preimage
//!                                                                       the operator
//!                                                                       writes down
//!  escape device  setup keygen --role escape → escape.json  (PUBLIC)   + the escape
//!                              --network <bitcoin|signet|regtest>       wallet secret
//!  coordinator    setup assemble       → descriptor, wallet_id, manifest_hash,
//!                                        coordinator auth key, INDEPENDENCE EVIDENCE,
//!                                        one endorsement request per node
//!  node host i    setup node-endorse   → endorsement-<id>.txt (PUBLIC)
//!  coordinator    setup finalize       → manifest, per-node configs, BACKUPS
//! ```
//!
//! Two rounds are not ceremony for its own sake. A node's channel-key endorsement is
//! signed over `manifest_hash` (ADR-0013 §4 — that domain separator is what stops a
//! manifest from another vault being substituted), and `manifest_hash` is not known
//! until every node's public key is in. The only way to collapse this to one round
//! is to hand the coordinator the node secrets, which is the thing being removed.
//!
//! ## Escape independence (ADR-0012 §10, ADR-0003)
//!
//! A shared-seed escape wallet converts duress into THEFT: the sweep hands the
//! vault to a post-wrench attacker who already holds the user key. This ceremony
//! therefore does three things instead of the one tripwire ADR-0003 had:
//!
//!  1. the escape descriptor arrives as its own `keygen --role escape` artifact —
//!     a distinct generation step on a distinct device, not a string pasted in
//!     beside the node bundles;
//!  2. [`check_independence`] HARD-FAILS the ceremony on any detectable overlap
//!     between the escape wallet and the user key, any node key, any recovery key,
//!     or the hot wallet — including a bounded scan of the escape wallet's DERIVED
//!     keys, which is what catches "the escape wallet is the user's key at some
//!     index" now that vault keys are definite and carry no origin to compare;
//!  3. the evidence — every fingerprint and key compared, and the verdict — is
//!     written to `independence.txt` and printed, so the operator sees what was
//!     actually checked rather than a silent pass.
//!
//! What code still cannot check is stated in the report itself and in ADR-0003:
//! two keys from one seed at unrelated paths are cryptographically unlinkable, and
//! no software can verify that two commands ran on two physical devices.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::str::FromStr;

use bitcoin::bip32::{Xpriv, Xpub};
use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1::{All, Secp256k1, SecretKey};
use bitcoin::{NetworkKind, PublicKey};
use miniscript::{Descriptor, DescriptorPublicKey, ForEachKey};
use serde::{Deserialize, Serialize};
use vault_node::channel::ceremony;
use vault_node::nodekey::{self, KdfParams, Preimage};
use zeroize::{Zeroize, Zeroizing};

use crate::http::Error;

/// The file a node host keeps its published public bundle in.
const NODE_BUNDLE_FILE: &str = "node-public.json";

// ---------------------------------------------------------------------------
// Public artifacts
//
// Everything in this section is designed to be safe to copy off the machine that
// produced it. If a field here were secret the ceremony would be back where it
// started, so each type says explicitly what it carries.

/// What a node publishes after generating its own key: its two PUBLIC keys, the
/// PUBLIC derivation parameters its daemon will re-derive with, and where it
/// listens. No secret, by construction — the secret is the preimage, and the
/// preimage never enters this type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct NodeBundle {
    /// The node's federation signing pubkey — a vault descriptor key.
    pub(crate) signing_pubkey: String,
    /// The channel pubkey the daemon re-derives from its signing key at startup.
    pub(crate) channel_pubkey: String,
    /// wskdf salt (hex), Argon2id passes, Argon2id memory in KiB.
    pub(crate) node_key_salt: String,
    pub(crate) node_key_ops: u32,
    pub(crate) node_key_mem_kib: u32,
    /// Transport endpoints, pinned into the manifest (ADR-0013 §4).
    pub(crate) endpoints: Vec<String>,
}

impl NodeBundle {
    pub(crate) fn signing_pubkey(&self) -> Result<PublicKey, Error> {
        nodekey::parse_compressed_pubkey(&self.signing_pubkey)
    }

    pub(crate) fn channel_pubkey(&self) -> Result<PublicKey, Error> {
        nodekey::parse_compressed_pubkey(&self.channel_pubkey)
    }

    pub(crate) fn kdf(&self) -> Result<KdfParams, Error> {
        KdfParams::from_hex_salt(
            &self.node_key_salt,
            self.node_key_ops,
            self.node_key_mem_kib,
        )
    }
}

/// A wallet or key generated in its own distinct ceremony step, on its own device.
/// `descriptor` is present for wallet roles (escape), `pubkey` for the definite
/// vault roles (user, recovery).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct KeyBundle {
    /// `escape`, `user`, or `recovery`.
    pub(crate) role: String,
    /// Ranged wallet descriptor (escape only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) descriptor: Option<String>,
    /// Definite compressed pubkey (user / recovery).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) pubkey: Option<String>,
    /// BIP32 master fingerprint, when the role has one. The ADR-0003 tripwire.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) master_fingerprint: Option<String>,
}

// ---------------------------------------------------------------------------
// Policy numbers
//
// One struct, shared by the ceremony's config writer and the regtest harness, so
// "what the manifest was sealed over" and "what the configs say" cannot drift.

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PolicyParams {
    pub(crate) max_derivation_index: u32,
    pub(crate) hold_secs: u64,
    pub(crate) duress_delay_secs: u64,
    pub(crate) epsilon_secs: u64,
    pub(crate) combine_slack_secs: u64,
    pub(crate) delivery_horizon_secs: u64,
    pub(crate) max_commitment_age_secs: u64,
    pub(crate) policy_version: u32,
    pub(crate) escape_feerate_floor: u64,
    /// The fire-time escape coverage threshold (ADR-0013 §6). Federation-uniform and
    /// sealed into the manifest beside `escape_feerate_floor` (bead btc-policy-9y5.7):
    /// the ceremony hashes it and `node_config_toml` emits it, so every node's
    /// configured value is provably the one sealed, or that node fails startup.
    pub(crate) escape_coverage_pct: u8,
    /// Sealed whole-fee ceiling for replacement rungs (ADR-0016 §2).
    /// Defaults to `0`; [`check_escape_bump_ceiling`] currently accepts nothing else.
    #[serde(default)]
    pub(crate) escape_bump_max_fee_pct: u8,
    /// The vault's ONE chain (bead btc-policy-sealed-network-v2-mn6). Mandatory and
    /// un-defaulted: a defaulted network would let a ceremony that never names a chain
    /// seal one silently, into an immutable manifest. The adapter below is what keeps
    /// this struct `Copy` — `bitcoin`'s serde feature stays off (it would also accept
    /// `test`/`testnet4` and Core's `main`), and a `String` newtype would put an
    /// allocation in the struct the ceremony and the config writer share by copy.
    #[serde(with = "network_serde")]
    pub(crate) network: bitcoin::Network,
    pub(crate) hot_max_per_tx: u64,
    pub(crate) hot_max_per_window: u64,
    pub(crate) hot_window_secs: u64,
    pub(crate) max_msg_bytes: u64,
}

/// The one serde adapter for [`PolicyParams::network`]: canonical spellings only, and
/// exactly the ones [`vault_node::parse_vault_network`] accepts, so ceremony JSON and
/// node TOML cannot disagree about what a network name means.
mod network_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(
        network: &bitcoin::Network,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(vault_node::vault_network_name(*network))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<bitcoin::Network, D::Error> {
        let raw = String::deserialize(deserializer)?;
        vault_node::parse_vault_network(&raw).map_err(serde::de::Error::custom)
    }
}

impl PolicyParams {
    fn hot_budget(&self) -> vault_node::HotBudget {
        vault_node::HotBudget {
            max_per_tx_sat: self.hot_max_per_tx,
            max_per_window_sat: self.hot_max_per_window,
            window_secs: self.hot_window_secs,
        }
    }
}

/// Everything one node's config file needs. The ONE writer for a per-node policy
/// config: the ceremony and the regtest harness both go through it, so a field
/// added for one is present for the other instead of silently missing from a
/// federation that then fails startup — or, worse, boots weaker.
pub(crate) struct NodeConfig<'a> {
    pub(crate) listen_port: u16,
    pub(crate) kdf: &'a KdfParams,
    pub(crate) descriptor: &'a str,
    pub(crate) allowlist: &'a [String],
    pub(crate) escape_descriptor: &'a str,
    pub(crate) policy: &'a PolicyParams,
    pub(crate) coordinator_auth_pubkey: &'a str,
    pub(crate) pin_normal_hash: &'a str,
    pub(crate) pin_duress_hash: &'a str,
    /// `(rpc_addr, auth)`. Mandatory in channel mode — a node that cannot broadcast
    /// would accept spends it can never complete — so this is `Option` only for the
    /// channel-less fixtures that never reach a chain.
    pub(crate) chain_backend: Option<(&'a str, &'a str)>,
    /// The rendered `[channel]` block, or empty for channel-less mode.
    pub(crate) channel_toml: &'a str,
}

/// Render a per-node policy config (ADR-0013 §5).
///
/// **There is no key in here.** `node_key_salt`/`_ops`/`_mem_kib` name the
/// derivation; the operator supplies the preimage on the daemon's stdin.
pub(crate) fn node_config_toml(config: &NodeConfig) -> String {
    let allowlist: Vec<String> = config
        .allowlist
        .iter()
        .map(|descriptor| format!("\"{descriptor}\""))
        .collect();
    let p = config.policy;
    // Table headers end the top-level section, so `[chain_backend]` and `[channel]`
    // come last. `coordinator_auth_pubkey` is the trust root (ADR-0013 §2/§4): the
    // same key in every node's config and — in channel mode — hashed into
    // `manifest_hash`, so a node sealed to this manifest will not boot under a
    // swapped coordinator.
    let mut toml = format!(
        "listen_port = {}\n\
         node_key_salt = \"{}\"\n\
         node_key_ops = {}\n\
         node_key_mem_kib = {}\n\
         descriptor = \"{}\"\n\
         allowlist = [{}]\n\
         escape_descriptor = \"{}\"\n\
         max_derivation_index = {}\n\
         hold_secs = {}\n\
         duress_delay_secs = {}\n\
         epsilon_secs = {}\n\
         combine_slack_secs = {}\n\
         delivery_horizon_secs = {}\n\
         hot_max_per_tx = {}\n\
         hot_max_per_window = {}\n\
         hot_window_secs = {}\n\
         max_commitment_age_secs = {}\n\
         policy_version = {}\n\
         protocol_version = {}\n\
         escape_feerate_floor = {}\n\
         escape_coverage_pct = {}\n\
         escape_bump_max_fee_pct = {}\n\
         network = \"{}\"\n\
         pin_normal_hash = \"{}\"\n\
         pin_duress_hash = \"{}\"\n\
         coordinator_auth_pubkey = \"{}\"\n",
        config.listen_port,
        config.kdf.salt_hex(),
        config.kdf.ops(),
        config.kdf.mem_kib(),
        config.descriptor,
        allowlist.join(", "),
        config.escape_descriptor,
        p.max_derivation_index,
        p.hold_secs,
        p.duress_delay_secs,
        p.epsilon_secs,
        p.combine_slack_secs,
        p.delivery_horizon_secs,
        p.hot_max_per_tx,
        p.hot_max_per_window,
        p.hot_window_secs,
        p.max_commitment_age_secs,
        p.policy_version,
        vault_node::channel::PROTOCOL_VERSION,
        p.escape_feerate_floor,
        p.escape_coverage_pct,
        p.escape_bump_max_fee_pct,
        vault_node::vault_network_name(p.network),
        config.pin_normal_hash,
        config.pin_duress_hash,
        config.coordinator_auth_pubkey,
    );
    if let Some((rpc_addr, auth)) = config.chain_backend {
        toml.push_str(&format!(
            "\n[chain_backend]\nrpc_addr = \"{rpc_addr}\"\nauth = \"{auth}\"\n"
        ));
    }
    toml.push_str(config.channel_toml);
    toml
}

// ---------------------------------------------------------------------------
// Key independence (ADR-0003, ADR-0012 §10)

/// Everything the independence check compares. Borrowed rather than owned so the
/// caller cannot accidentally hand it a stale copy of the descriptor's keys.
pub(crate) struct IndependenceInputs<'a> {
    pub(crate) user_key: PublicKey,
    pub(crate) node_keys: &'a [PublicKey],
    pub(crate) recovery_keys: &'a [PublicKey],
    /// The coordinator auth key (ADR-0013 §2 trust root). It is not in the frozen
    /// descriptor, but a hostile-at-wrench coordinator (ADR-0010, ADR-0012) whose
    /// key can derive the escape wallet is the same duress→theft shape as a shared
    /// user key, so the escape scan compares against it too.
    pub(crate) coordinator_key: PublicKey,
    pub(crate) escape_descriptor: &'a str,
    pub(crate) hot_descriptors: &'a [String],
    /// The bound on the derived-key scan — the same `max_derivation_index` the
    /// nodes enforce, so the ceremony checks exactly the keys a node would ever
    /// accept an output to.
    pub(crate) max_derivation_index: u32,
}

/// Run the ceremony-time independence checks and produce the witnessed evidence.
///
/// `Err` means the ceremony must STOP: a detected overlap between the escape
/// wallet and the vault's own keys is the shared-seed → duress-becomes-theft case
/// (ADR-0012 §10), not a warning to click through. `Ok` carries the report text —
/// what was compared, what the residual is — for the operator and the artifact
/// directory.
pub(crate) fn check_independence(inputs: &IndependenceInputs) -> Result<String, Error> {
    let secp = Secp256k1::new();
    let escape = Descriptor::<DescriptorPublicKey>::from_str(inputs.escape_descriptor)
        .map_err(|e| format!("escape descriptor does not parse: {e}"))?;
    let escape_keys = derived_keys(&secp, &escape, inputs.max_derivation_index)?;

    // The escape wallet must be a KEY-CONTROLLED, RANGED wallet — the shape
    // `keygen --role escape` produces. A hand-written bundle (the documented mainnet
    // path) could otherwise seal a destination that makes every swept coin
    // anyone-spendable (`wsh(1)`) or permanently unspendable (`wsh(0)`): both parse and
    // carry no key, so the overlap scan below passes them trivially. Require a wildcard
    // (a fresh address per sweep, per the destination-allowlist rule) and at least one
    // derivable key (a signature-controlled spend), refusing before the manifest seals.
    if !escape.has_wildcard() {
        return Err(
            "the escape descriptor is not a ranged wallet (no `/*`): each incident sweep \
                    must pay a fresh address, so a definite or scriptless escape is not the \
                    intended wallet. Generate it with `btc-vault setup keygen --role escape \
                    --network <bitcoin|signet|regtest>`."
                .into(),
        );
    }
    if escape_keys.is_empty() {
        return Err(
            "the escape descriptor is not key-controlled — it derives no keys, so swept \
                    funds would be anyone-spendable or permanently unspendable. The escape wallet \
                    must be a signature-controlled ranged wallet (`btc-vault setup keygen --role \
                    escape`)."
                .into(),
        );
    }

    let mut report = String::new();
    report.push_str("btc-vault setup — key independence evidence (ADR-0003, ADR-0012 §10)\n");
    report.push_str("====================================================================\n\n");
    report.push_str(
        "A shared-seed escape wallet turns the duress sweep into THEFT: a post-wrench\n\
         attacker holding the user key would control the escape wallet, and the sweep\n\
         would hand them the vault. The escape key MUST be generated independently, on\n\
         its own device, in its own step. What follows is what this ceremony could\n\
         verify mechanically.\n\n",
    );

    // Vault keys, named. These are DEFINITE keys (one concrete pubkey per role), so
    // the comparison below is over the keys themselves — there is no origin or xpub
    // left to compare, which is exactly why the derived-key scan carries the weight
    // that ADR-0003's fingerprint tripwire used to.
    let mut vault_keys: Vec<(String, PublicKey)> = vec![("user".to_string(), inputs.user_key)];
    for (i, key) in inputs.node_keys.iter().enumerate() {
        vault_keys.push((format!("node[{i}]"), *key));
    }
    for (i, key) in inputs.recovery_keys.iter().enumerate() {
        vault_keys.push((format!("recovery[{i}]"), *key));
    }

    report.push_str("Vault keys (definite, from the frozen descriptor):\n");
    for (role, key) in &vault_keys {
        report.push_str(&format!("  {role:<12} {key}\n"));
    }
    // The coordinator auth key is not in the descriptor, but a compromised
    // coordinator that can derive the escape wallet is the same duress→theft, so it
    // joins the comparison set as a distinct target.
    let mut comparison_keys: Vec<(String, PublicKey)> = vault_keys.clone();
    comparison_keys.push(("coordinator".to_string(), inputs.coordinator_key));
    report.push_str(&format!(
        "  {:<12} {}   (trust root, ADR-0013 §2 — not in the descriptor)\n",
        "coordinator", inputs.coordinator_key
    ));

    // The escape descriptor's ANCESTOR keys: the xpub each derived child hangs off,
    // plus every non-hardened step down to the wildcard's parent. The derived-key
    // scan below sees only the children (`…/i`); it never sees the parent. But
    // non-hardened BIP32 derivation is child_priv = parent_priv + HMAC(chaincode,
    // parent_pub‖i) with a PUBLIC chain code, so whoever holds an ancestor private
    // key can derive every child private key. If an ancestor pubkey is a vault key
    // (or the coordinator key), the escape wallet is NOT independent and the sweep
    // pays that key's holder — the exact ADR-0012 §10 duress→theft that comparing
    // only the derived children misses.
    let escape_ancestors = escape_ancestor_keys(&secp, &escape);

    report.push_str(&format!(
        "\nEscape wallet: {}\n  derived keys scanned: 0..={} ({} keys); ancestor keys \
         compared: {}\n",
        inputs.escape_descriptor,
        inputs.max_derivation_index,
        escape_keys.len(),
        escape_ancestors.len(),
    ));

    // (1) Escape ⟂ every vault key AND the coordinator key. The load-bearing one.
    // A comparison key that the escape wallet DERIVES (a shared child) and one that
    // is an ANCESTOR xpub of the escape wallet (a shared/parent key that derives
    // every child) are both fatal.
    let mut violations: Vec<String> = Vec::new();
    for (role, key) in &comparison_keys {
        if let Some(index) = escape_keys.get(key) {
            violations.push(format!(
                "the escape wallet derives the {role} key {key} at index {index}: the escape \
                 wallet is NOT independent of the vault, and a duress sweep would pay an \
                 attacker who holds that key"
            ));
        }
        if escape_ancestors.contains(key) {
            violations.push(format!(
                "the {role} key {key} is an ANCESTOR xpub of the escape wallet: whoever holds \
                 its private key can derive every escape address (non-hardened BIP32 over the \
                 public chain code), so a duress sweep would pay that key's holder — the escape \
                 wallet is NOT independent of the vault"
            ));
        }
    }

    // (2) Escape ⟂ hot. Not merely "no shared leaf": if a hot key — a derived leaf OR
    // an ancestor xpub — is an ANCESTOR of the escape wallet (e.g. hot = parent/*,
    // escape = (parent/N)/*), the hot parent private key derives every escape address,
    // so the hot-key holder could control the duress sweep — the same theft the vault
    // scan catches, through the hot key. The fingerprint tripwire (3) misses this: an
    // origin-less parent and its child carry DIFFERENT fallback fingerprints. So
    // compare the FULL key set of each side — derived leaves ∪ ancestor xpubs — which
    // catches a derivation relationship in either direction, not only an identical
    // descriptor or a coincident leaf.
    let mut escape_all: BTreeSet<PublicKey> = escape_keys.keys().copied().collect();
    escape_all.extend(escape_ancestors.iter().copied());
    for hot in inputs.hot_descriptors {
        let parsed = Descriptor::<DescriptorPublicKey>::from_str(hot)
            .map_err(|e| format!("hot descriptor does not parse: {e}"))?;
        if parsed.to_string() == escape.to_string() {
            violations.push(format!(
                "the escape descriptor and a hot descriptor are the same wallet ({hot})"
            ));
            continue;
        }
        let mut hot_all: BTreeSet<PublicKey> =
            derived_keys(&secp, &parsed, inputs.max_derivation_index)?
                .into_keys()
                .collect();
        hot_all.extend(escape_ancestor_keys(&secp, &parsed));
        for key in hot_all.intersection(&escape_all) {
            violations.push(format!(
                "the escape wallet and the hot wallet share or derive the key {key}: one wallet is \
                 an ancestor of the other, so the hot-key holder could control the escape sweep"
            ));
        }
    }

    // (3) The ADR-0003 fingerprint tripwire, kept as defence-in-depth. It applies
    // between the RANGED wallets, which are the only descriptors here that still
    // carry BIP32 origins.
    let escape_fingerprints = fingerprints(&escape);
    report.push_str(&format!(
        "  master fingerprints: {}\n",
        if escape_fingerprints.is_empty() {
            "(none declared — the descriptor carries no BIP32 origin)".to_string()
        } else {
            escape_fingerprints.join(", ")
        }
    ));
    for hot in inputs.hot_descriptors {
        let parsed = Descriptor::<DescriptorPublicKey>::from_str(hot)
            .map_err(|e| format!("hot descriptor does not parse: {e}"))?;
        for fingerprint in fingerprints(&parsed) {
            if escape_fingerprints.contains(&fingerprint) {
                violations.push(format!(
                    "the escape wallet and the hot wallet share BIP32 master fingerprint \
                     {fingerprint}: they came from one seed"
                ));
            }
        }
    }

    report.push_str("\nChecks:\n");
    report.push_str("  [x] escape wallet vs every vault key (user, nodes, recovery) AND the\n      coordinator auth key — both the full derivation scan the nodes enforce AND\n      the escape wallet's ANCESTOR xpubs (a shared parent key derives every child)\n");
    report.push_str("  [x] escape wallet vs hot wallet (same descriptor, shared derived key,\n      shared BIP32 master fingerprint)\n");
    report.push_str("  [x] user / node / recovery keys all distinct (enforced by the vault\n      template parse — a duplicate is a rejected descriptor, not a warning)\n");

    if !violations.is_empty() {
        let mut message = String::from(
            "KEY INDEPENDENCE VIOLATED — the ceremony refuses to seal this vault.\n\n",
        );
        for violation in &violations {
            message.push_str(&format!("  * {violation}\n"));
        }
        message.push_str(
            "\nRegenerate the escape wallet on a DIFFERENT device, from a DIFFERENT seed\n\
             (`btc-vault setup keygen --role escape --network <bitcoin|signet|regtest>`),\n\
             and run the ceremony again.\n",
        );
        return Err(message.into());
    }

    report.push_str("\nVERDICT: no overlap detected.\n\n");
    report.push_str(
        "RESIDUAL — what no software can check (ADR-0003):\n\
        \x20 * Two keys derived from ONE seed at unrelated paths are cryptographically\n\
        \x20   unlinkable. A scan finds them only if the paths happen to collide.\n\
        \x20 * Physical device separation cannot be verified at all. That the escape\n\
        \x20   wallet was generated on a different machine than the coordinator and the\n\
        \x20   nodes is carried by the ceremony procedure, not by this check.\n\n\
         If the escape wallet shares a seed with the user key, DURESS IS THEFT: the\n\
         sweep pays the attacker. Regenerate rather than assume.\n",
    );
    Ok(report)
}

/// Every concrete key a ranged descriptor derives over `0..=max_index`, mapped to
/// the first index that produced it.
fn derived_keys(
    secp: &Secp256k1<All>,
    descriptor: &Descriptor<DescriptorPublicKey>,
    max_index: u32,
) -> Result<BTreeMap<PublicKey, u32>, Error> {
    let mut keys = BTreeMap::new();
    // A BIP389 multipath descriptor (`…/<0;1>/*`) — a common hardware-wallet export
    // shape — cannot be `derived_descriptor`'d directly: it yields
    // `ConversionError::MultiKey`. Expand it into one single-path descriptor per
    // branch first, exactly as policy-core does at fire time (`into_single_descriptors`),
    // so the ceremony scans the same key set a node would ever accept an output to
    // rather than rejecting a wallet the runtime accepts. For the escape wallet this
    // also means the independence scan covers BOTH branches. A non-multipath
    // descriptor expands to itself, so this one path covers every shape.
    let singles = descriptor
        .clone()
        .into_single_descriptors()
        .map_err(|e| format!("cannot expand {descriptor} into single-path descriptors: {e}"))?;
    for single in &singles {
        // A definite descriptor has no range; deriving at index 0 yields it
        // unchanged, so one pass covers both shapes without a special case.
        let last = if single.has_wildcard() { max_index } else { 0 };
        for index in 0..=last {
            let derived = single
                .derived_descriptor(secp, index)
                .map_err(|e| format!("cannot derive {single} at index {index}: {e}"))?;
            derived.for_each_key(|key| {
                keys.entry(*key).or_insert(index);
                true
            });
        }
    }
    Ok(keys)
}

/// The escape descriptor's ANCESTOR public keys: for every extended key it names,
/// the xpub itself plus each key along the non-hardened prefix of its derivation
/// path — every key whose PRIVATE key would let its holder derive the escape
/// wallet's children. Compared against the vault keys, this catches what the child
/// scan cannot: a vault key that is the escape wallet's PARENT xpub rather than one
/// of its derived children (the ADR-0012 §10 duress→theft, empirically the
/// reused-account-xpub case a hand-written hardware-wallet bundle can hit).
///
/// A hardened step ends the pub-derivable chain (an xpub cannot derive hardened
/// children); the ancestors already collected above it are still returned, since
/// holding one of THOSE private keys still reaches every child.
fn escape_ancestor_keys(
    secp: &Secp256k1<All>,
    descriptor: &Descriptor<DescriptorPublicKey>,
) -> Vec<PublicKey> {
    let mut ancestors = Vec::new();
    descriptor.for_each_key(|key| {
        match key {
            DescriptorPublicKey::XPub(x) => {
                collect_xpub_ancestors(secp, &x.xkey, &x.derivation_path, &mut ancestors)
            }
            DescriptorPublicKey::MultiXPub(x) => {
                for path in x.derivation_paths.paths() {
                    collect_xpub_ancestors(secp, &x.xkey, path, &mut ancestors);
                }
            }
            // A single key IS its own derived key; the child scan already has it.
            DescriptorPublicKey::Single(_) => {}
        }
        true
    });
    ancestors
}

/// Push `xkey` and each non-hardened step of `path` (the ancestors down to the
/// wildcard's parent) onto `out`, de-duplicated.
fn collect_xpub_ancestors(
    secp: &Secp256k1<All>,
    xkey: &Xpub,
    path: &bitcoin::bip32::DerivationPath,
    out: &mut Vec<PublicKey>,
) {
    let mut current = *xkey;
    let key = PublicKey::new(current.public_key);
    if !out.contains(&key) {
        out.push(key);
    }
    for step in path.into_iter() {
        match current.ckd_pub(secp, *step) {
            Ok(child) => {
                current = child;
                let key = PublicKey::new(current.public_key);
                if !out.contains(&key) {
                    out.push(key);
                }
            }
            // Hardened: cannot derive further from a public key. Stop; the ancestors
            // above are already recorded.
            Err(_) => break,
        }
    }
}

/// The BIP32 master fingerprints a descriptor's keys declare — ADR-0003's tripwire.
///
/// `master_fingerprint()` is the origin's fingerprint when the key expression
/// carries one, and the key's own fingerprint otherwise. That fallback is why the
/// check is defence-in-depth rather than the primary guarantee: two ORIGIN'd keys
/// sharing a fingerprint really did come from one seed, while two origin-less ones
/// only collide if they are the same key, which the derived-key scan already
/// catches.
fn fingerprints(descriptor: &Descriptor<DescriptorPublicKey>) -> Vec<String> {
    let mut found = Vec::new();
    descriptor.for_each_key(|key| {
        let text = key.master_fingerprint().to_string();
        if !found.contains(&text) {
            found.push(text);
        }
        true
    });
    found
}

// ---------------------------------------------------------------------------
// The ceremony, as a library (the CLI below is a thin wrapper, and the regtest
// harness drives these same functions — a demo that proved a second, harness-local
// provisioning path would be evidence about nothing).

/// A node's place in the assembled federation.
#[derive(Debug)]
pub(crate) struct SealedNode {
    pub(crate) node_id: u16,
    pub(crate) signing_pubkey: PublicKey,
    pub(crate) channel_pubkey: PublicKey,
    pub(crate) endpoints: Vec<String>,
}

/// What `assemble` produces: the frozen vault, its anchor, and the per-node
/// endorsement requests round two answers.
#[derive(Debug)]
pub(crate) struct Assembled {
    pub(crate) descriptor: String,
    pub(crate) wallet_id: [u8; 32],
    pub(crate) manifest_hash: [u8; 32],
    pub(crate) nodes: Vec<SealedNode>,
    pub(crate) independence_report: String,
    pub(crate) max_msg_bytes: u64,
}

/// Refuse ceilings above the ingress cap, coverage headroom, or ADR-0016's decided
/// 5x margin, then reject every remaining nonzero value until `btc-policy-sqn`.
/// This order keeps all four diagnoses reachable because the 5x rule is stronger
/// than coverage. `u32` prevents `pct * 5` and `100 - coverage` from wrapping.
fn check_escape_bump_ceiling(policy: &PolicyParams) -> Result<(), Error> {
    let ceiling = u32::from(policy.escape_bump_max_fee_pct);
    let headroom = 100u32.saturating_sub(u32::from(policy.escape_coverage_pct));
    if u64::from(ceiling) > policy_core::MAX_FEE_PERCENT {
        return Err(format!(
            "escape_bump_max_fee_pct = {ceiling} exceeds the {}% ingress fee cap every rung \
             passes through `verify_escape` (ADR-0016 §3)",
            policy_core::MAX_FEE_PERCENT
        )
        .into());
    }
    if ceiling > headroom {
        return Err(format!(
            "escape_bump_max_fee_pct = {ceiling} exceeds the fire-time coverage headroom of \
             {headroom}% left by escape_coverage_pct = {} (ADR-0016 §3)",
            policy.escape_coverage_pct
        )
        .into());
    }
    if ceiling * 5 > headroom {
        return Err(format!(
            "escape_bump_max_fee_pct = {ceiling} leaves less than ADR-0016's decided 5x margin \
             under the {headroom}% coverage headroom (escape_coverage_pct = {})",
            policy.escape_coverage_pct
        )
        .into());
    }
    if ceiling != 0 {
        return Err(format!(
            "escape_bump_max_fee_pct = {ceiling} is a cap-valid ceiling but an UNSUPPORTED \
             LADDER CONFIGURATION until btc-policy-sqn ships the rung composer; seal 0 or wait \
             for sqn (ADR-0016 §4)"
        )
        .into());
    }
    Ok(())
}

/// Check every ceremony destination descriptor's extended-key flavour against the
/// sealed network (bead btc-policy-descriptor-network-kind-x00). policy-core owns the
/// relation and its diagnostic; this parses the strings and names their roles.
fn check_ceremony_key_flavour(
    escape_descriptor: &str,
    hot_descriptors: &[String],
    network: bitcoin::Network,
) -> Result<(), Error> {
    let hot = hot_descriptors
        .iter()
        .map(|d| ("hot allowlist", d.as_str()));
    for (role, text) in std::iter::once(("escape", escape_descriptor)).chain(hot) {
        let descriptor = Descriptor::<DescriptorPublicKey>::from_str(text)
            .map_err(|e| format!("{role} descriptor does not parse: {e}"))?;
        policy_core::check_descriptor_network_kind(role, &descriptor, network)?;
    }
    Ok(())
}

/// Disclose the rung-only ceiling, unknown base fee, and fixed timelock together.
/// ADR-0016 §4 requires this until `btc-policy-wdu` makes the timelock selectable.
fn ladder_disclosure(policy: &PolicyParams) -> String {
    format!(
        "\n!! escape_bump_max_fee_pct = {} and recovery timelock = {} days (FIXED — not a \
         setting\n\x20  in this release). Decide them together: the timelock is how long the \
         funds are\n\x20  immobile if the sweep misses, and it is also the refresh deadline.\n\
         \x20  The ceiling governs REPLACEMENT RUNGS ONLY. It never caps the base Escape, which\n\
         \x20  is always retained and always pays its own nonzero fee. That concrete base fee\n\
         \x20  CANNOT EXIST at seal time — it depends on inputs, output shape and a feerate\n\
         \x20  source chosen later — so it is displayed per spend, never here.\n\
         \x20  At {}, no rung is offered: a SpendRequest presents exactly two transactions\n\
         \x20  (a RefreshRequest is a self-spend and presents one — it has no Escape).",
        policy.escape_bump_max_fee_pct,
        policy_core::RECOVERY_TIMELOCK_UNITS as u64 * 512 / 86_400,
        policy.escape_bump_max_fee_pct,
    )
}

/// Assemble the vault from PUBLIC bundles alone.
///
/// `node_bundles` order does not matter: `node_id` is the key's position in the
/// descriptor's canonical (lexicographic) order, computed here exactly as every
/// node computes it from the frozen descriptor (ADR-0013 §1).
#[allow(clippy::too_many_arguments)]
pub(crate) fn assemble(
    node_bundles: &[NodeBundle],
    threshold: usize,
    user_key: PublicKey,
    recovery_keys: &[PublicKey],
    coordinator_auth_pubkey: PublicKey,
    escape_descriptor: &str,
    hot_descriptors: &[String],
    policy: &PolicyParams,
) -> Result<Assembled, Error> {
    // The federation SHAPE, checked here because the descriptor it goes into is
    // frozen forever. `Node::from_toml_str` already refuses any other shape at
    // startup, so this is not a second enforcement — it is the same rule applied
    // before the point of no return. The distinction from the other startup bounds
    // (`hold_secs`, the delivery horizon, the velocity window) is that those live in
    // a config an operator can correct and re-run `finalize` for, while `t` and `n`
    // are consensus facts about the script the coins get locked to: get them wrong
    // and the only remedy is provisioning a different vault. Duplicating the
    // correctable bounds here would be a second copy that can drift; duplicating
    // this one is the difference between a re-run and a rotation.
    let n = node_bundles.len();
    // Checked arithmetic: `threshold` comes from operator-controlled ceremony JSON, so
    // `threshold * 2 - 1` must not panic (debug) or wrap (release) on an absurd value —
    // it must fall through to the shape-validation error like any other bad `t`.
    let expected_n = threshold
        .checked_mul(2)
        .and_then(|two_t| two_t.checked_sub(1));
    if threshold < 2 || expected_n != Some(n) {
        return Err(format!(
            "a federation must be exactly n = 2t - 1 with t >= 2 (ADR-0013 §1), got t = \
             {threshold}, n = {n}. Both halves are load-bearing: 2t > n leaves no unfrozen \
             signing quorum outside an armed set, and n >= 2t - 1 still reaches t honest \
             nodes when every tolerated t-1 minority withholds propagation. The descriptor \
             is immutable, so a vault sealed at another shape cannot be migrated - only \
             replaced"
        )
        .into());
    }
    // Canonical order first, so `node_id` is decided by the descriptor and not by
    // the order the operator happened to collect the bundles in.
    let mut ordered: Vec<(PublicKey, &NodeBundle)> = node_bundles
        .iter()
        .map(|bundle| Ok((bundle.signing_pubkey()?, bundle)))
        .collect::<Result<_, Error>>()?;
    ordered.sort_by_key(|(key, _)| key.to_string());

    let node_pubkeys: Vec<String> = ordered.iter().map(|(key, _)| key.to_string()).collect();
    let recovery_pubkeys: Vec<String> = recovery_keys.iter().map(|k| k.to_string()).collect();
    let descriptor_str = policy_core::vault_descriptor_string(
        &user_key.to_string(),
        threshold,
        &node_pubkeys,
        &recovery_pubkeys,
    );
    // Parse + validate against the frozen template. This is where an off-template
    // descriptor, a duplicate or cross-role key, and a ranged vault key are all
    // refused — the same code every node runs at startup, so a vault this ceremony
    // seals is a vault every node can load.
    let descriptor = Descriptor::<PublicKey>::from_str(&descriptor_str)
        .map_err(|e| format!("assembled descriptor does not parse: {e}"))?;
    let template = policy_core::parse_vault_template(&descriptor)
        .map_err(|e| format!("assembled descriptor is off-template: {e}"))?;
    let canonical = descriptor.to_string();
    let wallet_id = crate::fed::wallet_id(&descriptor);

    let mut independence_report = check_independence(&IndependenceInputs {
        user_key: template.user_key,
        node_keys: &template.node_keys,
        recovery_keys: &template.recovery_keys,
        coordinator_key: coordinator_auth_pubkey,
        escape_descriptor,
        hot_descriptors,
        max_derivation_index: policy.max_derivation_index,
    })?;

    // The coordinator is the second checkpoint on each node's key-derivation cost.
    // `node-keygen` already refuses a below-floor cost in production, but the public
    // bundle carries `node_key_ops`/`mem`, so a bundle that bypassed that gate (e.g. a
    // harness `--allow-weak-kdf` invocation cargo-culted onto a production host) would
    // otherwise seal silently. Record every node's cost in the witnessed evidence —
    // the artifact whose job is surfacing setup-time weaknesses must not omit a
    // security parameter it can see — and warn loudly on any below-floor node. Not a
    // hard refusal: the regtest harness legitimately assembles floor-cost bundles, and
    // the 63-bit preimage still leaves real margin, so this is defence-in-depth.
    independence_report.push_str("\nNode key-derivation cost (Argon2id, from each bundle):\n");
    let mut weak_nodes: Vec<usize> = Vec::new();
    for (node_id, (key, bundle)) in ordered.iter().enumerate() {
        let below = bundle.node_key_ops < nodekey::DEFAULT_KDF_OPS
            || bundle.node_key_mem_kib < nodekey::DEFAULT_KDF_MEM_KIB;
        independence_report.push_str(&format!(
            "  node[{node_id}] {key}  ops={} mem={} KiB{}\n",
            bundle.node_key_ops,
            bundle.node_key_mem_kib,
            if below {
                "   *** BELOW PRODUCTION FLOOR ***"
            } else {
                ""
            }
        ));
        if below {
            weak_nodes.push(node_id);
        }
    }
    if !weak_nodes.is_empty() {
        let warning = format!(
            "!! node(s) {weak_nodes:?} were key-derived BELOW the production KDF floor (defaults \
             ops {}, mem {} KiB). Their signing keys have a weaker offline margin over the PUBLIC \
             bundle. This is expected ONLY for a test/automation vault; for a production node, \
             re-run `setup node-keygen` WITHOUT --allow-weak-kdf and re-assemble.",
            nodekey::DEFAULT_KDF_OPS,
            nodekey::DEFAULT_KDF_MEM_KIB
        );
        eprintln!("{warning}");
        independence_report.push_str(&format!("\n{warning}\n"));
    }

    let ceremony_nodes: Vec<ceremony::CeremonyNode> = ordered
        .iter()
        .enumerate()
        .map(|(node_id, (key, bundle))| {
            if bundle.endpoints.is_empty() {
                return Err(Error::from(format!(
                    "node bundle for {key} declares no endpoints; the manifest pins them"
                )));
            }
            Ok(ceremony::CeremonyNode {
                node_id: node_id as u16,
                signing_pubkey: *key,
                endpoints: bundle.endpoints.clone(),
            })
        })
        .collect::<Result<_, Error>>()?;
    let channel_pubkeys: Vec<PublicKey> = ordered
        .iter()
        .map(|(_, bundle)| bundle.channel_pubkey())
        .collect::<Result<_, Error>>()?;

    // The listen ports each node publishes must be bootable: nonzero (`ChannelState::
    // build` rejects the `:0` "any free port" sentinel) and distinct (every v0 daemon
    // binds the ONE 127.0.0.1 namespace, so two nodes on one port cannot both bind and
    // the federation never reaches a t-of-n quorum). Validated here, on the shared seal
    // path both the CLI and the harness run, so a `finalize` cannot produce an
    // unbootable federation discovered only at a node's startup after the vault froze.
    let mut seen_ports: BTreeSet<u16> = BTreeSet::new();
    for node in &ceremony_nodes {
        let port = loopback_port(&node.endpoints, node.node_id)?;
        if !seen_ports.insert(port) {
            return Err(format!(
                "two federation nodes pin the same loopback port {port}: every v0 node binds \
                 127.0.0.1, so a shared port leaves one unable to bind. Re-run `setup node-keygen` \
                 so each host publishes a distinct 127.0.0.1:<port>."
            )
            .into());
        }
    }

    check_escape_bump_ceiling(policy)?;
    // The last moment the relation is free: the line below seals both into one hash.
    check_ceremony_key_flavour(escape_descriptor, hot_descriptors, policy.network)?;

    let manifest_hash = ceremony::manifest_hash(
        &wallet_id,
        &coordinator_auth_pubkey,
        &ceremony_nodes,
        &channel_pubkeys,
        policy.max_msg_bytes,
        policy.hot_budget(),
        hot_descriptors,
        escape_descriptor,
        policy.max_derivation_index,
        policy.escape_feerate_floor,
        policy.escape_coverage_pct,
        policy.escape_bump_max_fee_pct,
        policy.network,
    )?;

    let nodes = ceremony_nodes
        .into_iter()
        .zip(channel_pubkeys)
        .map(|(node, channel_pubkey)| SealedNode {
            node_id: node.node_id,
            signing_pubkey: node.signing_pubkey,
            channel_pubkey,
            endpoints: node.endpoints,
        })
        .collect();

    Ok(Assembled {
        descriptor: canonical,
        wallet_id,
        manifest_hash,
        nodes,
        independence_report,
        max_msg_bytes: policy.max_msg_bytes,
    })
}

impl Assembled {
    /// Verify one node's round-two endorsement against the signing key the manifest
    /// pins for it.
    ///
    /// The coordinator checks this rather than passing it through: an endorsement
    /// that does not verify would be discovered by every node at startup, after the
    /// vault is frozen and the hosts are sealed, and the only exit from that is a
    /// full re-provision. Catching it here costs one signature verification.
    pub(crate) fn verify_endorsement(&self, node_id: u16, endorsement: &str) -> Result<(), Error> {
        let node = self
            .nodes
            .iter()
            .find(|node| node.node_id == node_id)
            .ok_or_else(|| Error::from(format!("no node with node_id {node_id}")))?;
        ceremony::verify_endorsement(
            &node.signing_pubkey,
            &node.channel_pubkey,
            &self.wallet_id,
            &self.manifest_hash,
            node_id,
            &node.endpoints,
            endorsement,
        )
        .map_err(|e| {
            format!("node {node_id} endorsement does not verify against its signing key: {e}")
                .into()
        })
    }

    /// The `[channel]` block for `self_id` (ADR-0013 §5), including the MANDATORY
    /// `expected_manifest_hash` anchor and the sealed `max_msg_bytes`.
    pub(crate) fn channel_toml(
        &self,
        self_id: u16,
        endorsements: &BTreeMap<u16, String>,
    ) -> String {
        let mut toml = format!(
            "\n[channel]\nnode_id = {self_id}\nexpected_manifest_hash = \"{}\"\nmax_msg_bytes = {}\n",
            self.manifest_hash.to_lower_hex_string(),
            self.max_msg_bytes,
        );
        for node in &self.nodes {
            let endpoints: Vec<String> = node
                .endpoints
                .iter()
                .map(|endpoint| format!("\"{endpoint}\""))
                .collect();
            toml.push_str(&format!(
                "\n[[channel.nodes]]\nnode_id = {}\nsigning_pubkey = \"{}\"\n\
                 channel_pubkey = \"{}\"\nchannel_endorsement = \"{}\"\n\
                 endpoints = [{}]\n",
                node.node_id,
                node.signing_pubkey,
                node.channel_pubkey,
                endorsements.get(&node.node_id).map_or("", String::as_str),
                endpoints.join(", "),
            ));
        }
        toml
    }
}

// ---------------------------------------------------------------------------
// CLI

pub(crate) fn run(args: &[&str]) -> ExitCode {
    let result = match args {
        ["node-keygen", rest @ ..] => node_keygen(&Args::parse(rest)),
        ["node-endorse", rest @ ..] => node_endorse(&Args::parse(rest)),
        ["keygen", rest @ ..] => keygen(&Args::parse(rest)),
        ["assemble", rest @ ..] => assemble_cmd(&Args::parse(rest)),
        ["finalize", rest @ ..] => finalize_cmd(&Args::parse(rest), None),
        _ => Err(Error::from(USAGE)),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("setup FAILED: {e}");
            ExitCode::FAILURE
        }
    }
}

pub(crate) const USAGE: &str = "\
usage: btc-vault setup <step>

  ON EACH NODE HOST (the key never leaves it):
    node-keygen  --device-dir <dir> --endpoint 127.0.0.1:<port>
                 [--kdf-ops <n>] [--kdf-mem-kib <n>] [--preimage-file <path>]
                 [--allow-weak-kdf]   (below-default KDF cost; test/automation only)
    node-endorse --device-dir <dir> --wallet-id <hex> --manifest-hash <hex>
                 --node-id <n> [--preimage-file <path>]

  ON AN INDEPENDENT DEVICE (never a node host, never the coordinator):
    keygen       --role <escape|user|recovery> --out <file> [--secret-file <path>]
                 --network <bitcoin|signet|regtest>  (escape only, MANDATORY)

  ON THE COORDINATOR (public bytes only):
    assemble     --input <ceremony.json> --out <dir>
    finalize     --dir <dir>";

/// Flag parsing, deliberately tiny: `--name value` pairs and nothing else. A setup
/// ceremony is run a handful of times in a vault's life, from a written procedure.
struct Args(BTreeMap<String, String>);

impl Args {
    fn parse(args: &[&str]) -> Args {
        let mut map = BTreeMap::new();
        let mut i = 0;
        while i < args.len() {
            if let Some(name) = args[i].strip_prefix("--") {
                // `--name` takes the next token as its value, UNLESS that token is
                // itself a flag or absent — then it is a valueless boolean flag
                // (e.g. `--allow-weak-kdf`). Every valued flag this CLI takes has a
                // non-`--` value (paths, numbers, hex, descriptors), so this never
                // misreads an existing pair, and a trailing bare flag is no longer
                // silently dropped as it was under `i + 1 < len`.
                let value = match args.get(i + 1) {
                    Some(next) if !next.starts_with("--") => {
                        i += 2;
                        (*next).to_string()
                    }
                    _ => {
                        i += 1;
                        String::new()
                    }
                };
                map.insert(name.to_string(), value);
            } else {
                i += 1;
            }
        }
        Args(map)
    }

    /// Whether a valueless boolean flag was present (e.g. `--allow-weak-kdf`).
    fn flag(&self, name: &str) -> bool {
        self.0.contains_key(name)
    }

    fn get(&self, name: &str) -> Result<&str, Error> {
        // A bare `--name` with no following value parses as an empty string (see
        // `parse`). For a VALUED flag that is a missing value, not a real one, so
        // report it as missing — the operator gets the crisp usage error instead of a
        // downstream I/O failure on a cwd-relative path (e.g. `finalize --dir` with no
        // argument resolving `""/ceremony-state.json`).
        match self.0.get(name).map(String::as_str) {
            Some(value) if !value.is_empty() => Ok(value),
            _ => Err(Error::from(format!("missing --{name}\n\n{USAGE}"))),
        }
    }

    fn opt(&self, name: &str) -> Option<&str> {
        // Same rule for optional valued flags: an empty value reads as absent, so a
        // bare flag falls back to the default rather than a bogus "" value. Presence
        // of a valueless boolean flag is queried with `flag()`.
        self.0
            .get(name)
            .map(String::as_str)
            .filter(|value| !value.is_empty())
    }

    fn number<T: FromStr>(&self, name: &str, default: T) -> Result<T, Error> {
        match self.opt(name) {
            None => Ok(default),
            Some(text) => text
                .parse()
                .map_err(|_| Error::from(format!("--{name} must be a number, got {text:?}"))),
        }
    }
}

/// Birth one node's key. The ONE place a node identity comes into existence, and
/// it runs on that node's own host.
///
/// The secret comes back to the CALLER — this process, on this host — and the
/// bundle is everything else. Splitting them at the return type is what lets the
/// tests state the colocation property directly: whatever is in the bundle can go
/// to the coordinator, and nothing else may.
pub(crate) fn generate_node_identity(
    endpoint: String,
    ops: u32,
    mem_kib: u32,
) -> Result<(Preimage, NodeBundle), Error> {
    let preimage = Preimage::generate()?;
    let kdf = KdfParams::generate_with(ops, mem_kib)?;
    let seckey = nodekey::derive(&preimage, &kdf)?;
    let (signing_pubkey, channel_pubkey) = nodekey::public_identity(&seckey);
    Ok((
        preimage,
        NodeBundle {
            signing_pubkey: signing_pubkey.to_string(),
            channel_pubkey: channel_pubkey.to_string(),
            node_key_salt: kdf.salt_hex(),
            node_key_ops: kdf.ops(),
            node_key_mem_kib: kdf.mem_kib(),
            endpoints: vec![endpoint],
        },
    ))
}

fn node_keygen(args: &Args) -> Result<(), Error> {
    let device_dir = PathBuf::from(args.get("device-dir")?);
    let endpoint = args.get("endpoint")?.to_string();
    let ops = args.number("kdf-ops", nodekey::DEFAULT_KDF_OPS)?;
    let mem_kib = args.number("kdf-mem-kib", nodekey::DEFAULT_KDF_MEM_KIB)?;
    // The preimage entropy and the Argon2id cost are JOINT barriers. After the
    // ceremony the public bundle carries salt/ops/mem and the signing pubkey, so an
    // offline attacker's per-node search cost is (preimage width) × (per-guess KDF
    // cost). At the implementation floor (ops 1, mem 8 KiB) that per-guess cost is
    // memory-cheap and pipelinable, shrinking every node key's margin — and with it
    // the c = t−1 compromise budget the 2t−1 shape and the attack harness assume. A
    // PRODUCTION keygen must therefore not silently drop below the defaults; only a
    // test/automation host may, and it says so explicitly with --allow-weak-kdf.
    if !args.flag("allow-weak-kdf")
        && (ops < nodekey::DEFAULT_KDF_OPS || mem_kib < nodekey::DEFAULT_KDF_MEM_KIB)
    {
        return Err(format!(
            "refusing to generate a node key below the production KDF floor (got ops {ops}, mem \
             {mem_kib} KiB; defaults are ops {}, mem {} KiB): the preimage entropy and the \
             Argon2id cost jointly bound an offline search over the PUBLIC bundle, so a weaker \
             cost silently shrinks every node key's margin and the c = t-1 compromise budget the \
             federation depends on. Re-run at the defaults (omit --kdf-ops/--kdf-mem-kib), or pass \
             --allow-weak-kdf if this is a test/automation host.",
            nodekey::DEFAULT_KDF_OPS,
            nodekey::DEFAULT_KDF_MEM_KIB
        )
        .into());
    }
    std::fs::create_dir_all(&device_dir)?;
    let bundle_path = device_dir.join(NODE_BUNDLE_FILE);
    // A `--preimage-file` that aliases the PUBLIC bundle would let the secret write
    // overwrite the very file the operator publishes to the coordinator. Refuse
    // before writing either.
    if let Some(path) = args.opt("preimage-file") {
        if same_path(Path::new(path), &bundle_path) {
            return Err(format!(
                "--preimage-file {path} is the same file as the PUBLIC node bundle {}: the \
                 preimage (a secret) would overwrite the bundle published to the coordinator. \
                 Write the preimage to a SEPARATE path.",
                bundle_path.display()
            )
            .into());
        }
    }

    let (preimage, bundle) = generate_node_identity(endpoint, ops, mem_kib)?;
    let json = serde_json::to_string_pretty(&bundle)?;
    std::fs::write(&bundle_path, format!("{json}\n"))?;

    // The preimage goes to the OPERATOR, never to the coordinator. stderr, so a
    // caller capturing the public bundle on stdout cannot pick it up by accident.
    let hex = preimage.to_hex();
    eprintln!("\n================ WRITE THIS DOWN — IT IS NEVER STORED ================");
    eprintln!("  node-key preimage: {}", hex.as_str());
    eprintln!("  This is the ONLY copy. The node derives its signing key from it at");
    eprintln!("  startup and holds nothing at rest; lose it before the node starts and");
    eprintln!("  this node is dead (rotate the vault). It must never reach the");
    eprintln!("  coordinator or any other node host.");
    eprintln!("  Keep it until this node is UP and its host sealed, THEN securely destroy");
    eprintln!("  it: a rebooted node is permanently dead (ADR-0007 — rotate to a successor,");
    eprintln!("  never resurrect), so a retained preimage only preserves a path to reset a");
    eprintln!("  Locked node's budget, which nothing is meant to have.");
    eprintln!("======================================================================\n");
    if let Some(path) = args.opt("preimage-file") {
        write_secret_file(Path::new(path), hex.as_bytes())?;
        eprintln!(
            "  !! --preimage-file wrote the secret to {path} (AUTOMATION ONLY). A\n     \
             production ceremony omits this flag: a preimage on disk is the at-rest\n     \
             key this design exists to remove.\n"
        );
    }
    eprintln!("  published (PUBLIC, safe to copy to the coordinator):");
    eprintln!("    {}", device_dir.join(NODE_BUNDLE_FILE).display());
    println!("{json}");
    Ok(())
}

fn node_endorse(args: &Args) -> Result<(), Error> {
    let device_dir = PathBuf::from(args.get("device-dir")?);
    let node_id: u16 = args
        .get("node-id")?
        .parse()
        .map_err(|_| Error::from("--node-id must be a number"))?;
    let wallet_id = hex32(args.get("wallet-id")?, "wallet-id")?;
    let manifest_hash = hex32(args.get("manifest-hash")?, "manifest-hash")?;

    let bundle: NodeBundle =
        serde_json::from_str(&std::fs::read_to_string(device_dir.join(NODE_BUNDLE_FILE))?)?;
    let preimage = read_preimage(args)?;
    let seckey = nodekey::derive(&preimage, &bundle.kdf()?)?;
    let (signing_pubkey, _) = nodekey::public_identity(&seckey);
    // Fail closed before signing anything: an endorsement from the wrong key is a
    // manifest every node rejects at startup, discovered only after sealing.
    if signing_pubkey != bundle.signing_pubkey()? {
        return Err(format!(
            "the preimage does not derive this device's published key ({} vs {})",
            signing_pubkey, bundle.signing_pubkey
        )
        .into());
    }

    let endorsement = ceremony::endorse(
        &seckey,
        &wallet_id,
        &manifest_hash,
        node_id,
        &bundle.endpoints,
    );
    let path = device_dir.join(format!("endorsement-{node_id}.txt"));
    std::fs::write(&path, format!("{endorsement}\n"))?;
    eprintln!(
        "  endorsement for node {node_id} written to {}",
        path.display()
    );
    println!("{endorsement}");
    Ok(())
}

fn keygen(args: &Args) -> Result<(), Error> {
    let role = args.get("role")?;
    let out = PathBuf::from(args.get("out")?);
    // A `--secret-file` that aliases `--out` would overwrite the PUBLIC bundle with
    // the raw role secret — which the command still labels published. Refuse.
    if let Some(path) = args.opt("secret-file") {
        if same_path(Path::new(path), &out) {
            return Err(format!(
                "--secret-file {path} is the same file as --out {}: the secret would overwrite the \
                 PUBLIC bundle. Write the secret to a SEPARATE path.",
                out.display()
            )
            .into());
        }
    }
    let secp = Secp256k1::new();
    let mut seed = [0u8; 32];
    File::open("/dev/urandom")?.read_exact(&mut seed)?;

    let (bundle, secret) = match role {
        "escape" => {
            // A ranged single-sig wallet with a declared BIP32 origin: ranged so
            // every sweep pays a fresh address (DESIGN.md, destination allowlist),
            // origin'd so ADR-0003's fingerprint tripwire has something to compare.
            //
            // `--network` is MANDATORY here and has no default (bead
            // btc-policy-descriptor-network-kind-x00): the flavour it selects is checked at
            // assemble, finalize and node load, so a guessed default would be a key three
            // boundaries refuse — found after the escape device showed its secret and was put away.
            let network = vault_node::parse_vault_network(args.get("network")?)?;
            let xpriv = Xpriv::new_master(NetworkKind::from(network), &seed)?;
            let xpub = Xpub::from_priv(&secp, &xpriv);
            let fingerprint = xpriv.fingerprint(&secp);
            let descriptor = Descriptor::<DescriptorPublicKey>::from_str(&format!(
                "wpkh([{fingerprint}]{xpub}/*)"
            ))?;
            (
                KeyBundle {
                    role: role.to_string(),
                    descriptor: Some(descriptor.to_string()),
                    pubkey: None,
                    master_fingerprint: Some(fingerprint.to_string()),
                },
                xpriv.to_string(),
            )
        }
        "user" | "recovery" => {
            // A DEFINITE key: the vault descriptor takes one concrete pubkey per
            // role (ADR-0013 §1 as amended by bead 9y5.5).
            let seckey = SecretKey::from_slice(&seed)
                .map_err(|e| format!("cannot form a {role} key: {e}"))?;
            let pubkey = PublicKey::new(seckey.public_key(&secp));
            (
                KeyBundle {
                    role: role.to_string(),
                    descriptor: None,
                    pubkey: Some(pubkey.to_string()),
                    master_fingerprint: None,
                },
                seckey.display_secret().to_string(),
            )
        }
        other => {
            return Err(format!("--role must be escape, user, or recovery, got {other:?}").into())
        }
    };
    // Wipe the raw seed and hold the printable secret in a zeroizing wrapper, matching
    // nodekey.rs's discipline for the same class of bytes. This is a one-shot process
    // that shows the secret to the operator by design, so this only reduces
    // swap/core-dump residue — but it makes the hygiene uniform across the ceremony.
    seed.zeroize();
    let secret = Zeroizing::new(secret);

    let json = serde_json::to_string_pretty(&bundle)?;
    std::fs::write(&out, format!("{json}\n"))?;
    eprintln!("\n================ WRITE THIS DOWN — IT IS NEVER STORED ================");
    eprintln!("  {role} secret: {}", secret.as_str());
    if role == "escape" {
        eprintln!("  This wallet receives every incident sweep. Its seed MUST be independent");
        eprintln!("  of the user key: a shared seed turns duress into THEFT, because a");
        eprintln!("  post-wrench attacker holding the user key would control this wallet too.");
        eprintln!("  Generate it on a device that holds no other vault role.");
    }
    eprintln!("======================================================================\n");
    if let Some(path) = args.opt("secret-file") {
        write_secret_file(Path::new(path), secret.as_bytes())?;
        eprintln!("  !! --secret-file wrote the secret to {path} (AUTOMATION ONLY).\n");
    }
    eprintln!("  published (PUBLIC): {}", out.display());
    println!("{json}");
    Ok(())
}

/// The coordinator's ceremony input (`--input`). Every key-bearing entry is a PATH
/// to a bundle rather than an inline key: the artifact is the evidence that a
/// distinct generation step produced it, and requiring one is what makes "the
/// escape came from its own step" a property of the input format rather than of
/// the operator's memory.
#[derive(Debug, Deserialize)]
struct CeremonyInput {
    threshold: usize,
    node_bundles: Vec<String>,
    user_bundle: String,
    recovery_bundles: Vec<String>,
    escape_bundle: String,
    hot_descriptor: String,
    policy: PolicyParams,
    pin_normal_hash: String,
    pin_duress_hash: String,
    chain_backend_rpc_addr: String,
    chain_backend_auth: String,
}

/// What `assemble` leaves behind for `finalize`. NOT public: it carries the base64
/// chain-backend RPC credential and both Argon2id PIN digests, so `assemble` writes
/// it owner-only (`write_secret_file`) and the finalize banner + SETUP-CEREMONY.md
/// tell the operator to securely delete it once the vault is sealed.
#[derive(Debug, Serialize, Deserialize)]
struct CeremonyState {
    descriptor: String,
    wallet_id: String,
    manifest_hash: String,
    coordinator_auth_pubkey: String,
    nodes: Vec<StateNode>,
    escape_descriptor: String,
    hot_descriptor: String,
    policy: PolicyParams,
    pin_normal_hash: String,
    pin_duress_hash: String,
    chain_backend_rpc_addr: String,
    chain_backend_auth: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct StateNode {
    node_id: u16,
    signing_pubkey: String,
    channel_pubkey: String,
    // The listen port is NOT stored: finalize derives it from `endpoints` (the
    // endorsed, hash-bound source), so a separate field here would be a second copy
    // that could drift from the endpoint it must equal.
    endpoints: Vec<String>,
    node_key_salt: String,
    node_key_ops: u32,
    node_key_mem_kib: u32,
}

fn assemble_cmd(args: &Args) -> Result<(), Error> {
    let input: CeremonyInput = serde_json::from_str(&std::fs::read_to_string(args.get("input")?)?)?;
    let out = PathBuf::from(args.get("out")?);
    std::fs::create_dir_all(&out)?;

    let bundles: Vec<NodeBundle> = input
        .node_bundles
        .iter()
        .map(|path| -> Result<NodeBundle, Error> {
            Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
        })
        .collect::<Result<_, Error>>()?;
    let user = read_definite_bundle(&input.user_bundle, "user")?;
    let recovery: Vec<PublicKey> = input
        .recovery_bundles
        .iter()
        .map(|path| read_definite_bundle(path, "recovery"))
        .collect::<Result<_, Error>>()?;
    let escape: KeyBundle = serde_json::from_str(&std::fs::read_to_string(&input.escape_bundle)?)?;
    if escape.role != "escape" {
        return Err(format!(
            "{} is a {:?} bundle, not an escape bundle: the escape wallet must come from its \
             own `keygen --role escape` step on its own device (ADR-0012 §10)",
            input.escape_bundle, escape.role
        )
        .into());
    }
    let escape_descriptor = escape
        .descriptor
        .clone()
        .ok_or("the escape bundle carries no descriptor")?;

    // The coordinator's auth identity (ADR-0013 §2/§7). Generated ONCE per vault,
    // here, and backed up by `finalize` — losing it with no backup bricks the
    // normal path, because the manifest pins its pubkey and the manifest is
    // immutable.
    let secp = Secp256k1::new();
    let mut coord_seed = [0u8; 32];
    File::open("/dev/urandom")?.read_exact(&mut coord_seed)?;
    let coord_seckey = SecretKey::from_slice(&coord_seed)?;
    coord_seed.zeroize();
    let coord_pubkey = PublicKey::new(coord_seckey.public_key(&secp));

    let hot_descriptors = vec![input.hot_descriptor.clone()];
    let assembled = assemble(
        &bundles,
        input.threshold,
        user,
        &recovery,
        coord_pubkey,
        &escape_descriptor,
        &hot_descriptors,
        &input.policy,
    )?;

    // Bind each sealed node back to the bundle it came from, so `finalize` can
    // write that node's derivation parameters into its config. Key by the PARSED
    // pubkey's canonical string, not the bundle's raw hex: an operator bundle with
    // valid uppercase compressed-pubkey hex canonicalizes to lowercase in the sealed
    // node, and a raw-string map would then miss the lowercase lookup and fail an
    // otherwise-valid ceremony.
    let by_signing: BTreeMap<String, &NodeBundle> = bundles
        .iter()
        .map(|bundle| Ok((bundle.signing_pubkey()?.to_string(), bundle)))
        .collect::<Result<_, Error>>()?;
    let mut state_nodes = Vec::new();
    for node in &assembled.nodes {
        let bundle = by_signing
            .get(&node.signing_pubkey.to_string())
            .ok_or_else(|| Error::from("assembled node is not one of the input bundles"))?;
        // The node's listen port is the one it PUBLISHED, never a second copy the
        // ceremony input could disagree with. `assemble` already validated every
        // endpoint (loopback + nonzero + distinct ports) on the shared seal path, and
        // finalize re-derives the bind port from these same endpoints, so nothing here
        // stores a separate port copy that could drift.
        state_nodes.push(StateNode {
            node_id: node.node_id,
            signing_pubkey: node.signing_pubkey.to_string(),
            channel_pubkey: node.channel_pubkey.to_string(),
            endpoints: node.endpoints.clone(),
            node_key_salt: bundle.node_key_salt.clone(),
            node_key_ops: bundle.node_key_ops,
            node_key_mem_kib: bundle.node_key_mem_kib,
        });
    }

    let state = CeremonyState {
        descriptor: assembled.descriptor.clone(),
        wallet_id: assembled.wallet_id.to_lower_hex_string(),
        manifest_hash: assembled.manifest_hash.to_lower_hex_string(),
        coordinator_auth_pubkey: coord_pubkey.to_string(),
        nodes: state_nodes,
        escape_descriptor: escape_descriptor.clone(),
        hot_descriptor: input.hot_descriptor.clone(),
        policy: input.policy,
        pin_normal_hash: input.pin_normal_hash.clone(),
        pin_duress_hash: input.pin_duress_hash.clone(),
        chain_backend_rpc_addr: input.chain_backend_rpc_addr.clone(),
        chain_backend_auth: input.chain_backend_auth.clone(),
    };

    std::fs::write(
        out.join("descriptor.txt"),
        format!("{}\n", assembled.descriptor),
    )?;
    std::fs::write(out.join("wallet-id.txt"), format!("{}\n", state.wallet_id))?;
    std::fs::write(
        out.join("manifest-hash.txt"),
        format!("{}\n", state.manifest_hash),
    )?;
    std::fs::write(
        out.join("coordinator-auth.pubkey"),
        format!("{coord_pubkey}\n"),
    )?;
    write_secret_file(
        &out.join("coordinator-auth.secret"),
        format!("{}\n", coord_seckey.display_secret()).as_bytes(),
    )?;
    std::fs::write(out.join("independence.txt"), &assembled.independence_report)?;
    // `ceremony-state.json` carries the base64 chain-backend RPC credential and both
    // Argon2id PIN digests, so it is written owner-only like the auth secret next to
    // it — not at the process umask, where any local user on a shared coordinator
    // could take the RPC credential and the PIN digests offline.
    write_secret_file(
        &out.join("ceremony-state.json"),
        format!("{}\n", serde_json::to_string_pretty(&state)?).as_bytes(),
    )?;

    print!("{}", assembled.independence_report);
    println!("\nvault descriptor : {}", assembled.descriptor);
    println!("wallet_id        : {}", state.wallet_id);
    println!("manifest_hash    : {}", state.manifest_hash);
    println!("coordinator auth : {coord_pubkey}");
    // ADR-0013 §7 and ADR-0012's residual list both say these two belong in the
    // ceremony UX, and this is the moment: the auth key exists as of this command,
    // and the hostage window is what the operator is choosing when they set
    // `duress_delay_secs`. Neither is recoverable by learning it later.
    println!(
        "\n!! BACK UP {}/coordinator-auth.secret, SEPARATELY from the descriptor.\n\
        \x20  The manifest pins its PUBLIC half and the manifest is immutable, so losing it\n\
        \x20  with no backup BRICKS THE NORMAL PATH: every future request is rejected and the\n\
        \x20  only exit is the {}-day recovery timelock. Rotation is a NEW VAULT; there is no\n\
        \x20  in-place rotation in v0.",
        out.display(),
        policy_core::RECOVERY_TIMELOCK_UNITS as u64 * 512 / 86_400,
    );
    println!(
        "\n!! duress_delay_secs = {} is a CEILING on the hostage window, not a guarantee.\n\
        \x20  T = min(first_seen + duress_delay_secs, earliest pending hot Hold-expiry - eps),\n\
        \x20  so if a hot spend's Hold has already matured when the duress pin arrives, T is in\n\
        \x20  the past and the escape fires immediately — with no silent window at all.",
        input.policy.duress_delay_secs,
    );
    println!("{}", ladder_disclosure(&input.policy));
    println!("\nROUND TWO — on each node host, run:");
    for node in &state.nodes {
        println!(
            "  btc-vault setup node-endorse --device-dir <that node's dir> \\\n    \
             --wallet-id {} --manifest-hash {} --node-id {}",
            state.wallet_id, state.manifest_hash, node.node_id
        );
    }
    println!(
        "\nThen copy each endorsement to {}/endorsement-<node_id>.txt and run:\n  \
         btc-vault setup finalize --dir {}",
        out.display(),
        out.display()
    );
    Ok(())
}

struct Artifact {
    rel: String,
    contents: String,
    secret: bool,
}

const STAGING_DIR: &str = ".finalize-staging";
/// The published artifact root. Deliberately NEUTRAL: the manifest's own
/// `protocol_version` carries the schema revision, and a revision-bearing directory
/// name is a second copy of it that goes stale the moment the revision moves — as
/// `sealed-v1/` did at revision 2 (bead btc-policy-b8z).
const SEALED_DIR: &str = "sealed";

/// Stage the complete rendered set under this process's [`STAGING_DIR`], then make the
/// manifest, every independently usable node config, and the backup visible through ONE
/// same-filesystem directory rename to [`SEALED_DIR`] (ADR-0016 §4). Interruption
/// exposes no finalized partial set; an existing set is never accepted, merged, or
/// overwritten. `stage_failpoint` is the test seam for those interruptions: `Some(i)`
/// aborts immediately before artifact `i` is staged. Production passes `None`.
fn publish_artifact_set(
    dir: &Path,
    artifacts: &[Artifact],
    stage_failpoint: Option<usize>,
) -> Result<(), Error> {
    use std::os::unix::fs::DirBuilderExt;
    let staging = dir.join(format!("{STAGING_DIR}.{}", std::process::id()));
    let sealed = dir.join(SEALED_DIR);
    if sealed.exists() {
        return Err(format!(
            "{} already exists; finalize never accepts, merges, or overwrites a sealed artifact \
             set: inspect it and remove it explicitly before retrying",
            sealed.display()
        )
        .into());
    }
    // Staging is per invocation: a shared one lets an overlapping finalize clear this run's
    // staged set. A leftover at OUR path is an interrupted run's — never adopt any part of it.
    if staging.exists() {
        std::fs::remove_dir_all(&staging)
            .map_err(|e| format!("cannot clear stale staging {}: {e}", staging.display()))?;
    }
    std::fs::DirBuilder::new().mode(0o700).create(&staging)?;
    for (index, artifact) in artifacts.iter().enumerate() {
        if stage_failpoint == Some(index) {
            return Err(format!(
                "finalize interrupted before staging artifact {index} ({})",
                artifact.rel
            )
            .into());
        }
        let staged = staging.join(&artifact.rel);
        if let Some(parent) = staged.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if artifact.secret {
            write_secret_file(&staged, artifact.contents.as_bytes())?;
        } else {
            std::fs::write(&staged, &artifact.contents)?;
        }
    }
    std::fs::rename(&staging, &sealed)
        .map_err(|e| format!("cannot atomically publish {}: {e}", sealed.display()))?;
    Ok(())
}

fn finalize_cmd(args: &Args, stage_failpoint: Option<usize>) -> Result<(), Error> {
    let dir = PathBuf::from(args.get("dir")?);
    let state: CeremonyState =
        serde_json::from_str(&std::fs::read_to_string(dir.join("ceremony-state.json"))?)?;
    let wallet_id = hex32(&state.wallet_id, "wallet_id")?;
    let manifest_hash = hex32(&state.manifest_hash, "manifest_hash")?;
    let coord_pubkey = nodekey::parse_compressed_pubkey(&state.coordinator_auth_pubkey)?;

    // Endorsements bind the wallet_id HEX, not the descriptor text, so an edited or
    // corrupted `descriptor` field would still pass `verify_endorsement` and only
    // surface at node startup (the node recomputes H(descriptor) and its manifest
    // hash will not match the sealed anchor). Every other error of this class is
    // caught before sealing on the grounds that discovery at startup — after the
    // hosts are sealed — is expensive; keep the rule uniform by recomputing the
    // wallet_id from the descriptor sitting beside it.
    let descriptor = Descriptor::<PublicKey>::from_str(&state.descriptor)
        .map_err(|e| format!("ceremony-state.json descriptor does not parse: {e}"))?;
    // The template exposes the consensus facts the distributed manifest reports but the
    // hash preimage does not carry — `t`, `n`, and the recovery timelock are all in the
    // script (so descriptor-derivable), which is exactly why they can be re-read here
    // rather than trusted from a separate field.
    let template = policy_core::parse_vault_template(&descriptor)
        .map_err(|e| format!("ceremony-state.json descriptor is off-template: {e}"))?;
    let recomputed_wallet_id = crate::fed::wallet_id(&descriptor).to_lower_hex_string();
    if recomputed_wallet_id != state.wallet_id {
        return Err(format!(
            "ceremony-state.json wallet_id {} does not match H(descriptor) = {recomputed_wallet_id}: \
             the descriptor and wallet_id fields disagree (one was edited or corrupted). Re-run \
             `setup assemble` rather than finalize a state that cannot be trusted.",
            state.wallet_id
        )
        .into());
    }

    // The coordinator auth key is the trust root the manifest pins and every node
    // seals to (ADR-0013 §2/§4). finalize copies `coordinator-auth.secret` into the
    // backup as opaque bytes; if that file is stale, corrupted, or from another
    // ceremony, the sealed vault pins a pubkey whose private key no one holds — a
    // normal path BRICKED from birth, discovered only when the first real request is
    // rejected and the immutable manifest offers no rotation. Verify here, before any
    // artifact is written, that the secret on disk actually derives the pinned pubkey.
    let coord_secret_raw = std::fs::read_to_string(dir.join("coordinator-auth.secret"))
        .map_err(|e| format!("cannot read coordinator-auth.secret: {e}"))?;
    let coord_seckey = SecretKey::from_str(coord_secret_raw.trim())
        .map_err(|e| format!("coordinator-auth.secret is not a valid secret key: {e}"))?;
    let coord_secret_pubkey = PublicKey::new(coord_seckey.public_key(&Secp256k1::new()));
    if coord_secret_pubkey != coord_pubkey {
        return Err(format!(
            "coordinator-auth.secret derives {coord_secret_pubkey}, but ceremony-state.json pins \
             {coord_pubkey}: the secret beside this state is the wrong key (stale, corrupted, or \
             from another ceremony). Sealing now would BRICK the normal path — the manifest is \
             immutable and pins that pubkey. Restore the matching secret before finalizing."
        )
        .into());
    }

    // Nothing downstream bounds the ceiling — nodes hash it and never enforce it —
    // so `assemble`'s gate is the only one, and a state edited here then re-endorsed
    // at the hash the refusal below prints would seal a ladder no release can honour.
    check_escape_bump_ceiling(&state.policy)?;
    // Same reasoning as the ceiling above, for the descriptor/network relation: an
    // operator who edits a flavour here can recompute the hash below and re-endorse it,
    // reaching a state every downstream check passes. Run it BEFORE that recompute, so
    // the refusal names the relation and not a stale anchor.
    let hot = std::slice::from_ref(&state.hot_descriptor);
    check_ceremony_key_flavour(&state.escape_descriptor, hot, state.policy.network)?;

    // The wallet_id recompute above covers the descriptor; the manifest hash commits
    // to everything ELSE the sealed anchor binds — the policy caps (`max_msg_bytes`,
    // the hot-budget), the endpoints, and the channel keys. Endorsements are signed
    // over this hash, so an edited manifest-bound field in ceremony-state.json would
    // keep the OLD endorsed hash while finalize emits configs carrying the changed
    // value, and every node would reject the config at startup against the sealed
    // anchor. Recompute the hash from the state's own fields and refuse a mismatch
    // here, before sealing, keeping the "catch before startup" rule uniform.
    let ceremony_nodes: Vec<ceremony::CeremonyNode> = state
        .nodes
        .iter()
        .map(|node| -> Result<_, Error> {
            Ok(ceremony::CeremonyNode {
                node_id: node.node_id,
                signing_pubkey: nodekey::parse_compressed_pubkey(&node.signing_pubkey)?,
                endpoints: node.endpoints.clone(),
            })
        })
        .collect::<Result<_, Error>>()?;
    let channel_pubkeys: Vec<PublicKey> = state
        .nodes
        .iter()
        .map(|node| nodekey::parse_compressed_pubkey(&node.channel_pubkey))
        .collect::<Result<_, Error>>()?;
    let recomputed_manifest_hash = ceremony::manifest_hash(
        &wallet_id,
        &coord_pubkey,
        &ceremony_nodes,
        &channel_pubkeys,
        state.policy.max_msg_bytes,
        state.policy.hot_budget(),
        std::slice::from_ref(&state.hot_descriptor),
        &state.escape_descriptor,
        state.policy.max_derivation_index,
        state.policy.escape_feerate_floor,
        state.policy.escape_coverage_pct,
        state.policy.escape_bump_max_fee_pct,
        state.policy.network,
    )?
    .to_lower_hex_string();
    if recomputed_manifest_hash != state.manifest_hash {
        return Err(format!(
            "ceremony-state.json manifest_hash {} does not match the hash recomputed from its own \
             fields ({recomputed_manifest_hash}): a manifest-bound field (a policy cap, an \
             endpoint, or a channel key) was edited or corrupted after assembly. Every node would \
             reject the emitted config against the sealed anchor; re-run `setup assemble`.",
            state.manifest_hash
        )
        .into());
    }

    let assembled = Assembled {
        descriptor: state.descriptor.clone(),
        wallet_id,
        manifest_hash,
        nodes: state
            .nodes
            .iter()
            .map(|node| -> Result<SealedNode, Error> {
                Ok(SealedNode {
                    node_id: node.node_id,
                    signing_pubkey: nodekey::parse_compressed_pubkey(&node.signing_pubkey)?,
                    channel_pubkey: nodekey::parse_compressed_pubkey(&node.channel_pubkey)?,
                    endpoints: node.endpoints.clone(),
                })
            })
            .collect::<Result<_, Error>>()?,
        independence_report: String::new(),
        max_msg_bytes: state.policy.max_msg_bytes,
    };

    let mut endorsements = BTreeMap::new();
    for node in &state.nodes {
        let path = dir.join(format!("endorsement-{}.txt", node.node_id));
        let endorsement = std::fs::read_to_string(&path)
            .map_err(|e| {
                format!(
                    "cannot read node {}'s round-two endorsement from {}: {e}",
                    node.node_id,
                    path.display()
                )
            })?
            .trim()
            .to_string();
        assembled.verify_endorsement(node.node_id, &endorsement)?;
        endorsements.insert(node.node_id, endorsement);
    }

    // The distributed manifest (ADR-0013 §4): the base manifest plus each node's
    // endorsement, which is attached ALONGSIDE it and never inside the hashed part.
    let manifest = serde_json::json!({
        "wallet_id": state.wallet_id,
        "vault_descriptor": state.descriptor,
        "manifest_hash": state.manifest_hash,
        "coordinator_auth_pubkey": state.coordinator_auth_pubkey,
        // The runtime BaseManifest's `protocol_version` is a u32 (ADR-0013 §4), the
        // same value hashed into `manifest_hash`; emit the number, not the "v0" label.
        "protocol_version": vault_node::channel::PROTOCOL_VERSION,
        // `t`/`n`/`recovery_timelock` are consensus facts read back from the descriptor
        // (not the hash preimage), and `policy_version` is the one field that is neither
        // hash-bound nor descriptor-derivable — so recording it here is what lets the
        // manifest artifact round-trip the full typed BaseManifest for backup/audit.
        "t": template.threshold,
        "n": template.node_keys.len(),
        "recovery_timelock": template.recovery_timelock,
        "policy_version": state.policy.policy_version,
        "max_msg_bytes": state.policy.max_msg_bytes,
        "hot_max_per_tx": state.policy.hot_max_per_tx,
        "hot_max_per_window": state.policy.hot_max_per_window,
        "hot_window_secs": state.policy.hot_window_secs,
        "hot_allowlist": [state.hot_descriptor],
        "escape_descriptor": state.escape_descriptor,
        "max_derivation_index": state.policy.max_derivation_index,
        // The two fire-time selector inputs are hash-bound (bead btc-policy-9y5.7), so
        // the backup artifact must record them too or an operator could not recompute
        // `manifest_hash` from `manifest.json` alone (the documented backup set omits
        // `ceremony-state.json` and the node configs). Emit them beside the other
        // preimage fields, in preimage order.
        "escape_feerate_floor": state.policy.escape_feerate_floor,
        "escape_coverage_pct": state.policy.escape_coverage_pct,
        // The sealed ladder ceiling, hash-bound since ADR-0016 §3a and therefore
        // recorded here for the same reason as the two fields above.
        "escape_bump_max_fee_pct": state.policy.escape_bump_max_fee_pct,
        // The sealed vault network, hash-bound at manifest revision 2 and emitted in
        // preimage order for the same recompute-from-manifest.json reason. The
        // canonical spelling, never Core's `-chain=` argument.
        "network": vault_node::vault_network_name(state.policy.network),
        "nodes": state.nodes.iter().map(|node| serde_json::json!({
            "node_id": node.node_id,
            "signing_pubkey": node.signing_pubkey,
            "channel_pubkey": node.channel_pubkey,
            "transport_endpoints": node.endpoints,
            "channel_endorsement": endorsements.get(&node.node_id),
        })).collect::<Vec<_>>(),
    });
    let manifest_json = format!("{}\n", serde_json::to_string_pretty(&manifest)?);

    let allowlist = vec![
        state.hot_descriptor.clone(),
        state.escape_descriptor.clone(),
    ];
    // Render the WHOLE set before publishing (ADR-0016 §4): the ceiling and timelock
    // are jointly chosen in an immutable manifest, so a partial set is irreparable.
    // Nothing below touches the ceremony directory until `publish_artifact_set`.
    let artifact = |rel: &str, contents: String, secret: bool| Artifact {
        rel: rel.to_string(),
        contents,
        secret,
    };
    let public = |rel: &str, contents| artifact(rel, contents, false);
    let secret = |rel: &str, contents| artifact(rel, contents, true);
    let mut artifacts = vec![public("manifest.json", manifest_json.clone())];
    for node in &state.nodes {
        let kdf = KdfParams::from_hex_salt(
            &node.node_key_salt,
            node.node_key_ops,
            node.node_key_mem_kib,
        )?;
        let config = node_config_toml(&NodeConfig {
            // Derive the bind port from the endorsed, hash-bound endpoints rather than
            // trusting the redundant `state.listen_port`: if that separate field were
            // edited or corrupted after assembly, the manifest/endorsements (endpoint-
            // bound) would still verify, yet the emitted config would pin a port that
            // no longer matches its endpoint and `ChannelState::build` would reject the
            // node at startup — after sealing. Recomputing keeps the two in lockstep.
            listen_port: loopback_port(&node.endpoints, node.node_id)?,
            kdf: &kdf,
            descriptor: &state.descriptor,
            allowlist: &allowlist,
            escape_descriptor: &state.escape_descriptor,
            policy: &state.policy,
            coordinator_auth_pubkey: &coord_pubkey.to_string(),
            pin_normal_hash: &state.pin_normal_hash,
            pin_duress_hash: &state.pin_duress_hash,
            chain_backend: Some((&state.chain_backend_rpc_addr, &state.chain_backend_auth)),
            channel_toml: &assembled.channel_toml(node.node_id, &endorsements),
        });
        // Each `node-<id>.toml` carries both PIN digests and the chain-backend RPC
        // credential, so it is written owner-only rather than at the process umask.
        artifacts.push(secret(&format!("node-{}.toml", node.node_id), config));
    }

    // Backups (ADR-0013 §4/§7). A copy in a sibling directory is not itself
    // off-site storage — the README says so — but it is the artifact set an
    // operator moves, in one piece, to the media they trust.
    // Regenerate the state-derivable text files from the JUST-VERIFIED state rather
    // than blind-copying the working-dir siblings: finalize's whole rule is to catch an
    // edited artifact before sealing, and a corrupted `descriptor.txt` copied unchecked
    // into the backup would surface only years later at recovery, when the coins cannot
    // be located. `state.descriptor` passed the wallet_id recompute, `manifest_hash` the
    // manifest recompute, and `coord_pubkey` the secret-derivation check.
    // Reuse verified bytes; `fs::copy` remakes secrets at the umask. Re-read independence.txt.
    let sealed = dir.join(SEALED_DIR);
    let backup = sealed.join("backup");
    let independence = std::fs::read_to_string(dir.join("independence.txt"))
        .map_err(|e| format!("cannot back up independence.txt: {e}"))?;
    artifacts.extend([
        public("backup/descriptor.txt", format!("{}\n", state.descriptor)),
        public("backup/wallet-id.txt", format!("{}\n", state.wallet_id)),
        public(
            "backup/manifest-hash.txt",
            format!("{}\n", state.manifest_hash),
        ),
        public(
            "backup/coordinator-auth.pubkey",
            format!("{coord_pubkey}\n"),
        ),
        public("backup/manifest.json", manifest_json),
        public("backup/independence.txt", independence),
        secret("backup/coordinator-auth.secret", coord_secret_raw),
        public("backup/README.txt", BACKUP_README.to_string()),
    ]);
    publish_artifact_set(&dir, &artifacts, stage_failpoint)?;

    println!("sealed vault:");
    println!("  descriptor    : {}", state.descriptor);
    println!("  manifest_hash : {}", state.manifest_hash);
    println!("  manifest      : {}/manifest.json", sealed.display());
    println!("  node configs  : {}/node-<node_id>.toml", sealed.display());
    println!("  backups       : {}", backup.display());
    println!(
        "\nEach node config names its derivation, NOT its key: start a node with\n  \
         vault-node --config {SEALED_DIR}/node-<id>.toml   and give it that node's preimage on stdin.\n\
         A node starts ONCE in its life, before its host is sealed (ADR-0005/0007)."
    );
    println!(
        "\n!! The node-<id>.toml files and ceremony-state.json are written owner-only:\n   \
         each carries the chain-backend RPC credential and both PIN digests. After you\n   \
         distribute each node config to its own host, SECURELY DELETE the coordinator's\n   \
         copies — a coordinator that is not a single-purpose host should not retain them."
    );
    Ok(())
}

const BACKUP_README: &str = "\
btc-vault — vault backup set
============================

This directory is the minimum needed to VERIFY and, in the worst case, RECOVER
this vault. Move it to storage you control, off the coordinator.

  descriptor.txt            The full vault descriptor (all public keys). Without
                            it, even valid recovery keys cannot locate or spend
                            the coins. Back this up promiscuously.
  manifest.json             The immutable per-vault manifest: membership, channel
                            identities, endorsements, and the sealed policy
                            numbers. Public-ish; needed to reconstruct or verify.
  manifest-hash.txt         The anchor every node is sealed to.
  wallet-id.txt             H(canonical descriptor).
  coordinator-auth.pubkey   Pinned in the manifest.
  coordinator-auth.secret   *** SECRET. Store SEPARATELY from the descriptor. ***
                            Losing it with no backup BRICKS THE NORMAL PATH: the
                            manifest pins its pubkey and the manifest is immutable,
                            so every future request is rejected and the only exit
                            is the recovery timelock. There is no in-place
                            rotation in v0 -- a new auth key is a new vault.
  independence.txt          The ceremony's key-independence evidence.

NOT in here, and deliberately:
  * node-key preimages  -- each node's operator holds their own, on paper. No
                           machine holds two.
  * the escape wallet secret and the recovery keys -- they live on their own
                           devices, distributed socially/geographically.
";

// ---------------------------------------------------------------------------
// Small helpers

/// The port a node binds, taken from the endpoint it published.
///
/// v0 nodes bind loopback only (DESIGN.md, node API access control) and
/// `ChannelState::build` requires the self entry to advertise exactly
/// `127.0.0.1:<listen_port>`, so a non-loopback endpoint is refused HERE rather
/// than by every node at startup, once the vault is frozen. ADR-0013 §4 records the
/// same rule from the other side: v0 endpoints are localhost and never change, and
/// v1's onion addresses are to be derived from node key material.
///
/// EVERY published endpoint is pinned into the manifest and hashed, and a peer's
/// delivery tries them in turn, so all of them are validated — not just the first.
/// A hand-edited bundle with a routable secondary (`["127.0.0.1:9001",
/// "203.0.113.5:9001"]`) would otherwise seal and let a peer fall back to the
/// external address with a PIN-bearing carrier.
fn loopback_port(endpoints: &[String], node_id: u16) -> Result<u16, Error> {
    if endpoints.is_empty() {
        return Err(format!("node {node_id} published no endpoint").into());
    }
    let mut listen_port = None;
    for endpoint in endpoints {
        let addr = std::net::SocketAddr::from_str(endpoint).map_err(|e| {
            format!("node {node_id} endpoint {endpoint:?} is not a socket address: {e}")
        })?;
        // Exactly 127.0.0.1 — a broader `is_loopback()` would admit `::1`/`127.0.0.2`,
        // which pass here but fail `ChannelState::build`'s literal bind match at startup,
        // after the vault is frozen — and never a routable address.
        if addr.ip() != std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST) {
            return Err(format!(
                "node {node_id} publishes endpoint {endpoint:?}, but v0 nodes bind loopback only \
                 and every pinned manifest endpoint must be exactly 127.0.0.1:<port> (not {:?}); \
                 re-run `setup node-keygen` for that host with 127.0.0.1 endpoints only",
                addr.ip()
            )
            .into());
        }
        // Port 0 is the "any free port" sentinel `ChannelState::build` rejects, so a
        // `:0` endpoint would seal an unbootable node.
        if addr.port() == 0 {
            return Err(format!(
                "node {node_id} publishes endpoint {endpoint:?} with port 0: a node must pin the \
                 concrete port it binds, and `ChannelState::build` rejects 0. Re-run `setup \
                 node-keygen` for that host with a nonzero 127.0.0.1:<port> endpoint"
            )
            .into());
        }
        // The bind port is the FIRST endpoint's; the rest must be loopback too but do
        // not redefine the bind.
        listen_port.get_or_insert(addr.port());
    }
    Ok(listen_port.expect("endpoints is non-empty"))
}

fn read_definite_bundle(path: &str, role: &str) -> Result<PublicKey, Error> {
    let bundle: KeyBundle = serde_json::from_str(&std::fs::read_to_string(path)?)?;
    if bundle.role != role {
        return Err(format!("{path} is a {:?} bundle, expected {role:?}", bundle.role).into());
    }
    let pubkey = bundle
        .pubkey
        .ok_or_else(|| Error::from(format!("{path} carries no pubkey")))?;
    nodekey::parse_compressed_pubkey(&pubkey)
}

fn read_preimage(args: &Args) -> Result<Preimage, Error> {
    match args.opt("preimage-file") {
        // Hold the file's bytes in a zeroizing buffer so the preimage does not linger
        // in a freed `String` after `from_hex` copies it into the wiped `Preimage`.
        Some(path) => Preimage::from_hex(&Zeroizing::new(std::fs::read_to_string(path)?)),
        None => {
            eprint!("node-key preimage: ");
            std::io::stderr().flush()?;
            // No-echo when stdin is a terminal; unchanged for a piped/redirected read.
            Preimage::read_from_stdin()
        }
    }
}

fn hex32(text: &str, name: &str) -> Result<[u8; 32], Error> {
    use bitcoin::hex::FromHex;
    <[u8; 32]>::from_hex(text.trim()).map_err(|e| format!("{name} must be 32-byte hex: {e}").into())
}

/// Write a file only the owner can read — used for raw secrets AND for the
/// credential-bearing config artifacts (`ceremony-state.json`, `node-<id>.toml`),
/// which carry the base64 chain-backend auth and the PIN PHC hashes.
///
/// The bytes are written to a fresh owner-only temp file created with `O_EXCL`, then
/// atomically renamed over the destination. Writing in place would not be safe when
/// the destination already exists at a looser mode (a `--preimage-file`/`--secret-file`/
/// backup destination a prior run or a hand copy left at 0644): `.mode(0o600)` on an
/// open is honored by the kernel only when that open CREATES the inode, and a `chmod`
/// after the fact never revokes an fd a local user already holds on the old inode. A
/// brand-new `O_EXCL` inode has no prior openers, so the new secret is 0600 from birth;
/// `rename` swaps it into place in one step, and a reader holding the old inode keeps
/// reading the OLD bytes, never the new secret.
/// Whether two paths resolve to the same file — tolerant of `.`/`..` and a symlinked
/// PARENT directory even before the target files exist (the parent does exist: these
/// checks run against a `--out`/device-dir the ceremony is writing into). Falls back
/// to lexical equality when a parent cannot be canonicalized.
fn same_path(a: &Path, b: &Path) -> bool {
    let resolved = |p: &Path| -> Option<PathBuf> {
        let parent = match p.parent() {
            Some(dir) if !dir.as_os_str().is_empty() => dir.to_path_buf(),
            _ => PathBuf::from("."),
        };
        let file = p.file_name()?;
        parent.canonicalize().ok().map(|dir| dir.join(file))
    };
    match (resolved(a), resolved(b)) {
        (Some(x), Some(y)) => x == y,
        _ => a == b,
    }
}

fn write_secret_file(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    // The temp lives in the SAME directory so the rename is same-filesystem (atomic).
    let mut tmp_os = path.as_os_str().to_owned();
    tmp_os.push(".tmp");
    let tmp = PathBuf::from(tmp_os);
    let mut open = std::fs::OpenOptions::new();
    open.write(true).create_new(true).mode(0o600);
    // `create_new` is O_CREAT|O_EXCL: it refuses a pre-existing temp rather than adopt
    // one an attacker may have planted. A stale temp from an aborted prior run is the
    // only benign case, so clear it once and retry; a second collision fails closed.
    let mut file = match open.open(&tmp) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            std::fs::remove_file(&tmp)
                .map_err(|e| format!("cannot clear stale temp {}: {e}", tmp.display()))?;
            open.open(&tmp)
                .map_err(|e| format!("cannot create {}: {e}", tmp.display()))?
        }
        Err(e) => return Err(format!("cannot create {}: {e}", tmp.display()).into()),
    };
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(&tmp, path).map_err(|e| format!("cannot install {}: {e}", path.display()))?;
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::net::TcpListener;

    /// Argon2id's floor: these tests are about WHAT is derived and WHAT travels,
    /// never about the cost of deriving it.
    const OPS: u32 = 1;
    const MEM_KIB: u32 = 8;

    fn keypair(seed: u8) -> (SecretKey, PublicKey) {
        let secp = Secp256k1::new();
        let seckey = SecretKey::from_slice(&[seed; 32]).expect("valid sk");
        (seckey, PublicKey::new(seckey.public_key(&secp)))
    }

    /// A ranged single-sig wallet with a declared origin, from a fixed seed. `kind` is
    /// the extended-key flavour; every fixture here is on a test network, so `wallet` is
    /// the Test-kind default and only the relation tests ask for the mainnet shape.
    fn wallet_of(kind: NetworkKind, seed: u8) -> Descriptor<DescriptorPublicKey> {
        let secp = Secp256k1::new();
        let xpriv = Xpriv::new_master(kind, &[seed; 32]).expect("master");
        let xpub = Xpub::from_priv(&secp, &xpriv);
        let fingerprint = xpriv.fingerprint(&secp);
        Descriptor::from_str(&format!("wpkh([{fingerprint}]{xpub}/*)")).expect("wallet")
    }

    fn wallet(seed: u8) -> Descriptor<DescriptorPublicKey> {
        wallet_of(NetworkKind::Test, seed)
    }

    fn policy() -> PolicyParams {
        PolicyParams {
            max_derivation_index: 20,
            hold_secs: 0,
            duress_delay_secs: 0,
            epsilon_secs: 60,
            combine_slack_secs: 60,
            delivery_horizon_secs: 60,
            max_commitment_age_secs: 172_800,
            policy_version: 1,
            escape_feerate_floor: 1,
            escape_coverage_pct: vault_node::DEFAULT_ESCAPE_COVERAGE_PCT,
            escape_bump_max_fee_pct: vault_node::DEFAULT_ESCAPE_BUMP_MAX_FEE_PCT,
            hot_max_per_tx: 1_000_000,
            hot_max_per_window: 1_000_000,
            hot_window_secs: 172_800,
            max_msg_bytes: 1_048_576,
            network: bitcoin::Network::Regtest,
        }
    }

    /// Provision `n` node identities the way the ceremony does — one call per
    /// device — and keep each device's secret separate from its bundle.
    fn devices(n: usize) -> Vec<(Preimage, NodeBundle)> {
        (0..n)
            .map(|i| {
                generate_node_identity(format!("127.0.0.1:{}", 9000 + i), OPS, MEM_KIB)
                    .expect("node identity")
            })
            .collect()
    }

    /// The same provisioning, but pinning each endpoint to a port whose listener this
    /// fixture HOLDS. A sealed set's endpoints are what the loader's no-network-I/O
    /// sentinel accepts on, so a fixture that bound a free port and released it would
    /// race any parallel test for that port and could fail for that reason alone. The
    /// never-bound endpoints `devices` uses are fine for every caller that dials none,
    /// so only the ceremony fixture pays this. Non-blocking, so the sentinel's `accept`
    /// answers immediately.
    fn devices_holding_ports(n: usize) -> (Vec<(Preimage, NodeBundle)>, Vec<TcpListener>) {
        let (mut devices, mut listeners) = (Vec::new(), Vec::new());
        for _ in 0..n {
            let listener = TcpListener::bind(("127.0.0.1", 0)).expect("free loopback port");
            let addr = listener.local_addr().expect("addr").to_string();
            listener.set_nonblocking(true).expect("nonblocking");
            listeners.push(listener);
            devices.push(generate_node_identity(addr, OPS, MEM_KIB).expect("node identity"));
        }
        (devices, listeners)
    }

    /// The bead's headline property, stated as a test: what a node publishes is
    /// enough to assemble the vault, and it contains NOTHING that can reproduce
    /// that node's key. A coordinator holding every bundle holds zero node secrets.
    #[test]
    fn a_published_node_bundle_carries_no_secret_and_cannot_derive_the_key() {
        let devices = devices(3);
        for (preimage, bundle) in &devices {
            let published = serde_json::to_string(bundle).expect("serialize");
            assert!(
                !published.contains(preimage.to_hex().as_str()),
                "the published bundle must not contain the preimage"
            );
            // Everything in the bundle, plus ANY other device's secret, still fails
            // to reproduce this device's key: the preimage is the whole secret.
            for (other, _) in &devices {
                let derived = nodekey::derive(other, &bundle.kdf().expect("kdf")).expect("derive");
                let matches = PublicKey::new(derived.public_key(&Secp256k1::new())).to_string()
                    == bundle.signing_pubkey;
                assert_eq!(
                    matches,
                    std::ptr::eq(other, preimage),
                    "only this device's own preimage may derive its key"
                );
            }
        }
        // Distinct devices, distinct identities — no salt or key reuse across hosts.
        let keys: std::collections::HashSet<&String> =
            devices.iter().map(|(_, b)| &b.signing_pubkey).collect();
        assert_eq!(keys.len(), devices.len(), "every node key is distinct");
        let salts: std::collections::HashSet<&String> =
            devices.iter().map(|(_, b)| &b.node_key_salt).collect();
        assert_eq!(salts.len(), devices.len(), "every node salt is distinct");
    }

    /// The coordinator assembles a complete, loadable vault from PUBLIC bundles
    /// alone — the other half of "no machine holds two node secrets". If assembly
    /// needed a secret this would not compile, which is the point of the signature.
    #[test]
    fn the_ceremony_assembles_a_vault_from_public_bundles_alone() {
        let devices = devices(5);
        let bundles: Vec<NodeBundle> = devices.iter().map(|(_, b)| b.clone()).collect();
        let (_, user) = keypair(1);
        let recovery: Vec<PublicKey> = (0x30u8..=0x32).map(|i| keypair(i).1).collect();
        let (_, coord) = keypair(0xC0);
        let escape = wallet(0xE0).to_string();
        let hot = vec![wallet(0xA0).to_string()];

        let assembled = assemble(
            &bundles,
            3,
            user,
            &recovery,
            coord,
            &escape,
            &hot,
            &policy(),
        )
        .expect("assemble");

        // The descriptor names exactly the published keys, and `node_id` is the
        // canonical lexicographic position every party derives independently.
        let parsed = Descriptor::<PublicKey>::from_str(&assembled.descriptor).expect("parse");
        let template = policy_core::parse_vault_template(&parsed).expect("on-template");
        let mut expected: Vec<String> = bundles.iter().map(|b| b.signing_pubkey.clone()).collect();
        expected.sort();
        let named: Vec<String> = template.node_keys.iter().map(|k| k.to_string()).collect();
        assert_eq!(named, expected);
        for (index, node) in assembled.nodes.iter().enumerate() {
            assert_eq!(node.node_id, index as u16);
            assert_eq!(node.signing_pubkey.to_string(), expected[index]);
        }
    }

    /// The ceremony's ONE network seam (bead btc-policy-sealed-network-v2-mn6 A2).
    ///
    /// `bitcoin::Network`'s own serde and `FromStr` would accept `test`, `testnet4` and
    /// Core's `main` — two chains this vault cannot seal and one alias for a chain it
    /// can. The adapter accepts exactly three canonical strings, and the field is
    /// mandatory: a defaulted network would let a ceremony that never names a chain
    /// seal one anyway, into an immutable manifest.
    #[test]
    fn the_ceremony_input_accepts_exactly_the_three_canonical_network_spellings() {
        let base = serde_json::to_value(policy()).expect("PolicyParams serializes");
        assert_eq!(
            base["network"], "regtest",
            "the canonical spelling round-trips through the adapter"
        );
        let parse = |raw: Option<serde_json::Value>| {
            let mut value = base.clone();
            let object = value.as_object_mut().expect("a JSON object");
            match raw {
                Some(network) => object.insert("network".to_string(), network),
                None => object.remove("network"),
            };
            serde_json::from_value::<PolicyParams>(value)
        };
        for (spelling, expected) in [
            ("bitcoin", bitcoin::Network::Bitcoin),
            ("signet", bitcoin::Network::Signet),
            ("regtest", bitcoin::Network::Regtest),
        ] {
            let policy = parse(Some(spelling.into())).expect("a canonical spelling is accepted");
            assert_eq!(policy.network, expected, "{spelling}");
        }
        // The two testnets `bitcoin::Network` hands back, Core's mainnet spelling and
        // its alias, then case, padding, emptiness and plain garbage.
        let rejected = ["testnet", "testnet4", "test", "main", "mainnet"];
        let rejected = rejected
            .iter()
            .chain(&["Bitcoin", " regtest ", "", "mutinynet"]);
        for rejected in rejected.copied() {
            let err = parse(Some(rejected.into()))
                .expect_err("only the three canonical spellings are accepted")
                .to_string();
            assert!(
                err.contains("unsupported vault network")
                    && err.contains(vault_node::SUPPORTED_VAULT_NETWORKS),
                "{rejected:?} must be refused with the allowed set: {err}"
            );
        }
        assert!(
            parse(Some(3.into()))
                .expect_err("a non-string network is not a spelling at all")
                .to_string()
                .contains("string"),
            "a non-string network must be refused"
        );
        assert!(
            parse(None)
                .expect_err("the network is mandatory")
                .to_string()
                .contains("missing field `network`"),
            "an absent network must not silently default"
        );
    }

    /// The gate is on REAL ceremony output, not the parse alone: the sealed network
    /// reaches the manifest hash `assemble` seals AND the node config the federation is
    /// sealed alongside. Two networks, since one cannot tell a threaded value from a
    /// constant.
    #[test]
    fn the_sealed_network_reaches_both_the_manifest_hash_and_the_node_config() {
        let devices = devices(3);
        let bundles: Vec<NodeBundle> = devices.iter().map(|(_, b)| b.clone()).collect();
        let (_, user) = keypair(1);
        let recovery: Vec<PublicKey> = (0x30u8..=0x32).map(|i| keypair(i).1).collect();
        let (_, coord) = keypair(0xC0);
        let escape = wallet(0xE0).to_string();
        let hot = vec![wallet(0xA0).to_string()];
        let sealed = |network| {
            let policy = PolicyParams {
                network,
                ..policy()
            };
            let assembled = assemble(&bundles, 2, user, &recovery, coord, &escape, &hot, &policy)
                .expect("assemble");
            let config = node_config_toml(&NodeConfig {
                listen_port: 9000,
                kdf: &bundles[0].kdf().expect("kdf"),
                descriptor: &assembled.descriptor,
                allowlist: &hot,
                escape_descriptor: &escape,
                policy: &policy,
                coordinator_auth_pubkey: &coord.to_string(),
                pin_normal_hash: "x",
                pin_duress_hash: "y",
                chain_backend: None,
                channel_toml: "",
            });
            (assembled.manifest_hash, config)
        };
        let (signet_hash, signet_config) = sealed(bitcoin::Network::Signet);
        let (regtest_hash, regtest_config) = sealed(bitcoin::Network::Regtest);
        assert_ne!(
            signet_hash, regtest_hash,
            "the ceremony seals the network into manifest_hash, so two chains are two vaults"
        );
        assert!(
            signet_config.contains("network = \"signet\"")
                && regtest_config.contains("network = \"regtest\""),
            "the one config writer emits the network it was sealed with"
        );
    }

    /// ADR-0016 §3's four refusals, each reachable and each named distinctly. The
    /// ORDER is what makes that true: the 5x margin is strictly stronger than the
    /// coverage bound, so a coverage-only violation could never be diagnosed if the
    /// margin were checked first, and an over-cap value would be blamed on coverage if
    /// the ingress cap were checked last. The last row is not a bound at all: a value
    /// the caps ADMIT, refused because nothing composes its rungs until btc-policy-sqn.
    #[test]
    fn the_ceremony_refuses_every_ladder_ceiling_the_vault_cannot_honour() {
        for (ceiling, coverage, expected) in [
            (11, 95, "ingress fee cap"),
            (6, 95, "exceeds the fire-time coverage headroom"),
            (2, 95, "5x margin"),
            (1, 95, "UNSUPPORTED LADDER CONFIGURATION"),
            // Coverage above 100 IS reachable — nothing in this ceremony bounds it, only
            // the node does (lib.rs `1..=100`) — so the subtraction must not underflow.
            (1, 200, "exceeds the fire-time coverage headroom"),
            // A ceiling at the ingress cap with all the headroom in the world still
            // reaches the sqn gate — and `ceiling * 5` must not wrap on the way.
            (10, 0, "UNSUPPORTED LADDER CONFIGURATION"),
        ] {
            let policy = PolicyParams {
                escape_bump_max_fee_pct: ceiling,
                escape_coverage_pct: coverage,
                ..policy()
            };
            let err = check_escape_bump_ceiling(&policy)
                .err()
                .unwrap_or_else(|| {
                    panic!("ceiling {ceiling} at coverage {coverage} must be refused")
                })
                .to_string();
            assert!(
                err.contains(expected),
                "ceiling {ceiling} at coverage {coverage}: expected {expected:?}, got: {err}"
            );
        }
        // The supported posture seals: zero, ladderless, two transactions per spend.
        check_escape_bump_ceiling(&policy()).expect("the default zero ceiling seals");
    }

    #[test]
    fn a_misspelled_ladder_ceiling_is_not_silently_defaulted() {
        let misspelled = serde_json::to_string(&policy())
            .expect("serialize policy")
            .replace("\"escape_bump_max_fee_pct\"", "\"escape_bump_max_fee_pc\"");
        assert!(
            serde_json::from_str::<PolicyParams>(&misspelled).is_err(),
            "an unknown ceiling field must not silently select the zero default"
        );
    }

    /// The gate is WIRED, not merely present: a cap-valid nonzero ceiling must not
    /// survive the seal path the CLI and the regtest harness share. Without this, a
    /// `check_escape_bump_ceiling` that no caller invokes would test green.
    #[test]
    fn assemble_refuses_a_nonzero_ceiling_before_it_seals_anything() {
        let devices = devices(3);
        let bundles: Vec<NodeBundle> = devices.iter().map(|(_, b)| b.clone()).collect();
        let recovery: Vec<PublicKey> = (0x30u8..=0x32).map(|i| keypair(i).1).collect();
        let seal = |escape_bump_max_fee_pct| {
            assemble(
                &bundles,
                2,
                keypair(1).1,
                &recovery,
                keypair(0xC0).1,
                &wallet(0xE0).to_string(),
                &[wallet(0xA0).to_string()],
                &PolicyParams {
                    escape_bump_max_fee_pct,
                    ..policy()
                },
            )
        };
        let err = seal(1)
            .expect_err("a nonzero ceiling must not reach a sealed manifest")
            .to_string();
        assert!(
            err.contains("UNSUPPORTED LADDER CONFIGURATION"),
            "unexpected error: {err}"
        );
        seal(0).expect("the default zero ceiling assembles");
    }

    /// The relation is WIRED into the real seal path the CLI and the regtest harness
    /// share, and refuses a mismatched Escape and a mismatched hot wallet
    /// INDEPENDENTLY — one role is not coverage for the other. Remove only `assemble`'s
    /// call and every row reaches a completed `Assembled { .. manifest_hash .. }`.
    #[test]
    fn assemble_refuses_a_key_flavour_that_left_the_sealed_network_before_it_seals_anything() {
        use bitcoin::Network::{Bitcoin, Regtest};
        use NetworkKind::{Main, Test};
        let bundles: Vec<NodeBundle> = devices(3).into_iter().map(|(_, b)| b).collect();
        let recovery: Vec<PublicKey> = (0x30u8..=0x32).map(|i| keypair(i).1).collect();
        let (user, coord) = (keypair(1).1, keypair(0xC0).1);
        let seal = |network, escape_kind, hot_kind| {
            let policy = PolicyParams {
                network,
                ..policy()
            };
            let escape = wallet_of(escape_kind, 0xE0).to_string();
            let hot = [wallet_of(hot_kind, 0xA0).to_string()];
            assemble(&bundles, 2, user, &recovery, coord, &escape, &hot, &policy)
        };
        // The regtest vault offended by each role in turn, then the mainnet vault
        // carrying the tpub `keygen` emitted before `--network`.
        for (network, escape_kind, hot_kind, role, kind) in [
            (Regtest, Main, Test, "escape", "main-kind"),
            (Regtest, Test, Main, "hot allowlist", "main-kind"),
            (Bitcoin, Test, Main, "escape", "test-kind"),
        ] {
            let err = seal(network, escape_kind, hot_kind)
                .expect_err("a mismatched key flavour must not reach a sealed manifest")
                .to_string();
            assert!(
                err.contains(role)
                    && err.contains(kind)
                    && err.contains(vault_node::vault_network_name(network)),
                "unexpected error: {err}"
            );
        }
        // Both consistent pairs seal, so the refusals above are the relation talking.
        seal(Regtest, Test, Test).expect("a regtest vault seals its tpub wallets");
        seal(Bitcoin, Main, Main).expect("a bitcoin vault seals its xpub wallets");
    }

    /// `keygen --role escape --network` is MANDATORY and selects the flavour all three
    /// boundaries then enforce: `bitcoin` births an `xpub`, signet and regtest a `tpub`.
    /// A missing or unsupported network refuses rather than guessing a default the
    /// ceremony would reject later, after the escape device showed its secret.
    #[test]
    fn escape_keygen_births_the_flavour_its_network_seals_and_refuses_without_one() {
        let temp = crate::fed::TempDir::new("setup-keygen").expect("temp dir");
        let out = |name: &str| temp.path.join(name).display().to_string();
        // `--network ""` is how a row asks for the flag to be ABSENT entirely.
        let run = |network: &str, out: &str| {
            let mut argv = vec!["--role", "escape", "--out", out];
            if !network.is_empty() {
                argv.extend(["--network", network]);
            }
            keygen(&Args::parse(&argv))
        };
        for (network, prefix) in [("bitcoin", "xpub"), ("signet", "tpub"), ("regtest", "tpub")] {
            let path = out(network);
            run(network, &path).unwrap_or_else(|e| panic!("keygen for {network}: {e}"));
            let bundle: KeyBundle =
                serde_json::from_str(&std::fs::read_to_string(&path).expect("bundle"))
                    .expect("parse bundle");
            let text = bundle
                .descriptor
                .expect("escape bundles carry a descriptor");
            let parsed = Descriptor::from_str(&text).expect("escape descriptor");
            let sealed = vault_node::parse_vault_network(network).expect("supported network");
            assert!(
                text.contains(prefix),
                "a {network} key must be {prefix}: {text}"
            );
            // And it is sealable: this key passes the relation every boundary enforces.
            policy_core::check_descriptor_network_kind("escape", &parsed, sealed)
                .expect("keygen must birth a key its own network accepts");
        }
        let refused = |network| {
            run(network, &out("refused"))
                .expect_err("keygen must refuse")
                .to_string()
        };
        assert!(
            refused("").contains("missing --network"),
            "no default network"
        );
        assert!(refused("testnet").contains("unsupported vault network"));
        // And they land before the write, which is why the flag has no default.
        assert!(!temp.path.join("refused").exists(), "a refusal wrote a key");
    }

    /// ADR-0016 §4's ceremony-time disclosure, at the only ceiling this release
    /// accepts. None of its three facts is derivable from the number itself: the
    /// ceiling's scope (rungs, never the base Escape), the base fee's non-existence at
    /// seal time, and the fixed timelock beside it, so the two are still chosen
    /// together before `btc-policy-wdu` makes the second one selectable.
    #[test]
    fn the_ceremony_discloses_the_rung_only_scope_the_unknown_base_fee_and_the_timelock() {
        let disclosure = ladder_disclosure(&policy());
        for expected in [
            "escape_bump_max_fee_pct = 0",
            "recovery timelock = 180 days (FIXED",
            "REPLACEMENT RUNGS ONLY",
            "never caps the base Escape",
            "CANNOT EXIST at seal time",
            "exactly two transactions",
        ] {
            assert!(
                disclosure.contains(expected),
                "the ceremony disclosure must state {expected:?}: {disclosure}"
            );
        }
        // The "180" above is the descriptor's real timelock, not a copied number.
        assert_eq!(
            policy_core::RECOVERY_TIMELOCK_UNITS as u64 * 512 / 86_400,
            180
        );
    }

    /// Round two, end to end: a device re-derives from its own preimage, endorses,
    /// and the coordinator's verification accepts it — while the SAME endorsement
    /// attributed to another node, and one made over a different manifest, are both
    /// rejected before anything is sealed.
    #[test]
    fn an_endorsement_is_verified_before_the_manifest_is_sealed() {
        let devices = devices(3);
        let bundles: Vec<NodeBundle> = devices.iter().map(|(_, b)| b.clone()).collect();
        let (_, user) = keypair(1);
        let recovery: Vec<PublicKey> = (0x30u8..=0x32).map(|i| keypair(i).1).collect();
        let (_, coord) = keypair(0xC0);
        let escape = wallet(0xE0).to_string();
        let hot = vec![wallet(0xA0).to_string()];
        let assembled = assemble(
            &bundles,
            2,
            user,
            &recovery,
            coord,
            &escape,
            &hot,
            &policy(),
        )
        .expect("assemble");

        let node = &assembled.nodes[0];
        let (preimage, bundle) = devices
            .iter()
            .find(|(_, b)| b.signing_pubkey == node.signing_pubkey.to_string())
            .expect("the sealed node is one of the devices");
        let seckey = nodekey::derive(preimage, &bundle.kdf().expect("kdf")).expect("derive");
        let endorsement = ceremony::endorse(
            &seckey,
            &assembled.wallet_id,
            &assembled.manifest_hash,
            node.node_id,
            &bundle.endpoints,
        );
        assembled
            .verify_endorsement(node.node_id, &endorsement)
            .expect("a device's own endorsement verifies");

        // Same signature, wrong node_id: the digest binds node_id, so this is the
        // "endorsements got shuffled between hosts" mistake — caught here rather
        // than at every node's startup, after sealing.
        assert!(assembled.verify_endorsement(1, &endorsement).is_err());
        // An endorsement over a DIFFERENT manifest: the domain separator is what
        // stops another vault's manifest being substituted (ADR-0013 §4).
        let wrong = ceremony::endorse(
            &seckey,
            &assembled.wallet_id,
            &[0x9au8; 32],
            node.node_id,
            &bundle.endpoints,
        );
        assert!(assembled.verify_endorsement(node.node_id, &wrong).is_err());
    }

    /// **The load-bearing refusal** (ADR-0012 §10). An escape wallet that derives
    /// the USER key — the honest-lazy "one device exported both roles" case, and
    /// exactly the shape that converts duress into theft — stops the ceremony.
    #[test]
    fn a_shared_seed_escape_is_refused_at_ceremony_time() {
        let secp = Secp256k1::new();
        let escape = wallet(0xE0);
        // The user key is a key of the escape wallet itself, at a non-zero index:
        // one seed, both roles, no origin left on the vault side to compare.
        let derived = escape.derived_descriptor(&secp, 7).expect("derive");
        let mut user = None;
        derived.for_each_key(|key| {
            user = Some(*key);
            true
        });
        let user = user.expect("the wallet has a key");

        let devices = devices(3);
        let bundles: Vec<NodeBundle> = devices.iter().map(|(_, b)| b.clone()).collect();
        let recovery: Vec<PublicKey> = (0x30u8..=0x32).map(|i| keypair(i).1).collect();
        let (_, coord) = keypair(0xC0);
        let hot = vec![wallet(0xA0).to_string()];
        let err = assemble(
            &bundles,
            2,
            user,
            &recovery,
            coord,
            &escape.to_string(),
            &hot,
            &policy(),
        )
        .expect_err("a shared-seed escape must stop the ceremony");
        let message = err.to_string();
        assert!(
            message.contains("KEY INDEPENDENCE VIOLATED") && message.contains("user"),
            "the refusal must name the shared user key: {message}"
        );
        assert!(
            message.contains("index 7"),
            "the refusal must say WHERE the overlap is: {message}"
        );
    }

    /// The same refusal for the other vault roles, so the check is not accidentally
    /// user-only: a node key or a recovery key inside the escape wallet's range is
    /// equally fatal.
    #[test]
    fn an_escape_sharing_a_node_or_recovery_key_is_refused() {
        let secp = Secp256k1::new();
        let escape = wallet(0xE1);
        let escape_key_at = |index: u32| {
            let derived = escape.derived_descriptor(&secp, index).expect("derive");
            let mut key = None;
            derived.for_each_key(|k| {
                key = Some(*k);
                true
            });
            key.expect("key")
        };

        let devices = devices(3);
        let bundles: Vec<NodeBundle> = devices.iter().map(|(_, b)| b.clone()).collect();
        let (_, user) = keypair(1);
        let (_, coord) = keypair(0xC0);
        let hot = vec![wallet(0xA0).to_string()];

        // A recovery key that is really an escape-wallet address.
        let recovery = vec![escape_key_at(2), keypair(0x31).1, keypair(0x32).1];
        let err = assemble(
            &bundles,
            2,
            user,
            &recovery,
            coord,
            &escape.to_string(),
            &hot,
            &policy(),
        )
        .expect_err("a shared escape/recovery seed must stop the ceremony");
        assert!(err.to_string().contains("recovery[0]"), "unexpected: {err}");
    }

    /// The child scan compares the escape wallet's DERIVED addresses; the parent
    /// xpub they hang off is never one of them. A vault key that IS that parent is
    /// the worst case — non-hardened BIP32 over a public chain code lets its holder
    /// derive every escape address — so the ancestor comparison must refuse it.
    /// Empirically (Fable 9y5.5 pass-1) the pre-fix ceremony sealed exactly this and
    /// wrote "no overlap detected" into the witnessed evidence: a silent duress→theft.
    #[test]
    fn an_escape_wallet_whose_parent_xpub_is_the_user_key_is_refused() {
        let secp = Secp256k1::new();
        let devices = devices(3);
        let bundles: Vec<NodeBundle> = devices.iter().map(|(_, b)| b.clone()).collect();
        // The escape wallet is a ranged xpub; the user key is that xpub's OWN public
        // key — the account key a hand-written hardware-wallet bundle exports — so the
        // user private key derives every escape address. None of the escape's derived
        // children equal the user key, so only the ANCESTOR check can catch this.
        let xpriv = Xpriv::new_master(NetworkKind::Test, &[0xE7u8; 32]).expect("master");
        let xpub = Xpub::from_priv(&secp, &xpriv);
        let fingerprint = xpriv.fingerprint(&secp);
        let escape = format!("wpkh([{fingerprint}]{xpub}/*)");
        let user = PublicKey::new(xpub.public_key);
        let recovery: Vec<PublicKey> = (0x30u8..=0x32).map(|i| keypair(i).1).collect();
        let (_, coord) = keypair(0xC0);
        let hot = vec![wallet(0xA0).to_string()];
        let err = assemble(
            &bundles,
            2,
            user,
            &recovery,
            coord,
            &escape,
            &hot,
            &policy(),
        )
        .expect_err("an escape wallet the user key derives must stop the ceremony");
        let message = err.to_string();
        assert!(
            message.contains("KEY INDEPENDENCE VIOLATED") && message.contains("ANCESTOR"),
            "the refusal must name the ancestor overlap: {message}"
        );
        assert!(
            message.contains("user"),
            "and name the shared role: {message}"
        );
    }

    /// A compromised-at-wrench coordinator (ADR-0010, ADR-0012) whose auth key is the
    /// escape wallet's parent is the same duress→theft, so the coordinator key joins
    /// the comparison set even though it is not in the frozen descriptor.
    #[test]
    fn an_escape_wallet_derivable_from_the_coordinator_key_is_refused() {
        let secp = Secp256k1::new();
        let devices = devices(3);
        let bundles: Vec<NodeBundle> = devices.iter().map(|(_, b)| b.clone()).collect();
        let xpriv = Xpriv::new_master(NetworkKind::Test, &[0xE8u8; 32]).expect("master");
        let xpub = Xpub::from_priv(&secp, &xpriv);
        let fingerprint = xpriv.fingerprint(&secp);
        let escape = format!("wpkh([{fingerprint}]{xpub}/*)");
        let (_, user) = keypair(1);
        let recovery: Vec<PublicKey> = (0x30u8..=0x32).map(|i| keypair(i).1).collect();
        // The coordinator key IS the escape wallet's parent xpub.
        let coord = PublicKey::new(xpub.public_key);
        let hot = vec![wallet(0xA0).to_string()];
        let err = assemble(
            &bundles,
            2,
            user,
            &recovery,
            coord,
            &escape,
            &hot,
            &policy(),
        )
        .expect_err("an escape derivable from the coordinator key must stop the ceremony");
        let message = err.to_string();
        assert!(
            message.contains("KEY INDEPENDENCE VIOLATED") && message.contains("coordinator"),
            "the refusal must name the coordinator overlap: {message}"
        );
    }

    /// A BIP389 multipath escape descriptor (`…/<0;1>/*`) — a common hardware-wallet
    /// export shape — must be SCANNED, not rejected: policy-core expands it at fire
    /// time (`into_single_descriptors`), so the ceremony that seals the vault has to
    /// accept the same shape. Pre-fix, `derived_descriptor` returned MultiKey and the
    /// ceremony refused a legitimate escape wallet.
    #[test]
    fn a_multipath_escape_descriptor_is_scanned_not_rejected() {
        let secp = Secp256k1::new();
        let devices = devices(3);
        let bundles: Vec<NodeBundle> = devices.iter().map(|(_, b)| b.clone()).collect();
        let xpriv = Xpriv::new_master(NetworkKind::Test, &[0xE9u8; 32]).expect("master");
        let xpub = Xpub::from_priv(&secp, &xpriv);
        let fingerprint = xpriv.fingerprint(&secp);
        let escape = format!("wpkh([{fingerprint}]{xpub}/<0;1>/*)");
        let (_, user) = keypair(1);
        let recovery: Vec<PublicKey> = (0x30u8..=0x32).map(|i| keypair(i).1).collect();
        let (_, coord) = keypair(0xC0);
        let hot = vec![wallet(0xA0).to_string()];
        let assembled = assemble(
            &bundles,
            2,
            user,
            &recovery,
            coord,
            &escape,
            &hot,
            &policy(),
        )
        .expect("an independent multipath escape must seal, not be rejected");
        assert!(assembled
            .independence_report
            .contains("VERDICT: no overlap detected."));
    }

    /// The coordinator is the second KDF-cost checkpoint: `assemble` records every
    /// node's Argon2id cost in the witnessed evidence and flags any below the
    /// production floor. The `devices()` fixtures derive at the floor, so this seals
    /// (defence-in-depth, not a refusal) but the evidence names the weakness.
    #[test]
    fn assemble_records_node_kdf_cost_and_flags_below_floor() {
        let devices = devices(3);
        let bundles: Vec<NodeBundle> = devices.iter().map(|(_, b)| b.clone()).collect();
        let (_, user) = keypair(1);
        let recovery: Vec<PublicKey> = (0x30u8..=0x32).map(|i| keypair(i).1).collect();
        let (_, coord) = keypair(0xC0);
        let hot = vec![wallet(0xA0).to_string()];
        let assembled = assemble(
            &bundles,
            2,
            user,
            &recovery,
            coord,
            &wallet(0xE5).to_string(),
            &hot,
            &policy(),
        )
        .expect("floor-cost bundles still seal");
        assert!(assembled
            .independence_report
            .contains("Node key-derivation cost"));
        assert!(assembled
            .independence_report
            .contains("BELOW PRODUCTION FLOOR"));
    }

    /// The escape wallet must be independent of the HOT wallet too, including by
    /// derivation: hot = parent/*, escape = (parent/N)/* means the hot parent private
    /// key derives every escape address, so the hot-key holder controls the sweep.
    /// Origin-less descriptors carry no shared fingerprint (parent and child differ),
    /// so only the full escape⟂hot key-set comparison catches it.
    #[test]
    fn an_escape_derivable_from_a_hot_wallet_ancestor_is_refused() {
        let secp = Secp256k1::new();
        let devices = devices(3);
        let bundles: Vec<NodeBundle> = devices.iter().map(|(_, b)| b.clone()).collect();
        let (_, user) = keypair(1);
        let recovery: Vec<PublicKey> = (0x30u8..=0x32).map(|i| keypair(i).1).collect();
        let (_, coord) = keypair(0xC0);
        let parent = Xpriv::new_master(NetworkKind::Test, &[0xB7u8; 32]).expect("master");
        let parent_xpub = Xpub::from_priv(&secp, &parent);
        let branch = bitcoin::bip32::ChildNumber::from_normal_idx(3).expect("normal");
        let child_xpub = parent_xpub.ckd_pub(&secp, branch).expect("derive child");
        // Origin-less, so the fingerprint tripwire cannot catch it (parent and child
        // fall back to their OWN, distinct fingerprints).
        let hot = vec![format!("wpkh({parent_xpub}/*)")];
        let escape = format!("wpkh({child_xpub}/*)");
        let err = assemble(
            &bundles,
            2,
            user,
            &recovery,
            coord,
            &escape,
            &hot,
            &policy(),
        )
        .expect_err("an escape derivable from the hot parent must stop the ceremony");
        let message = err.to_string();
        assert!(
            message.contains("KEY INDEPENDENCE VIOLATED")
                && message.contains("hot-key holder could control the escape sweep"),
            "the refusal must name the hot↔escape derivation: {message}"
        );
    }

    /// The escape wallet must be a key-controlled RANGED wallet: a hand-written bundle
    /// with a scriptless (`wsh(1)` anyone-spendable) or definite (non-ranged) escape
    /// would otherwise seal a destination that loses or exposes every swept coin.
    #[test]
    fn a_scriptless_or_non_ranged_escape_is_refused() {
        let devices = devices(3);
        let bundles: Vec<NodeBundle> = devices.iter().map(|(_, b)| b.clone()).collect();
        let (_, user) = keypair(1);
        let recovery: Vec<PublicKey> = (0x30u8..=0x32).map(|i| keypair(i).1).collect();
        let (_, coord) = keypair(0xC0);
        let hot = vec![wallet(0xA0).to_string()];
        let seal =
            |escape: &str| assemble(&bundles, 2, user, &recovery, coord, escape, &hot, &policy());
        // Anyone-spendable / scriptless — refused (by the shape check or the descriptor
        // parse; either way it never seals).
        let err = seal("wsh(1)").expect_err("an anyone-spendable escape must be refused");
        let m = err.to_string();
        assert!(
            m.contains("ranged wallet")
                || m.contains("key-controlled")
                || m.contains("does not parse"),
            "unexpected: {m}"
        );
        // Keyed but DEFINITE (no `/*`): a non-ranged escape is not the intended wallet.
        let definite = format!("wpkh({})", keypair(0xE4).1);
        let err = seal(&definite).expect_err("a non-ranged escape must be refused");
        assert!(
            err.to_string().contains("ranged wallet"),
            "unexpected: {err}"
        );
    }

    /// A `--secret-file` that aliases the public `--out` would overwrite the bundle
    /// with the raw secret. `same_path` catches the alias (here via the lexical
    /// fallback, since the parents need not exist), before any write.
    #[test]
    fn a_secret_file_aliasing_the_public_out_is_refused() {
        assert!(same_path(Path::new("/a/b/x"), Path::new("/a/b/x")));
        assert!(!same_path(Path::new("/a/b/x"), Path::new("/a/b/y")));
        let args = Args::parse(&[
            "--role",
            "user",
            "--out",
            "/tmp/vault-x/bundle.json",
            "--secret-file",
            "/tmp/vault-x/bundle.json",
        ]);
        let err = keygen(&args).expect_err("a secret-file aliasing --out must refuse");
        assert!(
            err.to_string().contains("same file as --out"),
            "unexpected: {err}"
        );
    }

    /// A ceremony that would seal an unbootable federation — a `:0` port or two nodes
    /// pinned to one loopback port — is refused before finalize, not discovered at a
    /// node's startup after the vault is frozen.
    #[test]
    fn assemble_refuses_unbootable_ports() {
        let base = |bundles: &[NodeBundle]| {
            let (_, user) = keypair(1);
            let recovery: Vec<PublicKey> = (0x30u8..=0x32).map(|i| keypair(i).1).collect();
            let (_, coord) = keypair(0xC0);
            let hot = vec![wallet(0xA0).to_string()];
            assemble(
                bundles,
                2,
                user,
                &recovery,
                coord,
                &wallet(0xE0).to_string(),
                &hot,
                &policy(),
            )
        };
        // Port 0.
        let devs = devices(3);
        let mut bundles: Vec<NodeBundle> = devs.iter().map(|(_, b)| b.clone()).collect();
        bundles[0].endpoints = vec!["127.0.0.1:0".to_string()];
        let err = base(&bundles).expect_err("a :0 port must be refused");
        assert!(err.to_string().contains("port 0"), "unexpected: {err}");
        // Two nodes on one port.
        let devs = devices(3);
        let mut bundles: Vec<NodeBundle> = devs.iter().map(|(_, b)| b.clone()).collect();
        bundles[1].endpoints = bundles[0].endpoints.clone();
        let err = base(&bundles).expect_err("a duplicate port must be refused");
        assert!(
            err.to_string().contains("same loopback port"),
            "unexpected: {err}"
        );
        // A routable SECONDARY endpoint (first is loopback, so a first-only check would
        // pass) — every pinned endpoint is validated, not just the first.
        let devs = devices(3);
        let mut bundles: Vec<NodeBundle> = devs.iter().map(|(_, b)| b.clone()).collect();
        bundles[0].endpoints = vec!["127.0.0.1:9000".to_string(), "203.0.113.5:9000".to_string()];
        let err = base(&bundles).expect_err("a non-loopback secondary endpoint must be refused");
        assert!(
            err.to_string().contains("loopback only"),
            "unexpected: {err}"
        );
    }

    /// A bundle whose signing pubkey is valid UPPERCASE hex must still assemble: the
    /// sealed node canonicalizes to lowercase, and the bundle-lookup map is keyed by
    /// the parsed (canonical) key so the lookup does not miss.
    #[test]
    fn an_uppercase_pubkey_bundle_still_assembles() {
        let devices = devices(3);
        let mut bundles: Vec<NodeBundle> = devices.iter().map(|(_, b)| b.clone()).collect();
        bundles[0].signing_pubkey = bundles[0].signing_pubkey.to_uppercase();
        let (_, user) = keypair(1);
        let recovery: Vec<PublicKey> = (0x30u8..=0x32).map(|i| keypair(i).1).collect();
        let (_, coord) = keypair(0xC0);
        let hot = vec![wallet(0xA0).to_string()];
        assemble(
            &bundles,
            2,
            user,
            &recovery,
            coord,
            &wallet(0xE0).to_string(),
            &hot,
            &policy(),
        )
        .expect("an uppercase-hex bundle must assemble, not fail lookup");
    }

    /// An operator-supplied threshold larger than `usize::MAX / 2` must fall through to
    /// the shape-validation error, not panic (debug) or wrap (release) on `t * 2 - 1`.
    #[test]
    fn an_overflowing_threshold_is_a_shape_error_not_a_panic() {
        let devices = devices(3);
        let bundles: Vec<NodeBundle> = devices.iter().map(|(_, b)| b.clone()).collect();
        let (_, user) = keypair(1);
        let recovery: Vec<PublicKey> = (0x30u8..=0x32).map(|i| keypair(i).1).collect();
        let (_, coord) = keypair(0xC0);
        let hot = vec![wallet(0xA0).to_string()];
        let err = assemble(
            &bundles,
            usize::MAX / 2 + 1,
            user,
            &recovery,
            coord,
            &wallet(0xE0).to_string(),
            &hot,
            &policy(),
        )
        .expect_err("an overflowing threshold must be a shape error");
        assert!(
            err.to_string().contains("federation must be exactly"),
            "unexpected: {err}"
        );
    }

    /// A production keygen must not silently derive at a below-default KDF cost: the
    /// bundle publishes salt/ops/mem, so a cheap cost shrinks every node key's offline
    /// margin. The refusal fires on the args, BEFORE any filesystem work, and only
    /// `--allow-weak-kdf` (a test/automation opt-in) lets a weaker cost through.
    #[test]
    fn node_keygen_refuses_a_below_floor_kdf_without_the_optin() {
        let device_dir = "/proc/nonexistent/keygen-should-refuse-before-touching-fs";
        let args = Args::parse(&[
            "--device-dir",
            device_dir,
            "--endpoint",
            "127.0.0.1:9000",
            "--kdf-ops",
            "1",
            "--kdf-mem-kib",
            "8",
        ]);
        let err = node_keygen(&args).expect_err("below-floor kdf without opt-in must refuse");
        assert!(
            err.to_string().contains("production KDF floor"),
            "unexpected: {err}"
        );
        // The gate returns before `create_dir_all`, so nothing was written.
        assert!(!std::path::Path::new(device_dir).exists());
    }

    /// The arg parser must treat `--allow-weak-kdf` as a valueless flag without eating
    /// a following token or corrupting a preceding valued flag — the property the
    /// harness relies on when it appends the flag after `--preimage-file <path>`.
    #[test]
    fn a_valueless_flag_parses_without_disturbing_valued_flags() {
        let args = Args::parse(&["--device-dir", "/x", "--allow-weak-kdf"]);
        assert!(args.flag("allow-weak-kdf"));
        assert_eq!(args.get("device-dir").expect("present"), "/x");
        // A valued flag after a bare flag still parses; an absent flag reads false.
        let args = Args::parse(&["--allow-weak-kdf", "--endpoint", "127.0.0.1:9000"]);
        assert!(args.flag("allow-weak-kdf"));
        assert_eq!(args.get("endpoint").expect("present"), "127.0.0.1:9000");
        assert!(!Args::parse(&["--device-dir", "/x"]).flag("allow-weak-kdf"));
    }

    /// The ADR-0003 tripwire, retained as defence-in-depth: escape and hot wallets
    /// from one seed share a BIP32 master fingerprint, and the ceremony refuses
    /// before it ever gets to compare a derived key.
    #[test]
    fn an_escape_sharing_an_origin_with_the_hot_wallet_is_refused() {
        let devices = devices(3);
        let bundles: Vec<NodeBundle> = devices.iter().map(|(_, b)| b.clone()).collect();
        let (_, user) = keypair(1);
        let recovery: Vec<PublicKey> = (0x30u8..=0x32).map(|i| keypair(i).1).collect();
        let (_, coord) = keypair(0xC0);
        // Same seed, different derivation suffix: distinct descriptors, distinct
        // derived keys, ONE master fingerprint.
        let secp = Secp256k1::new();
        let xpriv = Xpriv::new_master(NetworkKind::Test, &[0xE2u8; 32]).expect("master");
        let xpub = Xpub::from_priv(&secp, &xpriv);
        let fingerprint = xpriv.fingerprint(&secp);
        let escape = format!("wpkh([{fingerprint}/0h]{xpub}/0/*)");
        let hot = vec![format!("wpkh([{fingerprint}/1h]{xpub}/1/*)")];

        let err = assemble(
            &bundles,
            2,
            user,
            &recovery,
            coord,
            &escape,
            &hot,
            &policy(),
        )
        .expect_err("a shared origin must stop the ceremony");
        assert!(
            err.to_string().contains("master fingerprint"),
            "unexpected: {err}"
        );
    }

    /// The honest path produces evidence the operator can read, and it says what it
    /// could NOT check. A silent pass would be the failure mode here.
    #[test]
    fn the_independence_report_states_its_verdict_and_its_residual() {
        let (_, user) = keypair(1);
        let node_keys: Vec<PublicKey> = (2u8..=6).map(|i| keypair(i).1).collect();
        let recovery: Vec<PublicKey> = (0x30u8..=0x32).map(|i| keypair(i).1).collect();
        let report = check_independence(&IndependenceInputs {
            user_key: user,
            node_keys: &node_keys,
            recovery_keys: &recovery,
            coordinator_key: keypair(0xC0).1,
            escape_descriptor: &wallet(0xE0).to_string(),
            hot_descriptors: &[wallet(0xA0).to_string()],
            max_derivation_index: 20,
        })
        .expect("independent keys pass");
        assert!(report.contains("VERDICT: no overlap detected."));
        assert!(report.contains("RESIDUAL"));
        assert!(report.contains("unlinkable"), "the report states the limit");
        // Every vault role is named in the evidence, not just summarized.
        assert!(report.contains("user"));
        assert!(report.contains("node[4]"));
        assert!(report.contains("recovery[2]"));
    }

    /// The federation shape is frozen into the descriptor, so a shape no node can
    /// boot must be refused BEFORE sealing rather than found at every node's
    /// startup, when the only remedy is provisioning a different vault.
    #[test]
    fn the_ceremony_refuses_a_federation_shape_no_node_can_boot() {
        let (_, user) = keypair(1);
        let recovery: Vec<PublicKey> = (0x30u8..=0x32).map(|i| keypair(i).1).collect();
        let (_, coord) = keypair(0xC0);
        let escape = wallet(0xE0).to_string();
        let hot = vec![wallet(0xA0).to_string()];
        // (t, n) pairs that are NOT n = 2t-1: 2-of-4 (an unfrozen quorum could sit
        // outside an armed set), 3-of-4 (three withholders leave the honest
        // remainder below t), and t = 1 (nothing to confirm an arm against).
        for (t, n) in [(2, 4), (3, 4), (1, 1), (3, 6)] {
            let bundles: Vec<NodeBundle> = devices(n).into_iter().map(|(_, b)| b).collect();
            let err = assemble(
                &bundles,
                t,
                user,
                &recovery,
                coord,
                &escape,
                &hot,
                &policy(),
            )
            .expect_err("{t}-of-{n} must not seal");
            assert!(err.to_string().contains("n = 2t - 1"), "unexpected: {err}");
        }
        // ...and the shapes that ARE n = 2t-1 seal fine.
        for (t, n) in [(2, 3), (3, 5), (4, 7)] {
            let bundles: Vec<NodeBundle> = devices(n).into_iter().map(|(_, b)| b).collect();
            assemble(
                &bundles,
                t,
                user,
                &recovery,
                coord,
                &escape,
                &hot,
                &policy(),
            )
            .unwrap_or_else(|e| panic!("{t}-of-{n} is a permitted shape: {e}"));
        }
    }

    /// A ranged vault descriptor cannot be sealed. The ceremony produces definite
    /// keys, so this is a guard against a hand-edited or future-drifted input
    /// rather than a shape the tooling emits — and it must be caught HERE, because
    /// a sealed vault whose descriptor no node can parse is unrecoverable.
    #[test]
    fn the_ceremony_refuses_a_ranged_vault_key() {
        let devices = devices(3);
        let mut bundles: Vec<NodeBundle> = devices.iter().map(|(_, b)| b.clone()).collect();
        bundles[0].signing_pubkey = "not-a-compressed-pubkey".to_string();
        let (_, user) = keypair(1);
        let recovery: Vec<PublicKey> = (0x30u8..=0x32).map(|i| keypair(i).1).collect();
        let (_, coord) = keypair(0xC0);
        assert!(assemble(
            &bundles,
            2,
            user,
            &recovery,
            coord,
            &wallet(0xE0).to_string(),
            &[wallet(0xA0).to_string()],
            &policy(),
        )
        .is_err());

        // And the template check itself, on a real ranged key EXPRESSION (built
        // directly rather than by unwrapping a descriptor string, whose checksum
        // covers the whole expression and would not survive the surgery).
        let secp = Secp256k1::new();
        let xpriv = Xpriv::new_master(NetworkKind::Test, &[0xB0u8; 32]).expect("master");
        let ranged_key = format!(
            "[{}]{}/*",
            xpriv.fingerprint(&secp),
            Xpub::from_priv(&secp, &xpriv)
        );
        let ranged = policy_core::vault_descriptor_string(
            &user.to_string(),
            2,
            &[
                ranged_key,
                keypair(3).1.to_string(),
                keypair(4).1.to_string(),
            ],
            &recovery.iter().map(|k| k.to_string()).collect::<Vec<_>>(),
        );
        let parsed = Descriptor::<DescriptorPublicKey>::from_str(&ranged).expect("parses");
        let err = policy_core::parse_vault_template(&parsed)
            .expect_err("a ranged vault key must be refused");
        assert!(err.contains("DEFINITE"), "unexpected: {err}");
    }

    /// The whole chain, in one test: five devices birth their own keys, the
    /// coordinator assembles from public bundles alone, each device endorses, and
    /// the resulting per-node config **is loaded by the real `vault_node::Node`**
    /// with only that device's preimage.
    ///
    /// This is what "the wskdf-derived key produces the node pubkey the manifest
    /// expects" means operationally: `Node::from_toml_str` re-derives the key,
    /// checks it against the frozen descriptor, recomputes `manifest_hash` from the
    /// config's own `[channel]` block, and compares it to the sealed anchor. If any
    /// of the ceremony's bytes disagreed with the node's own definitions — the
    /// hash preimage, the endorsement digest, the canonical key order — this
    /// federation would not boot, and neither would a real one.
    #[test]
    fn a_ceremony_sealed_config_loads_in_the_real_node_with_only_its_own_preimage() {
        let devices: Vec<(Preimage, NodeBundle)> = (0..5)
            .map(|i| {
                generate_node_identity(format!("127.0.0.1:{}", 9100 + i), OPS, MEM_KIB)
                    .expect("node identity")
            })
            .collect();
        let bundles: Vec<NodeBundle> = devices.iter().map(|(_, b)| b.clone()).collect();
        let (_, user) = keypair(1);
        let recovery: Vec<PublicKey> = (0x30u8..=0x32).map(|i| keypair(i).1).collect();
        let (_, coord) = keypair(0xC0);
        let escape = wallet(0xE0).to_string();
        let hot = wallet(0xA0).to_string();
        // n = 2t - 1, the shape ADR-0013 §1 requires in channel mode.
        let assembled = assemble(
            &bundles,
            3,
            user,
            &recovery,
            coord,
            &escape,
            std::slice::from_ref(&hot),
            &policy(),
        )
        .expect("assemble");

        let mut endorsements = BTreeMap::new();
        for node in &assembled.nodes {
            let (preimage, bundle) = devices
                .iter()
                .find(|(_, b)| b.signing_pubkey == node.signing_pubkey.to_string())
                .expect("sealed node is one of the devices");
            let seckey = nodekey::derive(preimage, &bundle.kdf().expect("kdf")).expect("derive");
            endorsements.insert(
                node.node_id,
                ceremony::endorse(
                    &seckey,
                    &assembled.wallet_id,
                    &assembled.manifest_hash,
                    node.node_id,
                    &bundle.endpoints,
                ),
            );
        }

        for node in &assembled.nodes {
            let (preimage, bundle) = devices
                .iter()
                .find(|(_, b)| b.signing_pubkey == node.signing_pubkey.to_string())
                .expect("sealed node is one of the devices");
            let config = node_config_toml(&NodeConfig {
                listen_port: loopback_port(&bundle.endpoints, node.node_id).expect("port"),
                kdf: &bundle.kdf().expect("kdf"),
                descriptor: &assembled.descriptor,
                allowlist: &[hot.clone(), escape.clone()],
                escape_descriptor: &escape,
                policy: &policy(),
                coordinator_auth_pubkey: &coord.to_string(),
                pin_normal_hash: &vault_node::argon2id_normal_phc_at("1234", 8),
                pin_duress_hash: &vault_node::argon2id_duress_phc_at("9999", 8),
                chain_backend: Some(("127.0.0.1:18443", "dGVzdDp0ZXN0")),
                channel_toml: &assembled.channel_toml(node.node_id, &endorsements),
            });
            vault_node::Node::from_toml_str(&config, preimage).unwrap_or_else(|e| {
                panic!("node {} must load its sealed config: {e}", node.node_id)
            });

            // ...and ONLY with its own preimage. Another device's secret derives a
            // key this vault does not name, which must be a fatal startup error
            // rather than a daemon that signs with a key nothing can combine.
            let (other, _) = devices
                .iter()
                .find(|(_, b)| b.signing_pubkey != node.signing_pubkey.to_string())
                .expect("another device");
            let err = vault_node::Node::from_toml_str(&config, other)
                .err()
                .expect("a stranger preimage must not boot this node");
            assert!(
                err.to_string()
                    .contains("not one of the vault descriptor's")
                    || err.to_string().contains("signing_pubkey"),
                "unexpected: {err}"
            );
        }
    }

    /// The config the ceremony writes names a DERIVATION, never a key. This is the
    /// retirement of `node_seckey`-at-rest, checked on the bytes that actually land
    /// on a node host.
    #[test]
    fn a_generated_node_config_contains_no_key_material() {
        let (preimage, bundle) =
            generate_node_identity("127.0.0.1:9000".to_string(), OPS, MEM_KIB).expect("identity");
        let kdf = bundle.kdf().expect("kdf");
        let seckey = nodekey::derive(&preimage, &kdf).expect("derive");
        let config = node_config_toml(&NodeConfig {
            listen_port: 9000,
            kdf: &kdf,
            descriptor: "wsh(...)",
            allowlist: &[wallet(0xA0).to_string()],
            escape_descriptor: &wallet(0xE0).to_string(),
            policy: &policy(),
            coordinator_auth_pubkey: &keypair(0xC0).1.to_string(),
            pin_normal_hash: "$argon2id$...",
            pin_duress_hash: "$argon2id$...",
            chain_backend: Some(("127.0.0.1:18443", "dGVzdDp0ZXN0")),
            channel_toml: "",
        });
        assert!(
            !config.contains("node_seckey"),
            "the retired at-rest key field must be gone"
        );
        assert!(!config.contains(&seckey.display_secret().to_string()));
        assert!(!config.contains(preimage.to_hex().as_str()));
        assert!(config.contains(&format!("node_key_salt = \"{}\"", kdf.salt_hex())));
    }

    // -----------------------------------------------------------------------
    // The finalize round trip (bead btc-policy-nsw)
    //
    // `finalize_cmd` is the REAL production seal path, and until this suite it had no
    // coverage at all: the regtest harness (`fed.rs`) calls `assemble` + `node_config_toml`
    // directly and never goes through it. That gap is why the 9y5.5 review found finalize
    // bugs across four consecutive passes (wallet_id/manifest_hash recompute, the
    // coordinator-secret verify, listen-port-from-endpoints, the complete typed
    // manifest.json, backup regeneration). These tests drive the ACTUAL commands —
    // `assemble_cmd` → per-device `ceremony::endorse` → `finalize_cmd` — over real files.

    /// A ceremony working directory carried with its `TempDir`, so the directory
    /// outlives the assertions and is removed afterwards.
    pub(crate) struct Ceremony {
        _temp: crate::fed::TempDir,
        dir: PathBuf,
        devices: Vec<(Preimage, NodeBundle)>,
        /// One per pinned endpoint, bound BEFORE the ceremony chose it and held for
        /// the fixture's life; see [`devices_holding_ports`] and the loader's sentinel.
        pub(crate) listeners: Vec<TcpListener>,
    }

    impl Ceremony {
        /// The published artifact root, spelled LITERALLY rather than through
        /// `SEALED_DIR` (bead btc-policy-sealed-network-v2-mn6 A8): a test that reads
        /// the constant would follow any future rename silently, including back to a
        /// revision-bearing name the docs and the b8z/sq7 target clauses no longer use.
        pub(crate) fn sealed(&self, rel: impl AsRef<Path>) -> PathBuf {
            self.dir.join("sealed").join(rel)
        }

        fn state(&self) -> CeremonyState {
            serde_json::from_str(
                &std::fs::read_to_string(self.dir.join("ceremony-state.json")).expect("state"),
            )
            .expect("parse state")
        }

        /// Rewrite `ceremony-state.json` after `edit` mutates the parsed state.
        fn edit_state(&self, edit: impl FnOnce(&mut serde_json::Value)) {
            let mut value: serde_json::Value = serde_json::from_str(
                &std::fs::read_to_string(self.dir.join("ceremony-state.json")).expect("state"),
            )
            .expect("parse state");
            edit(&mut value);
            std::fs::write(
                self.dir.join("ceremony-state.json"),
                serde_json::to_string_pretty(&value).expect("serialize"),
            )
            .expect("write state");
        }

        pub(crate) fn finalize(&self) -> Result<(), Error> {
            self.finalize_stopping_at(None)
        }

        /// `finalize` with the staging failpoint armed: `Some(i)` aborts immediately
        /// before artifact `i` is staged.
        fn finalize_stopping_at(&self, stage_failpoint: Option<usize>) -> Result<(), Error> {
            finalize_cmd(
                &Args::parse(&["--dir", self.dir.to_str().expect("utf-8 dir")]),
                stage_failpoint,
            )
        }
    }

    /// Run the ceremony up to (but not including) `finalize`: publish `n` device
    /// bundles, run the real `assemble_cmd` over a `ceremony-input.json`, then have
    /// each device endorse the sealed anchor with the key its OWN preimage derives —
    /// exactly what `setup node-endorse` does on each host.
    pub(crate) fn ceremony_through_endorse(n: usize, threshold: usize) -> Ceremony {
        let temp = crate::fed::TempDir::new("setup-finalize").expect("temp dir");
        let dir = temp.path.join("ceremony");
        std::fs::create_dir_all(&dir).expect("ceremony dir");
        let (devices, listeners) = devices_holding_ports(n);

        let mut node_bundles = Vec::new();
        for (index, (_, bundle)) in devices.iter().enumerate() {
            let path = dir.join(format!("node-bundle-{index}.json"));
            std::fs::write(&path, serde_json::to_string(bundle).expect("bundle")).expect("write");
            node_bundles.push(path.to_str().expect("utf-8").to_string());
        }
        let write_key_bundle = |name: &str, bundle: &KeyBundle| -> String {
            let path = dir.join(name);
            std::fs::write(&path, serde_json::to_string(bundle).expect("key bundle"))
                .expect("write");
            path.to_str().expect("utf-8").to_string()
        };
        let user_bundle = write_key_bundle(
            "user-bundle.json",
            &KeyBundle {
                role: "user".into(),
                descriptor: None,
                pubkey: Some(keypair(1).1.to_string()),
                master_fingerprint: None,
            },
        );
        let recovery_bundles: Vec<String> = (0x30u8..=0x32)
            .map(|seed| {
                write_key_bundle(
                    &format!("recovery-bundle-{seed}.json"),
                    &KeyBundle {
                        role: "recovery".into(),
                        descriptor: None,
                        pubkey: Some(keypair(seed).1.to_string()),
                        master_fingerprint: None,
                    },
                )
            })
            .collect();
        let escape_bundle = write_key_bundle(
            "escape-bundle.json",
            &KeyBundle {
                role: "escape".into(),
                descriptor: Some(wallet(0xE0).to_string()),
                pubkey: None,
                master_fingerprint: None,
            },
        );

        // `CeremonyInput` is deserialize-only (it is an operator-authored file), so the
        // test authors the same JSON an operator would rather than serializing the type.
        let input = serde_json::json!({
            "threshold": threshold,
            "node_bundles": node_bundles,
            "user_bundle": user_bundle,
            "recovery_bundles": recovery_bundles,
            "escape_bundle": escape_bundle,
            "hot_descriptor": wallet(0xA0).to_string(),
            "policy": policy(),
            // Real PHC strings at the fixture's Argon2 cost: `Node::load` validates the
            // shape and DISTINCT salts, so a placeholder would seal a vault no node boots.
            "pin_normal_hash": vault_node::argon2id_normal_phc_at("1234", MEM_KIB),
            "pin_duress_hash": vault_node::argon2id_duress_phc_at("9999", MEM_KIB),
            "chain_backend_rpc_addr": "127.0.0.1:18443",
            "chain_backend_auth": "dGVzdDp0ZXN0",
        });
        let input_path = dir.join("ceremony-input.json");
        std::fs::write(
            &input_path,
            serde_json::to_string_pretty(&input).expect("input"),
        )
        .expect("write input");

        assemble_cmd(&Args::parse(&[
            "--input",
            input_path.to_str().expect("utf-8"),
            "--out",
            dir.to_str().expect("utf-8"),
        ]))
        .expect("assemble");

        // Round two, on each device: endorse the sealed anchor with the key this
        // device's own preimage derives. `node-endorse` does exactly this, and writing
        // the file here is what that command writes.
        let ceremony = Ceremony {
            _temp: temp,
            dir,
            devices,
            listeners,
        };
        let state = ceremony.state();
        let wallet_id = hex32(&state.wallet_id, "wallet_id").expect("wallet_id");
        let manifest_hash = hex32(&state.manifest_hash, "manifest_hash").expect("manifest_hash");
        for node in &state.nodes {
            let (preimage, bundle) = ceremony
                .devices
                .iter()
                .find(|(_, bundle)| bundle.signing_pubkey == node.signing_pubkey)
                .expect("every sealed node is one of the published bundles");
            let seckey = nodekey::derive(preimage, &bundle.kdf().expect("kdf")).expect("derive");
            // Sign over the DEVICE's own endpoint copy, exactly as `node-endorse` does
            // (it reads the bundle on that host and never sees ceremony-state.json).
            // Signing over the state's copy instead would quietly assume the two agree,
            // which is part of what the endorsement exists to establish.
            let endorsement = vault_node::channel::ceremony::endorse(
                &seckey,
                &wallet_id,
                &manifest_hash,
                node.node_id,
                &bundle.endpoints,
            );
            std::fs::write(
                ceremony
                    .dir
                    .join(format!("endorsement-{}.txt", node.node_id)),
                format!("{endorsement}\n"),
            )
            .expect("write endorsement");
        }
        ceremony
    }

    /// Swap the sealed wallet in `field` for the `(kind, seed)` one and RE-SEAL: recompute
    /// `manifest_hash` from the state's own fields and have every device re-endorse it, as an
    /// operator who edited the state and re-ran round two would. Without it the state fails the
    /// hash recompute or a stale endorsement, which a test could not tell apart from a refusal.
    fn reseal(run: &Ceremony, field: &str, kind: NetworkKind, seed: u8) {
        run.edit_state(|state| {
            state[field] = serde_json::json!(wallet_of(kind, seed).to_string());
        });
        let state = run.state();
        let pubkey = |hex: &str| nodekey::parse_compressed_pubkey(hex).expect("sealed pubkey");
        let (nodes, channel_pubkeys): (Vec<ceremony::CeremonyNode>, Vec<PublicKey>) = state
            .nodes
            .iter()
            .map(|node| {
                let sealed = ceremony::CeremonyNode {
                    node_id: node.node_id,
                    signing_pubkey: pubkey(&node.signing_pubkey),
                    endpoints: node.endpoints.clone(),
                };
                (sealed, pubkey(&node.channel_pubkey))
            })
            .unzip();
        let wallet_id = hex32(&state.wallet_id, "wallet_id").expect("wallet_id");
        let manifest_hash = ceremony::manifest_hash(
            &wallet_id,
            &pubkey(&state.coordinator_auth_pubkey),
            &nodes,
            &channel_pubkeys,
            state.policy.max_msg_bytes,
            state.policy.hot_budget(),
            std::slice::from_ref(&state.hot_descriptor),
            &state.escape_descriptor,
            state.policy.max_derivation_index,
            state.policy.escape_feerate_floor,
            state.policy.escape_coverage_pct,
            state.policy.escape_bump_max_fee_pct,
            state.policy.network,
        )
        .expect("recompute the anchor over the edited state");
        run.edit_state(|value| {
            value["manifest_hash"] = serde_json::json!(manifest_hash.to_lower_hex_string());
        });
        for node in &state.nodes {
            let (preimage, bundle) = run
                .devices
                .iter()
                .find(|(_, bundle)| bundle.signing_pubkey == node.signing_pubkey)
                .expect("every sealed node is one of the published bundles");
            let sk = nodekey::derive(preimage, &bundle.kdf().expect("kdf")).expect("derive");
            let sig = ceremony::endorse(
                &sk,
                &wallet_id,
                &manifest_hash,
                node.node_id,
                &bundle.endpoints,
            );
            let path = run.dir.join(format!("endorsement-{}.txt", node.node_id));
            std::fs::write(path, format!("{sig}\n")).expect("write endorsement");
        }
    }

    /// Why assemble-only checking is not enough (bead btc-policy-descriptor-network-kind-x00): an
    /// operator who swaps a sealed destination wallet for the SAME key in the other flavour can
    /// recompute the anchor and re-endorse it — wallet_id, hash, coordinator secret and all five
    /// endorsements then verify, so finalize's own relation check is all that stands between that
    /// state and a sealed vault off its network. It covers escape and hot INDEPENDENTLY: emptying
    /// either argument alone must not leave the other row green.
    #[test]
    fn finalize_refuses_a_reendorsed_state_whose_key_flavour_left_the_sealed_network() {
        for (field, role, seed) in [
            ("escape_descriptor", "escape", 0xE0),
            ("hot_descriptor", "hot allowlist", 0xA0),
        ] {
            let run = ceremony_through_endorse(5, 3);
            reseal(&run, field, NetworkKind::Main, seed);
            let error = match run.finalize() {
                Err(error) => error.to_string(),
                Ok(()) => panic!("a re-endorsed {role} flavour mismatch must not seal"),
            };
            assert!(
                error.contains(role)
                    && error.contains("regtest")
                    && error.contains("main-kind (xpub)"),
                "the refusal must name the relation, got: {error}"
            );
            assert!(
                !run.sealed("manifest.json").exists() && !run.sealed("node-0.toml").exists(),
                "the relation must refuse BEFORE anything is sealed"
            );
        }
        // Control: the SAME edit in the MATCHING flavour still seals — nothing else proves
        // the recompute and the five re-endorsements are real work, since the relation is
        // checked first and a BROKEN reseal would refuse identically.
        let control = ceremony_through_endorse(5, 3);
        reseal(&control, "escape_descriptor", NetworkKind::Test, 0xE1);
        control.finalize().expect("a re-endorsed match still seals");
    }

    /// ADR-0016 §4: a ceremony interrupted mid-write leaves NOTHING sealed and is
    /// safely retriable — the manifest is immutable, so half a jointly chosen artifact
    /// set is not a thing a later edit can repair. Two interruption points, because
    /// they fail differently: artifact 1 is the instant AFTER the manifest itself is
    /// staged (the first thing rendered), and artifact 2 is BETWEEN two node configs,
    /// where a write-as-you-go finalize would already have published one host's config.
    #[test]
    fn an_interrupted_finalize_seals_nothing_and_an_exact_retry_completes_one_set() {
        use std::os::unix::fs::PermissionsExt;
        let ceremony = ceremony_through_endorse(3, 2);
        let published = [
            "manifest.json",
            "node-0.toml",
            "node-1.toml",
            "node-2.toml",
            "backup/manifest.json",
            "backup/coordinator-auth.secret",
            "backup/README.txt",
        ];
        let staging_name = format!("{STAGING_DIR}.{}", std::process::id());
        let staging = ceremony.dir.join(&staging_name);
        let mode = |path: &Path| path.metadata().expect("root mode").permissions().mode();
        // Staging is per invocation, so publication must never remove a directory it did not
        // create: clearing an overlapping finalize's set would leave it renaming a partial one.
        let theirs = ceremony.dir.join(STAGING_DIR);
        std::fs::create_dir(&theirs).expect("another invocation's staging directory");
        for failpoint in [1, 2] {
            let err = ceremony
                .finalize_stopping_at(Some(failpoint))
                .expect_err("the armed failpoint must abort finalize")
                .to_string();
            assert!(
                err.contains("interrupted before staging artifact"),
                "unexpected error: {err}"
            );
            for rel in published {
                // The ceremony ROOT as well as the sealed set: a write-in-place finalize
                // exposes the root path and never creates the sealed directory at all.
                assert!(
                    !ceremony.sealed(rel).exists() && !ceremony.dir.join(rel).exists(),
                    "failpoint {failpoint} published {rel}: an interrupted ceremony must seal \
                     nothing"
                );
            }
            // ...and it fired AFTER real bytes were written, or the case above would
            // prove nothing about a partial write.
            assert!(
                staging.join("manifest.json").exists(),
                "failpoint {failpoint} must fire after the manifest was staged"
            );
            assert_eq!(mode(&staging) & 0o077, 0, "staging root is not owner-only");
        }

        // The exact retry — same command, same directory — completes the set.
        ceremony
            .finalize()
            .expect("the exact retry seals the vault");
        for rel in published {
            assert!(
                ceremony.sealed(rel).exists(),
                "{rel} missing after the retry"
            );
        }
        assert!(
            !staging.exists(),
            "a completed publication leaves no staging directory behind"
        );
        assert!(theirs.exists(), "overlapping staging was destroyed");
        assert_eq!(mode(&ceremony.sealed("")) & 0o077, 0, "sealed root mode");

        // A completed seal is immutable even when its bytes still match. In particular,
        // a hand copy can preserve bytes while widening secret modes; finalize must not
        // bless that filesystem state as a verified artifact set.
        let secret = ceremony.sealed("backup/coordinator-auth.secret");
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o644))
            .expect("simulate an unsafe hand copy");
        let err = ceremony
            .finalize()
            .expect_err("finalize never accepts an existing sealed set")
            .to_string();
        assert!(err.contains("already exists"), "unexpected error: {err}");
    }

    #[test]
    fn a_root_level_publish_obstruction_cannot_expose_a_partial_artifact_set() {
        let temp = crate::fed::TempDir::new("atomic-publication").expect("tempdir");
        let dir = &temp.path;
        std::fs::create_dir(dir.join("manifest.json")).expect("obstruct any root-level write");
        let artifacts = [
            Artifact {
                rel: "manifest.json".into(),
                contents: "manifest".into(),
                secret: false,
            },
            Artifact {
                rel: "node-0.toml".into(),
                contents: "config".into(),
                secret: true,
            },
        ];
        publish_artifact_set(dir, &artifacts, None).expect("publish one complete directory");
        assert!(
            !dir.join("node-0.toml").exists(),
            "publication must not expose an independently usable node config"
        );
        // The LITERAL neutral root, and its owner-only mode: the rename moved the
        // directory name, not the atomic/0700 semantics it was published with.
        use std::os::unix::fs::PermissionsExt;
        let sealed = dir.join("sealed");
        assert!(sealed.join("node-0.toml").exists());
        assert_eq!(
            std::fs::metadata(&sealed)
                .expect("sealed dir")
                .permissions()
                .mode()
                & 0o777,
            0o700,
            "the neutral sealed root is still owner-only"
        );
    }

    /// The headline round trip: assemble → endorse → finalize seals a COMPLETE typed
    /// manifest, owner-only node configs whose bind port comes from the endorsed
    /// endpoint, and a backup regenerated from the verified state.
    #[test]
    fn the_finalize_round_trip_seals_a_complete_manifest_and_owner_only_configs() {
        let ceremony = ceremony_through_endorse(5, 3);
        ceremony.finalize().expect("finalize");
        let state = ceremony.state();

        // 1. manifest.json is the complete typed BaseManifest (ADR-0013 §4), not a
        //    partial echo: every field an operator needs to reconstruct the vault —
        //    including the ones the hash preimage does NOT carry (t/n/recovery_timelock/
        //    policy_version) and the ones it does.
        let manifest: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(ceremony.sealed("manifest.json")).expect("manifest.json"),
        )
        .expect("parse manifest");
        assert_eq!(
            manifest["protocol_version"],
            serde_json::json!(vault_node::channel::PROTOCOL_VERSION),
            "protocol_version is the hashed u32, not a \"v0\" label"
        );
        assert_eq!(manifest["t"], serde_json::json!(3));
        assert_eq!(manifest["n"], serde_json::json!(5));
        assert_eq!(
            manifest["recovery_timelock"],
            serde_json::json!(policy_core::RECOVERY_TIMELOCK_NSEQUENCE),
            "the recovery timelock is read back from the descriptor"
        );
        assert_eq!(manifest["wallet_id"], serde_json::json!(state.wallet_id));
        assert_eq!(
            manifest["manifest_hash"],
            serde_json::json!(state.manifest_hash)
        );
        assert_eq!(
            manifest["vault_descriptor"],
            serde_json::json!(state.descriptor)
        );
        // Every hash-preimage field, so `manifest_hash` is recomputable from this
        // artifact alone (the documented backup set carries no ceremony-state.json).
        for (field, expected) in [
            ("policy_version", serde_json::json!(policy().policy_version)),
            ("max_msg_bytes", serde_json::json!(policy().max_msg_bytes)),
            ("hot_max_per_tx", serde_json::json!(policy().hot_max_per_tx)),
            (
                "hot_max_per_window",
                serde_json::json!(policy().hot_max_per_window),
            ),
            (
                "hot_window_secs",
                serde_json::json!(policy().hot_window_secs),
            ),
            (
                "max_derivation_index",
                serde_json::json!(policy().max_derivation_index),
            ),
            (
                "escape_feerate_floor",
                serde_json::json!(policy().escape_feerate_floor),
            ),
            (
                "escape_coverage_pct",
                serde_json::json!(policy().escape_coverage_pct),
            ),
            (
                "escape_bump_max_fee_pct",
                serde_json::json!(policy().escape_bump_max_fee_pct),
            ),
            (
                "network",
                serde_json::json!(vault_node::vault_network_name(policy().network)),
            ),
            (
                "coordinator_auth_pubkey",
                serde_json::json!(state.coordinator_auth_pubkey),
            ),
            (
                "hot_allowlist",
                serde_json::json!([state.hot_descriptor.clone()]),
            ),
            (
                "escape_descriptor",
                serde_json::json!(state.escape_descriptor),
            ),
        ] {
            assert_eq!(manifest[field], expected, "manifest.json field {field}");
        }
        // Each node entry carries its FULL identity, not just an endorsement: the node
        // list is part of the hash preimage, so a manifest that dropped a pubkey or an
        // endpoint could not reproduce `manifest_hash` either.
        let nodes = manifest["nodes"].as_array().expect("nodes array");
        assert_eq!(nodes.len(), 5);
        for (entry, sealed) in nodes.iter().zip(&state.nodes) {
            assert_eq!(entry["node_id"], serde_json::json!(sealed.node_id));
            assert_eq!(
                entry["signing_pubkey"],
                serde_json::json!(sealed.signing_pubkey)
            );
            assert_eq!(
                entry["channel_pubkey"],
                serde_json::json!(sealed.channel_pubkey)
            );
            assert_eq!(
                entry["transport_endpoints"],
                serde_json::json!(sealed.endpoints)
            );
            assert!(
                entry["channel_endorsement"]
                    .as_str()
                    .is_some_and(|e| !e.is_empty()),
                "each node's endorsement rides ALONGSIDE the manifest, never inside the hash"
            );
        }

        // 2. Each node-<id>.toml is owner-only (it carries both PIN digests and the
        //    chain-backend credential) and binds the port from its ENDORSED endpoint.
        for node in &state.nodes {
            use std::os::unix::fs::PermissionsExt;
            let path = ceremony.sealed(format!("node-{}.toml", node.node_id));
            let mode = std::fs::metadata(&path)
                .expect("config metadata")
                .permissions()
                .mode();
            assert_eq!(
                mode & 0o777,
                0o600,
                "node-{}.toml carries PIN digests + the RPC credential",
                node.node_id
            );
            let config = std::fs::read_to_string(&path).expect("config");
            let expected_port =
                loopback_port(&node.endpoints, node.node_id).expect("endorsed endpoint");
            assert!(
                config.contains(&format!("listen_port = {expected_port}")),
                "node {} must bind the port its endorsed endpoint names",
                node.node_id
            );
            assert!(config.contains(&format!(
                "expected_manifest_hash = \"{}\"",
                state.manifest_hash
            )));
        }

        // 3. The backup exists. That it is REGENERATED rather than blind-copied is a
        //    separate property and needs a corrupted sibling to prove — see
        //    `the_backup_is_regenerated_from_verified_state_not_copied_from_siblings`.
        for name in ["descriptor.txt", "wallet-id.txt", "manifest-hash.txt"] {
            let path = ceremony.sealed("backup").join(name);
            assert!(path.exists(), "backup/{name} must be written");
        }
    }

    /// The backup is REGENERATED from the just-verified state, never blind-copied from
    /// the working-directory siblings `assemble` left behind.
    ///
    /// Asserting `backup/descriptor.txt == state.descriptor` on a clean run proves
    /// nothing: `assemble` writes a byte-identical sibling, so a `std::fs::copy`
    /// regression passes (Fable nsw review, verified by mutation). Corrupting the
    /// siblings first is what separates the two implementations — and it is exactly the
    /// scenario the production comment exists for: a corrupted `descriptor.txt` copied
    /// unchecked into the backup surfaces years later at recovery, when the coins cannot
    /// be located. finalize does not READ these siblings, so it must still succeed and
    /// still write the verified values.
    #[test]
    fn the_backup_is_regenerated_from_verified_state_not_copied_from_siblings() {
        let ceremony = ceremony_through_endorse(5, 3);
        let state = ceremony.state();
        for name in ["descriptor.txt", "wallet-id.txt", "manifest-hash.txt"] {
            std::fs::write(ceremony.dir.join(name), "corrupted-by-a-stray-edit\n")
                .expect("corrupt sibling");
        }
        ceremony
            .finalize()
            .expect("the siblings are not finalize inputs, so it still seals");
        for (name, expected) in [
            ("descriptor.txt", &state.descriptor),
            ("wallet-id.txt", &state.wallet_id),
            ("manifest-hash.txt", &state.manifest_hash),
        ] {
            let backed_up =
                std::fs::read_to_string(ceremony.sealed("backup").join(name)).expect("backup file");
            assert_eq!(
                backed_up.trim(),
                expected,
                "backup/{name} must be regenerated from the VERIFIED state, not copied \
                 from the corrupted sibling"
            );
        }
    }

    /// The bind port comes from the ENDORSED endpoints, never from a redundant stored
    /// field that could drift.
    ///
    /// `listen_port` is not hash-bound, so an edited copy would keep the manifest and
    /// every endorsement verifying while the emitted config pinned a port no longer
    /// matching its endpoint — and `ChannelState::build` would reject the node at
    /// startup, after the hosts were sealed. `StateNode` deliberately has no such field;
    /// injecting one (serde ignores unknown fields, so finalize still runs) and asserting
    /// the sealed config ignores it is what pins that decision against a regression that
    /// reintroduces and trusts it (Fable nsw review, verified by mutation).
    #[test]
    fn the_sealed_bind_port_comes_from_the_endorsed_endpoint_not_a_stored_field() {
        let ceremony = ceremony_through_endorse(5, 3);
        ceremony.edit_state(|state| {
            state["nodes"][0]["listen_port"] = serde_json::json!(12345);
        });
        ceremony.finalize().expect("an unknown field is ignored");
        let state = ceremony.state();
        let node = &state.nodes[0];
        let config =
            std::fs::read_to_string(ceremony.sealed(format!("node-{}.toml", node.node_id)))
                .expect("config");
        let endorsed_port =
            loopback_port(&node.endpoints, node.node_id).expect("endorsed endpoint");
        assert_ne!(endorsed_port, 12345, "the fixture's ports must not collide");
        assert!(
            config.contains(&format!("listen_port = {endorsed_port}")),
            "the config must bind the ENDORSED endpoint's port"
        );
        assert!(
            !config.contains("listen_port = 12345"),
            "a stored listen_port must never be trusted over the endorsed endpoint"
        );
    }

    /// Every finalize consistency check fires BEFORE anything is sealed. Each case
    /// edits one field of an otherwise-valid ceremony and asserts finalize refuses AND
    /// leaves no artifact behind — the whole point of catching it here rather than at
    /// node startup, after the hosts are sealed.
    #[test]
    fn finalize_refuses_an_edited_ceremony_before_sealing_anything() {
        // (label, mutation, the substring the operator must see)
        type Edit = Box<dyn Fn(&Ceremony)>;
        let cases: Vec<(&str, Edit, &str)> = vec![
            (
                "an edited descriptor",
                Box::new(|ceremony: &Ceremony| {
                    // A different but VALID on-template descriptor: it parses, so only
                    // the wallet_id recompute can catch it.
                    let other = ceremony_through_endorse(5, 3).state().descriptor;
                    ceremony.edit_state(|state| {
                        state["descriptor"] = serde_json::json!(other);
                    });
                }),
                "wallet_id",
            ),
            // (No separate "edited wallet_id" case: it terminates at the SAME production
            // branch as the edited-descriptor case above, which is strictly stronger — a
            // parsing, on-template descriptor that only the recompute can catch.)
            (
                "an edited manifest_hash",
                Box::new(|ceremony: &Ceremony| {
                    ceremony.edit_state(|state| {
                        state["manifest_hash"] =
                            serde_json::json!([0x22u8; 32].to_lower_hex_string());
                    });
                }),
                "manifest_hash",
            ),
            (
                "a manifest-bound policy cap edited after assembly",
                Box::new(|ceremony: &Ceremony| {
                    ceremony.edit_state(|state| {
                        state["policy"]["max_msg_bytes"] = serde_json::json!(4096);
                    });
                }),
                "manifest_hash",
            ),
            (
                "an endpoint edited after assembly (the bind port's only source)",
                Box::new(|ceremony: &Ceremony| {
                    ceremony.edit_state(|state| {
                        state["nodes"][0]["endpoints"] = serde_json::json!(["127.0.0.1:9999"]);
                    });
                }),
                "manifest_hash",
            ),
            (
                // Nothing downstream bounds the ceiling, and this gate runs BEFORE the
                // hash recompute, so it also refuses the re-endorsed consistent state
                // an operator reaches by pasting the recomputed hash back in.
                "a nonzero ladder ceiling edited in after assembly",
                Box::new(|ceremony: &Ceremony| {
                    ceremony.edit_state(|state| {
                        state["policy"]["escape_bump_max_fee_pct"] = serde_json::json!(1);
                    });
                }),
                "UNSUPPORTED LADDER CONFIGURATION",
            ),
            (
                "the wrong coordinator secret beside the state",
                Box::new(|ceremony: &Ceremony| {
                    // A valid key, just not the one the manifest pins — the stale/
                    // wrong-ceremony copy that would BRICK the normal path.
                    std::fs::write(
                        ceremony.dir.join("coordinator-auth.secret"),
                        format!("{}\n", keypair(0xDD).0.display_secret()),
                    )
                    .expect("write secret");
                }),
                "coordinator-auth.secret",
            ),
        ];

        for (label, edit, expected) in cases {
            let ceremony = ceremony_through_endorse(5, 3);
            edit(&ceremony);
            let error = match ceremony.finalize() {
                Err(error) => error.to_string(),
                Ok(()) => panic!("{label} must not finalize"),
            };
            assert!(
                error.contains(expected),
                "{label}: the refusal must name {expected}, got: {error}"
            );
            // Nothing sealed: the operator re-runs `assemble` against a clean state
            // rather than shipping half-written artifacts to the hosts.
            assert!(
                !ceremony.sealed("manifest.json").exists(),
                "{label}: finalize must refuse BEFORE writing the manifest"
            );
            assert!(
                !ceremony.sealed("node-0.toml").exists(),
                "{label}: finalize must refuse BEFORE writing any node config"
            );
        }
    }

    /// A missing or corrupted round-two endorsement is refused too: the manifest is
    /// only trustworthy because every node vouched for its own channel key, so
    /// finalize cannot seal a vault one host never endorsed.
    #[test]
    fn finalize_refuses_a_missing_or_forged_endorsement() {
        let ceremony = ceremony_through_endorse(5, 3);
        let missing = ceremony.dir.join("endorsement-2.txt");
        std::fs::remove_file(&missing).expect("remove endorsement");
        let error = match ceremony.finalize() {
            Err(error) => error.to_string(),
            Ok(()) => panic!("a missing endorsement must not finalize"),
        };
        assert!(
            error.contains("endorsement"),
            "the refusal must name the missing endorsement: {error}"
        );

        // A syntactically fine endorsement signed by the WRONG device is refused by
        // `verify_endorsement`, not merely a parse error.
        let ceremony = ceremony_through_endorse(5, 3);
        let state = ceremony.state();
        let wallet_id = hex32(&state.wallet_id, "wallet_id").expect("wallet_id");
        let manifest_hash = hex32(&state.manifest_hash, "manifest_hash").expect("manifest_hash");
        let victim = &state.nodes[2];
        // A device that is genuinely NOT the victim: `state.nodes` is in canonical
        // lexicographic key order while `devices` is in provisioning order, so the
        // wrong signer has to be selected by key, never by index.
        let (other_preimage, other_bundle) = ceremony
            .devices
            .iter()
            .find(|(_, bundle)| bundle.signing_pubkey != victim.signing_pubkey)
            .expect("another device exists in a 5-node federation");
        let wrong_key =
            nodekey::derive(other_preimage, &other_bundle.kdf().expect("kdf")).expect("derive");
        let forged = vault_node::channel::ceremony::endorse(
            &wrong_key,
            &wallet_id,
            &manifest_hash,
            victim.node_id,
            &victim.endpoints,
        );
        std::fs::write(
            ceremony
                .dir
                .join(format!("endorsement-{}.txt", victim.node_id)),
            format!("{forged}\n"),
        )
        .expect("write forged");
        assert!(
            ceremony.finalize().is_err(),
            "an endorsement from another device's key must not finalize"
        );
        assert!(
            !ceremony.sealed("manifest.json").exists(),
            "a forged endorsement must be caught before sealing"
        );
    }
}
