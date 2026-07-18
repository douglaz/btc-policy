//! vault-node: one federation key, one policy engine, `POST /sign`.
//!
//! Scope so far (see docs/DESIGN.md "Milestones"): PIN verification, the
//! descriptor-derived policy-core checks (input ownership, destination
//! allowlist, verified change, PSBT consistency, fee cap), user
//! partial-signature verification, the anti-replay log, and the Hold
//! (ADR-0004). Under Model B (ADR-0012) a node signs its partial(s) at INGRESS,
//! pin-independently, and the Hold delays a hot-class spend's **combine +
//! broadcast** — never its signing; a partial reaches a peer only at its
//! candidate's authorized fire event (invariant 7), while escape sweeps and
//! refresh self-spends fire at ingress. The NODES then combine and broadcast:
//! `/sign` answers accepted|refusal and structurally cannot carry a signature,
//! so the coordinator stays a pure relay that never holds a finalizable
//! transaction. Watchtower duty (ADR-0001) — a callable scan pass
//! ([`Node::watchtower_tick`]) classifies recovery-path spends and spends this
//! node never validated AND policy-ACCEPTED, of the node's own chain view, and
//! queues alerts a puller reads via `GET /events` (ADR-0002). Recognition is
//! NOT "co-signed" (in t-of-n, n−t nodes legitimately sign nothing) and NOT
//! merely "evaluated" (a spend this node REFUSED must still alert, or a theft
//! fanned to honest nodes would suppress its own alert). The classification
//! stays a deterministic callable
//! pass for tests, and in the running daemon a thin background task drives it
//! on a fixed interval ([`spawn_drivers`], V0-6b) — each node is its own
//! watchtower. Duress actions and lockdown remain v0 work (V0-4).

pub mod chain;
pub mod channel;
mod pin;
mod replay;
pub mod server;
pub mod watchtower;

pub use pin::{argon2id_duress_phc, argon2id_normal_phc};

use std::collections::HashSet;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bitcoin::hashes::{sha256, Hash};
use bitcoin::hex::FromHex;
use bitcoin::secp256k1::{ecdsa::Signature, Message, Secp256k1, SecretKey};
use bitcoin::sighash::SighashCache;
use bitcoin::{EcdsaSighashType, Psbt, PublicKey, ScriptBuf, Txid};
use miniscript::descriptor::WshInner;
use miniscript::{Descriptor, DescriptorPublicKey, Terminal};
use replay::{NonceDecision, NonceLog, ReplayLog, SignState, MAX_COORD_NONCE_BYTES};
use serde::Deserialize;
use subtle::{ConditionallySelectable, ConstantTimeEq};
use vault_proto::{
    Commitment, CommitmentInput, CommitmentOutput, CoordRequest, RefreshRequest, Refusal,
    RefusalCode, SignRequest, SignResponse, MAX_PIN_BYTES,
};

use crate::chain::{BitcoindBackend, ChainBackend};
use crate::channel::ChannelReply;
use crate::watchtower::{AlertQueue, Event};

pub type Error = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Input the node cannot decode: answered with HTTP 400, never a refusal.
#[derive(Debug)]
pub struct BadRequest(pub String);

/// The node's policy config file (TOML, written once at deploy time).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigFile {
    pub listen_port: u16,
    /// Hex-encoded 32-byte secret key. A key at rest is a deliberate
    /// first-light deviation from DESIGN.md D4/T1 (on-node key birth,
    /// in-memory wskdf-derived keys); the v0 provisioning task replaces this
    /// field. Only throwaway regtest keys ever land here.
    pub node_seckey: String,
    /// The node's own copy of the vault descriptor.
    pub descriptor: String,
    /// Allowlisted destination WALLETS as descriptors (hot + escape), never
    /// fixed addresses: an output is allowed when its script re-derives from one
    /// of these within `max_derivation_index` (DESIGN.md, "Destination
    /// allowlist"; CONTEXT.md, "Allowlist").
    pub allowlist: Vec<String>,
    /// The escape wallet's descriptor (ADR-0013 §5). Named apart from the
    /// allowlist so the node can tell an escape sweep (instant, under either PIN)
    /// from a hot-wallet spend (the Hold applies); its descriptor must ALSO appear
    /// in `allowlist` so the sweep passes the destination check.
    ///
    /// Mandatory since V0-8b: every `SpendRequest` carries a mandatory escape
    /// validated against it, so a node without one serves nothing.
    pub escape_descriptor: String,
    /// Bound on own-descriptor / allowlist derivation scans (DESIGN.md config
    /// schema, `max_derivation_index`).
    pub max_derivation_index: u32,
    pub hold_secs: u64,
    /// How long after a candidate's fire event the nodes may keep exchanging
    /// partials and combining (ADR-0013 §6; §1's combine window is
    /// `[fire_time, min(commitment_expiry, fire_time + combine_slack_secs)]`).
    /// Also the slack `EXPIRY_TOO_SHORT` demands a hot-class commitment outlive,
    /// so a spend is never accepted that could not possibly finish combining.
    #[serde(default = "default_combine_slack_secs")]
    pub combine_slack_secs: u64,
    /// Node-enforced cap on the coordinator-proposed commitment expiry: the
    /// node refuses any expiry beyond `now + max_commitment_age_secs` by its
    /// OWN clock, so a hostile coordinator cannot inflate the replay log's
    /// retention (DESIGN.md config schema; "Transaction commitment").
    pub max_commitment_age_secs: u64,
    /// Minimum time between refreshes of one coin (ADR-0013 §6, default ~30d).
    /// Well under the ~90-day refresh cadence, so legitimate refreshes never see
    /// it — but a wrench-time coordinator cannot drive repeated refreshes to burn
    /// the vault. The refresh path is pin-less and instant, so it has neither of
    /// the two things ADR-0006 leans on; this is half of what replaces them.
    #[serde(default = "default_refresh_min_interval_secs")]
    pub refresh_min_interval_secs: u64,
    /// Tight refresh-specific fee cap in sats/vB (ADR-0013 §6) — the other half.
    /// A real self-spend pays a normal feerate, never the 10% `max_fee_pct` a
    /// hot-class spend may use.
    #[serde(default = "default_refresh_max_feerate")]
    pub refresh_max_feerate: u64,
    /// The baked-at-setup policy identifier, bound into every commitment
    /// (policy is immutable, so this never changes).
    pub policy_version: u32,
    /// The two enrolled PINs as **Argon2id PHC strings**, each with its OWN salt
    /// (ADR-0012). Both are validated at startup as argon2id with valid params and
    /// DISTINCT salts (fatal config error otherwise), and the node compares a
    /// submitted pin against BOTH unconditionally in constant time
    /// ([`pin::verify_pin`]). Not SHA-256: a plain hash makes online guessing cheap,
    /// and distinct-salt argon2id is what the constant-cost duress compare rests on.
    pub pin_normal_hash: String,
    pub pin_duress_hash: String,
    /// The per-node pin-attempt budget (ADR-0013 §7): online-guessing rate limit.
    /// RAMDISK/node-lifetime, defaulted so a config that omits it still loads; the
    /// defaults are validated exactly as an explicit block is (`max_attempts`,
    /// `window_secs`, and `lockout_secs` >= 1; non-empty `backoff_schedule`).
    #[serde(default)]
    pub pin_attempt_budget: PinAttemptBudgetConfig,
    /// The coordinator's 33-byte compressed authentication pubkey: the mandatory
    /// per-vault trust root every request authenticates against (ADR-0013 §2/§4).
    /// Channel mode includes this same value in its base-manifest hash; when an
    /// `expected_manifest_hash` is provisioned, a changed key fails startup.
    /// Operationally, **rotation is a new vault** — this code has no in-place
    /// rotation mechanism (ADR-0013 §7).
    ///
    /// **Mandatory, deliberately un-defaulted**: every node is configured with
    /// exactly one coordinator, so `/sign` always enforces the coordinator-auth +
    /// freshness gate at ingress. ADR-0013 §2 states the rule unconditionally
    /// ("nodes reject any request not validly coord-signed and fresh"), and unlike
    /// `[channel]` — which §5 marks OPTIONAL — this field has no absent mode; it is
    /// required exactly as `pin_normal_hash` is. A `#[serde(default)]` would not be
    /// fail-open (the length check in [`Node::from_toml_str`] rejects the empty
    /// string an omitted field would produce), but it would move the "there is no
    /// coordinator-less node" rule out of the type and onto a guard several lines
    /// away, and it would answer a config that never mentions the field with a
    /// complaint about a malformed key instead of naming what is missing.
    pub coordinator_auth_pubkey: String,
    /// Optional chain-backend endpoint for the watchtower driver (ADR-0001,
    /// V0-6b). Absent ⇒ the daemon runs no scan task (unit tests and nodes
    /// without a reachable bitcoind still load). Present ⇒ the daemon spawns one
    /// background task scanning this bitcoind on a fixed interval.
    #[serde(default)]
    pub chain_backend: Option<ChainBackendConfig>,
    /// Optional at the parsing seam so policy-only tests can still construct the
    /// pre-channel shape. The runnable Model-B daemon requires this block: without
    /// a channel it cannot collect a quorum or broadcast, and `/sign` no longer
    /// returns a partial to let the coordinator finish instead. [`Node::load`] and
    /// [`server::serve`](crate::server::serve) therefore reject an absent channel
    /// before accepting traffic. Present ⇒ every invariant applies and `/channel`
    /// mounts.
    #[serde(default)]
    pub channel: Option<channel::ChannelConfig>,
}

/// ADR-0013 §6's default combine slack: 60 seconds is ample for a loopback (v0)
/// or Tor (v1) partial exchange among `n ≤ 15` nodes, and short enough that a
/// commitment need only outlive its Hold by a minute.
fn default_combine_slack_secs() -> u64 {
    60
}

/// ADR-0013 §6's ~30-day default refresh interval.
fn default_refresh_min_interval_secs() -> u64 {
    2_592_000
}

/// A deliberately generous sats/vB default: the refresh cap is a burn BOUND, not
/// a fee optimizer, and it only has to sit far below `max_fee_pct` (10% of a
/// vault-sized input is orders of magnitude more than this).
fn default_refresh_max_feerate() -> u64 {
    100
}

/// The per-node pin-attempt budget config (ADR-0013 §7). Every field defaults so a
/// config may omit the whole block, but the defaults are validated like any other
/// value at load ([`pin::PinBudgetConfig::validate`]).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinAttemptBudgetConfig {
    /// Wrong pins within `window_secs` that trip a lockout (default 5).
    #[serde(default = "default_max_attempts")]
    pub max_attempts: u64,
    /// Sliding window over which wrong pins accumulate (default 1h).
    #[serde(default = "default_window_secs")]
    pub window_secs: u64,
    /// Per-failure backoff sleep in seconds, indexed by the pre-failure count and
    /// clamped to the last entry (default `[0]` — no per-attempt delay; the lockout
    /// after `max_attempts` is the primary online-guessing defense). A deployment
    /// that wants a rising delay sets an explicit ramp, e.g. `[0, 1, 5, 30]` (keep a
    /// leading `0` so an honest single mistype is not penalized).
    #[serde(default = "default_backoff_schedule")]
    pub backoff_schedule: Vec<u64>,
    /// How long a lockout lasts once tripped, in seconds (default 15m).
    #[serde(default = "default_lockout_secs")]
    pub lockout_secs: u64,
}

impl Default for PinAttemptBudgetConfig {
    fn default() -> PinAttemptBudgetConfig {
        PinAttemptBudgetConfig {
            max_attempts: default_max_attempts(),
            window_secs: default_window_secs(),
            backoff_schedule: default_backoff_schedule(),
            lockout_secs: default_lockout_secs(),
        }
    }
}

fn default_max_attempts() -> u64 {
    5
}

fn default_window_secs() -> u64 {
    3_600
}

fn default_backoff_schedule() -> Vec<u64> {
    vec![0]
}

fn default_lockout_secs() -> u64 {
    900
}

/// The bitcoind JSON-RPC endpoint the watchtower driver scans, exactly what
/// [`BitcoindBackend`] needs (DESIGN.md, "Per-node chain backend").
#[derive(Debug, Deserialize)]
pub struct ChainBackendConfig {
    /// bitcoind JSON-RPC socket address, e.g. `"127.0.0.1:18443"` (loopback
    /// regtest).
    pub rpc_addr: String,
    /// base64 of `<user>:<password>` for HTTP Basic auth — the regtest cookie,
    /// base64-encoded, as the `Authorization: Basic` header carries it.
    pub auth: String,
}

/// A running node's validated state.
pub struct Node {
    pub listen_port: u16,
    seckey: SecretKey,
    pubkey: PublicKey,
    user_pubkey: PublicKey,
    witness_script: ScriptBuf,
    check_params: policy_core::CheckParams,
    /// The dual-Argon2id pin verifier (ADR-0012 constant-cost compare). Behind an
    /// `Arc<dyn ...>` so a test can inject a counting evaluator and assert exactly
    /// two evaluations run per SpendRequest; production always holds the real
    /// [`pin::Argon2Evaluator`].
    pin_evaluator: Arc<dyn pin::PinEvaluator>,
    /// The per-node attempt-budget config (ADR-0013 §7). Immutable; the mutable
    /// wrong-pin accounting lives in [`replay::SignState`] under the one `/sign`
    /// lock, so the budget check-then-update is atomic with the rest of the handler.
    pin_budget_config: pin::PinBudgetConfig,
    /// Terminal **Lockdown** (ADR-0008): once set, every spend AND refresh answers
    /// `FRAUD_SUSPECTED` for the node's lifetime. A monotonic latch (false→true,
    /// never back) with **durability EQUAL to the signing key's** (see
    /// `lockdown_flag_path`): the key lives in the tmpfs config, so it survives a
    /// process restart but dies on a machine reboot — Lockdown must match, or a
    /// bare process restart (crash-loop, supervisor respawn, OOM-kill — none need
    /// SSH) would reload the key from the surviving config yet resurrect an
    /// UNLOCKED signer. No reset on sealed nodes; a reboot is node death (tmpfs
    /// wiped → key AND flag gone), strictly stronger. V0-4a builds the state, the
    /// refusal, and the [`Node::enter_lockdown`] entry point; V0-4b drives WHEN it
    /// is entered (at T under duress).
    lockdown: AtomicBool,
    /// A PRE-OPENED handle to the RAMDISK Lockdown latch file, so the latch has the
    /// SAME durability as `node_seckey` (both on tmpfs; both die on reboot, both
    /// survive a process restart). Opened once by [`Node::load`] at startup — BEFORE
    /// the server accepts any connection — and held for the node's lifetime, so
    /// [`Node::enter_lockdown`] persists at `T` via `write_at` on this existing
    /// descriptor and needs NO fresh fd: an attacker cannot exhaust the fd table
    /// (EMFILE) to make the lockdown write fail and then restart into an unlocked
    /// signer. **Content, not existence, means locked** (a fresh boot's file is
    /// empty; enter_lockdown writes a marker) — so an empty file created at open time
    /// is not mistaken for a latch. `None` for a path-less [`Node::from_toml_str`]
    /// (pure in-RAM, unit tests only). This is NOT a durable at-rest "duress was
    /// detected" artifact (ADR-0008 bars those): a tmpfs file is wiped by the same
    /// reboot that wipes the key, so it never survives to a bare machine.
    lockdown_flag_file: Option<std::fs::File>,
    /// The duress arm-hook seam (ADR-0012 "internal fire bit"): incremented whenever
    /// a valid DURESS pin is seen — even when the node is locked out (fail-closed).
    /// V0-4a exposes only this counter (invisible on the wire, so it does not break
    /// pin-independent ingress); V0-4b builds the arm/freeze/sweep state machine on
    /// this same seam.
    duress_arm: AtomicU64,
    /// The coordinator authentication pubkey this node is sealed to (ADR-0013
    /// §2): every `/sign` request must be validly coord-signed, carry a fresh
    /// nonce, and fall inside the expiry window before the PIN is even consulted.
    /// Not optional — a node is always configured with exactly one coordinator.
    /// Channel mode includes this value in its manifest hash, and a provisioned
    /// `expected_manifest_hash` seals that hash at startup. The specified key
    /// lifecycle treats a change as a new vault rather than in-place rotation
    /// (§4/§7).
    coordinator_auth: PublicKey,
    /// Hash of this node's descriptor: the `wallet_id` bound into every
    /// commitment.
    wallet_id: [u8; 32],
    policy_version: u32,
    max_commitment_age_secs: u64,
    /// The Hold for hot-class spends (ADR-0004, as reworked by ADR-0012's Model-B
    /// Hold lifecycle): the node signs its partial at INGRESS and the Hold delays
    /// **combine + broadcast**, not signing. `0` fires on first submission (first
    /// light; keeps the demo one-shot).
    hold_secs: u64,
    /// The combine window's slack past a fire event (ADR-0013 §6).
    combine_slack_secs: u64,
    /// `t` — the federation threshold from the descriptor's `multi(t, …)`. A
    /// candidate combines once EVERY input carries `t` distinct valid partials.
    threshold: usize,
    /// ADR-0013 §6 refresh bounds. The refresh path is pin-less and instant, so
    /// these are its only burn defense.
    refresh_min_interval_secs: u64,
    refresh_max_feerate: u64,
    /// The `/sign` handler's replay log AND Hold-timer pending log under ONE
    /// lock (see [`replay::SignState`]). `/sign` is serialized BY DESIGN: the
    /// axum migration buys ISOLATION of `/sign` from `/events` (and, in V0-8a,
    /// `/channel`) — those keep their own locks below — NOT sign-vs-sign
    /// throughput. Two `/sign` requests still run one-at-a-time: the whole
    /// `handle_sign` call runs under this lock, so the check-then-update
    /// sequences over the two logs never interleave, exactly as the old
    /// sequential serve loop guaranteed. Splitting these into two locks is
    /// FORBIDDEN — interleaved check/update between two concurrent identical
    /// requests would corrupt replay semantics.
    sign_state: Mutex<SignState>,
    /// **The validated-AND-policy-ACCEPTED transaction set** (ADR-0012's
    /// watchtower recognition rule, and V0-8b's vault-authorized set). Holds the
    /// txid of every transaction this node validated and would authorize — the
    /// spend AND the escape of each accepted request — recorded at ingress when
    /// the node accepts, NEVER when it refuses.
    ///
    /// It replaces V0-6's co-signed set, which was the wrong criterion twice over:
    ///
    /// - **too narrow** for recognition: in a `t`-of-`n`, `n−t` nodes legitimately
    ///   never sign a given spend, so "I didn't sign it" false-alarms on honest
    ///   traffic;
    /// - **too broad** if relaxed to "I evaluated it": a spend a node policy-
    ///   REFUSED was evaluated, so a theft deliberately fanned out to honest nodes
    ///   would count as recognized and suppress its own alert. Acceptance is the
    ///   line — a refused theft is not in this set, so it alerts.
    ///
    /// Segwit txids exclude the witness and SIGHASH_ALL binds the witness to the
    /// exact transaction, so the unsigned tx's txid IS the txid it will confirm
    /// under; recording it at ingress is sound.
    ///
    /// The same set answers "may this spend chain off that unconfirmed parent?"
    /// (ADR-0012 build-over-mempool): a parent in here is vault-authorized and
    /// cannot be replaced without `t`-of-`n`; anything else is an external
    /// unconfirmed deposit and is excluded. Shared behind its own `Mutex` (not the
    /// per-`/sign` `SignState` lock): `/sign` writes it while the watchtower and
    /// fire drivers read it.
    authorized: Arc<Mutex<HashSet<Txid>>>,
    /// Queued watchtower alerts, pulled by the coordinator via `GET /events`
    /// (ADR-0002). Bounded, in-memory (DESIGN.md). Shared behind a `Mutex`: the
    /// background watchtower task writes it and `/events` reads it (V0-6b).
    alerts: Arc<Mutex<AlertQueue>>,
    /// Parsed chain-backend endpoint (rpc socket + base64 auth) for the
    /// watchtower driver, if configured. `None` ⇒ no scan task. Held so the
    /// daemon can build the backend and spawn the driver after load
    /// ([`spawn_drivers`]).
    chain_backend: Option<(SocketAddr, String)>,
    /// The node-to-node channel runtime (V0-8a), built from the sealed manifest
    /// when `[channel]` is present. `None` ⇒ absent-channel mode: `/channel` is
    /// not mounted and no channel invariant runs. Read by the `/channel` route and
    /// the `/sign`-path candidate-registry funnel.
    pub(crate) channel: Option<channel::ChannelState>,
    /// Requests this node has ACCEPTED and owes every peer (§3 propagation).
    ///
    /// A staging area, not a queue with semantics: `/sign` runs under the one
    /// `SignState` lock and must never do network I/O there, so it drops the
    /// accepted request here and the async pump ([`propagate_outbox`]) drains it
    /// once the lock is released.
    outbox: Mutex<Vec<vault_proto::TaggedRequest>>,
}

impl Node {
    pub fn load(path: &str) -> Result<Node, Error> {
        let raw =
            std::fs::read_to_string(path).map_err(|e| format!("cannot read config {path}: {e}"))?;
        let mut node = Node::from_toml_str(&raw)?;
        node.require_channel_mode()?;
        node.apply_persisted_lockdown(path)?;
        Ok(node)
    }

    /// Bind this node to its RAMDISK Lockdown flag and adopt any latch that survived
    /// into this process. Lockdown durability = signing-key durability: the key was
    /// just reloaded from the tmpfs config, so if the sibling flag ALSO survived
    /// (a process restart, not a machine reboot — a reboot wipes both) the node comes
    /// back TERMINALLY LOCKED. Without this, a bare process restart against the
    /// surviving config would resurrect an unlocked signer.
    fn apply_persisted_lockdown(&mut self, config_path: &str) -> Result<(), Error> {
        use std::io::Read;
        let flag_path = Node::lockdown_flag_path_for(config_path);
        // Pre-open (create if absent) the latch file ONCE, here at startup — before
        // the server serves any connection — and hold the descriptor for life. This
        // both (a) proves at startup that a future Lockdown CAN be persisted (open
        // fails → refuse to start, fail-closed: a node that cannot lock itself down
        // does not run) and (b) reserves the fd so `enter_lockdown` writes at `T`
        // WITHOUT allocating a new one — closing the EMFILE bypass (exhaust the fd
        // table before T so the lockdown write fails, then restart to release the
        // fds and come up unlocked). Not O_TRUNC: an existing latch keeps its marker.
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&flag_path)
            .map_err(|e| {
                format!(
                    "cannot open the RAMDISK Lockdown latch {} ({e}); refusing to start \
                     rather than run unable to lock down / unable to read a prior latch",
                    flag_path.display()
                )
            })?;
        // Content — not existence — means locked: a fresh boot's file is empty, and
        // a machine reboot wipes the file with the tmpfs anyway. Any non-empty
        // content is a persisted latch (robust even to a torn/partial marker write:
        // non-empty ⇒ locked, fail-closed).
        let mut marker = Vec::new();
        file.read_to_end(&mut marker).map_err(|e| {
            format!(
                "cannot read the Lockdown latch {}: {e}",
                flag_path.display()
            )
        })?;
        if !marker.is_empty() {
            self.lockdown.store(true, Ordering::Release);
        }
        self.lockdown_flag_file = Some(file);
        Ok(())
    }

    /// The RAMDISK Lockdown flag path for a config at `config_path`: a sibling file
    /// named after the config, so it is unique per node even when several nodes'
    /// configs share one tmpfs directory (e.g. the demo's five nodes).
    fn lockdown_flag_path_for(config_path: &str) -> std::path::PathBuf {
        std::path::PathBuf::from(format!("{config_path}.lockdown"))
    }

    pub fn from_toml_str(raw: &str) -> Result<Node, Error> {
        let config: ConfigFile = toml::from_str(raw).map_err(|e| format!("bad config: {e}"))?;
        let secp = Secp256k1::new();
        let seckey = SecretKey::from_str(&config.node_seckey)
            .map_err(|e| format!("bad node_seckey: {e}"))?;
        let pubkey = PublicKey::new(seckey.public_key(&secp));
        // The coordinator authentication pubkey this vault is configured with
        // (ADR-0013 §2). Parsed once here; it arms the `/sign` coord-auth gate and
        // is folded into the channel manifest hash below. Mandatory: a node with no pinned
        // coordinator could authenticate nothing, so an unparseable — or, via
        // serde, an absent — key is a fatal config error, never a silent no-gate.
        if config.coordinator_auth_pubkey.len() != 66 {
            return Err(
                "bad coordinator_auth_pubkey: expected a 33-byte compressed secp256k1 public key"
                    .into(),
            );
        }
        let coordinator_auth = PublicKey::from_str(&config.coordinator_auth_pubkey)
            .map_err(|e| format!("bad coordinator_auth_pubkey: {e}"))?;
        // The vault descriptor is parsed twice, on purpose: as concrete
        // `PublicKey` for the witness script + user-key extraction + sighash
        // (the first-light vault is definite), and as `DescriptorPublicKey` for
        // the bounded re-derivation primitive (input ownership + verified
        // change). Both parses are of the same string, so they cannot disagree.
        let descriptor = Descriptor::<PublicKey>::from_str(&config.descriptor)
            .map_err(|e| format!("bad descriptor: {e}"))?;
        let vault = Descriptor::<DescriptorPublicKey>::from_str(&config.descriptor)
            .map_err(|e| format!("bad descriptor: {e}"))?;
        let user_pubkey = first_light_user_key_of(&descriptor)?;
        // The federation: `t` (the combine threshold) and the node keys (for the
        // channel manifest's node_id ↔ descriptor-key bijection, §1). Both read
        // from the descriptor while the concrete parse is in scope.
        let (threshold, node_keys) = first_light_federation_of(&descriptor)?;
        // The coordinator is a DISTINCT role from the two the descriptor names:
        // its key authorizes *requests*, the user key authorizes *spends*, and the
        // federation keys *sign* them. Reusing one key across two roles silently
        // voids that separation — whoever holds that role's secret could then mint
        // coordinator-authenticated requests, which is precisely what this trust
        // root exists to prevent (a compromised node must not be able to
        // manufacture coordinator requests, ADR-0013 §2/§4). The collapse is
        // invisible at runtime: every gate still passes, so nothing else would
        // ever report it. No deployment needs the reuse — one human may hold two
        // roles, but a second keypair is free — so a collision is a fatal
        // provisioning error, caught here with the config's other cross-field
        // invariants rather than trusted to the setup ceremony.
        //
        // All three checks below compare the curve point (`.inner`), never
        // `bitcoin::PublicKey`, which also compares its compressed-encoding flag:
        // roles are identities on the curve, and an encoding must not disguise
        // reuse. No key reaching these checks can currently be uncompressed — the
        // length check above pins the coordinator key to 33 bytes, and `wsh()`
        // rejects uncompressed keys when the descriptor parses — so this is one
        // rule stated once for all three, not a live gap in any of them.
        if coordinator_auth.inner == user_pubkey.inner {
            return Err(
                "coordinator_auth_pubkey must not be the descriptor's user key: the coordinator \
                 authorizes requests and the user authorizes spends, so one key for both lets the \
                 user key mint its own coordinator requests"
                    .into(),
            );
        }
        if node_keys
            .iter()
            .any(|key| key.inner == coordinator_auth.inner)
        {
            return Err(
                "coordinator_auth_pubkey must not be one of the descriptor's federation node \
                 keys: one key for both roles lets a single compromised node mint coordinator \
                 requests to its peers"
                    .into(),
            );
        }
        // The channel identity is not a fourth independent key: `derive_channel_seckey`
        // is a deterministic, publicly-known function of the federation seckey, so
        // holding a node's signing key IS holding its channel key. A coordinator key
        // equal to a channel pubkey therefore collapses the same two roles the check
        // above rejects — it just spells the node's key differently. `ChannelState::build`
        // catches this for every node in the manifest, but only `[channel]` mode has a
        // manifest, so without this an absent-channel node accepts the collapse.
        // A node holds only its OWN seckey, so its own derived key is the only one it
        // can check here — which makes this a tripwire, not the complete check. The
        // reused node always refuses to boot (every node is provisioned with the same
        // vault-wide coordinator key), but the other n−1 cannot detect the collapse and
        // a quorum survives one dead node, so an operator who ignores the dead node
        // keeps a federation that honors requests minted by its key holder. The residual
        // is bounded — coordinator auth is one gate, and the user signature and PIN
        // still gate signing — and `[channel]` mode's `ChannelState::build` is the
        // complete check, because only it has the manifest to check peers against.
        if channel::channel_pubkey_of(&channel::derive_channel_seckey(&seckey)).inner
            == coordinator_auth.inner
        {
            return Err(
                "coordinator_auth_pubkey must not be this node's derived channel key: the \
                 channel key is derived from the node's federation seckey, so one key for both \
                 roles lets this node mint coordinator requests for the whole vault"
                    .into(),
            );
        }
        let witness_script = descriptor
            .explicit_script()
            .map_err(|e| format!("descriptor has no witness script: {e}"))?;
        // wallet_id binds a commitment to this vault. Hash the descriptor's
        // canonical string (checksum included) so coordinator and node — which
        // parse the same descriptor — derive the same id.
        let wallet_id = sha256::Hash::hash(descriptor.to_string().as_bytes()).to_byte_array();
        let mut allowed = Vec::new();
        for entry in &config.allowlist {
            let descriptor = Descriptor::<DescriptorPublicKey>::from_str(entry)
                .map_err(|e| format!("bad allowlist descriptor {entry}: {e}"))?;
            allowed.push(descriptor);
        }
        let escape_descriptor =
            Descriptor::<DescriptorPublicKey>::from_str(&config.escape_descriptor)
                .map_err(|e| format!("bad escape_descriptor: {e}"))?;
        if config.hold_secs >= config.max_commitment_age_secs {
            return Err(format!(
                "max_commitment_age_secs ({}) must exceed hold_secs ({})",
                config.max_commitment_age_secs, config.hold_secs
            )
            .into());
        }
        // A zero-width combine window `[fire, fire]` is a silent broadcast trap: the
        // fan-out never *initiates* a send once `now >= deadline` (see
        // `try_endpoints`), so with `combine_slack_secs = 0` no partial ever leaves
        // any node after its fire event, no candidate reaches quorum, and every
        // accepted spend signs at ingress then silently never broadcasts — the exact
        // invisible failure the `[chain_backend]` fatal below also guards. Reject it
        // at load rather than at "the money never moved".
        if config.combine_slack_secs == 0 {
            return Err(
                "combine_slack_secs must be greater than 0: a zero-width combine window \
                 [fire, fire] lets no node transmit a partial after the fire event, so every \
                 accepted spend would sign at ingress and then silently fail to broadcast"
                    .into(),
            );
        }
        // A zero refresh interval disables ADR-0013 §6's per-coin burn-rate
        // bound: every mark is pruned immediately and `elapsed < interval` can
        // never refuse. Unlike `duress_delay_secs`, zero has no useful meaning
        // here, so fail at provisioning rather than silently accepting an
        // unbounded refresh chain.
        if config.refresh_min_interval_secs == 0 {
            return Err(
                "refresh_min_interval_secs must be greater than 0: zero disables the per-coin \
                 refresh burn-rate bound"
                    .into(),
            );
        }
        // The EXPIRY_TOO_SHORT floor a hot spend must clear is `now + hold_secs +
        // combine_slack_secs`, while the node caps every accepted expiry at `now +
        // max_commitment_age_secs`. If the floor exceeds the cap, NO hot-class spend
        // can ever be accepted — a silent refuse-everything. Reject at load. (`==`
        // is allowed: the sole acceptable expiry is then exactly the cap, and
        // EXPIRY_TOO_SHORT accepts equality.)
        if config.hold_secs.saturating_add(config.combine_slack_secs)
            > config.max_commitment_age_secs
        {
            return Err(format!(
                "hold_secs ({}) + combine_slack_secs ({}) must not exceed \
                 max_commitment_age_secs ({}): the EXPIRY_TOO_SHORT floor would sit past the \
                 node's own expiry cap, so every hot-class spend would be refused",
                config.hold_secs, config.combine_slack_secs, config.max_commitment_age_secs
            )
            .into());
        }
        // Descriptor membership: the escape wallet must be an allowlist entry
        // so its sweep passes the destination check (canonical-string equality
        // covers checksum/format normalization).
        let escape_canonical = escape_descriptor.to_string();
        if !allowed.iter().any(|d| d.to_string() == escape_canonical) {
            return Err("escape_descriptor must also be present in allowlist".into());
        }
        // Both enrolled PINs must be Argon2id PHC strings with valid params and
        // DISTINCT salts (ADR-0012). Validated here so a placeholder SHA-256, a
        // non-argon2id KDF, or a copy-pasted shared salt is a fatal provisioning
        // error, never a silently-weakened compare at the wrench.
        pin::validate_digests(&config.pin_normal_hash, &config.pin_duress_hash)?;
        // The pin-attempt budget config (ADR-0013 §7): reject undefined table
        // indices and zero durations that silently disable accumulation/lockout.
        let pin_budget_config = pin::PinBudgetConfig {
            max_attempts: config.pin_attempt_budget.max_attempts,
            window_secs: config.pin_attempt_budget.window_secs,
            backoff_schedule: config.pin_attempt_budget.backoff_schedule.clone(),
            lockout_secs: config.pin_attempt_budget.lockout_secs,
        };
        pin_budget_config.validate()?;
        let pin_budget = pin::AttemptBudget::new(pin_budget_config.max_attempts)?;
        // The pin digests are stored (owned) inside the evaluator, re-parsed per
        // request. NOT lowercased: a PHC string's base64 salt/hash is case-sensitive,
        // so the old `.to_lowercase()` would corrupt it.
        let pin_evaluator: Arc<dyn pin::PinEvaluator> = Arc::new(pin::Argon2Evaluator::new(
            config.pin_normal_hash.clone(),
            config.pin_duress_hash.clone(),
        ));
        // Parse the optional watchtower endpoint now so a bad address fails at
        // load, not silently at the first scan.
        let chain_backend = config
            .chain_backend
            .as_ref()
            .map(|cb| {
                SocketAddr::from_str(&cb.rpc_addr)
                    .map(|addr| (addr, cb.auth.clone()))
                    .map_err(|e| format!("bad chain_backend.rpc_addr {:?}: {e}", cb.rpc_addr))
            })
            .transpose()?;
        // Channel mode is what makes this node responsible for BROADCASTING (§5):
        // it collects peers' partials, combines at fire, package-validates, and
        // pushes the transaction itself. With no chain backend it can do none of
        // that — it would authenticate requests, sign at ingress, exchange
        // partials, reach quorum, and then silently never broadcast, while every
        // `/sign` answer told the coordinator the spend was accepted. That failure
        // is invisible until the user notices the money never moved, so it is a
        // fatal provisioning error here rather than a runtime surprise.
        if config.channel.is_some() && chain_backend.is_none() {
            return Err(
                "[channel] mode requires a [chain_backend]: the nodes combine and broadcast \
                 (ADR-0012 Model B), so a node with no chain view of its own could accept and \
                 sign a spend it can never broadcast"
                    .into(),
            );
        }
        // The alert queue is shared with the channel so freshness-reject events
        // surface through the same `GET /events` path (codex I2).
        let alerts = Arc::new(Mutex::new(AlertQueue::new(watchtower::DEFAULT_ALERT_CAP)));
        // Build the channel runtime iff `[channel]` is present. Every §2 startup
        // invariant runs inside `build`; a failure is a fatal config error here,
        // never a runtime refusal.
        let channel = config
            .channel
            .as_ref()
            .map(|cfg| {
                channel::ChannelState::build(
                    cfg,
                    &seckey,
                    pubkey,
                    wallet_id,
                    &node_keys,
                    config.listen_port,
                    // The coordinator key is part of the hashed manifest (ADR-0013
                    // §4), so the node's manifest_hash binds the vault's one
                    // coordinator: a different key is a different vault (§7).
                    coordinator_auth,
                    Arc::clone(&alerts),
                )
            })
            .transpose()?;
        let sign_state = SignState {
            pin_budget,
            ..SignState::default()
        };
        Ok(Node {
            listen_port: config.listen_port,
            seckey,
            pubkey,
            user_pubkey,
            witness_script,
            check_params: policy_core::CheckParams {
                vault,
                allowed,
                // policy-core keeps this optional (a library contract: with no
                // escape configured nothing is escape-class). A node always has
                // one — the config above made it mandatory.
                escape: Some(escape_descriptor),
                max_derivation_index: config.max_derivation_index,
            },
            pin_evaluator,
            pin_budget_config,
            lockdown: AtomicBool::new(false),
            // Path-less construction (unit tests): no persistence. `Node::load`
            // pre-opens the flag file and reads the latch so a real deployment's
            // Lockdown survives a process restart (durability = key durability).
            lockdown_flag_file: None,
            duress_arm: AtomicU64::new(0),
            coordinator_auth,
            wallet_id,
            policy_version: config.policy_version,
            max_commitment_age_secs: config.max_commitment_age_secs,
            hold_secs: config.hold_secs,
            combine_slack_secs: config.combine_slack_secs,
            threshold,
            refresh_min_interval_secs: config.refresh_min_interval_secs,
            refresh_max_feerate: config.refresh_max_feerate,
            sign_state: Mutex::new(sign_state),
            authorized: Arc::new(Mutex::new(HashSet::new())),
            alerts,
            chain_backend,
            channel,
            outbox: Mutex::new(Vec::new()),
        })
    }

    /// The vault's own watched scriptPubKey(s) for the watchtower scan
    /// (ADR-0001). The first-light vault is a single definite P2WSH, so this is
    /// one script — the P2WSH of the node's witness script.
    pub fn vault_scripts(&self) -> Vec<ScriptBuf> {
        vec![ScriptBuf::new_p2wsh(&self.witness_script.wscript_hash())]
    }

    /// Run one watchtower scan pass (ADR-0001) against `backend`, classifying
    /// every spend of the vault's watched scripts at or after `from_height` and
    /// queueing new alerts. Returns how many NEW alerts were queued (a re-scan of
    /// an already-alerted spend queues nothing).
    ///
    /// This is the SAME pass the daemon's background driver runs — both go
    /// through [`watchtower::scan_pass`] over this node's shared authorized set
    /// and alert queue — so tests and production exercise one code path. The
    /// recovery-branch script set is empty in v0 (the first-light vault has no
    /// recovery branch), so this pass emits only `UnrecognizedSpend`;
    /// `RecoveryPathSpend` classification lives in [`watchtower::scan`] and is
    /// tested there.
    pub fn watchtower_tick(
        &self,
        backend: &dyn ChainBackend,
        from_height: u32,
    ) -> Result<usize, Error> {
        watchtower::scan_pass(
            backend,
            &self.vault_scripts(),
            &self.authorized,
            &self.alerts,
            from_height,
        )
        .map(|outcome| outcome.new_alerts)
    }

    /// The queued events after cursor `since`, plus the new cursor (the `GET
    /// /events` pull API; ADR-0002). No loss, no duplication across successive
    /// pulls. Carries watchtower alerts and — under `[channel]` — channel
    /// freshness-reject events, both through the one queue (codex I2).
    pub fn events(&self, since: u64) -> (Vec<Event>, u64) {
        self.alerts
            .lock()
            .expect("alerts lock poisoned")
            .since(since)
    }

    /// This node's own chain backend, when one is configured.
    fn backend(&self) -> Option<Arc<dyn ChainBackend + Send + Sync>> {
        let (addr, auth) = self.chain_backend.clone()?;
        Some(Arc::new(BitcoindBackend::new(addr, auth)))
    }

    /// Model B has no channel-less completion path: `/sign` structurally withholds
    /// the node partial, so only the node channel can collect `t` partials and let a
    /// node broadcast. Keep the parser usable by deterministic policy tests, but
    /// fail every runnable daemon before it can acknowledge an unfinishable spend.
    pub(crate) fn require_channel_mode(&self) -> Result<(), Error> {
        if self.channel.is_none() {
            return Err(
                "[channel] is required for the Model-B node daemon: /sign withholds partials, so \
                 a channel-less node cannot collect a quorum or broadcast"
                    .into(),
            );
        }
        Ok(())
    }

    /// Enter the terminal **Lockdown** state (ADR-0008). The entry point V0-4b calls
    /// at `T` under duress; V0-4a exposes it so the state + `FRAUD_SUSPECTED` refusal
    /// can be built and tested in isolation. Monotonic: once entered there is no
    /// programmatic exit (RAMDISK, no reset on sealed nodes — the only exit is the
    /// recovery path, and a reboot is node death, strictly stronger).
    ///
    /// The flag is set while holding `sign_state` so the transition LINEARIZES with
    /// in-flight `/sign` and `/refresh` handlers, which re-check `is_locked_down`
    /// under that same lock: a request either commits fully BEFORE this store (it
    /// began pre-Lockdown) or observes the flag and refuses — none registers a new
    /// candidate AFTER Lockdown. Because it acquires `sign_state`, it MUST NOT be
    /// called while that lock is already held.
    pub fn enter_lockdown(&self) {
        let _guard = self.sign_state.lock().expect("sign_state lock poisoned");
        // Persist the latch to tmpfs BEFORE flipping the in-RAM flag, so a crash or
        // OOM-kill after this point restarts LOCKED (fail-closed): once the marker is
        // on disk the next process reads it, and the only remaining window — a crash
        // between the write and the store below — still leaves the marker on disk,
        // i.e. still locked. The write goes through the descriptor pre-opened at
        // startup (see `lockdown_flag_file`), so it allocates NO new fd and cannot be
        // blocked by fd-table exhaustion (EMFILE). Durability = key durability.
        if let Some(file) = &self.lockdown_flag_file {
            use std::os::unix::fs::FileExt;
            if let Err(e) = file
                .write_all_at(b"locked\n", 0)
                .and_then(|()| file.sync_all())
            {
                // Only ENOSPC-class failure remains (the RAM is full); irreducible
                // (you cannot write to full storage) and self-limiting — such a node
                // is failing and a reboot is node death = safe. This process still
                // locks via the store below; logged loudly, never panicked (a panic
                // would exit into an unlocked respawn, strictly worse).
                eprintln!(
                    "enter_lockdown: WARNING could not persist RAMDISK lockdown latch: {e} \
                     (this process stays locked; a restart before reboot may not)"
                );
            }
        }
        self.lockdown.store(true, Ordering::Release);
    }

    /// Whether this node is in Lockdown. Read at the top of every spend/refresh (a
    /// lock-free fast path) AND re-checked under `sign_state` inside the handler, so
    /// a locked-down node answers `FRAUD_SUSPECTED` and does nothing else.
    pub fn is_locked_down(&self) -> bool {
        self.lockdown.load(Ordering::Acquire)
    }

    /// Fire the duress arm-hook (the ADR-0012 "internal fire bit"). V0-4a only
    /// counts firings — the observable seam V0-4b's arm/freeze/sweep machine hangs
    /// off. Invisible on the wire, so it does not break pin-independent ingress.
    ///
    /// Runs on EVERY SpendRequest with a constant-time-selected delta (1 for a
    /// duress verdict, 0 for normal/wrong) rather than behind an `if verdict ==
    /// Duress` branch: that keeps the arm-hook the SAME observable work for normal
    /// and duress — the last verdict-dependent step on the ingress hot path — so the
    /// constant-shape story (both Argon2 always run, budget touch is uniform) has no
    /// remaining seam. The COUNT is still +1 only for duress, so the fail-closed test
    /// reads exactly the duress arms.
    fn fire_arm_hook(&self, verdict: pin::PinVerdict) {
        let armed = (verdict as u8).ct_eq(&(pin::PinVerdict::Duress as u8));
        let delta = u64::conditional_select(&0, &1, armed);
        self.duress_arm.fetch_add(delta, Ordering::Relaxed);
    }

    /// How many times the duress arm-hook has fired (test-only observable for the
    /// fail-closed test: a valid duress pin arms even while the node is locked out).
    #[cfg(test)]
    pub(crate) fn duress_arm_count(&self) -> u64 {
        self.duress_arm.load(Ordering::Relaxed)
    }

    /// Swap in a test evaluator (e.g. a counting one) to assert the constant-cost
    /// invariant structurally.
    #[cfg(test)]
    pub(crate) fn set_pin_evaluator(&mut self, evaluator: Arc<dyn pin::PinEvaluator>) {
        self.pin_evaluator = evaluator;
    }

    /// The current pin evaluator, so a test can wrap it in a counting evaluator.
    #[cfg(test)]
    pub(crate) fn pin_evaluator(&self) -> Arc<dyn pin::PinEvaluator> {
        Arc::clone(&self.pin_evaluator)
    }
}

/// Spawn the node's background drivers, from within the tokio runtime, once after
/// [`Node::load`]:
///
///  - the **watchtower** (ADR-0001, V0-6b): scans this node's own chain view on an
///    interval, alerting on any vault spend it never validated-and-accepted;
///  - the **fire driver** (§1): releases partials at each candidate's authorized
///    fire event, then combines + broadcasts once quorum arrives.
///
/// Both need a chain backend, so both are no-ops without one — which channel mode
/// makes a fatal config error, precisely so a node that must broadcast cannot boot
/// unable to (see [`Node::from_toml_str`]). Unit tests build backend-less nodes
/// and start no tasks.
pub fn spawn_drivers(node: &Arc<Node>) {
    let Some(backend) = node.backend() else {
        return;
    };
    watchtower::spawn_driver(
        Arc::clone(&backend),
        node.vault_scripts(),
        Arc::clone(&node.authorized),
        Arc::clone(&node.alerts),
    );
    // Absent-channel mode has no candidate registry, so nothing can ever fire.
    if node.channel.is_none() {
        return;
    }
    let node = Arc::clone(node);
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(FIRE_INTERVAL);
        loop {
            ticker.tick().await;
            fire_tick_with_clock(
                Arc::clone(&node),
                Arc::clone(&backend),
                unix_now(),
                unix_now,
            )
            .await;
            // Schedule from pass completion, like the watchtower driver.
            ticker.reset();
        }
    });
}

/// Unix seconds by this node's own clock; before-epoch reads 0, which fails safe
/// (every real commitment then reads as expired).
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Interval between fire passes in the daemon driver. A `const`, not a config
/// knob: it is scheduling resolution, not policy. One second keeps the demo
/// snappy and costs nothing — a pass over an empty registry is a lock and a scan.
pub const FIRE_INTERVAL: Duration = Duration::from_secs(1);

/// One fire pass (§1) — the Model-B spend path's engine.
///
/// For every candidate whose authorized fire event has arrived and whose combine
/// window is still open:
///
///  1. **release** this node's own partials to every peer, once, through the
///     partial-release gate (ADR-0012 invariant 7) — the fan-out is spawned, not
///     awaited, so a dead peer's bounded retry never stalls the pass;
///  2. **combine + broadcast** as soon as ≥ `t` distinct valid signatures are
///     present on EVERY input, gated on package mempool-acceptance.
///
/// Release and combine are separate steps across ticks by nature: this node
/// releases on the first due tick and a later tick finds the peers' partials that
/// crossed in the meantime. Returns how many transactions this pass broadcast.
pub async fn fire_tick(
    node: Arc<Node>,
    backend: Arc<dyn ChainBackend + Send + Sync>,
    now: u64,
) -> usize {
    // Deterministic seam for direct tests. The daemon calls
    // `fire_tick_with_clock(..., unix_now)` above so blocking backend work never
    // reuses this pass-start timestamp for its final authorization check.
    fire_tick_with_clock(node, backend, now, move || now).await
}

async fn fire_tick_with_clock(
    node: Arc<Node>,
    backend: Arc<dyn ChainBackend + Send + Sync>,
    due_now: u64,
    clock: impl Fn() -> u64 + Send + 'static,
) -> usize {
    let Some(channel) = node.channel.as_ref() else {
        return 0;
    };
    channel.prune_store(due_now);
    let mut due = channel.due_for_fire(due_now);
    // A peer can settle near the end of the combine window while this node lacks
    // quorum or is delayed in backend work. Once the window closes it is too late
    // to release or broadcast, but not too late to observe settlement and clear a
    // hot spend's refresh-subordination entry. Add only live pending hot spends
    // still inside the bounded settlement-observation window (`fire_settlement_pollable`);
    // the channel gates below still keep their partials and finalization closed
    // outside the authorized window. The bound matters: without it a candidate
    // that missed its window would be re-polled at 1 Hz — two settlement RPCs each
    // pass — until commitment expiry (up to `max_commitment_age_secs`), needlessly
    // loading the backend and, under a post-outage backlog, risking a fresh
    // quorum-ready candidate's window on the same serial pass. Past the grace no
    // peer's combine window is still open, so the pending Hold instead lifts on its
    // commitment-expiry prune backstop.
    let pending = node
        .sign_state
        .lock()
        .expect("sign_state lock poisoned")
        .pending
        .ids(due_now);
    due.extend(
        pending
            .into_iter()
            .filter(|commitment_id| channel.fire_settlement_pollable(commitment_id, due_now)),
    );
    due.sort();
    due.dedup();
    if due.is_empty() {
        return 0;
    }
    for commitment_id in &due {
        // THE GATE. `release_partials` returns `None` unless this candidate's
        // fire event has arrived — so a Hold-bound spend, and every unscheduled
        // escape, silently produce nothing here.
        if let Some(release) = channel.release_partials(commitment_id, due_now) {
            spawn_fan_out(&node, release.outbound());
        }
    }
    // Combining calls the chain backend (blocking JSON-RPC), so it runs off the
    // runtime exactly as the watchtower pass does.
    let combine_node = Arc::clone(&node);
    match tokio::task::spawn_blocking(move || {
        combine_and_broadcast_with_clock(&combine_node, backend.as_ref(), &due, clock)
    })
    .await
    {
        Ok(count) => count,
        Err(join_error) => {
            eprintln!("fire: combine task panicked: {join_error}");
            0
        }
    }
}

/// Combine + broadcast every due candidate that has reached quorum. Synchronous
/// (the chain backend is blocking) and driven by `now`, so tests call it directly
/// with a mock backend and no runtime. Returns the number this node broadcast.
///
/// `try_finalize` reads the `broadcast` flag under the store lock, releases it,
/// broadcasts lock-free, then `mark_broadcast` re-takes the lock. That is safe
/// only because the daemon runs exactly one fire task ([`spawn_drivers`]) that
/// `await`s each pass to completion, so no two combine passes for one candidate
/// ever overlap; a second concurrent driver would need those three steps made
/// atomic (on-chain a double push is harmless — identical txid, deduped).
#[cfg(test)]
pub(crate) fn combine_and_broadcast(
    node: &Node,
    backend: &dyn ChainBackend,
    due: &[String],
    now: u64,
) -> usize {
    combine_and_broadcast_with_clock(node, backend, due, move || now)
}

fn combine_and_broadcast_with_clock(
    node: &Node,
    backend: &dyn ChainBackend,
    due: &[String],
    clock: impl Fn() -> u64,
) -> usize {
    let Some(channel) = node.channel.as_ref() else {
        return 0;
    };
    let mut broadcast = 0;
    for commitment_id in due {
        // Settlement does not require this node to have collected a local quorum.
        // A peer may already have broadcast while some partials to this node were
        // delayed or lost. Check by exact candidate txid first so the local pending
        // Hold cannot subordinate refreshes until expiry for a spend already in the
        // mempool or chain.
        let Some(candidate_txid) = channel.candidate_txid(commitment_id) else {
            continue;
        };
        match transaction_is_settled(backend, &candidate_txid) {
            Ok(true) => {
                settle_candidate(node, channel, commitment_id);
                println!(
                    "fire: candidate {commitment_id} already settled on-chain ({candidate_txid})"
                );
                continue;
            }
            Ok(false) => {}
            Err(e) => {
                eprintln!("fire: cannot check settlement for candidate {commitment_id}: {e}");
                continue;
            }
        }

        // `None` is the ordinary "still collecting" case, not an error.
        let Some(finalized) = channel.try_finalize(commitment_id, node.threshold, clock()) else {
            continue;
        };
        match broadcast_package(node, backend, &finalized.tx, finalized.deadline, &clock) {
            // Settled — whether THIS node pushed the transaction or a peer already
            // won the redundant-broadcast race. Either way the spend is on the
            // network, so clear the candidate and its pending Hold; only a
            // transient backend failure (the `Err` arm) leaves both intact for the
            // next tick.
            Ok(outcome) => {
                settle_candidate(node, channel, commitment_id);
                match outcome {
                    BroadcastOutcome::Sent(txid) => {
                        broadcast += 1;
                        println!("fire: broadcast {txid} for candidate {commitment_id}");
                    }
                    // A peer beat this node to it. Clearing the pending Hold here is
                    // load-bearing: otherwise every node but the race winner would
                    // keep a stale pending entry and wrongly subordinate refreshes
                    // to an already-settled spend until commitment expiry.
                    BroadcastOutcome::AlreadySettled(txid) => println!(
                        "fire: candidate {commitment_id} already settled on-chain ({txid})"
                    ),
                }
            }
            Err(e) => eprintln!("fire: cannot broadcast candidate {commitment_id}: {e}"),
        }
    }
    broadcast
}

/// Mark an exact candidate settled locally and release refresh subordination.
/// Unknown/non-hot candidate ids are harmless: both underlying removals are
/// intentionally idempotent.
fn settle_candidate(node: &Node, channel: &channel::ChannelState, commitment_id: &str) {
    channel.mark_broadcast(commitment_id);
    node.sign_state
        .lock()
        .expect("sign_state lock poisoned")
        .pending
        .remove(commitment_id);
}

/// The outcome of trying to put a finalized candidate on the network.
enum BroadcastOutcome {
    /// This node package-validated and pushed the transaction; the backend
    /// returned this txid.
    Sent(Txid),
    /// The exact transaction is ALREADY in this node's chain view — a peer won the
    /// redundant-broadcast race, the designed steady state (ADR-0012: every node
    /// fires on its own clock). Settlement is settlement no matter who broadcast,
    /// so this node treats it as done, never as a failure to retry.
    AlreadySettled(Txid),
}

/// Package-validate `tx` against this node's own chain view, then broadcast it
/// (§5). Every failure is an `Err` — the transaction is simply not broadcast, and
/// nothing panics.
///
/// Package assembly validates every unconfirmed vault-authorized ancestor, then
/// tests `tx` against this node's full mempool view. The RPC package is a
/// singleton because its ancestors are, by construction, transactions already
/// present in this node's OWN mempool; re-listing them makes Core reject
/// multi-generation/already-present packages. "Relay-standard" alone would not
/// tell us the candidate and its ancestry are acceptable.
fn broadcast_package(
    node: &Node,
    backend: &dyn ChainBackend,
    tx: &bitcoin::Transaction,
    deadline: u64,
    clock: &impl Fn() -> u64,
) -> Result<BroadcastOutcome, Error> {
    let txid = tx.compute_txid();
    // A peer may already have broadcast this exact transaction — redundant
    // broadcast is the designed steady state, since each node fires on its own
    // clock (ADR-0012). Once it is in this node's mempool its inputs read as
    // spent, so `assemble_package` below would `Err` on the "spent" prevout and
    // this node would mistake an already-SETTLED spend for a failure — never
    // clearing its pending Hold and wrongly subordinating refreshes until
    // commitment expiry. The peer copy may already be in a block rather than the
    // mempool, so recognize either location as settled.
    if transaction_is_settled(backend, &txid)? {
        return Ok(BroadcastOutcome::AlreadySettled(txid));
    }
    let authorized = node
        .authorized
        .lock()
        .expect("authorized lock poisoned")
        .clone();
    let package = chain::assemble_package(backend, tx, &authorized)?;
    match backend.test_package_accept(&package)? {
        chain::PackageVerdict::Accepted => {}
        chain::PackageVerdict::Rejected(reason) => {
            return Err(format!("package mempool-acceptance failed: {reason}").into())
        }
    }
    // Package/ancestor RPCs above are blocking and may begin just before the
    // combine deadline. Authorization is about the instant the transaction leaves
    // this node, not the pass-start timestamp, so re-read the clock immediately
    // before `sendrawtransaction`. Equality remains inside the inclusive window.
    let send_now = clock();
    if send_now > deadline {
        return Err(format!(
            "combine window closed at {deadline} before broadcast (now {send_now})"
        )
        .into());
    }
    match backend.broadcast(&bitcoin::consensus::serialize(tx)) {
        Ok(sent) => Ok(BroadcastOutcome::Sent(sent)),
        // A peer's copy can land in the narrow window between the check above and
        // this push; the backend then rejects the duplicate. If the exact
        // transaction is now in our mempool or active chain it settled after all
        // — the same AlreadySettled case, not a failure to retry.
        Err(e) => {
            if matches!(transaction_is_settled(backend, &txid), Ok(true)) {
                Ok(BroadcastOutcome::AlreadySettled(txid))
            } else {
                Err(e)
            }
        }
    }
}

/// Whether the exact candidate is already in this node's mempool OR active
/// chain. Redundant node broadcasts race both mempool admission and mining; both
/// outcomes settle the local candidate and its pending Hold.
fn transaction_is_settled(backend: &dyn ChainBackend, txid: &Txid) -> Result<bool, Error> {
    Ok(backend.mempool_transaction(txid)?.is_some() || backend.transaction_confirmed(txid)?)
}

/// Spawn one detached send per (peer × message). Detached on purpose: each send
/// retries with backoff until its own deadline, so awaiting them would let one
/// dead peer hold up the fire pass — and every other candidate with it.
fn spawn_fan_out(node: &Arc<Node>, messages: Vec<channel::Outbound>) {
    let Some(channel) = node.channel.as_ref() else {
        return;
    };
    for peer in channel.peer_ids() {
        for message in &messages {
            let node = Arc::clone(node);
            let msg_type = message.msg_type;
            let payload = message.payload.clone();
            let deadline = message.deadline;
            tokio::spawn(async move {
                let channel = node
                    .channel
                    .as_ref()
                    .expect("fan-out only spawns in channel mode");
                if let Err(e) =
                    channel::retry_message_until(channel, msg_type, peer, &payload, deadline).await
                {
                    // A peer that never accepts costs redundancy, never safety:
                    // the combine simply proceeds with whoever answered.
                    eprintln!("channel: cannot deliver {msg_type} to node {peer}: {e}");
                }
            });
        }
    }
}

/// Drain the outbox and propagate every accepted request to every peer (§3).
///
/// Called once the sign lock is released — by `/sign` and by the `/channel`
/// `request` path alike, so a request that arrives either way fans out the same.
/// Bounded and loop-free with no new mechanism: a node only ever propagates a
/// request it just ACCEPTED, and acceptance consumed that request's coordinator
/// nonce (ADR-0013 §2), so the copy that comes back from a peer is refused as a
/// replay and propagates no further. The fan-out therefore dies after one round,
/// at `n·(n−1)` messages.
pub fn propagate_outbox(node: &Arc<Node>) {
    if node.channel.is_none() {
        return;
    }
    let requests: Vec<vault_proto::TaggedRequest> =
        std::mem::take(&mut *node.outbox.lock().expect("outbox lock poisoned"));
    for request in requests {
        let expiry = match &request {
            vault_proto::TaggedRequest::Spend(spend) => spend.expiry,
            vault_proto::TaggedRequest::Refresh(refresh) => refresh.expiry,
        };
        // ONE outbound message, built by a pure function of the request: identical
        // path, identical count (every peer), identical size under either PIN.
        spawn_fan_out(
            node,
            vec![channel::Outbound {
                msg_type: channel::MSG_TYPE_REQUEST,
                payload: channel::request_payload(&request),
                deadline: expiry,
            }],
        );
    }
}

/// Ingest one raw `/channel` body (§3). The channel authenticates the envelope;
/// a `request` comes back here so THIS node applies its own coordinator-auth,
/// freshness, user-signature, and policy gates before anything is registered or
/// signed — a peer is transport, never an authority (signing-oracle prohibition).
///
/// An accepted request lands in the outbox and the caller pumps it onward, so one
/// delivered node brings the whole federation to the same state.
pub(crate) fn handle_channel_body(node: &Node, body: &[u8], now: u64) -> ChannelReply {
    let Some(channel) = node.channel.as_ref() else {
        // Unreachable: `/channel` is mounted only in channel mode.
        return ChannelReply::Rejected(channel::RejectReason::UnknownMsgType);
    };
    match channel.ingest(body, now) {
        channel::Ingested::Reply(reply) => reply,
        channel::Ingested::Request(request) => {
            // The node's own gates decide. The peer learns only that we processed
            // it — never our policy verdict, which is ours alone and which a peer
            // has no authority to act on anyway.
            let outcome = match request.as_ref() {
                // Envelope freshness used the caller's `now` above, but policy
                // freshness, Hold scheduling, and refresh timestamps must read the
                // clock only after acquiring `sign_state`. A relayed request may
                // wait behind another signer just like a direct `/sign` request.
                vault_proto::TaggedRequest::Spend(spend) => handle_sign_now(node, spend),
                vault_proto::TaggedRequest::Refresh(refresh) => handle_refresh_now(node, refresh),
            };
            match outcome {
                Ok(_) => ChannelReply::Accepted,
                // A peer relayed something this node cannot even decode. That is a
                // malformed payload, not a policy outcome.
                Err(_) => ChannelReply::Rejected(channel::RejectReason::MalformedPayload),
            }
        }
    }
}

/// Extract the user key from the fixed first-light descriptor template
/// `wsh(and_v(v:pk(USER),multi(t,node...)))`.
fn first_light_user_key_of(descriptor: &Descriptor<PublicKey>) -> Result<PublicKey, Error> {
    let template_err = || -> Error {
        "descriptor does not match the first-light template \
         wsh(and_v(v:pk(USER),multi(t,...)))"
            .into()
    };
    let Descriptor::Wsh(wsh) = descriptor else {
        return Err(template_err());
    };
    let WshInner::Ms(ms) = wsh.as_inner() else {
        return Err(template_err());
    };
    let Terminal::AndV(left, right) = &ms.node else {
        return Err(template_err());
    };
    // `v:pk(USER)` parses as Verify(Check(PkK(USER))).
    let Terminal::Verify(inner) = &left.node else {
        return Err(template_err());
    };
    let Terminal::Check(inner) = &inner.node else {
        return Err(template_err());
    };
    let Terminal::PkK(user) = &inner.node else {
        return Err(template_err());
    };
    let Terminal::Multi(_) = &right.node else {
        return Err(template_err());
    };
    Ok(*user)
}

/// Extract the federation from the first-light descriptor template's
/// `multi(t, node...)`: the threshold `t` and the node keys.
///
/// Both come from the descriptor and never from config, because both are
/// consensus facts about the script the coins are actually locked to. A config
/// copy of `t` could disagree with it — too low and this node would broadcast
/// transactions the network rejects, too high and every legitimate spend would
/// stall forever. The keys are the descriptor-canonical set the channel manifest's
/// `node_id` bijection is defined over (§1); they come back in descriptor order,
/// and the channel derives the canonical (lexicographic) order itself.
fn first_light_federation_of(
    descriptor: &Descriptor<PublicKey>,
) -> Result<(usize, Vec<PublicKey>), Error> {
    let template_err = || -> Error {
        "descriptor does not match the first-light template \
         wsh(and_v(v:pk(USER),multi(t,...)))"
            .into()
    };
    let Descriptor::Wsh(wsh) = descriptor else {
        return Err(template_err());
    };
    let WshInner::Ms(ms) = wsh.as_inner() else {
        return Err(template_err());
    };
    let Terminal::AndV(_left, right) = &ms.node else {
        return Err(template_err());
    };
    let Terminal::Multi(thresh) = &right.node else {
        return Err(template_err());
    };
    Ok((thresh.k(), thresh.data().to_vec()))
}

/// Handle one `/sign` submission. `now` is unix seconds by the node's own
/// clock (a parameter, never a system-clock read, so the anti-replay, expiry,
/// and fire logic is deterministically testable). `Err(BadRequest)` means
/// undecodable input (HTTP 400); every policy outcome — accepted or refused — is
/// `Ok`. Under Model B (ADR-0012) an accepted response carries NO node signature:
/// the node signs at ingress but withholds every partial until its candidate's
/// authorized fire event, and the NODES combine + broadcast, so a hostile
/// coordinator collecting `/sign` responses can never finalize (§2).
///
/// Ordering (ADR-0012 Model-B Hold lifecycle; ADR-0013 §§2-3, §6-7; ADR-0008):
///  -. Lockdown (ADR-0008) — a terminal-Lockdown node answers `FRAUD_SUSPECTED`
///     and does nothing else. Checked before the lock, so it short-circuits auth,
///     PIN, and the budget entirely.
///  0. coordinator-auth + freshness + fresh nonce + node-capped expiry — before
///     the PIN; an authentic request consumes its nonce even when a later check
///     refuses it ([`verify_coord_auth`]).
///  1. PIN + per-node attempt budget (ADR-0012 constant-cost compare; ADR-0013 §7)
///     — before anything is signed. BOTH Argon2id digests are computed and the
///     verdict is constant-time-selected ([`pin::verify_pin`]); the budget charges
///     ONLY wrong pins, a valid duress pin fires the arm-hook even when locked out
///     (fail-closed), and a locked-out node refuses to sign. A bad/locked PIN
///     verdict is never logged: the PIN is not part of the commitment, so recording
///     it would wrongly replay a `BAD_PIN` refusal for the same transaction
///     resubmitted with a good PIN.
///  2. decode BOTH PSBTs — the spend and its MANDATORY escape (§4); undecodable
///     input is a 400, not a refusal.
///  3. compute BOTH `commitment_id`s — the exact-byte pair of §4 (V0-2b).
///  4. idempotency — prune the replay/pending/refresh/candidate logs, then return
///     the recorded verdict for an identical resubmission. Accepted state is keyed
///     by the COMPLETE pair; a transaction-determined refusal stays keyed by the
///     spend commitment.
///  5. validate the spend: user-signature verification, then policy-core. A
///     refusal here is final and (when the commitment fully determines it,
///     [`is_recordable_verdict`]) recorded; an INVALID spend is never signed,
///     registered, or propagated.
///  6. derive the transaction CLASS from the outputs (ADR-0013 §3): reject a
///     mixed hot+escape spend, and reject a refresh-shaped (pays-only-the-vault)
///     SpendRequest, as `PSBT_INCONSISTENT`.
///  7. validate the mandatory escape (§4): node-VALIDATED, never node-built.
///  8. `EXPIRY_TOO_SHORT` for hot-class: the commitment must outlive its Hold and
///     the combine window (`now + hold_secs + combine_slack_secs`); equality passes.
///  9. sign BOTH transactions at ingress, pin-independently — NOTHING is
///     transmitted here (invariant 7: partials wait for the fire gate).
/// 10. register the PAIR — two distinct exact-byte candidates with roles; the
///     spend gets the fire window its class earned, the escape gets none.
/// 11. record both txids in the vault-authorized set (watchtower recognition +
///     unconfirmed-parent eligibility, ADR-0012); a REFUSED request never reaches
///     here, which is exactly what the recognition fix needs.
/// 12. the Hold timer, hot-class only — what refresh subordination reads.
/// 13. stage propagation to every peer (§3), sent by the async pump once the lock
///     releases; then answer `Accepted` with no signature.
pub fn handle_sign(
    node: &Node,
    request: &SignRequest,
    now: u64,
) -> Result<SignResponse, BadRequest> {
    handle_sign_after_lock(node, request, || now)
}

/// Handle an HTTP sign submission using the node's clock, read only after the
/// sign-state lock so queued time cannot stale expiry or Hold checks.
pub(crate) fn handle_sign_now(
    node: &Node,
    request: &SignRequest,
) -> Result<SignResponse, BadRequest> {
    handle_sign_after_lock(node, request, || {
        // Before the epoch is impossible in practice; treating it as 0 fails
        // safe because every real commitment then reads as expired.
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    })
}

/// Handle one first-class, pin-less refresh request (ADR-0013 §2): a self-spend
/// that resets a coin's recovery timelock. It passes the identical
/// coordinator-auth + freshness gate as a spend, then — because a refresh fires
/// at ingress — signs, registers, and becomes collectable immediately.
///
/// ADR-0012 makes a pin-less refresh conditional on burn bounds of its own because
/// "pin-less + instant means the refresh path has neither the Hold nor the pin that
/// ADR-0006 relies on for its burn defense". All three bounds are enforced here:
/// a minimum refresh interval and a tight refresh fee cap
/// ([`ConfigFile::refresh_min_interval_secs`], [`ConfigFile::refresh_max_feerate`],
/// ADR-0013 §6), plus refresh **subordination** — any pending spend blocks every
/// refresh, so a refresh can never race a spend that is waiting out its Hold.
///
/// A refresh arrives ONLY through this handler. The tagged union (ADR-0013 §2)
/// is what makes that true: a pure self-spend submitted as a PIN-carrying
/// `SpendRequest` is refused `PSBT_INCONSISTENT` in [`handle_sign`] rather than
/// served, which is what keeps refresh off the duress surface — admitting it there
/// would pose the question the union exists to delete (honor the pin, or ignore it?).
pub fn handle_refresh(
    node: &Node,
    request: &RefreshRequest,
    now: u64,
) -> Result<SignResponse, BadRequest> {
    handle_refresh_after_lock(node, request, || now)
}

/// Handle an HTTP Refresh submission using the node's clock, read only after the
/// sign-state lock so queueing cannot stale the freshness window.
pub(crate) fn handle_refresh_now(
    node: &Node,
    request: &RefreshRequest,
) -> Result<SignResponse, BadRequest> {
    handle_refresh_after_lock(node, request, || {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    })
}

fn handle_sign_after_lock(
    node: &Node,
    request: &SignRequest,
    clock: impl FnOnce() -> u64,
) -> Result<SignResponse, BadRequest> {
    // Terminal Lockdown (ADR-0008) short-circuits everything: a locked-down node
    // answers FRAUD_SUSPECTED to every spend for its lifetime and does no further
    // work — no auth, no pin, no signing. Checked before the lock so a locked-down
    // node does not even contend it.
    if node.is_locked_down() {
        return Ok(fraud_suspected());
    }
    // The whole call runs under ONE lock over the replay + pending logs
    // (`Mutex<SignState>`), reproducing the atomicity the old sequential serve
    // loop gave for free: two concurrent `/sign` requests execute one-at-a-time
    // and their check-then-update sequences never interleave. This serializes
    // `/sign` against `/sign` BY DESIGN — the async migration isolates `/sign`
    // from `/events` (and, in V0-8a, `/channel`), which keep their own locks,
    // not sign-vs-sign throughput.
    //
    // Deliberate throughput tradeoff (V0-4a): the PIN compare's TWO Argon2id
    // evaluations run under this lock (unconditionally, for the constant-cost
    // invariant), so an authenticated request holds it for ~2×Argon2 instead of
    // the old SHA-256 microseconds, serializing `/sign` against `/sign` for that
    // span. Hoisting the hash out is not a free win — pre-lock it would either
    // run Argon2 BEFORE coord-auth (an unauthenticated-Argon2 DoS vector) or
    // duplicate the atomic nonce consumption the lock exists to give. The hash is
    // gated by coord-auth, so only the vault's one pinned coordinator can trigger
    // it, and for a low-volume personal vault the serialized cost is acceptable.
    // The wrong-pin rate-limit backoff sleep is taken OUTSIDE this lock (below),
    // so a wrong-pin flood never pins `/sign` against honest spends.
    let mut state = node.sign_state.lock().expect("sign_state lock poisoned");
    // Authoritative Lockdown check, UNDER the lock. The pre-lock check above is only
    // a fast path; `enter_lockdown` sets the flag while holding this same lock, so a
    // terminal transition that races an in-flight request linearizes here — this
    // request either saw `false` and now holds the lock (and commits before Lockdown
    // could store) or sees `true` and refuses. Either way nothing is signed or
    // registered after Lockdown is entered.
    if node.is_locked_down() {
        return Ok(fraud_suspected());
    }
    let now = clock();

    // 0. Coordinator-auth + freshness gate (ADR-0013 §2/§3): every request must be
    //    validly coord-signed over its canonical bytes by the vault's one pinned
    //    coordinator, carry a fresh (unseen) nonce, and fall inside the expiry
    //    window — BEFORE the PIN, so an unauthenticated caller never reaches the
    //    PIN compare (the trust root V0-8b builds on). Runs under the one sign
    //    lock, so the nonce check-then-record is atomic. This gate also owns the
    //    node-capped expiry check for the whole handler, so nothing below
    //    re-checks the window. Its stale lower bound uses the nonce log's
    //    rollback-guarded clock (`max(high_water, now)`, [`NonceLog`]), so a clock
    //    rollback cannot revive a pruned nonce. Its future upper bound still uses
    //    raw `now`, preserving V0-2's exact `now + max_commitment_age_secs` cap.
    if let Err(rejected) = verify_coord_auth(
        node,
        request.coord_request(),
        &request.coord_sig,
        now,
        &mut state.coord_nonces,
    ) {
        return Ok(rejected);
    }
    // 1. PIN + per-node attempt budget, before anything is signed (ADR-0012 /
    //    ADR-0013 §7). BOTH Argon2id digests are computed unconditionally and the
    //    verdict is constant-time-selected ([`pin::verify_pin`]) — a short-circuit
    //    would make a duress pin one Argon2 slower and leak the duress bit to the
    //    coordinator-attacker. Normal and duress are then observably identical: same
    //    two Argon2, same (no-op) budget touch, same lack of backoff. Only a WRONG
    //    pin diverges (it charges the budget and sleeps its backoff), and a wrong
    //    pin is neither PIN, so its divergence leaks nothing about duress.
    //
    //    A bad-pin verdict is never recorded in the replay log: the pin is not part
    //    of the commitment, so recording it would wrongly replay a BAD_PIN refusal
    //    for the same transaction later resubmitted with a good pin.
    // Even an empty or over-length value runs both Argon2 evaluations: the structural
    // invariant is exactly two evaluations for every authenticated SpendRequest,
    // not two only after an input-shape fast path. It is forced Wrong afterward:
    // empty is also how an omitted wire field decodes, and values beyond
    // MAX_PIN_BYTES are outside the enrolment protocol.
    let compared = pin::verify_pin(node.pin_evaluator.as_ref(), request.pin.as_bytes());
    let verdict = if request.pin.is_empty() || request.pin.len() > MAX_PIN_BYTES {
        pin::PinVerdict::Wrong
    } else {
        compared
    };
    let charge = state
        .pin_budget
        .charge(verdict, now, &node.pin_budget_config);
    // Fail-closed (ADR-0012): a valid DURESS pin ALWAYS fires the arm-hook — even
    // when the node is locked out on a wrong-pin flood, and even though V0-4a still
    // signs a not-locked duress request identically to a normal one. The budget
    // never charges a valid pin, so this arming can never be rate-limited away. The
    // hook runs UNCONDITIONALLY here and selects its +1/+0 delta in constant time, so
    // normal and duress do identical observable work on this line too.
    node.fire_arm_hook(verdict);
    if charge.refuse {
        // Locked out (any pin) or a wrong pin: refuse to sign. Nothing below runs and
        // no verdict is recorded, so it is safe to drop the sign lock now and sleep
        // the backoff OUTSIDE it — a wrong-pin flood must not pin the one `/sign`
        // lock for the whole backoff and stall honest spends.
        drop(state);
        if !charge.backoff.is_zero() {
            std::thread::sleep(charge.backoff);
        }
        return Ok(pin_refusal(charge.locked));
    }
    ensure_request_propagatable(node, &vault_proto::TaggedRequest::Spend(request.clone()))?;

    // 2. Decode BOTH PSBTs; undecodable input is a 400, not a refusal. The escape
    //    is mandatory (ADR-0012: "a request missing the escape is invalid and
    //    rejected outright, so a hostile coordinator cannot strip the escape to
    //    force lockdown-only").
    let mut spend = decode_psbt(&request.psbt, "spend")?;
    let mut escape = decode_psbt(&request.escape_psbt, "escape")?;

    // 3. Bind this decision to the exact transactions. The commitments carry
    //    this node's OWN baked `policy_version` (from config, not the request):
    //    the node always evaluates and signs against its own static policy, so
    //    the request's `policy_version` is coordinator metadata that cannot
    //    change what gets signed and needs no separate match check here. The two
    //    are DISTINCT commitments — the pair of §4.
    let commitment_id = commitment_of(node, &spend, request.expiry).commitment_id();
    let escape_commitment_id = commitment_of(node, &escape, request.expiry).commitment_id();
    // Accepted idempotency must bind the COMPLETE candidate pair, not just the
    // spend commitment. A commitment deliberately excludes signature bytes, and
    // the spend id says nothing about which mandatory escape accompanied it. If an
    // Accepted entry lived under `commitment_id`, a coordinator could send peers
    // different valid user-signature instances or escapes and have the cache hide
    // the conflict before validation/registration. The request-pair key includes
    // both exact ingress PSBTs; PIN/auth transmission fields stay outside because
    // coordinator auth and the PIN are processed before this lookup by design.
    let accepted_replay_key =
        acceptance_replay_key(&[(&commitment_id, &spend), (&escape_commitment_id, &escape)]);
    // The two ids CAN coincide, and benignly: an escape-class spend already sweeps
    // to the escape wallet, so its mandatory escape may be byte-identical to it. The
    // pair then collapses to one candidate (`register_pair` leaves the resident and
    // drops the duplicate — see [`PartialStore::register`]). That is correct, not a
    // lost escape: an escape-class spend fires immediately under EITHER pin and is
    // never frozen, so — unlike a hot spend, whose escape always differs (hot pays
    // external, escape pays the vault's escape wallet) — it has no duress path that
    // needs a distinct escape to schedule. See challenges-round-3 for why rejecting
    // the equality was ruled out.

    // 4. Anti-replay log: prune expired entries (retention is bounded by each
    //    entry's expiry), then return idempotently for an identical, unexpired
    //    resubmission. Accepted state is keyed by the complete pair above;
    //    transaction-determined refusals remain keyed by the spend commitment. An
    //    RBF replacement has a different commitment and is never blocked here.
    //    Prune the pending log on the same schedule so its Hold timers stay bounded.
    state.replay.prune(now);
    if let Some(recorded) = state.replay.get(&accepted_replay_key, now) {
        return Ok(recorded);
    }
    if let Some(recorded) = state.replay.get(&commitment_id, now) {
        return Ok(recorded);
    }
    state.pending.prune(now);
    state.refreshes.prune(now, node.refresh_min_interval_secs);
    // Prune expired channel candidates on the SAME sweep the replay/pending logs
    // run on (§5): a candidate and its stored partials evict when its commitment
    // expires. (`/channel` lookup also evicts expired candidates, so an idle node
    // that never runs this sweep still rejects them.)
    if let Some(channel) = &node.channel {
        channel.prune_store(now);
    }

    // 5. Validate the spend (user-signature verification, then policy-core)
    //    WITHOUT signing yet. A refusal here is final and is recorded exactly as
    //    in V0-2: only verdicts the commitment fully determines are logged, so a
    //    signature- or PSBT-structure-dependent refusal stays unrecorded and an
    //    identical commitment resubmitted with a corrected signature is
    //    re-evaluated, not answered from a stale refusal (the log does not
    //    defend the signature; DESIGN.md, "What the anti-replay log is — and is
    //    not"). An invalid submission is never signed, registered, or propagated.
    if let Err(refused) = verify_spend(node, &spend) {
        record_verdict(&mut state.replay, &commitment_id, request.expiry, &refused);
        return Ok(refused);
    }

    // 6. Derive the spend's class from its OUTPUTS (ADR-0013 §3) — never from a
    //    coordinator label. This rejects a mixed hot+escape spend, which the
    //    per-output allowlist check above happily admits.
    let class = match policy_core::classify(&spend, &node.check_params) {
        Ok(class) => class,
        Err(v) => {
            let refused = refusal(map_policy_code(v.code), v.check, v.detail);
            record_verdict(&mut state.replay, &commitment_id, request.expiry, &refused);
            return Ok(refused);
        }
    };
    if class == policy_core::TxClass::Refresh {
        // A pure self-spend arriving as a PINNED SpendRequest (ADR-0013 §3). It
        // belongs in a pin-less RefreshRequest, and admitting it here would pose
        // the question the tagged union exists to delete: honor the pin, or ignore
        // it? Refusing is what keeps refresh off the duress surface.
        let refused = refusal(
            RefusalCode::PsbtInconsistent,
            "transaction_class",
            "every output pays the vault: a refresh must be submitted as a pin-less \
             RefreshRequest, not a SpendRequest"
                .into(),
        );
        record_verdict(&mut state.replay, &commitment_id, request.expiry, &refused);
        return Ok(refused);
    }

    // 7. Validate the mandatory escape the same way (§4): node-VALIDATED, never
    //    node-built — every input a vault UTXO, every destination output paying
    //    the escape descriptor, and the user's signature verifying over the exact
    //    bytes.
    if let Err(refused) = verify_escape(node, &escape) {
        // The replay key binds only the spend. An escape-derived refusal is not a
        // property of that commitment: the same exact spend may be paired with a
        // corrected escape on a fresh request. Caching it under the spend id would
        // strand that correction until expiry.
        return Ok(refused);
    }

    // 8. EXPIRY_TOO_SHORT (ADR-0013 §6): a hot-class commitment must outlive its
    //    Hold AND the combine window that follows, or this node would sign at
    //    ingress, hold the partial, and watch the candidate expire before it could
    //    ever combine. Equality passes. Not recorded in the replay log: it is a
    //    verdict about the node's clock, not about the commitment, so the same
    //    commitment resubmitted earlier in its life must be re-evaluated.
    let fire_at = match class {
        // Hot-class: the Hold delays combine + broadcast, never signing.
        policy_core::TxClass::Hot => now.saturating_add(node.hold_secs),
        // Escape-class completes immediately under EITHER pin — the destination is
        // the user's own escape wallet either way, so there is nothing to defer and
        // therefore no timing oracle (ADR-0012).
        policy_core::TxClass::Escape => now,
        policy_core::TxClass::Refresh => unreachable!("refresh-class was refused above"),
    };
    if class == policy_core::TxClass::Hot {
        let floor = fire_at.saturating_add(node.combine_slack_secs);
        if request.expiry < floor {
            return Ok(refusal(
                RefusalCode::ExpiryTooShort,
                "commitment_expiry",
                format!(
                    "expiry {} is before {floor} (now {now} + hold_secs {} + combine_slack_secs \
                     {}), so the spend could not finish combining before it expired",
                    request.expiry, node.hold_secs, node.combine_slack_secs
                ),
            ));
        }
    }

    // 9. Sign BOTH transactions, at ingress, pin-independently (ADR-0012's
    //    Model-B Hold lifecycle: "signing must not depend on the pin, or signing
    //    itself is a duress oracle"). NOTHING is transmitted here — the partials
    //    stay in this node's candidate registry until each candidate's authorized
    //    fire event opens the release gate (invariant 7).
    if let Err(detail) = add_node_signatures(node, &mut spend) {
        return Ok(refusal(RefusalCode::PsbtInconsistent, "signing", detail));
    }
    if let Err(detail) = add_node_signatures(node, &mut escape) {
        return Ok(refusal(RefusalCode::PsbtInconsistent, "signing", detail));
    }

    // 10. Register the PAIR (§4): two distinct exact-byte candidates with
    //     unambiguous roles, both signed, paired by this request. The spend gets
    //     the fire window its class earned; the escape gets NONE — V0-8b schedules
    //     nothing for it, and V0-4b's duress arm is what would give it one at T.
    if let Err(refused) = register_pair(
        node,
        RegisterPair {
            spend: &spend,
            spend_commitment_id: &commitment_id,
            escape: &escape,
            escape_commitment_id: &escape_commitment_id,
            fire: channel::FireWindow {
                fire_at,
                deadline: request
                    .expiry
                    .min(fire_at.saturating_add(node.combine_slack_secs)),
            },
            expiry: request.expiry,
        },
    ) {
        return Ok(refused);
    }

    // 11. Recognition + the vault-authorized set (ADR-0012): this node validated
    //     and policy-ACCEPTED both transactions, so both are recognized by its
    //     watchtower and both may serve as unconfirmed parents. A REFUSED request
    //     never reaches here, which is exactly the property the recognition fix
    //     needs — a theft fanned to honest nodes must still alert.
    {
        let mut authorized = node.authorized.lock().expect("authorized lock poisoned");
        authorized.insert(spend.unsigned_tx.compute_txid());
        authorized.insert(escape.unsigned_tx.compute_txid());
    }

    // 12. The Hold timer, for hot-class only. It is what "a refresh is subordinate
    //     to any pending spend" reads (ADR-0012). An escape-class spend fires now,
    //     so it is never pending — the ADR names that as the explicit exception.
    if class == policy_core::TxClass::Hot {
        state.pending.record(commitment_id.clone(), request.expiry);
    }

    // 13. Propagate to every peer (§3). Staged here, sent by the async pump once
    //     this lock is released: one delivered node brings the rest to the same
    //     state, so a coordinator cannot selectively deliver. Unconditional and
    //     pin-independent on every accepted request.
    node.outbox
        .lock()
        .expect("outbox lock poisoned")
        .push(vault_proto::TaggedRequest::Spend(request.clone()));

    let verdict = SignResponse::Accepted(vault_proto::Accepted {
        commitment_id: commitment_id.clone(),
        first_seen: now,
        remaining_secs: fire_at.saturating_sub(now),
    });
    record_verdict(
        &mut state.replay,
        &accepted_replay_key,
        request.expiry,
        &verdict,
    );
    Ok(verdict)
}

fn handle_refresh_after_lock(
    node: &Node,
    request: &RefreshRequest,
    clock: impl FnOnce() -> u64,
) -> Result<SignResponse, BadRequest> {
    // Lockdown (ADR-0008) refuses refreshes too: every spend AND refresh answers
    // FRAUD_SUSPECTED for the node's lifetime. (The refresh path is pin-less, so it
    // has no budget to touch — only Lockdown gates it here.) This pre-lock check is
    // a fast path.
    if node.is_locked_down() {
        return Ok(fraud_suspected());
    }
    // Refreshes share the same serialized SignState as spends, so consuming the
    // nonce remains atomic with every other request at ingress.
    let mut state = node.sign_state.lock().expect("sign_state lock poisoned");
    // Authoritative Lockdown re-check under the lock: `enter_lockdown` sets the flag
    // while holding `sign_state`, so a transition racing this refresh linearizes here
    // and no refresh registers after Lockdown is entered (mirrors `/sign`).
    if node.is_locked_down() {
        return Ok(fraud_suspected());
    }
    let now = clock();

    if let Err(rejected) = verify_coord_auth(
        node,
        request.coord_request(),
        &request.coord_sig,
        now,
        &mut state.coord_nonces,
    ) {
        return Ok(rejected);
    }
    ensure_request_propagatable(node, &vault_proto::TaggedRequest::Refresh(request.clone()))?;

    // Preserve the transport boundary: a signed but undecodable PSBT is still a
    // bad request (HTTP 400), not a policy outcome.
    let mut refresh = decode_psbt(&request.refresh_psbt, "refresh")?;

    let commitment_id = commitment_of(node, &refresh, request.expiry).commitment_id();
    let accepted_replay_key = acceptance_replay_key(&[(&commitment_id, &refresh)]);
    state.replay.prune(now);
    if let Some(recorded) = state.replay.get(&accepted_replay_key, now) {
        return Ok(recorded);
    }
    if let Some(recorded) = state.replay.get(&commitment_id, now) {
        return Ok(recorded);
    }
    state.pending.prune(now);
    state.refreshes.prune(now, node.refresh_min_interval_secs);
    if let Some(channel) = &node.channel {
        channel.prune_store(now);
    }

    // The same validation a spend gets: the user's signature over the exact bytes,
    // then input ownership + allowlist + fee cap.
    if let Err(refused) = verify_spend(node, &refresh) {
        record_verdict(&mut state.replay, &commitment_id, request.expiry, &refused);
        return Ok(refused);
    }

    // A refresh must BE a refresh: every output pays the vault (ADR-0013 §3). This
    // is what makes it safe to be pin-less — a transaction that can move nothing
    // to anyone needs no duress decision, so there is no signal for an attacker to
    // read on this path.
    match policy_core::classify(&refresh, &node.check_params) {
        Ok(policy_core::TxClass::Refresh) => {}
        Ok(other) => {
            let refused = refusal(
                RefusalCode::PsbtInconsistent,
                "transaction_class",
                format!(
                    "a RefreshRequest must be a pure self-spend, but this is {other:?}-class: \
                     every output must pay the vault descriptor"
                ),
            );
            record_verdict(&mut state.replay, &commitment_id, request.expiry, &refused);
            return Ok(refused);
        }
        Err(v) => {
            let refused = refusal(map_policy_code(v.code), v.check, v.detail);
            record_verdict(&mut state.replay, &commitment_id, request.expiry, &refused);
            return Ok(refused);
        }
    }

    // Subordination (ADR-0012): any pending spend blocks EVERY refresh. The rule
    // is deliberately COARSE — not "refreshes whose inputs overlap the pending
    // spend". A duress escape sweeps most of the vault while the triggering hot
    // spend touches a small subset, so an input-overlap rule would let a refresh
    // over a non-overlapping escape input finalize instantly and invalidate the
    // armed escape. Only the coarse rule closes that.
    //
    // It is silent, which is why it can be unconditional: the refresh is deferred
    // for a reason the attacker can already see — their own visible pending spend
    // — and it behaves identically under both PINs and in ordinary operation.
    if state.pending.has_any(now) {
        return Ok(refusal(
            RefusalCode::RefreshSubordinated,
            "refresh_subordination",
            "a spend is pending on this node; refreshes are subordinate to pending spends \
             (retry once it settles)"
                .into(),
        ));
    }

    // ADR-0013 §6's two burn bounds. ADR-0006 leans on the Hold and the pin for
    // its burn defense; a refresh is pin-less AND instant, so it has neither and
    // needs its own.
    if let Some(refused) = check_refresh_interval(node, &state, &refresh, now) {
        return Ok(refused);
    }
    if let Some(refused) = check_refresh_feerate(node, &refresh) {
        return Ok(refused);
    }

    // Sign at ingress, like every other class.
    if let Err(detail) = add_node_signatures(node, &mut refresh) {
        return Ok(refusal(RefusalCode::PsbtInconsistent, "signing", detail));
    }

    // A refresh is its own candidate with no escape to pair — it moves nothing to
    // anyone, so ADR-0013 §2 gives it no escape and no pin. It fires immediately.
    let fire = channel::FireWindow {
        fire_at: now,
        deadline: request
            .expiry
            .min(now.saturating_add(node.combine_slack_secs)),
    };
    if let Err(refused) = register_pair(
        node,
        RegisterPair {
            spend: &refresh,
            spend_commitment_id: &commitment_id,
            // Self-paired: a refresh has no escape (ADR-0013 §2), and the pairing
            // field is not optional, so it names itself rather than inventing an
            // absent-sibling case for one variant.
            escape: &refresh,
            escape_commitment_id: &commitment_id,
            fire,
            expiry: request.expiry,
        },
    ) {
        return Ok(refused);
    }

    // Start every touched coin's interval clock: the inputs (this coin has now
    // been refreshed) AND the outputs (the coins this refresh creates). Recording
    // the OUTPUTS is what actually bounds the burn RATE — an attacker chains
    // refreshes, each spending the last one's fresh output, so an inputs-only rule
    // would never fire on the chain it is meant to stop.
    state.refreshes.record(&refresh, now);

    node.authorized
        .lock()
        .expect("authorized lock poisoned")
        .insert(refresh.unsigned_tx.compute_txid());
    node.outbox
        .lock()
        .expect("outbox lock poisoned")
        .push(vault_proto::TaggedRequest::Refresh(request.clone()));

    let verdict = SignResponse::Accepted(vault_proto::Accepted {
        commitment_id: commitment_id.clone(),
        first_seen: now,
        remaining_secs: 0,
    });
    record_verdict(
        &mut state.replay,
        &accepted_replay_key,
        request.expiry,
        &verdict,
    );
    Ok(verdict)
}

/// ADR-0013 §6's minimum refresh interval, per coin. `None` ⇒ within bounds.
fn check_refresh_interval(
    node: &Node,
    state: &SignState,
    refresh: &Psbt,
    now: u64,
) -> Option<SignResponse> {
    for input in &refresh.unsigned_tx.input {
        let outpoint = input.previous_output;
        let Some(last) = state.refreshes.last_refresh(&outpoint) else {
            continue;
        };
        let elapsed = now.saturating_sub(last);
        if elapsed < node.refresh_min_interval_secs {
            return Some(refusal(
                RefusalCode::RefreshTooSoon,
                "refresh_min_interval",
                format!(
                    "coin {outpoint} was refreshed {elapsed}s ago, inside the \
                     {}s minimum refresh interval",
                    node.refresh_min_interval_secs
                ),
            ));
        }
    }
    None
}

/// ADR-0013 §6's tight refresh fee cap. `None` ⇒ within bounds.
///
/// The feerate is measured over the UNSIGNED transaction's vsize, which every node
/// computes identically from the exact committed bytes — the same determinism the
/// combine needs. It is a deliberate over-estimate (the final witness makes the
/// real transaction larger, hence its real feerate lower), so the error is always
/// toward refusing, never toward admitting a burn. That suits what this cap is: a
/// bound on the burn RATE, not a fee optimizer. It only has to sit far below
/// `max_fee_pct`, and it does.
fn check_refresh_feerate(node: &Node, refresh: &Psbt) -> Option<SignResponse> {
    let total_in: u64 = refresh
        .inputs
        .iter()
        .filter_map(|input| input.witness_utxo.as_ref())
        .fold(0, |acc, utxo| acc.saturating_add(utxo.value.to_sat()));
    let total_out: u64 = refresh
        .unsigned_tx
        .output
        .iter()
        .fold(0, |acc, txout| acc.saturating_add(txout.value.to_sat()));
    let fee = total_in.saturating_sub(total_out);
    let vsize = refresh.unsigned_tx.vsize() as u64;
    if vsize == 0 {
        return None;
    }
    // Compare `fee` against `cap * vsize` directly (widened to u128 so the product
    // cannot overflow) rather than the truncated integer feerate `fee / vsize`:
    // integer division rounds DOWN, so a refresh paying `cap * vsize + (vsize - 1)`
    // sats computes a feerate exactly equal to the cap and would slip through above
    // the bound. `fee == cap * vsize` (exactly the cap) still passes.
    let cap_sats = u128::from(node.refresh_max_feerate).saturating_mul(u128::from(vsize));
    if u128::from(fee) > cap_sats {
        return Some(refusal(
            RefusalCode::RefreshFeeExceedsCap,
            "refresh_fee_cap",
            format!(
                "refresh pays {fee} sat over {vsize} vB, above the {} sat/vB refresh cap \
                 ({cap_sats} sat)",
                node.refresh_max_feerate
            ),
        ));
    }
    None
}

/// The pair of exact-byte-bound transactions one accepted `SpendRequest` produces
/// (§4), ready to register.
struct RegisterPair<'a> {
    spend: &'a Psbt,
    spend_commitment_id: &'a str,
    escape: &'a Psbt,
    escape_commitment_id: &'a str,
    /// The SPEND's fire window. The escape gets none (see [`register_pair`]).
    fire: channel::FireWindow,
    expiry: u64,
}

/// The §4 candidate-registry funnel: register the accepted request's **pair** —
/// the spend and its mandatory escape — as two distinct candidates, each bound to
/// its own exact-byte commitment, each already carrying this node's ingress
/// signature, each naming the other.
///
/// The spend carries `pair.fire`; the escape carries **no fire window at all**.
/// That asymmetry is the whole V0-8b/V0-4b seam: the escape is signed, registered,
/// and assembled-and-waiting, but nothing in this slice can release its partials,
/// because the release gate reads the fire window and finds `None`. V0-4b's duress
/// arm is what schedules it (at `T`), and it then rides this identical path — no
/// new release mechanism, no second code path to audit.
///
/// Absent-channel mode ⇒ a no-op (no registry, so no assembly). In channel mode,
/// capacity is preflighted for the whole pair and refuses the request atomically:
/// an acknowledgement without retained partials cannot complete now that the
/// coordinator is structurally unable to assemble. A live same-id candidate bound
/// to a different user signature, sighash, or sibling is likewise a refusal.
fn register_pair(node: &Node, pair: RegisterPair) -> Result<(), SignResponse> {
    let Some(channel) = &node.channel else {
        return Ok(());
    };
    let keys = channel::CandidateKeys {
        witness_script: &node.witness_script,
        user_pubkey: &node.user_pubkey,
        self_signing_pubkey: &node.pubkey,
    };
    let specs = [
        Some(channel::CandidateSpec {
            psbt: pair.spend,
            commitment_id: pair.spend_commitment_id,
            paired_commitment_id: pair.escape_commitment_id,
            role: channel::CandidateRole::Spend,
            fire: Some(pair.fire),
            expiry: pair.expiry,
        }),
        // An escape-class spend may be byte-identical to its mandatory escape.
        // The spend candidate already has the immediate fire window, so preserve
        // the existing one-candidate collapse rather than registering a second
        // incompatible role under the same exact key.
        (pair.escape_commitment_id != pair.spend_commitment_id).then_some(channel::CandidateSpec {
            psbt: pair.escape,
            commitment_id: pair.escape_commitment_id,
            paired_commitment_id: pair.spend_commitment_id,
            role: channel::CandidateRole::Escape,
            fire: None,
            expiry: pair.expiry,
        }),
    ];
    let mut candidates = Vec::new();
    let mut commitment_ids = Vec::new();
    for spec in specs.into_iter().flatten() {
        let commitment_id = spec.commitment_id.to_string();
        match channel::Candidate::build(spec, &keys) {
            Ok(candidate) => {
                commitment_ids.push(commitment_id);
                candidates.push(candidate);
            }
            Err(e) => {
                return Err(refusal(
                    RefusalCode::PsbtInconsistent,
                    "candidate_registration",
                    format!("cannot build candidate {commitment_id}: {e}"),
                ))
            }
        }
    }
    let outcomes = channel.register_candidates(candidates);
    if outcomes
        .iter()
        .any(|outcome| matches!(outcome, channel::RegisterOutcome::Conflict))
    {
        return Err(refusal(
            RefusalCode::PsbtInconsistent,
            "candidate_identity",
            "this commitment is already registered under a different user-signature instance, \
             sighash, or paired candidate"
                .into(),
        ));
    }
    if outcomes
        .iter()
        .any(|outcome| matches!(outcome, channel::RegisterOutcome::AtCapacity))
    {
        return Err(refusal(
            RefusalCode::CandidateCapacity,
            "candidate_registry_capacity",
            format!(
                "the bounded candidate registry cannot atomically retain request candidates: {}",
                commitment_ids.join(", ")
            ),
        ));
    }
    Ok(())
}

/// Reject a request before policy acceptance when its coordinator JSON fits the
/// `/sign` cap but its base64 channel envelope would not fit `max_msg_bytes`.
/// This is a transport-shape error (HTTP 400 / malformed peer payload), not a
/// policy refusal, and it occurs before signing, registration, authorization, or
/// propagation acceptance state is written (coordinator freshness was already
/// consumed by the trust-root gate).
fn ensure_request_propagatable(
    node: &Node,
    request: &vault_proto::TaggedRequest,
) -> Result<(), BadRequest> {
    let Some(channel) = node.channel.as_ref() else {
        return Ok(());
    };
    if channel::request_fits_channel_body(request, channel.max_msg_bytes()) {
        return Ok(());
    }
    Err(BadRequest(format!(
        "request expands beyond the configured channel max_msg_bytes ({})",
        channel.max_msg_bytes()
    )))
}

/// Replay identity for an ACCEPTED candidate set. Each entry binds both the
/// exact unsigned commitment id and the complete ingress PSBT serialization,
/// including the user-signature instance and mandatory pair bytes. Length
/// prefixes keep the encoding unambiguous.
fn acceptance_replay_key(candidates: &[(&str, &Psbt)]) -> String {
    let mut bytes = b"vault-policy/accepted-request/v0".to_vec();
    for (commitment_id, psbt) in candidates {
        let commitment_id = commitment_id.as_bytes();
        bytes.extend_from_slice(&(commitment_id.len() as u64).to_le_bytes());
        bytes.extend_from_slice(commitment_id);
        let psbt = psbt.serialize();
        bytes.extend_from_slice(&(psbt.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&psbt);
    }
    format!("accepted:{}", sha256::Hash::hash(&bytes))
}

/// The `commitment_id` this node binds `psbt` to at `expiry` — the registry key
/// its candidate lives under. Test-only: production code derives it inside the
/// handler, from the same [`commitment_of`].
#[cfg(test)]
pub(crate) fn commitment_id_for(node: &Node, psbt: &Psbt, expiry: u64) -> String {
    commitment_of(node, psbt, expiry).commitment_id()
}

/// Build the [`Commitment`] for `psbt` under this node's wallet, at the
/// coordinator-proposed `expiry`. Every transaction-identifying field —
/// `version`, `lock_time`, each input's outpoint and `sequence`, and the
/// outputs — is read from the node's OWN unsigned tx, so the commitment binds
/// the exact transaction (ADR-0012): two txs differing in any of them get
/// distinct ids. The fee is `Σ input value − Σ output value`,
/// taking input values from each `witness_utxo` (v0 trusts the PSBT's prevout
/// data — regtest, honest coordinator; DESIGN.md, per-node chain backend).
/// It is computed saturating and never fails: an inconsistent PSBT (missing
/// `witness_utxo`, outputs exceeding inputs) still gets a stable commitment id
/// here and its refusal downstream — and any change to a prevout amount yields
/// a different fee, hence a different id.
fn commitment_of(node: &Node, psbt: &Psbt, expiry: u64) -> Commitment {
    let inputs = psbt
        .unsigned_tx
        .input
        .iter()
        .map(|txin| CommitmentInput {
            txid: txin.previous_output.txid.to_byte_array(),
            vout: txin.previous_output.vout,
            // Read this input's nSequence from the node's OWN copy of the
            // unsigned tx (ADR-0012) — never a coordinator-supplied summary.
            sequence: txin.sequence.to_consensus_u32(),
        })
        .collect();
    let outputs = psbt
        .unsigned_tx
        .output
        .iter()
        .map(|txout| CommitmentOutput {
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
    Commitment {
        wallet_id: node.wallet_id,
        // nVersion and nLockTime, read from the node's own unsigned tx so the
        // commitment binds the exact transaction (ADR-0012).
        version: psbt.unsigned_tx.version.0,
        lock_time: psbt.unsigned_tx.lock_time.to_consensus_u32(),
        inputs,
        outputs,
        fee: total_in.saturating_sub(total_out),
        expiry,
        policy_version: node.policy_version,
    }
}

/// The coordinator-auth + freshness gate (ADR-0013 §2/§3): the ingress check
/// EVERY request passes BEFORE the PIN. A request is rejected unless it is validly
/// coord-signed over its canonical bytes against the node's configured
/// `coordinator_auth_pubkey`, carries a nonce this node has not seen, and has an
/// expiry that is neither past nor beyond `now + max_commitment_age_secs`. `Err`
/// carries the wire refusal. There is no un-gated mode: the key is mandatory
/// config, so an unauthenticated caller never reaches the PIN, let alone a signer.
///
/// The `coord_sig` binds every field of the canonical [`vault_proto::CoordRequest`]
/// variant (spend/escape/pin or refresh, plus nonce, expiry, policy_version), so
/// tampering with any of them fails verification here; the nonce is single-use,
/// so a captured request cannot be replayed once recorded. `nonces` is taken under
/// the one `/sign` lock, making the seen-check and record atomic with the rest of
/// the handler.
///
/// Order matters: freshness state changes ONLY after the signature verifies, so a
/// caller without the coordinator key cannot advance its monotonic clock or grow
/// the bounded nonce log.
///
/// The nonce and expiry come from `request` itself ([`CoordRequest::nonce`] /
/// [`CoordRequest::expiry`]), never as parameters beside it: taking them
/// separately would let this gate check freshness on values other than the ones
/// `coord_sig` authenticated. `coord_sig` is a parameter because it is the one
/// field that is NOT part of its own preimage.
fn verify_coord_auth(
    node: &Node,
    request: CoordRequest<'_>,
    coord_sig: &str,
    now: u64,
    nonces: &mut NonceLog,
) -> Result<(), SignResponse> {
    // Authentication: coord_sig must ECDSA-verify over the canonical request bytes
    // against the configured coordinator_auth_pubkey. An absent, non-hex, or
    // non-DER signature is an authentication failure like any other.
    let digest = request.auth_digest();
    let der = Vec::<u8>::from_hex(coord_sig).map_err(|_| {
        refusal(
            RefusalCode::CoordAuthInvalid,
            "coord_sig",
            "coord_sig is not hex".into(),
        )
    })?;
    let sig = Signature::from_der(&der).map_err(|_| {
        refusal(
            RefusalCode::CoordAuthInvalid,
            "coord_sig",
            "coord_sig is not a DER ECDSA signature".into(),
        )
    })?;
    Secp256k1::verification_only()
        .verify_ecdsa(
            &Message::from_digest(digest),
            &sig,
            &node.coordinator_auth.inner,
        )
        .map_err(|_| {
            refusal(
                RefusalCode::CoordAuthInvalid,
                "coord_sig",
                "coord_sig does not verify against the pinned coordinator_auth_pubkey".into(),
            )
        })?;
    // Sender authenticated. Validate the expiry window, reject replay, enforce
    // capacity, and consume the nonce in one operation under the sign-state lock.
    // Pruning and the matching high-water advance through the expiries actually
    // removed happen ONLY when the complete freshness gate accepts the request.
    // Window, replay, and capacity refusals leave both untouched, while the mark
    // prevents a backwards clock step from reopening a pruned nonce ([`NonceLog`]).
    match nonces.check_and_record(
        request.nonce(),
        request.expiry(),
        now,
        node.max_commitment_age_secs,
    ) {
        NonceDecision::Accepted => Ok(()),
        NonceDecision::InvalidLength => Err(refusal(
            RefusalCode::CoordAuthInvalid,
            "coord_nonce",
            format!("request nonce must be 1..={MAX_COORD_NONCE_BYTES} bytes"),
        )),
        NonceDecision::OutsideWindow { now } => Err(refusal(
            RefusalCode::CommitmentExpired,
            "commitment_expiry",
            format!(
                "expiry {} is outside the acceptance window (now {now}, max age {}s)",
                request.expiry(),
                node.max_commitment_age_secs
            ),
        )),
        NonceDecision::Replayed => Err(refusal(
            RefusalCode::NonceReplayed,
            "coord_nonce",
            "request nonce has already been seen by this node".into(),
        )),
        NonceDecision::AtCapacity => Err(refusal(
            RefusalCode::CoordNonceCapacity,
            "coord_nonce_capacity",
            "coordinator nonce cache is at capacity".into(),
        )),
    }
}

/// The V0-1 validation: verify the user's signatures, then run policy-core.
/// Does NOT sign — signing is deferred (handler step 8) so a hot-class spend
/// can be held first (ADR-0004). `Err` carries the wire refusal to return.
fn verify_spend(node: &Node, psbt: &Psbt) -> Result<(), SignResponse> {
    // The user's partial signature must cryptographically verify on every
    // input against the node's own recomputed sighash — presence of a
    // partial_sig is never enough (DESIGN.md, "Sighash enforcement"). This
    // subsumes the "no output mutation after authorization" check: any
    // mutation after signing changes the sighash and invalidates the very
    // signature the node verifies.
    verify_user_signatures(node, psbt)?;
    // The policy-core checks: input ownership, destination allowlist +
    // verified change, and the fee cap — all descriptor-derived. `evaluate`
    // also keeps its own consistency precondition for direct policy-core
    // callers.
    if let Err(v) = policy_core::evaluate(psbt, &node.check_params) {
        return Err(refusal(map_policy_code(v.code), v.check, v.detail));
    }
    Ok(())
}

/// Record `verdict` under its already-derived replay `key`, but only when that
/// identity fully determines it (see [`is_recordable_verdict`]). Takes the
/// already-locked replay log (the handler holds the one `SignState` lock across
/// its whole run), so recording stays inside the same critical section as the
/// idempotency check above it.
fn record_verdict(replay: &mut ReplayLog, key: &str, expiry: u64, verdict: &SignResponse) {
    if is_recordable_verdict(verdict) {
        replay.record(key.to_string(), expiry, verdict.clone());
    }
}

/// Validate the request's mandatory escape (§4). The node **validates** it; it
/// never **builds** it — that is what dissolves the cross-node byte-identical
/// construction problem, since all `n` nodes must add partials over the *identical*
/// bytes for them to combine at all.
///
/// Three checks, all against the bytes as provided:
///
///  - the user's signature verifies over the exact bytes (so the coordinator
///    cannot alter a coin, fee, or output afterward — [`verify_user_signatures`]);
///  - every input is a vault UTXO and the fee is capped (policy-core);
///  - every destination output pays the escape descriptor — i.e. it is genuinely
///    escape-class, not a hot spend wearing the escape's name.
///
/// The fire-time sweep-admissibility checks (value coverage, the feerate floor,
/// package acceptance) are deliberately NOT here: ADR-0012 makes them fire-time
/// checks on the sweep track, never gates at ingress, and the sweep itself is
/// V0-4b.
fn verify_escape(node: &Node, psbt: &Psbt) -> Result<(), SignResponse> {
    let escape_refusal = |code, check: &str, detail| {
        // Name the escape explicitly: a refusal an operator cannot attribute to
        // one of the request's two transactions is a refusal they cannot act on.
        refusal(code, &format!("escape:{check}"), detail)
    };
    if let Err(SignResponse::Refusal(r)) = verify_user_signatures(node, psbt) {
        return Err(escape_refusal(r.code, &r.check, r.detail));
    }
    if let Err(v) = policy_core::evaluate(psbt, &node.check_params) {
        return Err(escape_refusal(map_policy_code(v.code), v.check, v.detail));
    }
    match policy_core::classify(psbt, &node.check_params) {
        Ok(policy_core::TxClass::Escape) => Ok(()),
        Ok(other) => Err(escape_refusal(
            RefusalCode::PsbtInconsistent,
            "transaction_class",
            format!(
                "the request's escape is {other:?}-class: every destination output must pay \
                 the escape descriptor"
            ),
        )),
        Err(v) => Err(escape_refusal(map_policy_code(v.code), v.check, v.detail)),
    }
}

/// Whether `verdict` may be recorded in the anti-replay log for idempotent
/// replay. Refusals are keyed by `commitment_id`, which binds only the logical
/// spend (wallet, version, lock time, outpoints + sequences, outputs, fee,
/// expiry, policy_version) — never witness data. Accepted decisions are keyed by
/// [`acceptance_replay_key`], which additionally binds every candidate's complete
/// ingress PSBT. Only verdicts their chosen key fully determines are safe:
///
/// - `Accepted` — this node validated, signed, and registered this exact candidate
///   set, including its user-signature instance and mandatory escape. Replaying
///   the acknowledgement is the idempotency job, and it makes a coordinator retry
///   safe without letting a conflicting pair borrow the earlier acceptance.
/// - `DEST_NOT_ALLOWED` / `CHANGE_NOT_DERIVABLE` / `FEE_EXCEEDS_CAP` /
///   `PSBT_INCONSISTENT` from the class predicate — the policy refusals that turn
///   solely on the outputs and fee the commitment binds. Because the outputs are
///   commitment-bound, the same commitment can NEVER become an acceptance, so
///   caching the refusal cannot block an honest spend. (An untrusted bip32 change
///   label only decides `DEST_NOT_ALLOWED` vs `CHANGE_NOT_DERIVABLE`; both are
///   refusals, so replaying either stays safe.)
///
/// Refusals that depend on data the commitment does NOT bind — the signature
/// (`USER_SIG_INVALID`, `BAD_SIGHASH`), the PSBT structure, or the untrusted
/// `witness_utxo` prevout script (`UNKNOWN_INPUT`) — are NOT recorded: an
/// identical commitment resubmitted with corrected witness data could legitimately
/// be accepted, so caching would otherwise replay a stale refusal and block an
/// honest spend. The log does not defend the signature — V0-1's sighash binding
/// does (DESIGN.md, "What the anti-replay log is — and is not").
///
/// `EXPIRY_TOO_SHORT` and `REFRESH_*` are likewise unrecorded: each turns on the
/// node's CLOCK or on state outside the commitment (a pending spend, a coin's last
/// refresh), so the same commitment can legitimately earn a different verdict
/// later. Caching them would make a transient "not yet" permanent.
///
/// `PSBT_INCONSISTENT` is not recordable in general (it can come from witness
/// data), so the class refusals ride the general rule and are simply re-derived on
/// resubmission — cheap, and always right.
fn is_recordable_verdict(verdict: &SignResponse) -> bool {
    match verdict {
        SignResponse::Accepted(_) => true,
        SignResponse::Refusal(refusal) => matches!(
            refusal.code,
            RefusalCode::DestNotAllowed
                | RefusalCode::ChangeNotDerivable
                | RefusalCode::FeeExceedsCap
        ),
    }
}

fn decode_psbt(base64: &str, field: &str) -> Result<Psbt, BadRequest> {
    Psbt::from_str(base64.trim()).map_err(|e| BadRequest(format!("cannot decode {field}: {e}")))
}

fn refusal(code: RefusalCode, check: &str, detail: String) -> SignResponse {
    SignResponse::Refusal(Refusal {
        code,
        check: check.into(),
        detail,
    })
}

/// The terminal-Lockdown refusal (ADR-0008): every post-lockdown spend/refresh
/// presents as automated fraud prevention, never as "duress PIN used" — the story
/// is "the system locked itself; nobody can override it."
fn fraud_suspected() -> SignResponse {
    refusal(
        RefusalCode::FraudSuspected,
        "lockdown",
        "funds quarantined by policy".into(),
    )
}

/// The pin/lockout refusal. Uniform within each state so it leaks nothing about
/// which pin was submitted: while locked out, a correct pin (normal OR duress) gets
/// the IDENTICAL refusal a wrong pin would, so an attacker who floods a node into
/// lockout cannot then read the victim's pin off the response. Lockout is a
/// transient rate-limit, NOT Lockdown, so it stays a `BAD_PIN` denial that clears
/// after `lockout_secs`.
fn pin_refusal(locked: bool) -> SignResponse {
    if locked {
        refusal(
            RefusalCode::BadPin,
            "pin_attempt_budget",
            "pin attempts are rate-limited; this node is temporarily locked out".into(),
        )
    } else {
        refusal(
            RefusalCode::BadPin,
            "pin",
            "submitted PIN does not match an enrolled PIN".into(),
        )
    }
}

fn map_policy_code(code: policy_core::ViolationCode) -> RefusalCode {
    match code {
        policy_core::ViolationCode::UnknownInput => RefusalCode::UnknownInput,
        policy_core::ViolationCode::DestNotAllowed => RefusalCode::DestNotAllowed,
        policy_core::ViolationCode::ChangeNotDerivable => RefusalCode::ChangeNotDerivable,
        policy_core::ViolationCode::FeeExceedsCap => RefusalCode::FeeExceedsCap,
        policy_core::ViolationCode::PsbtInconsistent => RefusalCode::PsbtInconsistent,
    }
}

/// Cryptographically verify the user's partial signature on every input
/// before the node contributes its own (DESIGN.md, Policy model →
/// "Sighash enforcement"). For each input the node recomputes the P2WSH
/// sighash from its own full `and_v(v:pk(USER),multi(...))` witness script,
/// the `witness_utxo` amount, and sighash type ALL, then:
///
/// - requires a `partial_sig` under the configured user key
///   (absent → `USER_SIG_INVALID`);
/// - requires that signature to commit to SIGHASH_ALL — P2WSH has no
///   SIGHASH_DEFAULT (anything else → `BAD_SIGHASH`);
/// - ECDSA-verifies it against the recomputed sighash and the user pubkey
///   (invalid → `USER_SIG_INVALID`).
///
/// A stale, garbage, or wrong-key signature — and any output mutated after
/// the user signed — all fail here. `Err` carries the wire refusal to return.
fn verify_user_signatures(node: &Node, psbt: &Psbt) -> Result<(), SignResponse> {
    let secp = Secp256k1::verification_only();
    let mut cache = SighashCache::new(&psbt.unsigned_tx);
    for (index, input) in psbt.inputs.iter().enumerate() {
        // Amount comes from witness_utxo; without it no sighash exists to
        // verify against — a decodable-but-inconsistent PSBT.
        let utxo = input.witness_utxo.as_ref().ok_or_else(|| {
            refusal(
                RefusalCode::PsbtInconsistent,
                "user_signature",
                format!("input {index} has no witness_utxo; sighash cannot be computed"),
            )
        })?;
        let sighash = cache
            .p2wsh_signature_hash(
                index,
                &node.witness_script,
                utxo.value,
                EcdsaSighashType::All,
            )
            .map_err(|e| {
                refusal(
                    RefusalCode::PsbtInconsistent,
                    "user_signature",
                    format!("cannot compute sighash for input {index}: {e}"),
                )
            })?;
        let Some(sig) = input.partial_sigs.get(&node.user_pubkey) else {
            return Err(refusal(
                RefusalCode::UserSigInvalid,
                "user_signature",
                format!("input {index} carries no partial signature for the user key"),
            ));
        };
        if sig.sighash_type != EcdsaSighashType::All {
            return Err(refusal(
                RefusalCode::BadSighash,
                "user_signature",
                format!(
                    "input {index} user signature commits to {:?}, not SIGHASH_ALL",
                    sig.sighash_type
                ),
            ));
        }
        secp.verify_ecdsa(
            &Message::from_digest(sighash.to_byte_array()),
            &sig.signature,
            &node.user_pubkey.inner,
        )
        .map_err(|_| {
            refusal(
                RefusalCode::UserSigInvalid,
                "user_signature",
                format!(
                    "input {index} user signature does not verify against the recomputed sighash"
                ),
            )
        })?;
    }
    Ok(())
}

/// Add this node's partial signature to every input, signing the node's own
/// recomputed p2wsh sighash (SIGHASH_ALL) with its own witness script.
fn add_node_signatures(node: &Node, psbt: &mut Psbt) -> Result<(), String> {
    let secp = Secp256k1::signing_only();
    let unsigned_tx = psbt.unsigned_tx.clone();
    let mut cache = SighashCache::new(&unsigned_tx);
    for (index, input) in psbt.inputs.iter_mut().enumerate() {
        let utxo = input
            .witness_utxo
            .as_ref()
            .ok_or_else(|| format!("input {index} has no witness_utxo"))?;
        let sighash = cache
            .p2wsh_signature_hash(
                index,
                &node.witness_script,
                utxo.value,
                EcdsaSighashType::All,
            )
            .map_err(|e| format!("sighash for input {index}: {e}"))?;
        let signature =
            secp.sign_ecdsa(&Message::from_digest(sighash.to_byte_array()), &node.seckey);
        input.partial_sigs.insert(
            node.pubkey,
            bitcoin::ecdsa::Signature {
                signature,
                sighash_type: EcdsaSighashType::All,
            },
        );
    }
    Ok(())
}

#[cfg(test)]
mod watchtower_wiring {
    //! Node-level wiring for ADR-0012's watchtower recognition rule: the node
    //! recognizes a vault spend iff it VALIDATED AND POLICY-ACCEPTED it, and
    //! alerts otherwise. Classification and cursor edge cases live in
    //! `watchtower`'s own tests; this proves the `Node` glue.

    use bitcoin::hashes::Hash;
    use bitcoin::{OutPoint, Psbt, Txid};
    use std::str::FromStr;

    use crate::chain::{mock::MockBackend, SpendSeen};
    use crate::watchtower::AlertKind;
    use crate::Node;
    use vault_proto::{SignResponse, TaggedRequest};

    /// The shared fixture vault, having ACCEPTED one honest hot spend, plus that
    /// spend's txid. Acceptance — not signing — is what puts the txid in the
    /// node's authorized set, which is what the watchtower recognizes against.
    fn accepted_node() -> (Node, Txid) {
        let (node, request) = crate::test_support::node_and_valid_request();
        let psbt = Psbt::from_str(&request.psbt).expect("fixture psbt");
        // The fixture's expiry is set against the real clock, so this reads the
        // real clock too (`handle_sign_now`) rather than a fixed `NOW`.
        let SignResponse::Accepted(_) = crate::handle_sign_now(&node, &request).expect("decodable")
        else {
            panic!("the honest hot spend must be accepted");
        };
        (node, psbt.unsigned_tx.compute_txid())
    }

    fn vault_spend(node: &Node, spend_txid: Txid) -> SpendSeen {
        SpendSeen {
            spend_txid,
            outpoint: OutPoint::new(Txid::from_byte_array([7; 32]), 0),
            script: node.vault_scripts()[0].clone(),
        }
    }

    #[test]
    fn an_accepted_spend_is_recognized_and_an_unknown_one_alerts_through_events() {
        let (node, accepted) = accepted_node();

        // The accepted spend on chain is recognized: nothing queued.
        let known = MockBackend {
            spends: vec![vault_spend(&node, accepted)],
            ..Default::default()
        };
        assert_eq!(node.watchtower_tick(&known, 0).expect("scan"), 0);
        assert!(node.events(0).0.is_empty());

        // A vault spend the node never accepted is an UnrecognizedSpend.
        let foreign = Txid::from_byte_array([0xAB; 32]);
        let unknown = MockBackend {
            spends: vec![vault_spend(&node, foreign)],
            ..Default::default()
        };
        assert_eq!(node.watchtower_tick(&unknown, 0).expect("scan"), 1);
        let (alerts, cursor) = node.events(0);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].watchtower().kind, AlertKind::UnrecognizedSpend);
        assert_eq!(alerts[0].watchtower().spend_txid, foreign.to_string());
        assert_eq!(cursor, 1);
    }

    /// **The B5 recognition fix.** A spend this node policy-REFUSED must NOT count
    /// as recognized.
    ///
    /// This is the attack it closes: a thief fans their theft out to the honest
    /// nodes on purpose. Under a "recognized because I evaluated it" rule, every
    /// honest node would mark it recognized and stay silent — the theft would
    /// suppress its own alert, using the watchtower's own fan-out to do it. Under
    /// "recognized because I ACCEPTED it", the refusal keeps it out of the
    /// authorized set and every honest node alerts.
    #[test]
    fn a_spend_this_node_policy_refused_is_not_recognized_and_still_alerts() {
        let (node, request) = crate::test_support::node_and_valid_request();
        let theft = crate::test_support::theft_request(&node, &request);
        let theft_txid = Psbt::from_str(&theft.psbt)
            .expect("theft psbt")
            .unsigned_tx
            .compute_txid();

        // The node evaluates it in full and REFUSES it on the allowlist.
        let refusal = match crate::handle_sign_now(&node, &theft).expect("decodable") {
            SignResponse::Refusal(refusal) => refusal,
            other => panic!("the theft must be refused, got {other:?}"),
        };
        assert_eq!(refusal.code, vault_proto::RefusalCode::DestNotAllowed);
        assert!(
            !node
                .authorized
                .lock()
                .expect("authorized")
                .contains(&theft_txid),
            "a REFUSED spend must never enter the authorized set: it was evaluated, not accepted"
        );

        // The thief broadcasts it anyway. The node must alert.
        let backend = MockBackend {
            spends: vec![vault_spend(&node, theft_txid)],
            ..Default::default()
        };
        assert_eq!(
            node.watchtower_tick(&backend, 0).expect("scan"),
            1,
            "a theft fanned to an honest node must still alert — it cannot suppress its own alarm"
        );
        let (alerts, _) = node.events(0);
        assert_eq!(alerts[0].watchtower().kind, AlertKind::UnrecognizedSpend);
        assert_eq!(alerts[0].watchtower().spend_txid, theft_txid.to_string());
    }

    /// The other half of the same fix: recognition is NOT co-signing. In a
    /// `t`-of-`n` only `t` nodes sign any spend, so keying the alert off the
    /// co-signed set false-alarms on the `n−t` honest non-signers. Here the node
    /// accepted the spend and never released a partial to anyone (no fire event has
    /// arrived) — and it must still recognize it.
    #[test]
    fn recognition_does_not_require_this_node_to_have_signed_into_the_quorum() {
        let (node, request) = crate::test_support::node_and_valid_request();
        let psbt = Psbt::from_str(&request.psbt).expect("fixture psbt");
        assert!(matches!(
            crate::handle_sign_now(&node, &request).expect("decodable"),
            SignResponse::Accepted(_)
        ));
        // This node is channel-less: it has no peers, released nothing, and is in
        // no combine set. Recognition rests on ACCEPTANCE alone.
        assert!(node.channel.is_none());
        let backend = MockBackend {
            spends: vec![vault_spend(&node, psbt.unsigned_tx.compute_txid())],
            ..Default::default()
        };
        assert_eq!(
            node.watchtower_tick(&backend, 0).expect("scan"),
            0,
            "a spend this node accepted raises nothing, whether or not it signed into the quorum"
        );
    }

    /// The escape of every accepted request is authorized too: it was validated and
    /// accepted at the same ingress, so if V0-4b ever fires it, the node's own
    /// watchtower must not alarm on its own sweep.
    #[test]
    fn the_accepted_requests_escape_is_recognized_as_well() {
        let (node, request) = crate::test_support::node_and_valid_request();
        let escape_txid = Psbt::from_str(&request.escape_psbt)
            .expect("escape psbt")
            .unsigned_tx
            .compute_txid();
        assert!(matches!(
            crate::handle_sign_now(&node, &request).expect("decodable"),
            SignResponse::Accepted(_)
        ));
        let backend = MockBackend {
            spends: vec![vault_spend(&node, escape_txid)],
            ..Default::default()
        };
        assert_eq!(node.watchtower_tick(&backend, 0).expect("scan"), 0);
    }

    /// A propagated request reaches recognition too: the node ran its own gates on
    /// it, so a spend it learned from a PEER is recognized exactly as one the
    /// coordinator delivered. Without this, `n−1` nodes would alert on every spend
    /// the coordinator happened to deliver to only one of them.
    #[test]
    fn a_request_learned_from_a_peer_is_recognized_after_this_node_validates_it() {
        let (node, request) = crate::test_support::node_and_valid_request();
        let psbt = Psbt::from_str(&request.psbt).expect("fixture psbt");
        // Exactly what `handle_channel_body` does with a propagated request: run
        // this node's own gates over it.
        let tagged = TaggedRequest::Spend(request);
        let TaggedRequest::Spend(spend) = &tagged else {
            unreachable!("built as a spend")
        };
        assert!(matches!(
            crate::handle_sign_now(&node, spend).expect("decodable"),
            SignResponse::Accepted(_)
        ));
        let backend = MockBackend {
            spends: vec![vault_spend(&node, psbt.unsigned_tx.compute_txid())],
            ..Default::default()
        };
        assert_eq!(node.watchtower_tick(&backend, 0).expect("scan"), 0);
    }
}

/// Shared test fixtures: a signable node and a valid `SignRequest`. Used by the
/// `server` HTTP regression tests, which drive the real handler over a real
/// socket (so the handler reads the system clock, unlike the direct-call unit
/// tests that pass a fixed `now`). Mirrors `watchtower_wiring::signed_node`'s
/// vault.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::hex::DisplayHex;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn key(i: u8) -> (SecretKey, PublicKey) {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[i; 32]).expect("32 nonzero bytes");
        (sk, PublicKey::new(sk.public_key(&secp)))
    }

    /// The coordinator this fixture's vault is sealed to (ADR-0013 §2).
    fn coord_key() -> (SecretKey, PublicKey) {
        key(0xC0)
    }

    /// A full absent-channel config with the three timing bounds parameterized and
    /// `extra` appended verbatim — used to exercise the load-time combine-window
    /// invariants (`combine_slack_secs > 0`, `hold + slack <= max_commitment_age`).
    pub(crate) fn config_with_bounds(
        hold_secs: u64,
        max_commitment_age_secs: u64,
        extra: &str,
    ) -> String {
        let (_, user) = key(1);
        let (nsk, node_pub) = key(2);
        let (_, hot_key) = key(10);
        let (_, escape_key) = key(11);
        let descriptor = format!("wsh(and_v(v:pk({user}),multi(1,{node_pub})))");
        format!(
            "listen_port = 0\nnode_seckey = \"{}\"\ndescriptor = \"{descriptor}\"\n\
             allowlist = [\"wpkh({hot_key})\", \"wpkh({escape_key})\"]\n\
             escape_descriptor = \"wpkh({escape_key})\"\n\
             max_derivation_index = 5\nhold_secs = {hold_secs}\n\
             max_commitment_age_secs = {max_commitment_age_secs}\npolicy_version = 1\n\
             pin_normal_hash = \"{}\"\npin_duress_hash = \"{}\"\n\
             coordinator_auth_pubkey = \"{}\"\n{extra}",
            nsk.display_secret(),
            argon2id_normal_phc("1234"),
            argon2id_duress_phc("9999"),
            coord_key().1,
        )
    }

    /// Attach a fresh `nonce` and the coordinator signature over the canonical
    /// request bytes — exactly what vault-cli does before relaying. Every request
    /// must clear the ingress coord-auth gate, so tests that RE-send a request
    /// (a coordinator retrying a timed-out or lost call) re-sign with a fresh
    /// nonce: the nonce is single-use per transmission, while idempotency lives on
    /// the commitment, so the same spend re-sent this way still returns the one
    /// recorded verdict from the anti-replay log.
    pub(crate) fn coord_sign(request: &mut SignRequest, nonce: &str) {
        request.nonce = nonce.to_string();
        // `coord_request()` selects the signed fields; coord_sig is never part of
        // its own preimage, so it needs no clearing before the digest.
        let digest = request.coord_request().auth_digest();
        let sig = Secp256k1::new().sign_ecdsa(&Message::from_digest(digest), &coord_key().0);
        request.coord_sig = sig.serialize_der().to_lower_hex_string();
    }

    /// Refresh counterpart to [`coord_sign`]: the same coordinator key and
    /// freshness contract, over the Refresh variant's canonical bytes.
    pub(crate) fn coord_sign_refresh(request: &mut RefreshRequest, nonce: &str) {
        request.nonce = nonce.to_string();
        let digest = request.coord_request().auth_digest();
        let sig = Secp256k1::new().sign_ecdsa(&Message::from_digest(digest), &coord_key().0);
        request.coord_sig = sig.serialize_der().to_lower_hex_string();
    }

    fn user_sign(node: &Node, psbt: &mut Psbt) {
        let value = psbt.inputs[0]
            .witness_utxo
            .as_ref()
            .expect("witness utxo")
            .value;
        let sighash = SighashCache::new(&psbt.unsigned_tx)
            .p2wsh_signature_hash(0, &node.witness_script, value, EcdsaSighashType::All)
            .expect("sighash");
        let signature =
            Secp256k1::new().sign_ecdsa(&Message::from_digest(sighash.to_byte_array()), &key(1).0);
        psbt.inputs[0].partial_sigs.clear();
        psbt.inputs[0].partial_sigs.insert(
            node.user_pubkey,
            bitcoin::ecdsa::Signature {
                signature,
                sighash_type: EcdsaSighashType::All,
            },
        );
    }

    /// Derive a valid pin-less refresh from the fixture spend: only the output is
    /// changed to pay the vault, then the user and coordinator re-sign the exact
    /// refresh bytes.
    pub(crate) fn valid_refresh_request(
        node: &Node,
        spend: &SignRequest,
        nonce: &str,
    ) -> RefreshRequest {
        let mut psbt = Psbt::from_str(&spend.psbt).expect("fixture psbt");
        psbt.unsigned_tx.output[0].script_pubkey = node.vault_scripts()[0].clone();
        // A realistic self-spend fee. The fixture spend's flat 10_000 sat would
        // read as ~106 sat/vB over this tiny transaction and trip the refresh fee
        // cap (ADR-0013 §6) — correctly: a real refresh pays a normal feerate.
        psbt.unsigned_tx.output[0].value = Amount::from_sat(99_999_000);
        user_sign(node, &mut psbt);
        let mut request = RefreshRequest {
            refresh_psbt: psbt.to_string(),
            nonce: String::new(),
            expiry: spend.expiry,
            policy_version: spend.policy_version,
            coord_sig: String::new(),
        };
        coord_sign_refresh(&mut request, nonce);
        request
    }

    /// A 1-of-1 vault (user key + one node key, `hold_secs = 0`) bound to
    /// `listen_port = 0`, plus a valid, coordinator-signed hot-spend `SignRequest`
    /// that `handle_sign` signs on first submission. The request's `expiry` is set
    /// against the REAL clock and sits well inside `max_commitment_age_secs`. The
    /// enrolled normal pin is `1234`, the duress pin `9999`.
    pub(crate) fn node_and_valid_request() -> (Node, SignRequest) {
        node_and_valid_request_with_budget("")
    }

    /// [`node_and_valid_request`] with an explicit `[pin_attempt_budget]` TOML block
    /// appended (empty ⇒ the defaulted budget), so the attempt-budget tests can
    /// enrol a small `max_attempts` with a zero backoff (no real sleeping).
    pub(crate) fn node_and_valid_request_with_budget(budget_toml: &str) -> (Node, SignRequest) {
        let (_, user) = key(1);
        let (nsk, node_pub) = key(2);
        let (_, hot_key) = key(10);
        let (_, escape_key) = key(11);
        let descriptor = format!("wsh(and_v(v:pk({user}),multi(1,{node_pub})))");
        let hot = Descriptor::<DescriptorPublicKey>::from_str(&format!("wpkh({hot_key})"))
            .expect("hot descriptor");
        let escape = Descriptor::<DescriptorPublicKey>::from_str(&format!("wpkh({escape_key})"))
            .expect("escape descriptor");
        let hot_spk = hot
            .at_derivation_index(0)
            .expect("definite")
            .script_pubkey();
        let config = format!(
            "listen_port = 0\nnode_seckey = \"{}\"\ndescriptor = \"{descriptor}\"\n\
             allowlist = [\"{hot}\", \"{escape}\"]\nescape_descriptor = \"{escape}\"\n\
             max_derivation_index = 5\nhold_secs = 0\n\
             max_commitment_age_secs = 172800\npolicy_version = 1\n\
             pin_normal_hash = \"{}\"\npin_duress_hash = \"{}\"\n\
             coordinator_auth_pubkey = \"{}\"\n{budget_toml}",
            nsk.display_secret(),
            argon2id_normal_phc("1234"),
            argon2id_duress_phc("9999"),
            coord_key().1,
        );
        let node = Node::from_toml_str(&config).expect("valid config");
        let escape_spk = escape
            .at_derivation_index(0)
            .expect("definite")
            .script_pubkey();
        // The spend and its MANDATORY escape (§4): one vault input, paid to the hot
        // wallet and to the escape wallet respectively. Both user-signed, as a real
        // coordinator composes them.
        let spend = spend_to(&node, hot_spk);
        let escape_psbt = spend_to(&node, escape_spk);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut request = SignRequest {
            psbt: spend.to_string(),
            escape_psbt: escape_psbt.to_string(),
            pin: "1234".into(),
            nonce: String::new(),
            expiry: now + 3_600,
            policy_version: 1,
            coord_sig: String::new(),
        };
        coord_sign(&mut request, "test-support-first-send");
        (node, request)
    }

    /// The fixture spend redirected to a NON-allowlisted destination, re-signed by
    /// the user and the coordinator over the theft's exact bytes. Everything a
    /// thief holding the user key and the PIN can produce; only the allowlist stops
    /// it, so the node's verdict is `DEST_NOT_ALLOWED` and nothing else.
    pub(crate) fn theft_request(node: &Node, spend: &SignRequest) -> SignRequest {
        let mut psbt = Psbt::from_str(&spend.psbt).expect("fixture psbt");
        // A P2WSH of a hash no descriptor in this vault can derive.
        psbt.unsigned_tx.output[0].script_pubkey =
            ScriptBuf::new_p2wsh(&bitcoin::WScriptHash::from_byte_array([0xEE; 32]));
        user_sign(node, &mut psbt);
        let mut request = SignRequest {
            psbt: psbt.to_string(),
            ..spend.clone()
        };
        coord_sign(&mut request, "test-support-theft");
        request
    }

    /// A user-signed one-input vault spend paying `dest_spk`.
    fn spend_to(node: &Node, dest_spk: ScriptBuf) -> Psbt {
        let value = Amount::from_sat(100_000_000);
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([7; 32]), 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                script_pubkey: dest_spk,
                value: Amount::from_sat(99_990_000),
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).expect("unsigned tx");
        psbt.inputs[0].witness_utxo = Some(TxOut {
            script_pubkey: node.vault_scripts()[0].clone(),
            value,
        });
        psbt.inputs[0].witness_script = Some(node.witness_script.clone());
        user_sign(node, &mut psbt);
        psbt
    }
}

#[cfg(test)]
mod commitment_parity_tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version;
    use bitcoin::Sequence;

    #[test]
    fn commitment_serialization_round_trips_and_id_is_stable() {
        // T4 round-trip: the canonical encoding is deterministic and total, so
        // a commitment that is serialized and deserialized re-derives the
        // identical `commitment_id`. (A hand-copied "coordinator" builder was
        // dropped in review — with no independent producer before V0-8 it only
        // tested a copy against itself; the real coordinator-vs-node parity
        // test lands in V0-8a where vault-cli first builds a Commitment. The
        // three mutation tests below carry the load-bearing proof that each new
        // tx field changes the id.)
        let (node, request) = test_support::node_and_valid_request();
        let psbt = Psbt::from_str(&request.psbt).expect("coordinator PSBT");
        let built = commitment_of(&node, &psbt, request.expiry);
        let id = built.commitment_id();

        let json = serde_json::to_string(&built).expect("serialize commitment");
        let restored: Commitment = serde_json::from_str(&json).expect("deserialize commitment");

        assert_eq!(
            restored, built,
            "serde round-trip must preserve the commitment value"
        );
        assert_eq!(
            restored.commitment_id(),
            id,
            "serde round-trip must preserve the canonical commitment id"
        );
    }

    #[test]
    fn changing_only_tx_version_changes_the_commitment_id() {
        let (node, request) = test_support::node_and_valid_request();
        let base = Psbt::from_str(&request.psbt).expect("coordinator PSBT");
        let mut variant = base.clone();
        variant.unsigned_tx.version = Version::ONE;

        assert_ne!(
            commitment_of(&node, &base, request.expiry).commitment_id(),
            commitment_of(&node, &variant, request.expiry).commitment_id(),
            "nVersion must change the commitment id"
        );
    }

    #[test]
    fn changing_only_lock_time_changes_the_commitment_id() {
        let (node, request) = test_support::node_and_valid_request();
        let base = Psbt::from_str(&request.psbt).expect("coordinator PSBT");
        let mut variant = base.clone();
        variant.unsigned_tx.lock_time = LockTime::from_consensus(500_000);

        assert_ne!(
            commitment_of(&node, &base, request.expiry).commitment_id(),
            commitment_of(&node, &variant, request.expiry).commitment_id(),
            "nLockTime must change the commitment id"
        );
    }

    #[test]
    fn changing_only_one_input_sequence_changes_the_commitment_id() {
        let (node, request) = test_support::node_and_valid_request();
        let base = Psbt::from_str(&request.psbt).expect("coordinator PSBT");
        let mut variant = base.clone();
        variant.unsigned_tx.input[0].sequence = Sequence::from_consensus(0xffff_fffd);

        assert_ne!(
            commitment_of(&node, &base, request.expiry).commitment_id(),
            commitment_of(&node, &variant, request.expiry).commitment_id(),
            "a single input's nSequence must change the commitment id"
        );
    }
}

#[cfg(test)]
mod config_bounds_tests {
    use super::test_support::config_with_bounds;
    use super::Node;

    /// A zero-width combine window is a silent broadcast trap, so it is a fatal
    /// config, not a runtime surprise.
    #[test]
    fn a_zero_combine_slack_is_a_fatal_config() {
        let err = Node::from_toml_str(&config_with_bounds(0, 172_800, "combine_slack_secs = 0\n"))
            .err()
            .expect("zero combine slack must be rejected at load");
        assert!(
            err.to_string().contains("combine_slack_secs"),
            "unexpected config error: {err}"
        );
    }

    /// Zero makes every refresh mark prune immediately and the interval predicate
    /// impossible to trip, disabling ADR-0013 §6's burn-rate bound.
    #[test]
    fn a_zero_refresh_interval_is_a_fatal_config() {
        let err = Node::from_toml_str(&config_with_bounds(
            0,
            172_800,
            "refresh_min_interval_secs = 0\n",
        ))
        .err()
        .expect("zero refresh interval must be rejected at load");
        assert!(
            err.to_string().contains("refresh_min_interval_secs"),
            "unexpected config error: {err}"
        );
    }

    /// If the EXPIRY_TOO_SHORT floor (`hold + slack`) exceeds the node's own expiry
    /// cap, every hot spend is silently refused — also a fatal config.
    #[test]
    fn hold_plus_slack_past_max_commitment_age_is_a_fatal_config() {
        let err = Node::from_toml_str(&config_with_bounds(
            0,
            172_800,
            "combine_slack_secs = 200000\n",
        ))
        .err()
        .expect("hold + slack past the expiry cap must be rejected at load");
        let err = err.to_string();
        assert!(
            err.contains("combine_slack_secs") && err.contains("max_commitment_age_secs"),
            "unexpected config error: {err}"
        );
    }

    /// The default combine slack (60) leaves a usable window, so the same config
    /// with no override loads.
    #[test]
    fn the_default_combine_slack_still_loads() {
        Node::from_toml_str(&config_with_bounds(0, 172_800, ""))
            .expect("a config on the default combine slack is valid");
    }

    /// Security-sensitive top-level options must fail closed when misspelled,
    /// rather than being silently ignored by serde.
    #[test]
    fn an_unknown_top_level_config_field_is_fatal() {
        let err = Node::from_toml_str(&config_with_bounds(
            0,
            172_800,
            "max_commitment_age_sec = 86400\n",
        ))
        .err()
        .expect("an unknown top-level field must be rejected at load");
        assert!(
            err.to_string().contains("max_commitment_age_sec"),
            "unexpected config error: {err}"
        );
    }

    /// A misspelled budget key must not fall back to the default attempt limit.
    #[test]
    fn an_unknown_pin_attempt_budget_field_is_fatal() {
        let err = Node::from_toml_str(&config_with_bounds(
            0,
            172_800,
            "[pin_attempt_budget]\nmax_attemps = 2\n",
        ))
        .err()
        .expect("an unknown pin-attempt-budget field must be rejected at load");
        assert!(
            err.to_string().contains("max_attemps"),
            "unexpected config error: {err}"
        );
    }
}

#[cfg(test)]
mod sign_clock_tests {
    use super::{handle_sign_after_lock, test_support::node_and_valid_request};
    use std::sync::{mpsc, Arc};
    use std::time::Duration;

    #[test]
    fn queued_sign_reads_the_clock_only_after_acquiring_sign_state() {
        let (node, request) = node_and_valid_request();
        let now = request.expiry;
        let node = Arc::new(node);
        let worker_node = Arc::clone(&node);
        let state = node.sign_state.lock().expect("sign_state lock");
        let (started_tx, started_rx) = mpsc::channel();
        let (clock_tx, clock_rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            started_tx.send(()).expect("worker started");
            handle_sign_after_lock(&worker_node, &request, || {
                clock_tx.send(()).expect("clock read");
                now
            })
        });

        started_rx.recv().expect("worker start");
        assert!(clock_rx.recv_timeout(Duration::from_millis(50)).is_err());
        drop(state);
        clock_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("clock read after lock");
        worker
            .join()
            .expect("worker thread")
            .expect("valid request");
    }
}

/// V0-4a substrate: the constant-cost pin compare, the per-node attempt budget, and
/// terminal Lockdown, exercised through the real `handle_sign`/`handle_refresh`
/// handlers. The transition-table arithmetic and the digest validation live in
/// [`pin`]'s own unit tests; this module proves the node GLUE — that the handler
/// runs two Argon2 evaluations per SpendRequest, charges the budget only on wrong
/// pins, refuses a locked-out node while still arming under a valid duress pin, and
/// answers FRAUD_SUSPECTED once locked down.
#[cfg(test)]
mod pin_substrate_tests {
    use super::pin::{PinEvaluator, PinSlot};
    use super::test_support::{
        coord_sign, node_and_valid_request, node_and_valid_request_with_budget,
        valid_refresh_request,
    };
    use super::{handle_refresh, handle_sign, Node};
    use std::sync::Arc;
    use subtle::Choice;
    use vault_proto::{RefusalCode, SignRequest, SignResponse, MAX_PIN_BYTES};

    /// The normal pin every fixture node enrols (`node_and_valid_request`).
    const NORMAL: &str = "1234";
    /// The enrolled duress pin.
    const DURESS: &str = "9999";
    /// A pin that matches neither.
    const WRONG: &str = "0000";

    /// A small attempt budget with a ZERO backoff, so the handler tests exercise
    /// lockout without any real sleeping.
    const SMALL_BUDGET: &str = "[pin_attempt_budget]\nmax_attempts = 3\nwindow_secs = 3600\n\
         backoff_schedule = [0, 0, 0]\nlockout_secs = 100\n";

    /// Clone `base`, set `pin`, and re-coord-sign under a fresh `nonce` (changing the
    /// pin invalidates the coordinator signature, since the pin is in its preimage).
    fn with_pin(base: &SignRequest, pin: &str, nonce: &str) -> SignRequest {
        let mut request = base.clone();
        request.pin = pin.into();
        coord_sign(&mut request, nonce);
        request
    }

    fn expect_refusal(response: SignResponse) -> vault_proto::Refusal {
        match response {
            SignResponse::Refusal(refusal) => refusal,
            other => panic!("expected refusal, got {other:?}"),
        }
    }

    /// PRIMARY structural constant-cost test: every SpendRequest — normal, duress, or
    /// wrong — runs EXACTLY two Argon2 evaluations, in the fixed order [Normal,
    /// Duress]. A short-circuit compare would make duress run only one (or one
    /// more), which the counting evaluator would catch here without a flaky clock.
    #[test]
    fn every_spendrequest_runs_two_argon2_evaluations_in_a_fixed_order() {
        use super::pin::test_util::CountingEvaluator;
        let (mut node, base) = node_and_valid_request();
        let now = base.expiry - 3_600;
        let counting = Arc::new(CountingEvaluator::new(node.pin_evaluator()));
        let calls = Arc::clone(&counting.calls);
        node.set_pin_evaluator(counting);

        for (i, pin) in [NORMAL, DURESS, WRONG].into_iter().enumerate() {
            calls.lock().expect("calls").clear();
            let request = with_pin(&base, pin, &format!("count-{i}"));
            let _ = handle_sign(&node, &request, now).expect("decodable");
            assert_eq!(
                *calls.lock().expect("calls"),
                vec![PinSlot::Normal, PinSlot::Duress],
                "pin {pin} must run exactly two Argon2 evaluations, Normal then Duress"
            );
        }

        calls.lock().expect("calls").clear();
        let over_length = "x".repeat(MAX_PIN_BYTES + 1);
        let request = with_pin(&base, &over_length, "count-over-length");
        let _ = handle_sign(&node, &request, now).expect("decodable");
        assert_eq!(
            *calls.lock().expect("calls"),
            vec![PinSlot::Normal, PinSlot::Duress],
            "an over-length authenticated SpendRequest must not bypass either evaluation"
        );
    }

    /// An omitted PIN decodes as empty. Even if provisioning enrolled the empty
    /// plaintext, the protocol boundary must classify it as Wrong only AFTER both
    /// evaluations, so omission can never authenticate or bypass the budget.
    #[test]
    fn an_empty_pin_is_wrong_even_if_the_enrolled_normal_digest_matches_it() {
        struct EmptyMatchesNormal;

        impl PinEvaluator for EmptyMatchesNormal {
            fn evaluate(&self, slot: PinSlot, pin: &[u8]) -> Choice {
                Choice::from((slot == PinSlot::Normal && pin.is_empty()) as u8)
            }
        }

        use super::pin::test_util::CountingEvaluator;
        let (mut node, base) = node_and_valid_request();
        let counting = Arc::new(CountingEvaluator::new(Arc::new(EmptyMatchesNormal)));
        let calls = Arc::clone(&counting.calls);
        node.set_pin_evaluator(counting);

        let response = handle_sign(
            &node,
            &with_pin(&base, "", "empty-enrolled-normal"),
            base.expiry - 3_600,
        )
        .expect("decodable");
        assert_eq!(expect_refusal(response).code, RefusalCode::BadPin);
        assert_eq!(
            *calls.lock().expect("calls"),
            vec![PinSlot::Normal, PinSlot::Duress],
            "empty input still performs both fixed-order evaluations"
        );
        assert_eq!(
            node.sign_state
                .lock()
                .expect("sign_state")
                .pin_budget
                .fails(),
            1,
            "empty input consumes the wrong-pin budget"
        );
        assert_eq!(node.duress_arm_count(), 0, "empty input never arms duress");
    }

    /// Budget instrumentation: the budget is touched exactly once per SpendRequest,
    /// and normal and duress leave IDENTICAL budget state (both no-ops) — only a
    /// wrong pin changes the logical wrong-count. This is the same-shaped-work
    /// property (codex C3): the two SILENT classes are indistinguishable in the
    /// budget, and only a wrong pin (which is neither PIN) diverges.
    #[test]
    fn the_budget_is_charged_once_and_normal_equals_duress() {
        let read = |node: &Node| {
            let state = node.sign_state.lock().expect("sign_state");
            (
                state.pin_budget.charges(),
                state.pin_budget.fails(),
                state.pin_budget.locked_until(),
            )
        };

        let (node_n, base_n) = node_and_valid_request();
        let now = base_n.expiry - 3_600;
        handle_sign(&node_n, &with_pin(&base_n, NORMAL, "n"), now).expect("decodable");

        let (node_d, base_d) = node_and_valid_request();
        handle_sign(&node_d, &with_pin(&base_d, DURESS, "d"), now).expect("decodable");

        let (node_w, base_w) = node_and_valid_request();
        handle_sign(&node_w, &with_pin(&base_w, WRONG, "w"), now).expect("decodable");

        assert_eq!(
            read(&node_n),
            (1, 0, 0),
            "a normal pin charges once and consumes nothing"
        );
        assert_eq!(
            read(&node_n),
            read(&node_d),
            "normal and duress leave identical budget state — no observable difference"
        );
        assert_eq!(
            read(&node_w),
            (1, 1, 0),
            "only a wrong pin advances the wrong-count"
        );
    }

    /// The attempt-budget lifecycle through the handler (the normative table): a
    /// wrong-pin flood reaches lockout; a locked-out node refuses a valid NORMAL pin
    /// while a valid DURESS pin STILL invokes the arm-hook (fail-closed); and the
    /// node recovers after `lockout_secs`.
    #[test]
    fn wrong_pin_flood_locks_out_then_recovers_and_duress_still_arms_while_locked() {
        let (node, base) = node_and_valid_request_with_budget(SMALL_BUDGET);
        let now = base.expiry - 3_600;

        // Three wrong pins (max_attempts = 3) trip the lockout.
        for i in 0..3 {
            let refusal = expect_refusal(
                handle_sign(&node, &with_pin(&base, WRONG, &format!("wrong-{i}")), now)
                    .expect("decodable"),
            );
            assert_eq!(refusal.code, RefusalCode::BadPin, "a wrong pin is BAD_PIN");
        }

        // A valid NORMAL pin is now refused (locked out) — and its refusal is the
        // same BAD_PIN a wrong pin gets, so lockout leaks nothing about the pin.
        let locked_normal = expect_refusal(
            handle_sign(&node, &with_pin(&base, NORMAL, "normal-locked"), now).expect("decodable"),
        );
        assert_eq!(locked_normal.code, RefusalCode::BadPin);
        assert_eq!(
            locked_normal.check, "pin_attempt_budget",
            "a locked-out refusal is a rate-limit denial, not an ordinary bad pin"
        );

        // A valid DURESS pin is ALSO refused while locked, but STILL arms (fail-closed).
        let arm_before = node.duress_arm_count();
        let locked_duress = expect_refusal(
            handle_sign(&node, &with_pin(&base, DURESS, "duress-locked"), now).expect("decodable"),
        );
        assert_eq!(locked_duress.code, RefusalCode::BadPin);
        assert_eq!(
            node.duress_arm_count(),
            arm_before + 1,
            "a valid duress pin must arm even when the node is locked out (fail-closed)"
        );

        // After lockout_secs the node recovers and a valid normal pin signs again.
        let recovered = handle_sign(
            &node,
            &with_pin(&base, NORMAL, "normal-recovered"),
            now + 100,
        )
        .expect("decodable");
        assert!(
            matches!(recovered, SignResponse::Accepted(_)),
            "the node must recover after lockout_secs: got {recovered:?}"
        );
    }

    /// Fail-closed / subordination: a pin-less refresh never touches the pin budget
    /// (it performs no pin compare at all — codex C2), so a refresh flood can neither
    /// consume the budget nor lock the node out of signing.
    #[test]
    fn a_refresh_never_touches_the_pin_budget() {
        let (node, spend) = node_and_valid_request();
        let refresh = valid_refresh_request(&node, &spend, "refresh-budget");
        let now = spend.expiry - 3_600;
        let response = handle_refresh(&node, &refresh, now).expect("decodable");
        assert!(
            matches!(response, SignResponse::Accepted(_)),
            "the refresh is valid"
        );
        assert_eq!(
            node.sign_state
                .lock()
                .expect("sign_state")
                .pin_budget
                .charges(),
            0,
            "the pin-less refresh path performs NO pin compare and cannot touch the budget"
        );
    }

    /// Lockdown is terminal (ADR-0008): once entered, every spend AND refresh answers
    /// FRAUD_SUSPECTED for the node's lifetime, with no reset.
    #[test]
    fn lockdown_refuses_every_spend_and_refresh_with_fraud_suspected() {
        let (node, spend) = node_and_valid_request();
        let refresh = valid_refresh_request(&node, &spend, "lockdown-refresh");
        let now = spend.expiry - 3_600;

        node.enter_lockdown();

        let spend_refusal = expect_refusal(
            handle_sign(&node, &with_pin(&spend, NORMAL, "ld-spend"), now).expect("decodable"),
        );
        assert_eq!(spend_refusal.code, RefusalCode::FraudSuspected);
        let refresh_refusal =
            expect_refusal(handle_refresh(&node, &refresh, now).expect("decodable"));
        assert_eq!(refresh_refusal.code, RefusalCode::FraudSuspected);

        // No reset: a second attempt is still FRAUD_SUSPECTED.
        assert!(node.is_locked_down());
        let again = expect_refusal(
            handle_sign(&node, &with_pin(&spend, NORMAL, "ld-again"), now).expect("decodable"),
        );
        assert_eq!(again.code, RefusalCode::FraudSuspected);
    }

    /// A locked-down node does not even reach the budget: FRAUD_SUSPECTED short-
    /// circuits before the pin compare, so Lockdown is not gated by (nor does it
    /// interact with) the attempt budget.
    #[test]
    fn lockdown_short_circuits_before_the_pin_budget() {
        let (node, spend) = node_and_valid_request();
        let now = spend.expiry - 3_600;
        node.enter_lockdown();
        handle_sign(&node, &with_pin(&spend, WRONG, "ld-wrong"), now).expect("decodable");
        assert_eq!(
            node.sign_state
                .lock()
                .expect("sign_state")
                .pin_budget
                .charges(),
            0,
            "Lockdown answers FRAUD_SUSPECTED before any pin/budget work runs"
        );
    }

    /// The config-validation wiring: a non-argon2id pin digest (the old SHA-256
    /// placeholder) is a fatal config error, not a silently-weakened compare.
    #[test]
    fn a_non_argon2id_pin_digest_is_a_fatal_config() {
        let config = super::test_support::config_with_bounds(0, 172_800, "");
        let bad = config.replacen(&crate::argon2id_normal_phc("1234"), "deadbeef", 1);
        let err = Node::from_toml_str(&bad)
            .err()
            .expect("a SHA-256 digest must be rejected");
        assert!(
            err.to_string().contains("pin_normal_hash"),
            "unexpected error: {err}"
        );
    }

    /// A `max_attempts = 0` budget is fatal (the table's `max_attempts-1` index would
    /// be undefined).
    #[test]
    fn a_zero_max_attempts_budget_is_a_fatal_config() {
        let err = Node::from_toml_str(&super::test_support::config_with_bounds(
            0,
            172_800,
            "[pin_attempt_budget]\nmax_attempts = 0\n",
        ))
        .err()
        .expect("max_attempts = 0 must be rejected");
        assert!(
            err.to_string().contains("max_attempts"),
            "unexpected error: {err}"
        );
    }

    /// An empty `backoff_schedule` is fatal (`len-1` would be undefined).
    #[test]
    fn an_empty_backoff_schedule_is_a_fatal_config() {
        let err = Node::from_toml_str(&super::test_support::config_with_bounds(
            0,
            172_800,
            "[pin_attempt_budget]\nbackoff_schedule = []\n",
        ))
        .err()
        .expect("an empty backoff_schedule must be rejected");
        assert!(
            err.to_string().contains("backoff_schedule"),
            "unexpected error: {err}"
        );
    }
}

/// Reboot-death (codex C5): the entire node deployment — OS image, binary, config
/// (INCLUDING `node_seckey`), and every piece of runtime state — lives on tmpfs
/// (ADR-0007), so a reboot leaves a BARE machine. The attempt budget dies with the
/// signing key in the same stroke; the node cannot restart or rejoin the vault.
///
/// Lockdown, by contrast, is persisted to a tmpfs flag with durability EQUAL to the
/// signing key's (both in the tmpfs deployment dir): a machine reboot wipes both
/// (node death, strictly stronger than Lockdown), but a bare PROCESS restart — which
/// reloads `node_seckey` from the surviving config and so CAN sign again — must also
/// reload the latch, or it would resurrect an unlocked signer. The tests below prove
/// BOTH edges: reboot ⇒ dead, process restart while locked ⇒ still locked.
#[cfg(test)]
mod reboot_death_tests {
    use super::Node;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn scratch_dir() -> std::path::PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("btc-policy-v04a-reboot-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create scratch RAMDISK dir");
        dir
    }

    #[test]
    fn a_reboot_destroys_the_config_and_the_node_cannot_rejoin() {
        let dir = scratch_dir();
        let path = dir.join("node.toml");
        let config = super::test_support::config_with_bounds(0, 172_800, "");
        std::fs::write(&path, &config).expect("write config to the RAMDISK");

        // While the RAMDISK holds its config + node_seckey the node loads and can be
        // driven into terminal Lockdown.
        let node = Node::from_toml_str(&std::fs::read_to_string(&path).expect("read config"))
            .expect("valid config");
        node.enter_lockdown();
        assert!(node.is_locked_down());

        // Reboot = tmpfs wiped: destroy the config (INCLUDING node_seckey), its
        // sibling Lockdown flag, and the whole deployment dir.
        std::fs::remove_file(&path).expect("wipe config");
        let _ = std::fs::remove_file(Node::lockdown_flag_path_for(
            path.to_str().expect("utf-8 path"),
        ));
        std::fs::remove_dir(&dir).expect("wipe RAMDISK dir");

        // The rebooted machine is bare — no config, no key, no Lockdown flag. It
        // cannot restart against the vault; `load` has nothing to read. This is the
        // machine-reboot edge (config GONE), strictly stronger than Lockdown.
        let err = Node::load(path.to_str().expect("utf-8 path"))
            .err()
            .expect("a rebooted node with no config cannot restart");
        assert!(
            err.to_string().contains("cannot read config"),
            "a rebooted node holds no key/config/budget/lockdown and cannot rejoin: {err}"
        );
    }

    /// The edge the reboot test does NOT cover and codex flagged: the MACHINE stays
    /// up (tmpfs config + node_seckey survive) but the vault-node PROCESS restarts —
    /// a crash-loop, supervisor respawn, or OOM-kill, none of which need SSH. The key
    /// reloads (the node CAN sign again), so Lockdown MUST reload with it, or the
    /// restart resurrects an unlocked signer. Exercises the real `enter_lockdown`
    /// persistence + `apply_persisted_lockdown` (what `load` calls) — no channel
    /// config needed to prove the latch's durability.
    #[test]
    fn a_process_restart_before_reboot_comes_back_locked_down() {
        let dir = scratch_dir();
        let path = dir.join("node.toml");
        let config_str = super::test_support::config_with_bounds(0, 172_800, "");
        std::fs::write(&path, &config_str).expect("write config to the RAMDISK");
        let path_str = path.to_str().expect("utf-8 path");
        let flag = Node::lockdown_flag_path_for(path_str);

        // Process 1 boots clean: apply_persisted_lockdown pre-opens the latch file
        // (created empty — content, not existence, means locked), then Lockdown fires.
        let mut p1 = Node::from_toml_str(&config_str).expect("valid config");
        p1.apply_persisted_lockdown(path_str).expect("read latch");
        assert!(!p1.is_locked_down(), "a fresh node starts unlocked");
        assert!(
            std::fs::read(&flag).map(|c| c.is_empty()).unwrap_or(true),
            "the pre-opened latch file is empty (not locked) before enter_lockdown"
        );
        p1.enter_lockdown();
        assert!(p1.is_locked_down());
        assert!(
            !std::fs::read(&flag).expect("latch file present").is_empty(),
            "enter_lockdown must persist a non-empty marker (durability = key durability)"
        );
        drop(p1); // the process dies — tmpfs (config + latch) is untouched.

        // Process 2 restarts against the SURVIVING config + flag: it reloads the key
        // (could sign) but MUST come back terminally locked.
        let mut p2 = Node::from_toml_str(&config_str).expect("valid config");
        assert!(
            !p2.is_locked_down(),
            "in-RAM default is unlocked before the flag is consulted"
        );
        p2.apply_persisted_lockdown(path_str).expect("read latch");
        assert!(
            p2.is_locked_down(),
            "a process restart while locked (config survived) must reload LOCKED — \
             else a bare respawn resurrects an unlocked signer"
        );

        // Now a real reboot wipes the flag with everything else: a fresh boot from a
        // clean tmpfs (no flag) is unlocked — the latch never outlives the key.
        std::fs::remove_file(&flag).expect("reboot wipes the flag");
        let mut p3 = Node::from_toml_str(&config_str).expect("valid config");
        p3.apply_persisted_lockdown(path_str).expect("read latch");
        assert!(
            !p3.is_locked_down(),
            "with the flag gone (reboot), a node is not spuriously locked"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
