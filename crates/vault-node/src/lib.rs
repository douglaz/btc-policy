//! vault-node: one federation key, one policy engine, `POST /sign`.
//!
//! Scope so far (see docs/DESIGN.md "Milestones"): PIN verification, the
//! descriptor-derived policy-core checks (input ownership, destination
//! allowlist, verified change, PSBT consistency, fee cap), user
//! partial-signature verification, the anti-replay log, and the Hold
//! (ADR-0004) — hot-wallet spends wait `hold_secs` as pending
//! spends before the node signs, while escape sweeps and refresh self-spends
//! sign instantly. Watchtower duty (ADR-0001) — a callable scan pass
//! ([`Node::watchtower_tick`]) classifies recovery-path and un-co-signed spends
//! of the node's own chain view and queues alerts a puller reads via
//! `GET /events` (ADR-0002). The classification stays a deterministic callable
//! pass for tests, and in the running daemon a thin background task drives it
//! on a fixed interval ([`Node::spawn_watchtower`], V0-6b) — each node is its own
//! watchtower. Duress actions and lockdown remain v0 work (V0-4).

pub mod chain;
pub mod channel;
mod replay;
pub mod server;
pub mod watchtower;

use std::collections::HashSet;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use bitcoin::sighash::SighashCache;
use bitcoin::{EcdsaSighashType, Psbt, PublicKey, ScriptBuf, Txid};
use miniscript::descriptor::WshInner;
use miniscript::{Descriptor, DescriptorPublicKey, Terminal};
use replay::{ReplayLog, SignState};
use serde::Deserialize;
use vault_proto::{
    Commitment, CommitmentInput, CommitmentOutput, Pending, Refusal, RefusalCode, SignRequest,
    SignResponse,
};

use crate::chain::{BitcoindBackend, ChainBackend};
use crate::watchtower::{AlertQueue, Event};

pub type Error = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Input the node cannot decode: answered with HTTP 400, never a refusal.
#[derive(Debug)]
pub struct BadRequest(pub String);

/// The node's policy config file (TOML, written once at deploy time).
#[derive(Debug, Deserialize)]
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
    /// The escape wallet's descriptor. Named apart from the allowlist so the
    /// node can tell an escape sweep (instant) from a hot-wallet spend (the Hold
    /// applies); its descriptor must ALSO appear in `allowlist` so the sweep
    /// passes the destination check. Optional: with `hold_secs = 0` every class
    /// signs instantly, so first light may leave it unset.
    #[serde(default)]
    pub escape_descriptor: Option<String>,
    /// Bound on own-descriptor / allowlist derivation scans (DESIGN.md config
    /// schema, `max_derivation_index`).
    pub max_derivation_index: u32,
    pub hold_secs: u64,
    /// Node-enforced cap on the coordinator-proposed commitment expiry: the
    /// node refuses any expiry beyond `now + max_commitment_age_secs` by its
    /// OWN clock, so a hostile coordinator cannot inflate the replay log's
    /// retention (DESIGN.md config schema; "Transaction commitment").
    pub max_commitment_age_secs: u64,
    /// The baked-at-setup policy identifier, bound into every commitment
    /// (policy is immutable, so this never changes).
    pub policy_version: u32,
    /// Lowercase hex SHA-256 of each enrolled PIN (argon2 comes with the
    /// real setup ceremony later).
    pub pin_normal_hash: String,
    pub pin_duress_hash: String,
    /// Optional chain-backend endpoint for the watchtower driver (ADR-0001,
    /// V0-6b). Absent ⇒ the daemon runs no scan task (unit tests and nodes
    /// without a reachable bitcoind still load). Present ⇒ the daemon spawns one
    /// background task scanning this bitcoind on a fixed interval.
    #[serde(default)]
    pub chain_backend: Option<ChainBackendConfig>,
    /// Optional node-to-node channel config (V0-8a; ADR-0013 §5). **Absent ⇒
    /// absent-channel mode**: `/channel` is NOT mounted, NO manifest/bijection/
    /// endorsement invariants run, and the node behaves exactly as pre-channel (so
    /// `demo first-light`, which does not use the channel, keeps passing WITHOUT
    /// editing the demo). Present ⇒ every invariant applies and `/channel` mounts.
    #[serde(default)]
    pub channel: Option<channel::ChannelConfig>,
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
    pin_normal_hash: String,
    pin_duress_hash: String,
    /// Hash of this node's descriptor: the `wallet_id` bound into every
    /// commitment.
    wallet_id: [u8; 32],
    policy_version: u32,
    max_commitment_age_secs: u64,
    /// The Hold for hot-class spends (ADR-0004): a hot-wallet spend is recorded
    /// as pending and signed only when re-submitted after this many seconds.
    /// `0` signs on first submission (first light; keeps the demo one-shot).
    hold_secs: u64,
    /// The escape wallet's descriptor when configured. A spend whose every
    /// non-change output re-derives from it is an escape sweep and skips the
    /// Hold. `None` ⇒ no spend is escape-class, harmless when `hold_secs = 0`.
    escape_descriptor: Option<Descriptor<DescriptorPublicKey>>,
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
    /// The node's sign log: the txids it has co-signed (ADR-0001 watchtower
    /// input). Because SIGHASH_ALL binds the witness to the exact transaction and
    /// segwit txids exclude the witness, the signed tx's txid equals its unsigned
    /// tx's txid — so a spend of a vault UTXO whose txid is absent here is one the
    /// node never authorized (an `UnrecognizedSpend`). Shared behind a `Mutex`
    /// (not the per-`/sign` `SignState` lock used for the logs above): the
    /// `/sign` handler writes it and the background watchtower task reads it
    /// (V0-6b).
    sign_log: Arc<Mutex<HashSet<Txid>>>,
    /// Queued watchtower alerts, pulled by the coordinator via `GET /events`
    /// (ADR-0002). Bounded, in-memory (DESIGN.md). Shared behind a `Mutex`: the
    /// background watchtower task writes it and `/events` reads it (V0-6b).
    alerts: Arc<Mutex<AlertQueue>>,
    /// Parsed chain-backend endpoint (rpc socket + base64 auth) for the
    /// watchtower driver, if configured. `None` ⇒ no scan task. Held so the
    /// daemon can build the backend and spawn the driver after load
    /// ([`Node::spawn_watchtower`]).
    chain_backend: Option<(SocketAddr, String)>,
    /// The node-to-node channel runtime (V0-8a), built from the sealed manifest
    /// when `[channel]` is present. `None` ⇒ absent-channel mode: `/channel` is
    /// not mounted and no channel invariant runs. Read by the `/channel` route and
    /// the `/sign`-path candidate-registry funnel.
    pub(crate) channel: Option<channel::ChannelState>,
}

impl Node {
    pub fn load(path: &str) -> Result<Node, Error> {
        let raw =
            std::fs::read_to_string(path).map_err(|e| format!("cannot read config {path}: {e}"))?;
        Node::from_toml_str(&raw)
    }

    pub fn from_toml_str(raw: &str) -> Result<Node, Error> {
        let config: ConfigFile = toml::from_str(raw).map_err(|e| format!("bad config: {e}"))?;
        let secp = Secp256k1::new();
        let seckey = SecretKey::from_str(&config.node_seckey)
            .map_err(|e| format!("bad node_seckey: {e}"))?;
        let pubkey = PublicKey::new(seckey.public_key(&secp));
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
        // The federation node keys, for the channel manifest's node_id ↔
        // descriptor-key bijection (§1). Extracted here while the concrete
        // descriptor is in scope; unused in absent-channel mode.
        let node_keys = first_light_node_keys_of(&descriptor)?;
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
        let escape_descriptor = config
            .escape_descriptor
            .as_deref()
            .map(Descriptor::<DescriptorPublicKey>::from_str)
            .transpose()
            .map_err(|e| format!("bad escape_descriptor: {e}"))?;
        if config.hold_secs >= config.max_commitment_age_secs {
            return Err(format!(
                "max_commitment_age_secs ({}) must exceed hold_secs ({})",
                config.max_commitment_age_secs, config.hold_secs
            )
            .into());
        }
        if let Some(escape) = &escape_descriptor {
            // Descriptor membership: the escape wallet must be an allowlist entry
            // so its sweep passes the destination check (canonical-string equality
            // covers checksum/format normalization).
            let escape_canonical = escape.to_string();
            if !allowed.iter().any(|d| d.to_string() == escape_canonical) {
                return Err("escape_descriptor must also be present in allowlist".into());
            }
        } else if config.hold_secs > 0 {
            return Err("escape_descriptor is required when hold_secs is nonzero".into());
        }
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
                    Arc::clone(&alerts),
                )
            })
            .transpose()?;
        Ok(Node {
            listen_port: config.listen_port,
            seckey,
            pubkey,
            user_pubkey,
            witness_script,
            check_params: policy_core::CheckParams {
                vault,
                allowed,
                max_derivation_index: config.max_derivation_index,
            },
            pin_normal_hash: config.pin_normal_hash.to_lowercase(),
            pin_duress_hash: config.pin_duress_hash.to_lowercase(),
            wallet_id,
            policy_version: config.policy_version,
            max_commitment_age_secs: config.max_commitment_age_secs,
            hold_secs: config.hold_secs,
            escape_descriptor,
            sign_state: Mutex::new(SignState::default()),
            sign_log: Arc::new(Mutex::new(HashSet::new())),
            alerts,
            chain_backend,
            channel,
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
    /// through [`watchtower::scan_pass`] over this node's shared sign log and
    /// alert queue — so tests and production exercise one code path. The
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
            &self.sign_log,
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

    /// If a chain backend is configured, spawn the background watchtower driver
    /// (ADR-0001, V0-6b). Otherwise this is a no-op. The daemon calls this once
    /// after [`Node::load`], from within the tokio runtime. The task shares this
    /// node's sign log and alert queue, so co-signed spends are recognized and
    /// alerts surface through `GET /events`. Unit tests build a `Node` without a
    /// chain backend and so never start a task.
    pub fn spawn_watchtower(&self) {
        let Some((addr, auth)) = self.chain_backend.clone() else {
            return;
        };
        let backend = BitcoindBackend::new(addr, auth);
        watchtower::spawn_driver(
            Arc::new(backend),
            self.vault_scripts(),
            Arc::clone(&self.sign_log),
            Arc::clone(&self.alerts),
        );
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

/// Extract the federation node keys (the `multi(t, node...)` keys) from the
/// first-light descriptor template — the descriptor-canonical key set the channel
/// manifest's `node_id` bijection is defined over (§1). Returned in descriptor
/// order; the channel derives the canonical (lexicographic) order itself.
fn first_light_node_keys_of(descriptor: &Descriptor<PublicKey>) -> Result<Vec<PublicKey>, Error> {
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
    Ok(thresh.data().to_vec())
}

/// Handle one `/sign` submission. `now` is unix seconds by the node's own
/// clock (a parameter, never a system-clock read, so the anti-replay, expiry,
/// and Hold logic is deterministically testable). `Err(BadRequest)` means
/// undecodable input (HTTP 400); every policy outcome — signed, pending, or
/// refused — is `Ok`.
///
/// Ordering (DESIGN.md, "Transaction commitment" + anti-replay log + Hold):
///  1. PIN — before anything is signed or recorded (ADR-0008). A bad PIN is
///     never logged: the PIN is not part of the commitment, so recording it
///     would wrongly replay a `BAD_PIN` refusal for the same transaction
///     resubmitted with the correct PIN.
///  2. decode both PSBTs (needed to build the commitment).
///  3. compute the `commitment_id` binding this decision to the exact tx.
///  4. idempotency — an identical, unexpired resubmission returns the recorded
///     verdict without re-evaluating.
///  5. node-capped expiry check against the node's own clock.
///  6. validate: user-signature verification, then policy-core. A refusal here
///     is final — an INVALID submission is refused, never held. Validation
///     precedes the Hold precisely so the pending log only ever holds spends
///     that would otherwise be signed (DESIGN.md, "the log IS the hold timer";
///     the demo's non-allowlisted theft is refused, not queued as pending).
///  7. the Hold (ADR-0004): route the now-valid spend by destination class. A
///     hot-wallet spend inside its window is recorded as a pending timer and
///     answered `Pending`; escape sweeps, refresh self-spends, elapsed holds,
///     and `hold_secs = 0` fall through to sign.
///  8. sign, record the verdict — only when the commitment fully determines it
///     (see [`is_recordable_verdict`]) — then answer.
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

fn handle_sign_after_lock(
    node: &Node,
    request: &SignRequest,
    clock: impl FnOnce() -> u64,
) -> Result<SignResponse, BadRequest> {
    // The whole call runs under ONE lock over the replay + pending logs
    // (`Mutex<SignState>`), reproducing the atomicity the old sequential serve
    // loop gave for free: two concurrent `/sign` requests execute one-at-a-time
    // and their check-then-update sequences never interleave. This serializes
    // `/sign` against `/sign` BY DESIGN — the async migration isolates `/sign`
    // from `/events` (and, in V0-8a, `/channel`), which keep their own locks,
    // not sign-vs-sign throughput.
    let mut state = node.sign_state.lock().expect("sign_state lock poisoned");
    let now = clock();

    // 1. PIN, before anything else: no valid PIN, nothing is ever signed
    //    (ADR-0008). At first light a duress PIN is verified and accepted
    //    exactly like the normal one — the duress *response* is v0 work,
    //    and the wire answer is identical by design anyway.
    let pin_hash = sha256::Hash::hash(request.pin.as_bytes()).to_string();
    if pin_hash != node.pin_normal_hash && pin_hash != node.pin_duress_hash {
        return Ok(refusal(
            RefusalCode::BadPin,
            "pin",
            "submitted PIN does not match an enrolled PIN".into(),
        ));
    }

    // 2. Decode both PSBTs; undecodable input is a 400, not a refusal.
    let mut psbt = decode_psbt(&request.psbt, "psbt")?;
    // The escape variant must at least decode (two-transaction ceremony,
    // ADR-0008); first light runs no further checks on it.
    decode_psbt(&request.escape_psbt, "escape_psbt")?;

    // 3. Bind this decision to the exact transaction. The commitment carries
    //    this node's OWN baked `policy_version` (from config, not the request):
    //    the node always evaluates and signs against its own static policy, so
    //    the request's `policy_version` is coordinator metadata that cannot
    //    change what gets signed and needs no separate match check here.
    let commitment = commitment_of(node, &psbt, request.expiry);
    let commitment_id = commitment.commitment_id();

    // 4. Anti-replay log: prune expired entries (retention is bounded by each
    //    entry's expiry), then return idempotently for an identical, unexpired
    //    resubmission. Keyed by commitment hash — an RBF replacement has a
    //    different id and is never blocked here. Prune the pending log on the
    //    same schedule so its Hold timers stay bounded too.
    state.replay.prune(now);
    if let Some(recorded) = state.replay.get(&commitment_id, now) {
        return Ok(recorded);
    }
    state.pending.prune(now);
    // Prune expired channel candidates on the SAME sweep the replay/pending logs
    // run on (§5): a candidate and its stored partials evict when its commitment
    // expires. (`/channel` lookup also evicts expired candidates, so an idle node
    // that never runs this sweep still rejects them.)
    if let Some(channel) = &node.channel {
        channel.prune_store(now);
    }

    // 5. Node-capped expiry, against the node's OWN clock: refuse an already-
    //    expired commitment, and refuse one whose expiry runs past the node's
    //    retention cap so a hostile coordinator can't inflate the log. An
    //    out-of-window commitment is NOT recorded — its expiry can't bound
    //    retention.
    if request.expiry <= now || request.expiry > now.saturating_add(node.max_commitment_age_secs) {
        return Ok(refusal(
            RefusalCode::CommitmentExpired,
            "commitment_expiry",
            format!(
                "expiry {} is outside the acceptance window (now {now}, max age {}s)",
                request.expiry, node.max_commitment_age_secs
            ),
        ));
    }

    // 6. Validate the spend (user-signature verification, then policy-core)
    //    WITHOUT signing yet. A refusal here is final and is recorded exactly as
    //    in V0-2: only verdicts the commitment fully determines are logged, so a
    //    signature- or PSBT-structure-dependent refusal stays unrecorded and an
    //    identical commitment resubmitted with a corrected signature is
    //    re-evaluated, not answered from a stale refusal (the log does not
    //    defend the signature; DESIGN.md, "What the anti-replay log is — and is
    //    not"). An invalid submission is never held: the pending log holds only
    //    spends that would otherwise be signed.
    if let Err(refused) = verify_spend(node, &psbt) {
        record_verdict(&mut state.replay, &commitment_id, request.expiry, &refused);
        return Ok(refused);
    }

    // 7. The Hold (ADR-0004). The spend is valid; route it by destination
    //    class. A hot-wallet spend inside its window is recorded as a pending
    //    timer (first_seen only — see PendingLog) and answered Pending; escape
    //    sweeps, refresh self-spends, elapsed holds, and hold_secs = 0 fall
    //    through to signing. Classification only routes: the checks above ran
    //    for every class, so a generous class can never bypass them.
    if destination_class(node, &psbt) == DestClass::Hot {
        let recorded_first_seen = state.pending.first_seen(&commitment_id, now);
        let first_seen = recorded_first_seen.unwrap_or(now);
        let elapsed = now.saturating_sub(first_seen);
        let hold_expires_at = first_seen.saturating_add(node.hold_secs);
        if request.expiry <= hold_expires_at {
            return Ok(refusal(
                RefusalCode::CommitmentExpired,
                "commitment_expiry",
                format!(
                    "expiry {} does not outlive the Hold window (first_seen {first_seen}, hold_secs {}s)",
                    request.expiry, node.hold_secs
                ),
            ));
        }
        if elapsed < node.hold_secs {
            // Inside the Hold. Start the timer on genuine first sight only
            // (reading first_seen above guarantees it never resets), then
            // answer Pending with the time left.
            if recorded_first_seen.is_none() {
                state
                    .pending
                    .record(commitment_id.clone(), now, request.expiry);
            }
            let pending = SignResponse::Pending(Pending {
                commitment_id: commitment_id.clone(),
                first_seen,
                // elapsed < hold_secs in this branch, so the difference is exact.
                remaining_secs: node.hold_secs - elapsed,
            });
            // §4 registry funnel: an accepted-but-Pending hot spend registers a
            // candidate at ingress, so a fast peer's partial arriving during our
            // Hold verifies instead of bouncing as unknown-candidate.
            register_verdict(node, &psbt, &commitment_id, request.expiry, &pending);
            return Ok(pending);
        }
    }

    // 8. Sign the PSBT in hand (re-verified in step 6), record the verdict,
    //    and answer. Reached by escape/refresh, an elapsed hot-class Hold, or
    //    hold_secs = 0.
    let verdict = match add_node_signatures(node, &mut psbt) {
        Ok(()) => {
            // Record the co-signed txid for the watchtower (ADR-0001): a later
            // on-chain spend with this txid is one the node authorized, not an
            // alert. The txid is taken from the unsigned tx — segwit excludes the
            // witness, so it is the txid the signed tx will broadcast under.
            node.sign_log
                .lock()
                .expect("sign_log lock poisoned")
                .insert(psbt.unsigned_tx.compute_txid());
            SignResponse::Signed(psbt.to_string())
        }
        Err(detail) => refusal(RefusalCode::PsbtInconsistent, "signing", detail),
    };
    record_verdict(&mut state.replay, &commitment_id, request.expiry, &verdict);
    // §4 registry funnel: an instantly-signed spend registers its candidate (with
    // this node's own partial already present); a signing refusal never registers.
    register_verdict(node, &psbt, &commitment_id, request.expiry, &verdict);
    Ok(verdict)
}

/// The §4 candidate-registry funnel: on a non-refused `/sign` verdict (Pending or
/// Signed, NEVER Refusal) build this node's canonical candidate and reserve a
/// store slot. Absent-channel mode ⇒ a no-op. At capacity the candidate is simply
/// not inserted (logged) and the `/sign` verdict/response is unchanged — capacity
/// gates the registry slot, not the sign decision (§5).
fn register_verdict(
    node: &Node,
    psbt: &Psbt,
    commitment_id: &str,
    expiry: u64,
    verdict: &SignResponse,
) {
    if !matches!(verdict, SignResponse::Signed(_) | SignResponse::Pending(_)) {
        return;
    }
    let Some(channel) = &node.channel else {
        return;
    };
    // Keep this node's own real signature in the candidate only when it actually
    // signed (a `Signed` verdict); a `Pending` candidate carries no self signature,
    // so any self entry in the request PSBT is a coordinator forgery to be stripped.
    let node_signed = matches!(verdict, SignResponse::Signed(_));
    match channel::Candidate::build(
        psbt,
        commitment_id,
        expiry,
        &node.witness_script,
        &node.user_pubkey,
        &node.pubkey,
        node_signed,
    ) {
        Ok(candidate) => {
            if matches!(
                channel.register_candidate(candidate),
                channel::RegisterOutcome::AtCapacity
            ) {
                eprintln!("channel: candidate {commitment_id} not registered — store at capacity");
            }
        }
        Err(e) => eprintln!("channel: cannot build candidate {commitment_id}: {e}"),
    }
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

/// Record `verdict` under `commitment_id` in the anti-replay log, but only when
/// the commitment fully determines it (see [`is_recordable_verdict`]). Takes the
/// already-locked replay log (the handler holds the one `SignState` lock across
/// its whole run), so recording stays inside the same critical section as the
/// idempotency check above it.
fn record_verdict(
    replay: &mut ReplayLog,
    commitment_id: &str,
    expiry: u64,
    verdict: &SignResponse,
) {
    if is_recordable_verdict(verdict) {
        replay.record(commitment_id.to_string(), expiry, verdict.clone());
    }
}

/// The destination class of a spend, read from its outputs (ADR-0004, "Policy
/// model → Hold"). This only ROUTES the Hold; every class still runs the full
/// sig + policy checks before signing, so a generous classification can never
/// bypass the allowlist or fee cap.
#[derive(Debug, PartialEq, Eq)]
enum DestClass {
    /// Every non-change output re-derives from the escape wallet's descriptor —
    /// the incident sweep. Signs instantly: the escape sweep is the implicit
    /// cancel of any pending spend, so it must never itself be held.
    Escape,
    /// Self-spend: every output re-derives from the vault's own descriptor (a
    /// refresh resetting the recovery timelock). Signs instantly.
    Refresh,
    /// Pays the hot wallet (anything else). The Hold applies.
    Hot,
}

/// Classify `psbt` by destination (see [`DestClass`]). "Change" is a self-pay
/// that re-derives from the vault's own descriptor; the class turns on the
/// non-change outputs. Membership is decided by the same bounded re-derivation
/// primitive as the policy checks ([`policy_core::derives_within`]), never by
/// literal scriptPubKey comparison. With no escape descriptor configured
/// nothing is escape-class, which is harmless when `hold_secs = 0`.
fn destination_class(node: &Node, psbt: &Psbt) -> DestClass {
    let vault = &node.check_params.vault;
    let max = node.check_params.max_derivation_index;
    let mut non_change = psbt
        .unsigned_tx
        .output
        .iter()
        .filter(|output| !policy_core::derives_within(vault, output.script_pubkey.as_script(), max))
        .peekable();
    if non_change.peek().is_none() {
        // Every output re-derives from the vault: a refresh self-spend.
        return DestClass::Refresh;
    }
    match &node.escape_descriptor {
        Some(escape)
            if non_change.all(|output| {
                policy_core::derives_within(escape, output.script_pubkey.as_script(), max)
            }) =>
        {
            DestClass::Escape
        }
        _ => DestClass::Hot,
    }
}

/// Whether `verdict` may be recorded in the anti-replay log for idempotent
/// replay. The log is keyed by `commitment_id`, which binds only the logical
/// spend (wallet, version, lock time, outpoints + sequences, outputs, fee,
/// expiry, policy_version) — never the witness data. So only verdicts that
/// data fully determines are safe to replay:
///
/// - `Signed` — a valid user signature existed for this exact commitment;
///   replaying the recorded signed PSBT is the idempotency job.
/// - `DEST_NOT_ALLOWED` / `CHANGE_NOT_DERIVABLE` / `FEE_EXCEEDS_CAP` — the
///   policy refusals that turn solely on the outputs and fee the commitment
///   binds. Because the outputs are commitment-bound and derive from neither the
///   allowlist nor the vault, the same commitment can NEVER become a signature,
///   so caching the refusal cannot block an honest spend. (An untrusted bip32
///   change label only decides `DEST_NOT_ALLOWED` vs `CHANGE_NOT_DERIVABLE`;
///   both are refusals, so replaying either stays safe.)
///
/// Refusals that depend on data the commitment does NOT bind — the signature
/// (`USER_SIG_INVALID`, `BAD_SIGHASH`), the PSBT structure (`PSBT_INCONSISTENT`),
/// or the untrusted `witness_utxo` prevout script (`UNKNOWN_INPUT`) — are NOT
/// recorded: an identical commitment resubmitted with corrected witness data
/// could legitimately sign, so caching would otherwise replay a stale refusal
/// and block an honest spend. The log does not defend the signature — V0-1's
/// sighash binding does (DESIGN.md, "What the anti-replay log is — and is not").
/// `Pending` lives in the pending log (the Hold timer), never the anti-replay
/// log, so it is never recorded here.
fn is_recordable_verdict(verdict: &SignResponse) -> bool {
    match verdict {
        SignResponse::Signed(_) => true,
        SignResponse::Refusal(refusal) => matches!(
            refusal.code,
            RefusalCode::DestNotAllowed
                | RefusalCode::ChangeNotDerivable
                | RefusalCode::FeeExceedsCap
        ),
        SignResponse::Pending(_) => false,
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
    //! Node-level wiring: an honest `/sign` records its txid in the sign log, so
    //! the watchtower recognizes that spend and alerts (through `events`) only on
    //! vault spends the node never co-signed. Classification and cursor edge cases
    //! live in `watchtower`'s own tests; this proves the `Node` glue.

    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::{sha256, Hash};
    use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
    use bitcoin::sighash::SighashCache;
    use bitcoin::transaction::Version;
    use bitcoin::{
        Amount, EcdsaSighashType, OutPoint, Psbt, PublicKey, ScriptBuf, Sequence, Transaction,
        TxIn, TxOut, Txid, Witness,
    };
    use miniscript::{Descriptor, DescriptorPublicKey};
    use std::str::FromStr;

    use crate::chain::{mock::MockBackend, SpendSeen};
    use crate::watchtower::AlertKind;
    use crate::{handle_sign, Node};
    use vault_proto::{SignRequest, SignResponse};

    const NOW: u64 = 1_752_000_000;

    fn key(i: u8) -> (SecretKey, PublicKey) {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[i; 32]).expect("32 nonzero bytes");
        (sk, PublicKey::new(sk.public_key(&secp)))
    }

    /// A 1-of-1 vault (user + one node key) that signs an honest hot spend under
    /// `hold_secs = 0`, plus the resulting co-signed txid.
    fn signed_node() -> (Node, Txid) {
        let (_, user) = key(1);
        let (nsk, node_pub) = key(2);
        let (_, hot_key) = key(10);
        let descriptor = format!("wsh(and_v(v:pk({user}),multi(1,{node_pub})))");
        let hot = Descriptor::<DescriptorPublicKey>::from_str(&format!("wpkh({hot_key})"))
            .expect("hot descriptor");
        let hot_spk = hot
            .at_derivation_index(0)
            .expect("definite")
            .script_pubkey();
        let config = format!(
            "listen_port = 7100\nnode_seckey = \"{}\"\ndescriptor = \"{descriptor}\"\n\
             allowlist = [\"{hot}\"]\nmax_derivation_index = 5\nhold_secs = 0\n\
             max_commitment_age_secs = 172800\npolicy_version = 1\n\
             pin_normal_hash = \"{}\"\npin_duress_hash = \"{}\"\n",
            nsk.display_secret(),
            sha256::Hash::hash(b"1234"),
            sha256::Hash::hash(b"9999"),
        );
        let node = Node::from_toml_str(&config).expect("valid config");

        let vault_spk = node.vault_scripts()[0].clone();
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
                script_pubkey: hot_spk,
                value: Amount::from_sat(99_990_000),
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).expect("unsigned tx");
        let value = Amount::from_sat(100_000_000);
        psbt.inputs[0].witness_utxo = Some(TxOut {
            script_pubkey: vault_spk,
            value,
        });
        psbt.inputs[0].witness_script = Some(node.witness_script.clone());
        let sighash = SighashCache::new(&psbt.unsigned_tx)
            .p2wsh_signature_hash(0, &node.witness_script, value, EcdsaSighashType::All)
            .expect("sighash");
        let secp = Secp256k1::new();
        let signature = secp.sign_ecdsa(&Message::from_digest(sighash.to_byte_array()), &key(1).0);
        psbt.inputs[0].partial_sigs.insert(
            user,
            bitcoin::ecdsa::Signature {
                signature,
                sighash_type: EcdsaSighashType::All,
            },
        );
        let request = SignRequest {
            psbt: psbt.to_string(),
            escape_psbt: psbt.to_string(),
            pin: "1234".into(),
            expiry: NOW + 3_600,
            policy_version: 1,
        };
        let SignResponse::Signed(_) = handle_sign(&node, &request, NOW).expect("decodable") else {
            panic!("the honest hot spend must sign");
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
    fn a_co_signed_spend_is_recognized_and_an_unknown_one_alerts_through_events() {
        let (node, cosigned) = signed_node();

        // The co-signed spend on chain is recognized: nothing queued.
        let known = MockBackend {
            spends: vec![vault_spend(&node, cosigned)],
            ..Default::default()
        };
        assert_eq!(node.watchtower_tick(&known, 0).expect("scan"), 0);
        assert!(node.events(0).0.is_empty());

        // A vault spend the node never co-signed is an UnrecognizedSpend.
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
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn key(i: u8) -> (SecretKey, PublicKey) {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[i; 32]).expect("32 nonzero bytes");
        (sk, PublicKey::new(sk.public_key(&secp)))
    }

    /// A 1-of-1 vault (user key + one node key, `hold_secs = 0`) bound to
    /// `listen_port = 0`, plus a valid hot-spend `SignRequest` that `handle_sign`
    /// signs on first submission. The request's `expiry` is set against the REAL
    /// clock and sits well inside `max_commitment_age_secs`.
    pub(crate) fn node_and_valid_request() -> (Node, SignRequest) {
        let (_, user) = key(1);
        let (nsk, node_pub) = key(2);
        let (_, hot_key) = key(10);
        let descriptor = format!("wsh(and_v(v:pk({user}),multi(1,{node_pub})))");
        let hot = Descriptor::<DescriptorPublicKey>::from_str(&format!("wpkh({hot_key})"))
            .expect("hot descriptor");
        let hot_spk = hot
            .at_derivation_index(0)
            .expect("definite")
            .script_pubkey();
        let config = format!(
            "listen_port = 0\nnode_seckey = \"{}\"\ndescriptor = \"{descriptor}\"\n\
             allowlist = [\"{hot}\"]\nmax_derivation_index = 5\nhold_secs = 0\n\
             max_commitment_age_secs = 172800\npolicy_version = 1\n\
             pin_normal_hash = \"{}\"\npin_duress_hash = \"{}\"\n",
            nsk.display_secret(),
            sha256::Hash::hash(b"1234"),
            sha256::Hash::hash(b"9999"),
        );
        let node = Node::from_toml_str(&config).expect("valid config");
        let vault_spk = node.vault_scripts()[0].clone();
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
                script_pubkey: hot_spk,
                value: Amount::from_sat(99_990_000),
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).expect("unsigned tx");
        psbt.inputs[0].witness_utxo = Some(TxOut {
            script_pubkey: vault_spk,
            value,
        });
        psbt.inputs[0].witness_script = Some(node.witness_script.clone());
        let sighash = SighashCache::new(&psbt.unsigned_tx)
            .p2wsh_signature_hash(0, &node.witness_script, value, EcdsaSighashType::All)
            .expect("sighash");
        let secp = Secp256k1::new();
        let signature = secp.sign_ecdsa(&Message::from_digest(sighash.to_byte_array()), &key(1).0);
        psbt.inputs[0].partial_sigs.insert(
            user,
            bitcoin::ecdsa::Signature {
                signature,
                sighash_type: EcdsaSighashType::All,
            },
        );
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let request = SignRequest {
            psbt: psbt.to_string(),
            escape_psbt: psbt.to_string(),
            pin: "1234".into(),
            expiry: now + 3_600,
            policy_version: 1,
        };
        (node, request)
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
