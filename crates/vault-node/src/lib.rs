//! vault-node: one federation key, one policy engine, `POST /sign`.
//!
//! Scope so far (see docs/DESIGN.md "Milestones"): PIN verification, the
//! descriptor-derived policy-core checks (input ownership, destination
//! allowlist, verified change, PSBT consistency, fee cap), user
//! partial-signature verification, the anti-replay log, and the Hold
//! (ADR-0004) — hot-wallet spends wait `hold_secs` as pending
//! spends before the node signs, while escape sweeps and refresh self-spends
//! sign instantly. Duress actions, lockdown, watchtower duty, and `GET /events`
//! remain v0 work.

pub mod http;
mod replay;

use std::cell::RefCell;
use std::str::FromStr;

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use bitcoin::sighash::SighashCache;
use bitcoin::{EcdsaSighashType, Psbt, PublicKey, ScriptBuf};
use miniscript::descriptor::WshInner;
use miniscript::{Descriptor, DescriptorPublicKey, Terminal};
use replay::{PendingLog, ReplayLog};
use serde::Deserialize;
use vault_proto::{
    Commitment, CommitmentInput, CommitmentOutput, Pending, Refusal, RefusalCode, SignRequest,
    SignResponse,
};

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
    /// Anti-replay log. The `/sign` server is single-threaded; `RefCell`
    /// provides the interior mutability needed by the handler's `&Node`.
    replay_log: RefCell<ReplayLog>,
    /// Hold timers for hot-class pending spends, keyed by `commitment_id`
    /// (timer-only; see [`replay::PendingLog`]). Same single-threaded `RefCell`
    /// discipline as `replay_log`.
    pending_log: RefCell<PendingLog>,
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
            replay_log: RefCell::new(ReplayLog::default()),
            pending_log: RefCell::new(PendingLog::default()),
        })
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
    {
        let mut log = node.replay_log.borrow_mut();
        log.prune(now);
        if let Some(recorded) = log.get(&commitment_id, now) {
            return Ok(recorded);
        }
    }
    node.pending_log.borrow_mut().prune(now);

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
        record_verdict(node, &commitment_id, request.expiry, &refused);
        return Ok(refused);
    }

    // 7. The Hold (ADR-0004). The spend is valid; route it by destination
    //    class. A hot-wallet spend inside its window is recorded as a pending
    //    timer (first_seen only — see PendingLog) and answered Pending; escape
    //    sweeps, refresh self-spends, elapsed holds, and hold_secs = 0 fall
    //    through to signing. Classification only routes: the checks above ran
    //    for every class, so a generous class can never bypass them.
    if destination_class(node, &psbt) == DestClass::Hot {
        let recorded_first_seen = node.pending_log.borrow().first_seen(&commitment_id, now);
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
                node.pending_log
                    .borrow_mut()
                    .record(commitment_id.clone(), now, request.expiry);
            }
            return Ok(SignResponse::Pending(Pending {
                commitment_id,
                first_seen,
                // elapsed < hold_secs in this branch, so the difference is exact.
                remaining_secs: node.hold_secs - elapsed,
            }));
        }
    }

    // 8. Sign the PSBT in hand (re-verified in step 6), record the verdict,
    //    and answer. Reached by escape/refresh, an elapsed hot-class Hold, or
    //    hold_secs = 0.
    let verdict = match add_node_signatures(node, &mut psbt) {
        Ok(()) => SignResponse::Signed(psbt.to_string()),
        Err(detail) => refusal(RefusalCode::PsbtInconsistent, "signing", detail),
    };
    record_verdict(node, &commitment_id, request.expiry, &verdict);
    Ok(verdict)
}

/// Build the [`Commitment`] for `psbt` under this node's wallet, at the
/// coordinator-proposed `expiry`. The fee is `Σ input value − Σ output value`,
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
/// the commitment fully determines it (see [`is_recordable_verdict`]).
fn record_verdict(node: &Node, commitment_id: &str, expiry: u64, verdict: &SignResponse) {
    if is_recordable_verdict(verdict) {
        node.replay_log
            .borrow_mut()
            .record(commitment_id.to_string(), expiry, verdict.clone());
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
/// spend (wallet, outpoints, outputs, fee, expiry, policy_version) — never the
/// witness data. So only verdicts that data fully determines are safe to
/// replay:
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
