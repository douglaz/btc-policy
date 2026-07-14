//! vault-node: one federation key, one policy engine, `POST /sign`.
//!
//! First-light scope (see docs/DESIGN.md "Milestones"): PIN verification,
//! the two policy-core checks, user partial-signature verification, and node
//! signing at first submission (`hold_secs = 0`). The Hold, duress actions,
//! lockdown, watchtower duty, and `GET /events` are v0 work.

pub mod http;
mod replay;

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::str::FromStr;

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use bitcoin::sighash::SighashCache;
use bitcoin::{EcdsaSighashType, Psbt, PublicKey, ScriptBuf};
use miniscript::descriptor::WshInner;
use miniscript::{Descriptor, Terminal};
use replay::ReplayLog;
use serde::Deserialize;
use vault_proto::{
    Commitment, CommitmentInput, CommitmentOutput, Refusal, RefusalCode, SignRequest, SignResponse,
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
    /// Allowlisted destination scriptPubKeys, hex (baked; descriptor
    /// re-derivation is v0 work).
    pub allowlist: Vec<String>,
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
    /// Anti-replay log. The `/sign` server is single-threaded; `RefCell`
    /// provides the interior mutability needed by the handler's `&Node`.
    replay_log: RefCell<ReplayLog>,
}

impl Node {
    pub fn load(path: &str) -> Result<Node, Error> {
        let raw =
            std::fs::read_to_string(path).map_err(|e| format!("cannot read config {path}: {e}"))?;
        Node::from_toml_str(&raw)
    }

    pub fn from_toml_str(raw: &str) -> Result<Node, Error> {
        let config: ConfigFile = toml::from_str(raw).map_err(|e| format!("bad config: {e}"))?;
        if config.hold_secs != 0 {
            return Err("hold_secs must be 0: the Hold (ADR-0004) is v0 work, \
                 not implemented at first light"
                .into());
        }
        let secp = Secp256k1::new();
        let seckey = SecretKey::from_str(&config.node_seckey)
            .map_err(|e| format!("bad node_seckey: {e}"))?;
        let pubkey = PublicKey::new(seckey.public_key(&secp));
        let descriptor = Descriptor::<PublicKey>::from_str(&config.descriptor)
            .map_err(|e| format!("bad descriptor: {e}"))?;
        let user_pubkey = first_light_user_key_of(&descriptor)?;
        let witness_script = descriptor
            .explicit_script()
            .map_err(|e| format!("descriptor has no witness script: {e}"))?;
        // wallet_id binds a commitment to this vault. Hash the descriptor's
        // canonical string (checksum included) so coordinator and node — which
        // parse the same descriptor — derive the same id.
        let wallet_id = sha256::Hash::hash(descriptor.to_string().as_bytes()).to_byte_array();
        let mut allowed_spks = BTreeSet::new();
        for hex in &config.allowlist {
            let spk = ScriptBuf::from_hex(hex)
                .map_err(|e| format!("bad allowlist scriptPubKey {hex}: {e}"))?;
            allowed_spks.insert(spk);
        }
        Ok(Node {
            listen_port: config.listen_port,
            seckey,
            pubkey,
            user_pubkey,
            witness_script,
            check_params: policy_core::CheckParams {
                vault_spk: descriptor.script_pubkey(),
                allowed_spks,
            },
            pin_normal_hash: config.pin_normal_hash.to_lowercase(),
            pin_duress_hash: config.pin_duress_hash.to_lowercase(),
            wallet_id,
            policy_version: config.policy_version,
            max_commitment_age_secs: config.max_commitment_age_secs,
            replay_log: RefCell::new(ReplayLog::default()),
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
/// clock (a parameter, never a system-clock read, so the anti-replay and
/// expiry logic is deterministically testable). `Err(BadRequest)` means
/// undecodable input (HTTP 400); every policy outcome — signed or refused —
/// is `Ok`.
///
/// Ordering (DESIGN.md, "Transaction commitment" + anti-replay log):
///  1. PIN — before anything is signed or recorded (ADR-0008). A bad PIN is
///     never logged: the PIN is not part of the commitment, so recording it
///     would wrongly replay a `BAD_PIN` refusal for the same transaction
///     resubmitted with the correct PIN.
///  2. decode both PSBTs (needed to build the commitment).
///  3. compute the `commitment_id` binding this decision to the exact tx.
///  4. idempotency — an identical, unexpired resubmission returns the recorded
///     verdict without re-evaluating.
///  5. node-capped expiry check against the node's own clock.
///  6. the V0-1 checks (user-signature verification, then policy-core).
///  7. record the verdict — only when the commitment fully determines it (see
///     [`is_recordable_verdict`]) — then answer.
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
    //    different id and is never blocked here.
    {
        let mut log = node.replay_log.borrow_mut();
        log.prune(now);
        if let Some(recorded) = log.get(&commitment_id, now) {
            return Ok(recorded);
        }
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

    // 6 + 7. Evaluate (user-signature verification, then policy-core, then
    // signing), record the verdict, and answer. The log is an idempotency and
    // audit record: an identical commitment resubmitted before expiry gets the
    // same answer without re-evaluation. Only verdicts the commitment fully
    // determines are recorded — a signature- or PSBT-structure-dependent
    // refusal is left unrecorded so the same commitment resubmitted with a
    // corrected signature is re-evaluated, not answered from a stale refusal
    // (the log does not defend the signature; DESIGN.md, "What the anti-replay
    // log is — and is not").
    let verdict = evaluate_and_sign(node, &mut psbt);
    if is_recordable_verdict(&verdict) {
        node.replay_log
            .borrow_mut()
            .record(commitment_id, request.expiry, verdict.clone());
    }
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

/// The V0-1 evaluation: verify the user's signatures, run policy-core, and —
/// on success — add this node's signatures (`hold_secs = 0`, ADR-0004's
/// instant path). Returns the verdict to record and answer with.
fn evaluate_and_sign(node: &Node, psbt: &mut Psbt) -> SignResponse {
    // The user's partial signature must cryptographically verify on every
    // input against the node's own recomputed sighash — presence of a
    // partial_sig is never enough (DESIGN.md, "Sighash enforcement"). This
    // subsumes the "no output mutation after authorization" check: any
    // mutation after signing changes the sighash and invalidates the very
    // signature the node verifies.
    if let Err(response) = verify_user_signatures(node, psbt) {
        return response;
    }
    // The first-light policy checks (destination allowlist, fee cap).
    if let Err(v) = policy_core::evaluate(psbt, &node.check_params) {
        return refusal(map_policy_code(v.code), v.check, v.detail);
    }
    match add_node_signatures(node, psbt) {
        Ok(()) => SignResponse::Signed(psbt.to_string()),
        Err(detail) => refusal(RefusalCode::PsbtInconsistent, "signing", detail),
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
/// - `DEST_NOT_ALLOWED` / `FEE_EXCEEDS_CAP` — the two policy refusals that turn
///   solely on outputs and fee, both bound by the commitment.
///
/// Signature- and PSBT-structure-dependent refusals (`USER_SIG_INVALID`,
/// `BAD_SIGHASH`, `PSBT_INCONSISTENT`) are NOT recorded: the commitment does
/// not bind the signature or `witness_utxo` presence they turn on, so an
/// identical commitment resubmitted with a corrected signature would otherwise
/// replay a stale refusal and block an honest spend. The log does not defend
/// the signature — V0-1's sighash binding does (DESIGN.md, "What the
/// anti-replay log is — and is not"). `Pending` is unreachable at first light
/// (`hold_secs = 0`) and never recorded here.
fn is_recordable_verdict(verdict: &SignResponse) -> bool {
    match verdict {
        SignResponse::Signed(_) => true,
        SignResponse::Refusal(refusal) => matches!(
            refusal.code,
            RefusalCode::DestNotAllowed | RefusalCode::FeeExceedsCap
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
        policy_core::ViolationCode::DestNotAllowed => RefusalCode::DestNotAllowed,
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
