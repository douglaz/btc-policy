//! vault-node: one federation key, one policy engine, `POST /sign`.
//!
//! First-light scope (see docs/DESIGN.md "Milestones"): PIN verification,
//! the two policy-core checks, user partial-signature presence, and node
//! signing at first submission (`hold_secs = 0`). The Hold, duress actions,
//! lockdown, watchtower duty, and `GET /events` are v0 work.

pub mod http;

use std::collections::BTreeSet;
use std::str::FromStr;

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use bitcoin::sighash::SighashCache;
use bitcoin::{EcdsaSighashType, Psbt, PublicKey, ScriptBuf};
use miniscript::descriptor::WshInner;
use miniscript::{Descriptor, Terminal};
use serde::Deserialize;
use vault_proto::{Refusal, RefusalCode, SignRequest, SignResponse};

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

/// Handle one `/sign` submission. `Err(BadRequest)` means undecodable input
/// (HTTP 400); every policy outcome — signed or refused — is `Ok`.
pub fn handle_sign(node: &Node, request: &SignRequest) -> Result<SignResponse, BadRequest> {
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

    // 3. The first-light policy checks (destination allowlist, fee cap).
    if let Err(v) = policy_core::evaluate(&psbt, &node.check_params) {
        return Ok(refusal(map_policy_code(v.code), v.check, v.detail));
    }

    // 4. The user's partial signature must be present for the user key on
    //    every input. Presence only at first light; cryptographic
    //    verification against the node's own recomputed sighash is v0 work.
    for (index, input) in psbt.inputs.iter().enumerate() {
        if !input.partial_sigs.contains_key(&node.user_pubkey) {
            return Ok(refusal(
                RefusalCode::UserSigInvalid,
                "user_signature",
                format!("input {index} carries no partial signature for the user key"),
            ));
        }
    }

    // 5. hold_secs = 0: sign at first submission (ADR-0004's instant path).
    match add_node_signatures(node, &mut psbt) {
        Ok(()) => Ok(SignResponse::Signed(psbt.to_string())),
        Err(detail) => Ok(refusal(RefusalCode::PsbtInconsistent, "signing", detail)),
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
