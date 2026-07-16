//! Wire types shared by coordinator and nodes; drift is a compile error.
//!
//! Two-phase /sign per ADR-0004/0008: `{psbt, escape_psbt, pin}` ->
//! pending | signed | refusal. See docs/DESIGN.md ("/sign wire contract").
//!
//! Refusals are policy *outcomes*, not transport errors: nodes answer them
//! with HTTP 200. Only input the node cannot decode earns a 400.

use bitcoin::hashes::{sha256, Hash};
use serde::{Deserialize, Serialize};

/// The exact-transaction binding a node evaluates and signs against
/// (DESIGN.md, "Transaction commitment"; CONTEXT.md "Commitment"). Built
/// identically on coordinator and node from the same PSBT + config, it keys
/// the anti-replay log by content — **never** by outpoint set, so an RBF
/// replacement or rebroadcast is a fresh commitment, not a blocked replay.
///
/// The fields are plain owned types (not `bitcoin` types) so the struct is
/// serde-native without pulling in `bitcoin`'s serde feature; the canonical
/// byte encoding lives in [`Commitment::canonical_bytes`], not in serde.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commitment {
    /// Hash of the vault descriptor: which vault this spend belongs to.
    pub wallet_id: [u8; 32],
    /// The unsigned transaction's `version` (nVersion). Bound so two txs that
    /// differ only in version get distinct ids (ADR-0012, "the commitment binds
    /// the exact unsigned transaction").
    pub version: i32,
    /// The unsigned transaction's `nLockTime`. Bound for the same reason as
    /// [`Commitment::version`].
    pub lock_time: u32,
    /// Every input the transaction spends, in transaction order.
    pub inputs: Vec<CommitmentInput>,
    /// Every output the transaction pays, in transaction order.
    pub outputs: Vec<CommitmentOutput>,
    /// Absolute fee in satoshis (Σ input value − Σ output value).
    pub fee: u64,
    /// Coordinator-proposed expiry (unix seconds); the node caps it against
    /// its own clock so a hostile coordinator can't inflate retention.
    pub expiry: u64,
    /// The baked-at-setup policy identifier (policy never changes).
    pub policy_version: u32,
}

/// One transaction input, by outpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitmentInput {
    /// Previous-output txid as its raw 32 bytes.
    pub txid: [u8; 32],
    /// Previous-output index.
    pub vout: u32,
    /// This input's `nSequence`. Bound so two txs that differ only in a single
    /// input's sequence get distinct ids (ADR-0012).
    pub sequence: u32,
}

/// One transaction output, by scriptPubKey and amount.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitmentOutput {
    /// Raw scriptPubKey bytes.
    pub script_pubkey: Vec<u8>,
    /// Amount in satoshis.
    pub amount: u64,
}

impl Commitment {
    /// The deterministic, byte-identical encoding both sides hash. Every field
    /// is written at a fixed width, big-endian, with explicit length prefixes,
    /// so the bytes are unambiguous and two constructions of the same logical
    /// commitment produce identical output. The encoding is greenfield until
    /// v1 (DESIGN.md, "Wire format is greenfield until v1").
    ///
    /// Crate-private: the cross-crate contract is delivered through
    /// [`Commitment::commitment_id`]; nothing outside this crate hashes the
    /// bytes directly, so the encoding is not (yet) public surface.
    pub(crate) fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.wallet_id);
        // Header region: the transaction-level fields (nVersion, nLockTime).
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.lock_time.to_be_bytes());
        out.extend_from_slice(&(self.inputs.len() as u32).to_be_bytes());
        for input in &self.inputs {
            out.extend_from_slice(&input.txid);
            out.extend_from_slice(&input.vout.to_be_bytes());
            // Each input's nSequence, alongside its outpoint.
            out.extend_from_slice(&input.sequence.to_be_bytes());
        }
        out.extend_from_slice(&(self.outputs.len() as u32).to_be_bytes());
        for output in &self.outputs {
            out.extend_from_slice(&(output.script_pubkey.len() as u32).to_be_bytes());
            out.extend_from_slice(&output.script_pubkey);
            out.extend_from_slice(&output.amount.to_be_bytes());
        }
        out.extend_from_slice(&self.fee.to_be_bytes());
        out.extend_from_slice(&self.expiry.to_be_bytes());
        out.extend_from_slice(&self.policy_version.to_be_bytes());
        out
    }

    /// Lowercase-hex SHA-256 of [`Commitment::canonical_bytes`]. This is the
    /// key the anti-replay log records verdicts under.
    pub fn commitment_id(&self) -> String {
        sha256::Hash::hash(&self.canonical_bytes()).to_string()
    }
}

/// Body of `POST /sign`. Every submission carries both the primary PSBT and
/// the user-signed escape variant (same-inputs sweep to the escape wallet),
/// plus a PIN — the two-transaction ceremony of ADR-0008.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignRequest {
    /// Base64 PSBT of the spend being requested.
    pub psbt: String,
    /// Base64 PSBT of the escape variant (same inputs, swept to the escape wallet).
    pub escape_psbt: String,
    /// PIN in plaintext (hash-compared on the node; ADR-0008 accepts this for MVP).
    #[serde(default)]
    pub pin: String,
    /// Coordinator-proposed commitment expiry (unix seconds). The node caps it
    /// against its own clock and `max_commitment_age_secs` (DESIGN.md).
    #[serde(default)]
    pub expiry: u64,
    /// Baked policy identifier, bound into the commitment (policy never changes).
    #[serde(default)]
    pub policy_version: u32,
}

/// The three `/sign` outcomes. Serializes to exactly the DESIGN.md wire shapes:
/// `{"pending":{...}}`, `{"signed_psbt":"..."}`, `{"refusal":{...}}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignResponse {
    /// Hot-class spend inside its Hold (ADR-0004). Declared for the wire
    /// contract; not exercised at first light (hold_secs = 0).
    #[serde(rename = "pending")]
    Pending(Pending),
    /// The node ran every check and contributed its signature.
    #[serde(rename = "signed_psbt")]
    Signed(String),
    /// The node refuses to sign, with a machine-readable reason.
    #[serde(rename = "refusal")]
    Refusal(Refusal),
}

/// A hot-class commitment waiting out its Hold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pending {
    pub commitment_id: String,
    /// Unix seconds when this node first saw the commitment.
    pub first_seen: u64,
    /// Seconds left before re-submission returns a signature.
    pub remaining_secs: u64,
}

/// A node's structured decision not to sign.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Refusal {
    pub code: RefusalCode,
    /// Which policy check refused (e.g. "destination_allowlist").
    pub check: String,
    /// Human-readable specifics.
    pub detail: String,
}

/// The refusal-code enum from DESIGN.md ("/sign wire contract"). All variants
/// are declared even where first light never emits them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RefusalCode {
    WrongDescriptor,
    UnknownInput,
    DestNotAllowed,
    ChangeNotDerivable,
    FeeExceedsCap,
    BadSighash,
    UserSigInvalid,
    CommitmentExpired,
    PsbtInconsistent,
    BadPin,
    FraudSuspected,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_request_round_trips() {
        let req = SignRequest {
            psbt: "cHNidP8B".into(),
            escape_psbt: "cHNidP8C".into(),
            pin: "482913".into(),
            expiry: 1_752_500_000,
            policy_version: 1,
        };
        let json = serde_json::to_string(&req).expect("serialize");
        assert_eq!(
            json,
            r#"{"psbt":"cHNidP8B","escape_psbt":"cHNidP8C","pin":"482913","expiry":1752500000,"policy_version":1}"#
        );
        let back: SignRequest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, req);
    }

    /// A commitment with distinct, non-trivial data in every field, built twice
    /// from the same logical inputs (helper below).
    fn sample_commitment(outputs: Vec<CommitmentOutput>) -> Commitment {
        Commitment {
            wallet_id: [0x11; 32],
            version: 2,
            lock_time: 500_001,
            inputs: vec![
                CommitmentInput {
                    txid: [0x22; 32],
                    vout: 0,
                    sequence: 0xffff_fffd,
                },
                CommitmentInput {
                    txid: [0x33; 32],
                    vout: 7,
                    sequence: 0xffff_ffff,
                },
            ],
            outputs,
            fee: 10_000,
            expiry: 1_752_500_000,
            policy_version: 1,
        }
    }

    fn hot_output() -> CommitmentOutput {
        CommitmentOutput {
            script_pubkey: vec![0x00, 0x14, 0xAB, 0xCD],
            amount: 99_990_000,
        }
    }

    #[test]
    fn commitment_serialization_is_deterministic() {
        // Two independent constructions of the same logical commitment.
        let a = sample_commitment(vec![hot_output()]);
        let b = sample_commitment(vec![hot_output()]);
        assert_eq!(a.canonical_bytes(), b.canonical_bytes());
        assert_eq!(a.commitment_id(), b.commitment_id());
        // The id is a 32-byte hash rendered as lowercase hex.
        assert_eq!(a.commitment_id().len(), 64);
    }

    #[test]
    fn commitment_survives_serde_json() {
        let commitment = sample_commitment(vec![hot_output()]);
        let json = serde_json::to_string(&commitment).expect("serialize");
        let back: Commitment = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, commitment);
        // Serde is a transport, not the identity: the recovered value hashes
        // to the same commitment id.
        assert_eq!(back.commitment_id(), commitment.commitment_id());
    }

    #[test]
    fn commitment_is_not_keyed_by_outpoint_set() {
        // Same inputs (outpoints), different outputs and fee: an RBF-style
        // replacement. It MUST hash to a different id, so the log never blocks
        // a legitimate replacement (DESIGN.md, "anti-replay log").
        let original = sample_commitment(vec![hot_output()]);
        let mut replacement = sample_commitment(vec![CommitmentOutput {
            script_pubkey: vec![0x00, 0x14, 0xAB, 0xCD],
            amount: 99_980_000, // fee bump: less to the destination
        }]);
        replacement.fee = 20_000;
        assert_eq!(
            original.inputs, replacement.inputs,
            "the two txs spend the identical outpoints"
        );
        assert_ne!(original.commitment_id(), replacement.commitment_id());
    }

    #[test]
    fn missing_pin_decodes_as_empty_pin() {
        let json = r#"{"psbt":"cHNidP8B","escape_psbt":"cHNidP8C"}"#;
        let back: SignRequest = serde_json::from_str(json).expect("deserialize");
        assert_eq!(back.pin, "");
    }

    #[test]
    fn signed_response_uses_design_doc_shape() {
        let resp = SignResponse::Signed("cHNidP8B".into());
        let json = serde_json::to_string(&resp).expect("serialize");
        assert_eq!(json, r#"{"signed_psbt":"cHNidP8B"}"#);
        let back: SignResponse = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, resp);
    }

    #[test]
    fn pending_response_round_trips() {
        let resp = SignResponse::Pending(Pending {
            commitment_id: "c0ffee".into(),
            first_seen: 1_752_500_000,
            remaining_secs: 86_400,
        });
        let json = serde_json::to_string(&resp).expect("serialize");
        assert_eq!(
            json,
            r#"{"pending":{"commitment_id":"c0ffee","first_seen":1752500000,"remaining_secs":86400}}"#
        );
        let back: SignResponse = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, resp);
    }

    #[test]
    fn refusal_response_round_trips_with_screaming_snake_code() {
        let resp = SignResponse::Refusal(Refusal {
            code: RefusalCode::DestNotAllowed,
            check: "destination_allowlist".into(),
            detail: "output 0 pays a scriptPubKey outside the allowlist".into(),
        });
        let json = serde_json::to_string(&resp).expect("serialize");
        assert_eq!(
            json,
            r#"{"refusal":{"code":"DEST_NOT_ALLOWED","check":"destination_allowlist","detail":"output 0 pays a scriptPubKey outside the allowlist"}}"#
        );
        let back: SignResponse = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, resp);
    }
}
