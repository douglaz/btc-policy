//! Wire types shared by coordinator and nodes; drift is a compile error.
//!
//! Two-phase /sign per ADR-0004/0008: `{psbt, escape_psbt, pin}` ->
//! pending | signed | refusal. See docs/DESIGN.md ("/sign wire contract").
//!
//! Refusals are policy *outcomes*, not transport errors: nodes answer them
//! with HTTP 200. Only input the node cannot decode earns a 400.

use serde::{Deserialize, Serialize};

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
        };
        let json = serde_json::to_string(&req).expect("serialize");
        assert_eq!(
            json,
            r#"{"psbt":"cHNidP8B","escape_psbt":"cHNidP8C","pin":"482913"}"#
        );
        let back: SignRequest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, req);
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
