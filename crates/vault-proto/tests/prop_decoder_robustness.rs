//! V0-7: arbitrary-byte robustness for the wire types a hostile coordinator or
//! peer feeds a node.
//!
//! Everything a node decodes before it has authenticated anything lives here: the
//! tagged `/sign` body, the spend and refresh arms, and the response types the
//! coordinator decodes coming back. Three assertions, over three corpora (noise,
//! near-valid JSON, and structurally-valid-but-hostile field values):
//!
//!  - no input panics a decoder;
//!  - malformed input is a typed `Err`, never a partially-decoded value;
//!  - anything that DOES decode round-trips back to itself, so a decoder cannot
//!    quietly drop or coerce a field a later check depends on.
//!
//! The PIN is the one field with behaviour beyond decoding — it is zeroized on
//! drop and redacted in `Debug` — so the redaction is asserted over arbitrary
//! plaintexts rather than the one fixed sample the unit tests use.
//!
//! Counterexamples persist to `crates/vault-proto/tests/proptest-regressions/`.

use proptest::prelude::*;
use proptest::test_runner::FileFailurePersistence;
use vault_proto::{
    Accepted, Pin, RefreshRequest, Refusal, RefusalCode, SignRequest, SignResponse, TaggedRequest,
    MAX_PIN_BYTES,
};

/// See `prop_commitment_binding.rs` for why the persistence path is explicit.
fn config() -> ProptestConfig {
    ProptestConfig {
        failure_persistence: Some(Box::new(FileFailurePersistence::Direct(
            "tests/proptest-regressions/prop_decoder_robustness.txt",
        ))),
        ..ProptestConfig::default()
    }
}

/// A structurally valid tagged request whose every string field is arbitrary —
/// the shape a coordinator that has gone hostile actually sends: well-formed JSON,
/// nonsense contents.
fn tagged_request_strategy() -> impl Strategy<Value = TaggedRequest> {
    let text = ".{0,64}";
    prop_oneof![
        (
            text,
            text,
            prop::collection::vec(text, 0..3),
            text,
            text,
            any::<u64>(),
            any::<u32>(),
            text,
        )
            .prop_map(
                |(
                    psbt,
                    escape_psbt,
                    escape_bumps,
                    pin,
                    nonce,
                    expiry,
                    policy_version,
                    coord_sig,
                )| {
                    TaggedRequest::Spend(SignRequest {
                        psbt,
                        escape_psbt,
                        escape_bumps,
                        pin: pin.as_str().into(),
                        nonce,
                        expiry,
                        policy_version,
                        coord_sig,
                    })
                }
            ),
        (text, text, any::<u64>(), any::<u32>(), text).prop_map(
            |(refresh_psbt, nonce, expiry, policy_version, coord_sig)| TaggedRequest::Refresh(
                RefreshRequest {
                    refresh_psbt,
                    nonce,
                    expiry,
                    policy_version,
                    coord_sig,
                }
            )
        ),
    ]
}

/// A near-valid corpus: real JSON for a real request, with one byte flipped or the
/// body truncated. This is what actually exercises a decoder's interior — pure
/// noise almost always dies on the first character.
fn corrupt(json: &str, position: usize, xor: u8, truncate: bool) -> Vec<u8> {
    let mut bytes = json.as_bytes().to_vec();
    if bytes.is_empty() {
        return bytes;
    }
    if truncate {
        let cut = position % bytes.len();
        bytes.truncate(cut);
    } else {
        let index = position % bytes.len();
        bytes[index] ^= xor;
    }
    bytes
}

/// The request with its `coord_sig` cleared: exactly the content the coordinator
/// signature covers. `coord_sig` is deliberately NOT part of its own preimage, so
/// two requests differing only there are the SAME authenticated request — a
/// corrupted signature is a verification failure, not a different request.
fn signed_fields(request: &TaggedRequest) -> TaggedRequest {
    let mut copy = request.clone();
    match &mut copy {
        TaggedRequest::Spend(spend) => spend.coord_sig.clear(),
        TaggedRequest::Refresh(refresh) => refresh.coord_sig.clear(),
    }
    copy
}

/// The digest a node would authenticate this request under — taken from the
/// DECODED value, exactly as the ingress gate takes it.
fn digest_of(request: &TaggedRequest, wallet_id: &[u8; 32]) -> [u8; 32] {
    match request {
        TaggedRequest::Spend(spend) => spend.coord_request().auth_digest(wallet_id),
        TaggedRequest::Refresh(refresh) => refresh.coord_request().auth_digest(wallet_id),
    }
}

proptest! {
    #![proptest_config(config())]

    /// Arbitrary bytes at every pre-authentication decoder: each must return, and
    /// return an `Err` unless the bytes happened to be a valid encoding.
    #[test]
    fn arbitrary_bytes_never_panic_a_wire_decoder(
        bytes in proptest::collection::vec(any::<u8>(), 0..1024),
    ) {
        // `serde_json` is the only parser these types use, so "does not panic" is
        // the assertion and the call itself is the test. Anything that DOES decode
        // must survive a round trip — a decoder that accepted bytes it could not
        // reproduce would mean the node authenticated a different value than the
        // one it acted on.
        if let Ok(request) = serde_json::from_slice::<TaggedRequest>(&bytes) {
            let reencoded = serde_json::to_string(&request).expect("serialize");
            prop_assert_eq!(
                serde_json::from_str::<TaggedRequest>(&reencoded).expect("re-decode"),
                request
            );
        }
        if let Ok(request) = serde_json::from_slice::<SignRequest>(&bytes) {
            let reencoded = serde_json::to_string(&request).expect("serialize");
            prop_assert_eq!(
                serde_json::from_str::<SignRequest>(&reencoded).expect("re-decode"),
                request
            );
        }
        let _ = serde_json::from_slice::<RefreshRequest>(&bytes);
        let _ = serde_json::from_slice::<SignResponse>(&bytes);
        let _ = serde_json::from_slice::<vault_proto::Commitment>(&bytes);
    }

    /// The near-valid corpus, and the invariant that makes wire-level corruption a
    /// non-event: **what a node authenticates is the DECODED request, never the
    /// bytes it arrived in.** A corrupted body either fails to decode, or decodes
    /// to a value whose coord-auth digest differs exactly when the signed content
    /// differs. It must never panic.
    #[test]
    fn corruption_changes_the_authenticated_digest_exactly_when_it_changes_the_request(
        request in tagged_request_strategy(),
        position in 0usize..4096,
        xor in 1u8..=255,
        truncate in any::<bool>(),
        wallet_id in any::<[u8; 32]>(),
    ) {
        let json = serde_json::to_string(&request).expect("serialize");
        let corrupted = corrupt(&json, position, xor, truncate);
        prop_assume!(corrupted != json.as_bytes());
        if let Ok(decoded) = serde_json::from_slice::<TaggedRequest>(&corrupted) {
            // Decoding CAN still succeed — a flipped byte inside a string field is
            // still a valid string — and it can even yield the ORIGINAL request
            // back. Two ways, both found by this property and both correct:
            //
            //  - corrupting a KEY name makes serde ignore that member and fall back
            //    to the field's `#[serde(default)]`, which is invisible when the
            //    value was already the default (an omitted nonce, a zero expiry);
            //  - corrupting `coord_sig` changes the DTO but not the digest, because
            //    a signature is never part of its own preimage.
            //
            // Neither is a hole, and this assertion is why: the digest is a function
            // of the SIGNED content of the decoded request and of nothing else, so
            // corruption that survives decoding is corruption that changed nothing
            // the signature covers (case 1) or changed only the signature itself,
            // which then simply fails to verify (case 2).
            prop_assert_eq!(
                signed_fields(&decoded) == signed_fields(&request),
                digest_of(&decoded, &wallet_id) == digest_of(&request, &wallet_id),
                "the coord-auth digest must be a function of the decoded request's \
                 signed content, not of the bytes it arrived in"
            );
            let reencoded = serde_json::to_string(&decoded).expect("serialize");
            prop_assert_eq!(
                serde_json::from_str::<TaggedRequest>(&reencoded).expect("re-decode"),
                decoded
            );
        }
    }

    /// The tagged union's whole job (ADR-0013 §2): a spend and a refresh live in
    /// disjoint wire spaces, so a pin-less refresh can never be decoded as a
    /// malformed spend before it reaches the shared coordinator-auth gate.
    #[test]
    fn a_refresh_never_decodes_as_a_spend(request in tagged_request_strategy()) {
        let json = serde_json::to_string(&request).expect("serialize");
        let decoded: TaggedRequest = serde_json::from_str(&json).expect("round trip");
        prop_assert_eq!(&decoded, &request);
        let tagged_correctly = match request {
            TaggedRequest::Spend(_) => json.starts_with(r#"{"spend":"#),
            TaggedRequest::Refresh(_) => json.starts_with(r#"{"refresh":"#),
        };
        prop_assert!(
            tagged_correctly,
            "the external tag must name the arm: {}",
            json
        );
    }

    /// The `/sign` response types round-trip for every code and every payload, so a
    /// coordinator can always read back what a node said. The absence of a
    /// signature-bearing variant is a type-level property (there is no such
    /// variant to construct); the structural assertion below pins the exact wire
    /// fields so no PSBT-bearing field can appear.
    #[test]
    fn sign_response_wire_shape_has_no_psbt_field(
        commitment_id in ".{0,64}",
        first_seen in any::<u64>(),
        remaining_secs in any::<u64>(),
        check in ".{0,32}",
        detail in ".{0,64}",
    ) {
        let accepted = SignResponse::Accepted(Accepted {
            commitment_id,
            first_seen,
            remaining_secs,
        });
        let refusal = SignResponse::Refusal(Refusal {
            code: RefusalCode::BadPin,
            check,
            detail,
        });
        for response in [accepted, refusal] {
            let json = serde_json::to_string(&response).expect("serialize");
            let decoded = serde_json::from_str::<SignResponse>(&json).expect("round trip");
            prop_assert_eq!(
                &decoded,
                &response
            );
            let value: serde_json::Value = serde_json::from_str(&json).expect("JSON value");
            let outer = value.as_object().expect("response is an object");
            prop_assert_eq!(outer.len(), 1, "response has an unexpected top-level field");
            let (variant, expected_fields): (&str, &[&str]) = match &response {
                SignResponse::Accepted(_) => {
                    ("accepted", &["commitment_id", "first_seen", "remaining_secs"])
                }
                SignResponse::Refusal(_) => ("refusal", &["code", "check", "detail"]),
            };
            let fields = outer
                .get(variant)
                .and_then(serde_json::Value::as_object)
                .expect("known response variant");
            prop_assert_eq!(fields.len(), expected_fields.len());
            for field in expected_fields {
                prop_assert!(fields.contains_key(*field), "missing {variant}.{field}");
            }
        }
    }

    /// ADR-0008's "never persisted or logged" over ARBITRARY plaintexts, not the
    /// one sample the unit test uses: every `Debug` rendering uses its fixed
    /// redacted marker, and `clear` empties the secret.
    #[test]
    fn no_debug_rendering_ever_leaks_a_pin(plaintext in "[!-~]{3,64}") {
        let pin: Pin = plaintext.as_str().into();
        let bare = format!("{pin:?}");
        prop_assert_eq!(bare, "Pin(<redacted>)");
        prop_assert_eq!(pin.len(), plaintext.len());
        prop_assert!(!pin.is_empty());

        let mut request = SignRequest {
            psbt: "cHNidP8B".into(),
            escape_psbt: "cHNidP8C".into(),
            // A non-empty fee-bump ladder: the redaction claim has to hold for the
            // laddered shape too, and the ladder is public PSBT text that must render
            // in full so an operator can still identify the request from a log line.
            escape_bumps: vec!["cHNidP8D".into()],
            pin: plaintext.as_str().into(),
            nonce: "n".into(),
            expiry: 1,
            policy_version: 1,
            coord_sig: "00".into(),
        };
        let rendered = format!("{request:?}");
        let rendered_view = format!("{:?}", request.coord_request());
        prop_assert_eq!(
            rendered,
            "SignRequest { psbt: \"cHNidP8B\", escape_psbt: \"cHNidP8C\", escape_bumps: \
             [\"cHNidP8D\"], pin: Pin(<redacted>), nonce: \"n\", expiry: 1, policy_version: 1, \
             coord_sig: \"00\" }"
        );
        prop_assert_eq!(
            rendered_view,
            "CoordRequest::Spend { spend_psbt: \"cHNidP8B\", escape_psbt: \"cHNidP8C\", \
             escape_bumps: [\"cHNidP8D\"], pin: \"<redacted>\", nonce: \"n\", expiry: 1, \
             policy_version: 1 }"
        );
        // The preimage the coordinator signs DOES contain the plaintext — that is
        // what binds the pin to the request — which is exactly why it comes back
        // `Zeroizing`.
        let preimage = request.coord_request().canonical_bytes();
        let binds_the_pin = preimage
            .windows(plaintext.len())
            .any(|w| w == plaintext.as_bytes());
        prop_assert!(binds_the_pin, "the coord-auth preimage must bind the pin");
        request.pin.clear();
        prop_assert!(request.pin.is_empty());
    }

    /// A pin field of any length decodes — the length BOUND is a node-side policy
    /// check against `MAX_PIN_BYTES`, deliberately not a decoder failure, so an
    /// over-length pin reaches the same constant-time compare every other value
    /// does rather than earning a distinguishable early error.
    #[test]
    fn an_over_length_pin_decodes_and_is_left_for_the_node_to_bound(
        plaintext in "[ -~]{0,200}",
    ) {
        let json = serde_json::to_string(&SignRequest {
            psbt: String::new(),
            escape_psbt: String::new(),
            escape_bumps: Vec::new(),
            pin: plaintext.as_str().into(),
            nonce: String::new(),
            expiry: 0,
            policy_version: 0,
            coord_sig: String::new(),
        })
        .expect("serialize");
        let back: SignRequest = serde_json::from_str(&json).expect("deserialize");
        prop_assert_eq!(back.pin.len(), plaintext.len());
        prop_assert_eq!(back.pin.len() > MAX_PIN_BYTES, plaintext.len() > MAX_PIN_BYTES);
    }
}
