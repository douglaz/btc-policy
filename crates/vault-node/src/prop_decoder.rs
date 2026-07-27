//! V0-7: decoder robustness ("fuzz") for every untrusted-input parser a hostile
//! coordinator or peer can reach.
//!
//! cargo-fuzz/libFuzzer needs clang, which this build environment does not have,
//! so the fuzzing is done as proptest-driven arbitrary-byte robustness testing —
//! the same shape of coverage (random and near-valid bytes at the parser, asserting
//! no panic and a clean typed refusal) without the LLVM toolchain.
//!
//! Four corpora, because random noise alone only ever exercises the first few
//! bytes of a decoder:
//!
//!  - **noise**: arbitrary bytes straight at `/channel` and at the request decoder;
//!  - **near-valid**: a genuinely valid, correctly-signed envelope with exactly ONE
//!    field replaced or one byte corrupted, which is the only way to reach the
//!    checks that live BEHIND the signature;
//!  - **authenticated garbage**: a correctly-signed envelope (or a correctly
//!    coord-signed `/sign` request) whose PAYLOAD is arbitrary bytes — the
//!    compromised-peer and post-wrench-coordinator model;
//!  - **near-valid payloads**: one-byte corruptions of real `PartialPayload`,
//!    `TaggedRequest`, and PSBT encodings, which drive the parsers past their first
//!    framing checks.
//!
//! What is asserted throughout: no panic on ANY input and a typed rejection for
//! malformed input. The envelope-field corpus additionally pins the EXACT reject
//! reason, so a check that silently stopped firing cannot hide behind "well, it was
//! rejected".
//! The one corruption property is stated SEMANTICALLY (a surviving body must carry
//! the same message) rather than byte-level, because hex is case-insensitive; see
//! [`no_single_byte_corruption_of_a_valid_envelope_changes_what_the_node_acts_on`].

use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};

use bitcoin::hex::DisplayHex;
use bitcoin::Psbt;
use proptest::prelude::*;
use proptest::test_runner::FileFailurePersistence;
use vault_proto::{RefreshRequest, SignRequest, SignResponse, TaggedRequest};

use crate::channel::fixture::Fixture;
use crate::channel::{
    ChannelReply, ChannelState, Envelope, Ingested, PartialPayload, RejectReason, MSG_TYPE_PARTIAL,
    MSG_TYPE_REQUEST,
};
use crate::test_support::{
    coord_sign, coord_sign_refresh, node_and_valid_request, valid_refresh_request,
};
use crate::{handle_channel_body, handle_refresh, handle_sign, Node};

/// Counterexamples persist BESIDE this file. The path is stated explicitly rather
/// than left to proptest's `SourceParallel` default, which resolves `file!()`
/// against a directory that differs between a workspace build and a package build;
/// `Direct` is resolved against cargo's test CWD (the package root), so the file
/// always lands in `crates/vault-node/src/proptest-regressions/` and is committed.
pub(super) fn config(path: &'static str) -> ProptestConfig {
    ProptestConfig {
        failure_persistence: Some(Box::new(FileFailurePersistence::Direct(path))),
        ..ProptestConfig::default()
    }
}

/// The fixed instants every channel case runs at. The envelope freshness gate is
/// not what these properties are about, so sender and receiver share one clock.
const TS: u64 = 1_700_000_000;

/// The receiving node's id in the 2-of-3 fixture below.
const SELF_ID: u16 = 0;

/// A 2-of-3 channel fixture plus node 0 as a fully-built [`Node`], with the
/// per-peer quota raised well above the case budget: the properties send hundreds
/// of correctly-signed envelopes from one peer, and being rate-limited partway
/// through would silently stop testing the decoder.
fn channel_node() -> (Fixture, Node) {
    let fixture = Fixture::new(2, 3);
    let node = crate::test_support::load_node(&fixture.config(
        SELF_ID,
        0,
        "per_peer_quota_per_min = 1000000\n",
    ))
    .expect("valid channel config");
    (fixture, node)
}

fn channel_of(node: &Node) -> &ChannelState {
    node.channel.as_ref().expect("channel mode")
}

/// A correctly-signed envelope from peer 1 to node 0 carrying `payload`.
fn signed_envelope(fixture: &Fixture, msg_type: &str, payload: &[u8]) -> Envelope {
    fixture
        .channel_state(1)
        .build_envelope(msg_type, SELF_ID, payload, TS)
        .expect("envelope")
}

fn envelope_bytes(envelope: &Envelope) -> Vec<u8> {
    serde_json::to_vec(envelope).expect("an Envelope is always serializable")
}

/// One replacement of exactly one envelope field. Every variant is something a
/// hostile peer can put on the wire; the property below states, per variant, the
/// exact reason the node must answer with.
#[derive(Debug, Clone)]
enum FieldMutation {
    MsgType(String),
    ProtocolVersion(u32),
    /// A syntactically valid but different 32-byte id.
    WalletId([u8; 32]),
    ManifestHash([u8; 32]),
    /// Not 32 bytes of hex at all.
    WalletIdGarbage(String),
    ManifestHashGarbage(String),
    Sender(u16),
    Recipient(u16),
    PayloadB64(String),
    /// A syntactically valid but different 16-byte nonce.
    Nonce([u8; 16]),
    NonceGarbage(String),
    Timestamp(u64),
    /// Even-length hex that is not a valid DER ECDSA signature.
    SigMalformedDer(Vec<u8>),
    SigGarbage(String),
}

/// Strings that are definitely not hex of the required length.
fn non_hex_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        Just(String::new()),
        Just("zz".to_string()),
        Just("0".to_string()),
        "[g-zG-Z]{2,40}",
        proptest::collection::vec(any::<u8>(), 0..8)
            .prop_map(|b| b.to_lower_hex_string())
            .prop_filter("must not be the right length", |s| s.len() != 64),
    ]
}

fn field_mutation_strategy() -> impl Strategy<Value = FieldMutation> {
    prop_oneof![
        "[a-z_]{0,16}".prop_map(FieldMutation::MsgType),
        any::<u32>().prop_map(FieldMutation::ProtocolVersion),
        any::<[u8; 32]>().prop_map(FieldMutation::WalletId),
        any::<[u8; 32]>().prop_map(FieldMutation::ManifestHash),
        non_hex_strategy().prop_map(FieldMutation::WalletIdGarbage),
        non_hex_strategy().prop_map(FieldMutation::ManifestHashGarbage),
        any::<u16>().prop_map(FieldMutation::Sender),
        any::<u16>().prop_map(FieldMutation::Recipient),
        "[A-Za-z0-9+/=]{0,40}".prop_map(FieldMutation::PayloadB64),
        any::<[u8; 16]>().prop_map(FieldMutation::Nonce),
        non_hex_strategy().prop_map(FieldMutation::NonceGarbage),
        any::<u64>().prop_map(FieldMutation::Timestamp),
        proptest::collection::vec(any::<u8>(), 0..72).prop_map(FieldMutation::SigMalformedDer),
        prop_oneof![Just("zz".to_string()), Just("abc".to_string())]
            .prop_map(FieldMutation::SigGarbage),
    ]
}

/// Apply `mutation` to a copy of `envelope`; `None` when the "mutation" happens to
/// reproduce the original value, which is not a mutation at all.
fn mutate(
    envelope: &Envelope,
    mutation: &FieldMutation,
    self_wallet: &[u8; 32],
) -> Option<Envelope> {
    let mut e = envelope.clone();
    match mutation {
        FieldMutation::MsgType(s) => {
            if *s == e.msg_type {
                return None;
            }
            e.msg_type = s.clone();
        }
        FieldMutation::ProtocolVersion(v) => {
            if *v == e.protocol_version {
                return None;
            }
            e.protocol_version = *v;
        }
        FieldMutation::WalletId(id) => {
            if id == self_wallet {
                return None;
            }
            e.wallet_id = id.to_lower_hex_string();
        }
        FieldMutation::ManifestHash(h) => {
            let hex = h.to_lower_hex_string();
            if hex == e.manifest_hash {
                return None;
            }
            e.manifest_hash = hex;
        }
        FieldMutation::WalletIdGarbage(s) => e.wallet_id = s.clone(),
        FieldMutation::ManifestHashGarbage(s) => e.manifest_hash = s.clone(),
        FieldMutation::Sender(id) => {
            if *id == e.sender_node_id {
                return None;
            }
            e.sender_node_id = *id;
        }
        FieldMutation::Recipient(id) => {
            if *id == e.recipient_node_id {
                return None;
            }
            e.recipient_node_id = *id;
        }
        FieldMutation::PayloadB64(s) => {
            if *s == *e.payload_b64 {
                return None;
            }
            e.payload_b64 = s.clone().into();
        }
        FieldMutation::Nonce(n) => {
            let hex = n.to_lower_hex_string();
            if hex == e.nonce {
                return None;
            }
            e.nonce = hex;
        }
        FieldMutation::NonceGarbage(s) => e.nonce = s.clone(),
        FieldMutation::Timestamp(t) => {
            if *t == e.timestamp {
                return None;
            }
            e.timestamp = *t;
        }
        FieldMutation::SigMalformedDer(der) => {
            let hex = der.to_lower_hex_string();
            if hex == e.channel_sig {
                return None;
            }
            e.channel_sig = hex;
        }
        FieldMutation::SigGarbage(s) => e.channel_sig = s.clone(),
    }
    Some(e)
}

/// ORACLE: the reason `ingest` must answer, in the order `ingest` checks.
///
/// `node_count` is the federation size; `self_id` the receiving node.
fn expected_reason(mutation: &FieldMutation, node_count: u16, self_id: u16) -> RejectReason {
    match mutation {
        // Structurally undecodable fields lose before anything is compared.
        FieldMutation::WalletIdGarbage(_)
        | FieldMutation::ManifestHashGarbage(_)
        | FieldMutation::NonceGarbage(_)
        | FieldMutation::SigGarbage(_) => RejectReason::MalformedJson,
        // Then the manifest-pinned scalars, all BEFORE the signature is checked.
        FieldMutation::ProtocolVersion(_) => RejectReason::BadProtocolVersion,
        FieldMutation::WalletId(_) => RejectReason::WrongWallet,
        FieldMutation::ManifestHash(_) => RejectReason::WrongManifest,
        FieldMutation::Recipient(_) => RejectReason::WrongRecipient,
        FieldMutation::Sender(id) => {
            // A sender that is not an in-manifest peer is unknown; a sender that IS
            // one simply did not produce this signature.
            if *id == self_id || *id >= node_count {
                RejectReason::UnknownSender
            } else {
                RejectReason::BadChannelSig
            }
        }
        // Everything else is a SIGNED field (or the signature itself), so the
        // envelope signature is what refuses it — the "signature before decode"
        // ordering: none of these ever reach the payload decoder.
        FieldMutation::MsgType(_)
        | FieldMutation::PayloadB64(_)
        | FieldMutation::Nonce(_)
        | FieldMutation::Timestamp(_)
        | FieldMutation::SigMalformedDer(_) => RejectReason::BadChannelSig,
    }
}

fn rejected(ingested: Ingested) -> Option<RejectReason> {
    match ingested {
        Ingested::Reply(ChannelReply::Rejected(reason)) => Some(reason),
        _ => None,
    }
}

/// A fresh coordinator nonce per submission.
fn fresh_nonce() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    format!("v07-decoder-{}", COUNTER.fetch_add(1, Ordering::Relaxed))
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[test]
fn arbitrary_bytes_never_panic_the_channel_decoder() {
    let (_fixture, node) = channel_node();
    let channel = channel_of(&node);
    proptest!(
        config("src/proptest-regressions/prop_decoder_noise.txt"),
        |(body in proptest::collection::vec(any::<u8>(), 0..2048))| {
            // The raw envelope decoder …
            let reason = rejected(channel.ingest(&body, TS));
            prop_assert!(
                reason.is_some(),
                "arbitrary bytes must earn a typed rejection, got something else"
            );
            // … and the whole `/channel` entry point the axum handler calls.
            prop_assert!(matches!(
                handle_channel_body(&node, &body, TS),
                ChannelReply::Rejected(_)
            ));
        }
    );
}

#[test]
fn a_valid_envelope_with_one_mutated_field_is_rejected_for_the_exact_right_reason() {
    let (fixture, node) = channel_node();
    let channel = channel_of(&node);
    let wallet_id = fixture.wallet_id;
    // The positive control: the UNMUTATED envelope authenticates end to end. It
    // carries a partial for a commitment this node has not registered, so the
    // correct answer is `UnknownCandidate` — a 409, not a rejection. Without this,
    // every assertion below could be passing because the envelope was broken all
    // along.
    let payload = fixture
        .partial_payload(
            &fixture.spend_psbt(&fixture.hot_spk, 7),
            "not-a-registered-commitment",
            0,
            1,
        )
        .to_bytes();
    let valid = signed_envelope(&fixture, MSG_TYPE_PARTIAL, &payload);
    assert!(
        matches!(
            channel.ingest(&envelope_bytes(&valid), TS),
            Ingested::Reply(ChannelReply::UnknownCandidate)
        ),
        "the baseline envelope must authenticate, or the mutations below prove nothing"
    );

    proptest!(
        config("src/proptest-regressions/prop_decoder_envelope.txt"),
        |(mutation in field_mutation_strategy())| {
            let Some(mutated) = mutate(&valid, &mutation, &wallet_id) else {
                return Ok(());
            };
            let ingested = channel.ingest(&envelope_bytes(&mutated), TS);
            let reason = rejected(ingested)
                .ok_or_else(|| TestCaseError::fail(format!(
                    "a tampered envelope was not rejected: {mutation:?}"
                )))?;
            prop_assert_eq!(
                reason,
                expected_reason(&mutation, 3, SELF_ID),
                "wrong reject reason for {:?}",
                mutation
            );
        }
    );
}

/// Two envelope bodies carry the SAME message when every field the node acts on
/// agrees. The four hex fields are compared CASE-FOLDED, because the decoders they
/// pass through (`from_hex_32` / `from_hex_16` / `from_hex_vec`, `channel.rs:321`)
/// are case-insensitive: `…8d4b…` and `…8D4b…` are the same 32 bytes, so they are
/// one wallet id / manifest hash / nonce / signature, not two.
fn assert_same_message(survived: &Envelope, original: &Envelope) -> Result<(), TestCaseError> {
    prop_assert_eq!(&survived.msg_type, &original.msg_type);
    prop_assert_eq!(survived.protocol_version, original.protocol_version);
    prop_assert_eq!(
        survived.wallet_id.to_lowercase(),
        original.wallet_id.to_lowercase()
    );
    prop_assert_eq!(
        survived.manifest_hash.to_lowercase(),
        original.manifest_hash.to_lowercase()
    );
    prop_assert_eq!(survived.sender_node_id, original.sender_node_id);
    prop_assert_eq!(survived.recipient_node_id, original.recipient_node_id);
    prop_assert_eq!(survived.nonce.to_lowercase(), original.nonce.to_lowercase());
    prop_assert_eq!(survived.timestamp, original.timestamp);
    prop_assert_eq!(
        survived.channel_sig.to_lowercase(),
        original.channel_sig.to_lowercase()
    );
    // Compared without ever printing it: a `request` payload carries the PIN, which
    // is why `Envelope`'s own `Debug` redacts this field (`channel.rs:621`).
    prop_assert!(
        *survived.payload_b64 == *original.payload_b64,
        "the payload changed"
    );
    Ok(())
}

#[test]
fn no_single_byte_corruption_of_a_valid_envelope_changes_what_the_node_acts_on() {
    // The receiver is rebuilt per case (inside the closure) so its replay cache starts
    // empty every time; keep only the fixture here to sign ONE fixed, deterministic
    // envelope (a random per-case nonce would break proptest replay).
    let (fixture, _seed_node) = channel_node();
    let payload = fixture
        .partial_payload(
            &fixture.spend_psbt(&fixture.hot_spk, 7),
            "not-a-registered-commitment",
            0,
            1,
        )
        .to_bytes();
    let original = signed_envelope(&fixture, MSG_TYPE_PARTIAL, &payload);
    let valid = envelope_bytes(&original);
    proptest!(
        config("src/proptest-regressions/prop_decoder_corruption.txt"),
        |(position in 0usize..4096, xor in 1u8..=255, truncate in any::<bool>())| {
            // A FRESH receiver (same fixture keys/manifest, EMPTY replay cache) per
            // case, so a corruption that survives signature is judged by the decoder +
            // `assert_same_message` below, NEVER masked by a `ReplayedNonce` left when
            // an earlier case's (semantically-equal) corruption was accepted and
            // consumed the shared nonce (v0-exit review 2026-07-23, codex). The
            // envelope stays built once above (deterministic); only the receiver resets.
            let node = crate::test_support::load_node(
                &fixture.config(SELF_ID, 0, "per_peer_quota_per_min = 1000000\n"),
            )
            .expect("valid channel config");
            let channel = channel_of(&node);
            let mut body = valid.clone();
            if truncate {
                let cut = position % body.len();
                body.truncate(cut);
            } else {
                let index = position % body.len();
                body[index] ^= xor;
            }
            if body == valid {
                return Ok(());
            }
            // Every envelope field is covered by `channel_sig`, so a corrupted body
            // is normally rejected outright. The exception is not a hole: hex is
            // case-insensitive, and `xor = 32` is the ASCII case bit, so flipping it
            // on a hex letter (`'d'` -> `'D'`) re-encodes the SAME bytes. Such a body
            // authenticates because it IS the original message, and accepting it is
            // correct — the replay key is the DECODED nonce (`channel.rs:2277`,
            // consumed at `channel.rs:4110`), never the hex string, so case-folding
            // cannot mint a second identity for one envelope.
            //
            // So the property is semantic rather than byte-level, and keeps its
            // teeth: a corruption that survives while changing ANY field the node
            // acts on still fails here.
            if rejected(channel.ingest(&body, TS)).is_some() {
                return Ok(());
            }
            let survived: Envelope = serde_json::from_slice(&body).map_err(|e| {
                TestCaseError::fail(format!("an accepted body must decode: {e}"))
            })?;
            assert_same_message(&survived, &original)?;
        }
    );
}

#[test]
fn an_authenticated_peer_cannot_panic_the_payload_decoder() {
    let (fixture, node) = channel_node();
    // A compromised peer HOLDS a valid channel key, so it can put anything it likes
    // behind a correct signature. Everything malformed on the outside dies at the
    // signature; the separate near-valid property below drives deeper JSON fields.
    proptest!(
        config("src/proptest-regressions/prop_decoder_payload.txt"),
        |(
            payload in proptest::collection::vec(any::<u8>(), 0..1024),
            msg_type in prop_oneof![
                Just(MSG_TYPE_PARTIAL.to_string()),
                Just(MSG_TYPE_REQUEST.to_string()),
                "[a-z]{1,12}",
            ],
        )| {
            let payload_decodes = match msg_type.as_str() {
                MSG_TYPE_PARTIAL => serde_json::from_slice::<PartialPayload>(&payload).is_ok(),
                MSG_TYPE_REQUEST => serde_json::from_slice::<TaggedRequest>(&payload).is_ok(),
                _ => false,
            };
            let envelope = signed_envelope(&fixture, &msg_type, &payload);
            // Drive the production `/channel` dispatcher, not just the envelope
            // layer. If arbitrary bytes happen to decode as a request, this also
            // exercises the node's signing/refresh and carrier-confirmation path.
            let reply = handle_channel_body(&node, &envelope_bytes(&envelope), TS);
            match msg_type.as_str() {
                MSG_TYPE_PARTIAL | MSG_TYPE_REQUEST => {
                    // Truly malformed bytes always get a typed parser rejection.
                    // If the arbitrary corpus happens to form a syntactically valid
                    // payload, returning from its deeper semantic path is the
                    // robustness property.
                    if !payload_decodes {
                        prop_assert_eq!(
                            reply,
                            ChannelReply::Rejected(RejectReason::MalformedPayload)
                        );
                    }
                }
                _ => prop_assert_eq!(
                    reply,
                    ChannelReply::Rejected(RejectReason::UnknownMsgType)
                ),
            }
        }
    );
}

#[test]
fn an_authenticated_peer_cannot_panic_near_valid_payload_decoders() {
    let (fixture, node) = channel_node();
    let spend = fixture.spend_psbt(&fixture.hot_spk, 7);
    let partial = fixture
        .partial_payload(&spend, "not-a-registered-commitment", 0, 1)
        .to_bytes();
    let request =
        TaggedRequest::Spend(fixture.spend_request(&spend, TS + 3_600, "v07-near-valid-payload"));
    let request = serde_json::to_vec(&request).expect("TaggedRequest serializes");

    proptest!(
        config("src/proptest-regressions/prop_decoder_near_valid_payload.txt"),
        |(
            is_request in any::<bool>(),
            position in 0usize..4096,
            xor in 1u8..=255,
            truncate in any::<bool>(),
        )| {
            let original = if is_request { &request } else { &partial };
            let mut payload = original.clone();
            if truncate {
                payload.truncate(position % payload.len());
            } else {
                let index = position % payload.len();
                payload[index] ^= xor;
            }
            prop_assume!(payload != *original);

            let msg_type = if is_request {
                MSG_TYPE_REQUEST
            } else {
                MSG_TYPE_PARTIAL
            };
            let envelope = signed_envelope(&fixture, msg_type, &payload);
            // This is the production `/channel` path. Request corruptions that still
            // deserialize continue through signing/refresh and carrier confirmation;
            // malformed requests and every partial outcome return a typed reply.
            let reply = handle_channel_body(&node, &envelope_bytes(&envelope), TS);
            if is_request {
                match serde_json::from_slice::<TaggedRequest>(&payload) {
                    Ok(decoded) => {
                        let encoded = serde_json::to_vec(&decoded).expect("re-encode request");
                        prop_assert_eq!(
                            serde_json::from_slice::<TaggedRequest>(&encoded)
                                .expect("re-decode"),
                            decoded
                        );
                        prop_assert!(matches!(
                            reply,
                            ChannelReply::Accepted
                                | ChannelReply::Rejected(RejectReason::MalformedPayload)
                        ));
                    }
                    Err(_) => prop_assert_eq!(
                        reply,
                        ChannelReply::Rejected(RejectReason::MalformedPayload)
                    ),
                }
            } else if serde_json::from_slice::<PartialPayload>(&payload).is_err() {
                prop_assert_eq!(
                    reply,
                    ChannelReply::Rejected(RejectReason::MalformedPayload)
                );
            }
        }
    );
}

#[test]
fn the_request_decoders_never_panic_on_arbitrary_or_near_valid_bytes() {
    let fixture = Fixture::new(2, 3);
    // A REAL PSBT's consensus serialization, so the corrupted corpus below reaches
    // the interior of the PSBT decoder (key-value map, type bytes, length prefixes)
    // instead of dying on the magic bytes the way pure noise always does.
    let real_psbt = fixture.spend_psbt(&fixture.hot_spk, 7).serialize();
    proptest!(
        config("src/proptest-regressions/prop_decoder_request.txt"),
        |(
            noise in proptest::collection::vec(any::<u8>(), 0..2048),
            position in 0usize..4096,
            xor in 1u8..=255,
            truncate in any::<bool>(),
        )| {
            // The `/sign` and `/channel` request bodies, and the PSBT parser both
            // of them feed. Returning at all is the property; anything that DOES
            // decode must then re-encode to itself, so no decoder can accept bytes
            // it cannot reproduce.
            let _ = serde_json::from_slice::<TaggedRequest>(&noise);
            let _ = serde_json::from_slice::<SignRequest>(&noise);
            let _ = Psbt::deserialize(&noise);
            if let Ok(text) = std::str::from_utf8(&noise) {
                let _ = Psbt::from_str(text);
                let _ = serde_json::from_str::<TaggedRequest>(text);
            }

            let mut corrupted = real_psbt.clone();
            if truncate {
                corrupted.truncate(position % real_psbt.len());
            } else {
                corrupted[position % real_psbt.len()] ^= xor;
            }
            prop_assume!(corrupted != real_psbt);
            if let Ok(decoded) = Psbt::deserialize(&corrupted) {
                prop_assert_eq!(
                    Psbt::deserialize(&decoded.serialize()).expect("re-decode"),
                    decoded,
                    "a decoded PSBT must re-serialize to something that decodes back to it"
                );
            }
        }
    );
}

#[test]
fn a_correctly_coordinator_signed_request_of_garbage_is_refused_not_panicked() {
    // The post-wrench coordinator: it holds the auth key, so it can sign anything.
    // Its signature buys it past the ingress gate and straight into the PSBT
    // decoder — the deepest a non-peer attacker can push untrusted bytes.
    let (node, valid) = node_and_valid_request();
    proptest!(
        config("src/proptest-regressions/prop_decoder_signed_request.txt"),
        |(
            spend in "[A-Za-z0-9+/=]{0,64}",
            escape in "[A-Za-z0-9+/=]{0,64}",
            reuse_valid_spend in any::<bool>(),
        )| {
            let mut request = SignRequest {
                psbt: if reuse_valid_spend { valid.psbt.clone() } else { spend },
                escape_psbt: escape,
                escape_bumps: Vec::new(),
                // Keep the enrolled PIN fixed: PIN-shape and lockout behavior have
                // their own properties, while every case here must reach a PSBT
                // decoder rather than eventually short-circuit on attempt lockout.
                pin: "1234".into(),
                nonce: String::new(),
                expiry: valid.expiry,
                policy_version: valid.policy_version,
                coord_sig: String::new(),
            };
            coord_sign(&mut request, &node.wallet_id, &fresh_nonce());
            match handle_sign(&node, &request, now()) {
                // A 400 for an undecodable PSBT, or a structured refusal. Never an
                // acceptance: none of these carry a user-signed vault spend.
                Err(_) => {}
                Ok(SignResponse::Refusal(refusal)) => {
                    prop_assert_ne!(
                        refusal.check,
                        "pin_attempt_budget",
                        "decoder coverage silently degraded into PIN lockout"
                    );
                }
                Ok(SignResponse::Accepted(accepted)) => {
                    return Err(TestCaseError::fail(format!(
                        "garbage was accepted: {accepted:?}"
                    )))
                }
            }
        }
    );
}

#[test]
fn a_correctly_coordinator_signed_refresh_reaches_its_psbt_decoder() {
    let (node, spend) = node_and_valid_request();
    let valid = valid_refresh_request(&node, &spend, "v07-refresh-baseline");
    let valid_psbt = valid.refresh_psbt.as_bytes().to_vec();

    proptest!(
        config("src/proptest-regressions/prop_decoder_signed_refresh.txt"),
        |(
            garbage in "[A-Za-z0-9+/=]{0,64}",
            near_valid in any::<bool>(),
            position in 0usize..4096,
            xor in 1u8..=31,
            truncate in any::<bool>(),
        )| {
            let refresh_psbt = if near_valid {
                let mut bytes = valid_psbt.clone();
                if truncate {
                    bytes.truncate(position % bytes.len());
                } else {
                    let index = position % bytes.len();
                    bytes[index] ^= xor;
                }
                String::from_utf8(bytes).expect("base64 xor stays ASCII")
            } else {
                // `!` is outside the base64 alphabet, so this branch is guaranteed
                // malformed while still varying the rest of the hostile input.
                format!("!{garbage}")
            };
            prop_assert_ne!(&refresh_psbt, &valid.refresh_psbt);
            let mut request = RefreshRequest {
                refresh_psbt,
                nonce: String::new(),
                expiry: valid.expiry,
                policy_version: valid.policy_version,
                coord_sig: String::new(),
            };
            coord_sign_refresh(&mut request, &node.wallet_id, &fresh_nonce());
            let outcome = handle_refresh(&node, &request, now());
            if !near_valid {
                prop_assert!(
                    outcome.is_err(),
                    "guaranteed malformed refresh PSBT did not return BadRequest: {:?}",
                    outcome
                );
            }
            // For near-valid encodings, returning any typed outcome is the property:
            // some byte edits remain valid PSBT metadata and are then decided by the
            // user-signature and policy layers. In every case this call reached the
            // refresh-specific decoder behind a valid coordinator signature.
        }
    );
}
