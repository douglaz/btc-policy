//! Bead btc-policy-5jt: the combined signature-plus-policy-version gate on the two
//! `/channel` routes it also governs — a FRESH relay receipt and an OUTER-STALE carrier.
//! Declared from `channel.rs` under `#[cfg(test)]` with `#[path]`, so this is still a
//! module of `channel` — `super` is that module, and its private fixture and store
//! accessors are still in scope.
//!
//! The two DIRECT routes are `policy_version_direct_routes`, beside `lib.rs`.

use super::fixture::Fixture;
use super::*;
use crate::Node;
use vault_proto::{SignRequest, SignResponse};

const NOW: u64 = 1_752_000_000;
/// The pinned monotonic second, deliberately nowhere near `NOW`: a Spend nonce records its
/// carrier deadline `D` from this clock, and the outer-stale route reads it back.
const MONO_NOW: u64 = 4_200;
const EXPIRY: u64 = NOW + 3_600;
/// Received far enough past the envelope timestamp that `ingest` classifies it as an
/// outer-stale Spend instead of a fresh relay.
const STALE_AT: u64 = NOW + 301;

/// Node 0 of the fixture federation, in channel mode with its monotonic clock pinned.
fn channel_node(fx: &Fixture) -> Node {
    let node = crate::test_support::load_node(&fx.config(0, 0, "")).expect("config");
    node.channel
        .as_ref()
        .expect("channel")
        .pin_hot_clock(MONO_NOW);
    node
}

/// Everything a receipt could create or derive: registered candidates, arm intents and
/// carrier memos, memory-hard carrier derivations paid for, and the complete ingress sign
/// state (anti-replay log, pending, coordinator nonces and high-water, refresh log, PIN
/// budget).
fn receipt_state(node: &Node) -> (usize, (usize, usize), usize, Vec<String>) {
    let channel = node.channel.as_ref().expect("channel");
    (
        channel.store_len(),
        channel.intent_counts(),
        node.carrier_derivation_count(),
        node.sign_state.lock().expect("sign_state").shape(),
    )
}

/// `request` relayed from peer 1 inside a signed channel envelope stamped `ts` and
/// received at `received_at`.
fn relay(
    fx: &Fixture,
    node: &Node,
    request: &SignRequest,
    ts: u64,
    received_at: u64,
) -> ChannelReply {
    let payload = request_payload(&vault_proto::TaggedRequest::Spend(request.clone()));
    let envelope = fx
        .channel_state(1)
        .build_envelope(MSG_TYPE_REQUEST, 0, &payload, ts)
        .expect("envelope");
    let body = serde_json::to_vec(&envelope).expect("json");
    crate::handle_channel_body_with_clocks(node, &body, received_at, || NOW, || NOW)
}

/// The matching-version request and its byte-for-byte twin re-signed for a policy version
/// this node is not sealed to. Same nonce, same expiry, same PSBTs: the version is the ONLY
/// difference, so nothing else can be deciding these cases.
fn pair(fx: &Fixture, nonce: &str) -> (SignRequest, SignRequest) {
    let spend = fx.spend_psbt(&fx.hot_spk, 7);
    let matching = fx.spend_request(&spend, EXPIRY, nonce);
    let mut mismatched = matching.clone();
    mismatched.policy_version = 2;
    fx.coord_sign(&mut mismatched, nonce);
    (matching, mismatched)
}

/// FRESH RELAY. A peer relays a coordinator-signed Spend naming a policy version this node
/// is not sealed to. The peer learns nothing — `/channel` answers ACCEPTED for every
/// decodable POLICY outcome, so this reply is byte-identical to the one a policy-refused
/// request earns — and nothing is created or derived: no candidate, no arm intent, no
/// carrier memo, no memory-hard derivation, and no coordinator nonce. The matching control
/// on the SAME nonce moves that state, which is what proves the route was live and the
/// silence above was not a wiring accident.
#[test]
fn a_relayed_spend_for_another_policy_version_is_silent_and_derives_nothing() {
    let fx = Fixture::new(2, 3);
    let node = channel_node(&fx);
    let (matching, mismatched) = pair(&fx, "relay-policy-version");

    let before = receipt_state(&node);
    assert_eq!(
        relay(&fx, &node, &mismatched, NOW, NOW),
        ChannelReply::Accepted,
        "a relayed mismatch must not tell the peer this node's verdict"
    );
    assert_eq!(
        receipt_state(&node),
        before,
        "a relayed mismatch may create no receipt state and pay no carrier KDF"
    );

    assert_eq!(
        relay(&fx, &node, &matching, NOW, NOW),
        ChannelReply::Accepted,
        "the matching relay earns the same reply, so the silence is uniform"
    );
    assert_ne!(
        receipt_state(&node),
        before,
        "the matching relay must reach the state the mismatch left alone"
    );
}

/// OUTER-STALE. The same request arriving past the envelope skew window is a stale carrier
/// receipt. A version mismatch is refused by the SAME gate, before the carrier deadline is
/// even looked up: the reply stays `STALE_TIMESTAMP` and no state or derivation follows.
/// The control is the accepted-then-stale copy of the matching request, which reaches the
/// carrier machinery and answers otherwise.
#[test]
fn an_outer_stale_spend_for_another_policy_version_stays_stale_and_derives_nothing() {
    let fx = Fixture::new(2, 3);
    let node = channel_node(&fx);
    let (matching, mismatched) = pair(&fx, "outer-stale-policy-version");
    let stale = ChannelReply::Rejected(RejectReason::StaleTimestamp);

    // This node has already ruled on the matching request, so a carrier deadline for that
    // nonce EXISTS — the outer-stale route has something real to resolve.
    assert!(matches!(
        crate::handle_sign(&node, &matching, NOW).expect("decodable"),
        SignResponse::Accepted(_)
    ));
    let before = receipt_state(&node);

    assert_eq!(
        relay(&fx, &node, &mismatched, NOW, STALE_AT),
        stale,
        "an outer-stale mismatch is stale, not a carrier to resolve"
    );
    assert_eq!(
        receipt_state(&node),
        before,
        "an outer-stale mismatch may derive nothing and claim no holder slot"
    );

    assert_ne!(
        relay(&fx, &node, &matching, NOW, STALE_AT),
        stale,
        "the matching copy reaches the carrier route the mismatch never did"
    );
}
