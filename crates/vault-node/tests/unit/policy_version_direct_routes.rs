//! Bead btc-policy-5jt: the combined signature-plus-policy-version gate on the two DIRECT
//! routes. Declared from `lib.rs` under `#[cfg(test)]` with `#[path]`, so this is still a
//! module of the crate root — `super` is that root, and the private ingress state the
//! assertions read is still in scope.
//!
//! The two `/channel` routes the same gate governs — a fresh relay receipt and an
//! outer-stale carrier — need a channel node and live in
//! `channel::policy_version_relay_routes`.

use super::test_support::{
    coord_sign, coord_sign_refresh, node_and_valid_request, valid_refresh_request,
};
use super::{handle_refresh, handle_sign, Node};
use vault_proto::{RefusalCode, SignResponse};

/// The COMPLETE serialized ingress state: the anti-replay log, pending candidates, the
/// coordinator nonce log and its high-water mark, the refresh log and the PIN attempt
/// budget. A refusal that moved any one of them changes this value, so comparing it
/// across the refusal is what proves the gate consumed nothing.
fn state(node: &Node) -> Vec<String> {
    node.sign_state.lock().expect("sign_state").shape()
}

/// The refusal `response` must be, or a panic naming what came back instead.
fn refusal(response: SignResponse, what: &str) -> (RefusalCode, String, String) {
    match response {
        SignResponse::Refusal(r) => (r.code, r.check, r.detail),
        SignResponse::Accepted(a) => panic!("{what} must be refused, not {a:?}"),
    }
}

/// DIRECT SPEND. A coordinator-signed request naming a policy version this node is not
/// sealed to is refused `PSBT_INCONSISTENT` under a locally authored `policy_version`
/// check, and refused BEFORE anything moves: the whole sign state is byte-identical
/// afterwards, so the single-use nonce it carried is still unseen — proved by re-sending
/// that SAME nonce under the matching version and being ACCEPTED. Without the version
/// gate that adjacent control would come back `NONCE_REPLAYED`.
#[test]
fn a_direct_spend_naming_another_policy_version_is_typed_and_consumes_nothing() {
    let (node, request) = node_and_valid_request();
    assert_eq!(
        node.policy_version, 1,
        "the sealed version this test drives"
    );
    let now = request.expiry - 100;
    let before = state(&node);

    let mut mismatched = request.clone();
    mismatched.policy_version = 2;
    coord_sign(&mut mismatched, &node.wallet_id, "policy-version-spend");
    let answer = handle_sign(&node, &mismatched, now).expect("decodable");
    let (code, check, detail) = refusal(answer, "a spend for policy_version 2");
    assert_eq!(code, RefusalCode::PsbtInconsistent);
    assert_eq!(
        check, "policy_version",
        "the spend check is locally authored"
    );
    assert!(detail.contains("policy_version 2"), "{detail}");
    assert_eq!(
        state(&node),
        before,
        "a refused spend may consume no nonce, candidate or PIN attempt"
    );

    // The ADJACENT MATCHING CONTROL, on the very nonce the refusal saw. It is accepted,
    // so the refusal above neither recorded that nonce nor charged the budget, and
    // nothing but the version was ever wrong with these bytes.
    let mut matching = request.clone();
    coord_sign(&mut matching, &node.wallet_id, "policy-version-spend");
    assert!(
        matches!(
            handle_sign(&node, &matching, now).expect("decodable"),
            SignResponse::Accepted(_)
        ),
        "the same spend nonce under the sealed version must still be admissible"
    );
}

/// DIRECT REFRESH, through its own handler and its own state: the same typed refusal, the
/// same locally authored check, and the same untouched state — including the refresh log,
/// which a refusal reaching registration would have written to.
#[test]
fn a_direct_refresh_naming_another_policy_version_is_typed_and_consumes_nothing() {
    let (node, spend) = node_and_valid_request();
    let now = spend.expiry - 100;
    let refresh = valid_refresh_request(&node, &spend, "policy-version-refresh");
    let before = state(&node);

    let mut mismatched = refresh.clone();
    mismatched.policy_version = 2;
    coord_sign_refresh(&mut mismatched, &node.wallet_id, "policy-version-refresh");
    let answer = handle_refresh(&node, &mismatched, now).expect("decodable");
    let (code, check, detail) = refusal(answer, "a refresh for policy_version 2");
    assert_eq!(code, RefusalCode::PsbtInconsistent);
    assert_eq!(
        check, "policy_version",
        "the refresh check is locally authored"
    );
    assert!(detail.contains("policy_version 2"), "{detail}");
    assert_eq!(
        state(&node),
        before,
        "a refused refresh may consume no nonce and record no refresh"
    );

    assert!(
        matches!(
            handle_refresh(&node, &refresh, now).expect("decodable"),
            SignResponse::Accepted(_)
        ),
        "the same refresh nonce under the sealed version must still be admissible"
    );
}
