//! Handler-level integration tests for /sign — no bitcoind, no sockets.

use std::str::FromStr;

use bitcoin::absolute::LockTime;
use bitcoin::bip32::{DerivationPath, Fingerprint};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use bitcoin::sighash::SighashCache;
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, EcdsaSighashType, OutPoint, Psbt, PublicKey, ScriptBuf, Sequence, Transaction, TxIn,
    TxOut, Txid, WScriptHash, Witness,
};
use miniscript::{Descriptor, DescriptorPublicKey};
use vault_node::{handle_sign, Node};
use vault_proto::{RefusalCode, SignRequest, SignResponse};

const NORMAL_PIN: &str = "1111";
const DURESS_PIN: &str = "9999";
/// The node's clock for every handler call (a parameter, not a real read).
const NOW: u64 = 1_752_000_000;
/// The node's retention cap; expiries past `NOW + MAX_AGE` are refused.
const MAX_AGE: u64 = 172_800;
/// A well-inside-the-window expiry for the honest-path requests.
const EXPIRY: u64 = NOW + 3_600;
const POLICY_VERSION: u32 = 1;
/// The node's bounded derivation-index scan for these handler tests.
const MAX_DERIV: u32 = 20;

fn seckey(index: u8) -> SecretKey {
    SecretKey::from_slice(&[index; 32]).expect("32 nonzero bytes")
}

fn pubkey(secp: &Secp256k1<bitcoin::secp256k1::All>, index: u8) -> PublicKey {
    PublicKey::new(seckey(index).public_key(secp))
}

fn descriptor_str() -> String {
    let secp = Secp256k1::new();
    let user = pubkey(&secp, 1);
    let nodes: Vec<String> = (2..=6).map(|i| pubkey(&secp, i).to_string()).collect();
    format!("wsh(and_v(v:pk({user}),multi(3,{})))", nodes.join(","))
}

struct Fixture {
    node: Node,
    descriptor: Descriptor<PublicKey>,
    hot_spk: ScriptBuf,
    escape_spk: ScriptBuf,
}

/// The default (V0-1/V0-2) fixture: no Hold, escape wallet not set apart.
fn fixture() -> Fixture {
    build_fixture(0, false)
}

/// A fixture whose node enforces a `hold_secs` Hold and knows its escape
/// wallet — the V0-3 class-routing setup.
fn held_fixture(hold_secs: u64) -> Fixture {
    build_fixture(hold_secs, true)
}

/// A single-key `wpkh(<pubkey>)` destination descriptor and the scriptPubKey it
/// derives — a definite (non-wildcard) allowlist entry, enough to exercise the
/// handler's descriptor membership without an xpub. `derives_within`'s bounded
/// scan over ranged descriptors is covered in policy-core's own tests.
fn wpkh_dest(key_index: u8) -> (String, ScriptBuf) {
    let secp = Secp256k1::new();
    let descriptor =
        Descriptor::<DescriptorPublicKey>::from_str(&format!("wpkh({})", pubkey(&secp, key_index)))
            .expect("valid wpkh descriptor");
    let spk = descriptor
        .derived_descriptor(&secp, 0)
        .expect("derivable")
        .script_pubkey();
    (descriptor.to_string(), spk)
}

fn hot_dest() -> (String, ScriptBuf) {
    wpkh_dest(10)
}

fn escape_dest() -> (String, ScriptBuf) {
    wpkh_dest(11)
}

/// User key is index 1; the five node keys are 2..=6; the Node under test
/// holds key 2. The hot and escape wallets are both allowlisted descriptors (so
/// an escape sweep passes the destination check); `configure_escape`
/// additionally names the escape descriptor in config so the node can route it
/// as the escape class.
fn build_fixture(hold_secs: u64, configure_escape: bool) -> Fixture {
    let descriptor_str = descriptor_str();
    let descriptor = Descriptor::<PublicKey>::from_str(&descriptor_str).expect("valid descriptor");
    let (hot_desc, hot_spk) = hot_dest();
    let (escape_desc, escape_spk) = escape_dest();
    let config = config_text(
        &descriptor_str,
        &hot_desc,
        &escape_desc,
        hold_secs,
        MAX_AGE,
        configure_escape,
        true,
    );
    Fixture {
        node: Node::from_toml_str(&config).expect("valid config"),
        descriptor,
        hot_spk,
        escape_spk,
    }
}

fn config_text(
    descriptor_str: &str,
    hot_desc: &str,
    escape_desc: &str,
    hold_secs: u64,
    max_commitment_age_secs: u64,
    configure_escape: bool,
    allow_escape: bool,
) -> String {
    let escape_line = if configure_escape {
        format!("escape_descriptor = \"{escape_desc}\"\n")
    } else {
        String::new()
    };
    let allowlist = if allow_escape {
        format!("\"{hot_desc}\", \"{escape_desc}\"")
    } else {
        format!("\"{hot_desc}\"")
    };
    format!(
        "listen_port = 7000\n\
         node_seckey = \"{}\"\n\
         descriptor = \"{descriptor_str}\"\n\
         allowlist = [{allowlist}]\n\
         {escape_line}\
         max_derivation_index = {MAX_DERIV}\n\
         hold_secs = {hold_secs}\n\
         max_commitment_age_secs = {max_commitment_age_secs}\n\
         policy_version = {POLICY_VERSION}\n\
         pin_normal_hash = \"{}\"\n\
         pin_duress_hash = \"{}\"\n",
        seckey(2).display_secret(),
        sha256::Hash::hash(NORMAL_PIN.as_bytes()),
        sha256::Hash::hash(DURESS_PIN.as_bytes()),
    )
}

fn fixture_config(
    hold_secs: u64,
    max_commitment_age_secs: u64,
    configure_escape: bool,
    allow_escape: bool,
) -> String {
    let descriptor_str = descriptor_str();
    let (hot_desc, _) = hot_dest();
    let (escape_desc, _) = escape_dest();
    config_text(
        &descriptor_str,
        &hot_desc,
        &escape_desc,
        hold_secs,
        max_commitment_age_secs,
        configure_escape,
        allow_escape,
    )
}

/// A `count`-input PSBT spending the vault to `outputs`, witness data filled.
fn vault_psbt_n(fixture: &Fixture, count: u32, outputs: Vec<(ScriptBuf, u64)>) -> Psbt {
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: (0..count)
            .map(|vout| TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([7; 32]), vout),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            })
            .collect(),
        output: outputs
            .into_iter()
            .map(|(script_pubkey, sats)| TxOut {
                script_pubkey,
                value: Amount::from_sat(sats),
            })
            .collect(),
    };
    let mut psbt = Psbt::from_unsigned_tx(tx).expect("unsigned tx");
    let witness_script = fixture
        .descriptor
        .explicit_script()
        .expect("wsh witness script");
    for input in psbt.inputs.iter_mut() {
        input.witness_utxo = Some(TxOut {
            script_pubkey: fixture.descriptor.script_pubkey(),
            value: Amount::from_sat(100_000_000),
        });
        input.witness_script = Some(witness_script.clone());
    }
    psbt
}

/// One-input PSBT spending the vault to `outputs` (the common case).
fn vault_psbt(fixture: &Fixture, outputs: Vec<(ScriptBuf, u64)>) -> Psbt {
    vault_psbt_n(fixture, 1, outputs)
}

/// Insert a partial signature under the configured user pubkey (index 1) on
/// input `index`, signing the P2WSH sighash of type `sighash_type` with `key`.
/// The sighash is computed for that same type, so an honest SIGHASH_ALL
/// signature verifies while a SIGHASH_NONE one is a genuine but wrong-type
/// signature. The signature is always *filed* under the user key — that is
/// where the node looks for it — so varying `key` (not the storage slot) is
/// what lets the garbage-key test sign with a non-user key.
fn sign_input(
    fixture: &Fixture,
    psbt: &mut Psbt,
    index: usize,
    key: &SecretKey,
    sighash_type: EcdsaSighashType,
) {
    let secp = Secp256k1::new();
    let witness_script = fixture
        .descriptor
        .explicit_script()
        .expect("wsh witness script");
    let value = psbt.inputs[index]
        .witness_utxo
        .as_ref()
        .expect("witness_utxo")
        .value;
    let unsigned_tx = psbt.unsigned_tx.clone();
    let mut cache = SighashCache::new(&unsigned_tx);
    let sighash = cache
        .p2wsh_signature_hash(index, &witness_script, value, sighash_type)
        .expect("sighash");
    let signature = secp.sign_ecdsa(&Message::from_digest(sighash.to_byte_array()), key);
    psbt.inputs[index].partial_sigs.insert(
        pubkey(&secp, 1),
        bitcoin::ecdsa::Signature {
            signature,
            sighash_type,
        },
    );
}

/// Honestly sign every input with the user key (index 1), SIGHASH_ALL.
fn user_sign(fixture: &Fixture, psbt: &mut Psbt) {
    for index in 0..psbt.inputs.len() {
        sign_input(fixture, psbt, index, &seckey(1), EcdsaSighashType::All);
    }
}

fn request(psbt: &Psbt, pin: &str) -> SignRequest {
    request_at(psbt, pin, EXPIRY)
}

fn request_at(psbt: &Psbt, pin: &str, expiry: u64) -> SignRequest {
    SignRequest {
        psbt: psbt.to_string(),
        // The escape variant only has to decode at first light; reusing the
        // primary PSBT keeps these handler tests self-contained.
        escape_psbt: psbt.to_string(),
        pin: pin.into(),
        expiry,
        policy_version: POLICY_VERSION,
    }
}

fn expect_refusal(response: SignResponse) -> vault_proto::Refusal {
    match response {
        SignResponse::Refusal(refusal) => refusal,
        other => panic!("expected refusal, got {other:?}"),
    }
}

#[test]
fn wrong_pin_is_refused_with_bad_pin() {
    let fixture = fixture();
    let mut psbt = vault_psbt(&fixture, vec![(fixture.hot_spk.clone(), 99_990_000)]);
    user_sign(&fixture, &mut psbt);
    let response =
        handle_sign(&fixture.node, &request(&psbt, "0000"), NOW).expect("decodable request");
    let refusal = expect_refusal(response);
    assert_eq!(refusal.code, RefusalCode::BadPin);
}

#[test]
fn missing_pin_field_is_refused_with_bad_pin() {
    let fixture = fixture();
    let mut psbt = vault_psbt(&fixture, vec![(fixture.hot_spk.clone(), 99_990_000)]);
    user_sign(&fixture, &mut psbt);
    let body = serde_json::json!({
        "psbt": psbt.to_string(),
        "escape_psbt": psbt.to_string(),
    });
    let request: SignRequest = serde_json::from_value(body).expect("missing pin defaults");
    let response = handle_sign(&fixture.node, &request, NOW).expect("decodable request");
    let refusal = expect_refusal(response);
    assert_eq!(refusal.code, RefusalCode::BadPin);
}

#[test]
fn missing_user_signature_is_refused() {
    let fixture = fixture();
    let psbt = vault_psbt(&fixture, vec![(fixture.hot_spk.clone(), 99_990_000)]);
    let response =
        handle_sign(&fixture.node, &request(&psbt, NORMAL_PIN), NOW).expect("decodable request");
    let refusal = expect_refusal(response);
    assert_eq!(refusal.code, RefusalCode::UserSigInvalid);
}

#[test]
fn output_mutation_after_user_signing_is_refused() {
    let fixture = fixture();
    let mut psbt = vault_psbt(&fixture, vec![(fixture.hot_spk.clone(), 99_990_000)]);
    user_sign(&fixture, &mut psbt);
    // The user committed to 99_990_000 sat; mutating the output afterwards
    // changes the sighash and must invalidate the very signature the node
    // verifies (mutation is subsumed by sighash enforcement).
    psbt.unsigned_tx.output[0].value = Amount::from_sat(99_980_000);
    let response =
        handle_sign(&fixture.node, &request(&psbt, NORMAL_PIN), NOW).expect("decodable request");
    let refusal = expect_refusal(response);
    assert_eq!(refusal.code, RefusalCode::UserSigInvalid);
}

#[test]
fn wrong_sighash_type_is_refused_with_bad_sighash() {
    let fixture = fixture();
    let mut psbt = vault_psbt(&fixture, vec![(fixture.hot_spk.clone(), 99_990_000)]);
    // A genuine user signature, but committing to SIGHASH_NONE, not ALL.
    sign_input(&fixture, &mut psbt, 0, &seckey(1), EcdsaSighashType::None);
    let response =
        handle_sign(&fixture.node, &request(&psbt, NORMAL_PIN), NOW).expect("decodable request");
    let refusal = expect_refusal(response);
    assert_eq!(refusal.code, RefusalCode::BadSighash);
}

#[test]
fn missing_user_signature_on_one_of_several_inputs_is_refused() {
    let fixture = fixture();
    let mut psbt = vault_psbt_n(&fixture, 2, vec![(fixture.hot_spk.clone(), 199_990_000)]);
    // Sign only the first input; the second carries no user signature.
    sign_input(&fixture, &mut psbt, 0, &seckey(1), EcdsaSighashType::All);
    let response =
        handle_sign(&fixture.node, &request(&psbt, NORMAL_PIN), NOW).expect("decodable request");
    let refusal = expect_refusal(response);
    assert_eq!(refusal.code, RefusalCode::UserSigInvalid);
}

#[test]
fn garbage_signature_under_user_key_is_refused() {
    let fixture = fixture();
    let mut psbt = vault_psbt(&fixture, vec![(fixture.hot_spk.clone(), 99_990_000)]);
    // A well-formed SIGHASH_ALL signature over the correct sighash, but made
    // by a non-user key (index 42) while still filed under the user pubkey.
    // This is exactly the first-light gap: any DER blob under the user key
    // used to pass on presence alone.
    sign_input(&fixture, &mut psbt, 0, &seckey(42), EcdsaSighashType::All);
    let response =
        handle_sign(&fixture.node, &request(&psbt, NORMAL_PIN), NOW).expect("decodable request");
    let refusal = expect_refusal(response);
    assert_eq!(refusal.code, RefusalCode::UserSigInvalid);
}

#[test]
fn missing_witness_utxo_is_refused_as_psbt_inconsistent() {
    let fixture = fixture();
    let mut psbt = vault_psbt(&fixture, vec![(fixture.hot_spk.clone(), 99_990_000)]);
    // Sign honestly, then strip the witness_utxo: without the input amount the
    // node cannot recompute the sighash, so it cannot verify the (present,
    // valid) user signature.
    user_sign(&fixture, &mut psbt);
    psbt.inputs[0].witness_utxo = None;
    let response =
        handle_sign(&fixture.node, &request(&psbt, NORMAL_PIN), NOW).expect("decodable request");
    let refusal = expect_refusal(response);
    assert_eq!(refusal.code, RefusalCode::PsbtInconsistent);
    assert_eq!(refusal.check, "user_signature");
}

#[test]
fn honest_request_is_signed_by_the_node() {
    let fixture = fixture();
    let mut psbt = vault_psbt(&fixture, vec![(fixture.hot_spk.clone(), 99_990_000)]);
    user_sign(&fixture, &mut psbt);
    let response =
        handle_sign(&fixture.node, &request(&psbt, NORMAL_PIN), NOW).expect("decodable request");
    let SignResponse::Signed(signed) = response else {
        panic!("expected signed_psbt, got {response:?}");
    };
    let signed = Psbt::from_str(&signed).expect("valid returned psbt");
    let secp = Secp256k1::new();
    assert!(
        signed.inputs[0]
            .partial_sigs
            .contains_key(&pubkey(&secp, 2)),
        "node must contribute its own partial signature"
    );
}

#[test]
fn duress_pin_is_accepted_identically_at_first_light() {
    let fixture = fixture();
    let mut psbt = vault_psbt(&fixture, vec![(fixture.hot_spk.clone(), 99_990_000)]);
    user_sign(&fixture, &mut psbt);
    let response =
        handle_sign(&fixture.node, &request(&psbt, DURESS_PIN), NOW).expect("decodable request");
    assert!(
        matches!(response, SignResponse::Signed(_)),
        "duress must answer exactly like normal (ADR-0008), got {response:?}"
    );
}

#[test]
fn non_allowlisted_destination_is_refused_through_the_handler() {
    let fixture = fixture();
    let theft_spk = ScriptBuf::new_p2wsh(&WScriptHash::from_byte_array([0xEE; 32]));
    let mut psbt = vault_psbt(&fixture, vec![(theft_spk, 99_990_000)]);
    user_sign(&fixture, &mut psbt);
    let response =
        handle_sign(&fixture.node, &request(&psbt, NORMAL_PIN), NOW).expect("decodable request");
    let refusal = expect_refusal(response);
    assert_eq!(refusal.code, RefusalCode::DestNotAllowed);
    assert_eq!(refusal.check, "destination_allowlist");
}

#[test]
fn input_not_deriving_from_the_vault_is_unknown_input() {
    let fixture = fixture();
    let mut psbt = vault_psbt(&fixture, vec![(fixture.hot_spk.clone(), 99_990_000)]);
    user_sign(&fixture, &mut psbt);
    // Repoint the prevout scriptPubKey to one the vault descriptor cannot
    // derive. The value is unchanged, so the P2WSH sighash — and thus the user
    // signature — still verifies; only input ownership fails.
    let foreign = ScriptBuf::new_p2wsh(&WScriptHash::from_byte_array([0x33; 32]));
    if let Some(utxo) = psbt.inputs[0].witness_utxo.as_mut() {
        utxo.script_pubkey = foreign;
    }
    let response =
        handle_sign(&fixture.node, &request(&psbt, NORMAL_PIN), NOW).expect("decodable request");
    let refusal = expect_refusal(response);
    assert_eq!(refusal.code, RefusalCode::UnknownInput);
    assert_eq!(refusal.check, "input_ownership");
}

#[test]
fn labeled_change_that_does_not_derive_is_change_not_derivable_through_the_handler() {
    let fixture = fixture();
    // An output paying a non-derivable script, but MARKED as change with a
    // fabricated bip32 hint — the theft vector. The node must re-derive and
    // refuse ChangeNotDerivable rather than trust the label.
    let theft = ScriptBuf::new_p2wsh(&WScriptHash::from_byte_array([0xEE; 32]));
    let mut psbt = vault_psbt(&fixture, vec![(theft, 99_990_000)]);
    let secp = Secp256k1::new();
    psbt.outputs[0].bip32_derivation.insert(
        pubkey(&secp, 1).inner,
        (Fingerprint::default(), DerivationPath::master()),
    );
    user_sign(&fixture, &mut psbt);
    let response =
        handle_sign(&fixture.node, &request(&psbt, NORMAL_PIN), NOW).expect("decodable request");
    let refusal = expect_refusal(response);
    assert_eq!(refusal.code, RefusalCode::ChangeNotDerivable);
    assert_eq!(refusal.check, "verified_change");
}

#[test]
fn undecodable_psbt_is_a_bad_request_not_a_refusal() {
    let fixture = fixture();
    let request = SignRequest {
        psbt: "not base64 at all".into(),
        escape_psbt: "also not".into(),
        pin: NORMAL_PIN.into(),
        expiry: EXPIRY,
        policy_version: POLICY_VERSION,
    };
    assert!(handle_sign(&fixture.node, &request, NOW).is_err());
}

// ---------------------------------------------------------------------------
// V0-2: node-capped expiry + the anti-replay log

#[test]
fn expiry_in_the_past_is_refused_as_commitment_expired() {
    let fixture = fixture();
    let mut psbt = vault_psbt(&fixture, vec![(fixture.hot_spk.clone(), 99_990_000)]);
    user_sign(&fixture, &mut psbt);
    // expiry == NOW is already expired (the window is `now < expiry`).
    let response = handle_sign(&fixture.node, &request_at(&psbt, NORMAL_PIN, NOW), NOW)
        .expect("decodable request");
    let refusal = expect_refusal(response);
    assert_eq!(refusal.code, RefusalCode::CommitmentExpired);
}

#[test]
fn expiry_beyond_the_node_cap_is_refused_as_commitment_expired() {
    let fixture = fixture();
    let mut psbt = vault_psbt(&fixture, vec![(fixture.hot_spk.clone(), 99_990_000)]);
    user_sign(&fixture, &mut psbt);
    // One second past `NOW + MAX_AGE`: a hostile coordinator trying to inflate
    // the node's retention. The node caps it against its OWN clock.
    let response = handle_sign(
        &fixture.node,
        &request_at(&psbt, NORMAL_PIN, NOW + MAX_AGE + 1),
        NOW,
    )
    .expect("decodable request");
    let refusal = expect_refusal(response);
    assert_eq!(refusal.code, RefusalCode::CommitmentExpired);
}

#[test]
fn expiry_within_the_window_is_accepted() {
    let fixture = fixture();
    let mut psbt = vault_psbt(&fixture, vec![(fixture.hot_spk.clone(), 99_990_000)]);
    user_sign(&fixture, &mut psbt);
    // Exactly at the cap is inside the window (`expiry <= now + max_age`).
    let response = handle_sign(
        &fixture.node,
        &request_at(&psbt, NORMAL_PIN, NOW + MAX_AGE),
        NOW,
    )
    .expect("decodable request");
    assert!(
        matches!(response, SignResponse::Signed(_)),
        "an in-window honest spend must be signed, got {response:?}"
    );
}

#[test]
fn identical_resubmission_returns_the_recorded_signed_verdict() {
    let fixture = fixture();
    let mut psbt = vault_psbt(&fixture, vec![(fixture.hot_spk.clone(), 99_990_000)]);
    user_sign(&fixture, &mut psbt);
    let req = request(&psbt, NORMAL_PIN);

    let first = handle_sign(&fixture.node, &req, NOW).expect("decodable request");
    let SignResponse::Signed(first_signed) = first else {
        panic!("first submission must sign");
    };
    // The identical resubmission returns the recorded verdict — byte-for-byte
    // the same signed PSBT — without re-evaluating.
    let second = handle_sign(&fixture.node, &req, NOW).expect("decodable request");
    let SignResponse::Signed(second_signed) = second else {
        panic!("resubmission must replay the recorded signed verdict");
    };
    assert_eq!(first_signed, second_signed);
}

#[test]
fn identical_resubmission_returns_the_recorded_refusal() {
    let fixture = fixture();
    let theft_spk = ScriptBuf::new_p2wsh(&WScriptHash::from_byte_array([0xEE; 32]));
    let mut psbt = vault_psbt(&fixture, vec![(theft_spk, 99_990_000)]);
    user_sign(&fixture, &mut psbt);
    let req = request(&psbt, NORMAL_PIN);

    let first = expect_refusal(handle_sign(&fixture.node, &req, NOW).expect("decodable request"));
    assert_eq!(first.code, RefusalCode::DestNotAllowed);
    // Resubmitting the refused commitment returns the recorded refusal.
    let second = expect_refusal(handle_sign(&fixture.node, &req, NOW).expect("decodable request"));
    assert_eq!(second, first);
}

#[test]
fn a_signature_dependent_refusal_is_not_replayed_after_correction() {
    let fixture = fixture();
    let mut psbt = vault_psbt(&fixture, vec![(fixture.hot_spk.clone(), 99_990_000)]);
    // First submission of an honestly-destined spend, but with NO user
    // signature yet → USER_SIG_INVALID. That refusal depends on witness data
    // the commitment does not bind, so it must NOT be recorded for replay.
    let first = expect_refusal(
        handle_sign(&fixture.node, &request(&psbt, NORMAL_PIN), NOW).expect("decodable request"),
    );
    assert_eq!(first.code, RefusalCode::UserSigInvalid);

    // The user signs the IDENTICAL transaction (same inputs/outputs/fee/expiry
    // ⇒ same commitment_id, since signing only adds partial_sigs) and
    // resubmits. It must be evaluated afresh and signed — not answered from the
    // stale USER_SIG_INVALID. Keying idempotency on the commitment while
    // caching a signature-dependent refusal would deadlock the honest spend
    // until expiry.
    user_sign(&fixture, &mut psbt);
    let second =
        handle_sign(&fixture.node, &request(&psbt, NORMAL_PIN), NOW).expect("decodable request");
    assert!(
        matches!(second, SignResponse::Signed(_)),
        "a corrected resubmission of the same commitment must be re-evaluated, got {second:?}"
    );
}

#[test]
fn a_replacement_spending_the_same_inputs_is_not_blocked_by_the_log() {
    let fixture = fixture();
    // Original: pays the hot wallet, gets signed and recorded.
    let mut original = vault_psbt(&fixture, vec![(fixture.hot_spk.clone(), 99_990_000)]);
    user_sign(&fixture, &mut original);
    let signed = handle_sign(&fixture.node, &request(&original, NORMAL_PIN), NOW)
        .expect("decodable request");
    assert!(matches!(signed, SignResponse::Signed(_)));

    // RBF-style replacement: SAME single outpoint, different fee (a fee bump),
    // still to the hot wallet. It must get a fresh evaluation — not the
    // recorded verdict — because the log is keyed by commitment, not outpoint.
    let mut replacement = vault_psbt(&fixture, vec![(fixture.hot_spk.clone(), 99_980_000)]);
    assert_eq!(
        replacement.unsigned_tx.input[0].previous_output,
        original.unsigned_tx.input[0].previous_output,
        "the replacement spends the identical outpoint"
    );
    user_sign(&fixture, &mut replacement);
    let response = handle_sign(&fixture.node, &request(&replacement, NORMAL_PIN), NOW)
        .expect("decodable request");
    assert!(
        matches!(response, SignResponse::Signed(_)),
        "a replacement is a new commitment and must be evaluated afresh, got {response:?}"
    );
}

// ---------------------------------------------------------------------------
// V0-3: the Hold — per-destination-class routing (ADR-0004)

/// A Hold long enough to observe, comfortably inside the retention cap.
const HOLD: u64 = 3_600;

/// A held-test request whose commitment expiry sits at the node's cap — far
/// beyond any Hold these tests exercise, so re-submission after the window is
/// never mistaken for an expired commitment.
fn held_request(psbt: &Psbt) -> SignRequest {
    request_at(psbt, NORMAL_PIN, NOW + MAX_AGE)
}

fn expect_pending(response: SignResponse) -> vault_proto::Pending {
    match response {
        SignResponse::Pending(pending) => pending,
        other => panic!("expected pending, got {other:?}"),
    }
}

fn expect_config_error(raw: String) -> String {
    match Node::from_toml_str(&raw) {
        Ok(_) => panic!("config must be rejected"),
        Err(err) => err.to_string(),
    }
}

#[test]
fn nonzero_hold_requires_an_escape_spk() {
    let err = expect_config_error(fixture_config(HOLD, MAX_AGE, false, true));
    assert!(
        err.contains("escape_descriptor is required"),
        "unexpected config error: {err}"
    );
}

#[test]
fn escape_spk_must_also_be_allowlisted() {
    let err = expect_config_error(fixture_config(HOLD, MAX_AGE, true, false));
    assert!(
        err.contains("escape_descriptor must also be present in allowlist"),
        "unexpected config error: {err}"
    );
}

#[test]
fn max_commitment_age_must_exceed_hold() {
    let err = expect_config_error(fixture_config(HOLD, HOLD, true, true));
    assert!(
        err.contains("max_commitment_age_secs") && err.contains("must exceed hold_secs"),
        "unexpected config error: {err}"
    );
}

#[test]
fn hot_class_first_submission_is_pending_for_the_full_hold() {
    let fixture = held_fixture(HOLD);
    let mut psbt = vault_psbt(&fixture, vec![(fixture.hot_spk.clone(), 99_990_000)]);
    user_sign(&fixture, &mut psbt);
    let response =
        handle_sign(&fixture.node, &held_request(&psbt), NOW).expect("decodable request");
    let pending = expect_pending(response);
    assert_eq!(pending.first_seen, NOW);
    assert_eq!(
        pending.remaining_secs, HOLD,
        "first sight must report the whole Hold as remaining"
    );
}

#[test]
fn resubmission_before_the_window_is_still_pending_with_less_time() {
    let fixture = held_fixture(HOLD);
    let mut psbt = vault_psbt(&fixture, vec![(fixture.hot_spk.clone(), 99_990_000)]);
    user_sign(&fixture, &mut psbt);
    let req = held_request(&psbt);

    let first = handle_sign(&fixture.node, &req, NOW).expect("decodable request");
    assert_eq!(expect_pending(first).remaining_secs, HOLD);

    // Half the Hold later the same commitment is still inside its window. The
    // timer keeps the original first_seen, so remaining_secs has shrunk.
    let later = NOW + HOLD / 2;
    let pending =
        expect_pending(handle_sign(&fixture.node, &req, later).expect("decodable request"));
    assert_eq!(pending.first_seen, NOW, "the Hold timer must not reset");
    assert_eq!(pending.remaining_secs, HOLD - HOLD / 2);
}

#[test]
fn resubmission_at_or_after_the_window_is_signed() {
    let fixture = held_fixture(HOLD);
    let mut psbt = vault_psbt(&fixture, vec![(fixture.hot_spk.clone(), 99_990_000)]);
    user_sign(&fixture, &mut psbt);
    let req = held_request(&psbt);

    assert!(matches!(
        handle_sign(&fixture.node, &req, NOW).expect("decodable request"),
        SignResponse::Pending(_)
    ));
    // Exactly at first_seen + hold_secs the window has elapsed: the node signs
    // the PSBT in hand (re-verified), contributing its own partial signature.
    let response = handle_sign(&fixture.node, &req, NOW + HOLD).expect("decodable request");
    let SignResponse::Signed(signed) = response else {
        panic!("the Hold has elapsed; the node must sign, got {response:?}");
    };
    let signed = Psbt::from_str(&signed).expect("valid returned psbt");
    let secp = Secp256k1::new();
    assert!(
        signed.inputs[0]
            .partial_sigs
            .contains_key(&pubkey(&secp, 2)),
        "node must contribute its own partial signature after the Hold"
    );
}

#[test]
fn escape_class_sweep_signs_instantly_despite_a_hold() {
    let fixture = held_fixture(HOLD);
    // Every non-change output pays the escape wallet: an escape sweep, which is
    // the implicit cancel and must never be held.
    let mut psbt = vault_psbt(&fixture, vec![(fixture.escape_spk.clone(), 99_990_000)]);
    user_sign(&fixture, &mut psbt);
    let response =
        handle_sign(&fixture.node, &held_request(&psbt), NOW).expect("decodable request");
    assert!(
        matches!(response, SignResponse::Signed(_)),
        "an escape sweep is instant even under a Hold, got {response:?}"
    );
}

#[test]
fn refresh_self_spend_signs_instantly_despite_a_hold() {
    let fixture = held_fixture(HOLD);
    let vault_spk = fixture.descriptor.script_pubkey();
    // Every output pays the vault back: a refresh self-spend.
    let mut psbt = vault_psbt(&fixture, vec![(vault_spk, 99_990_000)]);
    user_sign(&fixture, &mut psbt);
    let response =
        handle_sign(&fixture.node, &held_request(&psbt), NOW).expect("decodable request");
    assert!(
        matches!(response, SignResponse::Signed(_)),
        "a refresh self-spend is instant even under a Hold, got {response:?}"
    );
}

#[test]
fn an_invalid_hot_spend_is_refused_not_held() {
    let fixture = held_fixture(HOLD);
    // A hot-class spend with NO user signature. It fails validation, so the
    // response is a Refusal — not Pending. A held spend answers Pending, so a
    // Refusal here proves the invalid submission was never recorded as pending
    // (the pending log holds only spends that would otherwise be signed).
    let psbt = vault_psbt(&fixture, vec![(fixture.hot_spk.clone(), 99_990_000)]);
    let response =
        handle_sign(&fixture.node, &held_request(&psbt), NOW).expect("decodable request");
    let refusal = expect_refusal(response);
    assert_eq!(refusal.code, RefusalCode::UserSigInvalid);
}

#[test]
fn hot_spend_expiring_at_the_hold_boundary_is_refused_not_pending() {
    let fixture = held_fixture(HOLD);
    let mut psbt = vault_psbt(&fixture, vec![(fixture.hot_spk.clone(), 99_990_000)]);
    user_sign(&fixture, &mut psbt);
    // Expiry is exclusive. If expiry == first_seen + hold_secs, the spend will
    // be expired exactly when the Hold elapses, so recording Pending would
    // promise a signature that can never be returned.
    let response = handle_sign(
        &fixture.node,
        &request_at(&psbt, NORMAL_PIN, NOW + HOLD),
        NOW,
    )
    .expect("decodable request");
    let refusal = expect_refusal(response);
    assert_eq!(refusal.code, RefusalCode::CommitmentExpired);
}

#[test]
fn a_hot_spend_signs_instantly_when_hold_is_zero() {
    // hold_secs = 0 is the first-light configuration: the hot class exists but
    // the Hold is a no-op, so the spend signs on first submission. No pending
    // entry is created (the demo stays one-shot).
    let fixture = held_fixture(0);
    let mut psbt = vault_psbt(&fixture, vec![(fixture.hot_spk.clone(), 99_990_000)]);
    user_sign(&fixture, &mut psbt);
    let response =
        handle_sign(&fixture.node, &held_request(&psbt), NOW).expect("decodable request");
    assert!(
        matches!(response, SignResponse::Signed(_)),
        "hold_secs = 0 signs the hot spend on first submission, got {response:?}"
    );
}
