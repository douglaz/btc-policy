//! Handler-level integration tests for /sign — no bitcoind, no sockets.

use std::str::FromStr;

use bitcoin::absolute::LockTime;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use bitcoin::sighash::SighashCache;
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, EcdsaSighashType, OutPoint, Psbt, PublicKey, ScriptBuf, Sequence, Transaction, TxIn,
    TxOut, Txid, WScriptHash, Witness,
};
use miniscript::Descriptor;
use vault_node::{handle_sign, Node};
use vault_proto::{RefusalCode, SignRequest, SignResponse};

const NORMAL_PIN: &str = "1111";
const DURESS_PIN: &str = "9999";

fn seckey(index: u8) -> SecretKey {
    SecretKey::from_slice(&[index; 32]).expect("32 nonzero bytes")
}

fn pubkey(secp: &Secp256k1<bitcoin::secp256k1::All>, index: u8) -> PublicKey {
    PublicKey::new(seckey(index).public_key(secp))
}

struct Fixture {
    node: Node,
    descriptor: Descriptor<PublicKey>,
    hot_spk: ScriptBuf,
}

/// User key is index 1; the five node keys are 2..=6; the Node under test
/// holds key 2.
fn fixture() -> Fixture {
    let secp = Secp256k1::new();
    let user = pubkey(&secp, 1);
    let nodes: Vec<String> = (2..=6).map(|i| pubkey(&secp, i).to_string()).collect();
    let descriptor_str = format!("wsh(and_v(v:pk({user}),multi(3,{})))", nodes.join(","));
    let descriptor = Descriptor::<PublicKey>::from_str(&descriptor_str).expect("valid descriptor");
    let hot_spk = ScriptBuf::new_p2wsh(&WScriptHash::from_byte_array([0xAA; 32]));
    let config = format!(
        "listen_port = 7000\n\
         node_seckey = \"{}\"\n\
         descriptor = \"{descriptor_str}\"\n\
         allowlist = [\"{hot_spk:x}\"]\n\
         hold_secs = 0\n\
         pin_normal_hash = \"{}\"\n\
         pin_duress_hash = \"{}\"\n",
        seckey(2).display_secret(),
        sha256::Hash::hash(NORMAL_PIN.as_bytes()),
        sha256::Hash::hash(DURESS_PIN.as_bytes()),
    );
    Fixture {
        node: Node::from_toml_str(&config).expect("valid config"),
        descriptor,
        hot_spk,
    }
}

/// One-input PSBT spending the vault to `outputs`, with witness data filled.
fn vault_psbt(fixture: &Fixture, outputs: Vec<(ScriptBuf, u64)>) -> Psbt {
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array([7; 32]), 0),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: outputs
            .into_iter()
            .map(|(script_pubkey, sats)| TxOut {
                script_pubkey,
                value: Amount::from_sat(sats),
            })
            .collect(),
    };
    let mut psbt = Psbt::from_unsigned_tx(tx).expect("unsigned tx");
    psbt.inputs[0].witness_utxo = Some(TxOut {
        script_pubkey: fixture.descriptor.script_pubkey(),
        value: Amount::from_sat(100_000_000),
    });
    psbt.inputs[0].witness_script = Some(
        fixture
            .descriptor
            .explicit_script()
            .expect("wsh witness script"),
    );
    psbt
}

fn user_sign(fixture: &Fixture, psbt: &mut Psbt) {
    let secp = Secp256k1::new();
    let witness_script = fixture
        .descriptor
        .explicit_script()
        .expect("wsh witness script");
    let unsigned_tx = psbt.unsigned_tx.clone();
    let mut cache = SighashCache::new(&unsigned_tx);
    let value = psbt.inputs[0]
        .witness_utxo
        .as_ref()
        .expect("witness_utxo")
        .value;
    let sighash = cache
        .p2wsh_signature_hash(0, &witness_script, value, EcdsaSighashType::All)
        .expect("sighash");
    let signature = secp.sign_ecdsa(&Message::from_digest(sighash.to_byte_array()), &seckey(1));
    psbt.inputs[0].partial_sigs.insert(
        pubkey(&secp, 1),
        bitcoin::ecdsa::Signature {
            signature,
            sighash_type: EcdsaSighashType::All,
        },
    );
}

fn request(psbt: &Psbt, pin: &str) -> SignRequest {
    SignRequest {
        psbt: psbt.to_string(),
        // The escape variant only has to decode at first light; reusing the
        // primary PSBT keeps these handler tests self-contained.
        escape_psbt: psbt.to_string(),
        pin: pin.into(),
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
    let response = handle_sign(&fixture.node, &request(&psbt, "0000")).expect("decodable request");
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
    let response = handle_sign(&fixture.node, &request).expect("decodable request");
    let refusal = expect_refusal(response);
    assert_eq!(refusal.code, RefusalCode::BadPin);
}

#[test]
fn missing_user_signature_is_refused() {
    let fixture = fixture();
    let psbt = vault_psbt(&fixture, vec![(fixture.hot_spk.clone(), 99_990_000)]);
    let response =
        handle_sign(&fixture.node, &request(&psbt, NORMAL_PIN)).expect("decodable request");
    let refusal = expect_refusal(response);
    assert_eq!(refusal.code, RefusalCode::UserSigInvalid);
}

#[test]
fn honest_request_is_signed_by_the_node() {
    let fixture = fixture();
    let mut psbt = vault_psbt(&fixture, vec![(fixture.hot_spk.clone(), 99_990_000)]);
    user_sign(&fixture, &mut psbt);
    let response =
        handle_sign(&fixture.node, &request(&psbt, NORMAL_PIN)).expect("decodable request");
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
        handle_sign(&fixture.node, &request(&psbt, DURESS_PIN)).expect("decodable request");
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
        handle_sign(&fixture.node, &request(&psbt, NORMAL_PIN)).expect("decodable request");
    let refusal = expect_refusal(response);
    assert_eq!(refusal.code, RefusalCode::DestNotAllowed);
    assert_eq!(refusal.check, "destination_allowlist");
}

#[test]
fn undecodable_psbt_is_a_bad_request_not_a_refusal() {
    let fixture = fixture();
    let request = SignRequest {
        psbt: "not base64 at all".into(),
        escape_psbt: "also not".into(),
        pin: NORMAL_PIN.into(),
    };
    assert!(handle_sign(&fixture.node, &request).is_err());
}
