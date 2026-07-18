//! Handler-level integration tests for /sign — no bitcoind, no sockets.

use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};

use bitcoin::absolute::LockTime;
use bitcoin::bip32::{DerivationPath, Fingerprint};
use bitcoin::hashes::Hash;
use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use bitcoin::sighash::SighashCache;
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, EcdsaSighashType, OutPoint, Psbt, PublicKey, ScriptBuf, Sequence, Transaction, TxIn,
    TxOut, Txid, WScriptHash, Witness,
};
use miniscript::{Descriptor, DescriptorPublicKey};
use vault_node::{handle_refresh, handle_sign, Node};
use vault_proto::{RefreshRequest, RefusalCode, SignRequest, SignResponse};

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
/// Flat fee on the fixture escape — well under the 10% cap over the 100_000_000
/// sat per-input fixture value.
const ESCAPE_FEE: u64 = 10_000;

fn seckey(index: u8) -> SecretKey {
    SecretKey::from_slice(&[index; 32]).expect("32 nonzero bytes")
}

fn pubkey(secp: &Secp256k1<bitcoin::secp256k1::All>, index: u8) -> PublicKey {
    PublicKey::new(seckey(index).public_key(secp))
}

/// The coordinator every fixture node here is sealed to (ADR-0013 §2/§4): its
/// public half is pinned in the config `config_text` emits, its secret half signs
/// every request, so each one clears the ingress coord-auth gate. Index 0xC0 sits
/// clear of the vault's own keys (user 1, nodes 2..=6, hot 10, escape 11).
fn coord_key() -> (SecretKey, PublicKey) {
    let secp = Secp256k1::new();
    (seckey(0xC0), pubkey(&secp, 0xC0))
}

/// Sign `req` as `sk` over the canonical request bytes under an explicit `nonce`
/// — the coordinator's exact role (vault-cli does this before every relay).
/// Taking the key and nonce explicitly is what lets the negative tests below sign
/// as the WRONG coordinator, or re-use a nonce on purpose.
fn coord_sign_as(req: &mut SignRequest, sk: &SecretKey, nonce: &str) {
    req.nonce = nonce.to_string();
    // coord_sig is never part of its own preimage; no clearing needed. Re-signing
    // a request that already carries a sig therefore just overwrites it.
    let digest = req.coord_request().auth_digest();
    let sig = Secp256k1::new().sign_ecdsa(&Message::from_digest(digest), sk);
    req.coord_sig = sig.serialize_der().to_lower_hex_string();
}

/// Coord-sign `req` as the vault's pinned coordinator under a nonce unique to
/// this call. A coordinator issues a fresh single-use nonce per **transmission**,
/// so this is also how a test re-sends an existing request (past a Hold, or
/// retrying a lost call): the commitment is unchanged, so the anti-replay log
/// still returns the one recorded verdict, but the transmission is fresh.
fn coord_sign(req: &mut SignRequest) {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    coord_sign_as(req, &coord_key().0, &format!("nonce-{n}"));
}

fn coord_sign_refresh(req: &mut RefreshRequest) {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    req.nonce = format!("refresh-nonce-{n}");
    let digest = req.coord_request().auth_digest();
    let sig = Secp256k1::new().sign_ecdsa(&Message::from_digest(digest), &coord_key().0);
    req.coord_sig = sig.serialize_der().to_lower_hex_string();
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

/// The default fixture: no Hold, so a hot-class spend's fire event is its ingress.
fn fixture() -> Fixture {
    build_fixture(0)
}

/// A fixture whose node enforces a `hold_secs` Hold — a hot-class spend is
/// accepted and signed at ingress, and fires `hold_secs` later.
fn held_fixture(hold_secs: u64) -> Fixture {
    build_fixture(hold_secs)
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
/// an escape sweep passes the destination check), and the escape descriptor is
/// also named in config — mandatory since V0-8b, because every `SpendRequest`
/// carries an escape validated against it.
fn build_fixture(hold_secs: u64) -> Fixture {
    let descriptor_str = descriptor_str();
    let descriptor = Descriptor::<PublicKey>::from_str(&descriptor_str).expect("valid descriptor");
    let (_, hot_spk) = hot_dest();
    let (_, escape_spk) = escape_dest();
    Fixture {
        node: Node::from_toml_str(&fixture_config(hold_secs, MAX_AGE, true)).expect("valid config"),
        descriptor,
        hot_spk,
        escape_spk,
    }
}

fn fixture_config(hold_secs: u64, max_commitment_age_secs: u64, allow_escape: bool) -> String {
    let descriptor_str = descriptor_str();
    let (hot_desc, _) = hot_dest();
    let (escape_desc, _) = escape_dest();
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
         escape_descriptor = \"{escape_desc}\"\n\
         max_derivation_index = {MAX_DERIV}\n\
         hold_secs = {hold_secs}\n\
         max_commitment_age_secs = {max_commitment_age_secs}\n\
         policy_version = {POLICY_VERSION}\n\
         pin_normal_hash = \"{}\"\n\
         pin_duress_hash = \"{}\"\n\
         coordinator_auth_pubkey = \"{}\"\n",
        seckey(2).display_secret(),
        vault_node::argon2id_normal_phc(NORMAL_PIN),
        vault_node::argon2id_duress_phc(DURESS_PIN),
        coord_key().1,
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

impl Fixture {
    /// A coordinator-authenticated `SpendRequest` for `psbt`, carrying the
    /// mandatory escape a real coordinator would compose alongside it.
    fn request(&self, psbt: &Psbt, pin: &str) -> SignRequest {
        self.request_at(psbt, pin, EXPIRY)
    }

    fn request_at(&self, psbt: &Psbt, pin: &str, expiry: u64) -> SignRequest {
        self.request_with_escape(psbt, &self.escape_for(psbt), pin, expiry)
    }

    /// A request pairing an explicit `escape` with `spend` — for the tests that
    /// are about the escape itself.
    fn request_with_escape(
        &self,
        spend: &Psbt,
        escape: &Psbt,
        pin: &str,
        expiry: u64,
    ) -> SignRequest {
        let mut request = SignRequest {
            psbt: spend.to_string(),
            escape_psbt: escape.to_string(),
            pin: pin.into(),
            nonce: String::new(),
            expiry,
            policy_version: POLICY_VERSION,
            coord_sig: String::new(),
        };
        // Every fixture node is sealed to a coordinator, so a request only reaches
        // the policy checks these tests are about once it is coord-authenticated.
        coord_sign(&mut request);
        request
    }

    /// The mandatory escape for `spend`: the SAME inputs swept to the escape
    /// wallet, user-signed — the shape a real coordinator composes at the wrench,
    /// and what the node validates (never builds).
    fn escape_for(&self, spend: &Psbt) -> Psbt {
        let total: u64 = spend
            .inputs
            .iter()
            .filter_map(|input| input.witness_utxo.as_ref())
            .map(|utxo| utxo.value.to_sat())
            .sum();
        let mut escape = vault_psbt_n(
            self,
            spend.unsigned_tx.input.len() as u32,
            vec![(self.escape_spk.clone(), total.saturating_sub(ESCAPE_FEE))],
        );
        user_sign(self, &mut escape);
        escape
    }
}

fn refresh_request(psbt: &Psbt) -> RefreshRequest {
    refresh_request_at(psbt, EXPIRY)
}

/// A coordinator-authenticated refresh whose commitment expires at `expiry` — for
/// the tests that advance the node's clock past the default window.
fn refresh_request_at(psbt: &Psbt, expiry: u64) -> RefreshRequest {
    let mut request = RefreshRequest {
        refresh_psbt: psbt.to_string(),
        nonce: String::new(),
        expiry,
        policy_version: POLICY_VERSION,
        coord_sig: String::new(),
    };
    coord_sign_refresh(&mut request);
    request
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
    let response = handle_sign(&fixture.node, &fixture.request(&psbt, "0000"), NOW)
        .expect("decodable request");
    let refusal = expect_refusal(response);
    assert_eq!(refusal.code, RefusalCode::BadPin);
}

#[test]
fn missing_pin_field_is_refused_with_bad_pin() {
    let fixture = fixture();
    let mut psbt = vault_psbt(&fixture, vec![(fixture.hot_spk.clone(), 99_990_000)]);
    user_sign(&fixture, &mut psbt);
    // The `pin` field is absent from the wire body (it defaults to empty); every
    // OTHER field is authentic, so the request clears the coord-auth gate and the
    // refusal that comes back is the PIN's, which is what this test is about.
    let body = serde_json::json!({
        "spend": psbt.to_string(),
        "escape": psbt.to_string(),
        "expiry": EXPIRY,
        "policy_version": POLICY_VERSION,
    });
    let mut request: SignRequest = serde_json::from_value(body).expect("missing pin defaults");
    assert_eq!(
        request.pin.as_str(),
        "",
        "an absent pin field must decode as empty"
    );
    coord_sign(&mut request);
    let response = handle_sign(&fixture.node, &request, NOW).expect("decodable request");
    let refusal = expect_refusal(response);
    assert_eq!(refusal.code, RefusalCode::BadPin);
}

#[test]
fn missing_user_signature_is_refused() {
    let fixture = fixture();
    let psbt = vault_psbt(&fixture, vec![(fixture.hot_spk.clone(), 99_990_000)]);
    let response = handle_sign(&fixture.node, &fixture.request(&psbt, NORMAL_PIN), NOW)
        .expect("decodable request");
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
    let response = handle_sign(&fixture.node, &fixture.request(&psbt, NORMAL_PIN), NOW)
        .expect("decodable request");
    let refusal = expect_refusal(response);
    assert_eq!(refusal.code, RefusalCode::UserSigInvalid);
}

#[test]
fn wrong_sighash_type_is_refused_with_bad_sighash() {
    let fixture = fixture();
    let mut psbt = vault_psbt(&fixture, vec![(fixture.hot_spk.clone(), 99_990_000)]);
    // A genuine user signature, but committing to SIGHASH_NONE, not ALL.
    sign_input(&fixture, &mut psbt, 0, &seckey(1), EcdsaSighashType::None);
    let response = handle_sign(&fixture.node, &fixture.request(&psbt, NORMAL_PIN), NOW)
        .expect("decodable request");
    let refusal = expect_refusal(response);
    assert_eq!(refusal.code, RefusalCode::BadSighash);
}

#[test]
fn missing_user_signature_on_one_of_several_inputs_is_refused() {
    let fixture = fixture();
    let mut psbt = vault_psbt_n(&fixture, 2, vec![(fixture.hot_spk.clone(), 199_990_000)]);
    // Sign only the first input; the second carries no user signature.
    sign_input(&fixture, &mut psbt, 0, &seckey(1), EcdsaSighashType::All);
    let response = handle_sign(&fixture.node, &fixture.request(&psbt, NORMAL_PIN), NOW)
        .expect("decodable request");
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
    let response = handle_sign(&fixture.node, &fixture.request(&psbt, NORMAL_PIN), NOW)
        .expect("decodable request");
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
    let response = handle_sign(&fixture.node, &fixture.request(&psbt, NORMAL_PIN), NOW)
        .expect("decodable request");
    let refusal = expect_refusal(response);
    assert_eq!(refusal.code, RefusalCode::PsbtInconsistent);
    assert_eq!(refusal.check, "user_signature");
}

/// The pure-relay contract (§2): an honest request is ACCEPTED, and the response
/// carries no node signature — because no `SignResponse` variant can hold one.
///
/// This is the structural half of "the coordinator never finalizes". Deleting
/// vault-cli's combine code would not be enough: as long as the response COULD
/// carry a partial, a post-wrench coordinator could collect `t` of them and
/// broadcast a coerced spend itself, breaking the Hold and duress silence without
/// compromising a single node. The node signs here — it just does not tell the
/// coordinator (the partial goes to peers, at fire; see `release_partials`).
#[test]
fn an_honest_request_is_accepted_with_no_signature_in_the_response() {
    let fixture = fixture();
    let mut psbt = vault_psbt(&fixture, vec![(fixture.hot_spk.clone(), 99_990_000)]);
    user_sign(&fixture, &mut psbt);
    let response = handle_sign(&fixture.node, &fixture.request(&psbt, NORMAL_PIN), NOW)
        .expect("decodable request");
    let accepted = expect_accepted(response.clone());
    assert_eq!(accepted.first_seen, NOW);

    // Nothing a coordinator could finalize with: the whole serialized response
    // carries no PSBT and no signature.
    let json = serde_json::to_string(&response).expect("serialize");
    assert!(
        !json.contains("cHNidP") && !json.to_lowercase().contains("psbt"),
        "a /sign response must never carry a node signature: {json}"
    );
}

#[test]
fn duress_pin_is_accepted_identically_at_first_light() {
    let fixture = fixture();
    let mut psbt = vault_psbt(&fixture, vec![(fixture.hot_spk.clone(), 99_990_000)]);
    user_sign(&fixture, &mut psbt);
    let response = handle_sign(&fixture.node, &fixture.request(&psbt, DURESS_PIN), NOW)
        .expect("decodable request");
    assert!(
        matches!(response, SignResponse::Accepted(_)),
        "duress must answer exactly like normal (ADR-0008), got {response:?}"
    );
}

#[test]
fn non_allowlisted_destination_is_refused_through_the_handler() {
    let fixture = fixture();
    let theft_spk = ScriptBuf::new_p2wsh(&WScriptHash::from_byte_array([0xEE; 32]));
    let mut psbt = vault_psbt(&fixture, vec![(theft_spk, 99_990_000)]);
    user_sign(&fixture, &mut psbt);
    let response = handle_sign(&fixture.node, &fixture.request(&psbt, NORMAL_PIN), NOW)
        .expect("decodable request");
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
    let response = handle_sign(&fixture.node, &fixture.request(&psbt, NORMAL_PIN), NOW)
        .expect("decodable request");
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
    let response = handle_sign(&fixture.node, &fixture.request(&psbt, NORMAL_PIN), NOW)
        .expect("decodable request");
    let refusal = expect_refusal(response);
    assert_eq!(refusal.code, RefusalCode::ChangeNotDerivable);
    assert_eq!(refusal.check, "verified_change");
}

#[test]
fn undecodable_psbt_is_a_bad_request_not_a_refusal() {
    let fixture = fixture();
    // Coord-signed: an authentic request whose PSBT is simply undecodable, so the
    // 400 comes from the decode and not from the auth gate in front of it.
    let mut request = SignRequest {
        psbt: "not base64 at all".into(),
        escape_psbt: "also not".into(),
        pin: NORMAL_PIN.into(),
        nonce: String::new(),
        expiry: EXPIRY,
        policy_version: POLICY_VERSION,
        coord_sig: String::new(),
    };
    coord_sign(&mut request);
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
    let response = handle_sign(
        &fixture.node,
        &fixture.request_at(&psbt, NORMAL_PIN, NOW),
        NOW,
    )
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
        &fixture.request_at(&psbt, NORMAL_PIN, NOW + MAX_AGE + 1),
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
        &fixture.request_at(&psbt, NORMAL_PIN, NOW + MAX_AGE),
        NOW,
    )
    .expect("decodable request");
    assert!(
        matches!(response, SignResponse::Accepted(_)),
        "an in-window honest spend must be signed, got {response:?}"
    );
}

#[test]
fn identical_resubmission_returns_the_recorded_accepted_verdict() {
    let fixture = fixture();
    let mut psbt = vault_psbt(&fixture, vec![(fixture.hot_spk.clone(), 99_990_000)]);
    user_sign(&fixture, &mut psbt);
    let mut req = fixture.request(&psbt, NORMAL_PIN);

    let first = expect_accepted(handle_sign(&fixture.node, &req, NOW).expect("decodable request"));
    // Resubmitting the identical COMMITMENT returns the recorded verdict without
    // re-evaluating. The re-send carries a fresh nonce because a nonce is
    // single-use per transmission (ADR-0013 §2); idempotency is keyed on the
    // commitment, not the nonce, so the two gates compose instead of colliding.
    coord_sign(&mut req);
    let second = expect_accepted(handle_sign(&fixture.node, &req, NOW).expect("decodable request"));
    assert_eq!(first, second);
}

#[test]
fn identical_resubmission_returns_the_recorded_refusal() {
    let fixture = fixture();
    let theft_spk = ScriptBuf::new_p2wsh(&WScriptHash::from_byte_array([0xEE; 32]));
    let mut psbt = vault_psbt(&fixture, vec![(theft_spk, 99_990_000)]);
    user_sign(&fixture, &mut psbt);
    let mut req = fixture.request(&psbt, NORMAL_PIN);

    let first = expect_refusal(handle_sign(&fixture.node, &req, NOW).expect("decodable request"));
    assert_eq!(first.code, RefusalCode::DestNotAllowed);
    // Resubmitting the refused commitment (fresh nonce, same commitment) returns
    // the recorded refusal.
    coord_sign(&mut req);
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
        handle_sign(&fixture.node, &fixture.request(&psbt, NORMAL_PIN), NOW)
            .expect("decodable request"),
    );
    assert_eq!(first.code, RefusalCode::UserSigInvalid);

    // The user signs the IDENTICAL transaction (same inputs/outputs/fee/expiry
    // ⇒ same commitment_id, since signing only adds partial_sigs) and
    // resubmits. It must be evaluated afresh and signed — not answered from the
    // stale USER_SIG_INVALID. Keying idempotency on the commitment while
    // caching a signature-dependent refusal would deadlock the honest spend
    // until expiry.
    user_sign(&fixture, &mut psbt);
    let second = handle_sign(&fixture.node, &fixture.request(&psbt, NORMAL_PIN), NOW)
        .expect("decodable request");
    assert!(
        matches!(second, SignResponse::Accepted(_)),
        "a corrected resubmission of the same commitment must be re-evaluated, got {second:?}"
    );
}

#[test]
fn an_escape_refusal_is_not_cached_under_the_spend_commitment() {
    let fixture = fixture();
    let mut spend = vault_psbt(&fixture, vec![(fixture.hot_spk.clone(), 99_990_000)]);
    user_sign(&fixture, &mut spend);

    // The spend is valid, but its first mandatory escape pays an unknown
    // destination. DEST_NOT_ALLOWED is normally recordable when it belongs to the
    // spend; here it belongs to a different exact-byte candidate.
    let unknown = ScriptBuf::new_p2wsh(&WScriptHash::from_byte_array([0xED; 32]));
    let mut bad_escape = vault_psbt(&fixture, vec![(unknown, 99_990_000)]);
    user_sign(&fixture, &mut bad_escape);
    let first = expect_refusal(
        handle_sign(
            &fixture.node,
            &fixture.request_with_escape(&spend, &bad_escape, NORMAL_PIN, EXPIRY),
            NOW,
        )
        .expect("decodable request"),
    );
    assert_eq!(first.code, RefusalCode::DestNotAllowed);
    assert!(first.check.starts_with("escape:"));

    // Same spend commitment, corrected escape, fresh coordinator nonce. A cache
    // keyed only by the spend must not replay the escape's old refusal.
    let corrected = fixture.escape_for(&spend);
    let second = handle_sign(
        &fixture.node,
        &fixture.request_with_escape(&spend, &corrected, NORMAL_PIN, EXPIRY),
        NOW,
    )
    .expect("decodable request");
    assert!(
        matches!(second, SignResponse::Accepted(_)),
        "a corrected escape must be evaluated and accepted, got {second:?}"
    );
}

#[test]
fn a_replacement_spending_the_same_inputs_is_not_blocked_by_the_log() {
    let fixture = fixture();
    // Original: pays the hot wallet, gets signed and recorded.
    let mut original = vault_psbt(&fixture, vec![(fixture.hot_spk.clone(), 99_990_000)]);
    user_sign(&fixture, &mut original);
    let accepted = handle_sign(&fixture.node, &fixture.request(&original, NORMAL_PIN), NOW)
        .expect("decodable request");
    assert!(matches!(accepted, SignResponse::Accepted(_)));

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
    let response = handle_sign(
        &fixture.node,
        &fixture.request(&replacement, NORMAL_PIN),
        NOW,
    )
    .expect("decodable request");
    assert!(
        matches!(response, SignResponse::Accepted(_)),
        "a replacement is a new commitment and must be evaluated afresh, got {response:?}"
    );
}

// ---------------------------------------------------------------------------
// The Hold under Model B (ADR-0012) + the class contract (ADR-0013 §3)

/// A Hold long enough to observe, comfortably inside the retention cap.
const HOLD: u64 = 3_600;
/// The node's default `combine_slack_secs` (ADR-0013 §6). The fixture config does
/// not set it, so these tests pin the default the node applies.
const COMBINE_SLACK: u64 = 60;

impl Fixture {
    /// A held-test request whose commitment expiry sits at the node's cap — far
    /// beyond any Hold these tests exercise, so nothing is mistaken for an
    /// expired or too-short commitment.
    fn held_request(&self, psbt: &Psbt) -> SignRequest {
        self.request_at(psbt, NORMAL_PIN, NOW + MAX_AGE)
    }
}

fn expect_accepted(response: SignResponse) -> vault_proto::Accepted {
    match response {
        SignResponse::Accepted(accepted) => accepted,
        other => panic!("expected accepted, got {other:?}"),
    }
}

fn expect_config_error(raw: String) -> String {
    match Node::from_toml_str(&raw) {
        Ok(_) => panic!("config must be rejected"),
        Err(err) => err.to_string(),
    }
}

#[test]
fn escape_descriptor_is_required() {
    // Every SpendRequest carries a mandatory escape validated against this
    // descriptor, so a node without one could serve nothing. Omitting the field
    // must fail at LOAD, not leave a node that boots and refuses everything.
    let raw = fixture_config(HOLD, MAX_AGE, true)
        .lines()
        .filter(|line| !line.starts_with("escape_descriptor"))
        .collect::<Vec<_>>()
        .join("\n");
    let err = expect_config_error(raw);
    assert!(
        err.contains("escape_descriptor"),
        "unexpected config error: {err}"
    );
}

#[test]
fn escape_spk_must_also_be_allowlisted() {
    let err = expect_config_error(fixture_config(HOLD, MAX_AGE, false));
    assert!(
        err.contains("escape_descriptor must also be present in allowlist"),
        "unexpected config error: {err}"
    );
}

#[test]
fn max_commitment_age_must_exceed_hold() {
    let err = expect_config_error(fixture_config(HOLD, HOLD, true));
    assert!(
        err.contains("max_commitment_age_secs") && err.contains("must exceed hold_secs"),
        "unexpected config error: {err}"
    );
}

// -- the Model-B Hold: sign at ingress, fire at Hold expiry ------------------

#[test]
fn a_held_hot_spend_is_accepted_and_signed_at_ingress_with_the_whole_hold_remaining() {
    let fixture = held_fixture(HOLD);
    // Vault change is excluded from classification (ADR-0013 §3), so the one
    // non-change output makes this an ordinary held hot spend.
    let mut psbt = vault_psbt(
        &fixture,
        vec![
            (fixture.hot_spk.clone(), 90_000_000),
            (fixture.descriptor.script_pubkey(), 9_990_000),
        ],
    );
    user_sign(&fixture, &mut psbt);
    let accepted = expect_accepted(
        handle_sign(&fixture.node, &fixture.held_request(&psbt), NOW).expect("decodable request"),
    );
    assert_eq!(accepted.first_seen, NOW);
    assert_eq!(
        accepted.remaining_secs, HOLD,
        "first sight must report the whole Hold as remaining before the fire event"
    );
}

/// Model B: the node signs at ingress and the HOLD delays combine + broadcast,
/// never signing (ADR-0012's Model-B Hold lifecycle). Signing only after the Hold
/// would make signing itself a duress oracle.
///
/// There is no re-submission any more — the coordinator sends once, and the node
/// schedules its own fire — so a re-send is answered idempotently from the
/// anti-replay log rather than re-evaluated into a signature.
#[test]
fn a_held_hot_spend_is_answered_idempotently_on_a_re_send() {
    let fixture = held_fixture(HOLD);
    let mut psbt = vault_psbt(&fixture, vec![(fixture.hot_spk.clone(), 99_990_000)]);
    user_sign(&fixture, &mut psbt);
    let mut req = fixture.held_request(&psbt);

    let first = expect_accepted(handle_sign(&fixture.node, &req, NOW).expect("decodable request"));
    assert_eq!(first.remaining_secs, HOLD);

    // Half the Hold later, the coordinator re-sends with a fresh nonce (single-use
    // per transmission). Idempotency is keyed on the COMMITMENT, so this returns
    // the one recorded verdict — the schedule the first acceptance fixed is never
    // reset, and the node never signs twice.
    coord_sign(&mut req);
    let second = expect_accepted(
        handle_sign(&fixture.node, &req, NOW + HOLD / 2).expect("decodable request"),
    );
    assert_eq!(second, first, "a re-send returns the ONE recorded verdict");
}

#[test]
fn an_escape_class_spend_fires_immediately_even_under_a_hold() {
    let fixture = held_fixture(HOLD);
    // The canonical Rotate shape: every output pays the escape wallet. It
    // completes immediately under EITHER pin — the destination is the user's own
    // escape wallet either way, so there is nothing to defer and thus no timing
    // oracle (ADR-0012).
    let mut psbt = vault_psbt(&fixture, vec![(fixture.escape_spk.clone(), 99_990_000)]);
    user_sign(&fixture, &mut psbt);
    let accepted = expect_accepted(
        handle_sign(&fixture.node, &fixture.held_request(&psbt), NOW).expect("decodable request"),
    );
    assert_eq!(
        accepted.remaining_secs, 0,
        "an escape-class spend's fire event is now, even under a Hold"
    );
}

#[test]
fn an_escape_class_spend_with_vault_change_fires_immediately_too() {
    let fixture = held_fixture(HOLD);
    // Vault change is permitted in every class and excluded from classification
    // (ADR-0013 §3), so this is still escape-class.
    let mut psbt = vault_psbt(
        &fixture,
        vec![
            (fixture.escape_spk.clone(), 90_000_000),
            (fixture.descriptor.script_pubkey(), 9_990_000),
        ],
    );
    user_sign(&fixture, &mut psbt);
    let accepted = expect_accepted(
        handle_sign(&fixture.node, &fixture.held_request(&psbt), NOW).expect("decodable request"),
    );
    assert_eq!(accepted.remaining_secs, 0);
}

/// ADR-0013 §3: a SpendRequest whose spend classifies refresh-class is REJECTED.
/// A pure self-spend belongs in a pin-less RefreshRequest — admitting it here
/// would pose the "honor the pin or ignore it?" question the tagged union deletes,
/// and put refresh back on the duress surface.
#[test]
fn a_refresh_shaped_spend_request_is_rejected() {
    let fixture = held_fixture(HOLD);
    let vault_spk = fixture.descriptor.script_pubkey();
    let mut psbt = vault_psbt(&fixture, vec![(vault_spk, 99_990_000)]);
    user_sign(&fixture, &mut psbt);
    let refusal = expect_refusal(
        handle_sign(&fixture.node, &fixture.held_request(&psbt), NOW).expect("decodable request"),
    );
    assert_eq!(refusal.code, RefusalCode::PsbtInconsistent);
    assert_eq!(refusal.check, "transaction_class");
}

#[test]
fn an_invalid_hot_spend_is_refused_never_signed_or_registered() {
    let fixture = held_fixture(HOLD);
    // A hot-class spend with NO user signature. It fails validation, so it is
    // refused — never signed, never registered, never propagated.
    let psbt = vault_psbt(&fixture, vec![(fixture.hot_spk.clone(), 99_990_000)]);
    let refusal = expect_refusal(
        handle_sign(&fixture.node, &fixture.held_request(&psbt), NOW).expect("decodable request"),
    );
    assert_eq!(refusal.code, RefusalCode::UserSigInvalid);
}

/// EXPIRY_TOO_SHORT (ADR-0013 §6): a hot-class commitment must outlive its Hold
/// AND the combine window that follows. Otherwise the node would sign at ingress,
/// hold the partial, and watch the candidate expire before it could ever combine —
/// an acceptance that could only ever fail silently.
#[test]
fn a_hot_spend_whose_expiry_cannot_outlive_the_hold_plus_combine_window_is_refused() {
    let fixture = held_fixture(HOLD);
    let mut psbt = vault_psbt(&fixture, vec![(fixture.hot_spk.clone(), 99_990_000)]);
    user_sign(&fixture, &mut psbt);
    // One second short of `now + hold_secs + combine_slack_secs`.
    let refusal = expect_refusal(
        handle_sign(
            &fixture.node,
            &fixture.request_at(&psbt, NORMAL_PIN, NOW + HOLD + COMBINE_SLACK - 1),
            NOW,
        )
        .expect("decodable request"),
    );
    assert_eq!(refusal.code, RefusalCode::ExpiryTooShort);
    assert_eq!(refusal.check, "commitment_expiry");
}

/// Equality passes: expiry EXACTLY at `now + hold_secs + combine_slack_secs` is
/// accepted. The bound is the last instant the combine could still complete, not
/// the first instant it could not.
#[test]
fn a_hot_spend_expiring_exactly_at_the_bound_is_accepted() {
    let fixture = held_fixture(HOLD);
    let mut psbt = vault_psbt(&fixture, vec![(fixture.hot_spk.clone(), 99_990_000)]);
    user_sign(&fixture, &mut psbt);
    let response = handle_sign(
        &fixture.node,
        &fixture.request_at(&psbt, NORMAL_PIN, NOW + HOLD + COMBINE_SLACK),
        NOW,
    )
    .expect("decodable request");
    assert_eq!(expect_accepted(response).remaining_secs, HOLD);
}

/// The bound is hot-class only: an escape-class spend fires NOW, so it needs only
/// the combine window, not a Hold it does not have.
#[test]
fn expiry_too_short_does_not_apply_to_an_escape_class_spend() {
    let fixture = held_fixture(HOLD);
    let mut psbt = vault_psbt(&fixture, vec![(fixture.escape_spk.clone(), 99_990_000)]);
    user_sign(&fixture, &mut psbt);
    let response = handle_sign(
        &fixture.node,
        // Far short of the hot-class bound, but it fires immediately.
        &fixture.request_at(&psbt, NORMAL_PIN, NOW + HOLD),
        NOW,
    )
    .expect("decodable request");
    assert_eq!(expect_accepted(response).remaining_secs, 0);
}

#[test]
fn a_hot_spend_fires_immediately_when_hold_is_zero() {
    // hold_secs = 0 is the first-light configuration: the hot class exists but the
    // Hold is a no-op, so the fire event is ingress itself.
    let fixture = held_fixture(0);
    let mut psbt = vault_psbt(&fixture, vec![(fixture.hot_spk.clone(), 99_990_000)]);
    user_sign(&fixture, &mut psbt);
    let accepted = expect_accepted(
        handle_sign(&fixture.node, &fixture.held_request(&psbt), NOW).expect("decodable request"),
    );
    assert_eq!(accepted.remaining_secs, 0);
}

/// The coordinator-auth + freshness gate (ADR-0013 §2/§3): a node admits a
/// request past the PIN only if it is validly coord-signed over its canonical
/// bytes by the coordinator configured for that node, carries an unseen nonce, and
/// has a fresh expiry. This is the trust root V0-8b authenticates spends against.
///
/// Every fixture node is sealed to [`coord_key`] — the gate is not optional — so
/// these tests use the ordinary [`fixture`] and vary only what the coordinator
/// does: sign as the wrong key, tamper after signing, stale the expiry, replay a
/// nonce. `hold_secs = 0`, so an authentic request signs on first submission and
/// the verdict shows the gate was cleared.
mod coord_auth {
    use super::*;

    /// A user-signed hot spend, coord-signed by the vault's pinned coordinator —
    /// the node signs it iff it authenticates.
    fn honest_request() -> (Fixture, SignRequest) {
        let fixture = fixture();
        let mut psbt = vault_psbt(&fixture, vec![(fixture.hot_spk.clone(), 99_990_000)]);
        user_sign(&fixture, &mut psbt);
        let req = fixture.request(&psbt, NORMAL_PIN);
        (fixture, req)
    }

    #[test]
    fn a_correctly_coord_signed_request_signs() {
        let (fixture, req) = honest_request();
        assert!(
            matches!(
                handle_sign(&fixture.node, &req, NOW).expect("decodable"),
                SignResponse::Accepted(_)
            ),
            "an authentic coord-signed request must reach the signer"
        );
    }

    /// A user-signed pure self-spend, coord-signed by the vault's pinned
    /// coordinator — the first-class pin-less Refresh arm (ADR-0013 §2).
    ///
    /// The output value leaves a REALISTIC self-spend fee (1_000 sat over a ~94 vB
    /// transaction, ~10 sat/vB). The spend fixture's flat 10_000 sat would read as
    /// ~106 sat/vB here and trip the refresh fee cap — correctly, which is the
    /// point of that cap and is covered by its own test.
    fn honest_refresh() -> (Fixture, RefreshRequest) {
        let fixture = fixture();
        let mut psbt = vault_psbt(
            &fixture,
            vec![(fixture.descriptor.script_pubkey(), 99_999_000)],
        );
        user_sign(&fixture, &mut psbt);
        let req = refresh_request(&psbt);
        (fixture, req)
    }

    #[test]
    fn a_correctly_coord_signed_refresh_is_accepted() {
        let (fixture, req) = honest_refresh();
        let accepted =
            expect_accepted(handle_refresh(&fixture.node, &req, NOW).expect("decodable refresh"));
        assert_eq!(
            accepted.remaining_secs, 0,
            "a refresh is instant: it has no Hold and no pin"
        );
    }

    /// The Refresh arm authenticates against the same pinned root as a spend: a
    /// refresh signed by a coordinator outside it is rejected, so the pin-less arm
    /// is not a way around the trust root. The root proven here is the `fixture`
    /// node's CONFIGURED `coordinator_auth_pubkey` — that fixture is channel-less,
    /// so no manifest binds it; what this test pins is the gate, not the sealing
    /// ceremony (see [`CoordRequest`] for how far the pin goes today).
    #[test]
    fn a_refresh_from_a_coordinator_outside_the_configured_root_is_rejected() {
        let (fixture, mut req) = honest_refresh();
        let digest = req.coord_request().auth_digest();
        let sig = Secp256k1::new().sign_ecdsa(&Message::from_digest(digest), &seckey(0xC1));
        req.coord_sig = sig.serialize_der().to_lower_hex_string();
        let refusal =
            expect_refusal(handle_refresh(&fixture.node, &req, NOW).expect("decodable refresh"));
        assert_eq!(refusal.code, RefusalCode::CoordAuthInvalid);
    }

    /// Freshness binds the Refresh arm too: the second transmission of an
    /// authentic refresh is refused, proving the first consumed nonce state rather
    /// than bypassing the gate on a refresh-only path.
    #[test]
    fn a_replayed_refresh_nonce_is_rejected() {
        let (fixture, req) = honest_refresh();
        expect_accepted(handle_refresh(&fixture.node, &req, NOW).expect("decodable refresh"));
        let refusal =
            expect_refusal(handle_refresh(&fixture.node, &req, NOW).expect("decodable refresh"));
        assert_eq!(refusal.code, RefusalCode::NonceReplayed);
    }

    /// Tampering with any coord-signed refresh field breaks the signature: the
    /// digest covers the full canonical request, not just the PSBT.
    #[test]
    fn a_tampered_refresh_field_breaks_the_coord_signature() {
        let (fixture, mut req) = honest_refresh();
        req.expiry += 1;
        let refusal =
            expect_refusal(handle_refresh(&fixture.node, &req, NOW).expect("decodable refresh"));
        assert_eq!(refusal.code, RefusalCode::CoordAuthInvalid);
    }

    #[test]
    fn a_request_from_a_coordinator_outside_the_configured_root_is_rejected() {
        // The node is sealed to coordinator 0xC0; a request signed by a DIFFERENT
        // coordinator (0xC1, not the configured one) is rejected — the exact
        // property every node enforces (ADR-0013 §2), and the reason a coordinator
        // cannot be swapped without minting a new vault.
        let (fixture, mut req) = honest_request();
        coord_sign_as(&mut req, &seckey(0xC1), "nonce-wrong-key");
        let refusal = expect_refusal(handle_sign(&fixture.node, &req, NOW).expect("decodable"));
        assert_eq!(refusal.code, RefusalCode::CoordAuthInvalid);
    }

    #[test]
    fn an_unsigned_request_is_rejected_before_the_pin() {
        // A request with no coord_sig at all never passes the gate.
        let (fixture, mut req) = honest_request();
        req.nonce = String::new();
        req.coord_sig = String::new();
        let refusal = expect_refusal(handle_sign(&fixture.node, &req, NOW).expect("decodable"));
        assert_eq!(refusal.code, RefusalCode::CoordAuthInvalid);

        // And it is rejected BEFORE the PIN: an unauthenticated caller cannot even
        // probe the PIN, let alone reach the signer. The PIN here is deliberately
        // WRONG, which is what makes the ordering observable — the two checks
        // disagree about this request, so only the one that runs first can answer.
        // `BadPin` here would mean the gate had moved after the PIN compare. (With
        // a VALID pin both orderings return CoordAuthInvalid and the test cannot
        // fail, which is exactly what it used to do.)
        let (fixture2, mut req2) = honest_request();
        req2.pin = "0000".into();
        assert_ne!(
            req2.pin.as_str(),
            NORMAL_PIN,
            "the pin must actually be wrong"
        );
        assert_ne!(
            req2.pin.as_str(),
            DURESS_PIN,
            "the pin must actually be wrong"
        );
        req2.nonce = String::new();
        req2.coord_sig = String::new();
        let refusal2 = expect_refusal(handle_sign(&fixture2.node, &req2, NOW).expect("decodable"));
        assert_eq!(refusal2.code, RefusalCode::CoordAuthInvalid);
    }

    #[test]
    fn tampering_a_field_after_signing_is_rejected() {
        // Tamper the escape PSBT after signing: coord_sig binds it, so it fails.
        let (fixture, mut req) = honest_request();
        req.escape_psbt = format!("{}=", req.escape_psbt);
        let refusal = expect_refusal(handle_sign(&fixture.node, &req, NOW).expect("decodable"));
        assert_eq!(refusal.code, RefusalCode::CoordAuthInvalid);

        // Tamper the nonce after signing: the nonce is in the signed bytes too, so
        // an attacker cannot refresh a captured request by swapping in a new nonce.
        let (fixture2, mut req2) = honest_request();
        req2.nonce = "nonce-tamper-swapped".into();
        let refusal2 = expect_refusal(handle_sign(&fixture2.node, &req2, NOW).expect("decodable"));
        assert_eq!(refusal2.code, RefusalCode::CoordAuthInvalid);
    }

    #[test]
    fn a_stale_or_over_horizon_expiry_is_rejected() {
        // Already past: expiry <= now. Re-signed after the edit, so this is an
        // authentic request that is merely stale — not a signature failure.
        let (fixture, mut past) = honest_request();
        past.expiry = NOW - 1;
        coord_sign(&mut past);
        let refusal = expect_refusal(handle_sign(&fixture.node, &past, NOW).expect("decodable"));
        assert_eq!(refusal.code, RefusalCode::CommitmentExpired);

        // Beyond the node's own retention cap: now + MAX_AGE + 1. A hostile
        // coordinator cannot inflate how long the node must remember this nonce.
        let (fixture2, mut far) = honest_request();
        far.expiry = NOW + MAX_AGE + 1;
        coord_sign(&mut far);
        let refusal2 = expect_refusal(handle_sign(&fixture2.node, &far, NOW).expect("decodable"));
        assert_eq!(refusal2.code, RefusalCode::CommitmentExpired);
    }

    #[test]
    fn a_replayed_nonce_is_rejected() {
        let (fixture, req) = honest_request();
        assert!(matches!(
            handle_sign(&fixture.node, &req, NOW).expect("decodable"),
            SignResponse::Accepted(_)
        ));

        // The identical request (same nonce, same signature) is a replay: the gate
        // rejects it BEFORE the anti-replay log's idempotent short-circuit, because
        // a coordinator nonce is single-use per transmission. A genuine coordinator
        // retry re-signs with a fresh nonce and gets the recorded verdict instead
        // (see `identical_resubmission_returns_the_recorded_signed_verdict`).
        let refusal = expect_refusal(handle_sign(&fixture.node, &req, NOW).expect("decodable"));
        assert_eq!(refusal.code, RefusalCode::NonceReplayed);
    }

    /// The last of the gate's five decisions to reach the wire: a full nonce
    /// cache refuses with `COORD_NONCE_CAPACITY`. `NonceLog`'s own tests cover the
    /// bound; this covers the decision → refusal mapping the handler owns.
    ///
    /// The flood is built from requests carrying a deliberately WRONG pin, which
    /// is what makes it cheap — and is itself the ADR-0013 §7 residual in the
    /// open: the gate consumes a nonce BEFORE the pin compare, so a request
    /// refused later still burns a slot. `BadPin` on every fill request is
    /// therefore an assertion, not an incidental detail.
    ///
    /// The wrong pin is deliberately OVER the `MAX_PIN_BYTES` bound, which forces a
    /// `Wrong` verdict independent of the fixture's enrolled digests: an over-length
    /// value is unenrollable, so it can never match either PIN. That is a CORRECTNESS
    /// choice, not a cost one — `handle_sign` runs BOTH Argon2 evaluations
    /// unconditionally BEFORE the over-length override (the constant-cost invariant;
    /// see `every_spendrequest_runs_two_argon2_evaluations_in_a_fixed_order`), so this
    /// flood still runs 2×FLOOD_BOUND Argon2. It stays fast only because the fixture
    /// enrols at `MIN_M_COST`, NOT because the hash is skipped. Do NOT add a length
    /// fast-path ahead of the compare to "speed this up": that would reintroduce the
    /// exact timing leak the constant-cost compare exists to close.
    #[test]
    fn a_full_nonce_cache_refuses_with_coord_nonce_capacity() {
        let (fixture, template) = honest_request();
        // A bound on the cap, not the cap itself: the test must not restate the
        // private MAX_COORD_NONCES, only outlast it.
        const FLOOD_BOUND: usize = 16_384;
        let over_length_pin = "x".repeat(vault_proto::MAX_PIN_BYTES + 1);
        let mut capacity_refusal = None;
        for i in 0..FLOOD_BOUND {
            let mut req = template.clone();
            req.pin = over_length_pin.as_str().into();
            coord_sign_as(&mut req, &coord_key().0, &format!("flood-{i}"));
            let refusal = expect_refusal(handle_sign(&fixture.node, &req, NOW).expect("decodable"));
            if refusal.code == RefusalCode::CoordNonceCapacity {
                capacity_refusal = Some(refusal);
                break;
            }
            assert_eq!(
                refusal.code,
                RefusalCode::BadPin,
                "until the cache fills, an authentic request is refused at the PIN — \
                 having already spent its nonce at the gate (request {i})"
            );
        }
        let refusal = capacity_refusal
            .expect("the authenticated nonce cache must be bounded, and refuse once full");
        assert_eq!(refusal.check, "coord_nonce_capacity");

        // The cache is full, not broken: the refusal is capacity, not a
        // misreported auth or replay failure. A fresh, authentic, correctly
        // pinned request gets the same answer — no slot, no signature.
        let mut honest = template.clone();
        coord_sign_as(&mut honest, &coord_key().0, "flood-then-honest");
        let refusal = expect_refusal(handle_sign(&fixture.node, &honest, NOW).expect("decodable"));
        assert_eq!(refusal.code, RefusalCode::CoordNonceCapacity);
    }

    #[test]
    fn an_oversized_authenticated_nonce_is_rejected() {
        let (fixture, mut req) = honest_request();
        // The demo's 32 random bytes are 64 hex characters. A larger signed
        // value must not enter the retained nonce map.
        coord_sign_as(&mut req, &coord_key().0, &"x".repeat(65));
        let refusal = expect_refusal(handle_sign(&fixture.node, &req, NOW).expect("decodable"));
        assert_eq!(refusal.code, RefusalCode::CoordAuthInvalid);
        assert_eq!(refusal.check, "coord_nonce");
    }

    #[test]
    fn clock_rollback_cannot_reopen_a_pruned_nonce() {
        let (fixture, mut old) = honest_request();
        old.expiry = NOW + 100;
        coord_sign_as(&mut old, &coord_key().0, "old-nonce");
        assert!(matches!(
            handle_sign(&fixture.node, &old, NOW).expect("decodable"),
            SignResponse::Accepted(_)
        ));

        // Advance authenticated node time to the old request's expiry. This
        // prunes its nonce while admitting a distinct, later-expiring request.
        let mut newer = old.clone();
        newer.expiry = NOW + 200;
        coord_sign_as(&mut newer, &coord_key().0, "new-nonce");
        assert!(matches!(
            handle_sign(&fixture.node, &newer, NOW + 100).expect("decodable"),
            SignResponse::Accepted(_)
        ));

        // Even if wall time steps backwards into the old request's original
        // window, the authenticated high-water keeps that request expired.
        let refusal =
            expect_refusal(handle_sign(&fixture.node, &old, NOW + 50).expect("decodable"));
        assert_eq!(refusal.code, RefusalCode::CommitmentExpired);
    }

    /// The known-good fixture config with its whole `coordinator_auth_pubkey`
    /// line replaced by `line` (which must carry its own key and newline); `""`
    /// drops the field entirely. Everything else is the config the rest of this
    /// file loads, so the pinned coordinator is the ONLY variable.
    fn config_with_coord_line(line: &str) -> String {
        let cfg = fixture_config(0, MAX_AGE, true);
        let (head, tail) = cfg
            .split_once("coordinator_auth_pubkey")
            .expect("the fixture config pins a coordinator");
        let rest = tail.split_once('\n').map(|(_, rest)| rest).unwrap_or("");
        format!("{head}{line}{rest}")
    }

    #[test]
    fn a_config_without_a_coordinator_auth_pubkey_fails_startup() {
        // The trust root is MANDATORY, and this is what keeps the ingress gate
        // un-bypassable: a node with no pinned coordinator could authenticate
        // nothing, so an absent key must be fatal at STARTUP rather than yield a
        // running node whose `/sign` gate verifies against nobody. There is no
        // "no coordinator" mode for a request to fall into — the absent-field
        // case is a dead config, not a permissive one. (ADR-0013 §2 states the
        // reject-unless-coord-signed rule unconditionally; §5 marks `[channel]`
        // optional, but never this.)
        let err = expect_config_error(config_with_coord_line(""));
        assert!(
            err.contains("coordinator_auth_pubkey"),
            "an absent coordinator_auth_pubkey must fail startup by name: {err}"
        );
    }

    #[test]
    fn a_malformed_coordinator_auth_pubkey_fails_startup() {
        // A key that does not parse is fatal at startup too — never a node that
        // loads and then refuses (or, worse, admits) every request at runtime.
        let err = expect_config_error(config_with_coord_line(
            "coordinator_auth_pubkey = \"not-a-pubkey\"\n",
        ));
        assert!(
            err.contains("bad coordinator_auth_pubkey"),
            "unexpected config error: {err}"
        );
    }

    #[test]
    fn an_uncompressed_coordinator_auth_pubkey_fails_startup() {
        let secp = Secp256k1::new();
        let uncompressed = seckey(0xC0).public_key(&secp).serialize_uncompressed();
        let err = expect_config_error(config_with_coord_line(&format!(
            "coordinator_auth_pubkey = \"{}\"\n",
            uncompressed.to_lower_hex_string()
        )));
        assert!(
            err.contains("33-byte compressed"),
            "unexpected config error: {err}"
        );
    }

    #[test]
    fn a_coordinator_key_that_is_the_user_key_fails_startup() {
        // The coordinator authorizes REQUESTS; the user authorizes SPENDS. One key
        // for both roles means the user key can mint its own coordinator requests,
        // so the gate authenticates nothing it did not already assume. Nothing at
        // runtime would ever report this — every check still passes — so the only
        // place to catch it is startup.
        let secp = Secp256k1::new();
        let err = expect_config_error(config_with_coord_line(&format!(
            "coordinator_auth_pubkey = \"{}\"\n",
            pubkey(&secp, 1)
        )));
        assert!(
            err.contains("must not be the descriptor's user key"),
            "unexpected config error: {err}"
        );
    }

    #[test]
    fn a_coordinator_key_that_is_a_federation_node_key_fails_startup() {
        // The isolation this trust root exists to provide: a compromised node must
        // not be able to manufacture coordinator requests for its peers. Reusing a
        // federation signing key as the coordinator key hands exactly that power to
        // whichever node holds it. Checked for EVERY node key, not just this
        // node's own — the danger is a peer minting requests at us just as much.
        let secp = Secp256k1::new();
        for index in 2..=6 {
            let err = expect_config_error(config_with_coord_line(&format!(
                "coordinator_auth_pubkey = \"{}\"\n",
                pubkey(&secp, index)
            )));
            assert!(
                err.contains("must not be one of the descriptor's federation node keys"),
                "node key {index} must be refused as a coordinator key: {err}"
            );
        }
    }
}

/// The refresh contract (ADR-0013 §2/§6): pin-less, instant, and bounded by its
/// own limits, because it has neither the Hold nor the PIN that ADR-0006 relies on
/// for its burn defense.
mod refresh_bounds {
    use super::*;

    /// The fixture refresh: a pure self-spend paying `value` back to the vault,
    /// over the vault UTXO at `input_txid:0`.
    fn refresh_of(fixture: &Fixture, input_txid: u8, value: u64) -> Psbt {
        refresh_of_inputs(
            fixture,
            vec![OutPoint::new(Txid::from_byte_array([input_txid; 32]), 0)],
            value,
        )
    }

    fn refresh_of_inputs(fixture: &Fixture, inputs: Vec<OutPoint>, value: u64) -> Psbt {
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: inputs
                .into_iter()
                .map(|previous_output| TxIn {
                    previous_output,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                })
                .collect(),
            output: vec![TxOut {
                script_pubkey: fixture.descriptor.script_pubkey(),
                value: Amount::from_sat(value),
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).expect("unsigned tx");
        for input in &mut psbt.inputs {
            input.witness_utxo = Some(TxOut {
                script_pubkey: fixture.descriptor.script_pubkey(),
                value: Amount::from_sat(100_000_000),
            });
            input.witness_script = Some(
                fixture
                    .descriptor
                    .explicit_script()
                    .expect("wsh witness script"),
            );
        }
        user_sign(fixture, &mut psbt);
        psbt
    }

    /// A realistic self-spend fee: ~1_000 sat over a ~94 vB transaction.
    fn healthy_refresh(fixture: &Fixture, input_txid: u8) -> Psbt {
        refresh_of(fixture, input_txid, 99_999_000)
    }

    /// The node's default `refresh_min_interval_secs` (ADR-0013 §6, ~30 days).
    const MIN_INTERVAL: u64 = 2_592_000;

    #[test]
    fn a_refresh_is_accepted_signed_and_instant() {
        let fixture = fixture();
        let psbt = healthy_refresh(&fixture, 7);
        let accepted = expect_accepted(
            handle_refresh(&fixture.node, &refresh_request(&psbt), NOW).expect("decodable"),
        );
        assert_eq!(accepted.first_seen, NOW);
        assert_eq!(
            accepted.remaining_secs, 0,
            "a refresh has no Hold: it moves nothing to anyone"
        );
    }

    /// ADR-0013 §6's minimum refresh interval, on the coin a refresh CREATES.
    ///
    /// This is the half that actually bounds the burn RATE: an attacker driving
    /// repeated refreshes to burn the vault must CHAIN them — refresh A→B, then
    /// B→C — and every link spends a coin the previous refresh just made. Keyed on
    /// inputs alone, each link would spend a never-before-seen outpoint and the
    /// interval would never fire.
    #[test]
    fn a_chained_refresh_of_a_freshly_refreshed_coin_is_refused_as_too_soon() {
        let fixture = fixture();
        let first = healthy_refresh(&fixture, 7);
        expect_accepted(
            handle_refresh(&fixture.node, &refresh_request(&first), NOW).expect("decodable"),
        );

        // The next link spends the coin the first refresh created.
        let first_txid = first.unsigned_tx.compute_txid();
        let mut second = healthy_refresh(&fixture, 8);
        second.unsigned_tx.input[0].previous_output = OutPoint::new(first_txid, 0);
        user_sign(&fixture, &mut second);

        let refusal = expect_refusal(
            handle_refresh(&fixture.node, &refresh_request(&second), NOW + 60).expect("decodable"),
        );
        assert_eq!(refusal.code, RefusalCode::RefreshTooSoon);
        assert_eq!(refusal.check, "refresh_min_interval");
    }

    #[test]
    fn refreshing_the_same_coin_again_inside_the_interval_is_refused() {
        let fixture = fixture();
        let first = healthy_refresh(&fixture, 7);
        expect_accepted(
            handle_refresh(&fixture.node, &refresh_request(&first), NOW).expect("decodable"),
        );
        // A different transaction (different output value ⇒ different commitment)
        // over the SAME coin, one day later — well inside the ~30-day interval.
        let again = refresh_of(&fixture, 7, 99_998_000);
        let day_later = NOW + 86_400;
        let refusal = expect_refusal(
            handle_refresh(
                &fixture.node,
                &refresh_request_at(&again, day_later + 3_600),
                day_later,
            )
            .expect("decodable"),
        );
        assert_eq!(refusal.code, RefusalCode::RefreshTooSoon);
    }

    #[test]
    fn every_input_of_a_multi_input_refresh_is_checked_for_recent_history() {
        let fixture = fixture();
        let first = healthy_refresh(&fixture, 7);
        expect_accepted(
            handle_refresh(&fixture.node, &refresh_request(&first), NOW).expect("decodable"),
        );

        // Put an untracked coin first and the recently refreshed coin second. A
        // missing history entry for input 0 must continue, not return from the
        // whole check and silently skip input 1.
        let multi = refresh_of_inputs(
            &fixture,
            vec![
                OutPoint::new(Txid::from_byte_array([8; 32]), 0),
                first.unsigned_tx.input[0].previous_output,
            ],
            199_998_000,
        );
        let refusal = expect_refusal(
            handle_refresh(
                &fixture.node,
                &refresh_request_at(&multi, NOW + 3_660),
                NOW + 60,
            )
            .expect("decodable"),
        );
        assert_eq!(refusal.code, RefusalCode::RefreshTooSoon);
        assert!(
            refusal
                .detail
                .contains(&first.unsigned_tx.input[0].previous_output.to_string()),
            "the second, tracked input must be the refused coin: {refusal:?}"
        );
    }

    #[test]
    fn refreshing_the_same_coin_once_the_interval_has_elapsed_is_accepted() {
        let fixture = fixture();
        let first = healthy_refresh(&fixture, 7);
        expect_accepted(
            handle_refresh(&fixture.node, &refresh_request(&first), NOW).expect("decodable"),
        );
        // Past the interval. The legitimate ~90-day cadence never sees this bound.
        let again = refresh_of(&fixture, 7, 99_998_000);
        let later = NOW + MIN_INTERVAL;
        expect_accepted(
            handle_refresh(
                &fixture.node,
                &refresh_request_at(&again, later + 3_600),
                later,
            )
            .expect("decodable"),
        );
    }

    /// ADR-0013 §6's tight refresh fee cap — the other half of the burn bound. A
    /// real self-spend pays a normal feerate, never the 10% `max_fee_pct` a
    /// hot-class spend may use.
    #[test]
    fn a_refresh_above_the_refresh_fee_cap_is_refused() {
        let fixture = fixture();
        // 5_000_000 sat of fee: far under `max_fee_pct` (10% of 100_000_000), so
        // the ORDINARY fee cap admits it — and this cap is what stops it.
        let psbt = refresh_of(&fixture, 7, 95_000_000);
        let refusal = expect_refusal(
            handle_refresh(&fixture.node, &refresh_request(&psbt), NOW).expect("decodable"),
        );
        assert_eq!(refusal.code, RefusalCode::RefreshFeeExceedsCap);
        assert_eq!(refusal.check, "refresh_fee_cap");
    }

    /// The refresh fee cap is an EXACT bound: `fee == cap * vsize` (exactly the cap)
    /// passes, but a single satoshi more is refused. The truncated integer feerate
    /// `fee / vsize` would round `cap * vsize + 1` back down to the cap and wrongly
    /// admit it — this pins the burn bound to the satoshi.
    #[test]
    fn the_refresh_fee_cap_is_enforced_to_the_exact_satoshi() {
        let fixture = fixture();
        // The fixture leaves `refresh_max_feerate` at its 100 sat/vB default.
        const CAP: u64 = 100;
        let vsize = refresh_of(&fixture, 7, 99_990_000).unsigned_tx.vsize() as u64;

        // Exactly at the cap: accepted (equality passes).
        let at_cap = refresh_of(&fixture, 8, 100_000_000 - CAP * vsize);
        expect_accepted(
            handle_refresh(&fixture.node, &refresh_request(&at_cap), NOW).expect("decodable"),
        );

        // One satoshi over `cap * vsize`: the truncated feerate still reads as the
        // cap, but the exact bound refuses it. (Distinct coin, so no min-interval
        // collision with the accepted refresh above.)
        let over_fee = CAP * vsize + 1;
        assert_eq!(
            over_fee / vsize,
            CAP,
            "the truncated feerate equals the cap — exactly the trap this closes"
        );
        let over = refresh_of(&fixture, 9, 100_000_000 - over_fee);
        let refusal = expect_refusal(
            handle_refresh(&fixture.node, &refresh_request(&over), NOW).expect("decodable"),
        );
        assert_eq!(refusal.code, RefusalCode::RefreshFeeExceedsCap);
        assert_eq!(refusal.check, "refresh_fee_cap");
    }

    /// Refresh subordination (ADR-0012): while ANY spend is pending, every refresh
    /// is turned away — deliberately coarse, not "refreshes whose inputs overlap".
    /// A duress escape sweeps most of the vault while the triggering hot spend
    /// touches a few coins, so an input-overlap rule would let a refresh over a
    /// non-overlapping escape input finalize instantly and invalidate the armed
    /// escape. Only the coarse rule closes that.
    #[test]
    fn a_refresh_is_subordinate_to_a_pending_spend_it_shares_no_inputs_with() {
        let fixture = held_fixture(HOLD);
        // A pending hot spend over coin 7.
        let mut spend = vault_psbt(&fixture, vec![(fixture.hot_spk.clone(), 99_990_000)]);
        user_sign(&fixture, &mut spend);
        expect_accepted(
            handle_sign(&fixture.node, &fixture.held_request(&spend), NOW).expect("decodable"),
        );

        // A refresh over a DIFFERENT coin (8), sharing no input with the pending
        // spend. It is still blocked.
        let refresh = healthy_refresh(&fixture, 8);
        assert_ne!(
            refresh.unsigned_tx.input[0].previous_output,
            spend.unsigned_tx.input[0].previous_output,
            "the refresh and the pending spend share no input"
        );
        let refusal = expect_refusal(
            handle_refresh(&fixture.node, &refresh_request(&refresh), NOW).expect("decodable"),
        );
        assert_eq!(refusal.code, RefusalCode::RefreshSubordinated);
        assert_eq!(refusal.check, "refresh_subordination");
    }

    /// The block is bounded by the pending spend's commitment expiry, so an
    /// attacker holding a spend pending forever to starve refreshes cannot: it is
    /// denial, and it ends. (Retriable, not terminal.)
    #[test]
    fn a_refresh_is_served_once_the_pending_spend_has_expired() {
        let fixture = held_fixture(HOLD);
        let mut spend = vault_psbt(&fixture, vec![(fixture.hot_spk.clone(), 99_990_000)]);
        user_sign(&fixture, &mut spend);
        let spend_expiry = NOW + MAX_AGE;
        expect_accepted(
            handle_sign(&fixture.node, &fixture.held_request(&spend), NOW).expect("decodable"),
        );

        let refresh = healthy_refresh(&fixture, 8);
        // Blocked while the spend is pending...
        assert_eq!(
            expect_refusal(
                handle_refresh(&fixture.node, &refresh_request(&refresh), NOW).expect("decodable")
            )
            .code,
            RefusalCode::RefreshSubordinated
        );
        // ...and served after its final authorized fire second. The refresh's own
        // expiry has to outlive the spend's, so it is re-issued at the later clock.
        expect_accepted(
            handle_refresh(
                &fixture.node,
                &refresh_request_at(&refresh, spend_expiry + 3_600),
                spend_expiry + 1,
            )
            .expect("decodable"),
        );
    }

    /// A RefreshRequest must BE a refresh: anything that can move value to a
    /// destination is refused on this pin-less path. This is what keeps refresh off
    /// the duress surface — a transaction that moves nothing to anyone needs no
    /// duress decision, so there is no signal for an attacker to read here.
    #[test]
    fn a_refresh_request_carrying_a_hot_destination_is_rejected() {
        let fixture = fixture();
        let mut psbt = vault_psbt(&fixture, vec![(fixture.hot_spk.clone(), 99_999_000)]);
        user_sign(&fixture, &mut psbt);
        let refusal = expect_refusal(
            handle_refresh(&fixture.node, &refresh_request(&psbt), NOW).expect("decodable"),
        );
        assert_eq!(refusal.code, RefusalCode::PsbtInconsistent);
        assert_eq!(refusal.check, "transaction_class");
    }
}
