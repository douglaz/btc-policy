//! V0-7: the protocol-level half of DESIGN.md T3's mutation property.
//!
//! Two bindings live in this crate, and both are what make "no mutated tx passes
//! an authorization bound to the original" true at all:
//!
//!  - the **commitment**, whose canonical encoding must be INJECTIVE — two
//!    different transactions can never share a `commitment_id`, or a node's
//!    registered candidate would cover a transaction it never evaluated;
//!  - the **coordinator-request** digest, whose preimage must bind every signed
//!    field (and the vault's `wallet_id` as a domain separator), or a signature
//!    issued for one request would authenticate another.
//!
//! `crates/vault-node/src/prop_mutation.rs` drives the same invariant through the
//! real ingress on real PSBTs; this file states it over the encodings themselves,
//! where a length-prefix ambiguity or a forgotten field would live.
//!
//! Counterexamples persist to `crates/vault-proto/tests/proptest-regressions/`.

use proptest::prelude::*;
use proptest::test_runner::FileFailurePersistence;
use vault_proto::{
    Commitment, CommitmentInput, CommitmentOutput, CoordRequest, RefreshRequest, SignRequest,
};

use bitcoin::secp256k1::{
    ecdsa::Signature, Message, PublicKey as SecpPublicKey, Secp256k1, SecretKey,
};

/// `Direct` rather than proptest's default: an integration test under `tests/` has
/// no `lib.rs`/`main.rs` above it, so the default `SourceParallel` finds nothing
/// and silently persists no counterexample at all. The path is relative to the
/// package root, which is cargo's CWD when the test runs.
fn config() -> ProptestConfig {
    ProptestConfig {
        failure_persistence: Some(Box::new(FileFailurePersistence::Direct(
            "tests/proptest-regressions/prop_commitment_binding.txt",
        ))),
        ..ProptestConfig::default()
    }
}

// --- generators --------------------------------------------------------------

fn commitment_input_strategy() -> impl Strategy<Value = CommitmentInput> {
    (any::<[u8; 32]>(), any::<u32>(), any::<u32>()).prop_map(|(txid, vout, sequence)| {
        CommitmentInput {
            txid,
            vout,
            sequence,
        }
    })
}

fn commitment_output_strategy() -> impl Strategy<Value = CommitmentOutput> {
    // Scripts of varied length, including empty: the length prefix is exactly what
    // stops a long script from swallowing the field that follows it.
    (proptest::collection::vec(any::<u8>(), 0..40), any::<u64>()).prop_map(
        |(script_pubkey, amount)| CommitmentOutput {
            script_pubkey,
            amount,
        },
    )
}

fn commitment_strategy() -> impl Strategy<Value = Commitment> {
    (
        any::<[u8; 32]>(),
        any::<i32>(),
        any::<u32>(),
        proptest::collection::vec(commitment_input_strategy(), 0..4),
        proptest::collection::vec(commitment_output_strategy(), 0..4),
        any::<u64>(),
        any::<u64>(),
        any::<u32>(),
    )
        .prop_map(
            |(wallet_id, version, lock_time, inputs, outputs, fee, expiry, policy_version)| {
                Commitment {
                    wallet_id,
                    version,
                    lock_time,
                    inputs,
                    outputs,
                    fee,
                    expiry,
                    policy_version,
                }
            },
        )
}

/// One field-level edit to a commitment. Named rather than "any two commitments"
/// so a failure says WHICH field stopped being bound.
#[derive(Debug, Clone)]
enum Edit {
    WalletId([u8; 32]),
    Version(i32),
    LockTime(u32),
    Fee(u64),
    Expiry(u64),
    PolicyVersion(u32),
    InputTxid { index: usize, txid: [u8; 32] },
    InputVout { index: usize, vout: u32 },
    InputSequence { index: usize, sequence: u32 },
    OutputScript { index: usize, script: Vec<u8> },
    OutputAmount { index: usize, amount: u64 },
    PushInput(CommitmentInput),
    PushOutput(CommitmentOutput),
    DropInput { index: usize },
    DropOutput { index: usize },
    SwapInputs { a: usize, b: usize },
    SwapOutputs { a: usize, b: usize },
}

fn edit_strategy() -> impl Strategy<Value = Edit> {
    prop_oneof![
        any::<[u8; 32]>().prop_map(Edit::WalletId),
        any::<i32>().prop_map(Edit::Version),
        any::<u32>().prop_map(Edit::LockTime),
        any::<u64>().prop_map(Edit::Fee),
        any::<u64>().prop_map(Edit::Expiry),
        any::<u32>().prop_map(Edit::PolicyVersion),
        (0usize..4, any::<[u8; 32]>()).prop_map(|(index, txid)| Edit::InputTxid { index, txid }),
        (0usize..4, any::<u32>()).prop_map(|(index, vout)| Edit::InputVout { index, vout }),
        (0usize..4, any::<u32>())
            .prop_map(|(index, sequence)| Edit::InputSequence { index, sequence }),
        (0usize..4, proptest::collection::vec(any::<u8>(), 0..40))
            .prop_map(|(index, script)| Edit::OutputScript { index, script }),
        (0usize..4, any::<u64>()).prop_map(|(index, amount)| Edit::OutputAmount { index, amount }),
        commitment_input_strategy().prop_map(Edit::PushInput),
        commitment_output_strategy().prop_map(Edit::PushOutput),
        (0usize..4).prop_map(|index| Edit::DropInput { index }),
        (0usize..4).prop_map(|index| Edit::DropOutput { index }),
        (0usize..4, 0usize..4).prop_map(|(a, b)| Edit::SwapInputs { a, b }),
        (0usize..4, 0usize..4).prop_map(|(a, b)| Edit::SwapOutputs { a, b }),
    ]
}

/// Apply `edit`, or `None` when it is a no-op on this commitment (an index past the
/// end, a "new" value equal to the old one, a swap of an element with itself).
fn apply(commitment: &Commitment, edit: &Edit) -> Option<Commitment> {
    let mut c = commitment.clone();
    match edit {
        Edit::WalletId(id) => set_if_different(&mut c.wallet_id, *id)?,
        Edit::Version(v) => set_if_different(&mut c.version, *v)?,
        Edit::LockTime(v) => set_if_different(&mut c.lock_time, *v)?,
        Edit::Fee(v) => set_if_different(&mut c.fee, *v)?,
        Edit::Expiry(v) => set_if_different(&mut c.expiry, *v)?,
        Edit::PolicyVersion(v) => set_if_different(&mut c.policy_version, *v)?,
        Edit::InputTxid { index, txid } => {
            let i = index.checked_rem(c.inputs.len())?;
            set_if_different(&mut c.inputs[i].txid, *txid)?;
        }
        Edit::InputVout { index, vout } => {
            let i = index.checked_rem(c.inputs.len())?;
            set_if_different(&mut c.inputs[i].vout, *vout)?;
        }
        Edit::InputSequence { index, sequence } => {
            let i = index.checked_rem(c.inputs.len())?;
            set_if_different(&mut c.inputs[i].sequence, *sequence)?;
        }
        Edit::OutputScript { index, script } => {
            let i = index.checked_rem(c.outputs.len())?;
            if c.outputs[i].script_pubkey == *script {
                return None;
            }
            c.outputs[i].script_pubkey = script.clone();
        }
        Edit::OutputAmount { index, amount } => {
            let i = index.checked_rem(c.outputs.len())?;
            set_if_different(&mut c.outputs[i].amount, *amount)?;
        }
        Edit::PushInput(input) => c.inputs.push(input.clone()),
        Edit::PushOutput(output) => c.outputs.push(output.clone()),
        Edit::DropInput { index } => {
            let i = index.checked_rem(c.inputs.len())?;
            c.inputs.remove(i);
        }
        Edit::DropOutput { index } => {
            let i = index.checked_rem(c.outputs.len())?;
            c.outputs.remove(i);
        }
        Edit::SwapInputs { a, b } => {
            let (x, y) = (
                a.checked_rem(c.inputs.len())?,
                b.checked_rem(c.inputs.len())?,
            );
            if c.inputs[x] == c.inputs[y] {
                return None;
            }
            c.inputs.swap(x, y);
        }
        Edit::SwapOutputs { a, b } => {
            let (x, y) = (
                a.checked_rem(c.outputs.len())?,
                b.checked_rem(c.outputs.len())?,
            );
            if c.outputs[x] == c.outputs[y] {
                return None;
            }
            c.outputs.swap(x, y);
        }
    }
    Some(c)
}

fn set_if_different<T: PartialEq>(slot: &mut T, value: T) -> Option<()> {
    if *slot == value {
        return None;
    }
    *slot = value;
    Some(())
}

// --- coordinator-request generators ------------------------------------------

/// An owned [`CoordRequest`] field set; the borrowing enum cannot be generated
/// directly because its variants hold `&'a str`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum OwnedRequest {
    Spend {
        spend_psbt: String,
        escape_psbt: String,
        pin: String,
        nonce: String,
        expiry: u64,
        policy_version: u32,
    },
    Refresh {
        refresh_psbt: String,
        nonce: String,
        expiry: u64,
        policy_version: u32,
    },
}

impl OwnedRequest {
    fn borrow(&self) -> CoordRequest<'_> {
        match self {
            OwnedRequest::Spend {
                spend_psbt,
                escape_psbt,
                pin,
                nonce,
                expiry,
                policy_version,
            } => CoordRequest::Spend {
                spend_psbt,
                escape_psbt,
                pin,
                nonce,
                expiry: *expiry,
                policy_version: *policy_version,
            },
            OwnedRequest::Refresh {
                refresh_psbt,
                nonce,
                expiry,
                policy_version,
            } => CoordRequest::Refresh {
                refresh_psbt,
                nonce,
                expiry: *expiry,
                policy_version: *policy_version,
            },
        }
    }
}

/// Deliberately short, heavily-colliding alphabets. A separator or length-prefix
/// bug shows up as `("ab", "c")` and `("a", "bc")` hashing alike, and that only
/// gets generated when the field values are drawn from a tiny space.
///
/// This covers the node channel too, not just this crate: the channel's envelope
/// preimage builds its variable fields through `Enc::var`, which delegates to
/// [`vault_proto::push_var`] — the same one length-prefix rule these adjacent
/// fields exercise here.
fn field_strategy() -> impl Strategy<Value = String> {
    "[ab]{0,4}"
}

fn owned_request_strategy() -> impl Strategy<Value = OwnedRequest> {
    prop_oneof![
        (
            field_strategy(),
            field_strategy(),
            field_strategy(),
            field_strategy(),
            0u64..4,
            0u32..4,
        )
            .prop_map(
                |(spend_psbt, escape_psbt, pin, nonce, expiry, policy_version)| {
                    OwnedRequest::Spend {
                        spend_psbt,
                        escape_psbt,
                        pin,
                        nonce,
                        expiry,
                        policy_version,
                    }
                }
            ),
        (field_strategy(), field_strategy(), 0u64..4, 0u32..4).prop_map(
            |(refresh_psbt, nonce, expiry, policy_version)| OwnedRequest::Refresh {
                refresh_psbt,
                nonce,
                expiry,
                policy_version,
            }
        ),
    ]
}

fn coord_keypair(seed: u8) -> (SecretKey, SecpPublicKey) {
    let sk = SecretKey::from_slice(&[seed; 32]).expect("32 nonzero bytes");
    (sk, sk.public_key(&Secp256k1::new()))
}

fn coord_sign(request: &CoordRequest, sk: &SecretKey, wallet_id: &[u8; 32]) -> Signature {
    Secp256k1::new().sign_ecdsa(&Message::from_digest(request.auth_digest(wallet_id)), sk)
}

fn coord_verify(
    request: &CoordRequest,
    sig: &Signature,
    pk: &SecpPublicKey,
    wallet_id: &[u8; 32],
) -> bool {
    Secp256k1::new()
        .verify_ecdsa(
            &Message::from_digest(request.auth_digest(wallet_id)),
            sig,
            pk,
        )
        .is_ok()
}

proptest! {
    #![proptest_config(config())]

    /// The commitment id is a FUNCTION of the commitment: built twice from the same
    /// fields it is the same id, and serde round-tripping does not change it.
    #[test]
    fn the_commitment_id_is_a_pure_function_of_the_commitment(c in commitment_strategy()) {
        let twin = c.clone();
        prop_assert_eq!(c.commitment_id(), twin.commitment_id());
        let json = serde_json::to_string(&c).expect("serialize");
        let back: Commitment = serde_json::from_str(&json).expect("deserialize");
        prop_assert_eq!(back.commitment_id(), c.commitment_id());
    }

    /// **Injectivity.** Any single-field edit — including reordering two inputs or
    /// two outputs, which the wire order binds — produces a different id. Without
    /// this a node's registered candidate could cover a transaction it never
    /// evaluated, which is the whole mutation attack.
    #[test]
    fn any_edit_to_a_commitment_changes_its_id(
        c in commitment_strategy(),
        edit in edit_strategy(),
    ) {
        let Some(mutated) = apply(&c, &edit) else {
            return Ok(());
        };
        prop_assert_ne!(&c, &mutated, "the edit must actually change the commitment");
        prop_assert_ne!(
            c.commitment_id(),
            mutated.commitment_id(),
            "{:?} left the commitment id unchanged",
            edit
        );
    }

    /// The stronger, edit-free form: two INDEPENDENTLY generated commitments that
    /// differ at all must have different ids. This is where a length-prefix
    /// ambiguity would surface — a script whose bytes could be re-read as the
    /// amount that follows it, say — because nothing constrains the two values to
    /// be near-neighbours.
    #[test]
    fn distinct_commitments_never_share_an_id(
        a in commitment_strategy(),
        b in commitment_strategy(),
    ) {
        prop_assume!(a != b);
        prop_assert_ne!(a.commitment_id(), b.commitment_id());
    }

    /// The coordinator-auth digest binds EVERY field of the request plus the vault
    /// it was issued for: two requests that differ in any way, or the same request
    /// under two vaults, never share a digest. `Spend` and `Refresh` live in
    /// disjoint digest spaces by construction (the variant tag byte).
    #[test]
    fn distinct_coordinator_requests_never_share_a_digest(
        a in owned_request_strategy(),
        b in owned_request_strategy(),
        wallet_x in any::<[u8; 32]>(),
        wallet_y in any::<[u8; 32]>(),
    ) {
        let (ra, rb) = (a.borrow(), b.borrow());
        if a != b {
            prop_assert_ne!(
                ra.auth_digest(&wallet_x),
                rb.auth_digest(&wallet_x),
                "two different requests shared a digest: {:?} vs {:?}",
                a,
                b
            );
        } else {
            prop_assert_eq!(ra.auth_digest(&wallet_x), rb.auth_digest(&wallet_x));
        }
        if wallet_x != wallet_y {
            prop_assert_ne!(
                ra.auth_digest(&wallet_x),
                ra.auth_digest(&wallet_y),
                "the wallet_id domain separator did not separate"
            );
        }
    }

    /// The signature consequence of the digest property: a coordinator signature
    /// issued for one request never authenticates a different one, and never
    /// authenticates the same request at a different vault. This is the binding a
    /// relaying peer would have to break to substitute a transaction.
    #[test]
    fn a_coordinator_signature_never_transfers_to_a_different_request(
        original in owned_request_strategy(),
        other in owned_request_strategy(),
        wallet_x in any::<[u8; 32]>(),
        wallet_y in any::<[u8; 32]>(),
    ) {
        let (sk, pk) = coord_keypair(0xC0);
        let signed = original.borrow();
        let sig = coord_sign(&signed, &sk, &wallet_x);
        prop_assert!(
            coord_verify(&signed, &sig, &pk, &wallet_x),
            "the signing key must verify its own request"
        );
        if other != original {
            prop_assert!(
                !coord_verify(&other.borrow(), &sig, &pk, &wallet_x),
                "a signature for {:?} authenticated {:?}",
                original,
                other
            );
        }
        if wallet_y != wallet_x {
            prop_assert!(
                !coord_verify(&signed, &sig, &pk, &wallet_y),
                "a signature bound to one vault authenticated another"
            );
        }
    }

    /// The wire DTOs hand `CoordRequest` exactly the bytes they carry: whatever a
    /// node reads off the wire is what gets authenticated. A rename or a reordered
    /// field in either DTO would break this without breaking any round-trip test.
    #[test]
    fn the_wire_dtos_authenticate_the_fields_they_carry(
        psbt in field_strategy(),
        escape in field_strategy(),
        pin in field_strategy(),
        nonce in field_strategy(),
        expiry in any::<u64>(),
        policy_version in any::<u32>(),
        wallet_id in any::<[u8; 32]>(),
    ) {
        let request = SignRequest {
            psbt: psbt.clone(),
            escape_psbt: escape.clone(),
            pin: pin.as_str().into(),
            nonce: nonce.clone(),
            expiry,
            policy_version,
            coord_sig: "ignored: never part of its own preimage".into(),
        };
        let expected = CoordRequest::Spend {
            spend_psbt: &psbt,
            escape_psbt: &escape,
            pin: &pin,
            nonce: &nonce,
            expiry,
            policy_version,
        };
        prop_assert_eq!(
            request.coord_request().auth_digest(&wallet_id),
            expected.auth_digest(&wallet_id)
        );
        // The gate reads the nonce and expiry back out of the signed value, so
        // they can never be checked on data the signature did not cover.
        prop_assert_eq!(request.coord_request().nonce(), nonce.as_str());
        prop_assert_eq!(request.coord_request().expiry(), expiry);

        let refresh = RefreshRequest {
            refresh_psbt: psbt.clone(),
            nonce: nonce.clone(),
            expiry,
            policy_version,
            coord_sig: String::new(),
        };
        let expected_refresh = CoordRequest::Refresh {
            refresh_psbt: &psbt,
            nonce: &nonce,
            expiry,
            policy_version,
        };
        prop_assert_eq!(
            refresh.coord_request().auth_digest(&wallet_id),
            expected_refresh.auth_digest(&wallet_id)
        );
        // A spend and a refresh over the same PSBT string are different requests.
        prop_assert_ne!(
            request.coord_request().auth_digest(&wallet_id),
            refresh.coord_request().auth_digest(&wallet_id)
        );
    }
}
