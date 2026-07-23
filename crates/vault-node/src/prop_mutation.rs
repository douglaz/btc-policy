//! V0-7: DESIGN.md T3's PSBT-mutation property, driven through the real node.
//!
//! The invariant, stated once: **no mutated transaction passes an authorization
//! bound to the original.** A user-signed spend and its paired escape carry two
//! authorizations — the user's signature over the exact transaction, and the
//! coordinator's signature over the exact request bytes — and this suite generates
//! structural mutations (reorder / insert / drop an input or an output, change an
//! output value or scriptPubKey, `nSequence`, `nLockTime`, `nVersion`, a prevout,
//! or the witness bytes) and asserts that neither authorization transfers:
//!
//!  1. any consensus-relevant mutation changes the `commitment_id`, so the
//!     candidate a node registered for the original does not cover the mutant;
//!  2. submitting a mutant under the ORIGINAL request's `coord_sig` is
//!     `COORD_AUTH_INVALID` — including a witness-only mutation, which the
//!     commitment deliberately does not bind but the coord-auth preimage does;
//!  3. a mutant the coordinator re-signs — everything a post-wrench coordinator
//!     can do, since it holds that key and not the user's — is still REFUSED,
//!     because the user's signature no longer covers the transaction.
//!
//! `policy-core` evaluation is covered from both ends: the mutants that redirect
//! value to a script the vault cannot re-derive are refused by the allowlist here,
//! and `crates/policy-core/tests/prop_refusal_core.rs` runs the same class of
//! property over arbitrary output sets.
//!
//! Counterexamples persist to `crates/vault-node/src/proptest-regressions/` and
//! are committed, so anything this suite finds is replayed first on every run.

use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};

use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, OutPoint, Psbt, ScriptBuf, Sequence, TxIn, TxOut, Txid, WScriptHash, Witness,
};
use proptest::prelude::*;
use vault_proto::{RefusalCode, SignRequest, SignResponse};

use crate::prop_decoder::config;
use crate::test_support::{coord_sign, node_and_valid_multi_request};
use crate::{commitment_id_for, handle_sign, Node};

/// Where this file's counterexamples persist; `config` explains why the path is
/// spelled out rather than left to proptest's default.
const REGRESSIONS: &str = "src/proptest-regressions/prop_mutation.txt";

/// Which of the request's two transactions a case mutates. Both are user-signed
/// and both are coord-signed, so the invariant must hold for the mandatory escape
/// exactly as it does for the spend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Target {
    Spend,
    Escape,
}

/// One structural edit to a PSBT. Every variant is a mutation a hostile
/// coordinator or peer could attempt on bytes it is relaying.
#[derive(Debug, Clone, Copy)]
enum Mutation {
    /// Move value: pay the destination more or less.
    OutputValue { index: usize, delta: i64 },
    /// Redirect an output to a scriptPubKey no configured descriptor produces.
    OutputScript { index: usize, tag: u8 },
    /// Add a whole output (to the attacker's own script).
    InsertOutput { at: usize, tag: u8, sats: u64 },
    /// Remove an output.
    DropOutput { index: usize },
    /// Reorder two outputs without changing their contents.
    SwapOutputs { a: usize, b: usize },
    /// Add a whole input, carrying a copy of input 0's PSBT map.
    InsertInput { at: usize, tag: u8 },
    /// Remove an input.
    DropInput { index: usize },
    /// Reorder two inputs and their corresponding PSBT maps.
    SwapInputs { a: usize, b: usize },
    /// Flip bits in one input's `nSequence` (RBF / relative-timelock signalling).
    Sequence { index: usize, flip: u32 },
    /// Change `nLockTime`.
    LockTime { value: u32 },
    /// Change `nVersion`.
    Version { delta: i32 },
    /// Re-point an input at a different previous transaction.
    PrevoutTxid { index: usize, tag: u8 },
    /// Re-point an input at a different output of the same transaction.
    PrevoutVout { index: usize, vout: u32 },
    /// Lie about a prevout's value — the PSBT metadata v0 takes on trust for the
    /// fee, and the amount BIP143 commits to.
    PrevoutValue { index: usize, delta: i64 },
    /// Witness bytes only: a final script witness spliced onto an input. The
    /// unsigned transaction is untouched, so this is deliberately NOT
    /// consensus-relevant — it changes the PSBT's SERIALIZATION and nothing the
    /// commitment binds.
    WitnessBytes { index: usize, tag: u8, len: usize },
}

impl Mutation {
    /// Whether this mutation touches a field the [`vault_proto::Commitment`]
    /// binds — i.e. whether it produces a genuinely different transaction.
    ///
    /// Only [`Mutation::WitnessBytes`] does not: the commitment binds the exact
    /// UNSIGNED transaction (version, locktime, every outpoint + `nSequence`,
    /// every output, and the fee), and segwit witness data is by construction not
    /// part of it. That is correct, not a gap — the request's exact bytes are
    /// bound by the coordinator signature and by the node's acceptance replay key,
    /// which is what property 2 below pins down.
    fn changes_the_transaction(self) -> bool {
        !matches!(self, Mutation::WitnessBytes { .. })
    }

    /// The mutations policy is BLIND to but the user's `SIGHASH_ALL` signature is NOT.
    /// Each of these changes the signed transaction while leaving EVERY policy predicate
    /// (class / destination / amount / coverage) reading exactly the same thing, so a
    /// re-coordinator-signed mutant re-clears coord-auth + freshness AND passes policy
    /// unchanged — the ONLY thing left to refuse it is that the user signature no longer
    /// covers the transaction. That makes this the subset where "the user signature does
    /// not transfer" has EXACT teeth: the refusal must be `USER_SIG_INVALID`, not merely
    /// "refused somewhere".
    ///
    /// - `nSequence`/`nLockTime`/`nVersion`: in the sighash, in no policy predicate.
    /// - `SwapInputs`/`SwapOutputs`: policy scans are ORDER-INSENSITIVE (it checks the
    ///   set of inputs/outputs, not their order), so a reorder is invisible to it.
    /// - `PrevoutTxid`/`PrevoutVout`: input ownership/coverage reads `witness_utxo`, not
    ///   the outpoint, so re-pointing an input at a different prevout (same value/script)
    ///   is invisible to policy.
    ///
    /// EXCLUDED (policy-RELEVANT, may legitimately refuse for a non-user-sig reason):
    /// Insert/Drop of an output or input (changes the set policy classifies/covers),
    /// `OutputValue`/`OutputScript`/`InsertOutput` (amount/destination), `PrevoutValue`
    /// (the value policy reads for coverage). `WitnessBytes` never reaches here — it
    /// leaves the unsigned tx untouched and is skipped by `changes_the_transaction`.
    ///
    /// (v0-exit review 2026-07-23: codex found the broad `!= CoordAuthInvalid` assertion
    /// too loose; Fable identified the policy-blind subset as where it is precise; codex
    /// then caught that the subset must also include the order/outpoint mutations. The
    /// property empirically confirms every member of this set is refused USER_SIG_INVALID.)
    fn is_policy_blind(self) -> bool {
        matches!(
            self,
            Mutation::Sequence { .. }
                | Mutation::LockTime { .. }
                | Mutation::Version { .. }
                | Mutation::SwapInputs { .. }
                | Mutation::SwapOutputs { .. }
                | Mutation::PrevoutTxid { .. }
                | Mutation::PrevoutVout { .. }
        )
    }
}

/// A scriptPubKey no descriptor this vault configures can re-derive.
fn stranger_spk(tag: u8) -> ScriptBuf {
    ScriptBuf::new_p2wsh(&WScriptHash::from_byte_array([tag; 32]))
}

/// Apply `mutation`, or `None` when it would be a no-op on this PSBT (a delta that
/// clamps back onto the original value, a "different" txid that is the same one).
/// A no-op is not a mutation, so the properties skip it rather than assert a
/// difference that was never made.
fn apply(psbt: &Psbt, mutation: Mutation) -> Option<Psbt> {
    let mut m = psbt.clone();
    match mutation {
        Mutation::OutputValue { index, delta } => {
            let i = index.checked_rem(m.unsigned_tx.output.len())?;
            let old = m.unsigned_tx.output[i].value.to_sat();
            // Clamped well inside 21e14 sat so the amount stays constructible.
            let new = old.saturating_add_signed(delta).min(1_000_000_000_000);
            if new == old {
                return None;
            }
            m.unsigned_tx.output[i].value = Amount::from_sat(new);
        }
        Mutation::OutputScript { index, tag } => {
            let i = index.checked_rem(m.unsigned_tx.output.len())?;
            let spk = stranger_spk(tag);
            if m.unsigned_tx.output[i].script_pubkey == spk {
                return None;
            }
            m.unsigned_tx.output[i].script_pubkey = spk;
        }
        Mutation::InsertOutput { at, tag, sats } => {
            let i = at % (m.unsigned_tx.output.len() + 1);
            m.unsigned_tx.output.insert(
                i,
                TxOut {
                    script_pubkey: stranger_spk(tag),
                    value: Amount::from_sat(sats),
                },
            );
            m.outputs.insert(i, bitcoin::psbt::Output::default());
        }
        Mutation::DropOutput { index } => {
            let i = index.checked_rem(m.unsigned_tx.output.len())?;
            m.unsigned_tx.output.remove(i);
            m.outputs.remove(i);
        }
        Mutation::SwapOutputs { a, b } => {
            let a = a.checked_rem(m.unsigned_tx.output.len())?;
            let b = b.checked_rem(m.unsigned_tx.output.len())?;
            if a == b || m.unsigned_tx.output[a] == m.unsigned_tx.output[b] {
                return None;
            }
            m.unsigned_tx.output.swap(a, b);
            m.outputs.swap(a, b);
        }
        Mutation::InsertInput { at, tag } => {
            let i = at % (m.unsigned_tx.input.len() + 1);
            m.unsigned_tx.input.insert(
                i,
                TxIn {
                    previous_output: OutPoint::new(Txid::from_byte_array([tag; 32]), 0),
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                },
            );
            // Carry a copy of input 0's map so the inserted input is structurally
            // complete (it has a `witness_utxo`): the mutation under test is the
            // extra INPUT, not a missing PSBT field.
            let template = m.inputs.first().cloned().unwrap_or_default();
            m.inputs.insert(i, template);
        }
        Mutation::DropInput { index } => {
            let i = index.checked_rem(m.unsigned_tx.input.len())?;
            m.unsigned_tx.input.remove(i);
            m.inputs.remove(i);
        }
        Mutation::SwapInputs { a, b } => {
            let a = a.checked_rem(m.unsigned_tx.input.len())?;
            let b = b.checked_rem(m.unsigned_tx.input.len())?;
            if a == b || m.unsigned_tx.input[a] == m.unsigned_tx.input[b] {
                return None;
            }
            m.unsigned_tx.input.swap(a, b);
            m.inputs.swap(a, b);
        }
        Mutation::Sequence { index, flip } => {
            let i = index.checked_rem(m.unsigned_tx.input.len())?;
            if flip == 0 {
                return None;
            }
            let old = m.unsigned_tx.input[i].sequence.to_consensus_u32();
            m.unsigned_tx.input[i].sequence = Sequence::from_consensus(old ^ flip);
        }
        Mutation::LockTime { value } => {
            let new = LockTime::from_consensus(value);
            if new == m.unsigned_tx.lock_time {
                return None;
            }
            m.unsigned_tx.lock_time = new;
        }
        Mutation::Version { delta } => {
            if delta == 0 {
                return None;
            }
            m.unsigned_tx.version = Version(m.unsigned_tx.version.0.wrapping_add(delta));
        }
        Mutation::PrevoutTxid { index, tag } => {
            let i = index.checked_rem(m.unsigned_tx.input.len())?;
            let txid = Txid::from_byte_array([tag; 32]);
            if m.unsigned_tx.input[i].previous_output.txid == txid {
                return None;
            }
            m.unsigned_tx.input[i].previous_output.txid = txid;
        }
        Mutation::PrevoutVout { index, vout } => {
            let i = index.checked_rem(m.unsigned_tx.input.len())?;
            if m.unsigned_tx.input[i].previous_output.vout == vout {
                return None;
            }
            m.unsigned_tx.input[i].previous_output.vout = vout;
        }
        Mutation::PrevoutValue { index, delta } => {
            let i = index.checked_rem(m.inputs.len())?;
            let utxo = m.inputs[i].witness_utxo.as_ref()?;
            let old = utxo.value.to_sat();
            let new = old.saturating_add_signed(delta).min(1_000_000_000_000);
            if new == old {
                return None;
            }
            let script_pubkey = utxo.script_pubkey.clone();
            m.inputs[i].witness_utxo = Some(TxOut {
                script_pubkey,
                value: Amount::from_sat(new),
            });
        }
        Mutation::WitnessBytes { index, tag, len } => {
            let i = index.checked_rem(m.inputs.len())?;
            let witness = Witness::from_slice(&[vec![tag; len.max(1)]]);
            if m.inputs[i].final_script_witness.as_ref() == Some(&witness) {
                return None;
            }
            m.inputs[i].final_script_witness = Some(witness);
        }
    }
    Some(m)
}

fn nonzero_i64() -> impl Strategy<Value = i64> {
    prop_oneof![-5_000_000i64..=-1, 1i64..=5_000_000]
}

fn mutation_strategy() -> impl Strategy<Value = Mutation> {
    prop_oneof![
        (0usize..4, nonzero_i64())
            .prop_map(|(index, delta)| Mutation::OutputValue { index, delta }),
        (0usize..4, 1u8..=255).prop_map(|(index, tag)| Mutation::OutputScript { index, tag }),
        (0usize..4, 1u8..=255, 0u64..=50_000_000)
            .prop_map(|(at, tag, sats)| Mutation::InsertOutput { at, tag, sats }),
        (0usize..4).prop_map(|index| Mutation::DropOutput { index }),
        (0usize..4, 0usize..4).prop_map(|(a, b)| Mutation::SwapOutputs { a, b }),
        (0usize..4, 1u8..=255).prop_map(|(at, tag)| Mutation::InsertInput { at, tag }),
        (0usize..4).prop_map(|index| Mutation::DropInput { index }),
        (0usize..4, 0usize..4).prop_map(|(a, b)| Mutation::SwapInputs { a, b }),
        (0usize..4, 1u32..=u32::MAX).prop_map(|(index, flip)| Mutation::Sequence { index, flip }),
        (0u32..=800_000).prop_map(|value| Mutation::LockTime { value }),
        prop_oneof![-4i32..=-1, 1i32..=4].prop_map(|delta| Mutation::Version { delta }),
        (0usize..4, 1u8..=255).prop_map(|(index, tag)| Mutation::PrevoutTxid { index, tag }),
        (0usize..4, 1u32..=16).prop_map(|(index, vout)| Mutation::PrevoutVout { index, vout }),
        (0usize..4, nonzero_i64())
            .prop_map(|(index, delta)| Mutation::PrevoutValue { index, delta }),
        (0usize..4, 1u8..=255, 1usize..=64).prop_map(|(index, tag, len)| Mutation::WitnessBytes {
            index,
            tag,
            len
        }),
    ]
}

fn target_strategy() -> impl Strategy<Value = Target> {
    prop_oneof![Just(Target::Spend), Just(Target::Escape)]
}

/// The request's PSBT for `target`, parsed.
fn psbt_of(request: &SignRequest, target: Target) -> Psbt {
    let base64 = match target {
        Target::Spend => &request.psbt,
        Target::Escape => &request.escape_psbt,
    };
    Psbt::from_str(base64).expect("the fixture request carries two valid PSBTs")
}

/// `request` with `target`'s PSBT replaced by `psbt`, and NOTHING else changed —
/// in particular the coordinator signature is left exactly as it was, which is the
/// whole point of property 2.
fn with_psbt(request: &SignRequest, target: Target, psbt: &Psbt) -> SignRequest {
    let mut mutated = request.clone();
    match target {
        Target::Spend => mutated.psbt = psbt.to_string(),
        Target::Escape => mutated.escape_psbt = psbt.to_string(),
    }
    mutated
}

/// A fresh coordinator nonce per submission. A coordinator nonce is single-use, so
/// the properties that DO re-sign need a new one for every case.
fn fresh_nonce() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    format!("v07-mutation-{}", COUNTER.fetch_add(1, Ordering::Relaxed))
}

/// The clock the properties submit against: the fixture request's expiry is set
/// one hour ahead of the real clock, so `now` has to be the real clock too.
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Submit `request` and assert the node did not accept it; return the refusal for
/// the caller to inspect.
fn refusal_of(node: &Node, request: &SignRequest) -> Result<vault_proto::Refusal, TestCaseError> {
    match handle_sign(node, request, now()) {
        Ok(SignResponse::Refusal(refusal)) => Ok(refusal),
        Ok(SignResponse::Accepted(accepted)) => Err(TestCaseError::fail(format!(
            "the node ACCEPTED a mutated transaction: {accepted:?}"
        ))),
        // A `BadRequest` is the wire-level 400 (an undecodable or over-sized body);
        // it is still a non-acceptance, but the properties below all expect a
        // structured policy outcome, so surface anything else as a failure.
        Err(bad) => Err(TestCaseError::fail(format!(
            "expected a structured refusal, got a 400: {bad:?}"
        ))),
    }
}

/// The original request, submitted once and accepted — the positive control every
/// property below is stated against ("a node that ACCEPTED the original ...").
fn accepted_baseline() -> (Node, SignRequest) {
    let (node, request) = node_and_valid_multi_request();
    match handle_sign(&node, &request, now()) {
        Ok(SignResponse::Accepted(_)) => {}
        other => panic!("the fixture request must be accepted as the baseline: {other:?}"),
    }
    (node, request)
}

#[test]
fn a_consensus_mutation_always_changes_the_commitment_id() {
    let (node, original) = accepted_baseline();
    let expiry = original.expiry;
    proptest!(config(REGRESSIONS), |(target in target_strategy(), mutation in mutation_strategy())| {
        let base = psbt_of(&original, target);
        let Some(mutant) = apply(&base, mutation) else {
            return Ok(());
        };
        let base_id = commitment_id_for(&node, &base, expiry);
        let mutant_id = commitment_id_for(&node, &mutant, expiry);
        if mutation.changes_the_transaction() {
            prop_assert_ne!(
                &base_id,
                &mutant_id,
                "{:?} on the {:?} left the commitment id unchanged, so an \
                 authorization bound to the original would still cover it",
                mutation,
                target
            );
        } else {
            // Witness data is not part of the transaction the commitment binds.
            // Stated as an assertion rather than left implicit: if this ever
            // starts differing, the commitment has silently started binding
            // witness bytes, and the anti-replay log's "the log does not defend
            // the signature" reasoning would need revisiting.
            prop_assert_eq!(
                &base_id,
                &mutant_id,
                "the commitment binds the unsigned transaction, not the witness"
            );
        }
    });
}

#[test]
fn no_mutant_is_covered_by_the_originals_coordinator_authorization() {
    let (node, original) = accepted_baseline();
    proptest!(config(REGRESSIONS), |(target in target_strategy(), mutation in mutation_strategy())| {
        let base = psbt_of(&original, target);
        let Some(mutant) = apply(&base, mutation) else {
            return Ok(());
        };
        // The mutant carried on the ORIGINAL request: same pin, same nonce, same
        // expiry, same `coord_sig`. Everything a relaying peer or a coordinator
        // replaying a captured request can assemble without the coordinator key.
        let forged = with_psbt(&original, target, &mutant);
        let refusal = refusal_of(&node, &forged)?;
        prop_assert_eq!(
            refusal.code,
            RefusalCode::CoordAuthInvalid,
            "{:?} on the {:?} was not caught by the coordinator binding: {:?}",
            mutation,
            target,
            refusal
        );
        // The coord-auth preimage binds the PSBTs as their exact base64, so even
        // the witness-only mutation — which the commitment deliberately does not
        // bind — fails here. Neither authorization transfers.
    });
}

#[test]
fn a_recoordinator_signed_mutant_is_still_refused_because_the_user_never_signed_it() {
    let (node, original) = accepted_baseline();
    proptest!(config(REGRESSIONS), |(target in target_strategy(), mutation in mutation_strategy())| {
        // Witness-only mutations leave the transaction — and therefore the user's
        // signature over it — intact, so they are not this property's subject.
        prop_assume!(mutation.changes_the_transaction());
        let base = psbt_of(&original, target);
        let Some(mutant) = apply(&base, mutation) else {
            return Ok(());
        };
        // The post-wrench coordinator's FULL power: it holds the coordinator auth
        // key, so it re-signs the mutated request over a fresh nonce. It does not
        // hold the user key, and cannot forge the one signature that binds the
        // transaction.
        let mut reissued = with_psbt(&original, target, &mutant);
        coord_sign(&mut reissued, &node.wallet_id, &fresh_nonce());
        let refusal = refusal_of(&node, &reissued)?;
        prop_assert_ne!(
            refusal.code,
            RefusalCode::CoordAuthInvalid,
            "the re-issued request must clear coord-auth, or this property is \
             testing the previous one over again"
        );
        if mutation.is_policy_blind() {
            // Policy is blind to this mutation and the request re-cleared coord-auth +
            // freshness, so the only thing left to catch the mutant is that the user
            // signature no longer covers the mutated transaction. Any code other than
            // USER_SIG_INVALID here would mean an incidental gate was masking a broken
            // user-signature binding (v0-exit review 2026-07-23).
            prop_assert_eq!(
                refusal.code,
                RefusalCode::UserSigInvalid,
                "a policy-blind mutant {:?} must be refused because the user signature \
                 does not transfer, not for an incidental reason: {:?}",
                mutation,
                refusal
            );
        }
        if target == Target::Escape {
            prop_assert!(
                refusal.check.starts_with("escape:"),
                "a refusal derived from the mandatory escape must name it: {:?}",
                refusal
            );
        }
    });
}

#[test]
fn a_mutant_that_redirects_value_off_the_allowlist_is_refused_by_policy_core() {
    let (node, original) = accepted_baseline();
    let redirect = prop_oneof![
        (0usize..4, 1u8..=255).prop_map(|(index, tag)| Mutation::OutputScript { index, tag }),
        (0usize..4, 1u8..=255, 1u64..=50_000_000)
            .prop_map(|(at, tag, sats)| Mutation::InsertOutput { at, tag, sats }),
    ];
    proptest!(config(REGRESSIONS), |(target in target_strategy(), mutation in redirect)| {
        let base = psbt_of(&original, target);
        let Some(mutant) = apply(&base, mutation) else {
            return Ok(());
        };
        // Straight at policy-core, with the node's own configured parameters: an
        // output paying a script no configured descriptor re-derives is refused by
        // the destination allowlist, whatever else the transaction does.
        let violation = policy_core::evaluate(&mutant, &node.check_params)
            .expect_err("a payment to an unknown script must be refused");
        prop_assert_eq!(
            violation.code,
            policy_core::ViolationCode::DestNotAllowed,
            "{:?} produced {:?}",
            mutation,
            violation
        );
    });
}
