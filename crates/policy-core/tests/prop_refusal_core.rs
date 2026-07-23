//! V0-7: property-based invariants for the pure refusal core (DESIGN.md T3).
//!
//! The unit tests beside `lib.rs` pin the cases someone thought to write. This
//! suite answers the different question — "the input you didn't think to test" —
//! by generating arbitrary output sets against a FIXED vault / escape / hot
//! descriptor set and checking the refusal core against a complete oracle: for
//! every generated spend, an independent re-derivation of what
//! [`policy_core::evaluate`], [`policy_core::classify`], and
//! [`policy_core::hot_outflow`] must answer, computed from the generator's own
//! ground truth rather than from the code under test.
//!
//! Determinism: proptest's default failure persistence writes any counterexample
//! it finds to `crates/policy-core/tests/proptest-regressions/`, and that file is
//! committed, so a found counterexample is replayed first on every later run.
//! `PROPTEST_CASES` still tunes the exploratory budget on top of it.

use std::str::FromStr;
use std::sync::LazyLock;

use bitcoin::absolute::LockTime;
use bitcoin::bip32::{DerivationPath, Fingerprint, Xpriv, Xpub};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{PublicKey, Secp256k1};
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, NetworkKind, OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    WScriptHash, Witness,
};
use miniscript::{Descriptor, DescriptorPublicKey};
use policy_core::{classify, evaluate, hot_outflow, CheckParams, TxClass, ViolationCode};
use proptest::prelude::*;
use proptest::test_runner::FileFailurePersistence;

/// Counterexamples are persisted BESIDE this file, at a path stated explicitly
/// rather than left to proptest's default: the default (`SourceParallel`) walks up
/// looking for a `lib.rs`/`main.rs`, which an integration test under `tests/` does
/// not have — it prints "failed to find lib.rs or main.rs" and silently persists
/// nothing. `Direct` is resolved against the package root (cargo's CWD for tests),
/// so the file lands in `crates/policy-core/tests/proptest-regressions/` and is
/// committed: a counterexample this suite ever finds is replayed first, forever.
fn config() -> ProptestConfig {
    ProptestConfig {
        failure_persistence: Some(Box::new(FileFailurePersistence::Direct(
            "tests/proptest-regressions/prop_refusal_core.txt",
        ))),
        ..ProptestConfig::default()
    }
}

/// The derivation bound every generated case runs under. Small on purpose:
/// `derives_within` scans `0..=max` per descriptor per output, so the bound is
/// the suite's inner loop. What the properties test is the BOUNDARY, and a
/// boundary at 4 is the same boundary as one at 10_000.
const MAX_INDEX: u32 = 4;

/// The one vault input every generated spend consumes.
const TOTAL_IN: u64 = 1_000_000;

/// The fixed descriptor set the whole suite generates against: the node's own
/// vault, the hot wallet, and the escape wallet. Built once — parsing a
/// descriptor per generated case would dominate the runtime.
struct Wallets {
    vault: Descriptor<DescriptorPublicKey>,
    hot: Descriptor<DescriptorPublicKey>,
    escape: Descriptor<DescriptorPublicKey>,
}

static WALLETS: LazyLock<Wallets> = LazyLock::new(|| Wallets {
    // A RANGED vault (`wsh(multi(2, …/*, …/*))`), not the definite first-light
    // one: the derivation bound is only observable on a wildcard descriptor, and
    // "an input past `max_derivation_index` is refused" is one of the invariants
    // under test.
    vault: Descriptor::from_str(&format!("wsh(multi(2,{}/*,{}/*))", xpub(1), xpub(2)))
        .expect("valid ranged vault descriptor"),
    hot: Descriptor::from_str(&format!("wpkh({}/*)", xpub(0xA0))).expect("valid hot descriptor"),
    escape: Descriptor::from_str(&format!("wpkh({}/*)", xpub(0xB0)))
        .expect("valid escape descriptor"),
});

/// A deterministic xpub from a fixed seed byte.
fn xpub(seed: u8) -> Xpub {
    let secp = Secp256k1::new();
    let xpriv = Xpriv::new_master(NetworkKind::Test, &[seed; 32]).expect("master key");
    Xpub::from_priv(&secp, &xpriv)
}

/// The scriptPubKey `descriptor` produces at `index`.
fn spk_at(descriptor: &Descriptor<DescriptorPublicKey>, index: u32) -> ScriptBuf {
    descriptor
        .derived_descriptor(&Secp256k1::verification_only(), index)
        .expect("derivable")
        .script_pubkey()
}

/// The node's `CheckParams` at a given per-transaction Hot cap. The escape
/// descriptor is BOTH an `allowed` entry and the named `escape` — exactly how a
/// node configures it, and what lets `classify` tell a sweep from a hot payment.
fn params(hot_max_per_tx: u64) -> CheckParams {
    CheckParams {
        vault: WALLETS.vault.clone(),
        allowed: vec![WALLETS.hot.clone(), WALLETS.escape.clone()],
        escape: Some(WALLETS.escape.clone()),
        max_derivation_index: MAX_INDEX,
        hot_max_per_tx: Amount::from_sat(hot_max_per_tx),
    }
}

/// Where one generated output pays. The generator knows this; the code under
/// test must re-derive it from the scriptPubKey alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dest {
    /// Vault change, within the bound.
    Vault(u32),
    /// The hot wallet, within the bound.
    Hot(u32),
    /// The escape wallet, within the bound.
    Escape(u32),
    /// The hot wallet PAST `max_derivation_index` — a real hot address the node
    /// must nonetheless not recognize.
    HotPastBound(u32),
    /// A scriptPubKey no configured descriptor produces: the attacker's own.
    Stranger(u8),
}

/// The three buckets the refusal core sorts an output into, plus "recognized by
/// nothing". This is the ORACLE — computed from the generator's intent, never by
/// calling the code under test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Bucket {
    Vault,
    Escape,
    Hot,
    Unrecognized,
}

impl Dest {
    fn bucket(self) -> Bucket {
        match self {
            Dest::Vault(_) => Bucket::Vault,
            Dest::Escape(_) => Bucket::Escape,
            Dest::Hot(_) => Bucket::Hot,
            Dest::HotPastBound(_) | Dest::Stranger(_) => Bucket::Unrecognized,
        }
    }

    fn spk(self) -> ScriptBuf {
        match self {
            Dest::Vault(i) => spk_at(&WALLETS.vault, i),
            Dest::Hot(i) | Dest::HotPastBound(i) => spk_at(&WALLETS.hot, i),
            Dest::Escape(i) => spk_at(&WALLETS.escape, i),
            // A P2WSH of a raw 32-byte hash. No descriptor in the set can produce
            // it (the vault's own P2WSH hashes a real witness script), so it is
            // the attacker-controlled destination in its purest form.
            Dest::Stranger(tag) => ScriptBuf::new_p2wsh(&WScriptHash::from_byte_array([tag; 32])),
        }
    }
}

fn dest_strategy() -> impl Strategy<Value = Dest> {
    prop_oneof![
        3 => (0u32..=MAX_INDEX).prop_map(Dest::Vault),
        3 => (0u32..=MAX_INDEX).prop_map(Dest::Hot),
        3 => (0u32..=MAX_INDEX).prop_map(Dest::Escape),
        1 => (MAX_INDEX + 1..=MAX_INDEX + 4).prop_map(Dest::HotPastBound),
        1 => (1u8..=255).prop_map(Dest::Stranger),
    ]
}

/// The subset of [`dest_strategy`] every configured descriptor recognizes. Used
/// by the properties whose subject is a spend the ALLOWLIST already admits — the
/// class predicate and the Hot cap — so those cases are constructed rather than
/// filtered (filtering for "hot and escape and nothing unrecognized" rejects the
/// overwhelming majority of draws and starves the run).
fn allowlisted_dest_strategy() -> impl Strategy<Value = Dest> {
    prop_oneof![
        (0u32..=MAX_INDEX).prop_map(Dest::Vault),
        (0u32..=MAX_INDEX).prop_map(Dest::Hot),
        (0u32..=MAX_INDEX).prop_map(Dest::Escape),
    ]
}

/// One generated output: where it pays, its share of the spendable value, and
/// whether the PSBT *labels* it as change (an untrusted bip32 hint that only
/// decides WHICH refusal a non-derivable output earns).
#[derive(Debug, Clone, Copy)]
struct OutSpec {
    dest: Dest,
    weight: u64,
    labeled_change: bool,
}

fn out_spec_strategy(dest: impl Strategy<Value = Dest>) -> impl Strategy<Value = OutSpec> {
    (dest, 0u64..=1000, any::<bool>()).prop_map(|(dest, weight, labeled_change)| OutSpec {
        dest,
        weight,
        labeled_change,
    })
}

/// One whole generated spend: the outputs, the fee as permille of the single
/// input, an optional overspend (outputs exceeding inputs), and how the per-tx
/// Hot cap is chosen.
///
/// Amounts are generated as WEIGHTS and then scaled to `TOTAL_IN − fee`, rather
/// than drawn independently: independent draws would land almost every case
/// outside the 10% fee cap, and the interesting branches (accepted, over the Hot
/// cap, exactly at a boundary) would essentially never be reached.
#[derive(Debug, Clone)]
struct Case {
    outputs: Vec<OutSpec>,
    fee_permille: u64,
    overspend: u64,
    cap: Cap,
}

/// How a case picks its per-transaction Hot cap.
///
/// A cap drawn only as a fraction of the input essentially never lands ON the
/// spend's own outflow, so the boundary the check actually turns on — "exactly at
/// the cap passes" — would go untested no matter how many cases ran. Naming the
/// boundary as a generator choice puts it in the sample.
#[derive(Debug, Clone, Copy)]
enum Cap {
    /// Drawn as permille of the input, independent of what the spend moves.
    Permille(u64),
    /// Exactly this spend's hot outflow: must PASS.
    AtOutflow,
    /// One satoshi under it: must REFUSE.
    JustUnderOutflow,
    /// One satoshi over it: must pass.
    JustOverOutflow,
}

fn case_strategy() -> impl Strategy<Value = Case> {
    case_strategy_over(dest_strategy(), 1)
}

/// [`case_strategy`] restricted to destinations the allowlist recognizes, with a
/// floor on the output count.
fn case_strategy_over(
    dest: impl Strategy<Value = Dest>,
    min_outputs: usize,
) -> impl Strategy<Value = Case> {
    (
        prop::collection::vec(out_spec_strategy(dest), min_outputs..=4),
        // 0–20% fee: straddles the 10% cap in both directions.
        0u64..=200,
        // Usually balanced; sometimes outputs exceed inputs outright.
        prop_oneof![9 => Just(0u64), 1 => 1u64..=200_000],
        prop_oneof![
            3 => (0u64..=1000).prop_map(Cap::Permille),
            1 => Just(Cap::AtOutflow),
            1 => Just(Cap::JustUnderOutflow),
            1 => Just(Cap::JustOverOutflow),
        ],
    )
        .prop_map(|(outputs, fee_permille, overspend, cap)| Case {
            outputs,
            fee_permille,
            overspend,
            cap,
        })
}

/// The destinations no configured descriptor re-derives: a real hot address past
/// the bound, and a script the attacker chose outright.
fn unrecognized_dest_strategy() -> impl Strategy<Value = Dest> {
    prop_oneof![
        (MAX_INDEX + 1..=MAX_INDEX + 4).prop_map(Dest::HotPastBound),
        (1u8..=255).prop_map(Dest::Stranger),
    ]
}

/// Every destination an attacker controls the value of — anything that pays
/// neither the vault nor the escape wallet. The hot wallet belongs here: it is
/// allowlisted, but its funds have LEFT the vault's protection.
fn attacker_dest_strategy() -> impl Strategy<Value = Dest> {
    prop_oneof![
        (0u32..=MAX_INDEX).prop_map(Dest::Hot),
        unrecognized_dest_strategy(),
    ]
}

/// [`case_strategy`] with one output FORCED to `dest`.
///
/// The properties below whose subject is "a spend containing at least one output
/// of kind K" build that spend instead of drawing arbitrary ones and filtering
/// with `prop_assume!`. Filtering passes at the default case count and then aborts
/// the run with `Too many global rejects` (proptest caps global rejects at 1024)
/// the moment the budget is raised — which is exactly when a property suite earns
/// its keep. It also silently spends most of the default budget on rejected draws.
/// Constructing the shape makes every case a real one, at any budget.
fn case_with_forced_output(dest: impl Strategy<Value = Dest>) -> impl Strategy<Value = Case> {
    (case_strategy(), dest, 0usize..4).prop_map(|(mut case, dest, index)| {
        let i = index % case.outputs.len();
        case.outputs[i].dest = dest;
        case
    })
}

/// A spend guaranteed to pay BOTH the hot allowlist AND the escape wallet, with
/// every output allowlisted: the mixed-class shape, CONSTRUCTED rather than
/// filtered out of the general strategy.
fn mixed_case_strategy() -> impl Strategy<Value = Case> {
    (
        case_strategy_over(allowlisted_dest_strategy(), 2),
        0u32..=MAX_INDEX,
        0u32..=MAX_INDEX,
    )
        .prop_map(|(mut case, hot_index, escape_index)| {
            case.outputs[0].dest = Dest::Hot(hot_index);
            case.outputs[1].dest = Dest::Escape(escape_index);
            case
        })
}

impl Case {
    /// Each output's satoshi amount: the spendable value split by weight, with
    /// the rounding remainder and any overspend landing on the last output.
    fn amounts(&self) -> Vec<u64> {
        let spendable = TOTAL_IN - TOTAL_IN * self.fee_permille / 1000;
        let total_weight: u64 = self.outputs.iter().map(|o| o.weight).sum();
        let mut amounts: Vec<u64> = if total_weight == 0 {
            vec![0; self.outputs.len()]
        } else {
            self.outputs
                .iter()
                .map(|o| spendable * o.weight / total_weight)
                .collect()
        };
        let assigned: u64 = amounts.iter().sum();
        let last = amounts.len() - 1;
        amounts[last] += spendable - assigned + self.overspend;
        amounts
    }

    fn hot_cap(&self) -> u64 {
        let outflow = self.expected_hot_outflow();
        match self.cap {
            Cap::Permille(permille) => TOTAL_IN * permille / 1000,
            Cap::AtOutflow => outflow,
            Cap::JustUnderOutflow => outflow.saturating_sub(1),
            Cap::JustOverOutflow => outflow.saturating_add(1),
        }
    }

    /// The generated spend as a PSBT: one owned vault input at index 0 carrying
    /// the whole `TOTAL_IN`, and the generated outputs.
    fn psbt(&self) -> Psbt {
        let amounts = self.amounts();
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([9; 32]), 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: self
                .outputs
                .iter()
                .zip(&amounts)
                .map(|(spec, sats)| TxOut {
                    script_pubkey: spec.dest.spk(),
                    value: Amount::from_sat(*sats),
                })
                .collect(),
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).expect("unsigned tx");
        psbt.inputs[0].witness_utxo = Some(TxOut {
            script_pubkey: spk_at(&WALLETS.vault, 0),
            value: Amount::from_sat(TOTAL_IN),
        });
        for (out_map, spec) in psbt.outputs.iter_mut().zip(&self.outputs) {
            if spec.labeled_change {
                out_map.bip32_derivation.insert(
                    fake_change_pubkey(),
                    (
                        Fingerprint::default(),
                        DerivationPath::from_str("m/0/0").expect("path"),
                    ),
                );
            }
        }
        psbt
    }

    /// ORACLE: the hot outflow — every output paying neither the vault nor the
    /// escape wallet, including the ones no descriptor recognizes (over-counting
    /// can only refuse, which is the safe direction).
    fn expected_hot_outflow(&self) -> u64 {
        self.outputs
            .iter()
            .zip(self.amounts())
            .filter(|(spec, _)| !matches!(spec.dest.bucket(), Bucket::Vault | Bucket::Escape))
            .map(|(_, sats)| sats)
            .sum()
    }

    /// ORACLE: what `classify` must answer.
    fn expected_class(&self) -> Result<TxClass, ViolationCode> {
        if self
            .outputs
            .iter()
            .any(|o| o.dest.bucket() == Bucket::Unrecognized)
        {
            return Err(ViolationCode::PsbtInconsistent);
        }
        let hot = self.outputs.iter().any(|o| o.dest.bucket() == Bucket::Hot);
        let escape = self
            .outputs
            .iter()
            .any(|o| o.dest.bucket() == Bucket::Escape);
        match (hot, escape) {
            // Mixed hot+escape: exactly one class per spend, so this is refused.
            (true, true) => Err(ViolationCode::PsbtInconsistent),
            (true, false) => Ok(TxClass::Hot),
            (false, true) => Ok(TxClass::Escape),
            (false, false) => Ok(TxClass::Refresh),
        }
    }

    /// ORACLE: what `evaluate` must answer, in the check order `evaluate` runs
    /// (consistency → inputs → destinations → Hot budget → fee). Every generated
    /// case is structurally consistent and spends an owned input, so the first
    /// two never fire here.
    fn expected_evaluation(&self) -> Result<(), ViolationCode> {
        let amounts = self.amounts();
        // Destinations: the FIRST unrecognized output decides, and its untrusted
        // change label decides which of the two refusals it earns.
        if let Some(spec) = self
            .outputs
            .iter()
            .find(|o| o.dest.bucket() == Bucket::Unrecognized)
        {
            return Err(if spec.labeled_change {
                ViolationCode::ChangeNotDerivable
            } else {
                ViolationCode::DestNotAllowed
            });
        }
        if self.expected_hot_outflow() > self.hot_cap() {
            return Err(ViolationCode::HotBudgetExceeded);
        }
        let total_out: u64 = amounts.iter().sum();
        if total_out > TOTAL_IN {
            return Err(ViolationCode::PsbtInconsistent);
        }
        if (TOTAL_IN - total_out) * 100 > 10 * TOTAL_IN {
            return Err(ViolationCode::FeeExceedsCap);
        }
        Ok(())
    }
}

/// A dummy pubkey for the untrusted bip32 "this is my change" hint. Its contents
/// are never trusted by the checks — only its presence is read.
fn fake_change_pubkey() -> bitcoin::secp256k1::PublicKey {
    let sk = bitcoin::secp256k1::SecretKey::from_slice(&[7; 32]).expect("sk");
    PublicKey::from_secret_key(&Secp256k1::new(), &sk)
}

fn code_of(result: Result<(), policy_core::Violation>) -> Result<(), ViolationCode> {
    result.map_err(|v| v.code)
}

proptest! {
    #![proptest_config(config())]

    /// The headline: over ARBITRARY output sets against the fixed descriptor set,
    /// `evaluate`, `classify`, and `hot_outflow` each match an oracle derived from
    /// the generator's own ground truth. Every named invariant in the V0-7 bead is
    /// a corollary of this one, and the focused properties below then state the
    /// security-relevant ones in their own words.
    #[test]
    fn the_refusal_core_matches_its_oracle_on_arbitrary_output_sets(case in case_strategy()) {
        let psbt = case.psbt();
        let params = params(case.hot_cap());

        prop_assert_eq!(
            code_of(evaluate(&psbt, &params)),
            case.expected_evaluation(),
            "evaluate disagreed with the oracle for {:?}",
            case
        );
        prop_assert_eq!(
            classify(&psbt, &params).map(|c| c.class).map_err(|v| v.code),
            case.expected_class(),
            "classify disagreed with the oracle for {:?}",
            case
        );
        prop_assert_eq!(
            hot_outflow(&psbt, &params).to_sat(),
            case.expected_hot_outflow(),
            "hot_outflow is the sum of every non-vault, non-escape output"
        );
        // The class decision and the Hot meter are one scan over one output set,
        // so a classifiable spend can never be metered on a different quantity
        // than the one it was classified on.
        if let Ok(classification) = classify(&psbt, &params) {
            prop_assert_eq!(classification.hot_outflow, hot_outflow(&psbt, &params));
        }
    }

    /// An output the attacker chose — anything that does not pay the vault or the
    /// escape wallet — can only ever be classified `Hot` (frozen + metered
    /// downstream) or refused. It is NEVER `Escape` (which completes immediately
    /// under either PIN) and never `Refresh` (instant and pin-less). That is the
    /// duress-bypass closure, stated over arbitrary inputs.
    #[test]
    fn an_attacker_controlled_output_is_only_ever_hot_or_refused(
        case in case_with_forced_output(attacker_dest_strategy()),
    ) {
        let psbt = case.psbt();
        match classify(&psbt, &params(case.hot_cap())) {
            Ok(classification) => prop_assert_eq!(
                classification.class,
                TxClass::Hot,
                "a spend carrying an attacker-controlled output classified as \
                 {:?} for {:?}",
                classification.class,
                case
            ),
            Err(violation) => prop_assert_eq!(violation.code, ViolationCode::PsbtInconsistent),
        }
    }

    /// A spend that pays BOTH the hot allowlist and the escape wallet is refused
    /// `PSBT_INCONSISTENT` even though every one of its outputs is individually
    /// allowlisted — the 99%-to-hot + dust-to-escape duress bypass.
    #[test]
    fn a_mixed_hot_and_escape_spend_is_always_refused(case in mixed_case_strategy()) {
        let psbt = case.psbt();
        let params = params(case.hot_cap());
        // The allowlist alone admits it: this is precisely why the class predicate
        // has to exist.
        prop_assert_eq!(
            code_of(evaluate(&psbt, &params)),
            case.expected_evaluation(),
            "the allowlist is not what refuses a mixed spend"
        );
        let violation = classify(&psbt, &params).expect_err("mixed class must be refused");
        prop_assert_eq!(violation.code, ViolationCode::PsbtInconsistent);
        prop_assert_eq!(violation.check, "transaction_class");
    }

    /// An output paying neither the vault, nor the escape wallet, nor a
    /// hot-allowlist descriptor within the bound is REFUSED — never silently
    /// given a class. Covers the past-`max_derivation_index` hot address, which is
    /// a real hot-wallet script the node must nonetheless not recognize.
    #[test]
    fn an_unrecognized_output_is_always_refused(
        case in case_with_forced_output(unrecognized_dest_strategy()),
    ) {
        let psbt = case.psbt();
        let params = params(case.hot_cap());
        let violation = evaluate(&psbt, &params).expect_err("unrecognized output must be refused");
        prop_assert!(matches!(
            violation.code,
            ViolationCode::DestNotAllowed | ViolationCode::ChangeNotDerivable
        ));
        let class_violation = classify(&psbt, &params).expect_err("no class");
        prop_assert_eq!(class_violation.code, ViolationCode::PsbtInconsistent);
        prop_assert_eq!(class_violation.check, "transaction_class");
    }

    /// The per-transaction Hot budget refuses EXACTLY when the outflow exceeds the
    /// cap — not before (equality passes, as every cap in the crate does) and not
    /// after. Restricted to fully-allowlisted output sets, since a non-allowlisted
    /// destination is refused earlier and by a different check.
    #[test]
    fn the_per_tx_hot_cap_refuses_exactly_when_outflow_exceeds_it(
        case in case_strategy_over(allowlisted_dest_strategy(), 1),
    ) {
        let psbt = case.psbt();
        let outflow = case.expected_hot_outflow();
        let cap = case.hot_cap();
        let over_cap = code_of(evaluate(&psbt, &params(cap)))
            == Err(ViolationCode::HotBudgetExceeded);
        prop_assert_eq!(
            over_cap,
            outflow > cap,
            "outflow {} against cap {}",
            outflow,
            cap
        );
        // And the boundary itself, from both sides, for this exact spend.
        prop_assert_ne!(
            code_of(evaluate(&psbt, &params(outflow))),
            Err(ViolationCode::HotBudgetExceeded),
            "a cap set exactly at the outflow must pass"
        );
        if outflow > 0 {
            prop_assert_eq!(
                code_of(evaluate(&psbt, &params(outflow - 1))),
                Err(ViolationCode::HotBudgetExceeded),
                "one satoshi under the outflow must refuse"
            );
        }
    }

    /// Input ownership is proved by re-derivation within the bound, never by the
    /// PSBT's own hints: a prevout script from the vault descriptor PAST
    /// `max_derivation_index` is `UNKNOWN_INPUT`, and so is any foreign script.
    #[test]
    fn an_input_outside_the_bounded_vault_derivation_is_refused(
        index in 0u32..=MAX_INDEX + 4,
        foreign in any::<bool>(),
        tag in 1u8..=255,
    ) {
        let case = Case {
            outputs: vec![OutSpec {
                dest: Dest::Hot(0),
                weight: 1,
                labeled_change: false,
            }],
            fee_permille: 10,
            overspend: 0,
            cap: Cap::Permille(1000),
        };
        let mut psbt = case.psbt();
        let script_pubkey = if foreign {
            ScriptBuf::new_p2wsh(&WScriptHash::from_byte_array([tag; 32]))
        } else {
            spk_at(&WALLETS.vault, index)
        };
        psbt.inputs[0].witness_utxo = Some(TxOut {
            script_pubkey,
            value: Amount::from_sat(TOTAL_IN),
        });
        let owned = !foreign && index <= MAX_INDEX;
        let verdict = code_of(evaluate(&psbt, &params(TOTAL_IN)));
        if owned {
            prop_assert_eq!(verdict, Ok(()));
        } else {
            prop_assert_eq!(verdict, Err(ViolationCode::UnknownInput));
        }
    }
}
