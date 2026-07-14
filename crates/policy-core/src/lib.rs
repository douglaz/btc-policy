//! Pure policy-check evaluation for the federated vault.
//!
//! No I/O, no clock, no chain access — same inputs, same verdict on every
//! node; vault-node owns all resolution. See docs/DESIGN.md ("Policy model")
//! and CONTEXT.md for the vocabulary ("policy" must always be qualified).
//!
//! V0-5 makes every "does this script belong to a known descriptor within a
//! bounded index?" question run through ONE re-derivation primitive
//! ([`derives_within`]): input ownership, verified change, and the destination
//! allowlist all re-derive scripts from descriptors instead of matching literal
//! scriptPubKeys. This is why the allowlist is descriptors + a bounded index
//! rather than fixed addresses — a static address list would force address
//! reuse on the hot and escape wallets forever (DESIGN.md, "Destination
//! allowlist"; CONTEXT.md, "Allowlist").
//!
//! The checks this crate ships: PSBT consistency, input ownership, destination
//! allowlist + verified change, and the fee cap (ADR-0006). Sighash
//! enforcement and the Hold live in vault-node; the chain backend (real prevout
//! ground truth) is V0-6 — v0 still trusts each input's `witness_utxo` for the
//! prevout script.

use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Psbt, Script};
use miniscript::{Descriptor, DescriptorPublicKey};

/// Fee cap for first light: fee may not exceed this percentage of the total
/// input value (ADR-0006 — a generous bug guard, not a security control).
pub const MAX_FEE_PERCENT: u64 = 10;

/// Parameters for the policy checks, built from the node's policy config. Every
/// wallet the vault can touch is expressed as a descriptor + a bounded
/// derivation index; scripts are re-derived and compared, never string-matched.
#[derive(Debug, Clone)]
pub struct CheckParams {
    /// The node's OWN vault descriptor. An input is owned, and an output is
    /// verified change, exactly when its script re-derives from this descriptor
    /// within `max_derivation_index`.
    pub vault: Descriptor<DescriptorPublicKey>,
    /// Allowlisted destination descriptors (hot wallet + escape wallet). An
    /// output is an allowed destination when its script re-derives from one of
    /// these within `max_derivation_index`.
    pub allowed: Vec<Descriptor<DescriptorPublicKey>>,
    /// Bound on the derivation-index scan: an address beyond this index is not
    /// recognized (DESIGN.md config schema, `max_derivation_index`).
    pub max_derivation_index: u32,
}

/// Machine-readable result code for a failed policy check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViolationCode {
    UnknownInput,
    DestNotAllowed,
    ChangeNotDerivable,
    FeeExceedsCap,
    PsbtInconsistent,
}

/// A failed policy check. vault-node maps this onto its wire `Refusal`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub code: ViolationCode,
    /// Which check refused, in stable snake_case.
    pub check: &'static str,
    pub detail: String,
}

impl Violation {
    fn new(code: ViolationCode, check: &'static str, detail: String) -> Self {
        Violation {
            code,
            check,
            detail,
        }
    }
}

/// The one bounded re-derivation primitive (DESIGN.md, "Input ownership" /
/// "Verified change" / "Destination allowlist" all cite the same machinery).
///
/// Returns whether `spk` is the scriptPubKey `descriptor` produces at some
/// derivation index in `0..=max`, on any of the chains the descriptor defines:
/// a multipath `<0;1>` descriptor expands (via `into_single_descriptors`) to
/// one single-path descriptor per chain, so both the external and the
/// internal/change chain are scanned. A non-wildcard descriptor produces a
/// single script and is checked once (the `max` bound is irrelevant to it).
///
/// Deterministic and bounded: the scan never runs past `max`, and the same
/// inputs always give the same answer. Pure — the secp context is local
/// computation, not I/O.
pub fn derives_within(
    descriptor: &Descriptor<DescriptorPublicKey>,
    spk: &Script,
    max: u32,
) -> bool {
    let secp = Secp256k1::verification_only();
    // Multipath (`<0;1>`) descriptors split into one descriptor per chain;
    // a non-multipath descriptor yields itself. A descriptor that cannot be
    // split (should not happen for a valid parsed descriptor) matches nothing.
    let Ok(singles) = descriptor.clone().into_single_descriptors() else {
        return false;
    };
    for single in &singles {
        // A wildcard descriptor is scanned across the bounded index range; a
        // definite one has a single script, so index 0 alone suffices.
        let last = if single.has_wildcard() { max } else { 0 };
        for index in 0..=last {
            if let Ok(derived) = single.derived_descriptor(&secp, index) {
                if derived.script_pubkey().as_script() == spk {
                    return true;
                }
            }
        }
    }
    false
}

/// Run the policy checks against a PSBT. `Ok(())` means every check passed; the
/// first violation wins.
///
/// Input prevout scripts and values come from each input's `witness_utxo` —
/// v0 trusts the PSBT's prevout data (regtest, honest coordinator); the per-node
/// chain backend that stops trusting it is V0-6 (DESIGN.md, "Prevout ground
/// truth").
pub fn evaluate(psbt: &Psbt, params: &CheckParams) -> Result<(), Violation> {
    check_psbt_consistency(psbt)?;
    check_inputs(psbt, params)?;
    check_destinations(psbt, params)?;
    check_fee(psbt)?;
    Ok(())
}

/// PSBT consistency: the global/input/output sections must be coherent and
/// complete before any check reads them. A decodable-but-inconsistent PSBT is
/// refused `PsbtInconsistent` (undecodable input is a 400 at the wire, handled
/// in vault-node — DESIGN.md, "PSBT consistency"). Requiring a `witness_utxo`
/// on every input here lets the ownership and fee checks read prevout data
/// without each re-proving its presence.
fn check_psbt_consistency(psbt: &Psbt) -> Result<(), Violation> {
    let tx_inputs = psbt.unsigned_tx.input.len();
    let tx_outputs = psbt.unsigned_tx.output.len();
    if tx_inputs == 0 {
        return Err(Violation::new(
            ViolationCode::PsbtInconsistent,
            "psbt_consistency",
            "transaction has no inputs".into(),
        ));
    }
    if tx_outputs == 0 {
        return Err(Violation::new(
            ViolationCode::PsbtInconsistent,
            "psbt_consistency",
            "transaction has no outputs".into(),
        ));
    }
    if psbt.inputs.len() != tx_inputs {
        return Err(Violation::new(
            ViolationCode::PsbtInconsistent,
            "psbt_consistency",
            format!(
                "{} input map(s) for {tx_inputs} transaction input(s)",
                psbt.inputs.len()
            ),
        ));
    }
    if psbt.outputs.len() != tx_outputs {
        return Err(Violation::new(
            ViolationCode::PsbtInconsistent,
            "psbt_consistency",
            format!(
                "{} output map(s) for {tx_outputs} transaction output(s)",
                psbt.outputs.len()
            ),
        ));
    }
    for (index, input) in psbt.inputs.iter().enumerate() {
        if input.witness_utxo.is_none() {
            return Err(Violation::new(
                ViolationCode::PsbtInconsistent,
                "psbt_consistency",
                format!("input {index} has no witness_utxo"),
            ));
        }
    }
    Ok(())
}

/// Input ownership: every input's prevout scriptPubKey must re-derive from the
/// node's own vault descriptor within the bounded index. A PSBT bip32 path is an
/// untrusted hint; ownership is proved only by re-derivation. A non-derivable
/// input → `UnknownInput` (DESIGN.md, "Input ownership"). The prevout script is
/// taken from `witness_utxo` at v0 (its presence is guaranteed by
/// [`check_psbt_consistency`]); the chain backend is V0-6.
fn check_inputs(psbt: &Psbt, params: &CheckParams) -> Result<(), Violation> {
    for (index, input) in psbt.inputs.iter().enumerate() {
        let utxo = input
            .witness_utxo
            .as_ref()
            .expect("check_psbt_consistency guarantees witness_utxo for every input");
        if !derives_within(
            &params.vault,
            &utxo.script_pubkey,
            params.max_derivation_index,
        ) {
            return Err(Violation::new(
                ViolationCode::UnknownInput,
                "input_ownership",
                format!(
                    "input {index} prevout script {:x} does not derive from the vault \
                     descriptor within index {}",
                    utxo.script_pubkey, params.max_derivation_index
                ),
            ));
        }
    }
    Ok(())
}

/// Destination allowlist + verified change: every output is either (a) derivable
/// from an allowlisted destination descriptor, or (b) verified change — derived
/// from the node's own vault descriptor. Otherwise it is refused.
///
/// The refusal code distinguishes the two failure shapes: an output the PSBT
/// *labels* as change (a bip32 derivation hint claiming this vault owns it) that
/// does NOT actually re-derive from the vault descriptor is the fake-change
/// theft vector → `ChangeNotDerivable`; any other unrecognized output — a plain
/// non-allowlisted destination, OP_RETURN, or anything else → `DestNotAllowed`
/// (DESIGN.md, "Destination allowlist" / "Verified change"). The bip32 label is
/// never trusted — it only decides which refusal to report.
fn check_destinations(psbt: &Psbt, params: &CheckParams) -> Result<(), Violation> {
    let max = params.max_derivation_index;
    for (index, (txout, out_map)) in psbt
        .unsigned_tx
        .output
        .iter()
        .zip(&psbt.outputs)
        .enumerate()
    {
        let spk = txout.script_pubkey.as_script();
        // (a) an allowlisted destination wallet.
        if params
            .allowed
            .iter()
            .any(|descriptor| derives_within(descriptor, spk, max))
        {
            continue;
        }
        // (b) verified change: derived from the node's own vault descriptor.
        if derives_within(&params.vault, spk, max) {
            continue;
        }
        // Recognized by neither. An untrusted change label decides the reason.
        let labeled_change = !out_map.bip32_derivation.is_empty();
        return Err(if labeled_change {
            Violation::new(
                ViolationCode::ChangeNotDerivable,
                "verified_change",
                format!(
                    "output {index} is labeled change but does not derive from the vault \
                     descriptor within index {max}"
                ),
            )
        } else {
            Violation::new(
                ViolationCode::DestNotAllowed,
                "destination_allowlist",
                format!("output {index} pays non-allowlisted scriptPubKey {spk:x}"),
            )
        });
    }
    Ok(())
}

/// Fee cap: fee (Σ inputs − Σ outputs) must not exceed
/// `MAX_FEE_PERCENT` % of Σ inputs. Exactly at the cap passes.
/// [`check_psbt_consistency`] has already guaranteed every input carries a
/// `witness_utxo`.
fn check_fee(psbt: &Psbt) -> Result<(), Violation> {
    // Sums and products stay in u128 sats: u64 values cannot overflow them,
    // so no checked arithmetic is needed anywhere in this check.
    let total_in: u128 = psbt
        .inputs
        .iter()
        .filter_map(|input| input.witness_utxo.as_ref())
        .map(|utxo| u128::from(utxo.value.to_sat()))
        .sum();
    let total_out: u128 = psbt
        .unsigned_tx
        .output
        .iter()
        .map(|output| u128::from(output.value.to_sat()))
        .sum();
    if total_out > total_in {
        return Err(Violation::new(
            ViolationCode::PsbtInconsistent,
            "fee_cap",
            format!("outputs ({total_out} sat) exceed inputs ({total_in} sat)"),
        ));
    }
    let fee = total_in - total_out;
    if fee * 100 > u128::from(MAX_FEE_PERCENT) * total_in {
        return Err(Violation::new(
            ViolationCode::FeeExceedsCap,
            "fee_cap",
            format!("fee {fee} sat exceeds {MAX_FEE_PERCENT}% of total input value {total_in} sat"),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::bip32::{DerivationPath, Fingerprint, Xpriv, Xpub};
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::PublicKey;
    use bitcoin::transaction::Version;
    use bitcoin::{
        Amount, NetworkKind, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
        WScriptHash, Witness,
    };
    use std::str::FromStr;

    const MAX: u32 = 20;

    /// A deterministic xpub from a fixed seed byte.
    fn xpub(seed: u8) -> Xpub {
        let secp = Secp256k1::new();
        let xpriv = Xpriv::new_master(NetworkKind::Test, &[seed; 32]).expect("master key");
        Xpub::from_priv(&secp, &xpriv)
    }

    /// A ranged single-sig descriptor `wpkh(<xpub>/*)` — the shape of a hot or
    /// escape wallet allowlist entry (fresh address per index).
    fn ranged(seed: u8) -> Descriptor<DescriptorPublicKey> {
        Descriptor::from_str(&format!("wpkh({}/*)", xpub(seed))).expect("valid ranged descriptor")
    }

    /// A multipath `wpkh(<xpub>/<0;1>/*)` descriptor — ONE descriptor defining
    /// both an external (chain 0) and an internal/change (chain 1) chain, the
    /// shape a single descriptor uses to express the task's "external and
    /// internal/change chains as the descriptor defines".
    fn multipath(seed: u8) -> Descriptor<DescriptorPublicKey> {
        Descriptor::from_str(&format!("wpkh({}/<0;1>/*)", xpub(seed)))
            .expect("valid multipath descriptor")
    }

    /// The vault descriptor: `wsh(multi(2, k0, k1, k2))` with concrete keys —
    /// the shape of the first-light vault (definite, single script).
    fn vault() -> Descriptor<DescriptorPublicKey> {
        let secp = Secp256k1::new();
        let keys: Vec<String> = (1u8..=3)
            .map(|i| {
                let sk = bitcoin::secp256k1::SecretKey::from_slice(&[i; 32]).expect("sk");
                PublicKey::from_secret_key(&secp, &sk).to_string()
            })
            .collect();
        Descriptor::from_str(&format!("wsh(multi(2,{}))", keys.join(","))).expect("valid vault")
    }

    fn vault_spk() -> ScriptBuf {
        derived_spk(&vault(), 0)
    }

    /// The scriptPubKey `descriptor` produces at `index`.
    fn derived_spk(descriptor: &Descriptor<DescriptorPublicKey>, index: u32) -> ScriptBuf {
        let secp = Secp256k1::verification_only();
        descriptor
            .derived_descriptor(&secp, index)
            .expect("derivable")
            .script_pubkey()
    }

    fn params() -> CheckParams {
        CheckParams {
            vault: vault(),
            allowed: vec![ranged(0xA0), ranged(0xB0)],
            max_derivation_index: MAX,
        }
    }

    /// A one-input PSBT (prevout = the vault script) with the given outputs. The
    /// bool per output marks it as PSBT-labeled change (a bip32 hint claiming
    /// vault ownership — an untrusted hint the checks must re-derive, not trust).
    fn psbt_with(input_sats: u64, outputs: Vec<(ScriptBuf, u64, bool)>) -> Psbt {
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([9; 32]), 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: outputs
                .iter()
                .map(|(script_pubkey, sats, _)| TxOut {
                    script_pubkey: script_pubkey.clone(),
                    value: Amount::from_sat(*sats),
                })
                .collect(),
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).expect("unsigned tx");
        psbt.inputs[0].witness_utxo = Some(TxOut {
            script_pubkey: vault_spk(),
            value: Amount::from_sat(input_sats),
        });
        for (out_map, (_, _, labeled)) in psbt.outputs.iter_mut().zip(&outputs) {
            if *labeled {
                // A single dummy bip32 hint is enough to mark the output as
                // "change" for the label test; its contents are never trusted.
                let secp = Secp256k1::new();
                let sk = bitcoin::secp256k1::SecretKey::from_slice(&[7; 32]).expect("sk");
                let pk = PublicKey::from_secret_key(&secp, &sk);
                out_map.bip32_derivation.insert(
                    pk,
                    (
                        Fingerprint::default(),
                        DerivationPath::from_str("m/0/0").expect("path"),
                    ),
                );
            }
        }
        psbt
    }

    fn random_spk(tag: u8) -> ScriptBuf {
        ScriptBuf::new_p2wsh(&WScriptHash::from_byte_array([tag; 32]))
    }

    // --- the re-derivation primitive ---------------------------------------

    #[test]
    fn derivation_scan_is_bounded_and_deterministic() {
        let hot = ranged(0xA0);
        let at_max = derived_spk(&hot, MAX);
        let past_max = derived_spk(&hot, MAX + 1);
        // At the bound it matches; one index past the bound it does not.
        assert!(derives_within(&hot, at_max.as_script(), MAX));
        assert!(!derives_within(&hot, past_max.as_script(), MAX));
        // Deterministic: the same query repeated gives the same answer.
        assert!(derives_within(&hot, at_max.as_script(), MAX));
        // A definite (non-wildcard) descriptor matches its one script regardless.
        assert!(derives_within(&vault(), vault_spk().as_script(), 0));
    }

    #[test]
    fn multipath_descriptor_scans_both_external_and_change_chains() {
        // The primitive expands a `<0;1>` descriptor (via into_single_descriptors)
        // and scans BOTH chains, so a script on the external OR the change chain
        // derives — this is the "external and internal/change chains" contract.
        let desc = multipath(0xC0);
        let singles = desc
            .clone()
            .into_single_descriptors()
            .expect("multipath splits into single-path descriptors");
        assert_eq!(singles.len(), 2, "a <0;1> descriptor defines two chains");
        for single in &singles {
            let on_chain = derived_spk(single, 4);
            let past_max = derived_spk(single, MAX + 1);
            assert!(
                derives_within(&desc, on_chain.as_script(), MAX),
                "a script on this chain within the bound must derive"
            );
            assert!(
                !derives_within(&desc, past_max.as_script(), MAX),
                "a script one index past the bound must not derive on any chain"
            );
        }
    }

    // --- destination allowlist (descriptor-derived) ------------------------

    #[test]
    fn hot_address_at_index_zero_and_index_n_both_pass() {
        for index in [0, 7, MAX] {
            let spk = derived_spk(&ranged(0xA0), index);
            let psbt = psbt_with(100_000, vec![(spk, 99_000, false)]);
            assert_eq!(evaluate(&psbt, &params()), Ok(()), "index {index}");
        }
    }

    #[test]
    fn hot_address_past_the_index_bound_is_refused() {
        let spk = derived_spk(&ranged(0xA0), MAX + 1);
        let psbt = psbt_with(100_000, vec![(spk, 99_000, false)]);
        let violation = evaluate(&psbt, &params()).expect_err("beyond the bound");
        assert_eq!(violation.code, ViolationCode::DestNotAllowed);
    }

    #[test]
    fn random_non_derivable_output_is_dest_not_allowed() {
        let psbt = psbt_with(100_000, vec![(random_spk(0xEE), 99_000, false)]);
        let violation = evaluate(&psbt, &params()).expect_err("non-derivable");
        assert_eq!(violation.code, ViolationCode::DestNotAllowed);
        assert_eq!(violation.check, "destination_allowlist");
    }

    // --- verified change ----------------------------------------------------

    #[test]
    fn change_back_to_the_vault_passes() {
        // Output pays a script that derives from the vault's own descriptor.
        let psbt = psbt_with(
            100_000,
            vec![
                (derived_spk(&ranged(0xA0), 3), 40_000, false),
                (vault_spk(), 55_000, false),
            ],
        );
        assert_eq!(evaluate(&psbt, &params()), Ok(()));
    }

    #[test]
    fn labeled_change_that_does_not_derive_is_change_not_derivable() {
        // The theft vector: an output paying the attacker, marked as change with
        // a (fabricated, untrusted) bip32 hint. It does not derive from the
        // vault, so the change label must not save it.
        let psbt = psbt_with(100_000, vec![(random_spk(0xCC), 99_000, true)]);
        let violation = evaluate(&psbt, &params()).expect_err("fake change");
        assert_eq!(violation.code, ViolationCode::ChangeNotDerivable);
        assert_eq!(violation.check, "verified_change");
    }

    // --- input ownership ----------------------------------------------------

    #[test]
    fn input_not_deriving_from_the_vault_is_unknown_input() {
        let mut psbt = psbt_with(
            100_000,
            vec![(derived_spk(&ranged(0xA0), 0), 99_000, false)],
        );
        // Rewrite the prevout script to one that derives from no descriptor.
        psbt.inputs[0].witness_utxo = Some(TxOut {
            script_pubkey: random_spk(0x11),
            value: Amount::from_sat(100_000),
        });
        let violation = evaluate(&psbt, &params()).expect_err("foreign input");
        assert_eq!(violation.code, ViolationCode::UnknownInput);
        assert_eq!(violation.check, "input_ownership");
    }

    // --- PSBT consistency ---------------------------------------------------

    #[test]
    fn missing_witness_utxo_is_psbt_inconsistent() {
        let mut psbt = psbt_with(
            100_000,
            vec![(derived_spk(&ranged(0xA0), 0), 99_000, false)],
        );
        psbt.inputs[0].witness_utxo = None;
        let violation = evaluate(&psbt, &params()).expect_err("no prevout");
        assert_eq!(violation.code, ViolationCode::PsbtInconsistent);
        assert_eq!(violation.check, "psbt_consistency");
    }

    #[test]
    fn empty_psbt_is_psbt_inconsistent() {
        // No inputs and no outputs: every downstream check is vacuous and the fee
        // is 0 (0 in, 0 out), so WITHOUT the completeness guards this empty tx
        // would pass every check and be signed. The "no inputs" guard refuses it.
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![],
        };
        let psbt = Psbt::from_unsigned_tx(tx).expect("unsigned tx");
        let violation = evaluate(&psbt, &params()).expect_err("empty psbt");
        assert_eq!(violation.code, ViolationCode::PsbtInconsistent);
        assert_eq!(violation.check, "psbt_consistency");
    }

    #[test]
    fn zero_output_psbt_is_psbt_inconsistent() {
        // One input, no outputs: not "complete". The "no outputs" guard refuses
        // it as PsbtInconsistent rather than letting the fee cap mislabel a
        // zero-output (100%-fee) tx as FeeExceedsCap.
        let psbt = psbt_with(100_000, vec![]);
        let violation = evaluate(&psbt, &params()).expect_err("no outputs");
        assert_eq!(violation.code, ViolationCode::PsbtInconsistent);
        assert_eq!(violation.check, "psbt_consistency");
    }

    #[test]
    fn input_map_count_mismatch_is_psbt_inconsistent() {
        let mut psbt = psbt_with(
            100_000,
            vec![(derived_spk(&ranged(0xA0), 0), 99_000, false)],
        );
        // Drop the per-input map while the unsigned tx still has the input:
        // a decodable-but-inconsistent PSBT.
        psbt.inputs.clear();
        let violation = evaluate(&psbt, &params()).expect_err("length mismatch");
        assert_eq!(violation.code, ViolationCode::PsbtInconsistent);
    }

    // --- fee cap ------------------------------------------------------------

    #[test]
    fn fee_over_ten_percent_is_refused() {
        // fee = 10_001 of 100_000 inputs: just over the cap.
        let psbt = psbt_with(
            100_000,
            vec![(derived_spk(&ranged(0xA0), 0), 89_999, false)],
        );
        let violation = evaluate(&psbt, &params()).expect_err("must refuse");
        assert_eq!(violation.code, ViolationCode::FeeExceedsCap);
        assert_eq!(violation.check, "fee_cap");
    }

    #[test]
    fn fee_exactly_at_boundary_passes() {
        // fee = 10_000 of 100_000 inputs: exactly 10%.
        let psbt = psbt_with(
            100_000,
            vec![(derived_spk(&ranged(0xA0), 0), 90_000, false)],
        );
        assert_eq!(evaluate(&psbt, &params()), Ok(()));
    }

    #[test]
    fn outputs_exceeding_inputs_is_psbt_inconsistent() {
        let psbt = psbt_with(
            100_000,
            vec![(derived_spk(&ranged(0xA0), 0), 200_000, false)],
        );
        let violation = evaluate(&psbt, &params()).expect_err("must refuse");
        assert_eq!(violation.code, ViolationCode::PsbtInconsistent);
    }
}
