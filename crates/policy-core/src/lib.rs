//! Pure policy-check evaluation for the federated vault (first-light subset).
//!
//! No I/O, no clock, no chain access — same inputs, same verdict on every
//! node; vault-node owns all resolution. See docs/DESIGN.md ("Policy model")
//! and CONTEXT.md for the vocabulary ("policy" must always be qualified).
//!
//! First light ships exactly two real checks:
//! destination allowlist and the fee cap (ADR-0006). The rest of the check
//! set (input ownership, verified change, sighash enforcement, PSBT
//! consistency, the Hold) is v0 work with its own tasks.

use std::collections::BTreeSet;

use bitcoin::{Psbt, ScriptBuf};

/// Fee cap for first light: fee may not exceed this percentage of the total
/// input value (ADR-0006 — a generous bug guard, not a security control).
pub const MAX_FEE_PERCENT: u64 = 10;

/// Parameters for the first-light policy checks, baked from the node's
/// policy config. Allowlist entries are literal scriptPubKeys here;
/// descriptor re-derivation is v0 work.
#[derive(Debug, Clone)]
pub struct CheckParams {
    /// The vault's own scriptPubKey: paying back to the vault is always allowed.
    pub vault_spk: ScriptBuf,
    /// Allowlisted destination scriptPubKeys (hot wallet + escape wallet).
    pub allowed_spks: BTreeSet<ScriptBuf>,
}

/// Machine-readable result code for a failed first-light policy check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViolationCode {
    DestNotAllowed,
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

/// Run the first-light policy checks against a PSBT. `Ok(())` means every
/// check passed; the first violation wins.
///
/// Input values come from each input's `witness_utxo` — first light trusts
/// the PSBT's prevout data (regtest, honest coordinator); v1 must not
/// (DESIGN.md, per-node chain backend).
pub fn evaluate(psbt: &Psbt, params: &CheckParams) -> Result<(), Violation> {
    check_destinations(psbt, params)?;
    check_fee(psbt)?;
    Ok(())
}

/// Destination allowlist: every output must pay an allowlisted scriptPubKey
/// or the vault's own scriptPubKey (self-pay). Anything else is refused.
fn check_destinations(psbt: &Psbt, params: &CheckParams) -> Result<(), Violation> {
    for (index, output) in psbt.unsigned_tx.output.iter().enumerate() {
        let spk = &output.script_pubkey;
        if *spk != params.vault_spk && !params.allowed_spks.contains(spk) {
            return Err(Violation::new(
                ViolationCode::DestNotAllowed,
                "destination_allowlist",
                format!("output {index} pays non-allowlisted scriptPubKey {spk:x}"),
            ));
        }
    }
    Ok(())
}

/// Fee cap: fee (Σ inputs − Σ outputs) must not exceed
/// `MAX_FEE_PERCENT` % of Σ inputs. Exactly at the cap passes.
fn check_fee(psbt: &Psbt) -> Result<(), Violation> {
    // Sums and products stay in u128 sats: u64 values cannot overflow them,
    // so no checked arithmetic is needed anywhere in this check.
    let mut total_in: u128 = 0;
    for (index, input) in psbt.inputs.iter().enumerate() {
        let Some(utxo) = &input.witness_utxo else {
            return Err(Violation::new(
                ViolationCode::PsbtInconsistent,
                "fee_cap",
                format!("input {index} has no witness_utxo; fee cannot be computed"),
            ));
        };
        total_in += u128::from(utxo.value.to_sat());
    }
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
    use bitcoin::hashes::Hash;
    use bitcoin::transaction::Version;
    use bitcoin::{
        Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Txid, WScriptHash, Witness,
    };

    fn spk(tag: u8) -> ScriptBuf {
        ScriptBuf::new_p2wsh(&WScriptHash::from_byte_array([tag; 32]))
    }

    fn params() -> CheckParams {
        CheckParams {
            vault_spk: spk(0),
            allowed_spks: [spk(1), spk(2)].into_iter().collect(),
        }
    }

    /// A one-input PSBT with the given input value and outputs.
    fn psbt_with(input_sats: u64, outputs: Vec<(ScriptBuf, u64)>) -> Psbt {
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
                .into_iter()
                .map(|(script_pubkey, sats)| TxOut {
                    script_pubkey,
                    value: Amount::from_sat(sats),
                })
                .collect(),
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).expect("unsigned tx");
        psbt.inputs[0].witness_utxo = Some(TxOut {
            script_pubkey: spk(0),
            value: Amount::from_sat(input_sats),
        });
        psbt
    }

    #[test]
    fn allowlisted_output_passes() {
        let psbt = psbt_with(100_000, vec![(spk(1), 99_000)]);
        assert_eq!(evaluate(&psbt, &params()), Ok(()));
    }

    #[test]
    fn non_allowlisted_output_is_refused() {
        let psbt = psbt_with(100_000, vec![(spk(1), 50_000), (spk(7), 49_000)]);
        let violation = evaluate(&psbt, &params()).expect_err("must refuse");
        assert_eq!(violation.code, ViolationCode::DestNotAllowed);
        assert_eq!(violation.check, "destination_allowlist");
        assert!(
            violation.detail.contains("output 1"),
            "{}",
            violation.detail
        );
    }

    #[test]
    fn self_pay_to_vault_spk_passes() {
        let psbt = psbt_with(100_000, vec![(spk(1), 40_000), (spk(0), 59_000)]);
        assert_eq!(evaluate(&psbt, &params()), Ok(()));
    }

    #[test]
    fn fee_over_ten_percent_is_refused() {
        // fee = 10_001 of 100_000 inputs: just over the cap.
        let psbt = psbt_with(100_000, vec![(spk(1), 89_999)]);
        let violation = evaluate(&psbt, &params()).expect_err("must refuse");
        assert_eq!(violation.code, ViolationCode::FeeExceedsCap);
        assert_eq!(violation.check, "fee_cap");
    }

    #[test]
    fn fee_exactly_at_boundary_passes() {
        // fee = 10_000 of 100_000 inputs: exactly 10%.
        let psbt = psbt_with(100_000, vec![(spk(1), 90_000)]);
        assert_eq!(evaluate(&psbt, &params()), Ok(()));
    }

    #[test]
    fn missing_witness_utxo_is_psbt_inconsistent() {
        let mut psbt = psbt_with(100_000, vec![(spk(1), 99_000)]);
        psbt.inputs[0].witness_utxo = None;
        let violation = evaluate(&psbt, &params()).expect_err("must refuse");
        assert_eq!(violation.code, ViolationCode::PsbtInconsistent);
    }

    #[test]
    fn outputs_exceeding_inputs_is_psbt_inconsistent() {
        let psbt = psbt_with(100_000, vec![(spk(1), 200_000)]);
        let violation = evaluate(&psbt, &params()).expect_err("must refuse");
        assert_eq!(violation.code, ViolationCode::PsbtInconsistent);
    }
}
