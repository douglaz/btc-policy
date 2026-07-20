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
//! allowlist + verified change, the fee cap (ADR-0006), and the per-transaction
//! **Hot budget** (ADR-0014) — the allowlist bounds WHERE a hot spend pays, the
//! Hot budget bounds HOW MUCH. Its rolling-window sibling needs node state, so it
//! lives in vault-node; only the pure, per-transaction half is here. Sighash
//! enforcement and the Hold live in vault-node; the chain backend (real prevout
//! ground truth) is V0-6 — v0 still trusts each input's `witness_utxo` for the
//! prevout script.

use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Amount, Psbt, Script};
use miniscript::{Descriptor, DescriptorPublicKey};

pub mod template;

pub use template::{
    parse_vault_template, recovery_sequence, vault_descriptor_string, VaultTemplate, RECOVERY_KEYS,
    RECOVERY_THRESHOLD, RECOVERY_TIMELOCK_NSEQUENCE, RECOVERY_TIMELOCK_UNITS,
};

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
    /// The escape wallet's descriptor, when configured. It is ALSO an `allowed`
    /// entry (that is what lets a sweep pass the destination check); naming it
    /// separately is what lets [`classify`] tell an escape destination from a hot
    /// one. `None` ⇒ no output is escape-class (see [`classify`]).
    pub escape: Option<Descriptor<DescriptorPublicKey>>,
    /// Bound on the derivation-index scan: an address beyond this index is not
    /// recognized (DESIGN.md config schema, `max_derivation_index`).
    pub max_derivation_index: u32,
    /// The per-transaction half of the **Hot budget** (ADR-0014): a hot-class
    /// spend whose [`hot_outflow`] exceeds this is refused `HOT_BUDGET_EXCEEDED`.
    /// Federation-uniform (pinned in the Manifest preimage by vault-node), so
    /// every node computes the same verdict on the same spend. The rolling-window
    /// half needs node state and lives in vault-node.
    pub hot_max_per_tx: Amount,
}

/// The transaction class a node DERIVES from a spend's outputs — never trusts
/// from a coordinator label (ADR-0013 §3; ADR-0012, "Transaction class is DERIVED
/// by the node from the spend's outputs"). The channel envelope's `spend_purpose`
/// is a hint with no authority.
///
/// Class drives behavior, so a misclassification is a duress bypass, not a
/// cosmetic error: escape-class completes immediately under *either* PIN, so if
/// "has an escape output" were enough to earn escape-class, an attacker would
/// send 99%-to-hot + dust-to-escape and have it complete instantly under the
/// duress PIN — extraction, with stolen hot keys. Requiring *every* destination
/// output to pay the escape descriptor, and rejecting mixed, is what removes that.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxClass {
    /// Every output pays the vault: a pure self-spend that moves nothing to
    /// anyone. Instant, pin-less, and bounded by its own interval + fee cap
    /// (ADR-0013 §6) — it belongs in a `RefreshRequest`, not a `SpendRequest`.
    Refresh,
    /// Every destination output pays the escape descriptor (vault change allowed
    /// alongside). Completes immediately under either PIN.
    Escape,
    /// Every destination output pays a hot-allowlist descriptor (vault change
    /// allowed alongside). Signed at ingress, partial held, combined + broadcast
    /// at Hold expiry.
    Hot,
}

/// What [`classify`] decided, plus the [`hot_outflow`] its own output scan already
/// measured on the way there.
///
/// The outflow rides along because the class decision and the Hot-budget meter are
/// the SAME scan over the SAME outputs: `classify` sorts each output into vault /
/// escape / hot, and the hot bucket's value is exactly what
/// [`hot_outflow`] sums. Returning it means a caller that needs both — the velocity
/// ledger at ingress does — pays for one pass instead of two, and cannot meter a
/// different quantity than the one it classified on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Classification {
    pub class: TxClass,
    /// Zero for [`TxClass::Refresh`] and [`TxClass::Escape`], which have no hot
    /// destinations at all — "hot-class only" falls out of the definition.
    pub hot_outflow: Amount,
}

/// Machine-readable result code for a failed policy check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViolationCode {
    UnknownInput,
    DestNotAllowed,
    ChangeNotDerivable,
    FeeExceedsCap,
    PsbtInconsistent,
    /// A hot-class spend moving more than `hot_max_per_tx` to the hot wallet
    /// (ADR-0014, the per-transaction half of the Hot budget).
    HotBudgetExceeded,
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
    check_hot_budget(psbt, params)?;
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

/// The node-derived transaction class (ADR-0013 §3, normative). Reads ONLY the
/// spend's outputs, re-deriving each against the vault / escape / hot descriptors
/// through the same bounded primitive every other check uses.
///
/// **Vault-change outputs are permitted in every class and excluded from the
/// decision**; the class turns on the remaining *destination* outputs:
///
/// - no destination outputs at all ⇒ [`TxClass::Refresh`] (a pure self-spend);
/// - every destination pays the escape descriptor ⇒ [`TxClass::Escape`];
/// - every destination pays a hot-allowlist descriptor ⇒ [`TxClass::Hot`];
/// - destinations spanning BOTH hot and escape ⇒ `PSBT_INCONSISTENT`. This is the
///   mixed-class rejection, and it is load-bearing: without it the
///   99%-to-hot + dust-to-escape spend above is a duress bypass.
///
/// A destination matching NO allowlisted descriptor is left to
/// [`check_destinations`] — that is the ordinary allowlist refusal
/// (`DEST_NOT_ALLOWED`), not a class question. So callers run [`evaluate`] first;
/// this then sees only outputs already known to be vault change or allowlisted,
/// and any leftover is reported as mixed rather than silently classified.
///
/// Returns a [`Classification`]: the class plus the hot outflow this same scan
/// measured, so the velocity ledger never re-derives what was just computed.
pub fn classify(psbt: &Psbt, params: &CheckParams) -> Result<Classification, Violation> {
    let max = params.max_derivation_index;
    let mut escape_outputs = Vec::new();
    let mut hot_outputs = Vec::new();
    let mut unrecognized = Vec::new();
    // The hot bucket's value, accumulated by the same pass that sorts it: on the
    // `Ok` path this is exactly `hot_outflow(psbt, params)`, since every output is
    // then vault change, escape, or hot. `saturating_add` for the same reason
    // `hot_outflow` uses it — a saturating sum over-counts, which can only refuse.
    let mut hot_sat = 0u64;
    for (index, txout) in psbt.unsigned_tx.output.iter().enumerate() {
        let spk = txout.script_pubkey.as_script();
        // Vault change: permitted in every class, excluded from the decision.
        if derives_within(&params.vault, spk, max) {
            continue;
        }
        let escape = params
            .escape
            .as_ref()
            .is_some_and(|escape| derives_within(escape, spk, max));
        if escape {
            escape_outputs.push(index);
            continue;
        }
        // Hot = allowlisted but not the escape wallet. The escape descriptor is
        // itself an allowlist entry, so it must be tested (above) FIRST or every
        // escape output would read as hot.
        if params
            .allowed
            .iter()
            .any(|descriptor| derives_within(descriptor, spk, max))
        {
            hot_outputs.push(index);
            hot_sat = hot_sat.saturating_add(txout.value.to_sat());
            continue;
        }
        unrecognized.push(index);
    }
    if !unrecognized.is_empty() {
        return Err(Violation::new(
            ViolationCode::PsbtInconsistent,
            "transaction_class",
            format!(
                "output(s) {unrecognized:?} pay neither the vault, the escape descriptor, \
                 nor a hot-allowlist descriptor, so the spend has no single class"
            ),
        ));
    }
    let hot_outflow = Amount::from_sat(hot_sat);
    match (hot_outputs.is_empty(), escape_outputs.is_empty()) {
        (true, true) => Ok(Classification {
            class: TxClass::Refresh,
            hot_outflow,
        }),
        (true, false) => Ok(Classification {
            class: TxClass::Escape,
            hot_outflow,
        }),
        (false, true) => Ok(Classification {
            class: TxClass::Hot,
            hot_outflow,
        }),
        (false, false) => Err(Violation::new(
            ViolationCode::PsbtInconsistent,
            "transaction_class",
            format!(
                "mixed-class spend: output(s) {hot_outputs:?} pay the hot allowlist and \
                 output(s) {escape_outputs:?} pay the escape wallet; a spend has exactly one class"
            ),
        )),
    }
}

/// **Hot outflow**: the sum of a spend's outputs to non-vault, non-escape
/// destinations — what a hot-class spend actually moves out of the vault to the
/// hot wallet, and the quantity BOTH halves of the Hot budget meter (ADR-0014 §5).
///
/// Vault change is excluded because it never leaves the vault, and the fee is
/// excluded because it goes to miners rather than to the attacker (and is already
/// bounded by [`MAX_FEE_PERCENT`]). Escape outputs are excluded because an escape
/// pays the user's own wallet and is not a loss (ADR-0014 §7) — with
/// `params.escape == None` nothing is escape, exactly as [`classify`] reads it.
///
/// Callers run [`evaluate`] first, so every output is already known to be vault
/// change or allowlisted and this sums exactly the hot destinations. Reached
/// before that, an unrecognized output is counted too: over-counting can only
/// refuse a spend, never admit an over-budget one, which is the safe direction.
/// The `saturating_add` is the same trade — a sum that saturates over-counts.
pub fn hot_outflow(psbt: &Psbt, params: &CheckParams) -> Amount {
    let max = params.max_derivation_index;
    let mut sat = 0u64;
    for txout in &psbt.unsigned_tx.output {
        let spk = txout.script_pubkey.as_script();
        if derives_within(&params.vault, spk, max) {
            continue;
        }
        if params
            .escape
            .as_ref()
            .is_some_and(|escape| derives_within(escape, spk, max))
        {
            continue;
        }
        sat = sat.saturating_add(txout.value.to_sat());
    }
    Amount::from_sat(sat)
}

/// The per-transaction half of the Hot budget (ADR-0014 §1): hot outflow may not
/// exceed `hot_max_per_tx`. Exactly at the cap passes, as every other cap in this
/// crate does.
///
/// This is the check that turns "the hot wallet is the accepted risk budget" from
/// an assumption into a bound: without it the allowlist constrains only WHERE a
/// coerced hot spend pays, never HOW MUCH, so one spend could pay the entire vault
/// to the hot wallet. Pure and amount-based — it never reads a pin, which is what
/// lets it fire at ingress without becoming a duress oracle.
///
/// A refresh (no destination outputs) and an escape sweep both have zero hot
/// outflow, so neither can ever trip this — ADR-0014 §7's "hot-class only" falls
/// out of [`hot_outflow`]'s definition rather than needing a class argument.
fn check_hot_budget(psbt: &Psbt, params: &CheckParams) -> Result<(), Violation> {
    let outflow = hot_outflow(psbt, params);
    if outflow > params.hot_max_per_tx {
        return Err(Violation::new(
            ViolationCode::HotBudgetExceeded,
            "hot_budget",
            format!(
                "hot outflow {} sat exceeds the per-transaction Hot budget of {} sat",
                outflow.to_sat(),
                params.hot_max_per_tx.to_sat()
            ),
        ));
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

    /// The per-tx Hot budget every fixture below uses unless it is the thing under
    /// test. Far above the 99_000-sat spends the other tests build, so the cap is
    /// inert for them — a fixture whose cap silently bit would turn every unrelated
    /// test into a Hot-budget test.
    const HOT_CAP: Amount = Amount::from_sat(1_000_000);

    fn params() -> CheckParams {
        CheckParams {
            vault: vault(),
            allowed: vec![ranged(0xA0), ranged(0xB0)],
            escape: None,
            max_derivation_index: MAX,
            hot_max_per_tx: HOT_CAP,
        }
    }

    /// The hot wallet (0xA0) and the escape wallet (0xB0) as a node configures
    /// them: BOTH allowlisted, escape named separately so [`classify`] can tell
    /// them apart.
    fn class_params() -> CheckParams {
        CheckParams {
            vault: vault(),
            allowed: vec![ranged(0xA0), ranged(0xB0)],
            escape: Some(ranged(0xB0)),
            max_derivation_index: MAX,
            hot_max_per_tx: HOT_CAP,
        }
    }

    /// [`class_params`] re-capped, for the Hot-budget tests.
    fn capped_params(hot_max_per_tx: u64) -> CheckParams {
        CheckParams {
            hot_max_per_tx: Amount::from_sat(hot_max_per_tx),
            ..class_params()
        }
    }

    fn hot_spk(index: u32) -> ScriptBuf {
        derived_spk(&ranged(0xA0), index)
    }

    fn escape_spk(index: u32) -> ScriptBuf {
        derived_spk(&ranged(0xB0), index)
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

    // -- the transaction-class predicate (ADR-0013 §3) -----------------------

    #[test]
    fn every_output_to_the_vault_is_refresh_class() {
        let psbt = psbt_with(100_000, vec![(vault_spk(), 90_000, false)]);
        assert_eq!(
            classify(&psbt, &class_params()).map(|c| c.class),
            Ok(TxClass::Refresh)
        );
    }

    #[test]
    fn a_hot_destination_with_vault_change_is_hot_class() {
        let psbt = psbt_with(
            100_000,
            vec![(hot_spk(5), 60_000, false), (vault_spk(), 30_000, false)],
        );
        assert_eq!(
            classify(&psbt, &class_params()).map(|c| c.class),
            Ok(TxClass::Hot)
        );
    }

    #[test]
    fn every_destination_to_the_escape_wallet_is_escape_class_even_with_vault_change() {
        // Vault change is permitted in EVERY class and excluded from the
        // decision, so it must not downgrade a sweep out of escape-class.
        let psbt = psbt_with(
            100_000,
            vec![
                (escape_spk(0), 60_000, false),
                (escape_spk(1), 20_000, false),
                (vault_spk(), 10_000, false),
            ],
        );
        assert_eq!(
            classify(&psbt, &class_params()).map(|c| c.class),
            Ok(TxClass::Escape)
        );
    }

    /// The duress bypass this predicate exists to close: 99% to the hot wallet
    /// plus dust to the escape wallet. Every output is individually allowlisted,
    /// so `evaluate` passes it — a "has an escape output ⇒ escape-class" rule
    /// would complete it IMMEDIATELY under the duress PIN, which with stolen hot
    /// keys is extraction. It must be rejected outright.
    #[test]
    fn a_mixed_hot_and_escape_spend_is_rejected_even_though_every_output_is_allowlisted() {
        let psbt = psbt_with(
            100_000,
            vec![(hot_spk(5), 89_000, false), (escape_spk(0), 1_000, false)],
        );
        assert_eq!(
            evaluate(&psbt, &class_params()),
            Ok(()),
            "each output is individually allowlisted, so the allowlist alone admits this spend"
        );
        let violation = classify(&psbt, &class_params()).expect_err("mixed class must be rejected");
        assert_eq!(violation.code, ViolationCode::PsbtInconsistent);
        assert_eq!(violation.check, "transaction_class");
    }

    /// The escape descriptor is itself an allowlist entry, so testing "hot" by
    /// allowlist membership alone would read every escape output as hot and
    /// silently turn a sweep into a held hot-class spend.
    #[test]
    fn an_escape_output_is_not_read_as_hot_merely_because_it_is_allowlisted() {
        let psbt = psbt_with(100_000, vec![(escape_spk(0), 90_000, false)]);
        assert!(
            class_params()
                .allowed
                .iter()
                .any(|d| derives_within(d, escape_spk(0).as_script(), MAX)),
            "the escape wallet must be allowlisted, or its sweep could not pass the destination check"
        );
        assert_eq!(
            classify(&psbt, &class_params()).map(|c| c.class),
            Ok(TxClass::Escape)
        );
    }

    #[test]
    fn with_no_escape_descriptor_configured_nothing_is_escape_class() {
        // `escape: None` — the escape wallet's script is still allowlisted, so it
        // reads as an ordinary hot destination rather than a sweep.
        let psbt = psbt_with(100_000, vec![(escape_spk(0), 90_000, false)]);
        assert_eq!(
            classify(&psbt, &params()).map(|c| c.class),
            Ok(TxClass::Hot)
        );
    }

    // -- the per-transaction Hot budget (ADR-0014 §1) ------------------------

    #[test]
    fn a_hot_spend_over_the_per_tx_cap_is_refused() {
        let psbt = psbt_with(100_000, vec![(hot_spk(3), 90_000, false)]);
        // Under a 100_000-sat cap this same spend passes, so the refusal below is
        // the cap talking and not some other check.
        assert_eq!(evaluate(&psbt, &capped_params(100_000)), Ok(()));
        let violation = evaluate(&psbt, &capped_params(89_999)).expect_err("over the cap");
        assert_eq!(violation.code, ViolationCode::HotBudgetExceeded);
        assert_eq!(violation.check, "hot_budget");
    }

    #[test]
    fn hot_outflow_exactly_at_the_cap_passes() {
        let psbt = psbt_with(100_000, vec![(hot_spk(3), 90_000, false)]);
        assert_eq!(evaluate(&psbt, &capped_params(90_000)), Ok(()));
    }

    /// Outflow is what LEAVES the vault to the hot wallet. Vault change never
    /// leaves, and the fee goes to miners rather than to a coercer (and is already
    /// bounded by the 10% guard), so counting either would make the cap mean
    /// something other than "how much a coerced spend can move".
    #[test]
    fn vault_change_and_the_fee_do_not_count_against_the_cap() {
        // 100_000 in: 50_000 to hot, 40_000 back to the vault, 10_000 fee.
        let psbt = psbt_with(
            100_000,
            vec![(hot_spk(3), 50_000, false), (vault_spk(), 40_000, false)],
        );
        assert_eq!(
            hot_outflow(&psbt, &class_params()),
            Amount::from_sat(50_000)
        );
        // A cap at exactly the hot payment admits it. Were change or the fee
        // counted, the outflow would read 90_000 or 100_000 and this would refuse.
        assert_eq!(evaluate(&psbt, &capped_params(50_000)), Ok(()));
    }

    /// ADR-0014 §7: an escape sweep pays the user's own wallet and a refresh never
    /// leaves the vault, so neither is a loss and neither may consume the budget.
    /// Both fall out of `hot_outflow` being zero rather than needing a class test.
    #[test]
    fn escape_and_refresh_spends_never_consume_the_hot_budget() {
        let sweep = psbt_with(
            100_000,
            vec![(escape_spk(0), 60_000, false), (vault_spk(), 30_000, false)],
        );
        let refresh = psbt_with(100_000, vec![(vault_spk(), 90_000, false)]);
        for (name, psbt) in [("escape", &sweep), ("refresh", &refresh)] {
            assert_eq!(
                hot_outflow(psbt, &class_params()),
                Amount::ZERO,
                "{name} moves nothing to the hot wallet"
            );
            // A zero cap is the strongest possible statement of this: even with no
            // hot budget at all, these two still pass.
            assert_eq!(evaluate(psbt, &capped_params(0)), Ok(()), "{name}");
        }
    }

    /// `classify` returns the outflow its own scan measured and vault-node meters
    /// THAT value, so the class decision and the Hot budget can never be taken over
    /// different quantities. This pins the two definitions together: whatever
    /// `hot_outflow` says for a classifiable spend, `classify` must say too.
    #[test]
    fn the_classification_carries_the_same_outflow_hot_outflow_computes() {
        let cases = [
            // hot with vault change
            vec![(hot_spk(5), 60_000, false), (vault_spk(), 30_000, false)],
            // several hot outputs, summed
            vec![
                (hot_spk(1), 40_000, false),
                (hot_spk(2), 40_000, false),
                (vault_spk(), 15_000, false),
            ],
            // escape sweep — zero hot outflow
            vec![(escape_spk(0), 60_000, false), (vault_spk(), 30_000, false)],
            // pure refresh — zero hot outflow
            vec![(vault_spk(), 90_000, false)],
        ];
        for outputs in cases {
            let psbt = psbt_with(100_000, outputs);
            let classification = classify(&psbt, &class_params()).expect("classifiable");
            assert_eq!(
                classification.hot_outflow,
                hot_outflow(&psbt, &class_params()),
                "classify and hot_outflow must agree for a {:?}-class spend",
                classification.class
            );
        }
    }

    /// The cap must not shadow the allowlist. A non-allowlisted destination is
    /// `DEST_NOT_ALLOWED` whether or not it is also over the cap — the demo's act-two
    /// theft assertion depends on exactly this ordering.
    #[test]
    fn a_non_allowlisted_destination_is_still_dest_not_allowed_when_it_is_also_over_the_cap() {
        let psbt = psbt_with(100_000, vec![(random_spk(0xEE), 90_000, false)]);
        let violation = evaluate(&psbt, &capped_params(1)).expect_err("theft");
        assert_eq!(violation.code, ViolationCode::DestNotAllowed);
    }

    #[test]
    fn an_over_budget_hot_spend_is_identified_before_the_fee_guard() {
        // 80k hot outflow from a 100k input is over the 70k Hot cap and the 20k
        // fee is also over the 10% fee guard. The budget verdict must surface so
        // vault-node takes its duress-carrier propagation path; the destination
        // check above still retains precedence for transactions that cannot pay an
        // authorized wallet at all.
        let psbt = psbt_with(100_000, vec![(hot_spk(3), 80_000, false)]);
        let violation = evaluate(&psbt, &capped_params(70_000)).expect_err("over both caps");
        assert_eq!(violation.code, ViolationCode::HotBudgetExceeded);
    }

    /// Several hot outputs are one payment for budget purposes: capping each
    /// output separately would let a coercer split one vault-sized spend into `k`
    /// under-cap outputs of the same transaction and move the whole thing.
    #[test]
    fn multiple_hot_outputs_are_summed_not_capped_individually() {
        let psbt = psbt_with(
            100_000,
            vec![
                (hot_spk(1), 40_000, false),
                (hot_spk(2), 40_000, false),
                (vault_spk(), 15_000, false),
            ],
        );
        assert_eq!(
            hot_outflow(&psbt, &class_params()),
            Amount::from_sat(80_000)
        );
        let violation = evaluate(&psbt, &capped_params(50_000))
            .expect_err("each output is under 50_000, but together they are not");
        assert_eq!(violation.code, ViolationCode::HotBudgetExceeded);
    }

    #[test]
    fn an_unallowlisted_output_has_no_class() {
        // `classify` runs after `evaluate`, which refuses this with
        // DEST_NOT_ALLOWED; reached directly it must refuse rather than guess.
        let stranger = derived_spk(&ranged(0xEE), 0);
        let psbt = psbt_with(100_000, vec![(stranger, 90_000, false)]);
        let violation = classify(&psbt, &class_params()).expect_err("no class");
        assert_eq!(violation.code, ViolationCode::PsbtInconsistent);
    }
}
