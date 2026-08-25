//! The dormant deterministic Spend and its mandatory base Escape, composed over M3a's
//! prepared view (bead btc-policy-m3b-spend-composition-nq8).
//!
//! [`compose_spend`] is the whole seam and it has NO caller: the M4 command that will
//! reach it is unwritten, nothing here constructs a [`crate::core_view::CoreRpc`], and the
//! CLI dispatch names none of it. What it does is total rather than chosen — no coin
//! selection, no absorption, no output-topology decision. It parses the caller's
//! destination and binds it to the sealed network BEFORE any Core read, hands M3a the
//! three scripts, and afterwards takes every chain-derived value from M3a's `PreparedView`
//! rather than from the local copies it supplied: the canonical coins, the canonical script
//! triple, both preflighted sizes, the primary rate and the verified full parents.
//!
//! The result is the pair a node can combine — a Hot primary paying the EXACT requested
//! amount plus mandatory vault change, and a one-output base Escape sweeping the same
//! ordered coins, with an EMPTY replacement ladder. The primary pays M3a's integer sat/vB
//! rate; the Escape pays that rate maxed against the sealed floor; each is multiplied by
//! its own preflighted vsize, and every product and subtraction is checked.
//!
//! That rate can already be ZERO: it is M3a's ceiling over the node's own signals, so a
//! node whose two floors are zero and whose estimate is absent or itself zero yields zero
//! sat/vB, and a zero sealed floor leaves the Escape there too. Nothing here raises it. A
//! zero primary rate is a NAMED liveness/non-relay residual of what that node reported —
//! the pair may sit unrelayed, which redirects no value — and no reason to invent a
//! positive floor this seam has no authority to set.
//!
//! `policy_core::evaluate` stays the sole authority over the 10% whole-fee cap and runs on
//! BOTH final transactions. The `minimal_non_dust()` refused under here is rust-bitcoin's
//! and Core's DEFAULT dust policy; it establishes nothing about a node configured with a
//! custom `-dustrelayfee`. Composition is confirmed-only under ADR-0012/0013: value or
//! floors moving afterwards can leave the pair slow, non-relaying or inadmissible at fire
//! time, which degrades to Lockdown/Recovery rather than redirecting value.
//!
//! RESIDUAL: the 64 MiB gross parent projection M3a bounds this attachment at sits far
//! above the sealed `max_msg_bytes` a node enforces on the request that will one day carry
//! the pair, and nothing here reads that field. A pathologically fragmented vault can
//! therefore compose and sign a pair refused as a transport SHAPE rather than by policy;
//! presenting that belongs to the unwritten submitter, not to this dormant seam.

use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, Amount, EcdsaSighashType, ScriptBuf};
use miniscript::{Descriptor, DescriptorPublicKey};
use policy_core::TxClass;

use crate::core_view::CoreView;
use crate::http::Error;
use crate::inventory::{pair, prepare_view};
use crate::sealed::LiveVault;
use crate::signer::{SpendAuthorization, UserAuthorization};

/// Compose the frozen [`UserAuthorization::Spend`] paying `amount` to `destination_text`,
/// or refuse. Both transactions spend EVERY confirmed vault coin M3a scanned, in its
/// canonical order.
pub(crate) fn compose_spend(
    vault: &LiveVault,
    core: &dyn CoreView,
    destination_text: &str,
    amount: Amount,
) -> Result<UserAuthorization, Error> {
    // The caller's own text, bound to the sealed network BEFORE a single Core read: an
    // address for another chain is a terminal mistake, not something to discover after an
    // inventory bracket has run.
    let parsed: Address<NetworkUnchecked> = destination_text
        .parse()
        .map_err(|e| format!("the destination address does not parse: {e}"))?;
    let network = vault.network;
    let destination = parsed
        .require_network(network)
        .map_err(|_| format!("that is not an address on the sealed {network} network"))?
        .script_pubkey();
    // The change is the sealed descriptor's own script, and M3a checks it against the one
    // it derives for itself. The Escape is index 0 of the descriptor's first branch.
    let change = vault.descriptor.script_pubkey();
    let sealed_escape = vault
        .check_params
        .escape
        .as_ref()
        .ok_or("the sealed vault configures no escape wallet")?;
    let escape_script = base_escape_script(sealed_escape)?;

    // M3a owns everything from here to the closing tip. Nothing below re-reads a caller
    // copy: the canonical triple, the coins, the sizes, the rate and the parents all come
    // back out of the view.
    let prepared = prepare_view(
        core,
        network,
        &vault.descriptor,
        [&destination, &change, &escape_script],
    )?;
    let mut total = Amount::ZERO;
    for utxo in prepared.utxos() {
        total = total
            .checked_add(utxo.txout.value)
            .ok_or("the prepared input values overflow a u64 of satoshi")?;
    }
    let [primary_vsize, escape_vsize] = prepared.preflight_vsizes();
    let rate = prepared.sat_per_vb();
    // Per SHAPE, not one fee reused: the base Escape has one output where the primary has
    // two, and it is priced at the sealed floor whenever the node's own rate is under it.
    let primary_fee = Amount::from_sat(rate)
        .checked_mul(primary_vsize)
        .ok_or("the primary fee overflows at this rate and size")?;
    let escape_rate = rate.max(vault.escape_feerate_floor);
    let escape_fee = Amount::from_sat(escape_rate)
        .checked_mul(escape_vsize)
        .ok_or("the base escape fee overflows at this rate and size")?;
    // The requested amount is preserved EXACTLY; the change and the sweep are what is
    // left. Neither is ever absorbed into a fee to make a shape fit.
    let change_value = total
        .checked_sub(amount)
        .and_then(|rest| rest.checked_sub(primary_fee))
        .ok_or("the vault does not hold the requested amount and its primary fee")?;
    let sweep = total
        .checked_sub(escape_fee)
        .ok_or("the vault does not hold the base escape's own fee")?;

    // Every concrete output against ITS OWN script's default dust minimum; equality passes.
    let values = [amount, change_value, sweep];
    for (index, name) in ["destination", "vault change", "base escape"]
        .into_iter()
        .enumerate()
    {
        let floor = prepared.scripts()[index].minimal_non_dust().to_sat();
        let held = values[index].to_sat();
        if held < floor {
            return Err(format!("the {name} output is under its script's dust minimum").into());
        }
    }
    // The sealed coverage relation, widened so neither side can wrap. Equality passes, and
    // a sealed 100% therefore refuses any pair whose escape pays a fee at all.
    let covered = u128::from(sweep.to_sat()) * 100;
    let required = u128::from(total.to_sat()) * u128::from(vault.escape_coverage_pct);
    if covered < required {
        return Err("the base escape output is under the sealed coverage requirement".into());
    }

    // M3a's own final builder, over the inputs it preflighted. Both shapes must still
    // finalize at the size their fee was priced against.
    let [mut primary, mut escape] = pair(&prepared, [amount, change_value, sweep])?;
    for (psbt, priced) in [(&primary, primary_vsize), (&escape, escape_vsize)] {
        let reached = prepared.finalized_vsize(&psbt.unsigned_tx)?;
        if reached != priced {
            return Err(format!(
                "a composed shape finalizes at {reached} vB, not the {priced} vB it was priced at"
            )
            .into());
        }
    }
    // The full previous transaction of EVERY input of BOTH transactions, cloned only
    // through the completed inventory, plus an EXPLICIT `SIGHASH_ALL`. The refusal names
    // no identifier: a peer-chosen txid is a reflection channel (see `inventory.rs`).
    for psbt in [&mut primary, &mut escape] {
        for index in 0..psbt.inputs.len() {
            let txid = psbt.unsigned_tx.input[index].previous_output.txid;
            let parent = prepared
                .inventory()
                .full_parent(txid)
                .ok_or("a prepared input has no verified full previous transaction")?;
            psbt.inputs[index].non_witness_utxo = Some(parent);
            psbt.inputs[index].sighash_type = Some(EcdsaSighashType::All.into());
        }
    }
    // The final bytes, against the sealed policy. This is the sole `MAX_FEE_PERCENT`
    // authority and it binds BOTH transactions; M2 repeats it before it signs.
    for (psbt, expected) in [(&primary, TxClass::Hot), (&escape, TxClass::Escape)] {
        let refused = |v: policy_core::Violation| format!("final policy refusal: {}", v.check);
        policy_core::evaluate(psbt, &vault.check_params).map_err(refused)?;
        let class = policy_core::classify(psbt, &vault.check_params)
            .map_err(refused)?
            .class;
        if class != expected {
            return Err(format!(
                "a composed transaction classifies as {class:?}, not {expected:?}"
            )
            .into());
        }
    }
    Ok(UserAuthorization::Spend {
        wallet_id: vault.wallet_id,
        authorization: SpendAuthorization::new(primary, escape, Vec::new()),
    })
}

/// The BASE escape script: derivation index 0 of the FIRST canonical branch of the sealed
/// escape descriptor. A BIP389 `<0;1>` wallet expands to one single-path descriptor per
/// branch and the base is the first of them; a non-multipath descriptor expands to itself,
/// so one path covers both shapes. There is no address-index state here and no immediate
/// `derives_within` recheck — deriving index 0 from a branch of that descriptor cannot
/// fail to derive from it. The real proof is the final policy verdict on the composed
/// bytes, which reads the sealed `check_params` rather than this local expansion.
pub(crate) fn base_escape_script(
    escape: &Descriptor<DescriptorPublicKey>,
) -> Result<ScriptBuf, Error> {
    let branches = escape
        .clone()
        .into_single_descriptors()
        .map_err(|e| format!("the sealed escape descriptor does not expand: {e}"))?;
    let base = branches
        .into_iter()
        .next()
        .expect("successful descriptor expansion returns at least one branch");
    Ok(base
        .at_derivation_index(0)
        .map_err(|e| format!("the sealed escape descriptor has no index 0: {e}"))?
        .script_pubkey())
}
