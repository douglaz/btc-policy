//! The stable confirmed-only vault inventory, prepared against ONE bounded read-only
//! Core view (bead btc-policy-m3a-core-view-inventory-rha).
//!
//! [`prepare_view`] is the whole seam. It takes the sealed DEFINITE descriptor — never a
//! `LiveVault` — derives the vault script, the exact witness script and the maximum
//! satisfaction weight from it BEFORE any Core RPC, refuses a supplied vault-change
//! script that is not its own, and then runs at most three inventory brackets. What it
//! returns is a [`PreparedView`]: the canonically ordered nonempty coin set, one
//! canonical script triple, both preflighted maximum finalized sizes, the primary
//! integer sat/vB rate, and an opaque [`CompletedInventory`] holding the verified full
//! parents.
//!
//! Deterministic and confirmed-only: the inventory is EVERY confirmed, mature,
//! mempool-unspent coin paying the one definite sealed vault script, in canonical
//! outpoint order. There is no coin selection and no discovery of
//! vault-authorized-unconfirmed value — the stage-1 narrowing ADR-0012/0013 name, whose
//! release blocker is `btc-policy-w2b`. A scanned coin that is mempool-spent refuses the
//! WHOLE inventory rather than being omitted, because omitting it prepares an
//! under-covered Escape.
//!
//! Acceptance proves mutual consistency during one bounded bracket against an honest
//! monotone Core. It reserves no coin, is no attestation, and says nothing about changes
//! after the closing reads: value arriving or changing later can still make the base
//! inadmissible at fire time, which degrades to Lockdown/Recovery.
//!
//! NO refusal here interpolates a Core-derived txid, block hash, outpoint or script: a
//! hostile loopback listener is handed the Basic auth head before it answers, and a
//! 64-hex cookie password is a syntactically VALID txid, so anything it names is a
//! reflection channel. The typed values are kept and checked internally; only the
//! contradiction and its remedy cross out, with the trusted numbers that cannot carry a
//! secret (heights, confirmations, vouts, byte and vsize bounds).
//!
//! Its ONE caller is [`crate::compose`], itself dormant. Final output values, the sealed
//! Escape floor, ATTACHING those parents, `SIGHASH_ALL`, dust/coverage/policy and the
//! authorization belong to `btc-policy-m3b-spend-composition-nq8`. It lands dormant behind
//! [`crate::core_view`], whose transport is unbounded and lossy until qhe closes.

use std::collections::BTreeMap;

use bitcoin::absolute::LockTime;
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, BlockHash, Network, Psbt, PublicKey, ScriptBuf, Sequence, Transaction, TxOut, Txid,
};
use miniscript::Descriptor;

use crate::core_view::{CoreView, ScanCoin};
use crate::fed::{build_spend_n, Utxo};
use crate::http::Error;

/// Gross duplicated `non_witness_utxo` bytes the composer may project across BOTH PSBT
/// input-map sets. Equality passes. Checked DURING the parent fetch, so retained
/// pre-clone material is bounded by this plus ONE in-flight response nothing yet caps (qhe).
const MAX_COMPOSER_FULL_PREVTX_BYTES: u64 = 64 * 1024 * 1024;

/// Maximum finalized size either shape may reach, in vB. Equality passes.
const MAX_COMPOSER_VSIZE: u64 = 100_000;

/// Coinbase maturity in confirmations. Equality passes.
const COINBASE_MATURITY: u64 = 100;

/// TOTAL inventory passes. No sleep, no backoff, no nested retry, and no
/// scan-contention loop: only observed tip movement makes a pass retryable.
const INVENTORY_PASSES: u32 = 3;

/// The verified full parents of an ACCEPTED bracket, and the only capability that
/// exposes them. The map is private and its one accessor is the sole clone site, but
/// "no full-parent clone before the projection completed" is OBSERVED by the counter
/// below, not enforced by this type: `m45` breaks it in one line and no type changes.
pub(crate) struct CompletedInventory {
    parents: BTreeMap<Txid, Transaction>,
}

impl CompletedInventory {
    /// The verified full parent of `txid`, for the final composition that attaches it as
    /// `non_witness_utxo`. This is the ONE place a full parent is cloned.
    pub(crate) fn full_parent(&self, txid: Txid) -> Option<Transaction> {
        self.parents.get(&txid).map(clone_full_parent)
    }
}

#[cfg(test)]
thread_local! {
    /// Test-only: how many full parents THIS THREAD has cloned. `cargo test` gives every
    /// test its own thread, so a class reads only its own clones.
    static PARENT_CLONES: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// The one full-parent clone site, funnelled so it can be COUNTED. Nothing before a
/// completed projection calls it; `m45` moves a clone into the fetch loop and the class
/// that observes this counter goes red.
fn clone_full_parent(parent: &Transaction) -> Transaction {
    #[cfg(test)]
    PARENT_CLONES.with(|clones| clones.set(clones.get() + 1));
    parent.clone()
}

/// The OWNED canonical shape inputs both the zero-amount preflight and the final pair
/// build over. Constructed once per pass, immediately after the scan is sorted, and
/// handed on unchanged inside [`PreparedView`] — so the shape the composer finally
/// builds is the shape that was preflighted, by construction rather than by convention.
struct ShapeInputs {
    utxos: Vec<Utxo>,
    witness_script: ScriptBuf,
    /// `[destination, INTERNALLY DERIVED vault change, base Escape]`. The caller's copy
    /// of the vault-change script is checked and then discarded.
    scripts: [ScriptBuf; 3],
}

/// One accepted bracket.
struct Bracket {
    shape: ShapeInputs,
    inventory: CompletedInventory,
    primary_vsize: u64,
    escape_vsize: u64,
}

/// Everything the final composition may read, and nothing it may re-supply.
pub(crate) struct PreparedView {
    bracket: Bracket,
    /// The descriptor's own maximum satisfaction weight, derived here.
    weight: u64,
    /// The PRIMARY rate in integer sat/vB. The unit is the point: M3b's sealed Escape
    /// floor is sat/vB, so there is no sat/kvB value here to compare it against.
    sat_vb: u64,
}

impl PreparedView {
    /// The canonically ordered, duplicate-free, nonempty coin set.
    pub(crate) fn utxos(&self) -> &[Utxo] {
        &self.bracket.shape.utxos
    }

    /// `[destination, vault change, base Escape]`, with the vault change the one this
    /// module derived from the descriptor.
    pub(crate) fn scripts(&self) -> &[ScriptBuf; 3] {
        &self.bracket.shape.scripts
    }

    /// `[primary, base Escape]` maximum finalized sizes, measured before any candidate
    /// or parent RPC and never recomputed from caller input.
    pub(crate) fn preflight_vsizes(&self) -> [u64; 2] {
        [self.bracket.primary_vsize, self.bracket.escape_vsize]
    }

    pub(crate) fn sat_per_vb(&self) -> u64 {
        self.sat_vb
    }

    pub(crate) fn inventory(&self) -> &CompletedInventory {
        &self.bracket.inventory
    }

    /// The node's own maximum finalized size for `tx`, under the SAME derived weight
    /// both preflighted shapes were measured with.
    pub(crate) fn finalized_vsize(&self, tx: &Transaction) -> Result<u64, Error> {
        finalized_vsize(self.weight, tx)
    }
}

fn bad<T>(detail: String) -> Result<T, Error> {
    Err(detail.into())
}

/// Prepare the stable view: derive the vault's own scripts and weight, run the inventory
/// bracket, project the full parents, and only then read the fee signals.
///
/// `scripts` is `[destination, supplied vault change, base Escape]`. The supplied vault
/// change is a CHECK, not an input: it must equal the descriptor's own script — a
/// mismatch is terminal before any Core I/O — and the copy that survives is the one
/// derived here.
pub(crate) fn prepare_view(
    core: &dyn CoreView,
    network: Network,
    descriptor: &Descriptor<PublicKey>,
    scripts: [&ScriptBuf; 3],
) -> Result<PreparedView, Error> {
    // Derived from the sealed descriptor BEFORE any RPC: the script that is scanned, the
    // witness script every input map carries, and the weight both shapes are sized with.
    let vault_spk = descriptor.script_pubkey();
    let witness_script = descriptor.explicit_script()?;
    let weight = descriptor.max_weight_to_satisfy()?.to_wu();
    if *scripts[1] != vault_spk {
        return bad(
            "the supplied vault change script is not the one this sealed descriptor \
                    derives, so no Core read is issued"
                .into(),
        );
    }
    // ONE canonical triple: the caller's destination and Escape, and the vault change
    // this module derived. The supplied copy is dropped here and never stored.
    let canonical = [scripts[0].clone(), vault_spk.clone(), scripts[2].clone()];

    let mut accepted = None;
    for _ in 0..INVENTORY_PASSES {
        accepted = pass(core, network, &witness_script, &canonical, weight)?;
        if accepted.is_some() {
            break;
        }
    }
    let Some(bracket) = accepted else {
        return bad(format!(
            "the Core view did not hold still for {INVENTORY_PASSES} passes: the tip moved \
             during every inventory bracket"
        ));
    };

    // The fee signals are a LIVENESS snapshot taken after the accepted bracket and its
    // completed projection, not part of the coin-consistency proof: later floor movement
    // can make the pair slow or non-relaying, never redirect value.
    let estimate = core.fee_estimate()?;
    let floors = core.fee_floors()?;
    let floor = floors.incremental_relay.max(floors.mempool_min);
    let sat_kvb = estimate.map_or(floor, |estimate| estimate.max(floor));
    // Both node floors are checked but may be zero, and an absent estimate then yields a
    // zero primary rate. That is a LIVENESS fact about the node, not a policy this seam
    // invents.
    let sat_vb = sat_kvb.div_ceil(1000);
    Ok(PreparedView {
        bracket,
        weight,
        sat_vb,
    })
}

/// The two unsigned shapes over the prepared inputs, at final amounts:
/// `[paid to destination, kept as vault change, swept to the base Escape]`. It shares
/// [`build_pair`] with the zero-amount preflight, so a caller cannot re-supply UTXOs,
/// scripts, the witness script or an ordering of its own.
pub(crate) fn pair(prepared: &PreparedView, amounts: [Amount; 3]) -> Result<[Psbt; 2], Error> {
    build_pair(&prepared.bracket.shape, amounts)
}

/// ONE inventory bracket. `Ok(None)` means an observed tip moved, so the pass is
/// retryable; `Err` is terminal.
fn pass(
    core: &dyn CoreView,
    network: Network,
    witness_script: &ScriptBuf,
    scripts: &[ScriptBuf; 3],
    weight: u64,
) -> Result<Option<Bracket>, Error> {
    let info = core.chain_info()?;
    // The SHARED public-Signet-aware validator, against the explicit sealed network. Its
    // refusals interpolate the peer's own `chain`/`signet_challenge`, which a reflecting
    // Core fills with the credential — so only the verdict crosses this boundary.
    let sealed = vault_node::vault_network_name(network);
    vault_node::chain::verify_chain_identity(&info.identity, network)
        .map_err(|_| format!("this Core is not the sealed {sealed}; its own text is withheld"))?;
    if info.initial_block_download {
        return bad(
            "bitcoind is in initial block download: its confirmed vault view is \
                    stale, so no spend is prepared against it"
                .into(),
        );
    }
    let before = info.best_block;
    // The scanned script is the DERIVED one, carried in the canonical triple.
    let vault_spk = &scripts[1];
    let scan = core.scan_vault_script(vault_spk)?;
    // Step 2 binds the scan's OWN tip HERE, ahead of the stable-set refusals below, so a
    // set read across a reorg is retried rather than refused as though the chain had held
    // still. Movement observed LATER outranks the HELD contradictions alone, at the closing
    // tip; the classes the bead pins terminal — immaturity, size, projection — stay terminal.
    if scan.best_block != before {
        return Ok(None);
    }
    let mut tips = Vec::new();
    let coins = sorted_unique(scan.coins, vault_spk)?;
    // The owned canonical shape inputs, built ONCE per bracket and used for the preflight
    // below before being handed on unchanged.
    let shape = ShapeInputs {
        utxos: coins
            .iter()
            .map(|coin| Utxo {
                outpoint: coin.outpoint,
                txout: TxOut {
                    value: coin.value,
                    script_pubkey: coin.script.clone(),
                },
            })
            .collect(),
        witness_script: witness_script.clone(),
        scripts: scripts.clone(),
    };
    // The exact script/input-count skeletons, sized BEFORE any candidate or full-parent
    // RPC. Amounts are fixed-width, so these are the composed pair's own sizes.
    let [primary, escape] = build_pair(&shape, [Amount::ZERO; 3])?;
    let primary_vsize = finalized_vsize(weight, &primary.unsigned_tx)?;
    let escape_vsize = finalized_vsize(weight, &escape.unsigned_tx)?;

    let held = candidates(core, &coins, &mut tips)?;
    tips.push(core.best_block_hash()?);
    // Only observed TIP MOVEMENT makes a pass retryable, and it outranks every held
    // contradiction: a reorg explains all of them.
    if tips.iter().any(|tip| *tip != before) {
        return Ok(None);
    }
    match held {
        Err(stable) => bad(stable),
        Ok(parents) => Ok(Some(Bracket {
            shape,
            inventory: CompletedInventory { parents },
            primary_vsize,
            escape_vsize,
        })),
    }
}

/// The candidate half of a bracket: opening reads, parents grouped and projected, then
/// the closing reads. The INNER `Err` is a contradiction a tip move would explain, so it
/// is HELD until the caller reads the closing tip; the outer `Err` is terminal at once.
#[allow(clippy::type_complexity)]
fn candidates(
    core: &dyn CoreView,
    coins: &[ScanCoin],
    tips: &mut Vec<BlockHash>,
) -> Result<Result<BTreeMap<Txid, Transaction>, String>, Error> {
    let mut opening = Vec::with_capacity(coins.len());
    for coin in coins {
        let Some(view) = core.txout(coin.outpoint)? else {
            return Ok(Err(UNAVAILABLE.into()));
        };
        tips.push(view.best_block);
        // Immaturity is a STABLE fact about a coinbase and is terminal; confirmedness
        // and the value/script pair are cross-source agreement, which a reorg explains.
        if view.coinbase && view.confirmations < COINBASE_MATURITY {
            return bad(format!(
                "a scanned vault coin is an immature coinbase at {} of {COINBASE_MATURITY} \
                 confirmations",
                view.confirmations
            ));
        }
        if view.confirmations == 0 || view.value != coin.value || view.script != coin.script {
            return Ok(Err("a gettxout read contradicts its scan record".into()));
        }
        opening.push(view);
    }

    // GROUPED by parent before fetching, so a parent funding several selected coins is
    // fetched once and its bytes counted with its multiplicity.
    let mut groups: BTreeMap<Txid, Vec<usize>> = BTreeMap::new();
    for (index, coin) in coins.iter().enumerate() {
        groups.entry(coin.outpoint.txid).or_default().push(index);
    }
    let mut parents = BTreeMap::new();
    let mut projected = 0u64;
    for (txid, members) in groups {
        let height = coins[members[0]].height;
        let Some(block) = core.block_hash(height)? else {
            return Ok(Err(format!("no block at scanned height {height}")));
        };
        let Some(parent) = core.block_transaction(txid, block)? else {
            return Ok(Err(
                "a scanned parent is absent from the block at its scanned height".into(),
            ));
        };
        // The projection is INCREMENTAL and duplicated across both PSBT input-map sets,
        // and it is checked before this parent is retained: on refusal the in-flight
        // parent drops here and no later `getrawtransaction` is issued.
        let bytes = u64::try_from(parent.total_size())
            .ok()
            .and_then(|size| size.checked_mul(2 * members.len() as u64))
            .and_then(|both| projected.checked_add(both))
            .ok_or("projected full-prevtx bytes overflow")?;
        if bytes > MAX_COMPOSER_FULL_PREVTX_BYTES {
            return bad(format!(
                "the selected coins project {bytes} gross full-prevtx bytes across both PSBT \
                 sets, over the {MAX_COMPOSER_FULL_PREVTX_BYTES} byte bound"
            ));
        }
        projected = bytes;
        if parent.compute_txid() != txid {
            return Ok(Err("a fetched full transaction hashes elsewhere".into()));
        }
        for index in members {
            let vout = coins[index].outpoint.vout as usize;
            let agrees = parent.output.get(vout).is_some_and(|out| {
                out.value == coins[index].value && out.script_pubkey == coins[index].script
            });
            if !agrees {
                return Ok(Err(format!(
                    "a fetched full transaction contradicts vout {vout}"
                )));
            }
        }
        // MOVED, never cloned: the only copy this bracket makes is the one
        // [`CompletedInventory::full_parent`] hands out after acceptance.
        parents.insert(txid, parent);
    }

    // The CLOSING read of every selected candidate.
    for (coin, opened) in coins.iter().zip(&opening) {
        let Some(view) = core.txout(coin.outpoint)? else {
            return Ok(Err(UNAVAILABLE.into()));
        };
        tips.push(view.best_block);
        if view.value != opened.value || view.script != opened.script {
            return Ok(Err(
                "a vault coin changed between its opening and closing read".into(),
            ));
        }
    }
    Ok(Ok(parents))
}

/// The stage-1 coverage refusal. Under ONE unmoved tip a scanned confirmed vault coin
/// that is gone from the UTXO set is mempool-spent or otherwise unavailable. Confirmation
/// is not the remedy — the conflicting spend may never confirm — so the guidance is
/// reconciliation, and `btc-policy-w2b` owns composing over authorized-unconfirmed value.
const UNAVAILABLE: &str = "a scanned confirmed vault coin is absent from the UTXO set at the \
     same tip: it is spent in the mempool or otherwise unavailable. This composer spends every \
     confirmed vault coin, so the whole command is refused rather than composing an \
     under-covered escape from the remainder. Do not reissue until independent chain \
     reconciliation accounts for that coin.";

/// Canonical outpoint order, no duplicate, nothing off the one definite vault script,
/// and a nonempty set. All four are stable facts, so all four are terminal.
fn sorted_unique(mut coins: Vec<ScanCoin>, vault_spk: &ScriptBuf) -> Result<Vec<ScanCoin>, Error> {
    coins.sort_by_key(|coin| coin.outpoint);
    if coins
        .windows(2)
        .any(|pair| pair[0].outpoint == pair[1].outpoint)
    {
        return bad("scantxoutset reported one outpoint twice".into());
    }
    if coins.iter().any(|coin| coin.script != *vault_spk) {
        return bad(
            "scantxoutset returned a record that does not pay the definite vault script".into(),
        );
    }
    if coins.is_empty() {
        return bad("the sealed vault holds no confirmed coin to spend".into());
    }
    Ok(coins)
}

/// The SHARED private builder: the two unsigned shapes over the SAME ordered inputs, the
/// primary paying `[destination, vault change]` and the one-output base Escape. Both the
/// zero-amount preflight and the crate-visible [`pair`] come through here, over the same
/// owned [`ShapeInputs`]. `fed::build_spend_n` is reused for its pinned transaction shape
/// alone and is neither extended nor re-pointed — the demo and attack callers keep it —
/// and [`check_shape`] refuses any drift in what it returns.
fn build_pair(shape: &ShapeInputs, [paid, kept, swept]: [Amount; 3]) -> Result<[Psbt; 2], Error> {
    let [destination, change, escape] = &shape.scripts;
    let primary = [(destination.clone(), paid), (change.clone(), kept)];
    let built = [
        build_spend_n(&shape.utxos, &shape.witness_script, &primary)?,
        build_spend_n(
            &shape.utxos,
            &shape.witness_script,
            &[(escape.clone(), swept)],
        )?,
    ];
    for psbt in &built {
        check_shape(&psbt.unsigned_tx)?;
    }
    Ok(built)
}

/// The pinned unsigned form both shapes must have.
fn check_shape(tx: &Transaction) -> Result<(), Error> {
    let unsigned = tx.input.iter().all(|input| {
        input.sequence == Sequence::MAX && input.script_sig.is_empty() && input.witness.is_empty()
    });
    if tx.input.is_empty()
        || !unsigned
        || tx.version != Version::TWO
        || tx.lock_time != LockTime::ZERO
    {
        return bad(
            "a composed shape is not the pinned version 2, lock 0, final unsigned \
                    form over a nonempty input set"
                .into(),
        );
    }
    Ok(())
}

/// The maximum finalized vsize the node's own bound computes, refused above
/// [`MAX_COMPOSER_VSIZE`]. Equality passes.
fn finalized_vsize(weight: u64, tx: &Transaction) -> Result<u64, Error> {
    let vsize = vault_node::maximum_finalized_vsize_for(weight, tx)?;
    if vsize > MAX_COMPOSER_VSIZE {
        return bad(format!(
            "a composed shape reaches {vsize} vB finalized, over the {MAX_COMPOSER_VSIZE} vB \
             bound"
        ));
    }
    Ok(vsize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core_view::{ChainInfo, Floors, Scan, TxOutView};
    use crate::sealed::LiveVault;
    use crate::setup::tests::{ceremony_through_endorse, Ceremony};
    use bitcoin::base64::prelude::{Engine as _, BASE64_STANDARD};
    use bitcoin::{OutPoint, TxIn, Witness};
    use miniscript::DescriptorPublicKey;
    use serde_json::{json, Value};
    use std::cell::{Cell, RefCell};
    use std::collections::{BTreeSet, HashMap};
    use std::str::FromStr;
    use std::sync::OnceLock;
    use std::time::Instant;

    /// One vault coin, and the amount most classes pay out of it.
    const COIN: u64 = 1_000_000;
    const PAID: u64 = 50_000;
    /// The scanned confirmation height every fake coin carries.
    const HEIGHT: u32 = 411;

    /// Test-only: this thread's full-parent clone count, and its reset. `cargo test`
    /// normally gives each test its own thread, but `--test-threads=1` need not, so the
    /// clone-observing classes reset before they measure rather than assuming.
    fn parent_clones() -> u64 {
        PARENT_CLONES.with(Cell::get)
    }

    fn reset_parent_clones() {
        PARENT_CLONES.with(|clones| clones.set(0));
    }

    struct Fixture {
        _ceremony: Ceremony,
        artifacts: std::path::PathBuf,
    }

    /// ONE sealed set for every class: provisioning a federation is expensive and
    /// identical for all of them, so each class RE-READS the artifacts the production
    /// ceremony wrote rather than re-running it.
    fn fixture() -> &'static Fixture {
        static FIXTURE: OnceLock<Fixture> = OnceLock::new();
        FIXTURE.get_or_init(|| {
            let ceremony = ceremony_through_endorse(3, 2);
            ceremony.finalize().expect("finalize");
            let artifacts = ceremony.sealed("backup");
            Fixture {
                _ceremony: ceremony,
                artifacts,
            }
        })
    }

    /// The three scripts a caller supplies, read out of the sealed vault itself, plus the
    /// two values `prepare_view` derives INTERNALLY and this fixture only mirrors so a
    /// class can measure against them independently.
    struct Parts {
        vault: ScriptBuf,
        escape: ScriptBuf,
        destination: ScriptBuf,
        witness: ScriptBuf,
        weight: u64,
    }

    impl Parts {
        /// `[destination, supplied vault change, base Escape]`, the seam's own order.
        fn scripts(&self) -> [&ScriptBuf; 3] {
            [&self.destination, &self.vault, &self.escape]
        }
    }

    fn definite(d: &Descriptor<DescriptorPublicKey>, index: u32) -> ScriptBuf {
        d.at_derivation_index(index)
            .expect("definite")
            .script_pubkey()
    }

    fn sealed() -> (LiveVault, Parts) {
        let vault = LiveVault::load_artifacts(&fixture().artifacts).expect("the sealed set");
        let escape = vault.check_params.escape.as_ref().expect("an escape");
        let parts = Parts {
            vault: vault.descriptor.script_pubkey(),
            escape: definite(escape, 0),
            destination: definite(&vault.check_params.allowed[0], 0),
            witness: vault.descriptor.explicit_script().expect("witness script"),
            weight: vault
                .descriptor
                .max_weight_to_satisfy()
                .expect("weight")
                .to_wu(),
        };
        (vault, parts)
    }

    /// A previous transaction paying `outputs`, made unique by `tag`.
    fn prevtx(tag: u32, outputs: &[(&ScriptBuf, u64)]) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::from_consensus(tag),
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: outputs
                .iter()
                .map(|(script, value)| TxOut {
                    script_pubkey: (*script).clone(),
                    value: Amount::from_sat(*value),
                })
                .collect(),
        }
    }

    /// The unsigned shape a class sizes INDEPENDENTLY of this module: built here from the
    /// library types directly, then measured with the node's own bound.
    fn shape(inputs: &[OutPoint], outputs: &[(&ScriptBuf, u64)]) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: inputs
                .iter()
                .map(|outpoint| TxIn {
                    previous_output: *outpoint,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                })
                .collect(),
            output: outputs
                .iter()
                .map(|(script, value)| TxOut {
                    script_pubkey: (*script).clone(),
                    value: Amount::from_sat(*value),
                })
                .collect(),
        }
    }

    /// The two shapes' maximum finalized vsizes, hand-built and measured with
    /// `vault_node`'s own bound rather than with anything this module computes.
    fn measured(parts: &Parts, coins: &[OutPoint]) -> (u64, u64) {
        let primary = shape(coins, &[(&parts.destination, 1), (&parts.vault, 1)]);
        let escape = shape(coins, &[(&parts.escape, 1)]);
        let of = |tx: &Transaction| {
            vault_node::maximum_finalized_vsize_for(parts.weight, tx).expect("vsize")
        };
        (of(&primary), of(&escape))
    }

    /// A scripted read-only Core. The default world is ONE honest chain that does not
    /// move; each class sets the one field that is its deviation. Every call is logged
    /// in order, so a class can pin what was issued AND what never was.
    struct Fake {
        identity: Value,
        ibd: bool,
        tip: BlockHash,
        coins: Vec<ScanCoin>,
        parents: BTreeMap<Txid, Transaction>,
        confirmations: u64,
        coinbase: bool,
        /// `scantxoutset` bestblock deviations, keyed by that call's 0-based ordinal.
        scan_tip: HashMap<usize, BlockHash>,
        /// `gettxout` deviations, keyed by that call's 0-based ordinal over the run.
        null_at: BTreeSet<usize>,
        value_at: HashMap<usize, Amount>,
        script_at: HashMap<usize, ScriptBuf>,
        tip_at: HashMap<usize, BlockHash>,
        confirmations_at: HashMap<usize, u64>,
        /// `getbestblockhash` deviations, keyed the same way.
        after_at: HashMap<usize, BlockHash>,
        no_block: bool,
        no_history: bool,
        estimate: Option<u64>,
        estimate_fails: bool,
        floors: Option<(u64, u64)>,
        log: RefCell<Vec<String>>,
        txouts: Cell<usize>,
        tips: Cell<usize>,
        scans: Cell<usize>,
    }

    fn hash(byte: u8) -> BlockHash {
        BlockHash::from_str(&format!("{byte:02x}").repeat(32)).expect("a block hash")
    }

    impl Fake {
        /// A world funded by `funding`, each entry one `(previous transaction, vout)`
        /// paying the vault.
        fn over(funding: &[(&Transaction, u32)]) -> Fake {
            let mut coins = Vec::new();
            let mut parents = BTreeMap::new();
            for (parent, vout) in funding {
                let out = &parent.output[*vout as usize];
                coins.push(ScanCoin {
                    outpoint: OutPoint {
                        txid: parent.compute_txid(),
                        vout: *vout,
                    },
                    value: out.value,
                    script: out.script_pubkey.clone(),
                    height: HEIGHT,
                });
                parents.insert(parent.compute_txid(), (*parent).clone());
            }
            Fake {
                identity: json!({"chain": "regtest"}),
                ibd: false,
                tip: hash(0x11),
                coins,
                parents,
                confirmations: 6,
                coinbase: false,
                scan_tip: HashMap::new(),
                null_at: BTreeSet::new(),
                value_at: HashMap::new(),
                script_at: HashMap::new(),
                tip_at: HashMap::new(),
                confirmations_at: HashMap::new(),
                after_at: HashMap::new(),
                no_block: false,
                no_history: false,
                estimate: None,
                estimate_fails: false,
                // 1000 sat/kvB on both floors: a round fixture value that makes the
                // sat/kvB -> sat/vB conversion 1 sat/vB, NOT a claim about Core's own
                // default. That default moves between releases — the pinned daemon
                // reports 100 sat/kvB — so what it is belongs in the live suite, which
                // asserts it against the number the daemon itself reports.
                floors: Some((1_000, 1_000)),
                log: RefCell::new(Vec::new()),
                txouts: Cell::new(0),
                tips: Cell::new(0),
                scans: Cell::new(0),
            }
        }

        /// One coin of `value` from its own parent.
        fn holding(parts: &Parts, values: &[u64]) -> (Vec<Transaction>, Fake) {
            let parents: Vec<Transaction> = values
                .iter()
                .enumerate()
                .map(|(tag, value)| prevtx(tag as u32, &[(&parts.vault, *value)]))
                .collect();
            let funding: Vec<(&Transaction, u32)> =
                parents.iter().map(|parent| (parent, 0u32)).collect();
            let fake = Fake::over(&funding);
            (parents, fake)
        }

        fn note(&self, call: String) {
            self.log.borrow_mut().push(call);
        }

        /// Every call in order, argument and all.
        fn calls(&self) -> Vec<String> {
            self.log.borrow().clone()
        }

        /// Just the RPC names, in order.
        fn methods(&self) -> Vec<String> {
            self.calls()
                .iter()
                .map(|call| call.split(' ').next().unwrap_or_default().to_string())
                .collect()
        }

        fn issued(&self, method: &str) -> usize {
            self.methods().iter().filter(|name| *name == method).count()
        }
    }

    impl CoreView for Fake {
        fn chain_info(&self) -> Result<ChainInfo, Error> {
            self.note("getblockchaininfo".into());
            Ok(ChainInfo {
                identity: self.identity.clone(),
                initial_block_download: self.ibd,
                best_block: self.tip,
            })
        }

        fn best_block_hash(&self) -> Result<BlockHash, Error> {
            self.note("getbestblockhash".into());
            let ordinal = self.tips.get();
            self.tips.set(ordinal + 1);
            Ok(*self.after_at.get(&ordinal).unwrap_or(&self.tip))
        }

        fn scan_vault_script(&self, script: &ScriptBuf) -> Result<Scan, Error> {
            self.note(format!("scantxoutset {script:x}"));
            let coins = self
                .coins
                .iter()
                .map(|coin| ScanCoin {
                    outpoint: coin.outpoint,
                    value: coin.value,
                    script: coin.script.clone(),
                    height: coin.height,
                })
                .collect();
            let ordinal = self.scans.get();
            self.scans.set(ordinal + 1);
            Ok(Scan {
                best_block: *self.scan_tip.get(&ordinal).unwrap_or(&self.tip),
                coins,
            })
        }

        fn txout(&self, outpoint: OutPoint) -> Result<Option<TxOutView>, Error> {
            self.note(format!("gettxout {outpoint}"));
            let ordinal = self.txouts.get();
            self.txouts.set(ordinal + 1);
            if self.null_at.contains(&ordinal) {
                return Ok(None);
            }
            let coin = self
                .coins
                .iter()
                .find(|coin| coin.outpoint == outpoint)
                .ok_or("the fake holds no such coin")?;
            Ok(Some(TxOutView {
                best_block: *self.tip_at.get(&ordinal).unwrap_or(&self.tip),
                confirmations: *self
                    .confirmations_at
                    .get(&ordinal)
                    .unwrap_or(&self.confirmations),
                value: *self.value_at.get(&ordinal).unwrap_or(&coin.value),
                script: self
                    .script_at
                    .get(&ordinal)
                    .cloned()
                    .unwrap_or_else(|| coin.script.clone()),
                coinbase: self.coinbase,
            }))
        }

        fn block_hash(&self, height: u32) -> Result<Option<BlockHash>, Error> {
            self.note(format!("getblockhash {height}"));
            match self.no_block {
                true => Ok(None),
                false => Ok(Some(hash(0x77))),
            }
        }

        fn block_transaction(
            &self,
            txid: Txid,
            block: BlockHash,
        ) -> Result<Option<Transaction>, Error> {
            self.note(format!("getrawtransaction {txid} in {block}"));
            if self.no_history {
                return Ok(None);
            }
            let parent = self
                .parents
                .get(&txid)
                .ok_or("the fake holds no such parent")?;
            Ok(Some(parent.clone()))
        }

        fn fee_estimate(&self) -> Result<Option<u64>, Error> {
            self.note("estimatesmartfee".into());
            match self.estimate_fails {
                true => Err("core estimatesmartfee: refused".into()),
                false => Ok(self.estimate),
            }
        }

        fn fee_floors(&self) -> Result<Floors, Error> {
            self.note("getmempoolinfo".into());
            let (incremental_relay, mempool_min) = self
                .floors
                .ok_or("core reply: getmempoolinfo mempoolminfee is not a number")?;
            Ok(Floors {
                incremental_relay,
                mempool_min,
            })
        }
    }

    /// One class's single deviation from the honest default world, applied to a fake
    /// before the seam reads it.
    type Inject = Box<dyn Fn(&mut Fake)>;

    fn prepared(vault: &LiveVault, core: &Fake, parts: &Parts) -> PreparedView {
        prepare_view(core, vault.network, &vault.descriptor, parts.scripts())
            .unwrap_or_else(|e| panic!("the view must prepare: {e}"))
    }

    fn refused(vault: &LiveVault, core: &Fake, parts: &Parts, what: &str) -> String {
        match prepare_view(core, vault.network, &vault.descriptor, parts.scripts()) {
            Ok(_) => panic!("{what} must be refused"),
            Err(e) => e.to_string(),
        }
    }

    /// The canonical outpoints of `parents`, vout 0 each, in sorted order.
    fn canonical(parents: &[Transaction]) -> Vec<OutPoint> {
        let mut sorted: Vec<OutPoint> = parents
            .iter()
            .map(|parent| OutPoint {
                txid: parent.compute_txid(),
                vout: 0,
            })
            .collect();
        sorted.sort();
        sorted
    }

    /// 1. The FROZEN unsigned shape, shared by the zero-amount preflight and the final
    ///    amounts: two version-2, lock-0, `Sequence::MAX` transactions over the SAME
    ///    canonically ordered nonempty inputs, the primary paying exactly `[destination,
    ///    vault change]` and the base Escape exactly one output, every input map carrying
    ///    the canonical `witness_utxo` and the sealed `witness_script` — and NEITHER of
    ///    M3b's two attachments. The vault-change script the CALLER supplies is a check
    ///    that runs before any Core I/O, not an input: what is stored and paid is the one
    ///    this module derived from the sealed descriptor.
    #[test]
    fn the_prepared_pair_is_the_frozen_shape_at_preflight_and_at_final_amounts() {
        let (vault, parts) = sealed();
        let (parents, core) = Fake::holding(&parts, &[COIN, COIN / 2]);
        let view = prepared(&vault, &core, &parts);
        let sorted = canonical(&parents);

        // The canonical inputs, and the canonical script triple with the DERIVED vault
        // change in the middle.
        let held: Vec<OutPoint> = view.utxos().iter().map(|utxo| utxo.outpoint).collect();
        assert_eq!(held, sorted, "the canonical order is what is stored");
        assert_eq!(
            view.scripts(),
            &[
                parts.destination.clone(),
                parts.vault.clone(),
                parts.escape.clone()
            ]
        );
        let (primary_vsize, escape_vsize) = measured(&parts, &sorted);
        assert_eq!(view.preflight_vsizes(), [primary_vsize, escape_vsize]);

        // The final amounts, through the same private builder the preflight used.
        let amounts = [
            Amount::from_sat(PAID),
            Amount::from_sat(COIN),
            Amount::from_sat(COIN / 2),
        ];
        let [spend, escape] = pair(&view, amounts).expect("the pinned pair");
        let expected: [Vec<(ScriptBuf, u64)>; 2] = [
            vec![
                (parts.destination.clone(), PAID),
                (parts.vault.clone(), COIN),
            ],
            vec![(parts.escape.clone(), COIN / 2)],
        ];
        for (label, psbt, outputs) in [
            ("primary", &spend, &expected[0]),
            ("escape", &escape, &expected[1]),
        ] {
            let tx = &psbt.unsigned_tx;
            assert_eq!(tx.version, Version::TWO, "{label}");
            assert_eq!(tx.lock_time, LockTime::ZERO, "{label}");
            let spent: Vec<OutPoint> = tx.input.iter().map(|i| i.previous_output).collect();
            assert_eq!(spent, sorted, "{label} spends the sorted vault set");
            for input in &tx.input {
                assert_eq!(input.sequence, Sequence::MAX, "{label}");
                assert!(
                    input.script_sig.is_empty() && input.witness.is_empty(),
                    "{label}"
                );
            }
            let paid: Vec<(ScriptBuf, u64)> = tx
                .output
                .iter()
                .map(|out| (out.script_pubkey.clone(), out.value.to_sat()))
                .collect();
            assert_eq!(&paid, outputs, "{label}");
            for (index, map) in psbt.inputs.iter().enumerate() {
                assert_eq!(
                    map.witness_utxo.as_ref(),
                    Some(&view.utxos()[index].txout),
                    "{label}"
                );
                assert_eq!(map.witness_script.as_ref(), Some(&parts.witness), "{label}");
                // M3b owns both of these, and this child must not be the one that
                // attaches them: an input map that already carried a full parent would
                // put every projected byte in memory here instead of there.
                assert!(map.non_witness_utxo.is_none(), "{label}");
                assert!(map.sighash_type.is_none(), "{label}");
            }
        }
        // The final shapes are the preflighted ones, measured with the stored weight.
        assert_eq!(
            [
                view.finalized_vsize(&spend.unsigned_tx).expect("primary"),
                view.finalized_vsize(&escape.unsigned_tx).expect("escape"),
            ],
            [primary_vsize, escape_vsize]
        );

        // A supplied vault-change script that is not the descriptor's own is terminal
        // BEFORE any Core I/O — and the honest supply above is the adjacent control.
        let (_, untouched) = Fake::holding(&parts, &[COIN]);
        let mismatched = [&parts.destination, &parts.escape, &parts.escape];
        let error = prepare_view(&untouched, vault.network, &vault.descriptor, mismatched)
            .err()
            .expect("a foreign vault change script must be refused")
            .to_string();
        assert!(
            error.contains("not the one this sealed descriptor derives"),
            "{error}"
        );
        assert!(
            untouched.methods().is_empty(),
            "no Core read may be issued: {:?}",
            untouched.methods()
        );
    }

    /// 2. The scan's ORDER never reaches the prepared shape, and the three ways a scan
    ///    record set can be unusable are all refused before anything is opened — but only
    ///    once the scan's own `bestblock` has been bound to the before tip, so an unusable
    ///    set read across an observed reorg is retried rather than refused.
    #[test]
    fn the_scan_order_never_reaches_the_pair_and_an_unusable_record_set_is_refused() {
        let (vault, parts) = sealed();
        let (_, core) = Fake::holding(&parts, &[COIN, COIN / 2, COIN / 4]);
        let view = prepared(&vault, &core, &parts);

        let (_, mut reversed) = Fake::holding(&parts, &[COIN, COIN / 2, COIN / 4]);
        reversed.coins.reverse();
        let other = prepared(&vault, &reversed, &parts);
        let zero = [Amount::ZERO; 3];
        let [spend, escape] = pair(&view, zero).expect("a pair");
        let [other_spend, other_escape] = pair(&other, zero).expect("a pair");
        assert_eq!(
            spend.unsigned_tx, other_spend.unsigned_tx,
            "scan order leaked"
        );
        assert_eq!(
            escape.unsigned_tx, other_escape.unsigned_tx,
            "scan order leaked"
        );
        // The order the seam READ them in is the canonical one either way.
        let held: Vec<OutPoint> = spend
            .unsigned_tx
            .input
            .iter()
            .map(|input| input.previous_output)
            .collect();
        let mut sorted = held.clone();
        sorted.sort();
        assert_eq!(held, sorted);

        let (_, mut duplicated) = Fake::holding(&parts, &[COIN, COIN / 2]);
        let first = &duplicated.coins[0];
        duplicated.coins.push(ScanCoin {
            outpoint: first.outpoint,
            value: first.value,
            script: first.script.clone(),
            height: first.height,
        });
        let error = refused(&vault, &duplicated, &parts, "a duplicate scan record");
        assert!(error.contains("twice"), "{error}");

        let (_, mut foreign) = Fake::holding(&parts, &[COIN, COIN / 2]);
        foreign.coins[1].script = parts.escape.clone();
        let error = refused(&vault, &foreign, &parts, "an off-vault scan record");
        assert!(
            error.contains("does not pay the definite vault script"),
            "{error}"
        );

        let (_, mut empty) = Fake::holding(&parts, &[COIN]);
        empty.coins.clear();
        let error = refused(&vault, &empty, &parts, "an empty vault");
        assert!(error.contains("no confirmed coin"), "{error}");
        // None of the three reached a candidate read or a fee signal.
        for core in [&duplicated, &foreign, &empty] {
            assert_eq!(core.methods(), ["getblockchaininfo", "scantxoutset"]);
        }

        // Step 2 binds the scan's OWN bestblock BEFORE all three of those refusals. Each
        // set is terminal only when the chain held still; read across a MOVED scan tip the
        // same set is retried, because a reorg explains an inventory that arrived empty,
        // doubled or off-script just as well as it explains a contradictory candidate. The
        // still-tip run in each row is the adjacent positive control at one scan.
        let moved = hash(0x44);
        let unusable: [(&str, Inject); 3] = [
            (
                "a duplicate scan record",
                Box::new(|f: &mut Fake| {
                    let first = &f.coins[0];
                    let copy = ScanCoin {
                        outpoint: first.outpoint,
                        value: first.value,
                        script: first.script.clone(),
                        height: first.height,
                    };
                    f.coins.push(copy);
                }),
            ),
            (
                "an off-vault scan record",
                Box::new({
                    let elsewhere = parts.escape.clone();
                    move |f: &mut Fake| f.coins[1].script = elsewhere.clone()
                }),
            ),
            ("an empty vault", Box::new(|f: &mut Fake| f.coins.clear())),
        ];
        for (what, inject) in unusable {
            let (_, mut still) = Fake::holding(&parts, &[COIN, COIN / 2]);
            inject(&mut still);
            refused(&vault, &still, &parts, what);
            assert_eq!(
                still.issued("scantxoutset"),
                1,
                "{what} under a still tip is terminal at once"
            );

            let (_, mut moving) = Fake::holding(&parts, &[COIN, COIN / 2]);
            inject(&mut moving);
            moving.scan_tip = HashMap::from([(0, moved)]);
            let error = refused(&vault, &moving, &parts, what);
            assert_eq!(
                moving.issued("scantxoutset"),
                2,
                "{what} across a moved scan tip must be retried, not refused: {error}"
            );
        }
    }

    /// 4A-primary. The rate this seam returns takes the MAXIMUM of the estimate (when
    /// present) and both mandatory floors, then ceil-divides sat/kvB to INTEGER sat/vB.
    /// The unit is the guarantee: M3b's sealed Escape floor is already sat/vB, and there
    /// is no sat/kvB value here for it to be compared against too early. `core_view.rs`
    /// class 4 owns the checked BTC conversion each of these numbers arrives through, and
    /// its 4A-precision half owns the measured `f64` residual.
    #[test]
    fn the_primary_rate_is_the_estimate_and_both_floors_ceiled_to_integer_sat_per_vbyte() {
        let (vault, parts) = sealed();
        // (estimate sat/kvB, incremental sat/kvB, mempoolmin sat/kvB) -> sat/vB.
        let rows: [(Option<u64>, u64, u64, u64); 6] = [
            // No estimate at all: the node floors alone price it.
            (None, 1_000, 1_000, 1),
            (Some(3_000), 1_000, 1_000, 3),
            (Some(1_000), 7_000, 1_000, 7),
            (Some(1_000), 1_000, 9_000, 9),
            // Ceil, not truncate: a 2001 sat/kvB signal is 3 sat/vB, never 2.
            (Some(2_001), 1_000, 1_000, 3),
            // And the converted number is what leaves: 2000 sat/kvB is 2 sat/vB, so a
            // sealed 5 sat/vB Escape floor downstream cannot lose to a stale 2000.
            (Some(2_000), 1_000, 1_000, 2),
        ];
        for (estimate, incremental, mempool_min, rate) in rows {
            let (_, mut core) = Fake::holding(&parts, &[COIN]);
            core.estimate = estimate;
            core.floors = Some((incremental, mempool_min));
            let view = prepared(&vault, &core, &parts);
            assert_eq!(
                view.sat_per_vb(),
                rate,
                "primary {estimate:?}/{incremental}/{mempool_min}"
            );
            assert_eq!(core.issued("estimatesmartfee"), 1);
            assert_eq!(core.issued("getmempoolinfo"), 1);
        }
    }

    /// 5. The fee signals are read ONCE, AFTER an accepted bracket and its completed
    ///    projection, and a broken one fails the whole preparation: an `estimatesmartfee`
    ///    that REFUSES is not the absent estimate its sibling row falls back from, and
    ///    neither mempool floor defaults.
    #[test]
    fn a_broken_fee_signal_is_terminal_and_no_fee_is_read_before_the_bracket_closes() {
        let (vault, parts) = sealed();
        let (_, mut broken) = Fake::holding(&parts, &[COIN]);
        broken.estimate_fails = true;
        let error = refused(&vault, &broken, &parts, "a refusing estimate");
        assert!(error.contains("estimatesmartfee"), "{error}");
        // Read once, and only after the whole bracket closed.
        let methods = broken.methods();
        assert_eq!(
            methods.iter().filter(|m| *m == "estimatesmartfee").count(),
            1
        );
        let fees = methods
            .iter()
            .position(|m| m == "estimatesmartfee")
            .expect("read");
        let closed = methods
            .iter()
            .position(|m| m == "getbestblockhash")
            .expect("closed");
        let parent = methods
            .iter()
            .rposition(|m| m == "getrawtransaction")
            .expect("a parent");
        assert!(
            fees > closed && fees > parent,
            "the fee reads follow the whole bracket: {methods:?}"
        );

        let (_, mut floorless) = Fake::holding(&parts, &[COIN]);
        floorless.floors = None;
        let error = refused(&vault, &floorless, &parts, "a missing mempool floor");
        assert!(error.contains("getmempoolinfo"), "{error}");
        assert_eq!(floorless.issued("getmempoolinfo"), 1);
    }

    /// 10. The 100,000 vB bound is checked on BOTH exact skeletons after the scan and
    ///     BEFORE any candidate or full-parent RPC: equality passes, one more input
    ///     refuses, and the refusing run issued nothing but the identity read and the
    ///     scan. A fragmented donor cannot make this seam walk a million RPCs.
    #[test]
    fn the_hundred_thousand_vbyte_bound_is_checked_before_any_candidate_or_parent_rpc() {
        let (vault, parts) = sealed();
        let anchor = prevtx(0, &[(&parts.vault, COIN)]).compute_txid();
        let vsize = |inputs: usize| -> u64 {
            let held: Vec<OutPoint> = (0..inputs)
                .map(|vout| OutPoint {
                    txid: anchor,
                    vout: vout as u32,
                })
                .collect();
            let (primary, escape) = measured(&parts, &held);
            primary.max(escape)
        };
        let mut largest = 1;
        while vsize(largest + 1) <= MAX_COMPOSER_VSIZE {
            largest += 1;
        }
        assert!(vsize(largest) <= MAX_COMPOSER_VSIZE, "the boundary");
        assert!(vsize(largest + 1) > MAX_COMPOSER_VSIZE, "one past it");

        let (_, fits) = Fake::holding(&parts, &vec![COIN; largest]);
        prepared(&vault, &fits, &parts);
        let (_, over) = Fake::holding(&parts, &vec![COIN; largest + 1]);
        let error = refused(&vault, &over, &parts, "an over-size input set");
        assert!(error.contains("vB finalized, over the"), "{error}");
        assert_eq!(
            over.methods(),
            ["getblockchaininfo", "scantxoutset"],
            "no candidate or parent RPC may be issued once the shape is too big"
        );
    }

    /// 11. THREE total passes, taken back to back. A pass whose observed tip moved is
    ///     retried immediately — pass 2 and pass 3 each recover here — and a third
    ///     unstable pass is one typed refusal. There is no sleep, no backoff, no nested
    ///     retry and no global mempool-quiescence read: the whole three-pass refusal
    ///     completes in milliseconds and issues nothing outside the closed eight.
    #[test]
    fn three_passes_recover_from_tip_movement_and_the_third_unstable_one_refuses() {
        let (vault, parts) = sealed();
        let moved = hash(0x22);

        let (_, mut second) = Fake::holding(&parts, &[COIN]);
        second.null_at = BTreeSet::from([0]);
        second.after_at = HashMap::from([(0, moved)]);
        prepared(&vault, &second, &parts);
        assert_eq!(second.issued("getblockchaininfo"), 2, "one retry");

        let (_, mut third) = Fake::holding(&parts, &[COIN]);
        third.null_at = BTreeSet::from([0, 1]);
        third.after_at = HashMap::from([(0, moved), (1, moved)]);
        prepared(&vault, &third, &parts);
        assert_eq!(third.issued("getblockchaininfo"), 3, "two retries");

        // Wall clock is the only observable a `thread::sleep` or a backoff shows up in, so
        // the measurement stays — but the FASTEST of several identical runs is what is
        // asserted, not one run's. A sleep or backoff in any pass lengthens EVERY run,
        // while a scheduler pause on a loaded host lengthens one; taking the minimum tells
        // those apart, and buys a bound ten times tighter than one run could carry.
        let unstable = HashMap::from([(0, moved), (1, moved), (2, moved)]);
        let mut elapsed = std::time::Duration::MAX;
        for _ in 0..5 {
            let (_, mut run) = Fake::holding(&parts, &[COIN]);
            run.after_at = unstable.clone();
            let started = Instant::now();
            refused(&vault, &run, &parts, "a view that never settles");
            elapsed = elapsed.min(started.elapsed());
        }

        let (_, mut never) = Fake::holding(&parts, &[COIN]);
        never.after_at = unstable;
        let error = refused(&vault, &never, &parts, "a view that never settles");
        assert!(error.contains("did not hold still for 3 passes"), "{error}");
        assert_eq!(
            never.issued("getblockchaininfo"),
            3,
            "exactly three, never a fourth"
        );
        assert_eq!(
            never.issued("estimatesmartfee"),
            0,
            "no fee read after an unstable view"
        );
        assert!(
            elapsed < std::time::Duration::from_millis(50),
            "a sleep, backoff or nested retry would not fit in {elapsed:?}, the fastest \
             of five identical three-pass refusals"
        );
        // The closed capability, observed: every call any pass made is one of the eight,
        // and nothing asks the mempool as a whole whether it is quiet.
        let closed = [
            "getblockchaininfo",
            "getbestblockhash",
            "scantxoutset",
            "gettxout",
            "getblockhash",
            "getrawtransaction",
            "estimatesmartfee",
            "getmempoolinfo",
        ];
        for core in [&second, &third, &never] {
            for method in core.methods() {
                assert!(
                    closed.contains(&method.as_str()),
                    "{method} is outside the seam"
                );
            }
        }
    }

    /// 12. The EXACT precedence: only observed tip movement makes a pass retryable, it
    ///     outranks every held contradiction, and the terminal classes outrank both.
    ///     Each row runs twice over the same injection — once against a tip that never
    ///     moves, once against one that moves in every pass — so "held" and "terminal"
    ///     are told apart by what the second run answers, not by reading the code.
    #[test]
    fn only_observed_tip_movement_makes_a_pass_retryable_and_terminal_outranks_both() {
        let (vault, parts) = sealed();
        let elsewhere = definite(&vault.check_params.allowed[0], 3);
        let moved = hash(0x33);
        let rows: Vec<(&str, Inject, &str, bool)> = vec![
            // Held: a reorg explains each of these, so a moved tip retries them.
            (
                "a null opening read",
                Box::new(|f: &mut Fake| f.null_at = BTreeSet::from([0])),
                "absent from the UTXO set at the same tip",
                false,
            ),
            (
                "a null closing read",
                Box::new(|f: &mut Fake| f.null_at = BTreeSet::from([1])),
                "absent from the UTXO set at the same tip",
                false,
            ),
            (
                "an opening value that contradicts the scan",
                Box::new(|f: &mut Fake| f.value_at = HashMap::from([(0, Amount::from_sat(7))])),
                "contradicts its scan record",
                false,
            ),
            (
                "an opening script that contradicts the scan",
                Box::new({
                    let spk = elsewhere.clone();
                    move |f: &mut Fake| f.script_at = HashMap::from([(0, spk.clone())])
                }),
                "contradicts its scan record",
                false,
            ),
            (
                "a scanned coin reported unconfirmed",
                Box::new(|f: &mut Fake| f.confirmations_at = HashMap::from([(0, 0)])),
                "contradicts its scan record",
                false,
            ),
            (
                "a value that changed between the two reads",
                Box::new(|f: &mut Fake| f.value_at = HashMap::from([(1, Amount::from_sat(7))])),
                "changed between its opening and closing read",
                false,
            ),
            (
                "a script that changed between the two reads",
                Box::new({
                    let spk = elsewhere.clone();
                    move |f: &mut Fake| f.script_at = HashMap::from([(1, spk.clone())])
                }),
                "changed between its opening and closing read",
                false,
            ),
            (
                "no block at the scanned height",
                Box::new(|f: &mut Fake| f.no_block = true),
                "no block at scanned height",
                false,
            ),
            (
                "history the block-qualified lookup cannot produce",
                Box::new(|f: &mut Fake| f.no_history = true),
                "is absent from",
                false,
            ),
            // Terminal: stable facts a reorg does not explain, so a moved tip changes
            // nothing about them.
            (
                "an immature coinbase",
                Box::new(|f: &mut Fake| {
                    f.coinbase = true;
                    f.confirmations = COINBASE_MATURITY - 1;
                }),
                "immature coinbase",
                true,
            ),
            (
                "a backend still in initial block download",
                Box::new(|f: &mut Fake| f.ibd = true),
                "initial block download",
                true,
            ),
            (
                // The needle is the BOUNDARY's verdict, not the shared validator's
                // wording: class 18 replaced the propagated text — which quotes the
                // peer's own `chain` back — with one refusal naming only the sealed
                // network the caller passed in. What this row asserts is unchanged:
                // a foreign chain is refused, and a moved tip does not make it retryable.
                "a backend on another chain",
                Box::new(|f: &mut Fake| f.identity = json!({"chain": "main"})),
                "not the sealed regtest",
                true,
            ),
        ];
        for (what, inject, needle, terminal) in rows {
            let (_, mut stable) = Fake::holding(&parts, &[COIN]);
            inject(&mut stable);
            let error = refused(&vault, &stable, &parts, what);
            assert!(error.contains(needle), "{what} under a still tip: {error}");

            let (_, mut moving) = Fake::holding(&parts, &[COIN]);
            inject(&mut moving);
            moving.after_at = HashMap::from([(0, moved), (1, moved), (2, moved)]);
            let error = refused(&vault, &moving, &parts, what);
            match terminal {
                true => assert!(error.contains(needle), "{what} is terminal: {error}"),
                false => assert!(
                    error.contains("did not hold still"),
                    "{what} is retryable under a moved tip: {error}"
                ),
            }
        }

        // Every tip in the bracket is compared, not just the first and last: the scan's
        // own `bestblock`, each opening and closing `gettxout`, and the closing read.
        let places: [(&str, Inject); 4] = [
            (
                "the scan's bestblock",
                Box::new(move |f: &mut Fake| f.scan_tip = HashMap::from([(0, moved)])),
            ),
            (
                "an opening gettxout bestblock",
                Box::new(move |f: &mut Fake| f.tip_at = HashMap::from([(0, moved)])),
            ),
            (
                "a closing gettxout bestblock",
                Box::new(move |f: &mut Fake| f.tip_at = HashMap::from([(1, moved)])),
            ),
            (
                "the closing getbestblockhash",
                Box::new(move |f: &mut Fake| f.after_at = HashMap::from([(0, moved)])),
            ),
        ];
        for (what, inject) in places {
            let (_, mut core) = Fake::holding(&parts, &[COIN]);
            inject(&mut core);
            // One moved reading in pass 1 alone: the retry then finds a still chain and
            // prepares, which is what proves this point was compared at all.
            prepared(&vault, &core, &parts);
            assert_eq!(core.issued("scantxoutset"), 2, "{what} must force a retry");
        }
    }

    /// 13. A scanned confirmed vault coin that is mempool-spent under an unmoved tip
    ///     refuses the WHOLE inventory, before any fee signal is read, saying what
    ///     happened and telling the operator NOT to reissue until independent
    ///     reconciliation. It never prepares an under-covered set from the remainder: the
    ///     surviving coin appears in no prepared view, because no prepared view is
    ///     returned. The refusal does NOT name the coin: the scan's txids are the hostile
    ///     Core's to choose, and class 19 is where that channel is closed.
    #[test]
    fn a_mempool_spent_scanned_coin_refuses_the_whole_inventory_before_any_fee_read() {
        let (vault, parts) = sealed();
        let (_, control) = Fake::holding(&parts, &[COIN, COIN / 2]);
        let view = prepared(&vault, &control, &parts);
        assert_eq!(view.utxos().len(), 2, "the control keeps both");

        for (what, null) in [("at the opening read", 0), ("at the closing read", 3)] {
            let (_, mut spent) = Fake::holding(&parts, &[COIN, COIN / 2]);
            spent.null_at = BTreeSet::from([null]);
            let error = refused(&vault, &spent, &parts, what);
            // The reads go in CANONICAL order, not scan order, so the coin an ordinal
            // names is the sorted one.
            let mut order: Vec<OutPoint> = spent.coins.iter().map(|coin| coin.outpoint).collect();
            order.sort();
            let gone = order[usize::from(null > 1)];
            // What happened, and what NOT to do about it.
            assert!(
                error.contains("spent in the mempool or otherwise unavailable"),
                "{error}"
            );
            assert!(error.contains("Do not reissue"), "{error}");
            assert!(
                error.contains("independent chain reconciliation"),
                "{error}"
            );
            assert!(
                error.contains("refused rather than composing an under-covered escape"),
                "{error}"
            );
            // The overconfident label this refusal must NOT carry: the conflicting spend
            // may never confirm, so waiting is not the remedy (PR #33 review).
            let claim = error.to_lowercase();
            assert!(!claim.contains("wait for confirmation"), "{error}");
            assert!(!claim.contains("until it confirms"), "{error}");
            // And the coin's own outpoint stays OUT of it. A scan record is the peer's
            // text: its txid is 32 bytes it chose, which is exactly the width of a Core
            // cookie password. Class 19 drives that reflection end to end.
            assert!(
                !error.contains(&gone.to_string()) && !error.contains(&gone.txid.to_string()),
                "{what} named the coin: {error}"
            );
            // Refused BEFORE the liveness snapshot, and with nothing to hand anyone.
            assert_eq!(spent.issued("estimatesmartfee"), 0, "{what}");
            assert_eq!(spent.issued("getmempoolinfo"), 0, "{what}");
        }
    }

    /// 14. Full parents are resolved WITHOUT `-txindex`: the scan's retained confirmed
    ///     height resolves a block hash, and only the block-qualified lookup is issued.
    ///     Candidates are grouped by parent so a shared parent is fetched once, and the
    ///     parent is cross-checked against every other source — txid, vout bounds, value
    ///     and script — with coinbase maturity passing at exactly 100 confirmations.
    #[test]
    fn full_parents_are_block_qualified_grouped_and_cross_checked_at_every_source() {
        let (vault, parts) = sealed();
        // Two coins from ONE parent: one height lookup, one block-qualified fetch.
        let shared = prevtx(7, &[(&parts.vault, COIN), (&parts.vault, COIN / 2)]);
        let core = Fake::over(&[(&shared, 0), (&shared, 1)]);
        prepared(&vault, &core, &parts);
        assert_eq!(core.issued("getblockhash"), 1, "grouped by parent");
        assert_eq!(core.issued("getrawtransaction"), 1, "grouped by parent");
        let calls = core.calls();
        assert!(
            calls.contains(&format!("getblockhash {HEIGHT}")),
            "{calls:?}"
        );
        let qualified = format!(
            "getrawtransaction {} in {}",
            shared.compute_txid(),
            hash(0x77)
        );
        assert!(calls.contains(&qualified), "block-qualified: {calls:?}");

        // Coinbase maturity, at the boundary: 100 confirmations is mature, 99 is not.
        let (_, mut mature) = Fake::holding(&parts, &[COIN]);
        mature.coinbase = true;
        mature.confirmations = COINBASE_MATURITY;
        prepared(&vault, &mature, &parts);
        let (_, mut immature) = Fake::holding(&parts, &[COIN]);
        immature.coinbase = true;
        immature.confirmations = COINBASE_MATURITY - 1;
        let error = refused(&vault, &immature, &parts, "a 99-confirmation coinbase");
        assert!(error.contains("immature coinbase at 99 of 100"), "{error}");

        // Every way the full transaction can disagree with what the scan and the
        // `gettxout` pair already agreed on.
        let elsewhere = definite(&vault.check_params.allowed[0], 3);
        let rows: Vec<(&str, Inject, &str)> = vec![
            (
                "a parent that hashes elsewhere",
                Box::new(|f: &mut Fake| {
                    let txid = f.coins[0].outpoint.txid;
                    let foreign = Transaction {
                        lock_time: LockTime::from_consensus(9_999),
                        ..f.parents[&txid].clone()
                    };
                    f.parents.insert(txid, foreign);
                }),
                "hashes elsewhere",
            ),
            (
                "a vout past the parent's outputs",
                Box::new(|f: &mut Fake| f.coins[0].outpoint.vout = 5),
                "contradicts vout 5",
            ),
            // The value and script rows move the SCAN record rather than the parent:
            // editing the parent changes what it hashes to, so the txid check above
            // would answer first and these two disagreements would never be reached.
            (
                "a scanned value the parent contradicts",
                Box::new(|f: &mut Fake| f.coins[0].value = Amount::from_sat(7)),
                "contradicts vout 0",
            ),
        ];
        for (what, inject, needle) in rows {
            let (_, mut core) = Fake::holding(&parts, &[COIN]);
            inject(&mut core);
            let error = refused(&vault, &core, &parts, what);
            assert!(error.contains(needle), "{what}: {error}");
        }

        // The parent's SCRIPT is checked too, and reaching that check needs a scan
        // record that lies: an off-vault record is refused outright by the definite
        // script gate, and editing the parent changes what it hashes to. So the parent
        // here genuinely pays elsewhere while the scan claims the vault script.
        let foreign = prevtx(31, &[(&elsewhere, COIN)]);
        let mut core = Fake::over(&[(&foreign, 0)]);
        core.coins[0].script = parts.vault.clone();
        let error = refused(&vault, &core, &parts, "a parent paying elsewhere");
        assert!(error.contains("contradicts vout 0"), "{error}");
    }

    /// 15. The duplicated full-prevtx projection is bounded INCREMENTALLY, during the
    ///     fetch: one 4 MB parent is admitted, exactly 64 MiB across both PSBT input-map
    ///     sets passes, an over-cap projection refuses, a parent's multiplicity counts
    ///     once per candidate, and a refusal issues no further parent RPC.
    #[test]
    fn the_projected_full_prevtx_bytes_are_bounded_incrementally_during_the_fetch() {
        let (vault, parts) = sealed();
        let quarter = MAX_COMPOSER_FULL_PREVTX_BYTES as usize / 8;

        // A 4,000,000-byte parent is admitted: that is the ceiling on a SERIALIZED
        // transaction inside a block, and qhe's response bound must carry a whole one in
        // JSON hex. The padding here is base bytes, so this fixture weighs 16,000,000 WU
        // — four times the block limit, so no chain would ever confirm it. The projection
        // reads `total_size()`, and that is the quantity a response bound has to carry.
        let maximal = fat_parent(4_000_000, &parts.vault, 1, COIN);
        assert_eq!(maximal.total_size(), 4_000_000);
        let core = Fake::over(&[(&maximal, 0)]);
        prepared(&vault, &core, &parts);

        // Exactly the cap: four candidates on one 8 MiB parent, duplicated across both
        // input-map sets, is 67,108,864 bytes. Equality passes.
        let fat = fat_parent(quarter, &parts.vault, 5, COIN);
        let four: Vec<(&Transaction, u32)> = (0..4).map(|vout| (&fat, vout)).collect();
        assert_eq!(
            fat.total_size() * 4 * 2,
            MAX_COMPOSER_FULL_PREVTX_BYTES as usize
        );
        prepared(&vault, &Fake::over(&four), &parts);

        // A FIFTH candidate on the same parent is the multiplicity, and nothing else:
        // the same single parent, fetched once, now projects five times over.
        let five: Vec<(&Transaction, u32)> = (0..5).map(|vout| (&fat, vout)).collect();
        let core = Fake::over(&five);
        let error = refused(&vault, &core, &parts, "a fifth candidate on one parent");
        assert!(error.contains("over the 67108864 byte bound"), "{error}");
        assert_eq!(
            core.issued("getrawtransaction"),
            1,
            "one parent, fetched once"
        );

        // Past the cap refuses — 8,388,609 x 4 x 2 is 67,108,872, eight bytes over, the
        // smallest overshoot this shape can express — and this row is also what pins the
        // DUPLICATION: 8,388,609 x 4 is 33,554,436 bytes across ONE input-map set,
        // comfortably under the bound, so a projection that forgot the second set would
        // admit it.
        let over = fat_parent(quarter + 1, &parts.vault, 5, COIN);
        let four: Vec<(&Transaction, u32)> = (0..4).map(|vout| (&over, vout)).collect();
        assert!(over.total_size() * 4 < MAX_COMPOSER_FULL_PREVTX_BYTES as usize);
        let error = refused(
            &vault,
            &Fake::over(&four),
            &parts,
            "eight bytes past the cap",
        );
        assert!(error.contains("over the 67108864 byte bound"), "{error}");

        // Mid-fetch: the first parent in canonical order already exceeds the bound, so
        // the two later ones are never fetched at all.
        let huge = fat_parent(
            MAX_COMPOSER_FULL_PREVTX_BYTES as usize / 2 + 1,
            &parts.vault,
            1,
            COIN,
        );
        let mut funding: Vec<(&Transaction, u32)> = vec![(&huge, 0)];
        let later = successors(&parts, huge.compute_txid(), 2);
        funding.extend(later.iter().map(|parent| (parent, 0u32)));
        let core = Fake::over(&funding);
        let error = refused(&vault, &core, &parts, "a first parent past the bound");
        assert!(error.contains("over the 67108864 byte bound"), "{error}");
        assert_eq!(
            core.issued("getrawtransaction"),
            1,
            "no later parent may be fetched"
        );
        assert_eq!(core.issued("getblockhash"), 1, "nor its height resolved");
        assert_eq!(
            core.issued("gettxout"),
            3,
            "all three candidates opened first"
        );
    }

    /// `count` distinct one-output parents whose txids all sort AFTER `first`, so a
    /// canonical fetch order can be built without depending on how any one of them
    /// happens to hash.
    fn successors(parts: &Parts, first: Txid, count: usize) -> Vec<Transaction> {
        let mut later = Vec::new();
        for tag in 100u32.. {
            let parent = prevtx(tag, &[(&parts.vault, COIN)]);
            if parent.compute_txid() > first {
                later.push(parent);
            }
            if later.len() == count {
                return later;
            }
        }
        unreachable!("the tag range is exhausted")
    }

    /// A parent of EXACTLY `target` serialized bytes paying the vault `coins` times, the
    /// remainder taken up by one padding output. Used to drive the byte projection to
    /// its boundary without depending on any particular script encoding.
    fn fat_parent(target: usize, vault: &ScriptBuf, coins: usize, value: u64) -> Transaction {
        let outputs = vec![(vault, value); coins];
        let mut tx = prevtx(0, &outputs);
        tx.output.push(TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::new(),
        });
        let last = tx.output.len() - 1;
        let mut len = target / 2;
        for _ in 0..16 {
            tx.output[last].script_pubkey = ScriptBuf::from_bytes(vec![0x51; len]);
            let size = tx.total_size();
            if size == target {
                return tx;
            }
            len = usize::try_from(len as i64 + target as i64 - size as i64).expect("a length");
        }
        panic!("could not pad a parent to {target} bytes");
    }

    /// 15b. NO full parent is cloned before the projection has completed. The bound
    ///      exists so that what is held in memory during the fetch is the projection plus
    ///      ONE in-flight response — a copy retained per parent would double that and the
    ///      projection would still read as passing, which is exactly why this is observed
    ///      rather than argued. The world is the OVER-CAP MULTI-PARENT one, where the
    ///      first parent is admitted and retained and the second refuses: a clone moved
    ///      into the fetch loop (`m45`) has therefore already happened once when the
    ///      refusal lands, and this count is what notices.
    #[test]
    fn full_parent_clones_are_absent_before_the_projection_completes() {
        let (vault, parts) = sealed();
        // Two parents of a quarter of the cap plus one byte: the first projects
        // 33,554,434 bytes and is retained, the second takes it four bytes past 64 MiB.
        let each = MAX_COMPOSER_FULL_PREVTX_BYTES as usize / 4 + 1;
        let first = fat_parent(each, &parts.vault, 1, COIN);
        let second = successor_of_size(&parts, first.compute_txid(), each);
        assert!(
            (first.total_size() * 2) as u64 <= MAX_COMPOSER_FULL_PREVTX_BYTES,
            "the first parent must be admitted"
        );
        let core = Fake::over(&[(&first, 0), (&second, 0)]);

        reset_parent_clones();
        let error = refused(&vault, &core, &parts, "two parents past the bound");
        assert!(error.contains("over the 67108864 byte bound"), "{error}");
        assert_eq!(
            core.issued("getrawtransaction"),
            2,
            "the first parent was fetched and retained before the second refused"
        );
        assert_eq!(
            parent_clones(),
            0,
            "no full parent may be cloned before the projection completes"
        );
    }

    /// 15c. The ADJACENT CONTROL for 15b, and the reason 15b's zero is worth anything:
    ///      the completed-inventory accessor IS a clone site, so the counter 15b reads can
    ///      be moved off zero and the two together say "clones happen HERE and nowhere
    ///      earlier" rather than the vacuous "clones never happen". It measures a DELTA
    ///      from a reset taken after preparation, deliberately: `m45` moves a clone into
    ///      the fetch, and this control must stay green while 15b goes red — a control
    ///      that also counted the fetch would go red with it and prove nothing.
    #[test]
    fn full_parent_clones_come_only_from_the_completed_inventory_accessor() {
        let (vault, parts) = sealed();
        let (parents, core) = Fake::holding(&parts, &[COIN, COIN / 2]);
        let view = prepared(&vault, &core, &parts);
        reset_parent_clones();

        let sorted = canonical(&parents);
        for (index, outpoint) in sorted.iter().enumerate() {
            let parent = view
                .inventory()
                .full_parent(outpoint.txid)
                .expect("a verified full parent");
            assert_eq!(parent.compute_txid(), outpoint.txid);
            assert_eq!(
                parent_clones(),
                index as u64 + 1,
                "one clone per accessor call, and only there"
            );
        }
        // A txid this inventory never verified is an absence, not a panic and not a
        // clone: the accessor is the ONLY way out and it answers for what it holds.
        let stranger = prevtx(77, &[(&parts.vault, COIN)]).compute_txid();
        assert!(view.inventory().full_parent(stranger).is_none());
        assert_eq!(parent_clones(), sorted.len() as u64);
    }

    /// One parent of exactly `size` bytes whose txid sorts after `first`, so the two are
    /// fetched in a known order.
    fn successor_of_size(parts: &Parts, first: Txid, size: usize) -> Transaction {
        for tag in 1u32.. {
            let mut candidate = fat_parent(size, &parts.vault, 1, COIN);
            candidate.lock_time = LockTime::from_consensus(tag);
            if candidate.compute_txid() > first && candidate.total_size() == size {
                return candidate;
            }
        }
        unreachable!("the tag range is exhausted")
    }

    /// 17. The chain-identity check is the SHARED public-Signet-aware validator, run
    ///     against the EXPLICIT sealed network before anything else in a pass: the default
    ///     public signet prepares, a custom signet sharing `chain:"signet"` with it does
    ///     not, and a signet that reports no challenge at all cannot be told apart from a
    ///     custom one, so it does not either. No second implementation lives here — and
    ///     what these rows read is therefore the VERDICT, not the validator's wording:
    ///     that wording quotes the peer's own `chain`/`signet_challenge` back, so the
    ///     boundary replaces it with one refusal in the sealed network's trusted name
    ///     (class 18 is why). Each row still proves its own identity is refused while the
    ///     default public signet, the adjacent control, prepares.
    #[test]
    fn the_sealed_network_is_bound_through_the_shared_public_signet_aware_validator() {
        let (vault, parts) = sealed();
        let public = vault_node::chain::PUBLIC_SIGNET_CHALLENGE;
        // The ceremony fixture seals regtest; the NETWORK is what these rows change, and
        // it is an explicit argument to the seam rather than a field of anything here.
        let prepare = |identity: Value| -> Result<PreparedView, Error> {
            let (_, mut core) = Fake::holding(&parts, &[COIN]);
            core.identity = identity;
            prepare_view(&core, Network::Signet, &vault.descriptor, parts.scripts())
        };
        prepare(json!({"chain": "signet", "signet_challenge": public}))
            .expect("the default public signet");
        let rows = [
            (
                "a custom signet",
                json!({"chain": "signet", "signet_challenge": "51ae"}),
            ),
            (
                "a signet that names no challenge",
                json!({"chain": "signet"}),
            ),
            (
                "the chain this run is not sealed to",
                json!({"chain": "regtest"}),
            ),
        ];
        for (what, identity) in rows {
            let error = match prepare(identity) {
                Ok(_) => panic!("{what} must be refused"),
                Err(e) => e.to_string(),
            };
            assert!(error.contains("not the sealed signet"), "{what}: {error}");
        }
    }

    /// 18. A hostile Core cannot REFLECT the credential it was just handed into this
    ///     seam's diagnostics. `core_view`'s own redaction covers the peer's
    ///     `error.message`; this is the other half, and the harder one, because `chain`
    ///     and `signet_challenge` are members of a SUCCESSFUL `getblockchaininfo` result
    ///     — a misbound or hostile loopback listener needs no error reply at all, only
    ///     the Basic auth head it was just sent, echoed back in a field the shared
    ///     validator interpolates verbatim. Whether the reflector "already holds" the
    ///     cookie is not the question: what this refuses is putting it into an operator's
    ///     terminal, scrollback and pasted diagnostics. So the boundary keeps the
    ///     validator's VERDICT and drops its bytes, and the refusal names only the sealed
    ///     network the caller passed in. `m49` restores the propagated error and BOTH
    ///     classes below go red — they are two tests rather than two rows of one for that
    ///     reason: a shared class aborts at its first assertion, so the second field would
    ///     never have been observed failing and by this repo's rule would be asserting
    ///     nothing. Each carries its own adjacent VALID identity as its green control.
    fn reflection_refuses(what: &str, network: Network, identity: impl Fn(&str) -> Value) {
        let (vault, parts) = sealed();
        // Exactly what `CoreRpc::rpc` writes: the Basic auth head over child A's cookie.
        let cookie = "__cookie__:5f3aQ8ZrLm";
        let credential = format!("Basic {}", BASE64_STANDARD.encode(cookie));
        let (_, mut core) = Fake::holding(&parts, &[COIN]);
        core.identity = identity(&credential);
        let error = match prepare_view(&core, network, &vault.descriptor, parts.scripts()) {
            Ok(_) => panic!("{what} must be refused"),
            Err(e) => e.to_string(),
        };
        assert!(
            !error.contains(&credential) && !error.contains(cookie),
            "{what} reflected the credential into the diagnostic: {error}"
        );
        // The refusal still SAYS something, in the one name the peer does not own.
        let sealed = vault_node::vault_network_name(network);
        assert!(
            error.contains(&format!("not the sealed {sealed}")),
            "{what}: {error}"
        );
    }

    /// The adjacent control for each class below: this identity is VALID, so a refusal
    /// there is about the reflected field and not about a fixture that cannot prepare.
    fn identity_prepares(network: Network, identity: Value) {
        let (vault, parts) = sealed();
        let (_, mut core) = Fake::holding(&parts, &[COIN]);
        core.identity = identity;
        prepare_view(&core, network, &vault.descriptor, parts.scripts())
            .expect("a valid identity prepares");
    }

    /// 18a. The reflected field is `chain`, on a vault sealed to regtest.
    #[test]
    fn a_reflected_credential_in_the_chain_field_never_reaches_the_diagnostic() {
        identity_prepares(Network::Regtest, json!({"chain": "regtest"}));
        reflection_refuses(
            "a reflecting `chain`",
            Network::Regtest,
            |credential| json!({ "chain": credential }),
        );
    }

    /// 18b. The reflected field is `signet_challenge`, on a vault sealed to the public
    ///      signet — the field a custom-signet refusal quotes back verbatim.
    #[test]
    fn a_reflected_credential_in_the_signet_challenge_never_reaches_the_diagnostic() {
        let public = vault_node::chain::PUBLIC_SIGNET_CHALLENGE;
        identity_prepares(
            Network::Signet,
            json!({"chain": "signet", "signet_challenge": public}),
        );
        reflection_refuses(
            "a reflecting `signet_challenge`",
            Network::Signet,
            |credential| json!({"chain": "signet", "signet_challenge": credential}),
        );
    }
}
