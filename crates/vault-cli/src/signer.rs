//! The frozen user-signing seam (bead btc-policy-mby-user-signer-tae) and the one
//! concrete signer behind it.
//!
//! The user authorizes a GROUP — a primary transaction, its mandatory escape, and that
//! escape's replacement ladder — validated whole against child A's sealed [`LiveVault`]
//! before the first signature exists. Authority is that sealed state plus the
//! authenticated FULL previous transaction of every input; a caller's `wallet_id`, field
//! order, `witness_utxo` and `witness_script` carry none of it. Hardware later replaces
//! [`SoftwareSigner`] and nothing else.

use std::collections::BTreeSet;
use std::path::Path;

use bitcoin::hashes::Hash;
use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1::Message;
use bitcoin::sighash::SighashCache;
use bitcoin::{EcdsaSighashType, OutPoint, Psbt, ScriptBuf, Sequence, TxOut};
use policy_core::TxClass;
use vault_proto::{ESCAPE_RBF_SEQUENCE, MAX_ESCAPE_BUMPS};
use zeroize::Zeroizing;

use crate::http::Error;
use crate::sealed::{LiveVault, Scalar};

/// The vault a request NAMES — a display and lookup hint, never authority.
pub type WalletId = [u8; 32];

/// What a user signer is ever asked to do. Two arms, and structurally no PIN, no
/// coordinator material, and no declared role: every member's class is DERIVED.
///
/// The arms are lopsided and the seam is frozen as written, so the usual `Box` remedy is
/// unavailable; one request per authorization does not earn indirection.
#[allow(clippy::large_enum_variant)]
pub enum UserAuthorization {
    Spend {
        wallet_id: WalletId,
        authorization: SpendAuthorization,
    },
    Refresh {
        wallet_id: WalletId,
        authorization: RefreshAuthorization,
    },
}

/// A primary transaction, its mandatory escape, and that escape's replacement ladder.
/// Fields are private behind the narrow constructor, so a later sibling composes one but
/// can never re-point a leg past validation.
pub struct SpendAuthorization {
    spend: Psbt,
    escape: Psbt,
    escape_bumps: Vec<Psbt>,
}

impl SpendAuthorization {
    pub(crate) fn new(spend: Psbt, escape: Psbt, escape_bumps: Vec<Psbt>) -> Self {
        SpendAuthorization {
            spend,
            escape,
            escape_bumps,
        }
    }
}

/// A vault self-spend, alone: a refresh has no escape (ADR-0013 §2).
pub struct RefreshAuthorization {
    refresh: Psbt,
}

impl RefreshAuthorization {
    pub(crate) fn new(refresh: Psbt) -> Self {
        RefreshAuthorization { refresh }
    }
}

/// An authorized group, opaque by construction. The only route to the signed bytes
/// CONSUMES it, and it is built at exactly one place — the final expression of
/// [`UserSigner::authorize`]. That is what makes "no failure path returns a partially
/// signed group" a property of shape rather than of care.
pub struct Signed {
    display: String,
    members: Vec<Psbt>,
}

impl Signed {
    /// The display rendered BEFORE the first signature, and the signed group in
    /// `[primary, escape, rung…]` order.
    pub(crate) fn into_parts(self) -> (String, Vec<Psbt>) {
        (self.display, self.members)
    }
}

/// The seam. One method, one request type, one implementation today.
pub trait UserSigner {
    fn authorize(&mut self, req: &UserAuthorization) -> Result<Signed, Error>;
}

/// The v1 signer: one sealed vault, one user scalar from one owner-only regular file. No
/// keystore, no capability trait, no coordinator credential — child A's [`LiveVault`]
/// holds no secret and this type asks it for none.
pub(crate) struct SoftwareSigner<'v> {
    vault: &'v LiveVault,
    /// The user scalar in the zeroize-on-drop byte form `SecretKey` lacks.
    secret: Zeroizing<[u8; 32]>,
}

impl<'v> SoftwareSigner<'v> {
    /// Read the user scalar from the file the caller EXPLICITLY names and prove it
    /// derives the sealed descriptor's user key. A path is this constructor's only input —
    /// no argv, literal, or environment form — and the bytes reach no log, artifact, or
    /// error message.
    pub(crate) fn load_file(vault: &'v LiveVault, path: &Path) -> Result<Self, Error> {
        let text = crate::sealed::read_secret(path)?;
        let named = path.display();
        // Child A's guard owns the parse's only copy and erases it on the refusal below
        // as well as the success, since a key deriving the wrong public key is a secret
        // too. Best effort: whatever the library copied internally is beyond reach.
        let scalar = Scalar::parse(text.trim(), &format!("the user key at {named}"))?;
        if scalar.public_key() != vault.template.user_key {
            let refusal = "does not derive the sealed descriptor's user key";
            return bad(format!("the key at {named} {refusal}"));
        }
        let secret = scalar.into_zeroizing_bytes();
        Ok(SoftwareSigner { vault, secret })
    }
}

impl UserSigner for SoftwareSigner<'_> {
    /// Validate everything, render the display, build EVERY sighash message, and only then
    /// sign. The first signature comes into existence after the last thing that could
    /// refuse, so no error path can hand back a partially signed group — and the caller's
    /// own PSBTs are never touched, only the validated clones.
    fn authorize(&mut self, req: &UserAuthorization) -> Result<Signed, Error> {
        let group = prepare(self.vault, req)?;
        let display = group.display(self.vault);
        let witness_script = self.vault.descriptor.explicit_script()?;
        let sealed_spk = self.vault.descriptor.script_pubkey();
        let mut members: Vec<Psbt> = group.members.into_iter().map(|(_, m)| m.psbt).collect();
        let mut messages: Vec<Vec<(usize, Message)>> = Vec::new();
        for psbt in &members {
            let mut cache = SighashCache::new(&psbt.unsigned_tx);
            let mut per_input = Vec::new();
            for (index, input) in psbt.inputs.iter().enumerate() {
                let lost = "a normalized input lost its canonical prevout";
                let utxo = input.witness_utxo.as_ref().ok_or(lost)?;
                // Sealed-descriptor inputs only, and a REFUSAL rather than a skip:
                // `evaluate` already proved every input re-derives from the definite vault
                // descriptor, so arriving here means that proof stopped holding, and
                // returning the group with an input left unsigned is precisely the partial
                // authorization this seam must never produce.
                if utxo.script_pubkey != sealed_spk {
                    return bad(format!("input {index} is not a sealed-descriptor coin"));
                }
                let all = EcdsaSighashType::All;
                let hash = cache.p2wsh_signature_hash(index, &witness_script, utxo.value, all)?;
                per_input.push((index, Message::from_digest(hash.to_byte_array())));
            }
            messages.push(per_input);
        }
        let user_key = self.vault.template.user_key;
        // Rebuilt INSIDE the guard, so it is erased on this return and on an unwind.
        let scalar = Scalar::from_bytes(&self.secret)?;
        for (psbt, per_input) in members.iter_mut().zip(&messages) {
            for (index, message) in per_input {
                let signature = bitcoin::ecdsa::Signature {
                    signature: scalar.sign_ecdsa(message),
                    sighash_type: EcdsaSighashType::All,
                };
                psbt.inputs[*index].partial_sigs.insert(user_key, signature);
            }
        }
        Ok(Signed { display, members })
    }
}

/// What a request authorizes, rendered from the SAME validated canonical data
/// [`UserSigner::authorize`] signs. M4/M5 call this before asking the operator, and it
/// takes the sealed vault rather than a signer: an operator must be able to read what
/// they are about to authorize WITHOUT first handing over a key file, and a later
/// hardware signer reuses this rather than reimplementing it.
pub(crate) fn describe(vault: &LiveVault, req: &UserAuthorization) -> Result<String, Error> {
    Ok(prepare(vault, req)?.display(vault))
}

/// Validate the WHOLE group: every input against its authenticated previous transaction,
/// every member against the ONE sealed vault, the pair against the two shapes a node can
/// combine, the ladder against the node's own rules. Nothing here signs, and every caller
/// object is left untouched.
fn prepare(vault: &LiveVault, req: &UserAuthorization) -> Result<Group, Error> {
    let witness_script = vault.descriptor.explicit_script()?;
    let one = |psbt: &Psbt| member(vault, &witness_script, psbt);
    match req {
        UserAuthorization::Refresh {
            wallet_id,
            authorization,
        } => {
            let refresh = one(&authorization.refresh)?;
            // The arm is a caller's word; the outputs are the evidence, so the arm cannot
            // launder a Hot spend into the pin-less refresh path.
            if refresh.class != TxClass::Refresh {
                let class = refresh.class;
                return bad(format!("the refresh arm classifies as {class:?}"));
            }
            let members = vec![("vault-refresh transaction".to_string(), refresh)];
            let hint = *wallet_id;
            Ok(Group { hint, members })
        }
        UserAuthorization::Spend {
            wallet_id,
            authorization,
        } => {
            let bumps = &authorization.escape_bumps;
            if bumps.len() > MAX_ESCAPE_BUMPS {
                let (offered, cap) = (bumps.len(), MAX_ESCAPE_BUMPS);
                return bad(format!("{offered} rungs beat the {cap} a node takes"));
            }
            let spend = one(&authorization.spend)?;
            let escape = one(&authorization.escape)?;
            let rungs = bumps.iter().map(one).collect::<Result<Vec<_>, _>>()?;
            let pair = pair_labels(&spend, &escape)?;
            // The ladder attaches to the `escape` FIELD, so an escape-class PRIMARY has no
            // ladder of its own and owes [`unladdered`] what a ladder-less base owes. By
            // CLASS, never by field: positionally, an all-escape pair would authorize in
            // one caller order and refuse the same two transactions in the other.
            if spend.class == TxClass::Escape {
                unladdered(&spend)?;
            }
            check_ladder(vault, &escape, &rungs)?;
            let mut members = vec![(pair[0].to_string(), spend), (pair[1].to_string(), escape)];
            // Named for the leg they replace — leg 2 of an all-escape pair, the only thing
            // that ties a rung to its base when both legs are escapes.
            let ladder = (1..=rungs.len()).map(|n| format!("{} fee-bump {n}", pair[1]));
            members.extend(ladder.zip(rungs));
            let hint = *wallet_id;
            Ok(Group { hint, members })
        }
    }
}

/// One validated member. Every number here is recomputed from authenticated previous
/// transactions, so the display, the fees, and the ladder read one canonical source.
struct Member {
    psbt: Psbt,
    class: TxClass,
    total_in: u64,
    fee: u64,
    /// What actually LEAVES the vault: the outputs less the change paying the vault back.
    outflow: u64,
    outpoints: Vec<OutPoint>,
}

/// The validated group. Each member travels WITH the label it earned from its DERIVED
/// role, so the operator's only view cannot silently drop a member that still gets signed.
struct Group {
    hint: WalletId,
    members: Vec<(String, Member)>,
}

impl Group {
    /// The one operator display, over the canonical data every other check read. What
    /// LEAVES the vault is shown beside the fee — not the total output value, which counts
    /// vault change and so renders a small hot payment and a near-total drain over the same
    /// coin identically. This is the only surface the operator sees before signing.
    ///
    /// The aggregate alone is NOT the review ADR-0012 requires, which is of the outputs
    /// AND the fee, so every validated output is rendered under its member in transaction
    /// order. Two groups agreeing on fee, outflow and input count still differ in WHICH
    /// sealed destination is paid and in HOW the outflow splits — the freedom
    /// `policy_core` leaves inside the allowlisted wallets — and only these lines show it.
    /// The payee is an address for the SEALED network, the one form the operator can check
    /// against their own wallet; a script no address encodes falls back to its hex, since
    /// an output that is about to be bound by `SIGHASH_ALL` must be shown rather than
    /// dropped. Vault change is marked because it is excluded from the outflow above and
    /// would otherwise read as a payment. No output line may contain the word
    /// "transaction": that word is how a MEMBER is counted, and dropping a member is the
    /// failure that count exists to catch.
    fn display(&self, vault: &LiveVault) -> String {
        let named = self.hint.to_lower_hex_string();
        let caveat = "caller hint; the sealed state is authority";
        let mut lines = vec![format!("vault {named} authorization ({caveat})")];
        let change = vault.descriptor.script_pubkey();
        for (label, m) in &self.members {
            let (fee, out, held) = (m.fee, m.outflow, m.outpoints.len());
            let facts = format!("{fee} sat fee, {out} sat leaving the vault, {held} input(s)");
            lines.push(format!("{label}: {facts}"));
            for (n, o) in m.psbt.unsigned_tx.output.iter().enumerate() {
                let spk = o.script_pubkey.as_script();
                let payee = bitcoin::Address::from_script(spk, vault.network)
                    .map_or_else(|_| format!("script {spk:x}"), |a| a.to_string());
                let kept = o.script_pubkey == change;
                let marker = if kept { " (vault change)" } else { "" };
                let sat = o.value.to_sat();
                lines.push(format!("  output {n}: {sat} sat to {payee}{marker}"));
            }
        }
        lines.join("\n")
    }
}

fn bad<T>(detail: String) -> Result<T, Error> {
    Err(detail.into())
}

fn scripts(outputs: &[TxOut]) -> Vec<ScriptBuf> {
    outputs.iter().map(|o| o.script_pubkey.clone()).collect()
}

fn values(outputs: &[TxOut]) -> Vec<u64> {
    outputs.iter().map(|o| o.value.to_sat()).collect()
}

/// **Prevout authority.** Canonicalize one member: every input must carry its FULL
/// previous transaction, that transaction must hash to the outpoint's txid, the vout must
/// be in bounds, and the `TxOut` there is the only prevout truth. A supplied
/// `witness_utxo` must agree exactly and a supplied `witness_script` must be the sealed
/// one. Only the CLONE is normalized, so the caller's PSBT is left as it was.
fn member(vault: &LiveVault, witness_script: &ScriptBuf, psbt: &Psbt) -> Result<Member, Error> {
    let tx = &psbt.unsigned_tx;
    let shape = (tx.input.len(), tx.output.len());
    if (psbt.inputs.len(), psbt.outputs.len()) != shape {
        let (ins, outs) = shape;
        return bad(format!("PSBT maps do not fit {ins} in and {outs} out"));
    }
    let mut normalized = psbt.clone();
    let mut outpoints = Vec::new();
    let mut seen = BTreeSet::new();
    let mut total_in: u64 = 0;
    for (index, input) in tx.input.iter().enumerate() {
        // `Psbt::unsigned_tx` is public, so no constructor can hold these two empty, and
        // neither crosses the boundary the authorized group must: canonical PSBT parsing
        // refuses a scriptSig outright, and PSBT serialization drops an unsigned witness,
        // so the bytes reaching a node are not the bytes authorized here. `SIGHASH_ALL`
        // commits to neither, so no signature would bind them either.
        if !input.script_sig.is_empty() {
            return bad(format!("input {index} carries a script_sig"));
        }
        if !input.witness.is_empty() {
            return bad(format!("input {index} carries a witness"));
        }
        let outpoint = input.previous_output;
        if !seen.insert(outpoint) {
            return bad(format!("input {index} spends {outpoint} a second time"));
        }
        let map = &psbt.inputs[index];
        let declared = map.sighash_type;
        if declared.is_some_and(|t| t != EcdsaSighashType::All.into()) {
            return bad(format!("input {index} declares a sighash beyond ALL"));
        }
        let missing = format!("input {index} has no full previous transaction");
        let prevtx = map.non_witness_utxo.as_ref().ok_or(missing)?;
        let computed = prevtx.compute_txid();
        if computed != outpoint.txid {
            return bad(format!("input {index} prevtx hashes to {computed}"));
        }
        let vout = outpoint.vout as usize;
        let Some(canonical) = prevtx.output.get(vout).cloned() else {
            return bad(format!("input {index} spends vout {vout} past its prevtx"));
        };
        if map.witness_utxo.as_ref().is_some_and(|c| *c != canonical) {
            return bad(format!("input {index} witness_utxo disagrees with prevtx"));
        }
        let script = map.witness_script.as_ref();
        if script.is_some_and(|c| c != witness_script) {
            return bad(format!("input {index} names a foreign witness script"));
        }
        let value = canonical.value.to_sat();
        total_in = total_in.checked_add(value).ok_or("input value overflow")?;
        normalized.inputs[index].witness_utxo = Some(canonical);
        normalized.inputs[index].witness_script = Some(witness_script.clone());
        outpoints.push(outpoint);
    }
    let out = values(&tx.output);
    let sum = out.into_iter().try_fold(0u64, u64::checked_add);
    let total_out = sum.ok_or("output value overflow")?;
    let Some(fee) = total_in.checked_sub(total_out) else {
        return bad(format!("outputs {total_out} exceed {total_in} held sat"));
    };
    // Vault change never leaves, so the display must not count it: over one coin at one
    // fee, a small hot payment and a near-total drain have the SAME total output value and
    // differ only here. The vault descriptor is definite, so its single script is exactly
    // what `policy_core` treats as change (`derives_within` over `check_params.vault`, whose
    // string it is). The subtraction cannot underflow: `kept` sums a subset of `total_out`.
    let vault_spk = vault.descriptor.script_pubkey();
    let kept = tx.output.iter().filter(|o| o.script_pubkey == vault_spk);
    let outflow = total_out - kept.map(|o| o.value.to_sat()).sum::<u64>();
    let refused = |v: policy_core::Violation| format!("{}: {}", v.check, v.detail);
    let params = &vault.check_params;
    policy_core::evaluate(&normalized, params).map_err(refused)?;
    let class = policy_core::classify(&normalized, params)
        .map_err(refused)?
        .class;
    Ok(Member {
        psbt: normalized,
        class,
        total_in,
        fee,
        outflow,
        outpoints,
    })
}

/// The two group shapes a node can safely combine, DERIVED from the members' classes and
/// input sets: a Hot primary with its mandatory Escape over the SAME nonempty coins, or
/// two escape-destination transactions over nonempty DISJOINT coins.
///
/// Both relations are SYMMETRIC (`==` and `is_disjoint`), and that is the whole of "no
/// field-position semantics": swapping two valid escape legs cannot change the verdict,
/// and their labels stay generic because nothing authenticated says which leg is the
/// immediate spend and which the delayed residual. A Hot transaction in the escape field
/// is still refused — a CLASS it may not have, not a position it must occupy.
///
/// `filled` is redundant today (a member holding no coin is already refused in [`member`] —
/// by the fee subtraction if it pays out anything, by `policy_core`'s no-inputs clause if it
/// does not), and deliberately kept: nonempty input sets are a named part of both shapes, so
/// the rule reads here rather than out of remote arithmetic.
fn pair_labels(spend: &Member, escape: &Member) -> Result<[&'static str; 2], Error> {
    let set = |m: &Member| -> BTreeSet<OutPoint> { m.outpoints.iter().copied().collect() };
    let (a, b) = (set(spend), set(escape));
    let (filled, disjoint) = (!a.is_empty() && !b.is_empty(), a.is_disjoint(&b));
    match (spend.class, escape.class) {
        (TxClass::Hot, TxClass::Escape) if filled && a == b => Ok([
            "primary hot-destination transaction",
            "escape-destination transaction",
        ]),
        (TxClass::Escape, TxClass::Escape) if filled && disjoint => Ok([
            "escape-destination transaction 1",
            "escape-destination transaction 2",
        ]),
        (primary, mandatory) => bad(format!(
            "a {primary:?} over {} input(s) with a {mandatory:?} over {} is not a group a node \
             can combine",
            a.len(),
            b.len()
        )),
    }
}

/// An escape with nothing to replace it must be FINAL through `nSequence`:
/// `vault_node::expected_escape_sequence(false)` is `Sequence::MAX`, and it is re-checked at
/// FIRE time in `sweep_rung_admissible`. A ladder-less escape that signals BIP125 passes
/// node ingress, arms, and is then found inadmissible at T — the sweep never broadcasts and
/// the vault falls back to the delayed recovery timelock. The signer is the last party to
/// see these bytes, so it refuses here. That FIRE-time re-check reaches only the leg that
/// ARMS — the request's escape FIELD, which a node registers `CandidateRole::Escape` and
/// `sweep_rung_admissible` gates on. An escape-class PRIMARY is registered
/// `CandidateRole::Spend` and never meets it; it owes the same shape anyway because the rule
/// is by CLASS, and the same two transactions in the other caller order put it in the escape
/// field, where it does arm.
fn unladdered(escape: &Member) -> Result<(), Error> {
    let ins = &escape.psbt.unsigned_tx.input;
    match ins.iter().position(|i| i.sequence != Sequence::MAX) {
        Some(i) => bad(format!("ladder-less escape input {i} is not final at T")),
        None => Ok(()),
    }
}

/// **The ladder as AUTHORIZATION, not construction.** Each rung is already validated as an
/// escape in its own right; what is left is the replacement relation the node enforces at
/// ingress (`vault_node::ensure_escape_ladder`), plus the sealed ceiling the node never
/// checks and the signer therefore must.
fn check_ladder(vault: &LiveVault, base: &Member, rungs: &[Member]) -> Result<(), Error> {
    let rbf = Sequence::from_consensus(ESCAPE_RBF_SEQUENCE);
    let base_tx = &base.psbt.unsigned_tx;
    if rungs.is_empty() {
        return unladdered(base);
    }
    let weight = vault.descriptor.max_weight_to_satisfy()?.to_wu();
    let ceiling = u128::from(vault.escape_bump_max_fee_pct);
    let base_scripts = scripts(&base_tx.output);
    let base_version = base_tx.version;
    let mut previous_values = values(&base_tx.output);
    let mut previous_fee = base.fee;
    for (index, rung) in std::iter::once(base).chain(rungs).enumerate() {
        let tx = &rung.psbt.unsigned_tx;
        let final_at_t = tx.lock_time == bitcoin::absolute::LockTime::ZERO;
        if tx.version != base_version || !final_at_t {
            return bad(format!("rung {index} breaks base version or lock 0"));
        }
        if tx.input.iter().any(|i| i.sequence != rbf) {
            return bad(format!("rung {index} has input not signalling BIP125"));
        }
        if index == 0 {
            continue;
        }
        if rung.outpoints != base.outpoints || scripts(&tx.output) != base_scripts {
            return bad(format!("rung {index} lacks base inputs or scripts"));
        }
        let raised = values(&tx.output);
        if raised.iter().zip(&previous_values).any(|(v, p)| v > p) {
            return bad(format!("rung {index} raises an output above the one below"));
        }
        // The `> 0` filter is not subsumed by the relay minimum below: "the fee strictly
        // increases" and "the increase pays to relay" are two rules, and an equal-fee rung
        // must say so rather than blame the relay floor for it.
        let Some(delta) = rung.fee.checked_sub(previous_fee).filter(|d| *d > 0) else {
            let fee = rung.fee;
            return bad(format!("rung {index} pays {fee}, not over {previous_fee}"));
        };
        let minimum = vault_node::escape_replacement_min_fee_delta(weight, tx)?;
        if delta < minimum {
            let under = format!("adds {delta}, under {minimum} to relay");
            return bad(format!("rung {index} {under}"));
        }
        // The SEALED ceiling, over the rung's ENTIRE authenticated fee rather than its
        // increase, and in u128: at large values both sides overflow a u64 multiplication
        // and a wrapped comparison would admit precisely the rung this refuses. Equality
        // passes, as every cap here does, so a zero ceiling refuses every rung paying any
        // fee — what M1 sealed until `sqn`. The base is the replaced, not a replacement.
        if u128::from(rung.fee) * 100 > u128::from(rung.total_in) * ceiling {
            let pct = vault.escape_bump_max_fee_pct;
            let (fee, held) = (rung.fee, rung.total_in);
            return bad(format!(
                "rung {index} pays {fee} over sealed {pct}% of {held}"
            ));
        }
        previous_values = raised;
        previous_fee = rung.fee;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::setup::tests::{ceremony_through_endorse, Ceremony};
    use bitcoin::absolute::LockTime;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use bitcoin::transaction::Version;
    use bitcoin::PublicKey;
    use bitcoin::{Amount, Transaction, TxIn, Witness};
    use miniscript::{Descriptor, DescriptorPublicKey};
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::OnceLock;

    /// The user scalar the ceremony fixture seals into the vault descriptor.
    const USER_SECRET: [u8; 32] = [1u8; 32];
    const COIN: u64 = 1_000_000;
    const HOT_OUT: u64 = 50_000;
    const PRIMARY_FEE: u64 = 5_000;
    /// Non-round and unequal to [`PRIMARY_FEE`], so a display that recomputed, rounded, or
    /// reported the other member's fee could not match it by accident.
    const ESCAPE_FEE: u64 = 3_137;
    /// A rung increment two orders above the incremental-relay minimum it must clear.
    const BUMP: u64 = 50_000;

    struct Fixture {
        _ceremony: Ceremony,
        _temp: crate::fed::TempDir,
        artifacts: PathBuf,
        secret: PathBuf,
    }

    /// ONE sealed set and ONE user-key file for all seventeen classes: provisioning a
    /// federation is expensive and identical for every one of them, so each test RE-READS
    /// the artifacts rather than re-running the ceremony. A `OnceLock` never drops, so
    /// these two directories deliberately outlive the test binary.
    fn fixture() -> &'static Fixture {
        static FIXTURE: OnceLock<Fixture> = OnceLock::new();
        FIXTURE.get_or_init(|| {
            let ceremony = ceremony_through_endorse(3, 2);
            ceremony.finalize().expect("finalize");
            let artifacts = ceremony.sealed("backup");
            let temp = crate::fed::TempDir::new("user-signer").expect("temp dir");
            let secret = temp.path.join("user.secret");
            owner_only(&secret, &user_key(), 0o600);
            Fixture {
                _ceremony: ceremony,
                _temp: temp,
                artifacts,
                secret,
            }
        })
    }

    fn user_key() -> String {
        format!("{}\n", USER_SECRET.to_lower_hex_string())
    }

    fn owner_only(path: &Path, body: &str, mode: u32) {
        std::fs::write(path, body).expect("write");
        let mode = std::fs::Permissions::from_mode(mode);
        std::fs::set_permissions(path, mode).expect("mode");
    }

    /// The three scripts every fixture pays, all read out of the sealed vault itself.
    struct Scripts {
        vault: ScriptBuf,
        hot: ScriptBuf,
        escape: ScriptBuf,
    }

    fn definite(d: &Descriptor<DescriptorPublicKey>, index: u32) -> ScriptBuf {
        let definite = d.at_derivation_index(index).expect("definite");
        definite.script_pubkey()
    }

    fn sealed() -> (LiveVault, Scripts) {
        let v = LiveVault::load_artifacts(&fixture().artifacts).expect("the sealed set");
        let escape = v.check_params.escape.as_ref().expect("an escape");
        let s = Scripts {
            vault: v.descriptor.script_pubkey(),
            hot: definite(&v.check_params.allowed[0], 0),
            escape: definite(escape, 0),
        };
        (v, s)
    }

    fn signer(v: &LiveVault) -> SoftwareSigner<'_> {
        SoftwareSigner::load_file(v, &fixture().secret).expect("the user key")
    }

    fn txouts(outputs: &[(&ScriptBuf, u64)]) -> Vec<TxOut> {
        let one = |(spk, value): &(&ScriptBuf, u64)| TxOut {
            script_pubkey: (*spk).clone(),
            value: Amount::from_sat(*value),
        };
        outputs.iter().map(one).collect()
    }

    /// A FULL previous transaction paying `outputs`, made unique by `tag`.
    fn prevtx(tag: u32, outputs: &[(&ScriptBuf, u64)]) -> Transaction {
        let coinbase = TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        };
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::from_consensus(tag),
            input: vec![coinbase],
            output: txouts(outputs),
        }
    }

    /// A member PSBT spending each `(previous transaction, vout)` to `outputs`, carrying
    /// ONLY the full previous transaction — never a `witness_utxo` or witness script. Every
    /// input is FINAL through `nSequence`, which is what a node requires of a ladder-less
    /// escape and what [`rbf`] converts away for a laddered one.
    fn spend(funding: &[(&Transaction, u32)], outputs: &[(&ScriptBuf, u64)]) -> Psbt {
        let one = |(prev, vout): &(&Transaction, u32)| TxIn {
            previous_output: OutPoint {
                txid: prev.compute_txid(),
                vout: *vout,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        };
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: funding.iter().map(one).collect(),
            output: txouts(outputs),
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).expect("unsigned");
        for (index, (prev, _)) in funding.iter().enumerate() {
            psbt.inputs[index].non_witness_utxo = Some((*prev).clone());
        }
        psbt
    }

    /// The same member with every input signalling BIP125: what a LADDERED escape and each
    /// of its rungs must carry, and what a ladder-less one must not.
    fn rbf(psbt: &Psbt) -> Psbt {
        let mut signalling = psbt.clone();
        for input in &mut signalling.unsigned_tx.input {
            input.sequence = Sequence::from_consensus(ESCAPE_RBF_SEQUENCE);
        }
        signalling
    }

    /// One vault coin of `coin` satoshis and the three transactions most classes build
    /// from: a Hot primary, its mandatory ladder-less Escape over the SAME coin, and one
    /// signalling rung differing from that escape only in its fee.
    fn group(s: &Scripts, tag: u32, coin: u64, fee: u64, rung: u64) -> (Transaction, [Psbt; 3]) {
        let funding = prevtx(tag, &[(&s.vault, coin)]);
        let change = coin - HOT_OUT - PRIMARY_FEE;
        let members = [
            spend(&[(&funding, 0)], &[(&s.hot, HOT_OUT), (&s.vault, change)]),
            spend(&[(&funding, 0)], &[(&s.escape, coin - fee)]),
            rbf(&spend(&[(&funding, 0)], &[(&s.escape, coin - rung)])),
        ];
        (funding, members)
    }

    fn standard(s: &Scripts, tag: u32) -> (Transaction, [Psbt; 3]) {
        group(s, tag, COIN, ESCAPE_FEE, ESCAPE_FEE + BUMP)
    }

    /// Two escape-destination transactions over DISJOINT coins, deliberately unequal in
    /// input count and in fee, so a rule reading a field position has something to read.
    fn escape_pair(s: &Scripts) -> (Psbt, Psbt) {
        let two = prevtx(90, &[(&s.vault, COIN), (&s.vault, COIN)]);
        let one = prevtx(91, &[(&s.vault, COIN)]);
        let both: [(&Transaction, u32); 2] = [(&two, 0), (&two, 1)];
        let wide = spend(&both, &[(&s.escape, 2 * COIN - PRIMARY_FEE)]);
        (wide, spend(&[(&one, 0)], &[(&s.escape, COIN - ESCAPE_FEE)]))
    }

    fn spend_req(v: &LiveVault, a: &Psbt, b: &Psbt, bumps: &[Psbt]) -> UserAuthorization {
        let authorization = SpendAuthorization::new(a.clone(), b.clone(), bumps.to_vec());
        UserAuthorization::Spend {
            wallet_id: v.wallet_id,
            authorization,
        }
    }

    fn refresh_req(v: &LiveVault, refresh: &Psbt) -> UserAuthorization {
        UserAuthorization::Refresh {
            wallet_id: v.wallet_id,
            authorization: RefreshAuthorization::new(refresh.clone()),
        }
    }

    fn requested(req: &UserAuthorization) -> Vec<Psbt> {
        match req {
            UserAuthorization::Refresh { authorization, .. } => vec![authorization.refresh.clone()],
            UserAuthorization::Spend { authorization, .. } => {
                let pair = [&authorization.spend, &authorization.escape];
                let all = pair.into_iter().chain(&authorization.escape_bumps);
                all.cloned().collect()
            }
        }
    }

    /// The refusal `what` must earn — with the caller's own PSBTs proved byte-identical
    /// afterwards, which is how every refusing class below observes "never mutate caller
    /// objects".
    fn refuse(v: &LiveVault, req: &UserAuthorization, what: &str) -> String {
        let before = requested(req);
        let error = match signer(v).authorize(req) {
            Ok(_) => panic!("{what} must be refused"),
            Err(e) => e.to_string(),
        };
        assert_eq!(requested(req), before, "{what} mutated the caller");
        error
    }

    /// Each row swaps one bad member into the escape leg of an otherwise valid pair and
    /// names the needle its refusal must carry.
    fn refuse_each(v: &LiveVault, a: &Psbt, rows: &[(&str, &str, &Psbt)]) {
        for (what, needle, member) in rows {
            let error = refuse(v, &spend_req(v, a, member, &[]), what);
            assert!(error.contains(needle), "{what}: {error}");
        }
    }

    fn approve(v: &LiveVault, req: &UserAuthorization, what: &str) -> (String, Vec<Psbt>) {
        let signed = signer(v).authorize(req);
        signed
            .unwrap_or_else(|e| panic!("{what}: {e}"))
            .into_parts()
    }

    /// The one token that separates production from tests, spelled so that writing it
    /// here does not ITSELF occur. Class 15 counts the occurrences in this file and
    /// requires exactly one, and a literal needle would be the second.
    fn boundary() -> String {
        format!("#[cfg({})]", "test")
    }

    /// The PRODUCTION half of this file with comment-only lines dropped: a scan over the
    /// whole file would let this module's own literals satisfy a structural assertion.
    /// The cut is at the FIRST [`boundary`], so the count class 15 pins is what keeps
    /// this from silently becoming a scan over some shorter prefix.
    fn production() -> String {
        let source = include_str!("signer.rs");
        let code = source.split(&boundary()).next().unwrap_or(source);
        let lines = code.lines().filter(|l| !l.trim_start().starts_with("//"));
        lines.collect::<Vec<_>>().join("\n")
    }

    /// 1. The `wallet_id` is a hint in BOTH directions: a wrong one cannot stop a
    ///    correctly authenticated group, and a right one cannot carry a foreign input.
    #[test]
    fn a_wrong_wallet_hint_is_never_authority_and_a_foreign_input_is_refused() {
        let (vault, s) = sealed();
        let (_, [primary, escape, _]) = standard(&s, 1);
        let hint = [0xAB; 32];
        assert_ne!(hint, vault.wallet_id);
        let wrong = UserAuthorization::Spend {
            wallet_id: hint,
            authorization: SpendAuthorization::new(primary.clone(), escape, Vec::new()),
        };
        let (display, members) = approve(&vault, &wrong, "a wrong hint");
        assert_eq!(members.len(), 2);
        assert!(display.contains(&hint.to_lower_hex_string()), "{display}");
        // Both arms, because a hint check added to either would be authority.
        let (funding, _) = standard(&s, 11);
        let refresh = spend(&[(&funding, 0)], &[(&s.vault, COIN - PRIMARY_FEE)]);
        let misnamed = UserAuthorization::Refresh {
            wallet_id: hint,
            authorization: RefreshAuthorization::new(refresh),
        };
        approve(&vault, &misnamed, "a wrong hint on the refresh arm");

        let elsewhere = prevtx(19, &[(&s.hot, COIN)]);
        let foreign = spend(&[(&elsewhere, 0)], &[(&s.escape, COIN - ESCAPE_FEE)]);
        let rows = [("a foreign coin", "input_ownership", &foreign)];
        refuse_each(&vault, &primary, &rows);
    }

    /// 2. A genuine vault self-spend authorizes through the Refresh arm with `SIGHASH_ALL`;
    ///    a Hot transaction posted there cannot launder itself in.
    #[test]
    fn a_genuine_self_spend_authorizes_as_refresh_and_a_mislabeled_hot_one_does_not() {
        let (vault, s) = sealed();
        let (funding, [hot, _, _]) = standard(&s, 2);
        let refresh = spend(&[(&funding, 0)], &[(&s.vault, COIN - PRIMARY_FEE)]);
        let (_, members) = approve(&vault, &refresh_req(&vault, &refresh), "a self-spend");
        assert_eq!(members.len(), 1);
        let signatures: Vec<_> = members[0].inputs[0].partial_sigs.values().collect();
        assert_eq!(signatures.len(), 1);
        assert_eq!(signatures[0].sighash_type, EcdsaSighashType::All);

        let error = refuse(&vault, &refresh_req(&vault, &hot), "a mislabeled Hot");
        assert!(error.contains("classifies as Hot"), "{error}");
    }

    /// 3. Without the full previous transaction nothing authenticates a prevout — not even
    ///    a `witness_utxo` that happens to state the truth.
    #[test]
    fn a_member_without_its_full_previous_transaction_cannot_be_authorized() {
        let (vault, s) = sealed();
        let (funding, [primary, escape, _]) = standard(&s, 3);
        let mut bare = escape;
        bare.inputs[0].non_witness_utxo = None;
        bare.inputs[0].witness_utxo = Some(funding.output[0].clone());
        let rows = [("a witness UTXO alone", "no full previous", &bare)];
        refuse_each(&vault, &primary, &rows);
    }

    /// 4. A present but FALSE witness UTXO is refused, whichever half of it lies.
    #[test]
    fn a_false_witness_utxo_prevents_authorization_in_value_and_in_script() {
        let (vault, s) = sealed();
        let (_, [primary, escape, _]) = standard(&s, 4);
        let lie = |value: u64, script_pubkey: ScriptBuf| {
            let mut lying = escape.clone();
            let forged = TxOut {
                value: Amount::from_sat(value),
                script_pubkey,
            };
            lying.inputs[0].witness_utxo = Some(forged);
            lying
        };
        let (value, script) = (lie(COIN * 2, s.vault.clone()), lie(COIN, s.hot.clone()));
        let needle = "witness_utxo disagrees";
        let rows = [
            ("an inflated value", needle, &value),
            ("a foreign script", needle, &script),
        ];
        refuse_each(&vault, &primary, &rows);
    }

    /// 5. The sealed zero ceiling admits no rung, so the authorization is exactly the
    ///    primary plus its base Escape — and `describe` renders the SAME string `authorize`
    ///    rendered before it signed anything, without a key file being loaded at all.
    #[test]
    fn a_zero_ceiling_authorization_displays_exactly_two_transactions() {
        let (vault, s) = sealed();
        assert_eq!(vault.escape_bump_max_fee_pct, 0, "M1 seals it at zero");
        let (_, [primary, escape, _]) = standard(&s, 5);
        let req = spend_req(&vault, &primary, &escape, &[]);
        let display = describe(&vault, &req).expect("the display");
        let shown = display.lines().filter(|l| l.contains("transaction"));
        assert_eq!(shown.count(), 2, "{display}");
        let (rendered, members) = approve(&vault, &req, "the pair");
        assert_eq!(rendered, display);
        assert_eq!(members.len(), 2);
    }

    /// 6. That display carries the AUTHENTICATED base Escape fee — recomputed from the
    ///    previous transaction's own output value, and unlike the primary's — beside what
    ///    each member actually moves OUT of the vault, AND every output it is about to
    ///    bind with `SIGHASH_ALL`: the aggregate alone cannot separate two groups that
    ///    agree on fee, outflow and input count but pay different sealed destinations.
    #[test]
    fn the_display_reports_the_authenticated_actual_base_escape_fee() {
        let (vault, s) = sealed();
        let (funding, [primary, escape, _]) = standard(&s, 6);
        let swept: u64 = values(&escape.unsigned_tx.output).iter().sum();
        let actual = funding.output[0].value.to_sat() - swept;
        assert_eq!(actual, ESCAPE_FEE);
        let req = spend_req(&vault, &primary, &escape, &[]);
        let display = describe(&vault, &req).expect("the display");
        let swept_line = format!("transaction: {actual} sat fee, {swept} sat leaving");
        // The Hot leg keeps vault CHANGE, so its outflow and its total output value differ
        // by 19x here. Pinning the leg that HAS change is what stops the display from
        // rendering a 50k payment and a near-total drain over the same coin identically.
        let hot_line = format!("transaction: {PRIMARY_FEE} sat fee, {HOT_OUT} sat leaving");
        assert!(display.contains(&swept_line), "{display}");
        assert!(display.contains(&hot_line), "{display}");

        // ADR-0012 has the operator review the OUTPUTS as well as the fee, and the
        // aggregate is not that review. Both primaries below agree with the one above in
        // fee, in outflow and in input count, and differ only in WHICH allowlisted
        // destination is paid and in HOW the outflow splits — precisely the freedom
        // `policy_core` leaves inside the sealed wallets, since `allowed[0]` is
        // `wpkh([fp]xpub/*)` and every index through `max_derivation_index` derives. With
        // the outputs unrendered all three of these displays are byte-identical, so the
        // operator authorizing one of them cannot tell it from either other.
        let change = COIN - HOT_OUT - PRIMARY_FEE;
        let second = definite(&vault.check_params.allowed[0], 1);
        assert_ne!(second, s.hot, "a DIFFERENT allowlisted destination");
        let half = HOT_OUT / 2;
        let elsewhere = spend(&[(&funding, 0)], &[(&second, HOT_OUT), (&s.vault, change)]);
        let allocation = &[(&s.hot, half), (&second, half), (&s.vault, change)];
        let split = spend(&[(&funding, 0)], allocation);
        for (what, variant) in [("another destination", &elsewhere), ("a split", &split)] {
            let other = describe(&vault, &spend_req(&vault, variant, &escape, &[]))
                .expect("the variant display");
            // The aggregate facts are IDENTICAL by construction — asserted, so a variant
            // that drifted in fee or outflow could not be what makes the strings differ.
            assert!(other.contains(&hot_line), "{what}: {other}");
            assert!(other.contains(&swept_line), "{what}: {other}");
            assert_ne!(display, other, "{what} renders identically");
        }

        // Positive pins, so no `assert_ne!` above can pass on an incidental difference:
        // each output's own 0-based index, exact satoshi value and the address for the
        // SEALED network — the form the operator can check against their own wallet.
        let shown = describe(&vault, &spend_req(&vault, &split, &escape, &[])).expect("split");
        // Recomputed here from `vault.network` and the library type directly, so the pin
        // is independent of whatever the display itself decided to encode with.
        let payee = |spk: &ScriptBuf| {
            bitcoin::Address::from_script(spk.as_script(), vault.network)
                .expect("the sealed network's own address")
                .to_string()
        };
        let marker = " (vault change)";
        let pinned = [
            (&s.hot, half, ""),
            (&second, half, ""),
            (&s.vault, change, marker),
        ];
        for (n, (spk, sat, tail)) in pinned.into_iter().enumerate() {
            let line = format!("  output {n}: {sat} sat to {}{tail}", payee(spk));
            assert!(shown.lines().any(|l| l == line), "output {n}: {shown}");
        }
        // Vault change never leaves, so an unmarked change line reads as a third payment
        // and undoes the very distinction the outflow figure above exists to draw.
        let kept = format!("  output 1: {change} sat to {}{marker}", payee(&s.vault));
        assert!(display.lines().any(|l| l == kept), "{display}");
        // Output lines must not inflate what counts a MEMBER (class 5): three outputs on
        // one leg, still exactly two transactions.
        let members = shown.lines().filter(|l| l.contains("transaction"));
        assert_eq!(
            members.count(),
            2,
            "an output line counted as a member: {shown}"
        );
    }

    /// 7. Zero is a ceiling, not an absence of one: it refuses every replacement rung,
    ///    while the same pair without a ladder still authorizes.
    #[test]
    fn the_sealed_zero_ceiling_refuses_every_replacement_rung() {
        let (vault, s) = sealed();
        assert_eq!(vault.escape_bump_max_fee_pct, 0);
        let (_, [primary, escape, rung]) = standard(&s, 7);
        let req = spend_req(&vault, &primary, &rbf(&escape), &[rung]);
        let error = refuse(&vault, &req, "a rung at ceiling zero");
        assert!(error.contains("over sealed 0%"), "{error}");
        let bare = spend_req(&vault, &primary, &escape, &[]);
        approve(&vault, &bare, "the same pair unladdered");
    }

    /// 8. A nonzero ceiling is the exact widened whole-fee comparison: at-boundary and
    ///    below pass, one satoshi past it refuses. The values are chosen so BOTH sides
    ///    overflow a u64 multiplication — a narrow comparison would wrap and admit
    ///    precisely the rung this refuses.
    #[test]
    fn a_nonzero_ceiling_is_the_exact_widened_whole_fee_boundary() {
        let (mut vault, s) = sealed();
        // Test-only: M1 seals every live ceiling at zero until `sqn`, so the sealed value
        // is the one thing this class changes about the vault it validates against.
        vault.escape_bump_max_fee_pct = 5;
        let coin = 4_000_000_000_000_000_000u64;
        let edge = 200_000_000_000_000_000u64;
        assert!(edge.checked_mul(100).is_none() && coin.checked_mul(5).is_none());
        assert_eq!(u128::from(edge) * 100, u128::from(coin) * 5);

        // Far over the ceiling, and chosen so its u64 product wraps TWICE and lands BELOW
        // the equally-wrapped right-hand side: a narrow comparison admits exactly the rung
        // the widened one refuses, which no value near the boundary exposes.
        let wraps = 370_000_000_000_000_000u64;
        assert!(wraps.wrapping_mul(100) < coin.wrapping_mul(5));
        assert!(u128::from(wraps) * 100 > u128::from(coin) * 5);

        let under = [(edge - 1, true), (edge, true)];
        for (fee, admitted) in under.into_iter().chain([(edge + 1, false), (wraps, false)]) {
            let (_, [primary, escape, rung]) = group(&s, 8, coin, 1_000, fee);
            let req = spend_req(&vault, &primary, &rbf(&escape), &[rung]);
            match (signer(&vault).authorize(&req), admitted) {
                (Ok(signed), true) => assert_eq!(signed.into_parts().1.len(), 3),
                (Err(e), false) => assert!(e.to_string().contains("sealed 5%"), "{e}"),
                (Ok(_), false) => panic!("a rung past the ceiling was admitted"),
                (Err(e), true) => panic!("the boundary rung {fee} was refused: {e}"),
            }
        }
    }

    /// 9. Two valid, UNEQUAL, disjoint escape-destination transactions authorize in either
    ///    order: the relation is disjointness, which is symmetric.
    #[test]
    fn a_disjoint_all_escape_pair_authorizes_in_either_order() {
        let (vault, s) = sealed();
        let (a, b) = escape_pair(&s);
        for (what, x, y) in [("as composed", &a, &b), ("swapped", &b, &a)] {
            let (_, members) = approve(&vault, &spend_req(&vault, x, y, &[]), what);
            assert_eq!(members.len(), 2, "{what}");
        }
    }

    /// 10. Its display names only "escape-destination transaction 1" and "2", in either
    ///     order: nothing authenticated says which leg is the immediate spend and which the
    ///     delayed residual, so claiming either would exceed the bytes.
    #[test]
    fn a_swapped_all_escape_pair_renders_only_generic_one_and_two_labels() {
        let (vault, s) = sealed();
        let (a, b) = escape_pair(&s);
        for (what, x, y) in [("as composed", &a, &b), ("swapped", &b, &a)] {
            let display = describe(&vault, &spend_req(&vault, x, y, &[])).expect(what);
            for n in ["1", "2"] {
                let label = format!("escape-destination transaction {n}:");
                assert!(display.contains(&label), "{what}: {display}");
            }
            for banned in ["immediate", "residual", "primary", "secondary"] {
                let claimed = display.to_lowercase().contains(banned);
                assert!(!claimed, "{what} claimed {banned}: {display}");
            }
        }
    }

    /// 11. Neither leg carries a position-dependent meaning: swapping two unequal legs
    ///     yields the SAME signed transactions and rendered facts, only the two generic
    ///     labels trading places. A role read off a field would differ here.
    #[test]
    fn neither_leg_of_an_all_escape_pair_carries_a_positional_role() {
        let (vault, s) = sealed();
        let (a, b) = escape_pair(&s);
        let one = approve(&vault, &spend_req(&vault, &a, &b, &[]), "as composed");
        let other = approve(&vault, &spend_req(&vault, &b, &a, &[]), "swapped");
        let sorted = |mut g: Vec<Psbt>| {
            g.sort_by_key(|psbt| psbt.unsigned_tx.compute_txid());
            g
        };
        assert_eq!(sorted(one.1), sorted(other.1));
        let facts = |display: &str| {
            let split = |l: &str| l.split_once(": ").map(|(_, f)| f.to_string());
            let mut lines: Vec<String> = display.lines().skip(1).filter_map(split).collect();
            lines.sort_unstable();
            lines
        };
        assert_eq!(facts(&one.0), facts(&other.0));
        assert_ne!(one.0, other.0, "the labels follow the fields");

        // A REFUSAL must be as position-blind as an approval. The ladder-less finality rule
        // is the one clause that reads a single leg, so it must read it by CLASS: applied
        // to a field, a signalling leg authorizes in one caller order and refuses in the
        // other, and the same two transactions get opposite verdicts.
        let rbf_leg = rbf(&a);
        for (what, x, y) in [("rbf first", &rbf_leg, &b), ("rbf second", &b, &rbf_leg)] {
            let error = refuse(&vault, &spend_req(&vault, x, y, &[]), what);
            assert!(error.contains("final at T"), "{what}: {error}");
        }
    }

    /// 12. Every unsafe pair or ladder relationship a node could not combine is refused,
    ///     and `refuse` proves each leaves the caller's PSBTs byte-identical. The rung
    ///     table runs under a test-only NONZERO ceiling, because the sealed zero one is the
    ///     last clause in `check_ladder` and would otherwise refuse every row for itself.
    #[test]
    fn every_unsafe_pair_or_ladder_relationship_is_refused_before_the_first_signature() {
        let (vault, s) = sealed();
        let (mut open, _) = sealed();
        open.escape_bump_max_fee_pct = 10;
        let funding = prevtx(12, &[(&s.vault, COIN), (&s.vault, COIN)]);
        let coins: [(&Transaction, u32); 2] = [(&funding, 0), (&funding, 1)];
        let swept = 2 * COIN - ESCAPE_FEE - 1_000;
        let change = 2 * COIN - HOT_OUT - PRIMARY_FEE;
        let primary = spend(&coins, &[(&s.hot, HOT_OUT), (&s.vault, change)]);
        let escape = spend(&coins, &[(&s.escape, swept), (&s.vault, 1_000)]);
        let laddered = rbf(&escape);
        let bumped = spend(&coins, &[(&s.escape, swept - BUMP), (&s.vault, 1_000)]);
        let rung = rbf(&bumped);
        let elsewhere = prevtx(121, &[(&s.vault, COIN)]);
        let apart = spend(&[(&elsewhere, 0)], &[(&s.escape, COIN - ESCAPE_FEE)]);
        let overlap = spend(&[(&funding, 0)], &[(&s.escape, COIN - ESCAPE_FEE)]);
        let empty = spend(&[], &[(&s.escape, COIN)]);
        // FEWER maps than transaction inputs, which is the malformed shape that matters:
        // without the shape refusal the canonicalizing loop indexes `psbt.inputs` past its
        // end, so the clause guards a panic rather than repeating `policy_core`.
        let mut ragged = escape.clone();
        ragged.inputs.pop();
        let pairs = [
            ("a Hot primary over other coins", "not a group", &apart),
            ("a primary with no inputs", "exceed 0 held sat", &empty),
            ("a short input map", "maps do not fit", &ragged),
            // The mirror of the ladder's BIP125 rule: with no rung to replace it, an escape
            // that signals is inadmissible at T (`vault_node::sweep_rung_admissible`).
            ("a signalling ladder-less escape", "final at T", &laddered),
        ];
        refuse_each(&vault, &primary, &pairs);
        let shared = [("overlapping legs", "not a group", &overlap)];
        refuse_each(&vault, &escape, &shared);

        // Each row is ONE mutation away from a rung this signer accepts (the control at the
        // end), so every refusal below is earned by its own clause.
        type Edit = (&'static str, &'static str, fn(&mut Psbt));
        let edits: [Edit; 9] = [
            ("reordered coins", "inputs or scripts", |r| {
                r.unsigned_tx.input.swap(0, 1);
            }),
            ("swapped output scripts", "inputs or scripts", |r| {
                let outputs = &mut r.unsigned_tx.output;
                let first = outputs[0].script_pubkey.clone();
                outputs[0].script_pubkey = outputs[1].script_pubkey.clone();
                outputs[1].script_pubkey = first;
            }),
            ("an extra output", "inputs or scripts", |r| {
                let extra = r.unsigned_tx.output[1].clone();
                r.unsigned_tx.output.push(extra);
                r.outputs.push(Default::default());
            }),
            ("a raised output", "raises an output", |r| {
                r.unsigned_tx.output[0].value -= Amount::from_sat(1_000);
                r.unsigned_tx.output[1].value = Amount::from_sat(2_000);
            }),
            ("another version", "base version", |r| {
                r.unsigned_tx.version = Version::ONE;
            }),
            ("a nonzero nLockTime", "or lock 0", |r| {
                r.unsigned_tx.lock_time = LockTime::from_consensus(500_001);
            }),
            ("an unsignalled input", "BIP125", |r| {
                r.unsigned_tx.input[1].sequence = Sequence::MAX;
            }),
            ("the base's own fee", "not over", |r| {
                let held = 2 * COIN - ESCAPE_FEE - 1_000;
                r.unsigned_tx.output[0].value = Amount::from_sat(held);
            }),
            ("a one-satoshi raise", "to relay", |r| {
                let held = 2 * COIN - ESCAPE_FEE - 1_001;
                r.unsigned_tx.output[0].value = Amount::from_sat(held);
            }),
        ];
        for (what, needle, edit) in edits {
            let mut mutated = rung.clone();
            edit(&mut mutated);
            let req = spend_req(&open, &primary, &laddered, &[mutated]);
            let error = refuse(&open, &req, what);
            assert!(error.contains(needle), "a rung with {what}: {error}");
        }
        // Four rungs of ASCENDING fee, each admissible on its own — the steps are small
        // enough that the top rung stays under both the test ceiling and `policy_core`'s
        // own fee cap, so with the bound removed this ladder is ADMITTED and only the
        // bound itself can be refusing it.
        let taller = |n: u64| [(&s.escape, swept - 5_000 * n), (&s.vault, 1_000)];
        let steps = 1..=MAX_ESCAPE_BUMPS as u64 + 1;
        let over: Vec<Psbt> = steps.map(|n| rbf(&spend(&coins, &taller(n)))).collect();
        let req = spend_req(&open, &primary, &laddered, &over);
        let error = refuse(&open, &req, "an over-long ladder");
        assert!(error.contains("beat the 3 a node takes"), "{error}");

        // The control: unmutated, this exact ladder is a shape the signer accepts, so no
        // row above refused for a broken fixture. Its rung is labelled off the leg it
        // replaces, which is the only thing that would tie a rung to a base if BOTH legs
        // were escapes.
        let control = spend_req(&open, &primary, &laddered, &[rung]);
        let (rendered, _) = approve(&open, &control, "the unmutated ladder");
        let bump = "escape-destination transaction fee-bump 1";
        assert!(rendered.contains(bump), "{rendered}");

        // STRUCTURAL: a group becomes `Signed` at exactly one place, AFTER the whole
        // validation and after the last signature, and nothing between there and the return
        // can fail. The ordering assertions are what forbid a signer that signs first and
        // validates second — which the single build site alone would still permit.
        let code = production();
        let tail = code.split("Result<Signed, Error> {").nth(1);
        let tail = tail.expect("the signing path");
        let body = tail.split("\n}\n").next().unwrap_or(tail);
        let built = body.find("Ok(Signed {").expect("one build site");
        let checked = body.find("prepare(self.vault, req)?").expect("validation");
        let signs = body.find("sign_ecdsa").expect("the signing call");
        assert_eq!(code.matches("Ok(Signed {").count(), 1);
        // That count pins only the RETURNED build. `Signed {` occurs three times in the
        // production half — the declaration, its inherent impl, and that one build — so a
        // second construction bound to a name and handed back from an EARLIER path, which
        // is precisely a `Signed` whose members carry no signature, moves this count and
        // no other assertion here.
        assert_eq!(
            code.matches("Signed {").count(),
            3,
            "a second Signed is built"
        );
        // Both counts read the type's NAME, and inside `impl Signed` that same type is
        // spelled `Self` — so a second constructor there builds one while both counts hold,
        // and any sibling could then hand a later consumer a `Signed` whose members no
        // signer validated or signed. What that construction cannot do is live outside a
        // method, so the impl's method list is pinned the way [`SoftwareSigner`]'s is in
        // class 15: one ` fn `, the consuming `into_parts`. The declaration itself is
        // pinned verbatim there too, which is what keeps the fields private. Reading only
        // the FIRST such block is sound because `impl Signed {` CONTAINS `Signed {`: a
        // second block, inherent or trait, moves the count above before it reaches here.
        let sole = "impl Signed {";
        let block = code.split(sole).nth(1).expect("the inherent impl");
        let only = block.split("\n}\n").next().expect("its end");
        assert_eq!(only.matches(" fn ").count(), 1, "a second Signed method");
        assert!(checked < signs, "the whole group validates before it signs");
        assert!(signs < built, "and every signature exists before the group");
        // The region a partially signed group could escape through, anchored at the LOOP
        // HEAD rather than the first `sign_ecdsa` TOKEN: a refusal placed above that token
        // but inside the loop still runs after a signature exists, on every pass but the
        // first, so a region starting at the token would not cover it.
        let arms = body.find("for (psbt, per_input)").expect("the sign loop");
        assert!(arms < signs, "the loop head precedes the first signature");
        let armed = &body[arms..built];
        assert!(!armed.contains('?') && !armed.contains("return"), "{armed}");
    }

    /// 13. Every member must validate under the ONE sealed vault: a coin that is not the
    ///     wallet's, and a destination the policy bars, each refuse before signing.
    #[test]
    fn a_group_whose_members_do_not_share_one_sealed_identity_fails_before_signing() {
        let (vault, s) = sealed();
        let max = vault.check_params.max_derivation_index;
        assert!(max < 50, "the bounded scan must not reach index 50");
        let stranger = prevtx(131, &[(&s.escape, COIN)]);
        let other_wallet = spend(&[(&stranger, 0)], &[(&s.vault, COIN - ESCAPE_FEE)]);
        let funding = prevtx(132, &[(&s.vault, COIN)]);
        let beyond = definite(&vault.check_params.allowed[0], 50);
        let off_policy = spend(&[(&funding, 0)], &[(&beyond, COIN - ESCAPE_FEE)]);
        // Through the SINGLE-member Refresh arm: with no pair relation in play, the sealed
        // identity is the only thing that can be refusing either of these.
        let rows = [
            ("another wallet's coin", "input_ownership", &other_wallet),
            (
                "an unsealed destination",
                "destination_allowlist",
                &off_policy,
            ),
        ];
        for (what, needle, member) in rows {
            let error = refuse(&vault, &refresh_req(&vault, member), what);
            assert!(error.contains(needle), "{what}: {error}");
        }
    }

    /// 14. Every signature emitted, on every input of every member of every shape, is ECDSA
    ///     `SIGHASH_ALL` under the sealed user key — one per vault input — and an input
    ///     DECLARING anything else is refused rather than quietly signed with ALL.
    #[test]
    fn every_signature_this_signer_emits_commits_with_sighash_all() {
        let (mut vault, s) = sealed();
        vault.escape_bump_max_fee_pct = 10;
        let (funding, [primary, escape, rung]) = standard(&s, 14);
        let refresh = spend(&[(&funding, 0)], &[(&s.vault, COIN - PRIMARY_FEE)]);
        let (a, b) = escape_pair(&s);
        let laddered = spend_req(&vault, &primary, &rbf(&escape), &[rung]);
        let script = vault.descriptor.explicit_script().expect("witness script");
        let (secp, all) = (Secp256k1::new(), EcdsaSighashType::All);
        for (what, req, inputs) in [
            ("a refresh", refresh_req(&vault, &refresh), 1),
            ("a laddered spend", laddered, 3),
            ("an escape pair", spend_req(&vault, &a, &b, &[]), 3),
        ] {
            let (_, members) = approve(&vault, &req, what);
            let mut signatures = 0;
            for psbt in &members {
                let tx = psbt.unsigned_tx.clone();
                let mut cache = SighashCache::new(&tx);
                for (index, input) in psbt.inputs.iter().enumerate() {
                    let utxo = input.witness_utxo.as_ref().expect("canonical");
                    let hash = cache
                        .p2wsh_signature_hash(index, &script, utxo.value, all)
                        .expect("the ALL sighash");
                    let message = Message::from_digest(hash.to_byte_array());
                    for (key, signature) in &input.partial_sigs {
                        assert_eq!(*key, vault.template.user_key, "{what}");
                        assert_eq!(signature.sighash_type, all, "{what}");
                        // The LABEL alone proves nothing: verify against the message a
                        // SIGHASH_ALL commitment actually produces.
                        secp.verify_ecdsa(&message, &signature.signature, &key.inner)
                            .expect("the signature commits to SIGHASH_ALL");
                        signatures += 1;
                    }
                }
            }
            assert_eq!(signatures, inputs, "{what}: one per vault input");
        }
        // A caller-declared sighash beyond ALL is the one thing the loop above cannot see:
        // this signer signs ALL regardless, so the declaration must be REFUSED, not ignored.
        let mut declared = escape.clone();
        declared.inputs[0].sighash_type = Some(EcdsaSighashType::None.into());
        let req = spend_req(&vault, &primary, &declared, &[]);
        let error = refuse(&vault, &req, "a declared SIGHASH_NONE");
        assert!(error.contains("sighash beyond ALL"), "{error}");
    }

    /// 15. The user scalar comes from one owner-only, no-follow regular file the caller
    ///     NAMES, and nowhere else. Structurally: the seam is exactly the frozen seam, a
    ///     path is its only secret input, and no PIN material appears in it.
    #[test]
    fn the_user_key_is_read_only_from_an_owner_only_regular_file_named_by_path() {
        let (vault, _) = sealed();
        let temp = crate::fed::TempDir::new("user-key").expect("temp dir");
        let secret = user_key();
        let good = temp.path.join("good");
        owner_only(&good, &secret, 0o600);
        SoftwareSigner::load_file(&vault, &good).expect("the control");
        std::os::unix::fs::symlink(&good, temp.path.join("link")).expect("link");
        std::fs::create_dir(temp.path.join("dir")).expect("dir");
        owner_only(&temp.path.join("group"), &secret, 0o640);
        owner_only(&temp.path.join("world"), &secret, 0o604);
        for (name, needle) in [
            ("link", "cannot open"),
            ("dir", "not a regular file"),
            ("group", "mode 0640"),
            ("world", "mode 0604"),
        ] {
            let path = temp.path.join(name);
            let error = match SoftwareSigner::load_file(&vault, &path) {
                Ok(_) => panic!("{name} must be refused"),
                Err(e) => e.to_string(),
            };
            assert!(error.contains(needle), "{name}: {error}");
            assert!(!error.contains(secret.trim()), "{name} leaked it");
        }

        // EVERY `production()` scan below cuts this file at the FIRST test boundary — so a
        // second one placed anywhere above this module silently shrinks the scanned region
        // to a prefix that still satisfies all of them. A single `cfg(test)`-gated
        // `pub(crate) fn probe() {}` after the trait impl — written here without its
        // brackets, since a literal one would BE the second — leaves `describe`, `prepare`,
        // `member`, `pair_labels`, `unladdered` and `check_ladder` unscanned while every
        // `production()` scan in classes 12, 15 and 16 still passes, which is exactly a
        // scan that has stopped covering anything. There is one boundary in this file: the
        // one this module opens with.
        let whole = include_str!("signer.rs");
        assert_eq!(
            whole.matches(&boundary()).count(),
            1,
            "a second test boundary"
        );

        // The cut keeps the PREFIX, so the region BEYOND this module is unscanned in the
        // very same way, and one boundary does not close it. An item appended after this
        // module's final brace — `pub(crate) fn from_bytes(v: &LiveVault, raw: [u8; 32])
        // -> SoftwareSigner<'_>` returning the struct literal — is PRODUCTION code inside
        // this module tree, so it reaches those private fields, hands any sibling a signer
        // past `read_secret`'s owner-only refusals and past the derived-key match, and
        // moves NONE of the counts below: every one of them reads `production()`, which
        // ends where this module begins. So the module is required to be the file's LAST
        // item. Column 0 is the test, and it is sound because `cargo fmt --check` is a leg
        // of the gate: rustfmt returns every top-level item to column 0, so an appended
        // one cannot hide by being indented. This and the count above overlap on that
        // earlier graft — a second boundary leaves production code in the tail as well, so
        // either alone kills it — and neither covers the other's case: an item appended
        // past the final brace adds no boundary token at all.
        let tail = whole.split(&boundary()).nth(1).expect("this module");
        let outside = |l: &&str| !l.is_empty() && !l.starts_with(char::is_whitespace);
        let framing: Vec<&str> = tail.lines().filter(outside).collect();
        assert_eq!(
            framing,
            ["mod tests {", "}"],
            "an item past the test module"
        );

        // The bead's own text, verbatim down to the `pub`: a pin that paraphrased the
        // frozen declaration would stay green while the shipped seam drifted from it.
        // The two authorization structs close on `}`, which freezes the field LIST and
        // not merely each field's privacy: both are reached only through a `new`, so a
        // field grafted on and defaulted there — `declared_role`, say, the one input the
        // bead forbids trusting — compiles at every call site and leaves all 17 classes
        // green.
        //
        // The ENUM closes on `}` for its ARM list, which is a different case from an added
        // arm FIELD. The field case cannot compile: `prepare` matches both arms
        // field-by-field with no `..`, so a grafted field has no binding there. A whole
        // third arm does compile once its two exhaustive matches — `prepare` and the
        // `requested` helper — each gain a branch, and that mechanical compile fix is all
        // it costs: nothing else in this class moves. The type stays NAMED four times and
        // built once, `Signed {` stays at three, the graft and word scans read no arm, and
        // the class-12 ordering scan still finds `prepare` ahead of the first signature
        // even where the new arm builds its `Group` from caller-supplied fields. So a
        // third `Presigned`/`Raw` arm — carrying the declared role the bead forbids
        // trusting — would ship with all 17 classes green against a header-only needle.
        // The bead freezes this seam against "adding arms" in those words, so the pin is
        // the whole declaration through its closing brace rather than the header plus each
        // EXISTING arm's field pair, which freezes only the arms already there.
        //
        // The TRAIT closes on `}` for the same reason one level up — that brace freezes
        // its METHOD list, where two needles stopping at `authorize` would freeze only
        // that method's shape. A second `pub` method — one handing back the raw scalar,
        // an `authorize_unchecked`, one carrying PIN material — moves nothing else here:
        // the type stays NAMED four times and built once, the INHERENT impl still holds
        // one ` fn `, and no word scan reads it. Freezing the trait freezes its impl too,
        // since a trait impl may hold only the trait's own items.
        let code = production();
        for frozen in [
            "pub type WalletId = [u8; 32];",
            "pub enum UserAuthorization {\n    Spend {\n        wallet_id: WalletId,\n        authorization: SpendAuthorization,\n    },\n    Refresh {\n        wallet_id: WalletId,\n        authorization: RefreshAuthorization,\n    },\n}",
            "pub struct SpendAuthorization {\n    spend: Psbt,\n    escape: Psbt,\n    escape_bumps: Vec<Psbt>,\n}",
            "pub struct RefreshAuthorization {\n    refresh: Psbt,\n}",
            "pub trait UserSigner {\n    fn authorize(&mut self, req: &UserAuthorization) -> Result<Signed, Error>;\n}",
        ] {
            assert!(
                code.contains(frozen),
                "the seam no longer declares: {frozen}"
            );
        }
        // A path is the ONLY way a secret reaches this module, which the argv/environment
        // word scan below cannot show: the type is NAMED exactly four times — declaration,
        // inherent impl, build site, trait impl — the one build site spells the type out,
        // and the one impl that can build it holds one `fn`. The name count catches a
        // second impl under any lifetime spelling; the build count catches that same impl
        // smuggled in by respelling THIS build site `Self {` to hold the total at four.
        let constructor = "fn load_file(vault: &'v LiveVault, path: &Path)";
        let sole = "impl<'v> SoftwareSigner";
        let mentions = code.matches("SoftwareSigner").count();
        let builds = code.matches("SoftwareSigner {").count();
        assert_eq!((mentions, builds), (4, 1), "a second impl or build site");
        let block = code.split(sole).nth(1).expect("the inherent impl");
        let only = block.split("\n}\n").next().expect("its end");
        assert_eq!(only.matches(" fn ").count(), 1, "a second constructor");
        assert_eq!(only.matches(constructor).count(), 1);
        // Not one of those counts moves when a FIELD opens up, and `production()` reads
        // only this file — so the sibling that would then write `SoftwareSigner { vault,
        // secret: Zeroizing::new(raw) }`, past the owner-only file and the pubkey match,
        // is invisible from here. Rust's own privacy is what forbids it, and privacy is a
        // property of the DECLARATION, so pin both declarations verbatim: `Signed` because
        // the bead requires it opaque, the signer because its fields ARE the raw secret.
        for private in [
            "pub struct Signed {\n    display: String,\n    members: Vec<Psbt>,\n}",
            "pub(crate) struct SoftwareSigner<'v> {\n    vault: &'v LiveVault,\n    secret: Zeroizing<[u8; 32]>,\n}",
        ] {
            assert!(code.contains(private), "a field left its module: {private}");
        }
        // Privacy forbids that SIBLING, and by the same rule forbids nothing BELOW: a
        // private field is reachable from its declaring module AND every descendant of it.
        // So a production `mod helper;` — with `crates/vault-cli/src/signer/helper.rs`
        // holding that same `SoftwareSigner { vault, secret: Zeroizing::new(raw) }` — is
        // inside this module tree, past `read_secret`'s no-follow/regular/owner-only
        // refusals and past the derived-key match, while every count, pin, framing and
        // word scan here stays green: `production()` reads THIS file, so the child's bytes
        // are never scanned at all. `include!` and `#[path` graft the same code by the
        // same textual route. What the graft cannot omit is its DECLARATION here, so that
        // is what is refused: the sole production module declares no child and no textual
        // indirection into one. The needle carries its space for the same reason the
        // framing list above trusts column 0 — `cargo fmt --check` is a leg of the gate,
        // and rustfmt returns a `mod` split across lines to one `mod helper;`.
        for graft in ["mod ", "include!", "#[path"] {
            assert!(!code.contains(graft), "the signer grafts in {graft}");
        }
        for banned in ["argv", "env::", "args(", "PIN"] {
            assert!(!code.contains(banned), "the signer reaches for {banned}");
        }
        // By WORD, not substring: `wrapping_mul` contains "pin" and is not a pin. The word
        // is the `_`-separated SEGMENT, because the splitter below deliberately keeps `_`
        // INSIDE an identifier — so a prefix/suffix test alone reads `verify_pin_material`
        // and `duress_pin_hash` as pin-free, and this repo already spells names that way
        // (`within_pin_spread`, `assert_pin_cost_reached_the_node`). Segment matching also
        // subsumes the uppercase `PIN` in the substring list above, which stands whatever
        // this closure does.
        let named_pin = |w: &str| w.to_ascii_lowercase().split('_').any(|s| s == "pin");
        let split = |c: char| !c.is_alphanumeric() && c != '_';
        assert!(!code.split(split).any(named_pin), "the signer names a pin");
    }

    /// 16. The owned scalar is zeroize-on-drop, every plain `SecretKey` this module would
    ///     otherwise hold lives inside child A's RAII guard instead — at load and on the
    ///     signing rebuild alike — a key that does not derive the sealed one is refused
    ///     without printing itself, and no coordinator credential is reachable from here.
    #[test]
    fn the_signer_erases_its_parsed_key_and_refuses_one_that_is_not_the_sealed_users() {
        let (vault, _) = sealed();
        let temp = crate::fed::TempDir::new("wrong-key").expect("temp dir");
        let wrong = [9u8; 32].to_lower_hex_string();
        let path = temp.path.join("foreign");
        owner_only(&path, &format!("{wrong}\n"), 0o600);
        let error = match SoftwareSigner::load_file(&vault, &path) {
            Ok(_) => panic!("a key that is not the sealed user's is refused"),
            Err(e) => e.to_string(),
        };
        assert!(error.contains("does not derive the sealed"), "{error}");
        assert!(!error.contains(&wrong), "the refusal printed the secret");
        let held = signer(&vault);
        let owned = SecretKey::from_slice(held.secret.as_slice()).expect("scalar");
        assert_eq!(
            PublicKey::new(owned.public_key(&Secp256k1::new())),
            vault.template.user_key
        );

        let code = production();
        assert!(code.contains("secret: Zeroizing<[u8; 32]>"));
        // The user scalar exists ONLY inside child A's non-`Copy` RAII guard, and that is
        // a property of this whole half rather than of one line: name a plain `SecretKey`
        // or its raw bytes here at all — at load, or on the rebuild the signing loop needs
        // — and a `Copy` key or a bare array is live in a local that nothing erases, on
        // the refusal path and on an unwind alike. `Scalar` wipes itself on drop instead,
        // so this half hands the erase to a destructor and never spells one out.
        for raw in ["SecretKey", "secret_bytes", "non_secure_erase"] {
            assert!(
                !code.contains(raw),
                "a user scalar outside the guard: {raw}"
            );
        }
        assert_eq!(
            code.matches("Scalar::").count(),
            2,
            "exactly one guarded parse and one guarded rebuild"
        );
        let load = code.split("fn load_file").nth(1).expect("the constructor");
        let guarded = load.find("Scalar::parse(").expect("the guarded parse");
        let refusal = load.find("does not derive").expect("the refusal");
        assert!(guarded < refusal, "the key is guarded before the refusal");
        assert!(!code.contains("oordinator"), "no credential is reachable");
    }

    /// 17. The full previous transaction is the ONLY prevout authority: it alone is enough,
    ///     an agreeing `witness_utxo` is tolerated, its recomputed txid must match, its vout
    ///     must be in bounds, a supplied witness script must be the sealed one, and no
    ///     outpoint may repeat. An input of the UNSIGNED transaction carrying a scriptSig or
    ///     a witness is refused too: `Psbt::unsigned_tx` is public, so no constructor holds
    ///     those empty, and neither one survives the serialization boundary the group must
    ///     cross to reach the nodes.
    #[test]
    fn the_full_previous_transaction_is_the_only_prevout_authority() {
        let (vault, s) = sealed();
        let (funding, [primary, escape, _]) = standard(&s, 17);
        assert!(escape.inputs[0].witness_utxo.is_none());
        assert!(escape.inputs[0].witness_script.is_none());
        let req = spend_req(&vault, &primary, &escape, &[]);
        let (display, members) = approve(&vault, &req, "a full prevtx alone");
        let canonical = members[1].inputs[0].witness_utxo.as_ref();
        assert_eq!(
            canonical,
            Some(&funding.output[0]),
            "the clone is canonical"
        );
        assert!(
            display.contains(&format!("{ESCAPE_FEE} sat fee")),
            "{display}"
        );
        assert!(escape.inputs[0].witness_utxo.is_none(), "caller mutated");

        let mut agreeing = escape.clone();
        agreeing.inputs[0].witness_utxo = Some(funding.output[0].clone());
        approve(
            &vault,
            &spend_req(&vault, &primary, &agreeing, &[]),
            "an agreeing UTXO",
        );

        let mut relabeled = funding.clone();
        relabeled.lock_time = LockTime::from_consensus(777);
        let mut wrong_txid = escape.clone();
        wrong_txid.inputs[0].non_witness_utxo = Some(relabeled);
        let mut foreign_script = escape.clone();
        foreign_script.inputs[0].witness_script = Some(s.hot.clone());
        // The two fields a PSBT's unsigned transaction may never carry, reached the only
        // way they can be — by writing the public `unsigned_tx` AFTER the constructor that
        // checked them. Neither crosses the boundary the authorized group must: a scriptSig
        // is refused outright by canonical PSBT parsing at the node, and a witness is
        // dropped by PSBT serialization, so the bytes that arrive are not the bytes read.
        let mut scriptsig = escape.clone();
        scriptsig.unsigned_tx.input[0].script_sig = s.hot.clone();
        let mut witnessed = escape.clone();
        witnessed.unsigned_tx.input[0].witness = Witness::from_slice(&[[7u8; 9]]);
        // Both inputs spend one coin, and the outputs pay out what TWO of them would hold:
        // with the duplicate clause gone the double-counted total clears policy-core's fee
        // cap, so only that clause can refuse this.
        let twice = &[(&funding, 0), (&funding, 0)];
        let duplicate = spend(twice, &[(&s.escape, 2 * COIN - ESCAPE_FEE)]);
        let script = "foreign witness script";
        let (sig, wit) = ("carries a script_sig", "carries a witness");
        let rows = [
            ("a foreign prevtx", "hashes to", &wrong_txid),
            ("a foreign witness script", script, &foreign_script),
            ("the same outpoint twice", "a second time", &duplicate),
            ("a scriptSig on an unsigned input", sig, &scriptsig),
            ("a witness on an unsigned input", wit, &witnessed),
        ];
        refuse_each(&vault, &primary, &rows);

        // BOTH legs point past the prevtx, so their outpoint sets still match and the pair
        // rule cannot refuse this for the bound: a signer that resolved an out-of-range
        // vout to some other output would authorize the group outright.
        let past = |member: &Psbt| {
            let mut beyond = member.clone();
            beyond.unsigned_tx.input[0].previous_output.vout = 7;
            beyond
        };
        let oob = spend_req(&vault, &past(&primary), &past(&escape), &[]);
        let error = refuse(&vault, &oob, "a vout past its end");
        assert!(error.contains("spends vout 7"), "{error}");
    }
}
