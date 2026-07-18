//! `demo recovery-drill`: the timelocked recovery EXIT, demonstrated end-to-end on
//! a private regtest chain (V0-10). This is the exit a locked-down or otherwise
//! stuck vault takes — the one V0-4b's "freeze + lockdown → recovery" safety story
//! depends on: after the relative timelock matures, a 2-of-3 recovery keyset moves
//! the funds with **no user key, no node quorum, and no coordinator** (ADR-0013 §1;
//! DESIGN.md, Wallet Topology).
//!
//! Recovery is the FALLBACK exit, not the first-line answer to an attack: an
//! ongoing attack is met by the normal path + the escape sweep, and recovery is
//! what remains AFTER a failed escape + terminal lockdown, and for loss /
//! inheritance / a stuck vault. So this drill never touches the nodes or the
//! coordinator; the recovery key holders act alone.
//!
//! The drill proves the five properties the recovery branch must have:
//!
//!  1. the vault descriptor really carries the `older(4224679) + 2-of-3` recovery
//!     branch (it round-trips through the frozen template);
//!  2. a recovery spend BEFORE the relative lock matures is consensus-rejected
//!     (`non-BIP68-final`) — the timelock is real;
//!  3. 2-of-3 recovery signatures are required (1-of-3 cannot even finalize);
//!  4. after advancing **median-time-past** past the 512-second-unit relative lock
//!     (`setmocktime` + a handful of blocks — NOT mining 30375 blocks, since a
//!     TIME-based BIP68 lock matures on MTP, not height) the spend confirms;
//!  5. a node watchtower classifies the confirmed spend as `RecoveryPathSpend`
//!     (branch-identified from its witness), not `UnrecognizedSpend`.

use std::collections::HashSet;
use std::fs::File;
use std::str::FromStr;

use bitcoin::absolute::LockTime;
use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sighash::SighashCache;
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, EcdsaSighashType, Network, OutPoint, Psbt, PublicKey, ScriptBuf, Transaction, TxIn,
    TxOut, Witness,
};
use miniscript::psbt::PsbtExt;
use miniscript::{Descriptor, DescriptorPublicKey};
use serde_json::json;
use vault_node::chain::BitcoindBackend;
use vault_node::watchtower::{scan, AlertKind};

use crate::bitcoind::Bitcoind;
use crate::demo::{free_ports, Actor, TempDir};
use crate::http::Error;

/// Coins funded into the vault for the drill.
const FUND: Amount = Amount::from_sat(500_000_000);
/// Flat fee on the recovery sweep — trivially under any cap.
const FEE: Amount = Amount::from_sat(10_000);

pub fn run_recovery_drill() -> Result<(), Error> {
    let secp = Secp256k1::new();

    // RAII cleanup on every path (temp dir → bitcoind), like first light.
    println!(
        "[1/6] building the two-branch vault (normal 3-of-5 OR older(4224679)+2-of-3 recovery)"
    );
    let temp = TempDir::new()?;
    let mut urandom = File::open("/dev/urandom")?;
    let user = Actor::random(&secp, &mut urandom)?;
    let node_pubkeys: Vec<String> = (0..5)
        .map(|_| Ok(Actor::random(&secp, &mut urandom)?.pubkey.to_string()))
        .collect::<Result<_, Error>>()?;
    // The recovery keyset: these are the keys that will actually SIGN the exit.
    let recovery: Vec<Actor> = (0..policy_core::RECOVERY_KEYS)
        .map(|_| Actor::random(&secp, &mut urandom))
        .collect::<Result<_, _>>()?;
    let recovery_pubkeys: Vec<String> = recovery.iter().map(|a| a.pubkey.to_string()).collect();

    let descriptor_str = policy_core::vault_descriptor_string(
        &user.pubkey.to_string(),
        3,
        &node_pubkeys,
        &recovery_pubkeys,
    );
    let descriptor = Descriptor::<PublicKey>::from_str(&descriptor_str)?;
    // The built descriptor must be ON-template — the same check every node runs at
    // startup — so the drill can never demonstrate an exit the nodes would reject.
    let template = policy_core::parse_vault_template(&Descriptor::<DescriptorPublicKey>::from_str(
        &descriptor_str,
    )?)
    .map_err(|e| format!("the demo vault descriptor is off-template: {e}"))?;
    if template.recovery_timelock != policy_core::RECOVERY_TIMELOCK_NSEQUENCE {
        return Err(format!(
            "recovery timelock is older({}), not the BIP68 time-based older({})",
            template.recovery_timelock,
            policy_core::RECOVERY_TIMELOCK_NSEQUENCE
        )
        .into());
    }
    let witness_script = descriptor.explicit_script()?;
    let vault_spk = descriptor.script_pubkey();
    let vault_address = descriptor.address(Network::Regtest)?;
    println!(
        "      recovery branch present: older({}) + {}-of-{} (BIP68 time-lock, {} units of 512s)",
        template.recovery_timelock,
        policy_core::RECOVERY_THRESHOLD,
        policy_core::RECOVERY_KEYS,
        policy_core::RECOVERY_TIMELOCK_UNITS,
    );

    println!("[2/6] starting private regtest bitcoind, funding the vault");
    let port = free_ports(1)?[0];
    let mut bitcoind = Bitcoind::start(temp.path.join("bitcoind"), port)?;
    bitcoind.create_wallet("recovery-drill")?;
    let miner = bitcoind.call_str("getnewaddress", json!([]))?;
    bitcoind.call("generatetoaddress", json!([101, miner]))?;
    let funding_txid = bitcoind.call_str(
        "sendtoaddress",
        json!([vault_address.to_string(), FUND.to_btc()]),
    )?;
    bitcoind.call("generatetoaddress", json!([1, miner]))?;
    let funding_tx: Transaction =
        deserialize_hex(&bitcoind.call_str("getrawtransaction", json!([funding_txid]))?)?;
    let (outpoint, txout) = vault_utxo(&funding_tx, &vault_spk)?;
    println!("      vault funded: {outpoint} = {}", txout.value);

    // The recovery destination: an address this regtest wallet can see, so the
    // swept funds are verifiable on confirmation.
    let dest = bitcoind.call_str("getnewaddress", json!([]))?;
    let dest_spk = address_spk(&bitcoind, &dest)?;
    let sweep = txout
        .value
        .checked_sub(FEE)
        .ok_or("vault value cannot cover the recovery fee")?;

    println!("[3/6] a recovery spend BEFORE the timelock matures is consensus-rejected");
    let recovery_tx = build_recovery_spend(
        &secp,
        outpoint,
        &txout,
        &witness_script,
        &dest_spk,
        sweep,
        &recovery,
    )?;
    let recovery_hex = serialize_hex(&recovery_tx);
    match bitcoind.call("sendrawtransaction", json!([recovery_hex])) {
        Ok(_) => return Err("a pre-maturity recovery spend must be consensus-rejected".into()),
        Err(e) if e.to_string().contains("non-BIP68-final") => {
            println!("      REJECTED (non-BIP68-final) — the 180-day relative lock is real")
        }
        Err(e) => return Err(format!("recovery spend rejected, but not for BIP68: {e}").into()),
    }

    println!("[4/6] 2-of-3 recovery signatures are required (1-of-3 cannot finalize)");
    match build_recovery_spend(
        &secp,
        outpoint,
        &txout,
        &witness_script,
        &dest_spk,
        sweep,
        &recovery[..policy_core::RECOVERY_THRESHOLD - 1],
    ) {
        Ok(_) => return Err("a 1-of-3 recovery spend must not finalize".into()),
        // Only the SATISFIER's threshold refusal proves the 2-of-3 property. An
        // unrelated construction failure (PSBT/sighash) would otherwise let this
        // negative test "pass" for the wrong reason, so match the specific
        // finalize-does-not-satisfy error and treat anything else as a real failure.
        Err(e)
            if e.to_string()
                .contains("does not satisfy the recovery branch") =>
        {
            println!("      1-of-3 refused to finalize — the recovery keyset threshold holds")
        }
        Err(e) => {
            return Err(format!(
                "1-of-3 spend failed to build, but NOT at the threshold check: {e}"
            )
            .into())
        }
    }

    println!(
        "[5/6] advancing MEDIAN-TIME-PAST past the 512-sec-unit relative lock, then broadcasting"
    );
    advance_mtp_past_recovery_lock(&bitcoind, &miner)?;
    let confirmed_txid = bitcoind.call_str("sendrawtransaction", json!([recovery_hex]))?;
    bitcoind.call("generatetoaddress", json!([1, miner]))?;
    let confirmations = bitcoind.call("getrawtransaction", json!([confirmed_txid, true]))?
        ["confirmations"]
        .as_i64()
        .unwrap_or(0);
    if confirmations < 1 {
        return Err(format!("matured recovery spend {confirmed_txid} did not confirm").into());
    }
    println!(
        "      recovery spend {confirmed_txid} confirmed ({confirmations} conf) — funds exited via the recovery branch"
    );

    println!("[6/6] a node watchtower classifies the spend as RECOVERY_PATH_SPEND");
    let backend = BitcoindBackend::new(bitcoind.rpc_addr(), bitcoind.auth().to_string());
    let alerts = scan(
        &backend,
        std::slice::from_ref(&vault_spk),
        &HashSet::new(),
        0,
    )?;
    let alert = alerts
        .iter()
        .find(|a| a.spend_txid == confirmed_txid)
        .ok_or("the watchtower saw no spend of the vault script")?;
    if alert.kind != AlertKind::RecoveryPathSpend {
        return Err(format!(
            "the watchtower misclassified the recovery spend as {:?}, not RECOVERY_PATH_SPEND",
            alert.kind
        )
        .into());
    }
    println!("      watchtower alert: {}", serde_json::to_string(alert)?);

    println!(
        "\nRECOVERY DRILL COMPLETE — the timelocked recovery branch spent after MTP maturity, \
         the watchtower alerted. V0-4b's \"funds frozen → recovery\" is demonstrable."
    );
    Ok(())
}

/// Build, sign, and finalize a recovery-path spend of the single vault UTXO. The
/// input carries the BIP68 time-unit relative-lock `nSequence`
/// ([`policy_core::recovery_sequence`]), and the spend is satisfied by
/// `recovery_keys` alone — no user key, no node partials. `finalize_mut` (via
/// rust-miniscript) selects the recovery branch and builds its witness; it returns
/// `Err` when the supplied keys do not meet the 2-of-3 threshold, which is exactly
/// how the "1-of-3 is insufficient" property is enforced.
fn build_recovery_spend(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    outpoint: OutPoint,
    txout: &TxOut,
    witness_script: &ScriptBuf,
    dest_spk: &ScriptBuf,
    value: Amount,
    recovery_keys: &[Actor],
) -> Result<Transaction, Error> {
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            // The BIP68 TIME-based relative lock (30375 units of 512s + type-flag),
            // set from the descriptor's own `older(...)` value so the spend and the
            // script agree by construction. NOT Sequence::MAX (which disables the
            // relative lock and would fail to satisfy the recovery branch).
            sequence: policy_core::recovery_sequence(),
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            script_pubkey: dest_spk.clone(),
            value,
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(tx)?;
    psbt.inputs[0].witness_utxo = Some(txout.clone());
    psbt.inputs[0].witness_script = Some(witness_script.clone());
    let unsigned = psbt.unsigned_tx.clone();
    let sighash = SighashCache::new(&unsigned).p2wsh_signature_hash(
        0,
        witness_script,
        txout.value,
        EcdsaSighashType::All,
    )?;
    for actor in recovery_keys {
        let signature = secp.sign_ecdsa(
            &Message::from_digest(sighash.to_byte_array()),
            &actor.seckey,
        );
        psbt.inputs[0].partial_sigs.insert(
            actor.pubkey,
            bitcoin::ecdsa::Signature {
                signature,
                sighash_type: EcdsaSighashType::All,
            },
        );
    }
    // Reuse the caller's `secp` (`All` implements `Verification`) rather than
    // building a fresh verification-only context per call — context creation does
    // non-trivial precomputation.
    psbt.finalize_mut(secp).map_err(|e| {
        format!(
            "recovery spend does not satisfy the recovery branch (insufficient signatures?): {e:?}"
        )
    })?;
    Ok(psbt.extract_tx()?)
}

/// Advance the chain's MEDIAN-TIME-PAST past the recovery branch's 512-second-unit
/// relative lock. A TIME-based BIP68 lock matures on MTP, not block height, so this
/// bumps the node's clock (`setmocktime`) and mines a handful of blocks that carry
/// that timestamp — NOT 30375 blocks. It mines > 11 blocks with strictly-advancing
/// timestamps so the tip's MTP (the median of the last 11) clears the lock cleanly.
fn advance_mtp_past_recovery_lock(bitcoind: &Bitcoind, miner: &str) -> Result<(), Error> {
    let mediantime = bitcoind.call("getblockchaininfo", json!([]))?["mediantime"]
        .as_u64()
        .ok_or("getblockchaininfo has no mediantime")?;
    let lock_secs = u64::from(policy_core::RECOVERY_TIMELOCK_UNITS) * 512;
    // Jump the clock past the lock (plus an hour of slack), then keep bumping so
    // successive blocks have strictly increasing timestamps.
    let mut mocktime = mediantime + lock_secs + 3_600;
    for _ in 0..13 {
        bitcoind.call("setmocktime", json!([mocktime]))?;
        bitcoind.call("generatetoaddress", json!([1, miner]))?;
        mocktime += 600;
    }
    Ok(())
}

/// The vault UTXO within `funding_tx` — the output paying the vault scriptPubKey.
fn vault_utxo(funding_tx: &Transaction, vault_spk: &ScriptBuf) -> Result<(OutPoint, TxOut), Error> {
    let vout = funding_tx
        .output
        .iter()
        .position(|o| o.script_pubkey == *vault_spk)
        .ok_or("funding transaction paid no vault output")?;
    Ok((
        OutPoint::new(funding_tx.compute_txid(), vout as u32),
        funding_tx.output[vout].clone(),
    ))
}

/// The scriptPubKey of a bitcoind-owned address (the recovery destination).
fn address_spk(bitcoind: &Bitcoind, address: &str) -> Result<ScriptBuf, Error> {
    let hex = bitcoind.call("getaddressinfo", json!([address]))?["scriptPubKey"]
        .as_str()
        .ok_or("getaddressinfo has no scriptPubKey")?
        .to_string();
    Ok(ScriptBuf::from_hex(&hex)?)
}
