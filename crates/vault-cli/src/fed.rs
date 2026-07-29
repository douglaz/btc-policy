//! The regtest federation substrate: keys, the setup ceremony, node processes,
//! and the PSBT plumbing every scenario needs.
//!
//! Extracted from `demo first-light` so `demo` and `attack` drive the SAME
//! bring-up. That sharing is deliberate rather than tidy: the adversarial harness
//! is only evidence about production if the federation it attacks is the one the
//! honest demo proves works. A second, harness-local bring-up could drift into a
//! weaker vault — a looser cap, a stale manifest field — and every safety
//! assertion made against it would be about that weaker vault instead.
//!
//! Nothing here computes a manifest byte itself: [`Manifest::assemble`] delegates
//! to [`crate::setup`], which delegates to `vault_node::channel::ceremony` — the
//! node's own definitions — so a federation this provisions agrees with itself by
//! construction. It is also literally the code `btc-vault setup` runs, so the demos
//! are evidence about the production ceremony rather than about a harness twin.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::str::FromStr;
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bitcoin::absolute::LockTime;
use bitcoin::bip32::{Xpriv, Xpub};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1::{All, Message, Secp256k1, SecretKey};
use bitcoin::sighash::SighashCache;
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, CompressedPublicKey, EcdsaSighashType, NetworkKind, OutPoint, Psbt, PublicKey,
    ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use miniscript::{Descriptor, DescriptorPublicKey};
use vault_proto::{SignRequest, SignResponse, TaggedRequest, MAX_PIN_BYTES};
use zeroize::Zeroizing;

use crate::http::{self, Error};
use crate::setup;

// ---------------------------------------------------------------------------
// Keys and destinations

pub(crate) struct Actor {
    pub(crate) seckey: SecretKey,
    pub(crate) pubkey: PublicKey,
}

impl Actor {
    pub(crate) fn random(secp: &Secp256k1<All>, urandom: &mut File) -> Result<Actor, Error> {
        loop {
            let mut bytes = [0u8; 32];
            urandom.read_exact(&mut bytes)?;
            if let Ok(seckey) = SecretKey::from_slice(&bytes) {
                return Ok(Actor {
                    seckey,
                    pubkey: PublicKey::new(seckey.public_key(secp)),
                });
            }
        }
    }
}

pub(crate) fn p2wpkh_spk(actor: &Actor) -> ScriptBuf {
    ScriptBuf::new_p2wpkh(&CompressedPublicKey(actor.pubkey.inner).wpubkey_hash())
}

/// The coordinator's authentication identity (ADR-0013 §2). Generated ONCE per
/// vault; its public half is provisioned into every node's per-vault config
/// (`coordinator_auth_pubkey`) and hashed into the channel manifest. Its secret
/// half signs every relayed request, so each node authenticates before evaluating.
///
/// The whole duress threat model turns on who holds this: it is honest until the
/// wrench and hostile from that moment (ADR-0012 threat model). The attack harness
/// therefore drives this same type — a post-wrench coordinator is not a different
/// implementation, it is this one making different choices about what to relay and
/// to whom.
pub(crate) struct Coordinator {
    pub(crate) seckey: SecretKey,
    pub(crate) pubkey: PublicKey,
}

impl Coordinator {
    pub(crate) fn random(secp: &Secp256k1<All>, urandom: &mut File) -> Result<Coordinator, Error> {
        let actor = Actor::random(secp, urandom)?;
        Ok(Coordinator {
            seckey: actor.seckey,
            pubkey: actor.pubkey,
        })
    }

    /// Turn an unauthenticated spend body into a coordinator-authenticated request:
    /// attach a fresh single-use nonce and the coordinator's signature over the
    /// canonical request bytes (ADR-0013 §2).
    pub(crate) fn authorize(
        &self,
        secp: &Secp256k1<All>,
        wallet_id: &[u8; 32],
        mut request: SignRequest,
    ) -> Result<SignRequest, Error> {
        request.nonce = fresh_nonce()?;
        // `coord_request()` selects the signed fields; coord_sig is excluded from
        // its own preimage, so it needs no clearing before the digest. `wallet_id`
        // is bound into the digest as a domain separator (H2): pass the id of the
        // vault this coordinator is authorizing, which is the id its nodes verify.
        let digest = request.coord_request().auth_digest(wallet_id);
        let sig = secp.sign_ecdsa(&Message::from_digest(digest), &self.seckey);
        request.coord_sig = sig.serialize_der().to_lower_hex_string();
        Ok(request)
    }
}

/// A fresh 32-byte random nonce as lowercase hex — single-use per request so a
/// node rejects any replay (ADR-0013 §2/§3).
pub(crate) fn fresh_nonce() -> Result<String, Error> {
    let mut bytes = [0u8; 32];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes.to_lower_hex_string())
}

/// A ranged single-sig destination wallet: a `wpkh(<xpub>/*)` descriptor from a
/// throwaway master key, from which the coordinator derives a fresh address per
/// index. This is the shape of a hot/escape allowlist entry.
pub(crate) struct Wallet {
    /// The canonical descriptor string (with checksum) placed in the node config.
    pub(crate) descriptor: String,
    parsed: Descriptor<DescriptorPublicKey>,
}

impl Wallet {
    pub(crate) fn random(secp: &Secp256k1<All>, urandom: &mut File) -> Result<Wallet, Error> {
        let mut seed = [0u8; 32];
        urandom.read_exact(&mut seed)?;
        let xpriv = Xpriv::new_master(NetworkKind::Test, &seed)?;
        let xpub = Xpub::from_priv(secp, &xpriv);
        let parsed = Descriptor::<DescriptorPublicKey>::from_str(&format!("wpkh({xpub}/*)"))?;
        Ok(Wallet {
            descriptor: parsed.to_string(),
            parsed,
        })
    }

    /// The scriptPubKey of this wallet's address at `index`.
    pub(crate) fn address_spk(
        &self,
        secp: &Secp256k1<All>,
        index: u32,
    ) -> Result<ScriptBuf, Error> {
        Ok(self.parsed.derived_descriptor(secp, index)?.script_pubkey())
    }
}

/// `wallet_id` — the hash of the canonical vault descriptor — computed exactly as
/// the node computes it, so the manifest this ceremony hashes is the one every
/// node re-derives.
pub(crate) fn wallet_id(descriptor: &Descriptor<PublicKey>) -> [u8; 32] {
    sha256::Hash::hash(descriptor.to_string().as_bytes()).to_byte_array()
}

// ---------------------------------------------------------------------------
// PSBT plumbing

#[derive(Clone)]
pub(crate) struct Utxo {
    pub(crate) outpoint: OutPoint,
    pub(crate) txout: TxOut,
}

pub(crate) fn utxo_paying(tx: &Transaction, spk: &ScriptBuf) -> Result<Utxo, Error> {
    let vout = tx
        .output
        .iter()
        .position(|output| output.script_pubkey == *spk)
        .ok_or("transaction has no output paying the expected script")?;
    Ok(Utxo {
        outpoint: OutPoint::new(tx.compute_txid(), vout as u32),
        txout: tx.output[vout].clone(),
    })
}

pub(crate) fn build_spend(
    utxo: &Utxo,
    witness_script: &ScriptBuf,
    outputs: &[(ScriptBuf, Amount)],
) -> Result<Psbt, Error> {
    build_spend_n(std::slice::from_ref(utxo), witness_script, outputs)
}

/// The multi-input form. The escape sweeps the whole vault, so once a scenario
/// creates a second vault UTXO (a refresh output, a change output) the escape must
/// spend every one of them or fail the node's coverage check.
pub(crate) fn build_spend_n(
    utxos: &[Utxo],
    witness_script: &ScriptBuf,
    outputs: &[(ScriptBuf, Amount)],
) -> Result<Psbt, Error> {
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: utxos
            .iter()
            .map(|utxo| TxIn {
                previous_output: utxo.outpoint,
                script_sig: ScriptBuf::new(),
                // `Sequence::MAX` is non-relative-locking and non-RBF-signalling,
                // which is what the node's broadcastable-at-T check requires of an
                // escape (ADR-0012). Every spend here uses it so the escape variant
                // built from the same helper passes.
                sequence: Sequence::MAX,
                witness: Witness::new(),
            })
            .collect(),
        output: outputs
            .iter()
            .map(|(script_pubkey, value)| TxOut {
                script_pubkey: script_pubkey.clone(),
                value: *value,
            })
            .collect(),
    };
    let mut psbt = Psbt::from_unsigned_tx(tx)?;
    for (index, utxo) in utxos.iter().enumerate() {
        psbt.inputs[index].witness_utxo = Some(utxo.txout.clone());
        psbt.inputs[index].witness_script = Some(witness_script.clone());
    }
    Ok(psbt)
}

/// The `nSequence` every rung of a fee-bump ladder carries: BIP125-replaceable
/// (`< 0xfffffffe`) with bit 31 still set, so BIP68 relative timelocks stay
/// disabled. The node checks this exact value at ingress, so it comes from the
/// shared wire crate rather than from a second copy tied only by a comment.
const ESCAPE_RBF_SEQUENCE: u32 = vault_proto::ESCAPE_RBF_SEQUENCE;

/// Multipliers on the base escape's fee, one per ladder rung (bead
/// btc-policy-9y5.7). Geometric so three rungs span two orders of magnitude of
/// feerate: a spike that a 4× bump does not clear is usually one that needs 16× or
/// 64×, and intermediate steps would only add stored PSBTs without adding reach.
const ESCAPE_BUMP_MULTIPLIERS: [u64; 3] = [4, 16, 64];

/// A ladder longer than the node's bound is refused at ingress — and that refusal
/// takes the whole spend with it, not just the bump. Fail at COMPILE time instead.
const _: () = assert!(ESCAPE_BUMP_MULTIPLIERS.len() <= vault_proto::MAX_ESCAPE_BUMPS);

/// The share of the swept value the top ladder rung may pay in fee.
///
/// The node's own guard is the coverage check (fee ≤ `100 − escape_coverage_pct`
/// percent, i.e. 5% by default), enforced at fire time on whichever rung is
/// selected. This coordinator-side bound sits an order of magnitude below it, so a
/// composed ladder never proposes a rung the node would refuse and never brushes
/// the policy fee cap either.
const ESCAPE_BUMP_MAX_FEE_PCT: u64 = 1;

/// Below this the reduced escape output would be dust, so the rung is dropped.
const ESCAPE_BUMP_MIN_OUTPUT_SAT: u64 = 10_000;

/// **Compose the escape's pre-signed fee-bump ladder** (bead btc-policy-9y5.7).
///
/// Returns the escape rewritten as the ladder's base — same inputs, same outputs,
/// same values, only its `nSequence` changed to signal BIP125 replacement — plus the
/// higher-fee rungs. The federation cannot raise a fee on its own (the escape is
/// user-signed SIGHASH_ALL over its exact bytes), so the only bump that can ever
/// exist is one the user authorizes here, at composition time, alongside the escape
/// itself. The caller user-signs the base and every rung.
///
/// Each rung takes the extra fee out of the LARGEST escape output and changes nothing
/// else — same inputs, same output scripts, strictly higher fee — which is exactly
/// the shape the node's `ensure_escape_ladder` requires. Rungs that would exceed
/// [`ESCAPE_BUMP_MAX_FEE_PCT`] of the swept value, leave a dust output, or raise the
/// fee over the rung below by LESS than the node's incremental-relay minimum are
/// simply not offered: an unoffered rung is a bump that cannot happen, which is the
/// correct failure direction.
///
/// **The incremental-relay filter is load-bearing (bead btc-policy-9y5.7).** The node
/// refuses at ingress any rung whose absolute fee increase over the rung below it is
/// under `maximum_finalized_vsize · incremental_relay_rate`, and that refusal takes
/// the WHOLE `SpendRequest` — the duress carrier included. A small base fee makes the
/// unconditional 4× rung's `3·base_fee` delta fall under that minimum; offering it
/// would strand an otherwise-valid escape. So each rung is kept only if its fee clears
/// the last KEPT rung by at least the node's minimum, measured with the very same
/// [`vault_node::escape_replacement_min_fee_delta`] the node enforces (fed from the
/// vault descriptor's `max_weight_to_satisfy`, so the two cannot drift). Dropping a
/// too-close rung leaves the next rung a LARGER gap to clear; if none can, the escape
/// gets no ladder and degrades to the recovery path — never theft.
///
/// An escape with no outputs, no inputs, or an unknown input value gets NO ladder
/// (and keeps `Sequence::MAX`) rather than a half-formed one.
pub(crate) fn escape_fee_ladder(
    escape: &Psbt,
    max_vault_satisfaction_weight: u64,
) -> Result<(Psbt, Vec<Psbt>), Error> {
    let total_in = escape.inputs.iter().try_fold(0u64, |total, input| {
        input
            .witness_utxo
            .as_ref()
            .map(|utxo| total.saturating_add(utxo.value.to_sat()))
    });
    let Some(total_in) = total_in else {
        return Ok((escape.clone(), Vec::new()));
    };
    // Fund each bump's fee from the LARGEST escape output, not the last: a multi-output
    // escape whose LAST output is small would otherwise silently get fewer or zero rungs
    // even when the total swept value could easily fund them (Fable 9y5.7 review). The
    // node accepts a bump that shrinks ANY output — it checks same output scripts in the
    // same order + a strictly higher fee, never which output shrank — so drawing from the
    // largest output is valid. Ties break to the lowest index for a deterministic choice.
    let Some(fund_idx) = escape
        .unsigned_tx
        .output
        .iter()
        .enumerate()
        .max_by_key(|(index, output)| (output.value.to_sat(), std::cmp::Reverse(*index)))
        .map(|(index, _)| index)
    else {
        return Ok((escape.clone(), Vec::new()));
    };
    let total_out = escape
        .unsigned_tx
        .output
        .iter()
        .fold(0u64, |total, output| {
            total.saturating_add(output.value.to_sat())
        });
    let base_fee = total_in.saturating_sub(total_out);
    let mut base = escape.clone();
    for input in &mut base.unsigned_tx.input {
        input.sequence = Sequence::from_consensus(ESCAPE_RBF_SEQUENCE);
    }
    let fee_ceiling = total_in.saturating_mul(ESCAPE_BUMP_MAX_FEE_PCT) / 100;
    let fund_value = base.unsigned_tx.output[fund_idx].value.to_sat();
    // The node's per-rung minimum absolute fee increase, computed the SAME way it does
    // (`maximum_finalized_vsize · incremental_relay_rate`). Every rung shares the base's
    // inputs and output scripts, so the finalized size — and hence this minimum — is one
    // value for the whole ladder; bound it once from the base.
    let minimum_delta = vault_node::escape_replacement_min_fee_delta(
        max_vault_satisfaction_weight,
        &base.unsigned_tx,
    )
    .map_err(Error::from)?;
    let mut rungs = Vec::new();
    // The fee of the last rung actually KEPT (the base to start): a dropped rung is not
    // submitted, so the node measures the next rung's delta against this, not against the
    // rung that was skipped.
    let mut last_kept_fee = base_fee;
    for multiplier in ESCAPE_BUMP_MULTIPLIERS {
        let fee = base_fee.saturating_mul(multiplier);
        let extra = fee.saturating_sub(base_fee);
        if fee <= base_fee || fee > fee_ceiling {
            continue;
        }
        // A rung whose delta over the last kept rung is under the node's incremental-relay
        // minimum would be refused at ingress, taking the whole spend with it. Skip it: the
        // next multiplier clears a larger gap over this same `last_kept_fee`.
        if fee.saturating_sub(last_kept_fee) < minimum_delta {
            continue;
        }
        let Some(reduced) = fund_value.checked_sub(extra) else {
            continue;
        };
        if reduced < ESCAPE_BUMP_MIN_OUTPUT_SAT {
            continue;
        }
        let mut rung = base.clone();
        rung.unsigned_tx.output[fund_idx].value = Amount::from_sat(reduced);
        rungs.push(rung);
        last_kept_fee = fee;
    }
    // Without a rung there is nothing to replace, so leave the escape exactly as it
    // was: non-signalling and final through `nSequence`, the pre-ladder shape the
    // node still requires of a ladder-less escape.
    if rungs.is_empty() {
        return Ok((escape.clone(), Vec::new()));
    }
    Ok((base, rungs))
}

pub(crate) fn sign_all_inputs(
    secp: &Secp256k1<All>,
    psbt: &mut Psbt,
    signer: &Actor,
    witness_script: &ScriptBuf,
) -> Result<(), Error> {
    let unsigned_tx = psbt.unsigned_tx.clone();
    let mut cache = SighashCache::new(&unsigned_tx);
    for (index, input) in psbt.inputs.iter_mut().enumerate() {
        let utxo = input
            .witness_utxo
            .as_ref()
            .ok_or_else(|| format!("input {index} has no witness_utxo"))?;
        let sighash =
            cache.p2wsh_signature_hash(index, witness_script, utxo.value, EcdsaSighashType::All)?;
        let signature = secp.sign_ecdsa(
            &Message::from_digest(sighash.to_byte_array()),
            &signer.seckey,
        );
        input.partial_sigs.insert(
            signer.pubkey,
            bitcoin::ecdsa::Signature {
                signature,
                sighash_type: EcdsaSighashType::All,
            },
        );
    }
    Ok(())
}

pub(crate) fn summarize(response: &SignResponse) -> String {
    serde_json::to_string(response).unwrap_or_else(|_| format!("{response:?}"))
}

pub(crate) fn unix_now() -> Result<u64, Error> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

/// A coordinator-proposed commitment expiry: the current wall clock plus `ttl`.
/// Each node re-checks it against its own clock and cap.
pub(crate) fn commitment_expiry(ttl_secs: u64) -> Result<u64, Error> {
    Ok(unix_now()? + ttl_secs)
}

// ---------------------------------------------------------------------------
// The setup ceremony
//
// The harness plays the CEREMONY, not a shortcut around it. Every node-side step
// runs in its OWN process against its OWN directory (`NodeDevice`), and this
// process — the coordinator — only ever handles the public bytes those processes
// print. That is not decoration: the property the ceremony exists to establish is
// "no machine holds two node secrets", and a bring-up that generated five keys in
// one address space would be evidence about a different system than the one
// `btc-vault setup` provisions.

/// One node HOST, as a single-machine harness can model one: a directory that
/// stands in for that node's own machine, holding its own preimage and its own
/// published bundle.
///
/// The coordinator process **never reads the preimage**. It passes the file to a
/// child on stdin (`Stdio::from(File)`, so the bytes go kernel-to-kernel) and
/// otherwise touches only the path. The one exception is [`NodeDevice::compromise`],
/// which is the adversary taking the host — and taking the host is exactly how a
/// real attacker gets a node key.
///
/// The preimage IS a file here, which production's `setup node-keygen` deliberately
/// avoids: a real ceremony prints it once for a human to write down. A regtest run
/// has no human, so the harness uses the documented `--preimage-file` automation
/// escape hatch, in the node's own directory. That is the ONE deviation the demo
/// federation makes from the production key path, and it is confined to this type.
pub(crate) struct NodeDevice {
    /// This node host's own directory.
    dir: PathBuf,
    /// The operator secret, in the node's own directory and nowhere else.
    preimage_path: PathBuf,
    bundle: setup::NodeBundle,
    pub(crate) signing_pubkey: PublicKey,
    pub(crate) port: u16,
}

/// The Argon2id cost the harness derives node keys at: the implementation floor.
/// `attack all` stands up sixteen five-node federations, each key derived twice
/// (keygen, then the daemon), and production cost would add minutes to a run while
/// proving nothing — the derivation's CORRECTNESS is what the harness exercises,
/// and that is cost-independent.
const HARNESS_KDF_OPS: u32 = 1;
const HARNESS_KDF_MEM_KIB: u32 = 8;

impl NodeDevice {
    /// Run `btc-vault setup node-keygen` ON this device. The key is born in that
    /// child process, on this host, and only its PUBLIC half comes back.
    pub(crate) fn provision(cli: &Path, dir: PathBuf, port: u16) -> Result<NodeDevice, Error> {
        std::fs::create_dir_all(&dir)?;
        let preimage_path = dir.join("preimage");
        // Owner-only: node-keygen redirects its banner — WHICH INCLUDES THE PREIMAGE —
        // here, and this box may be multi-tenant. Even a modeled regtest preimage must
        // not be world-readable during the run.
        let log = File::options()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(dir.join("keygen.log"))?;
        let output = Command::new(cli)
            .args(["setup", "node-keygen", "--device-dir"])
            .arg(&dir)
            .args(["--endpoint", &format!("127.0.0.1:{port}")])
            .args(["--kdf-ops", &HARNESS_KDF_OPS.to_string()])
            .args(["--kdf-mem-kib", &HARNESS_KDF_MEM_KIB.to_string()])
            // This regtest harness builds many nodes per run and derives at the KDF
            // floor for speed; production keygen refuses that without this opt-in.
            .arg("--allow-weak-kdf")
            .arg("--preimage-file")
            .arg(&preimage_path)
            // The keygen banner (including the preimage) goes to the device's own
            // log, never to this process's stdout/stderr.
            .stderr(log)
            .stdin(Stdio::null())
            .output()
            .map_err(|e| format!("cannot run {} setup node-keygen: {e}", cli.display()))?;
        if !output.status.success() {
            return Err(format!(
                "node-keygen failed on {} ({}): {}",
                dir.display(),
                output.status,
                log_tail(&dir.join("keygen.log"))
            )
            .into());
        }
        let bundle: setup::NodeBundle = serde_json::from_slice(&output.stdout)
            .map_err(|e| format!("node-keygen did not publish a readable bundle: {e}"))?;
        let signing_pubkey = bundle.signing_pubkey()?;
        Ok(NodeDevice {
            dir,
            preimage_path,
            bundle,
            signing_pubkey,
            port,
        })
    }

    pub(crate) fn bundle(&self) -> &setup::NodeBundle {
        &self.bundle
    }

    /// Round two, ON this device: re-derive the key from the preimage and endorse
    /// this node's channel identity over the freshly agreed `manifest_hash`.
    fn endorse(
        &self,
        cli: &Path,
        wallet_id: &[u8; 32],
        manifest_hash: &str,
        node_id: u16,
    ) -> Result<String, Error> {
        // Owner-only for the same reason as keygen.log: node-endorse re-derives from
        // the preimage, and its banner is redirected here.
        let log = File::options()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(self.dir.join("endorse.log"))?;
        let output = Command::new(cli)
            .args(["setup", "node-endorse", "--device-dir"])
            .arg(&self.dir)
            .args(["--wallet-id", &wallet_id.to_lower_hex_string()])
            .args(["--manifest-hash", manifest_hash])
            .args(["--node-id", &node_id.to_string()])
            // The preimage reaches the child on stdin without this process ever
            // holding the bytes.
            .stdin(Stdio::from(File::open(&self.preimage_path)?))
            .stderr(log)
            .output()
            .map_err(|e| format!("cannot run {} setup node-endorse: {e}", cli.display()))?;
        if !output.status.success() {
            return Err(format!(
                "node-endorse failed for node {node_id} ({}): {}",
                output.status,
                log_tail(&self.dir.join("endorse.log"))
            )
            .into());
        }
        Ok(String::from_utf8(output.stdout)?.trim().to_string())
    }

    /// TAKE THIS HOST. Reads the device's own preimage and re-derives its signing
    /// key — precisely what an attacker with root on a node host obtains, and the
    /// only way the adversarial harness can play a compromised node (it has to
    /// hold that node's keys to combine partials as it does).
    ///
    /// Nothing else in the harness may call this: it is the one place a node secret
    /// legitimately enters the coordinator process, because at that point the
    /// coordinator process IS the attacker.
    pub(crate) fn compromise(&self, secp: &Secp256k1<All>) -> Result<Actor, Error> {
        let preimage = vault_node::nodekey::Preimage::from_hex(&std::fs::read_to_string(
            &self.preimage_path,
        )?)?;
        let seckey = vault_node::nodekey::derive(&preimage, &self.bundle.kdf()?)?;
        Ok(Actor {
            seckey,
            pubkey: PublicKey::new(seckey.public_key(secp)),
        })
    }
}

/// The assembled per-vault manifest (ADR-0013 §4): the frozen descriptor, the hash
/// every node is sealed to, and each node's channel endorsement — all computed by
/// [`setup`], the same code path `btc-vault setup assemble`/`finalize` runs.
pub(crate) struct Manifest {
    assembled: setup::Assembled,
    endorsements: BTreeMap<u16, String>,
    pub(crate) manifest_hash: String,
}

/// Everything the ceremony seals besides membership. Bundled because the manifest
/// hash and the generated node configs must emit the SAME values — a manifest
/// sealed over one Hot budget and configs written with another is a federation
/// that cannot boot, and passing them separately is how that drifts.
pub(crate) struct CeremonyParams<'a> {
    pub(crate) hot_allowlist: &'a [String],
    pub(crate) escape_descriptor: &'a str,
    pub(crate) threshold: usize,
    pub(crate) user_key: PublicKey,
    pub(crate) recovery_keys: &'a [PublicKey],
}

impl Manifest {
    /// Run both ceremony rounds over `devices`, which have already published their
    /// public bundles. Returns the sealed manifest AND the frozen descriptor: the
    /// ceremony produces the descriptor, so nothing upstream may build its own.
    pub(crate) fn assemble(
        cli: &Path,
        coord_auth_pubkey: &PublicKey,
        devices: &[NodeDevice],
        ceremony: &CeremonyParams,
        params: &NodeParams,
    ) -> Result<Manifest, Error> {
        let bundles: Vec<setup::NodeBundle> = devices.iter().map(|d| d.bundle().clone()).collect();
        let assembled = setup::assemble(
            &bundles,
            ceremony.threshold,
            ceremony.user_key,
            ceremony.recovery_keys,
            *coord_auth_pubkey,
            ceremony.escape_descriptor,
            ceremony.hot_allowlist,
            &params.policy(),
        )?;
        let manifest_hash = assembled.manifest_hash.to_lower_hex_string();

        // Round two: each device endorses its own channel key, in its own process.
        let mut endorsements = BTreeMap::new();
        for node in &assembled.nodes {
            let device = devices
                .iter()
                .find(|d| d.signing_pubkey == node.signing_pubkey)
                .ok_or("assembled node is not one of the provisioned devices")?;
            let endorsement =
                device.endorse(cli, &assembled.wallet_id, &manifest_hash, node.node_id)?;
            // Verify before sealing, exactly as `setup finalize` does: a bad
            // endorsement is otherwise a federation that fails startup after the
            // hosts are sealed.
            assembled.verify_endorsement(node.node_id, &endorsement)?;
            endorsements.insert(node.node_id, endorsement);
        }
        Ok(Manifest {
            assembled,
            endorsements,
            manifest_hash,
        })
    }

    /// The frozen vault descriptor the ceremony produced.
    pub(crate) fn descriptor(&self) -> &str {
        &self.assembled.descriptor
    }

    pub(crate) fn wallet_id(&self) -> [u8; 32] {
        self.assembled.wallet_id
    }

    /// The federation signing keys, in `node_id` order.
    pub(crate) fn signing_pubkeys(&self) -> Vec<PublicKey> {
        self.assembled
            .nodes
            .iter()
            .map(|node| node.signing_pubkey)
            .collect()
    }

    /// The channel identities, in `node_id` order.
    pub(crate) fn channel_pubkeys(&self) -> Vec<PublicKey> {
        self.assembled
            .nodes
            .iter()
            .map(|node| node.channel_pubkey)
            .collect()
    }

    /// This device's `node_id` — its position in the canonical order.
    pub(crate) fn node_id_of(&self, device: &NodeDevice) -> u16 {
        self.assembled
            .nodes
            .iter()
            .find(|node| node.signing_pubkey == device.signing_pubkey)
            .map(|node| node.node_id)
            .expect("every provisioned device is in the manifest")
    }

    /// The `[channel]` config block for `node_id` (ADR-0013 §5), carrying the
    /// MANDATORY `expected_manifest_hash` anchor and the sealed `max_msg_bytes`.
    pub(crate) fn channel_toml(&self, node_id: u16) -> String {
        self.assembled.channel_toml(node_id, &self.endorsements)
    }

    /// The ceremony's key-independence evidence (ADR-0003, ADR-0012 §10).
    pub(crate) fn independence_report(&self) -> &str {
        &self.assembled.independence_report
    }
}

// ---------------------------------------------------------------------------
// Node processes

/// The per-vault policy numbers written into every node's config AND sealed into
/// the manifest. One struct because the ceremony and the config writer must agree
/// field for field.
#[derive(Clone)]
pub(crate) struct NodeParams {
    pub(crate) hold_secs: u64,
    pub(crate) duress_delay_secs: u64,
    pub(crate) epsilon_secs: u64,
    pub(crate) combine_slack_secs: u64,
    pub(crate) max_commitment_age_secs: u64,
    pub(crate) delivery_horizon_secs: u64,
    pub(crate) max_derivation_index: u32,
    pub(crate) policy_version: u32,
    pub(crate) max_msg_bytes: u64,
    pub(crate) hot_budget: vault_node::HotBudget,
    pub(crate) normal_pin: String,
    pub(crate) duress_pin: String,
    /// The Argon2id memory cost (KiB) the two pin slots are ENROLLED at. Left at
    /// the fixture minimum everywhere except the silence scenarios, whose timing
    /// assertion is only meaningful when one evaluation dominates measurement noise
    /// (`vault_node::argon2id_normal_phc_at`).
    pub(crate) pin_m_cost_kib: u32,
    /// The fire-time panic feerate floor (sats/vB). A scenario raises this to make
    /// an otherwise ordinary escape inadmissible AT FIRE TIME without touching its
    /// ingress validity.
    pub(crate) escape_feerate_floor: u64,
}

impl NodeParams {
    /// These params as the ONE policy struct the ceremony hashes and the config
    /// writer emits. Derived rather than carried separately so the sealed manifest
    /// cannot disagree with the configs it is sealed alongside.
    pub(crate) fn policy(&self) -> setup::PolicyParams {
        setup::PolicyParams {
            max_derivation_index: self.max_derivation_index,
            hold_secs: self.hold_secs,
            duress_delay_secs: self.duress_delay_secs,
            epsilon_secs: self.epsilon_secs,
            combine_slack_secs: self.combine_slack_secs,
            delivery_horizon_secs: self.delivery_horizon_secs,
            max_commitment_age_secs: self.max_commitment_age_secs,
            policy_version: self.policy_version,
            escape_feerate_floor: self.escape_feerate_floor,
            // The harness never varies coverage, so seal + emit the shared default;
            // a heterogeneity test would add the field to `NodeParams` and set it here.
            escape_coverage_pct: vault_node::DEFAULT_ESCAPE_COVERAGE_PCT,
            hot_max_per_tx: self.hot_budget.max_per_tx_sat,
            hot_max_per_window: self.hot_budget.max_per_window_sat,
            hot_window_secs: self.hot_budget.window_secs,
            max_msg_bytes: self.max_msg_bytes,
        }
    }
}

/// One timed `/sign` round trip: the parsed verdict, the wall-clock latency, and
/// the RAW response body.
///
/// The body is carried, not just its length, because the silence probe compares the
/// COMPLETE observable response between the two pins. A length-preserving
/// difference — a flipped boolean, a swapped enum spelling of the same width, a
/// field whose value differs but whose encoding does not — is exactly the leak a
/// size comparison cannot see, and it is the shape a duress bit would most likely
/// take.
pub(crate) struct Timed {
    pub(crate) response: SignResponse,
    pub(crate) elapsed: Duration,
    pub(crate) body: String,
}

pub(crate) struct NodeProcess {
    pub(crate) index: usize,
    pub(crate) node_id: u16,
    pub(crate) port: u16,
    child: Child,
    config_path: PathBuf,
    log_path: PathBuf,
    /// This node host's own preimage file. The daemon reads its signing key's
    /// preimage from stdin, so every launch — first, restart, or the reboot-death
    /// drill — has to be handed this path; the harness never reads the bytes.
    preimage_path: PathBuf,
    node_bin: PathBuf,
}

/// Everything one node's config needs. A struct because the list outgrew the point
/// where positional arguments stay readable.
pub(crate) struct NodeSpawn<'a> {
    pub(crate) index: usize,
    /// This node's own host. Supplies its listen port, its PUBLIC derivation
    /// parameters, and the preimage path the daemon reads its secret from.
    pub(crate) device: &'a NodeDevice,
    pub(crate) allowlist: &'a [String],
    pub(crate) escape_descriptor: &'a str,
    pub(crate) coord_auth_pubkey: &'a str,
    pub(crate) bitcoind_rpc_addr: SocketAddr,
    pub(crate) bitcoind_auth: &'a str,
    pub(crate) manifest: &'a Manifest,
    pub(crate) params: &'a NodeParams,
}

impl NodeProcess {
    pub(crate) fn spawn(
        node_bin: &Path,
        nodes_dir: &Path,
        spawn: NodeSpawn,
    ) -> Result<NodeProcess, Error> {
        let NodeSpawn {
            index,
            device,
            allowlist,
            escape_descriptor,
            coord_auth_pubkey,
            bitcoind_rpc_addr,
            bitcoind_auth,
            manifest,
            params,
        } = spawn;
        let node_id = manifest.node_id_of(device);
        let rpc_addr = bitcoind_rpc_addr.to_string();
        // ONE config writer for the ceremony and the harness (`setup::node_config_toml`),
        // so a field that reaches production configs reaches these too. It writes
        // `node_key_salt`/`_ops`/`_mem_kib` — the PUBLIC derivation — and no key:
        // the daemon's secret arrives on stdin below.
        //
        // `[chain_backend]` is MANDATORY here: with `[channel]` on, this node
        // combines and broadcasts, and a node that could not broadcast would accept
        // spends it can never complete.
        let config = setup::node_config_toml(&setup::NodeConfig {
            listen_port: device.port,
            kdf: &device.bundle().kdf()?,
            descriptor: manifest.descriptor(),
            allowlist,
            escape_descriptor,
            policy: &params.policy(),
            coordinator_auth_pubkey: coord_auth_pubkey,
            pin_normal_hash: &vault_node::argon2id_normal_phc_at(
                &params.normal_pin,
                params.pin_m_cost_kib,
            ),
            pin_duress_hash: &vault_node::argon2id_duress_phc_at(
                &params.duress_pin,
                params.pin_m_cost_kib,
            ),
            chain_backend: Some((&rpc_addr, bitcoind_auth)),
            channel_toml: &manifest.channel_toml(node_id),
        });
        let config_path = nodes_dir.join(format!("node{index}.toml"));
        std::fs::write(&config_path, config)?;
        let log_path = nodes_dir.join(format!("node{index}.log"));
        let preimage_path = device.preimage_path.clone();
        let child = spawn_child(node_bin, &config_path, &log_path, Some(&preimage_path))?;
        Ok(NodeProcess {
            index,
            node_id,
            port: device.port,
            child,
            config_path,
            log_path,
            preimage_path,
            node_bin: node_bin.to_path_buf(),
        })
    }

    /// 1-based, for humans.
    pub(crate) fn number(&self) -> usize {
        self.index + 1
    }

    pub(crate) fn addr(&self) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, self.port))
    }

    /// Block until this node is SERVING, not merely connectable.
    ///
    /// `vault-node`'s main binds the listener BEFORE `server::serve` claims the
    /// one-shot process generation, so the kernel completes a handshake for a node
    /// that may still die on that claim. A raw `connect` therefore declares ready a
    /// node that will never answer, and the scenario built on top of it fails later
    /// on a bare connection error instead of here on the startup log. A shaped
    /// vault-node `/events` projection cannot come from a listener whose serve loop
    /// never started or from an unrelated process that recycled the port — the same
    /// distinction `restart_must_be_refused` relies on for the opposite conclusion.
    pub(crate) fn wait_ready(&mut self) -> Result<(), Error> {
        // 15s covers a regtest boot with room to spare. On a real chain a node's FIRST
        // bring-up against a backend still seeds its descriptor wallet from a full
        // `scantxoutset` (~10s on a 72M-UTXO signet, serialized process-wide across
        // nodes) PLUS the `importdescriptors` rescan that scan's birthday implies —
        // negligible against an empty vault, but on an already-funded one it rescans
        // from the oldest live vault output and dominates. The signet driver raises
        // this via `VAULT_NODE_READY_TIMEOUT_SECS` for that one-time cost; later
        // restarts read the wallet instead and the demos keep the fast default.
        let secs = std::env::var("VAULT_NODE_READY_TIMEOUT_SECS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(15);
        let deadline = Instant::now() + Duration::from_secs(secs);
        while Instant::now() < deadline {
            if let Some(status) = self.child.try_wait()? {
                return Err(format!(
                    "node {} exited at startup ({status}): {}",
                    self.number(),
                    log_tail(&self.log_path)
                )
                .into());
            }
            if Self::is_serving(self.addr()) {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Err(format!(
            "node {} did not start serving: {}",
            self.number(),
            log_tail(&self.log_path)
        )
        .into())
    }

    /// Kill this node's process WITHOUT destroying its deployment, then try to
    /// start a second process against the same config/key inode. Returns the log
    /// line the attempt died on.
    ///
    /// This must FAIL. `Node::claim_process_generation` takes a one-shot xattr on
    /// the config/key inode at the serving boundary, so a second generation is
    /// refused outright rather than resumed — "refusing to reload a signing key
    /// whose RAM-only Armed/candidate state may have died". The Lockdown latch is
    /// defence-in-depth beneath that refusal, not a resume path.
    ///
    /// So this is reboot-death enforced ONE LEVEL EARLIER than the tmpfs: even when
    /// the deployment survives the kill, there is no way back to signing.
    pub(crate) fn restart_must_be_refused(&mut self) -> Result<String, Error> {
        let _ = self.child.kill();
        let _ = self.child.wait();
        // The second generation gets the preimage, so it reaches the one-shot
        // generation claim rather than dying earlier for want of a key. That is the
        // point of this drill: even a host that kept everything cannot get back to
        // signing.
        let mut second = spawn_child(
            &self.node_bin,
            &self.config_path,
            &self.log_path,
            Some(&self.preimage_path),
        )?;
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            // A bare `?` on `try_wait` would return while the child is still alive,
            // and `std::process::Child` does not kill on drop — leaving a second
            // node process running against this deployment for the rest of the run.
            // Every other exit from this loop kills and reaps; so does this one.
            let waited = match second.try_wait() {
                Ok(waited) => waited,
                Err(e) => {
                    let _ = second.kill();
                    let _ = second.wait();
                    return Err(format!(
                        "cannot poll the second process generation of node {}: {e}",
                        self.number()
                    )
                    .into());
                }
            };
            if let Some(status) = waited {
                if status.success() {
                    return Err(format!(
                        "node {} exited cleanly on a second process generation; it must refuse \
                         to reload a signing key whose Armed/candidate RAM died",
                        self.number()
                    )
                    .into());
                }
                return Ok(log_tail(&self.log_path));
            }
            // SERVED means answered, not merely connectable. `vault-node`'s main
            // binds the listener BEFORE `server::serve` claims the process
            // generation, so between those two points the kernel completes a
            // handshake for a process that is about to die on the claim — and a raw
            // `connect` in that window would report a safety violation that did not
            // happen. Require the vault-node projection shape as well as HTTP 200 so
            // an unrelated process that recycled the released port cannot fabricate
            // a second-generation safety violation.
            if Self::is_serving(self.addr()) {
                let _ = second.kill();
                let _ = second.wait();
                return Err(format!(
                    "node {} SERVED a second process generation on the same config/key inode; \
                     the one-shot generation claim must refuse it",
                    self.number()
                )
                .into());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = second.kill();
        let _ = second.wait();
        Err(format!(
            "node {} neither served nor exited on a second process generation",
            self.number()
        )
        .into())
    }

    /// Kill the node AND destroy its deployment — config, the host's copy of the
    /// operator preimage, and the log. Models ADR-0007 reboot-death under the tmpfs
    /// deployment: the machine comes back bare, holding no signing key, no
    /// schedule, and no partials, so it cannot restart or rejoin. The method then
    /// attempts a restart against the vanished paths to prove the dead deployment
    /// cannot serve again.
    ///
    /// Since bead btc-policy-9y5.5 the config holds no key at all — only the PUBLIC
    /// derivation parameters — so what has to go is the pair: without the config the
    /// daemon has nothing to load, and without the preimage it could derive nothing
    /// even if it did. A production reboot has neither to delete: the key was only
    /// ever in RAM and the preimage only ever on the operator's paper.
    pub(crate) fn destroy(mut self) -> Result<(), Error> {
        let _ = self.child.kill();
        let _ = self.child.wait();
        // The whole DEVICE directory goes, not just the preimage file inside it: the
        // harness also writes that node's `setup node-keygen` banner there, and that
        // banner contains the preimage in plain text. Deleting one copy of a secret
        // and leaving another on the same modeled host would make this drill's claim
        // false — however little a temp directory that is about to be removed anyway
        // matters in practice. The host is what reboots, so the host is what is wiped.
        let device_dir = self
            .preimage_path
            .parent()
            .ok_or("the node's preimage has no device directory")?
            .to_path_buf();
        std::fs::remove_dir_all(&device_dir).map_err(|e| {
            format!(
                "cannot destroy node {} device host {}: {e}",
                self.number(),
                device_dir.display()
            )
        })?;
        std::fs::remove_file(&self.config_path).map_err(|e| {
            format!(
                "cannot destroy node {} config {}: {e}",
                self.number(),
                self.config_path.display()
            )
        })?;
        for (what, path) in [
            ("config", &self.config_path),
            ("operator preimage", &self.preimage_path),
        ] {
            if path.exists() {
                return Err(format!(
                    "node {} {what} still exists after deletion: {}",
                    self.number(),
                    path.display()
                )
                .into());
            }
        }
        std::fs::remove_file(&self.log_path).map_err(|e| {
            format!(
                "cannot destroy node {} log {}: {e}",
                self.number(),
                self.log_path.display()
            )
        })?;

        // Recreate only the diagnostic log, never the destroyed config/key. A bare
        // non-zero exit is not reboot-death evidence: a renamed CLI flag or loader
        // bug would fail too. Preserve stderr and require the daemon's exact
        // missing-config refusal below.
        // No preimage either: the rebooted machine has nothing. Its stdin is empty,
        // so even a node whose config somehow survived could not derive a key.
        let mut restart = spawn_child(&self.node_bin, &self.config_path, &self.log_path, None)
            .map_err(|e| format!("cannot attempt reboot-death restart: {e}"))?;
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            // Kill before returning, for the reason `restart_must_be_refused`
            // documents: a propagated `try_wait` error would abandon a live child.
            let waited = match restart.try_wait() {
                Ok(waited) => waited,
                Err(e) => {
                    let _ = restart.kill();
                    let _ = restart.wait();
                    return Err(format!(
                        "cannot poll the reboot-death restart of node {}: {e}",
                        self.number()
                    )
                    .into());
                }
            };
            if let Some(status) = waited {
                let evidence = log_tail(&self.log_path);
                if status.success() {
                    return Err(format!(
                        "node {} exited successfully when restarted without its destroyed \
                         config; reboot-death must refuse the bare machine. Log: {evidence}",
                        self.number(),
                    )
                    .into());
                }
                let expected = format!("cannot read config {}", self.config_path.display());
                let log = std::fs::read_to_string(&self.log_path).map_err(|e| {
                    format!(
                        "cannot read reboot-death evidence for node {} from {}: {e}",
                        self.number(),
                        self.log_path.display()
                    )
                })?;
                if !log.contains(&expected) {
                    return Err(format!(
                        "node {} refused the restart for an unexpected reason; expected \
                         {expected:?}. Log: {evidence}",
                        self.number()
                    )
                    .into());
                }
                return Ok(());
            }
            if Self::is_serving(self.addr()) {
                let _ = restart.kill();
                let _ = restart.wait();
                return Err(format!(
                    "node {} SERVED after its key-bearing config was destroyed",
                    self.number()
                )
                .into());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = restart.kill();
        let _ = restart.wait();
        Err(format!(
            "node {} neither refused nor served after its key-bearing config was destroyed",
            self.number()
        )
        .into())
    }

    /// Whether a vault-node is SERVING on this address. A raw TCP connect is not
    /// evidence: `vault-node` binds before its lifecycle claim, and an unrelated
    /// process can recycle the released port. Require the real `/events` surface and
    /// its vault-node projection shape.
    pub(crate) fn is_serving(addr: SocketAddr) -> bool {
        http::get_json(addr, "/events?since=0", Duration::from_millis(500))
            .ok()
            .filter(|response| response.status == 200)
            .and_then(|response| serde_json::from_str::<serde_json::Value>(&response.body).ok())
            .is_some_and(|projection| {
                projection
                    .get("alerts")
                    .is_some_and(|value| value.is_array())
                    && projection.get("cursor").is_some_and(|value| value.is_u64())
            })
    }

    pub(crate) fn log_tail(&self) -> String {
        log_tail(&self.log_path)
    }

    /// Whether this node's log contains `needle` anywhere. `log_tail` reads only the
    /// last few lines, which is right for a failure message but cannot attribute a
    /// refusal that happened earlier in the run — the fire-time scenarios need to
    /// show WHICH admissibility gate refused, not merely that the sweep is absent.
    pub(crate) fn log_contains(&self, needle: &str) -> bool {
        std::fs::read_to_string(&self.log_path)
            .map(|log| log.contains(needle))
            .unwrap_or(false)
    }

    pub(crate) fn sign(&self, request: &SignRequest) -> Result<SignResponse, Error> {
        post_sign(self.addr(), &TaggedRequest::Spend(request.clone()))
    }

    /// Raw `/sign` reply for transport-boundary scenarios. Most callers should use
    /// [`Self::sign`]; the adversarial harness needs the status and error body when
    /// it deliberately sends a coordinator JSON body that fits `/sign` but cannot
    /// fit the federation's base64-expanded channel envelope.
    pub(crate) fn sign_http(&self, request: &SignRequest) -> Result<http::Response, Error> {
        let body = encode_request(&TaggedRequest::Spend(request.clone()))?;
        http::post_json(self.addr(), "/sign", &body, None, Duration::from_secs(30))
    }

    pub(crate) fn send(&self, request: &TaggedRequest) -> Result<SignResponse, Error> {
        post_sign(self.addr(), request)
    }

    /// `/sign` with the raw wall-clock round-trip, for the silence probe. The
    /// latency of a request is the observable ADR-0012's constant-observable
    /// ingress promises is pin-independent, so the probe scenario measures it here
    /// rather than reconstructing it from logs.
    pub(crate) fn sign_timed(&self, request: &SignRequest) -> Result<Timed, Error> {
        let tagged = TaggedRequest::Spend(request.clone());
        let body = encode_request(&tagged)?;
        let start = Instant::now();
        let response = http::post_json(self.addr(), "/sign", &body, None, Duration::from_secs(30))?;
        let elapsed = start.elapsed();
        if response.status != 200 {
            return Err(format!(
                "node {} answered HTTP {}: {}",
                self.number(),
                response.status,
                response.body
            )
            .into());
        }
        Ok(Timed {
            response: serde_json::from_str(&response.body)?,
            elapsed,
            body: response.body,
        })
    }

    /// `GET /events` — the coordinator's alert pull (ADR-0002). The silence probe
    /// asserts these projections are identical under both PINs until `T`.
    pub(crate) fn events(&self, since: u64) -> Result<serde_json::Value, Error> {
        let response = http::get_json(
            self.addr(),
            &format!("/events?since={since}"),
            Duration::from_secs(30),
        )?;
        if response.status != 200 {
            return Err(format!(
                "node {} answered HTTP {} on /events: {}",
                self.number(),
                response.status,
                response.body
            )
            .into());
        }
        Ok(serde_json::from_str(&response.body)?)
    }

    /// `GET /pending` — the node's own projection of the spends it has ACCEPTED and
    /// not yet seen settle (bead btc-policy-k0t). Unlike the `/sign` acknowledgements,
    /// this is readable straight off each node, so a candidate fed directly to ONE node
    /// by a coordinator-auth-key thief is still visible during its Hold.
    pub(crate) fn pending(&self) -> Result<Vec<String>, Error> {
        let response = http::get_json(self.addr(), "/pending", Duration::from_secs(30))?;
        if response.status != 200 {
            return Err(format!(
                "node {} answered HTTP {} on /pending: {}",
                self.number(),
                response.status,
                response.body
            )
            .into());
        }
        let projection: serde_json::Value = serde_json::from_str(&response.body)?;
        projection["pending"]
            .as_array()
            .ok_or_else(|| {
                format!(
                    "node {} answered /pending without a `pending` array: {}",
                    self.number(),
                    response.body
                )
            })?
            .iter()
            .map(|id| {
                id.as_str().map(str::to_owned).ok_or_else(|| {
                    format!("node {} reported a non-string commitment id", self.number()).into()
                })
            })
            .collect()
    }
}

/// Launch a vault-node daemon. `preimage_path` is the node host's own operator
/// secret; `None` models a machine that no longer has one — the rebooted, bare
/// host of ADR-0007, which gets an EMPTY stdin and must refuse to start.
fn spawn_child(
    node_bin: &Path,
    config_path: &Path,
    log_path: &Path,
    preimage_path: Option<&Path>,
) -> Result<Child, Error> {
    // Append rather than truncate so a second process generation's log keeps the
    // first generation's lines: `restart_must_be_refused` reads the tail for the
    // line the refusal died on, and the evidence spans both processes.
    let log = File::options().create(true).append(true).open(log_path)?;
    Command::new(node_bin)
        .arg("--config")
        .arg(config_path)
        // Enable the node's harness-only `/channel` holder-commit marker
        // (`vault-node`'s `channel_marker_enabled`), which is off in production. The
        // adversarial scenarios read it as their only evidence that an intentionally
        // opaque `/channel` ACCEPTED actually committed a holder decision
        // (`confirm_with_compromised`). Set on every generation, including restarts,
        // since all daemon launches funnel through here.
        .env("BTC_VAULT_CHANNEL_MARKER", "1")
        // Regtest federations deploy on ordinary temp dirs, and the demo/attack-all
        // binary is `cfg!(test) = false`, so vault-node's startup tmpfs assertion
        // (P3a) would fatal without this. INSECURE in production (it defeats the
        // reboot-death model), which is exactly why it is confined to the harness.
        .env("BTC_VAULT_ALLOW_DURABLE_STORAGE", "1")
        .stdout(log.try_clone()?)
        .stderr(log)
        // The node derives its signing key from the operator preimage it reads
        // here; it holds none at rest (bead btc-policy-9y5.5). Handing the file
        // directly means the bytes go kernel-to-kernel and this process — the
        // coordinator — never holds a node secret in its own memory.
        .stdin(match preimage_path {
            Some(path) => Stdio::from(File::open(path).map_err(|e| {
                format!(
                    "cannot open the node's own preimage {}: {e}",
                    path.display()
                )
            })?),
            None => Stdio::null(),
        })
        .spawn()
        .map_err(|e| format!("cannot spawn {}: {e}", node_bin.display()).into())
}

/// Serialize a request for `/sign`, reserving the final allocation from a PIN-free
/// shape first. This keeps serde from freeing a grown allocation that already held
/// plaintext PIN bytes; the one final allocation is wiped on every path.
pub(crate) fn encode_request(tagged: &TaggedRequest) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut shape = tagged.clone();
    if let TaggedRequest::Spend(spend) = &mut shape {
        spend.pin.clear();
    }
    let capacity = serde_json::to_vec(&shape)?
        .len()
        .saturating_add(6 * MAX_PIN_BYTES);
    let mut body = Zeroizing::new(Vec::with_capacity(capacity));
    let allocation = body.as_ptr();
    serde_json::to_writer(&mut *body, tagged)?;
    debug_assert_eq!(
        body.as_ptr(),
        allocation,
        "secret request serialization must not reallocate"
    );
    Ok(body)
}

fn post_sign(addr: SocketAddr, tagged: &TaggedRequest) -> Result<SignResponse, Error> {
    let body = encode_request(tagged)?;
    let response = http::post_json(addr, "/sign", &body, None, Duration::from_secs(30))?;
    if response.status != 200 {
        return Err(format!(
            "node at {addr} answered HTTP {}: {}",
            response.status, response.body
        )
        .into());
    }
    Ok(serde_json::from_str(&response.body)?)
}

impl Drop for NodeProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub(crate) fn log_tail(path: &Path) -> String {
    match std::fs::read_to_string(path) {
        Ok(content) => {
            let mut lines: Vec<&str> = content.lines().rev().take(3).collect();
            lines.reverse();
            lines.join(" | ")
        }
        Err(_) => "(no node log)".into(),
    }
}

/// Find the compiled vault-node binary. `cargo run -p vault-cli` does not build
/// sibling binaries, so build it ourselves once per CLI process and reuse it for
/// every federation that process launches.
pub(crate) fn locate_vault_node() -> Result<PathBuf, Error> {
    static VAULT_NODE: OnceLock<Result<PathBuf, String>> = OnceLock::new();

    match VAULT_NODE
        .get_or_init(|| locate_binary("vault-node", "vault-node").map_err(|e| e.to_string()))
    {
        Ok(path) => Ok(path.clone()),
        Err(error) => Err(error.clone().into()),
    }
}

/// The `btc-vault` binary itself — the harness re-executes it for every NODE-SIDE
/// ceremony step, so those steps run in their own process against their own
/// directory instead of inside the coordinator's address space.
///
/// Found the same way as `vault-node` rather than reusing `current_exe()`: under
/// `cargo test` the current executable is a test harness, which has no `setup`
/// subcommand at all.
pub(crate) fn locate_btc_vault() -> Result<PathBuf, Error> {
    static BTC_VAULT: OnceLock<Result<PathBuf, String>> = OnceLock::new();

    match BTC_VAULT
        .get_or_init(|| locate_binary("vault-cli", "btc-vault").map_err(|e| e.to_string()))
    {
        Ok(path) => Ok(path.clone()),
        Err(error) => Err(error.clone().into()),
    }
}

fn locate_binary(package: &str, binary: &str) -> Result<PathBuf, Error> {
    let exe = std::env::current_exe()?;
    let dir = exe.parent().ok_or("current executable has no parent dir")?;
    // Test binaries live in `<profile>/deps`; ordinary `cargo run` binaries live in
    // `<profile>`. In either case, execute from the profile we actually build.
    // Otherwise `cargo run --release` builds a fresh DEV binary and silently
    // executes a potentially stale `target/release/<binary>`.
    let profile_dir = if dir.file_name().and_then(|name| name.to_str()) == Some("deps") {
        dir.parent()
            .ok_or("test executable has no profile parent")?
    } else {
        dir
    };
    let release = profile_dir.file_name().and_then(|name| name.to_str()) == Some("release");
    let sibling = profile_dir.join(binary);

    println!("      building {binary}...");
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut command = Command::new(cargo);
    command.args(["build", "-p", package]);
    if release {
        command.arg("--release");
    }
    let status = command
        .status()
        .map_err(|e| format!("cannot run cargo to build {binary}: {e}"))?;
    if !status.success() {
        return Err(format!(
            "cargo build -p {package}{} failed",
            if release { " --release" } else { "" }
        )
        .into());
    }

    if sibling.exists() {
        Ok(sibling)
    } else {
        Err(format!("cannot locate the {binary} binary after cargo build").into())
    }
}

// ---------------------------------------------------------------------------
// Temp dir + port allocation

pub(crate) struct TempDir {
    pub(crate) path: PathBuf,
}

impl TempDir {
    pub(crate) fn new(tag: &str) -> Result<TempDir, Error> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
        let path = std::env::temp_dir().join(format!(
            "btc-vault-{tag}-{}-{}{:09}",
            std::process::id(),
            now.as_secs(),
            now.subsec_nanos()
        ));
        std::fs::create_dir_all(&path)?;
        Ok(TempDir { path })
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Reserve `count` distinct free loopback ports by binding them all at once, then
/// releasing. A small race remains until the real processes bind; fine for a
/// harness that fails loudly.
pub(crate) fn free_ports(count: usize) -> Result<Vec<u16>, Error> {
    let mut listeners = Vec::new();
    let mut ports = Vec::new();
    for _ in 0..count {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        ports.push(listener.local_addr()?.port());
        listeners.push(listener);
    }
    Ok(ports)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Txid;

    /// A representative 3-of-5 P2WSH vault satisfaction weight (wu). The exact value
    /// only sets the node's per-rung relay-delta minimum; tests that care derive that
    /// minimum from [`vault_node::escape_replacement_min_fee_delta`] rather than a
    /// magic number, so the ladder is exercised against the bound the node enforces.
    const TEST_MAX_SAT_WEIGHT: u64 = 500;

    /// A one-input, one-output escape sweeping `input` sat to `dest` for `fee`.
    fn escape(input: u64, fee: u64) -> Psbt {
        let dest = ScriptBuf::from_hex("0014aabbccddeeff00112233445566778899aabbccdd")
            .expect("a valid p2wpkh scriptPubKey");
        let vault = ScriptBuf::from_hex(
            "0020112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00",
        )
        .expect("a valid p2wsh scriptPubKey");
        let utxo = Utxo {
            outpoint: OutPoint::new(Txid::from_byte_array([7; 32]), 0),
            txout: TxOut {
                script_pubkey: vault.clone(),
                value: Amount::from_sat(input),
            },
        };
        build_spend(&utxo, &vault, &[(dest, Amount::from_sat(input - fee))]).expect("escape")
    }

    /// The composed ladder is exactly what the node's `ensure_escape_ladder` demands:
    /// the base rewritten to signal BIP125 replacement, rungs over the same inputs and
    /// output scripts, and strictly ascending fees.
    #[test]
    fn the_composed_ladder_ascends_over_one_input_set_and_signals_replacement() {
        let base_fee = 10_000;
        let (base, rungs) =
            escape_fee_ladder(&escape(1_000_000_000, base_fee), TEST_MAX_SAT_WEIGHT)
                .expect("ladder");
        assert_eq!(rungs.len(), ESCAPE_BUMP_MULTIPLIERS.len());
        let fee_of = |psbt: &Psbt| -> u64 {
            let out: u64 = psbt
                .unsigned_tx
                .output
                .iter()
                .map(|o| o.value.to_sat())
                .sum();
            1_000_000_000 - out
        };
        assert_eq!(fee_of(&base), base_fee, "the base's own fee is untouched");
        let mut previous = base_fee;
        for (index, rung) in rungs.iter().enumerate() {
            assert_eq!(
                rung.unsigned_tx
                    .input
                    .iter()
                    .map(|i| i.previous_output)
                    .collect::<Vec<_>>(),
                base.unsigned_tx
                    .input
                    .iter()
                    .map(|i| i.previous_output)
                    .collect::<Vec<_>>(),
                "rung {index} must spend the base's inputs or it replaces nothing"
            );
            assert_eq!(
                rung.unsigned_tx
                    .output
                    .iter()
                    .map(|o| &o.script_pubkey)
                    .collect::<Vec<_>>(),
                base.unsigned_tx
                    .output
                    .iter()
                    .map(|o| &o.script_pubkey)
                    .collect::<Vec<_>>(),
                "a bump changes the fee, never what is swept"
            );
            let fee = fee_of(rung);
            assert!(
                fee > previous,
                "rung {index} pays {fee}, not more than {previous}"
            );
            assert_eq!(fee, base_fee * ESCAPE_BUMP_MULTIPLIERS[index]);
            previous = fee;
        }
        for rung in std::iter::once(&base).chain(&rungs) {
            assert!(
                rung.unsigned_tx
                    .input
                    .iter()
                    .all(|i| i.sequence.to_consensus_u32() == ESCAPE_RBF_SEQUENCE),
                "every rung, base included, must signal replacement"
            );
        }
        assert_eq!(
            base.unsigned_tx.lock_time,
            LockTime::ZERO,
            "a replaceable escape's finality comes from nLockTime, not nSequence"
        );
    }

    /// A rung the swept value cannot afford is simply not offered — and with no rung
    /// to replace it with, the escape keeps the non-signalling, final shape a
    /// ladder-less escape must have.
    #[test]
    fn an_unaffordable_ladder_is_not_offered_and_leaves_the_escape_unchanged() {
        // A fee already above 1% of the input: every multiplier overshoots the cap.
        let bare = escape(1_000_000, 50_000);
        let (base, rungs) = escape_fee_ladder(&bare, TEST_MAX_SAT_WEIGHT).expect("ladder");
        assert!(
            rungs.is_empty(),
            "no rung fits under the coordinator's fee bound"
        );
        assert_eq!(
            base.unsigned_tx, bare.unsigned_tx,
            "with nothing to replace, the escape is left exactly as composed"
        );
        assert!(base
            .unsigned_tx
            .input
            .iter()
            .all(|i| i.sequence == Sequence::MAX));
    }

    /// A rung whose fee increase over the rung below is UNDER the node's
    /// incremental-relay minimum is dropped, not offered — because the node refuses
    /// such a rung at ingress and that refusal takes the whole spend, duress carrier
    /// included (bead btc-policy-9y5.7). With a base fee small enough that the 4× rung's
    /// `3·base_fee` delta is under the minimum, the 4× rung must vanish and the 16× rung
    /// (whose `15·base_fee` clears it) becomes the first offered — and every offered
    /// rung must clear the minimum over the rung below it, exactly what the node checks.
    #[test]
    fn a_rung_below_the_incremental_relay_delta_is_dropped_not_offered() {
        // The node's per-rung minimum for this single-input ladder shape, computed the
        // same way the node does. The sequence rewrite in the ladder base does not change
        // the serialized size, so a plain escape's unsigned tx yields the same value.
        let minimum_delta = vault_node::escape_replacement_min_fee_delta(
            TEST_MAX_SAT_WEIGHT,
            &escape(1_000_000_000, 1).unsigned_tx,
        )
        .expect("delta");
        // `3·base_fee < minimum_delta ≤ 15·base_fee`: the 4× rung is under the floor, the
        // 16× rung clears it.
        let base_fee = (minimum_delta / 4).max(1);
        assert!(3 * base_fee < minimum_delta && 15 * base_fee >= minimum_delta);
        let (base, rungs) =
            escape_fee_ladder(&escape(1_000_000_000, base_fee), TEST_MAX_SAT_WEIGHT)
                .expect("ladder");
        let fee_of = |psbt: &Psbt| -> u64 {
            1_000_000_000
                - psbt
                    .unsigned_tx
                    .output
                    .iter()
                    .map(|o| o.value.to_sat())
                    .sum::<u64>()
        };
        assert_eq!(fee_of(&base), base_fee, "the base's own fee is untouched");
        assert_eq!(
            rungs.len(),
            2,
            "the 4× rung is under the relay delta and must be dropped, leaving 16× and 64×"
        );
        assert_eq!(
            fee_of(&rungs[0]),
            base_fee * 16,
            "the first OFFERED rung is the 16× — the too-close 4× was dropped"
        );
        assert_eq!(fee_of(&rungs[1]), base_fee * 64);
        // Every offered rung clears the node's minimum over the rung below it (the base
        // to start) — so `ensure_escape_ladder` accepts the whole ladder.
        let mut previous = base_fee;
        for rung in &rungs {
            let fee = fee_of(rung);
            assert!(
                fee.saturating_sub(previous) >= minimum_delta,
                "each offered rung must clear the relay minimum over the one below it"
            );
            previous = fee;
        }
    }
}
