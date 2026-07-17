//! `demo first-light`: the internal checkpoint from DESIGN.md — the smallest
//! end-to-end run of the real coordinator-authenticated tagged request protocol.
//!
//! Act one: an honest, user-signed, PIN-carrying spend to the allowlisted hot
//! wallet is signed by all 5 nodes; 3 signatures are combined, finalized,
//! broadcast, and confirmed on a private regtest chain. Act two: a correctly
//! user-signed theft to a non-allowlisted destination is refused by every
//! node with a structured DEST_NOT_ALLOWED.

use std::fs::File;
use std::io::Read;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::str::FromStr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bitcoin::absolute::LockTime;
use bitcoin::bip32::{Xpriv, Xpub};
use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use bitcoin::sighash::SighashCache;
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, CompressedPublicKey, EcdsaSighashType, Network, NetworkKind, OutPoint, Psbt, PublicKey,
    ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use miniscript::psbt::PsbtExt;
use miniscript::{Descriptor, DescriptorPublicKey};
use serde_json::json;
use vault_proto::{RefusalCode, SignRequest, SignResponse, TaggedRequest};

use crate::bitcoind::Bitcoind;
use crate::http::{self, Error};

const NORMAL_PIN: &str = "246802";
const DURESS_PIN: &str = "135791";
const NODE_COUNT: usize = 5;
const QUORUM: usize = 3;
/// The baked policy identifier every commitment carries (policy never changes).
const POLICY_VERSION: u32 = 1;
/// Node-enforced cap on coordinator-proposed expiry (DESIGN.md config schema).
const MAX_COMMITMENT_AGE_SECS: u64 = 172_800;
/// The expiry the coordinator proposes on each spend: an hour out, well inside
/// the node's cap.
const COMMITMENT_TTL_SECS: u64 = 3_600;
/// Bound on the node's own-descriptor / allowlist derivation scans.
const MAX_DERIVATION_INDEX: u32 = 100;
/// The (non-zero) index the honest spend pays the hot wallet at — a freshly
/// derived address, proving the allowlist is a descriptor, not a fixed address.
const HOT_INDEX: u32 = 5;
/// Coins sent into the vault.
const FUND: Amount = Amount::from_sat(1_000_000_000);
/// Act one pays this to the hot wallet; the rest returns to the vault.
const HOT_SPEND: Amount = Amount::from_sat(400_000_000);
/// Flat demo fee — far under the 10% cap.
const FEE: Amount = Amount::from_sat(10_000);

pub fn run_first_light() -> Result<(), Error> {
    let secp = Secp256k1::new();

    // RAII cleanup: locals drop in reverse order, so declaring temp dir →
    // bitcoind → node processes tears down nodes first, then bitcoind, then
    // removes the temp dir — even on the error path.
    // Deliberate first-light deviation from DESIGN.md D4/T1 (on-node key
    // birth, no machine ever holds two node keys, nothing at rest): this one
    // process births every throwaway regtest key and writes node seckeys into
    // temp-dir TOML. The v0 provisioning task (T1) removes this.
    println!("[1/4] generating throwaway keys (user, 5 nodes, destinations)");
    let temp = TempDir::new()?;
    let mut urandom = File::open("/dev/urandom")?;
    let user = Actor::random(&secp, &mut urandom)?;
    let node_actors: Vec<Actor> = (0..NODE_COUNT)
        .map(|_| Actor::random(&secp, &mut urandom))
        .collect::<Result<_, _>>()?;
    // The coordinator auth keypair (ADR-0013 §2): ONE root, generated once here,
    // provisioned into every node's per-vault config below (and therefore the
    // channel manifest whenever channel mode is enabled), and signing every
    // request the demo acts relay. Regtest provisioning — no SSH; the real
    // ceremony is later V0-9.
    let coordinator = Coordinator::random(&secp, &mut urandom)?;
    let coord_auth_pubkey = coordinator.pubkey.to_string();
    // Hot and escape wallets are ranged xpub descriptors, so every spend pays a
    // freshly derived address instead of a reused fixed one (DESIGN.md,
    // "Destination allowlist"). The honest spend pays the hot wallet at a
    // non-zero index; the escape variant sweeps to the escape wallet's index 0.
    let hot_wallet = Wallet::random(&secp, &mut urandom)?;
    let escape_wallet = Wallet::random(&secp, &mut urandom)?;
    let hot_spk = hot_wallet.address_spk(&secp, HOT_INDEX)?;
    let escape_spk = escape_wallet.address_spk(&secp, 0)?;
    // The attacker's destination is a raw key that derives from no descriptor.
    let attacker_spk = p2wpkh_spk(&Actor::random(&secp, &mut urandom)?);

    // The first-light vault: user key AND 3-of-5 node keys, P2WSH, no
    // recovery branch (the regtest demo vault is throwaway).
    let node_pubkeys: Vec<String> = node_actors.iter().map(|a| a.pubkey.to_string()).collect();
    let descriptor_str = format!(
        "wsh(and_v(v:pk({}),multi({QUORUM},{})))",
        user.pubkey,
        node_pubkeys.join(",")
    );
    let descriptor = Descriptor::<PublicKey>::from_str(&descriptor_str)?;
    let vault_spk = descriptor.script_pubkey();
    let witness_script = descriptor.explicit_script()?;
    let vault_address = descriptor.address(Network::Regtest)?;

    println!("[2/4] starting private regtest bitcoind, funding the vault");
    let ports = free_ports(1 + NODE_COUNT)?;
    let mut bitcoind = Bitcoind::start(temp.path.join("bitcoind"), ports[0])?;
    bitcoind.create_wallet("first-light")?;
    let mining_address = bitcoind.call_str("getnewaddress", json!([]))?;
    bitcoind.call("generatetoaddress", json!([101, mining_address]))?;
    let funding_txid = bitcoind.call_str(
        "sendtoaddress",
        json!([vault_address.to_string(), FUND.to_btc()]),
    )?;
    bitcoind.call("generatetoaddress", json!([1, mining_address]))?;
    let funding_hex = bitcoind.call_str("getrawtransaction", json!([funding_txid]))?;
    let funding_tx: Transaction = deserialize_hex(&funding_hex)?;
    let vault_utxo = utxo_paying(&funding_tx, &vault_spk)?;
    println!(
        "      vault {} funded with {} at {}",
        vault_address, vault_utxo.txout.value, vault_utxo.outpoint
    );

    println!("[3/4] starting {NODE_COUNT} vault-node processes");
    let node_bin = locate_vault_node()?;
    let nodes_dir = temp.path.join("nodes");
    std::fs::create_dir_all(&nodes_dir)?;
    let mut nodes = Vec::new();
    for (index, actor) in node_actors.iter().enumerate() {
        nodes.push(NodeProcess::spawn(
            &node_bin,
            &nodes_dir,
            index,
            ports[1 + index],
            actor,
            &descriptor_str,
            &[&hot_wallet.descriptor, &escape_wallet.descriptor],
            &escape_wallet.descriptor,
            // The one coordinator auth root, provisioned identically into every
            // node's per-vault config (ADR-0013 §2/§4).
            &coord_auth_pubkey,
            // Each node drives its own watchtower against this regtest bitcoind
            // (ADR-0001, V0-6b).
            bitcoind.rpc_addr(),
            bitcoind.auth(),
        )?);
    }
    for node in &mut nodes {
        node.wait_ready()?;
        println!(
            "      node {} listening on 127.0.0.1:{}",
            node.number(),
            node.port
        );
    }

    println!("[4/4] running the two acts");
    let spend_tx = act_one(
        &secp,
        &bitcoind,
        &mining_address,
        &nodes,
        &user,
        &coordinator,
        &witness_script,
        &vault_utxo,
        &vault_spk,
        &hot_spk,
        &escape_spk,
    )?;
    act_two(
        &secp,
        &nodes,
        &user,
        &coordinator,
        &witness_script,
        &spend_tx,
        &vault_spk,
        &attacker_spk,
        &escape_spk,
    )?;

    println!("\nFIRST LIGHT COMPLETE — honest spend confirmed, theft refused by every node");
    Ok(())
}

/// Act one — honest spend: hot-wallet payment + escape variant, user-signed,
/// normal PIN; all nodes sign; 3 signatures are combined and the spend
/// confirms on-chain. Returns the confirmed transaction.
#[allow(clippy::too_many_arguments)]
fn act_one(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    bitcoind: &Bitcoind,
    mining_address: &str,
    nodes: &[NodeProcess],
    user: &Actor,
    coordinator: &Coordinator,
    witness_script: &ScriptBuf,
    vault_utxo: &Utxo,
    vault_spk: &ScriptBuf,
    hot_spk: &ScriptBuf,
    escape_spk: &ScriptBuf,
) -> Result<Transaction, Error> {
    println!("\n== act one: honest spend to the hot wallet ==");
    let vault_value = vault_utxo.txout.value;
    let change = vault_value
        .checked_sub(HOT_SPEND)
        .and_then(|rest| rest.checked_sub(FEE))
        .ok_or("vault balance cannot cover the demo spend")?;
    let sweep = vault_value
        .checked_sub(FEE)
        .ok_or("vault balance cannot cover the escape sweep")?;

    let mut honest = build_spend(
        vault_utxo,
        witness_script,
        &[(hot_spk.clone(), HOT_SPEND), (vault_spk.clone(), change)],
    )?;
    let mut escape = build_spend(vault_utxo, witness_script, &[(escape_spk.clone(), sweep)])?;
    // The two-transaction ceremony (ADR-0008): the user signs the spend AND
    // its escape variant, every time.
    sign_all_inputs(secp, &mut honest, user, witness_script)?;
    sign_all_inputs(secp, &mut escape, user, witness_script)?;

    let body = SignRequest {
        psbt: honest.to_string(),
        escape_psbt: escape.to_string(),
        pin: NORMAL_PIN.into(),
        nonce: String::new(),
        expiry: commitment_expiry()?,
        policy_version: POLICY_VERSION,
        coord_sig: String::new(),
    };

    // Before the honest relay: the trust root itself. This same, otherwise
    // PERFECTLY valid spend — allowlisted destination, real user signature, real
    // PIN — signed by a coordinator outside the nodes' configured root — must be
    // refused by every node (ADR-0013 §2). Nothing but the coordinator identity
    // differs, so COORD_AUTH_INVALID (never DEST_NOT_ALLOWED or BAD_PIN) is proof
    // the configured root is what refused it.
    foreign_coordinator_is_refused(secp, nodes, &body)?;

    // The real coordinator authenticates the request it relays (fresh nonce +
    // signature over the canonical bytes) so every node admits it past the gate.
    let request = coordinator.authorize(secp, body)?;
    let mut node_signed = Vec::new();
    for node in nodes {
        match node.sign(&request)? {
            SignResponse::Signed(base64) => {
                println!("  node {} @127.0.0.1:{} → signed", node.number(), node.port);
                node_signed.push(Psbt::from_str(&base64)?);
            }
            other => {
                return Err(format!(
                    "node {} did not sign the honest spend: {}",
                    node.number(),
                    summarize(&other)
                )
                .into())
            }
        }
    }

    let mut combined = honest;
    for psbt in node_signed.into_iter().take(QUORUM) {
        combined.combine(psbt)?;
    }
    combined
        .finalize_mut(secp)
        .map_err(|errors| format!("finalize combined PSBT: {errors:?}"))?;
    let tx = combined.extract_tx()?;
    println!("  combined {QUORUM}-of-{NODE_COUNT} node signatures, finalized");

    let txid = bitcoind.call_str("sendrawtransaction", json!([serialize_hex(&tx)]))?;
    bitcoind.call("generatetoaddress", json!([1, mining_address]))?;
    let confirmations = bitcoind.call("getrawtransaction", json!([txid, true]))?["confirmations"]
        .as_i64()
        .unwrap_or(0);
    if confirmations < 1 {
        return Err(format!("broadcast spend {txid} did not confirm").into());
    }
    println!("  ACT ONE OK — honest spend {txid} confirmed ({confirmations} confirmation)");
    Ok(tx)
}

/// Act two — theft refusal: a correctly user-signed spend of the vault change
/// to a non-allowlisted destination, correct PIN. Every node must answer a
/// structured DEST_NOT_ALLOWED refusal.
#[allow(clippy::too_many_arguments)]
fn act_two(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    nodes: &[NodeProcess],
    user: &Actor,
    coordinator: &Coordinator,
    witness_script: &ScriptBuf,
    spend_tx: &Transaction,
    vault_spk: &ScriptBuf,
    attacker_spk: &ScriptBuf,
    escape_spk: &ScriptBuf,
) -> Result<(), Error> {
    println!("\n== act two: theft attempt — stolen user key, non-allowlisted destination ==");
    let change_utxo = utxo_paying(spend_tx, vault_spk)?;
    let loot = change_utxo
        .txout
        .value
        .checked_sub(FEE)
        .ok_or("vault change cannot cover the theft")?;

    let mut theft = build_spend(
        &change_utxo,
        witness_script,
        &[(attacker_spk.clone(), loot)],
    )?;
    let mut escape = build_spend(&change_utxo, witness_script, &[(escape_spk.clone(), loot)])?;
    // The attacker holds the stolen user key and (worst case) the PIN; the
    // destination allowlist alone must stop this.
    sign_all_inputs(secp, &mut theft, user, witness_script)?;
    sign_all_inputs(secp, &mut escape, user, witness_script)?;

    // The theft is a genuine coordinator-authenticated request too (the attacker
    // holds the user key and PIN); only the destination allowlist stops it, and it
    // must first pass the coord-auth gate to reach that policy refusal.
    let request = coordinator.authorize(
        secp,
        SignRequest {
            psbt: theft.to_string(),
            escape_psbt: escape.to_string(),
            pin: NORMAL_PIN.into(),
            nonce: String::new(),
            expiry: commitment_expiry()?,
            policy_version: POLICY_VERSION,
            coord_sig: String::new(),
        },
    )?;
    let mut refusals = 0;
    for node in nodes {
        match node.sign(&request)? {
            SignResponse::Refusal(refusal) if refusal.code == RefusalCode::DestNotAllowed => {
                println!(
                    "  node {} @127.0.0.1:{} → REFUSED {}",
                    node.number(),
                    node.port,
                    serde_json::to_string(&refusal)?
                );
                refusals += 1;
            }
            other => {
                return Err(format!(
                    "node {} did not refuse the theft with DEST_NOT_ALLOWED: {}",
                    node.number(),
                    summarize(&other)
                )
                .into())
            }
        }
    }
    println!("  ACT TWO OK — {refusals}/{NODE_COUNT} nodes refused with DEST_NOT_ALLOWED");
    Ok(())
}

/// The coordinator trust root, demonstrated against the live federation: a
/// request signed by a coordinator that is NOT the one provisioned into the
/// nodes' configured trust root is refused by EVERY node with
/// `COORD_AUTH_INVALID` (ADR-0013 §2). `body` is an otherwise-valid spend, so this
/// isolates coordinator authentication as the sole reason for the refusal — the
/// property V0-8b's Model-B spend path authenticates against.
fn foreign_coordinator_is_refused(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    nodes: &[NodeProcess],
    body: &SignRequest,
) -> Result<(), Error> {
    // A coordinator the vault was never sealed to: a different key, but one that
    // signs the canonical bytes just as correctly as the real one.
    let foreign = Coordinator::random(secp, &mut File::open("/dev/urandom")?)?;
    let request = foreign.authorize(secp, body.clone())?;
    let mut refusals = 0;
    for node in nodes {
        match node.sign(&request)? {
            SignResponse::Refusal(refusal) if refusal.code == RefusalCode::CoordAuthInvalid => {
                refusals += 1;
            }
            other => {
                return Err(format!(
                    "node {} did not refuse a foreign coordinator with COORD_AUTH_INVALID: {}",
                    node.number(),
                    summarize(&other)
                )
                .into())
            }
        }
    }
    println!(
        "  trust root OK — {refusals}/{NODE_COUNT} nodes refused a coordinator \
         outside their configured trust root with COORD_AUTH_INVALID"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Keys and destinations

struct Actor {
    seckey: SecretKey,
    pubkey: PublicKey,
}

impl Actor {
    fn random(
        secp: &Secp256k1<bitcoin::secp256k1::All>,
        urandom: &mut File,
    ) -> Result<Actor, Error> {
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

fn p2wpkh_spk(actor: &Actor) -> ScriptBuf {
    ScriptBuf::new_p2wpkh(&CompressedPublicKey(actor.pubkey.inner).wpubkey_hash())
}

/// The coordinator's authentication identity (ADR-0013 §2). Generated ONCE for
/// the demo vault; its public half is provisioned into every node's per-vault
/// config (`coordinator_auth_pubkey`) and is the channel-manifest input when that
/// mode is enabled. Its secret half signs every request the coordinator relays,
/// so each node authenticates a request before evaluating it. Rotation would be
/// a new vault (ADR-0013 §7), so the demo never rotates it.
struct Coordinator {
    seckey: SecretKey,
    pubkey: PublicKey,
}

impl Coordinator {
    fn random(
        secp: &Secp256k1<bitcoin::secp256k1::All>,
        urandom: &mut File,
    ) -> Result<Coordinator, Error> {
        let actor = Actor::random(secp, urandom)?;
        Ok(Coordinator {
            seckey: actor.seckey,
            pubkey: actor.pubkey,
        })
    }

    /// Turn an unauthenticated spend body into a coordinator-authenticated request:
    /// attach a fresh single-use nonce and the coordinator's signature over the
    /// canonical request bytes (ADR-0013 §2). Every node admits it past its gate.
    fn authorize(
        &self,
        secp: &Secp256k1<bitcoin::secp256k1::All>,
        mut request: SignRequest,
    ) -> Result<SignRequest, Error> {
        request.nonce = fresh_nonce()?;
        // `coord_request()` selects the signed fields; coord_sig is excluded from
        // its own preimage, so it needs no clearing before the digest.
        let digest = request.coord_request().auth_digest();
        let sig = secp.sign_ecdsa(&Message::from_digest(digest), &self.seckey);
        request.coord_sig = sig.serialize_der().to_lower_hex_string();
        Ok(request)
    }
}

/// A fresh 32-byte random nonce as lowercase hex — single-use per request so a
/// node rejects any replay (ADR-0013 §2/§3).
fn fresh_nonce() -> Result<String, Error> {
    let mut bytes = [0u8; 32];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes.to_lower_hex_string())
}

/// A ranged single-sig destination wallet: a `wpkh(<xpub>/*)` descriptor from a
/// throwaway master key, from which the coordinator derives a fresh address per
/// index. This is the shape of a hot/escape allowlist entry (DESIGN.md config
/// schema); the node stores only the descriptor string and re-derives.
struct Wallet {
    /// The canonical descriptor string (with checksum) placed in the node config.
    descriptor: String,
    parsed: Descriptor<DescriptorPublicKey>,
}

impl Wallet {
    fn random(
        secp: &Secp256k1<bitcoin::secp256k1::All>,
        urandom: &mut File,
    ) -> Result<Wallet, Error> {
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
    fn address_spk(
        &self,
        secp: &Secp256k1<bitcoin::secp256k1::All>,
        index: u32,
    ) -> Result<ScriptBuf, Error> {
        Ok(self.parsed.derived_descriptor(secp, index)?.script_pubkey())
    }
}

// ---------------------------------------------------------------------------
// PSBT plumbing

struct Utxo {
    outpoint: OutPoint,
    txout: TxOut,
}

fn utxo_paying(tx: &Transaction, spk: &ScriptBuf) -> Result<Utxo, Error> {
    let vout = tx
        .output
        .iter()
        .position(|output| output.script_pubkey == *spk)
        .ok_or("transaction has no output paying the vault")?;
    Ok(Utxo {
        outpoint: OutPoint::new(tx.compute_txid(), vout as u32),
        txout: tx.output[vout].clone(),
    })
}

fn build_spend(
    utxo: &Utxo,
    witness_script: &ScriptBuf,
    outputs: &[(ScriptBuf, Amount)],
) -> Result<Psbt, Error> {
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: utxo.outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: outputs
            .iter()
            .map(|(script_pubkey, value)| TxOut {
                script_pubkey: script_pubkey.clone(),
                value: *value,
            })
            .collect(),
    };
    let mut psbt = Psbt::from_unsigned_tx(tx)?;
    psbt.inputs[0].witness_utxo = Some(utxo.txout.clone());
    psbt.inputs[0].witness_script = Some(witness_script.clone());
    Ok(psbt)
}

fn sign_all_inputs(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
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

fn summarize(response: &SignResponse) -> String {
    serde_json::to_string(response).unwrap_or_else(|_| format!("{response:?}"))
}

/// A coordinator-proposed commitment expiry: the current wall clock plus the
/// TTL. Each node re-checks it against its own clock and cap.
fn commitment_expiry() -> Result<u64, Error> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    Ok(now + COMMITMENT_TTL_SECS)
}

// ---------------------------------------------------------------------------
// Node processes

struct NodeProcess {
    index: usize,
    port: u16,
    child: Child,
    log_path: PathBuf,
}

impl NodeProcess {
    #[allow(clippy::too_many_arguments)]
    fn spawn(
        node_bin: &Path,
        nodes_dir: &Path,
        index: usize,
        port: u16,
        actor: &Actor,
        descriptor: &str,
        allowlist: &[&str],
        escape_descriptor: &str,
        coord_auth_pubkey: &str,
        bitcoind_rpc_addr: SocketAddr,
        bitcoind_auth: &str,
    ) -> Result<NodeProcess, Error> {
        let allowlist_toml: Vec<String> =
            allowlist.iter().map(|desc| format!("\"{desc}\"")).collect();
        // The `[chain_backend]` table drives the node's watchtower thread; it
        // comes last because a TOML table header ends the top-level section.
        // `coordinator_auth_pubkey` is the trust root (ADR-0013 §2/§4): the same
        // key in every node's config, turning on the coord-auth gate.
        let config = format!(
            "listen_port = {port}\n\
             node_seckey = \"{}\"\n\
             descriptor = \"{descriptor}\"\n\
             allowlist = [{}]\n\
             escape_descriptor = \"{escape_descriptor}\"\n\
             max_derivation_index = {MAX_DERIVATION_INDEX}\n\
             hold_secs = 0\n\
             max_commitment_age_secs = {MAX_COMMITMENT_AGE_SECS}\n\
             policy_version = {POLICY_VERSION}\n\
             pin_normal_hash = \"{}\"\n\
             pin_duress_hash = \"{}\"\n\
             coordinator_auth_pubkey = \"{coord_auth_pubkey}\"\n\
             \n[chain_backend]\n\
             rpc_addr = \"{bitcoind_rpc_addr}\"\n\
             auth = \"{bitcoind_auth}\"\n",
            actor.seckey.display_secret(),
            allowlist_toml.join(", "),
            sha256::Hash::hash(NORMAL_PIN.as_bytes()),
            sha256::Hash::hash(DURESS_PIN.as_bytes()),
        );
        let config_path = nodes_dir.join(format!("node{index}.toml"));
        std::fs::write(&config_path, config)?;
        let log_path = nodes_dir.join(format!("node{index}.log"));
        let log = File::create(&log_path)?;
        let child = Command::new(node_bin)
            .arg("--config")
            .arg(&config_path)
            .stdout(log.try_clone()?)
            .stderr(log)
            .stdin(Stdio::null())
            .spawn()
            .map_err(|e| format!("cannot spawn {}: {e}", node_bin.display()))?;
        Ok(NodeProcess {
            index,
            port,
            child,
            log_path,
        })
    }

    /// 1-based, for humans.
    fn number(&self) -> usize {
        self.index + 1
    }

    fn addr(&self) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, self.port))
    }

    fn wait_ready(&mut self) -> Result<(), Error> {
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            if let Some(status) = self.child.try_wait()? {
                return Err(format!(
                    "node {} exited at startup ({status}): {}",
                    self.number(),
                    log_tail(&self.log_path)
                )
                .into());
            }
            if TcpStream::connect_timeout(&self.addr(), Duration::from_millis(250)).is_ok() {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Err(format!(
            "node {} did not start listening: {}",
            self.number(),
            log_tail(&self.log_path)
        )
        .into())
    }

    fn sign(&self, request: &SignRequest) -> Result<SignResponse, Error> {
        let body = serde_json::to_string(&TaggedRequest::Spend(request.clone()))?;
        let response = http::post_json(self.addr(), "/sign", &body, None, Duration::from_secs(30))?;
        if response.status != 200 {
            return Err(format!(
                "node {} answered HTTP {}: {}",
                self.number(),
                response.status,
                response.body
            )
            .into());
        }
        Ok(serde_json::from_str(&response.body)?)
    }
}

impl Drop for NodeProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn log_tail(path: &Path) -> String {
    match std::fs::read_to_string(path) {
        Ok(content) => {
            let mut lines: Vec<&str> = content.lines().rev().take(3).collect();
            lines.reverse();
            lines.join(" | ")
        }
        Err(_) => "(no node log)".into(),
    }
}

/// Find the compiled vault-node binary. `cargo run -p vault-cli` does not
/// build sibling binaries, so build it ourselves before every demo run. Cargo
/// no-ops when it is already fresh.
fn locate_vault_node() -> Result<PathBuf, Error> {
    let exe = std::env::current_exe()?;
    let dir = exe.parent().ok_or("current executable has no parent dir")?;
    let sibling = dir.join("vault-node");

    println!("      building vault-node...");
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let status = Command::new(cargo)
        .args(["build", "-p", "vault-node"])
        .status()
        .map_err(|e| format!("cannot run cargo to build vault-node: {e}"))?;
    if !status.success() {
        return Err("cargo build -p vault-node failed".into());
    }

    if sibling.exists() {
        Ok(sibling)
    } else {
        Err("cannot locate the vault-node binary after cargo build".into())
    }
}

// ---------------------------------------------------------------------------
// Temp dir + port allocation

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new() -> Result<TempDir, Error> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
        let path = std::env::temp_dir().join(format!(
            "btc-vault-first-light-{}-{}{:09}",
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

/// Reserve `count` distinct free loopback ports by binding them all at once,
/// then releasing. A small race remains until the real processes bind; fine
/// for a demo that fails loudly.
fn free_ports(count: usize) -> Result<Vec<u16>, Error> {
    let mut listeners = Vec::new();
    let mut ports = Vec::new();
    for _ in 0..count {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        ports.push(listener.local_addr()?.port());
        listeners.push(listener);
    }
    Ok(ports)
}
