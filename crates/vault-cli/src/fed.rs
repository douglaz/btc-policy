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
//! to `vault_node::channel::ceremony`, the node's own definitions, so a federation
//! this provisions agrees with itself by construction.

use std::fs::File;
use std::io::Read;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener};
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
use vault_node::channel::ceremony;
use vault_proto::{SignRequest, SignResponse, TaggedRequest, MAX_PIN_BYTES};
use zeroize::Zeroizing;

use crate::http::{self, Error};

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

/// The assembled per-vault manifest (ADR-0013 §4): membership, the hash every
/// node is sealed to, and each node's channel endorsement.
pub(crate) struct Manifest {
    /// Per node, in `node_id` order.
    pub(crate) entries: Vec<ManifestEntry>,
    pub(crate) manifest_hash: String,
    /// The `max_msg_bytes` that went into `manifest_hash`. Carried on the manifest
    /// rather than re-read from the params at config-writing time so the value the
    /// hash was taken over is BY CONSTRUCTION the value written into every
    /// `[channel]` block: any other arrangement lets the two drift, and a node whose
    /// configured cap disagrees with the sealed one fails startup outright
    /// (`channel.rs`, `expected_manifest_hash`).
    pub(crate) max_msg_bytes: u64,
}

pub(crate) struct ManifestEntry {
    pub(crate) node_id: u16,
    pub(crate) signing_pubkey: String,
    pub(crate) channel_pubkey: String,
    pub(crate) channel_endorsement: String,
    pub(crate) endpoint: String,
}

/// Everything the ceremony seals besides membership. Bundled because the manifest
/// hash and the generated node configs must emit the SAME values — a manifest
/// sealed over one Hot budget and configs written with another is a federation
/// that cannot boot, and passing them separately is how that drifts.
pub(crate) struct CeremonyParams<'a> {
    pub(crate) hot_allowlist: &'a [String],
    pub(crate) escape_descriptor: &'a str,
    pub(crate) max_derivation_index: u32,
    pub(crate) max_msg_bytes: u64,
    pub(crate) hot_budget: vault_node::HotBudget,
}

impl Manifest {
    pub(crate) fn assemble(
        wallet_id: &[u8; 32],
        coord_auth_pubkey: &PublicKey,
        node_actors: &[Actor],
        ports: &[u16],
        params: &CeremonyParams,
    ) -> Result<Manifest, Error> {
        // `node_id` is the node key's 0-based position in the descriptor's
        // CANONICAL order — lexicographic over the full key expression (§1). Every
        // party derives it from the frozen descriptor alone, so the mapping is a
        // total bijection and never a table anyone maintains.
        let mut canonical: Vec<&Actor> = node_actors.iter().collect();
        canonical.sort_by_key(|actor| actor.pubkey.to_string());
        let ceremony_nodes: Vec<ceremony::CeremonyNode> = canonical
            .iter()
            .enumerate()
            .map(|(node_id, actor)| ceremony::CeremonyNode {
                node_id: node_id as u16,
                signing_pubkey: actor.pubkey,
                endpoints: vec![endpoint_of(actor, node_actors, ports)],
            })
            .collect();
        let channel_pubkeys: Vec<PublicKey> = canonical
            .iter()
            .map(|actor| ceremony::channel_pubkey(&actor.seckey))
            .collect();
        // `max_msg_bytes` is a federation-uniform preimage field (V0-4b §0): a node
        // configured otherwise fails startup. That uniformity is itself a safety
        // property the attack harness asserts — it is what denies a hostile
        // coordinator the "oversize the carrier past ONE peer's cap" split vector.
        let hash = ceremony::manifest_hash(
            wallet_id,
            coord_auth_pubkey,
            &ceremony_nodes,
            &channel_pubkeys,
            params.max_msg_bytes,
            params.hot_budget,
            params.hot_allowlist,
            params.escape_descriptor,
            params.max_derivation_index,
        )?;
        let entries = canonical
            .iter()
            .zip(&ceremony_nodes)
            .zip(&channel_pubkeys)
            .map(|((actor, node), channel_pubkey)| ManifestEntry {
                node_id: node.node_id,
                signing_pubkey: actor.pubkey.to_string(),
                channel_pubkey: channel_pubkey.to_string(),
                // Each node's channel key is endorsed by that node's OWN Bitcoin
                // signing key: peers accept a channel identity only if a key already
                // in the federation vouches for it, so the coordinator cannot mint or
                // impersonate a node.
                channel_endorsement: ceremony::endorse(
                    &actor.seckey,
                    wallet_id,
                    &hash,
                    node.node_id,
                    &node.endpoints,
                ),
                endpoint: node.endpoints[0].clone(),
            })
            .collect();
        Ok(Manifest {
            entries,
            manifest_hash: hash.to_lower_hex_string(),
            max_msg_bytes: params.max_msg_bytes,
        })
    }

    /// This node's `node_id` — its position in the canonical order.
    pub(crate) fn node_id_of(&self, actor: &Actor) -> u16 {
        let pubkey = actor.pubkey.to_string();
        self.entries
            .iter()
            .find(|entry| entry.signing_pubkey == pubkey)
            .map(|entry| entry.node_id)
            .expect("every node actor is in the manifest")
    }

    /// The `[channel]` config block: this node's id, the FULL membership including
    /// itself (§5), the sealed `manifest_hash`, and the `max_msg_bytes` that hash
    /// was taken over.
    ///
    /// `max_msg_bytes` is written EXPLICITLY rather than left to
    /// `ChannelConfig::default_max_msg_bytes`. Leaving it out happens to boot only
    /// while the sealed value equals that default; seal any other cap and every node
    /// computes a different `manifest_hash` and refuses to start. Emitting the
    /// sealed value keeps the federation-uniform cap — the invariant that denies a
    /// hostile coordinator the "oversize past ONE peer's cap" split vector — true by
    /// construction instead of by coincidence.
    pub(crate) fn channel_toml(&self, actor: &Actor) -> String {
        let mut toml = format!(
            "\n[channel]\nnode_id = {}\nexpected_manifest_hash = \"{}\"\nmax_msg_bytes = {}\n",
            self.node_id_of(actor),
            self.manifest_hash,
            self.max_msg_bytes,
        );
        for entry in &self.entries {
            toml.push_str(&format!(
                "\n[[channel.nodes]]\nnode_id = {}\nsigning_pubkey = \"{}\"\n\
                 channel_pubkey = \"{}\"\nchannel_endorsement = \"{}\"\n\
                 endpoints = [\"{}\"]\n",
                entry.node_id,
                entry.signing_pubkey,
                entry.channel_pubkey,
                entry.channel_endorsement,
                entry.endpoint,
            ));
        }
        toml
    }
}

/// The loopback endpoint a node listens on. Endpoints are deliberately PINNED in
/// the manifest (§4, anti-redirection): nobody — not a compromised coordinator,
/// not a later config writer — can repoint one node's view of a peer.
pub(crate) fn endpoint_of(actor: &Actor, node_actors: &[Actor], ports: &[u16]) -> String {
    let index = node_actors
        .iter()
        .position(|a| a.pubkey == actor.pubkey)
        .expect("actor is one of the node actors");
    format!("127.0.0.1:{}", ports[index])
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
    /// The ceremony's view of these params. Derived rather than passed separately
    /// so the sealed manifest cannot disagree with the configs.
    pub(crate) fn ceremony<'a>(
        &'a self,
        hot_allowlist: &'a [String],
        escape_descriptor: &'a str,
    ) -> CeremonyParams<'a> {
        CeremonyParams {
            hot_allowlist,
            escape_descriptor,
            max_derivation_index: self.max_derivation_index,
            max_msg_bytes: self.max_msg_bytes,
            hot_budget: self.hot_budget,
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
    node_bin: PathBuf,
}

/// Everything one node's config needs. A struct because the list outgrew the point
/// where positional arguments stay readable.
pub(crate) struct NodeSpawn<'a> {
    pub(crate) index: usize,
    pub(crate) port: u16,
    pub(crate) actor: &'a Actor,
    pub(crate) descriptor: &'a str,
    pub(crate) allowlist: &'a [&'a str],
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
            port,
            actor,
            descriptor,
            allowlist,
            escape_descriptor,
            coord_auth_pubkey,
            bitcoind_rpc_addr,
            bitcoind_auth,
            manifest,
            params,
        } = spawn;
        let allowlist_toml: Vec<String> =
            allowlist.iter().map(|desc| format!("\"{desc}\"")).collect();
        // Table headers end the top-level section, so `[chain_backend]` and
        // `[channel]` come last. `coordinator_auth_pubkey` is the trust root
        // (ADR-0013 §2/§4): the same key in every node's config, and — in channel
        // mode — hashed into `manifest_hash`, so a node sealed to this manifest will
        // not boot under a swapped coordinator.
        //
        // `[chain_backend]` is MANDATORY here: with `[channel]` on, this node
        // combines and broadcasts, and a node that could not broadcast would accept
        // spends it can never complete.
        let config = format!(
            "listen_port = {port}\n\
             node_seckey = \"{}\"\n\
             descriptor = \"{descriptor}\"\n\
             allowlist = [{}]\n\
             escape_descriptor = \"{escape_descriptor}\"\n\
             max_derivation_index = {}\n\
             hold_secs = {}\n\
             duress_delay_secs = {}\n\
             epsilon_secs = {}\n\
             combine_slack_secs = {}\n\
             delivery_horizon_secs = {}\n\
             hot_max_per_tx = {}\n\
             hot_max_per_window = {}\n\
             hot_window_secs = {}\n\
             max_commitment_age_secs = {}\n\
             policy_version = {}\n\
             escape_feerate_floor = {}\n\
             pin_normal_hash = \"{}\"\n\
             pin_duress_hash = \"{}\"\n\
             coordinator_auth_pubkey = \"{coord_auth_pubkey}\"\n\
             \n[chain_backend]\n\
             rpc_addr = \"{bitcoind_rpc_addr}\"\n\
             auth = \"{bitcoind_auth}\"\n\
             {}",
            actor.seckey.display_secret(),
            allowlist_toml.join(", "),
            params.max_derivation_index,
            params.hold_secs,
            params.duress_delay_secs,
            params.epsilon_secs,
            params.combine_slack_secs,
            params.delivery_horizon_secs,
            params.hot_budget.max_per_tx_sat,
            params.hot_budget.max_per_window_sat,
            params.hot_budget.window_secs,
            params.max_commitment_age_secs,
            params.policy_version,
            params.escape_feerate_floor,
            vault_node::argon2id_normal_phc_at(&params.normal_pin, params.pin_m_cost_kib),
            vault_node::argon2id_duress_phc_at(&params.duress_pin, params.pin_m_cost_kib),
            manifest.channel_toml(actor),
        );
        let config_path = nodes_dir.join(format!("node{index}.toml"));
        std::fs::write(&config_path, config)?;
        let log_path = nodes_dir.join(format!("node{index}.log"));
        let child = spawn_child(node_bin, &config_path, &log_path)?;
        Ok(NodeProcess {
            index,
            node_id: manifest.node_id_of(actor),
            port,
            child,
            config_path,
            log_path,
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
        let mut second = spawn_child(&self.node_bin, &self.config_path, &self.log_path)?;
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

    /// Kill the node AND destroy its deployment — config, keys, log. Models
    /// ADR-0007 reboot-death under the tmpfs deployment: the machine comes back
    /// bare, holding no signing key, no schedule, and no partials, so it cannot
    /// restart or rejoin. Deletion of the key-bearing config is mandatory, and the
    /// method attempts a restart against the vanished path to prove the dead
    /// deployment cannot serve again.
    pub(crate) fn destroy(mut self) -> Result<(), Error> {
        let _ = self.child.kill();
        let _ = self.child.wait();
        std::fs::remove_file(&self.config_path).map_err(|e| {
            format!(
                "cannot destroy node {} key-bearing config {}: {e}",
                self.number(),
                self.config_path.display()
            )
        })?;
        if self.config_path.exists() {
            return Err(format!(
                "node {} key-bearing config still exists after deletion: {}",
                self.number(),
                self.config_path.display()
            )
            .into());
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
        let mut restart = spawn_child(&self.node_bin, &self.config_path, &self.log_path)
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
}

fn spawn_child(node_bin: &Path, config_path: &Path, log_path: &Path) -> Result<Child, Error> {
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
        .stdout(log.try_clone()?)
        .stderr(log)
        .stdin(Stdio::null())
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

    match VAULT_NODE.get_or_init(|| locate_vault_node_uncached().map_err(|e| e.to_string())) {
        Ok(path) => Ok(path.clone()),
        Err(error) => Err(error.clone().into()),
    }
}

fn locate_vault_node_uncached() -> Result<PathBuf, Error> {
    let exe = std::env::current_exe()?;
    let dir = exe.parent().ok_or("current executable has no parent dir")?;
    // Test binaries live in `<profile>/deps`; ordinary `cargo run` binaries live in
    // `<profile>`. In either case, execute the node from the profile we actually
    // build. Otherwise `cargo run --release` builds a fresh DEV node and silently
    // executes a potentially stale `target/release/vault-node`.
    let profile_dir = if dir.file_name().and_then(|name| name.to_str()) == Some("deps") {
        dir.parent()
            .ok_or("test executable has no profile parent")?
    } else {
        dir
    };
    let release = profile_dir.file_name().and_then(|name| name.to_str()) == Some("release");
    let sibling = profile_dir.join("vault-node");

    println!("      building vault-node...");
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut command = Command::new(cargo);
    command.args(["build", "-p", "vault-node"]);
    if release {
        command.arg("--release");
    }
    let status = command
        .status()
        .map_err(|e| format!("cannot run cargo to build vault-node: {e}"))?;
    if !status.success() {
        return Err(format!(
            "cargo build -p vault-node{} failed",
            if release { " --release" } else { "" }
        )
        .into());
    }

    if sibling.exists() {
        Ok(sibling)
    } else {
        Err("cannot locate the vault-node binary after cargo build".into())
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
