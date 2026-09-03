//! The sealed-artifact trust boundary (bead btc-policy-mby-sealed-vault-ingress-s7u).
//!
//! [`parse_manifest`] is syntax-tolerant so a captured pre-M1 manifest can still be READ —
//! cold recovery authority is the descriptor plus consensus. It is never hash-authenticated
//! under a v0 layout and never becomes a [`LiveVault`]: the revision check fires before any
//! current-field or hash error, before every sibling artifact read, and before any socket, and
//! no version-dispatched legacy preimage exists here.
//!
//! Custody is SPLIT by INSTRUCTION, not by ceremony output. [`LiveVault::load_artifacts`] reads
//! the non-secret runtime artifact directory the CALLER names: it never appends `sealed/backup`,
//! never forms `<artifacts>/coordinator-auth.secret`, and never holds a secret — so it loads
//! with that file absent and ignores a malformed decoy of that name beside the public artifacts.
//! The coordinator's authority is the separate concrete [`CoordinatorCredential`], read from a
//! second explicitly named path and verified against the pinned public key the vault carries.

use std::io::Read;
use std::net::SocketAddr;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::str::FromStr;

use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1::{ecdsa::Signature, Message, Secp256k1, SecretKey};
use bitcoin::{Amount, Network, PublicKey};
use miniscript::{Descriptor, DescriptorPublicKey};
use policy_core::{CheckParams, VaultTemplate};
use serde::Deserialize;
// The live schema: manifest revision 2 seals the network (bead btc-policy-sealed-network-v2-mn6).
use vault_node::channel::{ceremony, PROTOCOL_VERSION as CURRENT_PROTOCOL_VERSION};
use vault_node::nodekey::parse_compressed_pubkey as compressed_pubkey;
use zeroize::Zeroizing;

use crate::http::Error;

/// One node as the manifest publishes it; every field defaults so an older
/// revision still parses.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub(crate) struct ParsedNode {
    pub(crate) node_id: u16,
    pub(crate) signing_pubkey: String,
    pub(crate) channel_pubkey: String,
    pub(crate) transport_endpoints: Vec<String>,
    pub(crate) channel_endorsement: String,
}

/// A manifest as READ, not as trusted: nothing here is cross-checked.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub(crate) struct ParsedManifest {
    pub(crate) protocol_version: u32,
    pub(crate) wallet_id: String,
    pub(crate) vault_descriptor: String,
    pub(crate) manifest_hash: String,
    pub(crate) coordinator_auth_pubkey: String,
    pub(crate) t: usize,
    pub(crate) n: usize,
    pub(crate) recovery_timelock: u32,
    pub(crate) policy_version: u32,
    pub(crate) max_msg_bytes: u64,
    pub(crate) hot_max_per_tx: u64,
    pub(crate) hot_max_per_window: u64,
    pub(crate) hot_window_secs: u64,
    pub(crate) hot_allowlist: Vec<String>,
    pub(crate) escape_descriptor: String,
    pub(crate) max_derivation_index: u32,
    pub(crate) escape_feerate_floor: u64,
    pub(crate) escape_coverage_pct: u8,
    pub(crate) escape_bump_max_fee_pct: u8,
    pub(crate) network: String,
    pub(crate) nodes: Vec<ParsedNode>,
}

/// Read a manifest for COLD inspection: every field defaults, so an older revision parses.
pub(crate) fn parse_manifest(text: &str) -> Result<ParsedManifest, Error> {
    serde_json::from_str(text).map_err(|e| format!("manifest.json does not parse: {e}").into())
}

/// A vault whose complete artifact set was cross-checked, and therefore the only
/// thing this crate authorizes against.
pub(crate) struct LiveVault {
    pub(crate) wallet_id: [u8; 32],
    pub(crate) manifest_hash: [u8; 32],
    /// The frozen descriptor in definite-key form (template + witness script);
    /// `check_params.vault` is the same string for policy-core.
    pub(crate) descriptor: Descriptor<PublicKey>,
    pub(crate) template: VaultTemplate<PublicKey>,
    pub(crate) check_params: CheckParams,
    pub(crate) network: Network,
    /// The sealed ladder ceiling (ADR-0016 §2); nodes never enforce it, the signer does.
    pub(crate) escape_bump_max_fee_pct: u8,
    /// The base Escape's own sealed floor in sat/vB, and the percentage of the selected
    /// input value its one output must still cover (ADR-0016 §3). Both are already in the
    /// manifest hash preimage recomputed below, both are secret-free, and the composer
    /// (`btc-policy-m3b-spend-composition-nq8`) is their only reader.
    pub(crate) escape_feerate_floor: u64,
    pub(crate) escape_coverage_pct: u8,
    /// Carried and type-checked, NOT manifest-hash authenticated: the one manifest
    /// field that is neither in the hash preimage nor descriptor-derivable.
    pub(crate) policy_version: u32,
    pub(crate) max_msg_bytes: u64,
    /// The manifest-pinned coordinator identity, and only ever the PUBLIC half: the
    /// scalar that matches it belongs to [`CoordinatorCredential`], which this type
    /// neither loads nor holds nor can hand to child B's signer.
    pub(crate) coordinator_pubkey: PublicKey,
    /// Manifest-pinned loopback endpoints in node/endpoint order.
    pub(crate) endpoints: Vec<SocketAddr>,
}

fn read(dir: &Path, name: &str) -> Result<String, Error> {
    Ok(std::fs::read_to_string(dir.join(name))
        .map_err(|e| format!("cannot read {name}: {e}"))?
        .trim()
        .to_string())
}

fn parsed<T: FromStr>(text: &str, what: &str) -> Result<T, Error>
where
    T::Err: std::fmt::Display,
{
    T::from_str(text).map_err(|e| format!("{what} does not parse: {e}").into())
}

fn bad<T>(detail: String) -> Result<T, Error> {
    Err(detail.into())
}

impl LiveVault {
    /// Load and validate the non-secret runtime artifact set in the directory the
    /// caller EXPLICITLY names, or refuse. No ceremony root is inferred, no
    /// `sealed/backup` is appended, no credential path is joined onto `dir`, and no
    /// network I/O happens.
    pub(crate) fn load_artifacts(dir: &Path) -> Result<LiveVault, Error> {
        let text = read(dir, "manifest.json")?;
        // The revision FIRST, from a minimal envelope rather than the decoded current schema:
        // an old manifest is refused AS an old revision even when a later field does not fit
        // today's types, and always before any sibling artifact read and any socket.
        let envelope: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| format!("manifest.json does not parse: {e}"))?;
        let revision = &envelope["protocol_version"];
        if revision.as_u64() != Some(u64::from(CURRENT_PROTOCOL_VERSION)) {
            return bad(format!(
                "manifest protocol_version {revision} is not the live revision \
                 {CURRENT_PROTOCOL_VERSION}: a pre-M1 manifest parses for cold inspection but is \
                 never hash-authenticated under its own layout and cannot become a live vault"
            ));
        }
        let m = parse_manifest(&text)?;

        let text = read(dir, "descriptor.txt")?;
        let descriptor: Descriptor<PublicKey> = parsed(&text, "descriptor.txt")?;
        let canonical = descriptor.to_string();
        let claimed: Descriptor<PublicKey> = parsed(&m.vault_descriptor, "manifest descriptor")?;
        if claimed.to_string() != canonical {
            return bad("manifest vault_descriptor and descriptor.txt disagree".into());
        }
        let template = policy_core::parse_vault_template(&descriptor)
            .map_err(|e| format!("the sealed descriptor is off-template: {e}"))?;
        let wallet_id = crate::fed::wallet_id(&descriptor);
        for (name, claimed) in [
            ("wallet-id.txt", read(dir, "wallet-id.txt")?),
            ("manifest wallet_id", m.wallet_id.clone()),
        ] {
            if claimed != wallet_id.to_lower_hex_string() {
                return bad(format!("{name} is not H(canonical descriptor)"));
            }
        }
        // `t`, `n` and `recovery_timelock` are the three consensus facts the ceremony
        // reads back OUT of the descriptor rather than out of the hash preimage
        // (`setup.rs`), so the parsed template is authoritative and a manifest that
        // disagrees does not describe the vault it names.
        let (t, n) = (template.threshold, template.node_keys.len());
        let (lock, entries) = (template.recovery_timelock, m.nodes.len());
        let (mt, mn, mlock) = (m.t, m.n, m.recovery_timelock);
        if (mt, mn, mlock, entries) != (t, n, lock, n) {
            return bad(format!(
                "manifest {mt}-of-{mn} over {entries} nodes under older({mlock}) is not the \
                 descriptor's {t}-of-{n} under older({lock})"
            ));
        }

        // The sealed network, and both destination wallets bound to its flavour.
        let network = vault_node::parse_vault_network(&m.network)?;
        let escape: Descriptor<DescriptorPublicKey> =
            parsed(&m.escape_descriptor, "escape descriptor")?;
        policy_core::check_descriptor_network_kind("escape", &escape, network)?;
        let mut allowed = Vec::new();
        for text in &m.hot_allowlist {
            let hot: Descriptor<DescriptorPublicKey> = parsed(text, "hot descriptor")?;
            policy_core::check_descriptor_network_kind("hot allowlist", &hot, network)?;
            allowed.push(hot);
        }
        allowed.push(escape.clone());

        // The coordinator identity, PUBLIC half only. `dir.join("coordinator-auth.secret")`
        // is a path this loader must never form: the ceremony tells the operator to store
        // that credential away from the artifacts, so an adjacent file of that name is at
        // best stale and at worst planted. [`CoordinatorCredential`] owns the secret.
        let coordinator_pubkey = compressed_pubkey(&read(dir, "coordinator-auth.pubkey")?)?;
        if m.coordinator_auth_pubkey != coordinator_pubkey.to_string() {
            return bad("manifest coordinator_auth_pubkey and the backup pubkey disagree".into());
        }

        // Node identities and endpoints. `node_id` is the key's position in the
        // descriptor's canonical order, so the two must agree entry for entry —
        // an independent check rather than a re-reading of the hash below.
        let (mut nodes, mut channels, mut endpoints) = (Vec::new(), Vec::new(), Vec::new());
        for (index, node) in m.nodes.iter().enumerate() {
            let signing = compressed_pubkey(&node.signing_pubkey)?;
            if usize::from(node.node_id) != index || signing != template.node_keys[index] {
                return bad(format!(
                    "manifest node {index} claims node_id {} and a key that is not the \
                     descriptor's at that position",
                    node.node_id
                ));
            }
            if node.transport_endpoints.is_empty() {
                return bad(format!("manifest node {index} pins no endpoint"));
            }
            for endpoint in &node.transport_endpoints {
                let addr: SocketAddr = parsed(endpoint, "transport endpoint")?;
                if !addr.ip().is_loopback() {
                    return bad(format!("node {index} endpoint {addr} is not loopback"));
                }
                endpoints.push(addr);
            }
            channels.push(compressed_pubkey(&node.channel_pubkey)?);
            nodes.push(ceremony::CeremonyNode {
                node_id: node.node_id,
                signing_pubkey: signing,
                endpoints: node.transport_endpoints.clone(),
            });
        }

        // The anchor, recomputed from the manifest's own fields, then each node's
        // endorsement over it.
        let manifest_hash = ceremony::manifest_hash(
            &wallet_id,
            &coordinator_pubkey,
            &nodes,
            &channels,
            m.max_msg_bytes,
            vault_node::HotBudget {
                max_per_tx_sat: m.hot_max_per_tx,
                max_per_window_sat: m.hot_max_per_window,
                window_secs: m.hot_window_secs,
            },
            &m.hot_allowlist,
            &m.escape_descriptor,
            m.max_derivation_index,
            m.escape_feerate_floor,
            m.escape_coverage_pct,
            m.escape_bump_max_fee_pct,
            network,
        )?;
        for (name, claimed) in [
            ("manifest-hash.txt", read(dir, "manifest-hash.txt")?),
            ("manifest manifest_hash", m.manifest_hash.clone()),
        ] {
            if claimed != manifest_hash.to_lower_hex_string() {
                return bad(format!("{name} is not the manifest's own recomputed hash"));
            }
        }
        for (node, channel) in m.nodes.iter().zip(&channels) {
            ceremony::verify_endorsement(
                &template.node_keys[usize::from(node.node_id)],
                channel,
                &wallet_id,
                &manifest_hash,
                node.node_id,
                &node.transport_endpoints,
                &node.channel_endorsement,
            )
            .map_err(|e| format!("node {} endorsement does not verify: {e}", node.node_id))?;
        }

        Ok(LiveVault {
            wallet_id,
            manifest_hash,
            check_params: CheckParams {
                vault: parsed(&canonical, "vault descriptor")?,
                allowed,
                escape: Some(escape),
                max_derivation_index: m.max_derivation_index,
                hot_max_per_tx: Amount::from_sat(m.hot_max_per_tx),
            },
            descriptor,
            template,
            network,
            escape_bump_max_fee_pct: m.escape_bump_max_fee_pct,
            escape_feerate_floor: m.escape_feerate_floor,
            escape_coverage_pct: m.escape_coverage_pct,
            policy_version: m.policy_version,
            max_msg_bytes: m.max_msg_bytes,
            coordinator_pubkey,
            endpoints,
        })
    }

    pub(crate) fn channel_body_cap(&self) -> Result<usize, Error> {
        usize::try_from(self.max_msg_bytes).map_err(|_| "max_msg_bytes overflows usize".into())
    }
}

/// A secp256k1 scalar under RAII erasure: `SecretKey` is `Copy` and wipes nothing on drop, so
/// this owns the copy its operations read and erases THAT one on every exit — success, refusal
/// and unwind alike, and no other: a library-internal copy is beyond reach. No `Clone`/`Debug`.
pub(crate) struct Scalar(SecretKey);

impl Drop for Scalar {
    fn drop(&mut self) {
        self.0.non_secure_erase();
    }
}

impl Scalar {
    fn guarding(mut inbound: SecretKey) -> Scalar {
        let guarded = Scalar(inbound);
        inbound.non_secure_erase();
        guarded
    }
    pub(crate) fn parse(text: &str, what: &str) -> Result<Scalar, Error> {
        Ok(Scalar::guarding(parsed::<SecretKey>(text, what)?))
    }
    pub(crate) fn from_bytes(raw: &Zeroizing<[u8; 32]>) -> Result<Scalar, Error> {
        Ok(Scalar::guarding(SecretKey::from_slice(raw.as_slice())?))
    }
    pub(crate) fn public_key(&self) -> PublicKey {
        PublicKey::new(self.0.public_key(&Secp256k1::new()))
    }
    pub(crate) fn sign_ecdsa(&self, message: &Message) -> Signature {
        Secp256k1::signing_only().sign_ecdsa(message, &self.0)
    }
    pub(crate) fn into_zeroizing_bytes(self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.secret_bytes())
    }
}

/// The coordinator's authority over this vault, from a path the caller names OUTRIGHT.
/// One concrete type — no capability trait, no keystore framework — and deliberately no
/// `Debug`, so no diagnostic can print what it holds.
pub(crate) struct CoordinatorCredential {
    /// The scalar in the zeroize-on-drop byte form `secp256k1::SecretKey` lacks, so the
    /// copy this type owns is erased when it drops, and so is the parse's own copy in
    /// [`Self::load_file`]. Best effort: a library-internal copy is beyond its reach.
    seckey: Zeroizing<[u8; 32]>,
}

impl CoordinatorCredential {
    /// Load the credential at the explicitly selected `path` and prove it derives
    /// `pinned` — the manifest-pinned public key a [`LiveVault`] already cross-checked.
    /// A secret that does not derive it is a normal path bricked from birth against an
    /// immutable manifest, so this is a refusal and not a warning.
    pub(crate) fn load_file(path: &Path, pinned: &PublicKey) -> Result<Self, Error> {
        let text = read_secret(path)?;
        let scalar = Scalar::parse(text.trim(), "coordinator credential")?;
        let derived = scalar.public_key();
        let seckey = scalar.into_zeroizing_bytes();
        if derived != *pinned {
            return bad(format!(
                "credential {} does not derive the manifest-pinned coordinator public key",
                path.display()
            ));
        }
        Ok(CoordinatorCredential { seckey })
    }

    pub(crate) fn authenticate_spend(
        &self,
        request: &mut vault_proto::SignRequest,
        wallet_id: &[u8; 32],
    ) -> Result<(), Error> {
        request.nonce = crate::fed::fresh_nonce()?;
        let digest = request.coord_request().auth_digest(wallet_id);
        let signature = Scalar::from_bytes(&self.seckey)?.sign_ecdsa(&Message::from_digest(digest));
        request.coord_sig = signature.serialize_der().to_lower_hex_string();
        Ok(())
    }
}

/// Read a secret file: opened WITHOUT following a final symlink, then proved regular and
/// owner-only from the OPEN file's own metadata — so both checks describe the bytes that
/// were actually read, not a name that could be swapped between the check and the open.
/// The text is zeroizing all the way to the caller.
///
/// `pub(crate)` for child B's [`crate::signer::SoftwareSigner`], which reads the USER
/// scalar under the identical no-follow/regular/owner-only rules. One reader, so the
/// two secret files cannot drift apart on which paths they refuse.
pub(crate) fn read_secret(path: &Path) -> Result<Zeroizing<String>, Error> {
    read_file(path, None)
}

/// The Core cookie's whole-file cap: Core writes one short `__cookie__:` line.
pub(crate) const MAX_CORE_COOKIE_BYTES: usize = 4096;

/// The Core cookie, over that same open and BOUNDED: ONE `cap + 1` zeroizing buffer, never
/// grown, so exactly the cap is accepted only once EOF confirms it and cap+1 is refused.
pub(crate) fn read_core_cookie(path: &Path) -> Result<Zeroizing<String>, Error> {
    read_file(path, Some(MAX_CORE_COOKIE_BYTES))
}

/// The one reader both go through; `cap` bounds the WHOLE file, `None` being unbounded.
fn read_file(path: &Path, cap: Option<usize>) -> Result<Zeroizing<String>, Error> {
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        // `O_NONBLOCK`: a FIFO here would hang the open before `is_file` can refuse it.
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| format!("cannot open secret file {}: {e}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|e| format!("cannot stat {}: {e}", path.display()))?;
    if !metadata.is_file() {
        return bad(format!("{} is not a regular file", path.display()));
    }
    let mode = metadata.permissions().mode() & 0o7777;
    if mode & 0o077 != 0 {
        return bad(format!(
            "secret file {} is mode {mode:04o}: it must be readable by its owner alone",
            path.display()
        ));
    }
    if let Some(cap) = cap {
        let mut raw = Zeroizing::new(vec![0u8; cap + 1]);
        let mut filled = 0;
        while filled < raw.len() {
            match file.read(&mut raw[filled..]) {
                Ok(0) => break,
                Ok(read) => filled += read,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return bad(format!("cannot read secret file {}: {e}", path.display())),
            }
        }
        if filled > cap {
            return bad(format!("{} is over its {cap}-byte cap", path.display()));
        }
        return std::str::from_utf8(&raw[..filled])
            .map(|text| Zeroizing::new(text.to_owned()))
            .map_err(|e| format!("secret file {} is not UTF-8: {e}", path.display()).into());
    }
    // Sized from the open file: a reallocation mid-read leaves an un-wiped prefix behind.
    let mut text = Zeroizing::new(String::with_capacity(metadata.len() as usize + 1));
    file.read_to_string(&mut text)
        .map_err(|e| format!("cannot read secret file {}: {e}", path.display()))?;
    Ok(text)
}

#[cfg(test)]
#[path = "../tests/unit/sealed.rs"]
mod tests;
