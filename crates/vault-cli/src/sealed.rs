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
mod tests {
    use super::*;
    use crate::setup::tests::{ceremony_through_endorse, Ceremony};
    use bitcoin::hashes::{sha256, Hash};
    use vault_proto::SignRequest;

    /// The exact captured pre-M1 artifact and the checksum its provenance record states,
    /// so a fixture edited in place fails HERE rather than quietly weakening the one test
    /// whose whole point is that these bytes are historical.
    const PRE_M1: &str = include_str!("../tests/fixtures/pre-m1-manifest.json");
    const PRE_M1_SHA256: &str = "1758a90253c220e579a1fd759644dc572694e9e01065beb6217135ec620e87a9";

    /// A REAL sealed set: the production `assemble` → per-device endorse →
    /// `finalize` path, then its `sealed/backup/` operator artifact directory.
    fn sealed_set() -> (Ceremony, std::path::PathBuf) {
        let ceremony = ceremony_through_endorse(3, 2);
        ceremony.finalize().expect("finalize");
        let backup = ceremony.sealed("backup");
        (ceremony, backup)
    }

    fn manifest_of(backup: &Path) -> ParsedManifest {
        parse_manifest(&read(backup, "manifest.json").expect("manifest.json")).expect("parses")
    }

    /// The network-I/O sentinel: the fixture's OWN listeners, bound on every endpoint the
    /// manifest pins and held since before the ceremony chose them, are still un-accepted
    /// when `run` returns. A dialled or probed node would land on one, and nothing is bound
    /// and released here, so no parallel test can race this for a port.
    fn without_network_io<T>(ceremony: &Ceremony, run: impl FnOnce() -> T) -> T {
        let out = run();
        for listener in &ceremony.listeners {
            let idle =
                matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock);
            assert!(idle, "loading a sealed artifact set must open no socket");
        }
        out
    }

    /// This vault's manifest with `pointer` replaced by `literal`, or by the OTHER vault's value.
    fn spliced(original: &[u8], other: &[u8], pointer: &str, literal: &str) -> Vec<u8> {
        let mut value: serde_json::Value = serde_json::from_slice(original).expect("json");
        let foreign: serde_json::Value = serde_json::from_slice(other).expect("json");
        *value.pointer_mut(pointer).expect("field") = match literal {
            "" => foreign.pointer(pointer).expect("foreign field").clone(),
            text => serde_json::from_str(text).expect("literal"),
        };
        value.to_string().into_bytes()
    }

    /// The refusal `what` must earn. `LiveVault` deliberately carries no `Debug`,
    /// so the tests do not ask a vault-bearing type to print itself.
    fn refused(artifacts: &Path, what: &str) -> String {
        match LiveVault::load_artifacts(artifacts) {
            Ok(_) => panic!("{what} must be refused"),
            Err(e) => e.to_string(),
        }
    }

    /// The CAPTURED pre-M1 `manifest.json` — revision 0, byte-for-byte from the ceremony
    /// at 5c05a6d, provenance beside it — PARSES for cold inspection, which is the whole
    /// point of a syntax-tolerant reader. Live conversion still refuses it on the REVISION,
    /// and it does so in a directory holding NOTHING else with no credential path passed:
    /// a refusal naming a sibling artifact would prove the version gate ran too late.
    #[test]
    fn the_captured_pre_m1_manifest_parses_but_fails_conversion_on_its_version_first() {
        assert_eq!(
            sha256::Hash::hash(PRE_M1.as_bytes()).to_string(),
            PRE_M1_SHA256,
            "the fixture is not the bytes its provenance record names"
        );
        let old = parse_manifest(PRE_M1).expect("a pre-M1 manifest still parses");
        assert_eq!(old.protocol_version, 0);
        assert_eq!(old.recovery_timelock, 4_224_679, "a field revision 0 had");
        assert_eq!(old.escape_bump_max_fee_pct, 0, "a field revision 1 added");
        assert!(old.network.is_empty(), "a field revision 2 added");

        let temp = crate::fed::TempDir::new("pre-m1").expect("temp dir");
        std::fs::write(temp.path.join("manifest.json"), PRE_M1).expect("write");
        let error = refused(&temp.path, "a pre-M1 manifest");
        assert!(error.contains("protocol_version 0"), "{error}");
        // Every needle here is a LATER stage's own diagnostic, so the list is only as
        // complete as those diagnostics' current wording. Child B made [`read_secret`]
        // shared and reworded its three refusals from "credential" to "secret file", which
        // is accurate — it now reads the USER scalar too — and which left the open/mode/
        // read boundary named by nothing in this list. So "secret file" joins it, and
        // "credential" stays for [`CoordinatorCredential::load_file`]'s own two.
        for later in [
            "descriptor.txt",
            "recomputed hash",
            "credential",
            "secret file",
            "older(",
        ] {
            assert!(!error.contains(later), "the version comes first: {error}");
        }

        // Nor can a malformed CURRENT field outrank that diagnostic: a version gate placed
        // after the full decode answers "invalid type: string" for this file instead.
        let mut broken: serde_json::Value = serde_json::from_str(PRE_M1).expect("json");
        broken["recovery_timelock"] = "not a number".into();
        std::fs::write(temp.path.join("manifest.json"), broken.to_string()).expect("write");
        let error = refused(&temp.path, "an old manifest with a malformed current field");
        assert!(error.contains("protocol_version 0"), "{error}");
    }

    /// One artifact at a time — a whole file, a JSON pointer taking another vault's value,
    /// or one taking a literal: each is caught by its OWN cross-check, none reaches the
    /// network, and the exact restored bytes convert again.
    #[test]
    fn each_independently_tampered_artifact_is_refused_before_any_network_io() {
        // A leading `/` is a JSON pointer into manifest.json and a third column splices a
        // literal, for a value two regtest vaults share; anything else is a file. Neither
        // manifest anchor copy is authenticated by the file of that name, and `/network` is
        // refused by the FLAVOUR guard — which runs before the anchor, so it proves itself.
        // `/recovery_timelock` is answered by the descriptor-derived template, which is
        // authoritative for all three consensus facts the manifest reads back.
        const TAMPERS: [(&str, &str, &str); 12] = [
            ("descriptor.txt", "vault_descriptor", ""),
            ("wallet-id.txt", "wallet-id.txt", ""),
            ("manifest-hash.txt", "manifest-hash.txt", ""),
            ("coordinator-auth.pubkey", "coordinator_auth_pubkey", ""),
            ("/nodes/0/signing_pubkey", "at that position", ""),
            ("/nodes/0/transport_endpoints", "recomputed hash", ""),
            ("/nodes/0/channel_endorsement", "does not verify", ""),
            ("/wallet_id", "manifest wallet_id", ""),
            ("/manifest_hash", "manifest manifest_hash", ""),
            ("/recovery_timelock", "under older(1) is not", "1"),
            ("/network", "test-kind (tpub)", "\"bitcoin\""),
            ("/max_msg_bytes", "recomputed hash", "999999"),
        ];
        let (ceremony, backup) = sealed_set();
        let (other, foreign) = sealed_set();
        LiveVault::load_artifacts(&backup).expect("the untampered set converts");

        for (target, needle, literal) in TAMPERS {
            let json = target.starts_with('/');
            let file = if json { "manifest.json" } else { target };
            let original = std::fs::read(backup.join(file)).expect("artifact");
            let mut swap = std::fs::read(foreign.join(file)).expect("the other vault's");
            if json {
                swap = spliced(&original, &swap, target, literal);
            }
            assert_ne!(original, swap, "{target} must change the sealed value");
            std::fs::write(backup.join(file), &swap).expect("tamper");
            // BOTH fixtures' listeners: this row swaps node 0's endpoints for the OTHER
            // vault's, so a loader that dialled only that node lands solely on ITS listeners.
            let quiet = || without_network_io(&other, || refused(&backup, target));
            let error = without_network_io(&ceremony, quiet);
            assert!(error.contains(needle), "{target}: {error}");
            std::fs::write(backup.join(file), &original).expect("restore");
            LiveVault::load_artifacts(&backup).expect("the exact restored bytes convert again");
        }
    }

    /// The complete set converts, and every value the vault carries is one the
    /// artifacts proved — including the endpoints, in node/endpoint order.
    #[test]
    fn a_complete_sealed_set_converts_and_carries_only_cross_checked_values() {
        let (ceremony, backup) = sealed_set();
        let vault = without_network_io(&ceremony, || {
            LiveVault::load_artifacts(&backup).expect("converts")
        });
        let m = manifest_of(&backup);
        assert_eq!(vault.wallet_id.to_lower_hex_string(), m.wallet_id);
        assert_eq!(vault.manifest_hash.to_lower_hex_string(), m.manifest_hash);
        assert_eq!(vault.descriptor.to_string(), m.vault_descriptor);
        assert_eq!(vault.network, Network::Regtest);
        assert_eq!(vault.escape_bump_max_fee_pct, 0);
        // Type-checked and carried, NOT hash-authenticated — see the field's docs.
        assert_eq!(vault.policy_version, m.policy_version);
        // `max_msg_bytes` IS hash-authenticated — the tamper table above splices it and
        // the anchor catches it — and reaches a `usize` only through the checked
        // conversion, never an `as` that could truncate a sealed value.
        assert_eq!(vault.max_msg_bytes, m.max_msg_bytes);
        let cap = vault
            .channel_body_cap()
            .expect("the sealed cap fits this host");
        assert_eq!(u64::try_from(cap), Ok(m.max_msg_bytes));
        assert_eq!(vault.template.threshold, m.t);
        assert_eq!(vault.template.recovery_timelock, m.recovery_timelock);
        assert_eq!(vault.check_params.allowed.len(), m.hot_allowlist.len() + 1);
        let pinned = vault.coordinator_pubkey.to_string();
        assert_eq!(pinned, m.coordinator_auth_pubkey);
        let nodes = m.nodes.iter();
        let pinned: Vec<String> = nodes.flat_map(|n| n.transport_endpoints.clone()).collect();
        let loaded: Vec<String> = vault.endpoints.iter().map(SocketAddr::to_string).collect();
        assert_eq!(loaded, pinned);
    }

    /// The runtime artifact directory is NON-SECRET. Built from the exact finalized bytes
    /// with `coordinator-auth.secret` absent it still converts; a malformed decoy of that
    /// name dropped beside the artifacts changes nothing, because the loader never forms
    /// that path; and the credential the operator actually selected — stored elsewhere, as
    /// the ceremony's own README instructs — still pairs with the vault. Any mutation that
    /// reinstates `artifacts.join("coordinator-auth.secret")` dies on one of the three.
    #[test]
    fn artifacts_load_without_the_secret_and_an_adjacent_decoy_is_never_opened() {
        let (ceremony, backup) = sealed_set();
        let runtime = ceremony.sealed("runtime");
        std::fs::create_dir_all(&runtime).expect("runtime dir");
        for entry in std::fs::read_dir(&backup).expect("backup") {
            let path = entry.expect("entry").path();
            let name = path.file_name().expect("name").to_owned();
            if name != "coordinator-auth.secret" {
                std::fs::copy(&path, runtime.join(name)).expect("the exact finalized bytes");
            }
        }
        assert!(!runtime.join("coordinator-auth.secret").exists());
        let vault = without_network_io(&ceremony, || {
            LiveVault::load_artifacts(&runtime).expect("the secret is not a runtime artifact")
        });

        std::fs::write(runtime.join("coordinator-auth.secret"), "not a key\n").expect("decoy");
        LiveVault::load_artifacts(&runtime).expect("a decoy beside the artifacts is never read");

        let elsewhere = crate::fed::TempDir::new("credential").expect("temp dir");
        let selected = elsewhere.path.join("coordinator-auth.secret");
        std::fs::copy(backup.join("coordinator-auth.secret"), &selected).expect("copy");
        let credential = CoordinatorCredential::load_file(&selected, &vault.coordinator_pubkey)
            .expect("the explicitly selected credential pairs with the vault");
        // The pairing is proved the only way the credential still allows: an
        // authentication that verifies against the manifest-pinned PUBLIC half.
        authenticated(&credential, &vault, "pairs");
    }

    /// Authenticate a request through `cred`, verify the result against the vault's
    /// manifest-pinned coordinator public key, and hand the authenticated request back.
    fn authenticated(cred: &CoordinatorCredential, vault: &LiveVault, psbt: &str) -> SignRequest {
        let mut request = SignRequest {
            psbt: psbt.to_string(),
            escape_psbt: "escape".to_string(),
            escape_bumps: Vec::new(),
            pin: Default::default(),
            nonce: String::new(),
            expiry: 1_752_000_000,
            policy_version: vault.policy_version,
            coord_sig: String::new(),
        };
        cred.authenticate_spend(&mut request, &vault.wallet_id)
            .expect("the credential authenticates in place");
        let signature = request.coord_sig.clone();
        assert!(
            verifies(vault, &request, &signature),
            "under the pinned key"
        );
        request
    }

    /// Whether `coord_sig` verifies as the coordinator's authentication of `request`'s
    /// canonical bytes under the vault's manifest-pinned PUBLIC half.
    fn verifies(vault: &LiveVault, request: &SignRequest, coord_sig: &str) -> bool {
        let digest = Message::from_digest(request.coord_request().auth_digest(&vault.wallet_id));
        let der = <Vec<u8> as bitcoin::hex::FromHex>::from_hex(coord_sig).expect("hex");
        let sig = Signature::from_der(&der).expect("DER");
        let secp = Secp256k1::verification_only();
        secp.verify_ecdsa(&digest, &sig, &vault.coordinator_pubkey.inner)
            .is_ok()
    }

    /// The credential AUTHENTICATES and hands nothing else back: each call draws its own
    /// single-use nonce and signs the canonical bytes that nonce belongs to, verifiably under
    /// the manifest-pinned public half. That it returns no key, scalar, bytes or callback is a
    /// property of the DECLARATION, so it is checked on the production source.
    #[test]
    fn the_credential_authenticates_in_place_and_hands_back_no_secret_authority() {
        let (_ceremony, backup) = sealed_set();
        let vault = LiveVault::load_artifacts(&backup).expect("converts");
        let selected = backup.join("coordinator-auth.secret");
        let credential = CoordinatorCredential::load_file(&selected, &vault.coordinator_pubkey)
            .expect("the sealed credential");

        let first = authenticated(&credential, &vault, "one");
        let second = authenticated(&credential, &vault, "one");
        assert_ne!(first.nonce, second.nonce, "each call draws a fresh nonce");
        assert_ne!(first.coord_sig, second.coord_sig, "over its own nonce");
        // BODY-bound, not merely key-bound: a fresh nonce alone would make any two
        // signatures differ, so the claim is checked the other way round — this exact
        // signature over a request whose canonical bytes moved does not verify.
        let mut tampered = first.clone();
        tampered.psbt = "two".to_string();
        let bound = !verifies(&vault, &tampered, &first.coord_sig);
        assert!(bound, "the authentication is bound to the request bytes");

        let code = production_half();
        let block = impl_block(code, "CoordinatorCredential");
        assert_eq!(
            public_signatures(block),
            [
                "pub(crate) fn load_file(path: &Path, pinned: &PublicKey) -> Result<Self, Error> {",
                "pub(crate) fn authenticate_spend(",
            ],
            "the credential's public surface moved"
        );
        // No return in the whole impl — public or not, single- or multi-line — hands out
        // key material or the guard that holds it.
        for banned in ["SecretKey", "-> Scalar", "-> Zeroizing", "-> [u8"] {
            assert!(!block.contains(banned), "the credential returns {banned}");
        }
    }

    /// Every way the selected credential can be wrong, each at its own boundary. The
    /// symlink row is the sharpest: its TARGET is the control that loads, so the only
    /// thing that can refuse the link is the no-follow open itself.
    #[test]
    fn the_credential_refuses_a_symlink_a_directory_a_loose_mode_and_a_foreign_key() {
        let (_ceremony, backup) = sealed_set();
        let vault = LiveVault::load_artifacts(&backup).expect("converts");
        let temp = crate::fed::TempDir::new("credential").expect("temp dir");
        let secret = std::fs::read_to_string(backup.join("coordinator-auth.secret")).expect("read");
        let write = |name: &str, body: &str, mode: u32| -> std::path::PathBuf {
            let path = temp.path.join(name);
            std::fs::write(&path, body).expect("write");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("mode");
            path
        };

        let good = write("good", &secret, 0o600);
        CoordinatorCredential::load_file(&good, &vault.coordinator_pubkey).expect("the control");
        std::os::unix::fs::symlink(&good, temp.path.join("link")).expect("symlink");
        std::fs::create_dir(temp.path.join("dir")).expect("dir");
        write("group", &secret, 0o640);
        write("world", &secret, 0o604);
        write("malformed", "not a key\n", 0o600);
        write("foreign", &format!("{}\n", "11".repeat(32)), 0o600);
        for (name, needle) in [
            ("link", "cannot open"),
            ("dir", "not a regular file"),
            ("group", "mode 0640"),
            ("world", "mode 0604"),
            ("malformed", "does not parse"),
            ("foreign", "does not derive the manifest-pinned"),
        ] {
            let path = temp.path.join(name);
            let error = match CoordinatorCredential::load_file(&path, &vault.coordinator_pubkey) {
                Ok(_) => panic!("{name} must be refused"),
                Err(e) => e.to_string(),
            };
            assert!(error.contains(needle), "{name}: {error}");
            assert!(!error.contains(secret.trim()), "{name} printed the secret");
        }
    }

    /// The PRODUCTION half only: scanning the whole file would let a test's own assertion
    /// literals satisfy the scans below, which is how one of them once passed vacuously.
    fn production_half() -> &'static str {
        let source = include_str!("sealed.rs");
        source.split("#[cfg(test)]").next().unwrap_or(source)
    }

    /// The body of `impl <name> {` in `code`, up to its closing column-0 brace.
    fn impl_block(code: &'static str, name: &str) -> &'static str {
        let (_, body) = code
            .split_once(&format!("impl {name} {{\n"))
            .expect("the impl block");
        body.split("\n}\n").next().expect("its end")
    }

    /// Every non-private function signature line in one impl block, in source order.
    fn public_signatures(block: &'static str) -> Vec<&'static str> {
        block
            .lines()
            .map(str::trim)
            .filter(|line| {
                (line.starts_with("pub ") || line.starts_with("pub(")) && line.contains(" fn ")
            })
            .collect()
    }

    /// Whether a signature is one the guard may expose: no `SecretKey` in or out, no borrowed
    /// or bare byte view, no raw-key callback, no `Deref`, and a CONSUMING byte exposure only.
    fn permitted_surface(signature: &str) -> bool {
        let (params, returned) = signature.split_once("->").unwrap_or((signature, ""));
        !["SecretKey", "&[u8", "-> [u8", "Fn(", "dyn ", "Deref"]
            .iter()
            .any(|banned| signature.contains(banned))
            && (!returned.contains("Zeroizing<[u8; 32]>") || params.contains("(self)"))
    }

    /// Every Rust source in the workspace, sorted: the scan below must reach files this
    /// crate cannot `include_str!`, and a generated per-crate `target/` is not source.
    fn workspace_sources() -> Vec<std::path::PathBuf> {
        let crates = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("crates");
        let (mut found, mut stack) = (Vec::new(), vec![crates.to_path_buf()]);
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).expect("a workspace directory") {
                let path = entry.expect("entry").path();
                if path.is_dir() && path.file_name().is_some_and(|name| name != "target") {
                    stack.push(path);
                } else if path.extension().is_some_and(|kind| kind == "rs") {
                    found.push(path);
                }
            }
        }
        found.sort();
        assert!(found.len() > 20, "the workspace scan found almost nothing");
        found
    }

    /// The milestone scalar guard: its complete operational surface, the shapes that surface
    /// may never take, and — WORKSPACE-WIDE — that exactly one implementation anywhere owns a
    /// secret under that name, at its intended private definition here. The local check alone
    /// is evadable: a parallel secret-owning `Scalar` in any other normal-build file would hand
    /// out everything this one refuses to, and a scan of this file alone would not notice.
    #[test]
    fn the_scalar_guard_is_the_sole_secret_owner_and_exposes_only_its_pinned_surface() {
        let code = production_half();
        let block = impl_block(code, "Scalar");
        assert_eq!(
            public_signatures(block),
            [
                "pub(crate) fn parse(text: &str, what: &str) -> Result<Scalar, Error> {",
                "pub(crate) fn from_bytes(raw: &Zeroizing<[u8; 32]>) -> Result<Scalar, Error> {",
                "pub(crate) fn public_key(&self) -> PublicKey {",
                "pub(crate) fn sign_ecdsa(&self, message: &Message) -> Signature {",
                "pub(crate) fn into_zeroizing_bytes(self) -> Zeroizing<[u8; 32]> {",
            ],
            "the guard's surface moved"
        );
        // The rule that judges those, exercised on BOTH answers so it cannot pass
        // vacuously: the one permitted consuming conversion is accepted, and every escape
        // the guard forbids — the key itself, a borrow of it, a non-consuming or
        // non-zeroizing byte owner, a raw-key callback — is refused by that same rule.
        assert!(permitted_surface(
            "pub(crate) fn into_zeroizing_bytes(self) -> Zeroizing<[u8; 32]> {"
        ));
        for escape in [
            "pub(crate) fn seckey(&self) -> SecretKey {",
            "pub(crate) fn key(&self) -> &SecretKey {",
            "pub(crate) fn bytes(&self) -> &[u8; 32] {",
            "pub(crate) fn raw(&self) -> [u8; 32] {",
            "pub(crate) fn peek(&self) -> Zeroizing<[u8; 32]> {",
            "pub(crate) fn with_key<R>(&self, f: impl Fn(&SecretKey) -> R) -> R {",
        ] {
            assert!(!permitted_surface(escape), "the rule admits {escape}");
        }
        for signature in public_signatures(block) {
            assert!(
                permitted_surface(signature),
                "the guard exposes {signature}"
            );
        }
        // The ONE route a plain key takes in is private, and it wipes the `Copy` value it
        // was handed; `Drop` is what makes every other exit — success, refusal, unwind —
        // erase; and no `Clone`, `Debug` or `Deref` copies or prints what it holds.
        assert!(block.contains("fn guarding(mut inbound: SecretKey) -> Scalar {"));
        assert!(block.contains("inbound.non_secure_erase();"));
        // Every raw-key mention in the block is a route INTO that guard: its own private
        // parameter, plus the two constructors that hand their parse straight to it. A
        // fourth would be a key built or held outside it.
        let named = |l: &&str| !l.trim_start().starts_with("///") && l.contains("SecretKey");
        let raw = block.lines().filter(named).count();
        let guarded = block.matches("Scalar::guarding(").count();
        assert_eq!(
            (raw, guarded),
            (3, 2),
            "a raw key outside the guarding route"
        );
        let erasing = "impl Drop for Scalar {\n    fn drop(&mut self) {\n        \
                       self.0.non_secure_erase();\n    }\n}";
        assert!(code.contains(erasing), "the guard stopped erasing on drop");
        for spelling in ["Clone for Scalar", "Debug for Scalar", "Deref for Scalar"] {
            assert!(!code.contains(spelling), "Scalar implements {spelling}");
        }
        // A DERIVE grants what those three forbid while writing no `impl` line, so the
        // declaration itself is pinned, from the fragments the ownership scan also uses.
        let (owner, secret) = (format!("struct {}", "Scalar"), format!("Secret{}", "Key"));
        let sole = format!("`Debug`.\npub(crate) {owner}({secret});\n");
        assert!(code.contains(&sole), "an attribute on the guard");

        // WORKSPACE-WIDE OWNERSHIP. The needles are assembled from fragments so this
        // test's own bytes are never one of the declarations it counts.
        let mut owners = Vec::new();
        for path in workspace_sources() {
            let text = std::fs::read_to_string(&path).expect("a workspace source");
            for (offset, _) in text.match_indices(&owner) {
                // The declaration ends at whichever comes first: the `;` of a tuple or
                // unit struct, or the `}` closing a braced one.
                let rest = &text[offset..];
                let end = rest.find(';').unwrap_or(rest.len());
                let braced = rest.find('}').unwrap_or(rest.len());
                if rest[..end.min(braced)].contains(&secret) {
                    owners.push(path.clone());
                }
            }
        }
        let intended = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/sealed.rs");
        assert_eq!(
            owners,
            vec![intended],
            "exactly one workspace implementation may own a secret under this name"
        );
    }

    /// The two halves are separate BY DECLARATION, which is a property of shape and so is
    /// checked on the source: the policy half child B consumes declares no secret owner and
    /// no credential FIELD, the credential owns its scalar in a zeroize-on-drop buffer, and
    /// neither type derives `Debug`, so no diagnostic can print what a credential holds.
    #[test]
    fn the_policy_half_declares_no_secret_and_the_credential_erases_its_own() {
        let code = production_half();
        let declaration = code
            .split("pub(crate) struct LiveVault {")
            .nth(1)
            .and_then(|rest| rest.split('}').next())
            .expect("the LiveVault declaration");
        for banned in ["SecretKey", "seckey", "Zeroizing", "Credential"] {
            // FIELDS only: the field docs NAME the credential type, so a scan over the
            // whole declaration would answer for the comment rather than for a field.
            let owns = declaration
                .lines()
                .filter(|line| !line.trim_start().starts_with("///"))
                .any(|line| line.contains(banned));
            assert!(!owns, "LiveVault owns {banned}");
        }
        assert!(
            code.contains("seckey: Zeroizing<[u8; 32]>"),
            "the credential's scalar must be owned by a zeroize-on-drop buffer"
        );
        // Every spelling, not one literal: a reordered derive list, an extra derive, or a
        // hand-written impl would print a `Zeroizing` scalar in full (zeroize derives it).
        for kind in ["LiveVault", "CoordinatorCredential"] {
            // `split_once`, not `split().next()`: the latter answers with the WHOLE
            // half when the name is absent, so a renamed type would pass vacuously.
            let (above, _) = code
                .split_once(&format!("struct {kind} {{"))
                .expect("the declaration");
            let attributes = above.rsplit("\n\n").next().unwrap_or("");
            let prints = attributes
                .lines()
                .any(|l| l.starts_with("#[") && l.contains("Debug"))
                || code.contains(&format!("Debug for {kind}"));
            assert!(!prints, "{kind} must not print itself");
        }
    }
}
