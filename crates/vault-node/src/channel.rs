//! The node-to-node channel (V0-8a; V0-8b adds fire + `request`): authenticated
//! peer messaging, a verified partial-signature exchange, and the fire-gated
//! release + combine. ADR-0012 ("The node-to-node channel") is the authoritative
//! security spec; ADR-0013 §4 is the manifest root.
//!
//! This is the CHANNEL LAYER ONLY. It carries signatures and assembly, **never
//! policy** — a `request` envelope is authenticated here and handed straight back
//! to the node, which owns every policy gate. It does not run the duress state
//! machine (V0-4). It provides:
//!
//! - a self-authenticating **signed envelope** (possession proven per message —
//!   the fresh nonce+timestamp IS the challenge; there is no session handshake);
//! - a **partial** message verified against this node's own registered candidate;
//! - a **request** message carrying the coordinator-signed tagged request verbatim
//!   ([`MSG_TYPE_REQUEST`]), so delivery to one node reaches all;
//! - the **partial-release gate** ([`ChannelState::release_partials`]) — ADR-0012
//!   invariant 7, the one door a partial may leave through, and only at fire.
//!
//! # Ingress pipeline (every rejection exit is a tagged `ChannelReply`)
//!
//! ```text
//!   POST /channel  (pre-auth: 1 MiB body cap + global concurrency bound)
//!         │
//!   parse envelope JSON ─────────────── err ─▶ REJECTED(MALFORMED_JSON)
//!         │
//!   protocol_version == manifest's ──── ne ──▶ REJECTED(BAD_PROTOCOL_VERSION)
//!         │
//!   wallet_id == mine ───────────────── ne ──▶ REJECTED(WRONG_WALLET)
//!   manifest_hash == mine ───────────── ne ──▶ REJECTED(WRONG_MANIFEST)
//!         │
//!   recipient_node_id == my node_id ─── ne ──▶ REJECTED(WRONG_RECIPIENT)
//!         │
//!   sender_node_id in manifest ──────── no ──▶ REJECTED(UNKNOWN_SENDER)
//!         │            (endorsement is verified once at startup, so the
//!         │             manifest channel_pubkey is already endorsement-bound)
//!   channel_sig verifies over preimage  no ──▶ REJECTED(BAD_CHANNEL_SIG)
//!         │      ── sender now authenticated ──
//!   timestamp ∈ [now-300, now+60] ───── no ──▶ charge peer quota, then
//!                                                       REJECTED(STALE_TIMESTAMP) + freshness event
//!         │
//!   (sender,nonce) unseen ───────────── seen ▶ charge peer quota, then
//!                                                       REJECTED(REPLAYED_NONCE)
//!   charge peer quota (authenticated id) ─ hit ▶ RATE_LIMITED
//!   consume nonce (same atomic guard decision; AFTER quota so a rate-limited
//!     flood cannot grow the cache — the quota bounds it)
//!         │
//!   base64-decode payload_b64 ───────── err ─▶ REJECTED(MALFORMED_PAYLOAD)
//!         │
//!   dispatch on msg_type ──────────── unknown ▶ REJECTED(UNKNOWN_MSG_TYPE)
//!         ├── "partial" ─────────────────────────────────────────────────┐
//!         │  payload.wallet_id == envelope ─ ne ─▶ REJECTED(PAYLOAD_WALLET_MISMATCH)
//!         │  signer_node_id == sender_node_id  ne ─▶ REJECTED(SIGNER_MISMATCH)
//!         │  candidate(commitment_id) present  no ─▶ UNKNOWN_CANDIDATE  (retriable)
//!         │  txid / user_sig_hash / input / sighash ▶ REJECTED(WRONG_*)
//!         │  verify partial vs expected pubkey  no ─▶ REJECTED(BAD_PARTIAL_SIG)
//!         │  store (≤1 per (input,signer), no evict) ▶ ACCEPTED
//!         │
//!         └── "request" ─▶ Ingested::Request — handed to the NODE, which re-runs
//!               its own coord-auth + freshness + user-sig + policy gates. The
//!               channel decides nothing about it (signing-oracle prohibition).
//! ```
//!
//! # Canonical byte layout (this implementer OWNS it; v0 greenfield until v1)
//!
//! All digests are BIP340-style **tagged SHA-256**: `H_tag(x) = SHA256(SHA256(tag)
//! || SHA256(tag) || x)`. Length-prefix rule: only variable-length fields carry a
//! **u32-LE length prefix**; fixed-width numerics are written at their width **LE,
//! no prefix**; 32-byte hashes and 33-byte compressed pubkeys are raw, no prefix.
//!
//! | digest (tag)                                    | preimage fields, in order (LE; `var`=u32-len+bytes; `eps`=u32-count then each `var`) |
//! |-------------------------------------------------|-------------------------------------------------------------------------------------|
//! | channel-key  `btc-policy/channel-key/v0`        | `node_seckey[32]` (then `‖ counter:u8` on retry)                                    |
//! | manifest     `btc-policy/manifest/v0`           | `wallet_id[32]`, `protocol_version:u32`, `coordinator_auth_pubkey[33]` (ADR-0013 §4), node-count:u32, per node(by id): `node_id:u16`, `signing_pubkey[33]`, `channel_pubkey[33]`, `endpoints:eps` |
//! | endorsement  `btc-policy/channel-endorsement/v0`| `wallet_id[32]`, `manifest_hash[32]`, `node_id:u16`, `channel_pubkey[33]`, `protocol_version:u32`, `endpoints:eps` |
//! | envelope     `btc-policy/channel-envelope/v0`   | `msg_type:var`, `protocol_version:u32`, `wallet_id[32]`, `manifest_hash[32]`, `sender_node_id:u16`, `recipient_node_id:u16`, `payload_b64_bytes:var`, `nonce:var`, `timestamp:u64` |
//! | user-sig     `btc-policy/user-sig-hash/v0`      | per input in order: `user_der_sig:var`, `sighash_type:u8`                            |
//!
//! Byte conventions: pubkeys 33-byte compressed raw in preimages (hex in JSON);
//! hashes 32-byte raw in preimages (lowercase hex in JSON); `nonce` 16 random
//! bytes (hex in JSON, length-prefixed raw in the envelope preimage). The
//! **`payload_b64` field is signed as its raw ASCII bytes, un-decoded** — identity
//! before payload parsing: the node verifies the envelope, THEN base64-decodes.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::io::Read;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use bitcoin::hashes::Hash;
use bitcoin::hex::{DisplayHex, FromHex};
use bitcoin::secp256k1::{ecdsa::Signature, Message, Secp256k1, SecretKey};
use bitcoin::sighash::SighashCache;
use bitcoin::{ecdsa, EcdsaSighashType, Psbt, PublicKey, ScriptBuf, Transaction, Txid};
use bytes::Bytes;
use miniscript::psbt::PsbtExt;
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;
use zeroize::{Zeroize, Zeroizing};
// The channel's digest and length-prefix primitives live in vault-proto and are
// shared with the coordinator-request preimage, so the two provably cannot drift.
use vault_proto::{push_var, tagged_hash, TaggedRequest, MAX_PIN_BYTES};

use crate::replay::MAX_COORD_NONCE_BYTES;
use crate::watchtower::{AlertQueue, FreshnessEvent, FreshnessKind};
use crate::Error;

/// The pinned wire/protocol version for v0 (ADR-0013 §4 `BaseManifest`). The
/// minimal in-memory manifest sets it here and the envelope check compares
/// against it — a named const, never a magic literal. V0-9 carries it forward.
pub const PROTOCOL_VERSION_V0: u32 = 0;

/// Domain-separation tags (fixed consts — every digest names its tag so
/// independent derivations agree; codex audit 2026-07-16).
const CHANNEL_KEY_TAG: &str = "btc-policy/channel-key/v0";
const MANIFEST_TAG: &str = "btc-policy/manifest/v0";
const ENDORSEMENT_TAG: &str = "btc-policy/channel-endorsement/v0";
const ENVELOPE_TAG: &str = "btc-policy/channel-envelope/v0";
const USER_SIG_HASH_TAG: &str = "btc-policy/user-sig-hash/v0";

/// Freshness window (decided 2026-07-16): accept `timestamp ∈ [now-300, now+60]`.
/// 5 min past tolerance is for v1 Tor latency + retries + skew; 60 s future is
/// skew only. Hygiene, not safety — every planned msg_type is recipient-bound +
/// idempotent — so these are `const`s, NOT config (a hygiene knob, not a ceremony
/// knob). Nodes never exchange or negotiate time.
const FRESHNESS_PAST_SECS: u64 = 300;
const FRESHNESS_FUTURE_SECS: u64 = 60;

/// How long past its own combine window a node keeps polling a hot spend's
/// settlement (§1 post-window recognition). Bounds what would otherwise be a
/// 1 Hz settlement poll running until commitment expiry (up to
/// `max_commitment_age_secs`, hours) for a candidate that missed its window.
///
/// A peer can only broadcast inside ITS combine window `[peer_fire, peer_fire +
/// combine_slack]`. Every node fixes `fire = first_seen + hold`, and freshness
/// pins each node's `first_seen` to `[coord_ts - FRESHNESS_FUTURE, coord_ts +
/// FRESHNESS_PAST]`, so the widest any peer's window can trail this node's is
/// `FRESHNESS_PAST + FRESHNESS_FUTURE`. Past `deadline + this`, no peer's window
/// is still open, so no peer can newly settle the spend; if it has not settled by
/// then it never will over the channel, and the pending Hold's guaranteed
/// backstop is its commitment-expiry prune. Polling further only loads the
/// backend and can starve a fresh quorum-ready candidate on the same pass.
const SETTLEMENT_OBSERVE_GRACE_SECS: u64 = FRESHNESS_PAST_SECS + FRESHNESS_FUTURE_SECS;

/// Per-peer quota window; `per_peer_quota_per_min` envelopes are allowed per this
/// many seconds, keyed by authenticated `sender_node_id`.
const QUOTA_WINDOW_SECS: u64 = 60;

/// A canonical secp256k1 ECDSA DER signature is at most 72 bytes. A serialized
/// PSBT partial-signature entry adds 37 fixed bytes around it: compact-size key
/// length (1), key type (1), compressed pubkey (33), compact-size value length
/// (1), and the sighash-type byte (1). Candidates reserve these maxima at
/// registration because §5 forbids rejecting a verified partial for capacity.
const MAX_ECDSA_DER_BYTES: usize = 72;
const PSBT_PARTIAL_SIG_FIXED_BYTES: usize = 37;

// --- `[channel]` config (ADR-0013 §5; OPTIONAL block — absent ⇒ absent-channel
//     mode, /channel not mounted, no invariants run). Every field has a default,
//     so a minimal `[channel]` block is valid.

/// The optional `[channel]` config block. Present ⇒ every manifest/bijection/
/// endorsement invariant runs and `/channel` is mounted.
#[derive(Debug, Deserialize)]
pub struct ChannelConfig {
    /// This node's id (its 0-based position in the descriptor's canonical node-key
    /// order — validated against the manifest at startup).
    pub node_id: u16,
    /// FULL membership: all `n` entries INCLUDING self (the manifest hash needs
    /// all `n`; self-inclusion removes the "does peers contain me?" ambiguity).
    pub nodes: Vec<ChannelNodeConfig>,
    #[serde(default = "default_max_active_candidates")]
    pub max_active_candidates: usize,
    #[serde(default = "default_max_candidate_store_bytes")]
    pub max_candidate_store_bytes: usize,
    #[serde(default = "default_per_peer_quota_per_min")]
    pub per_peer_quota_per_min: u64,
    #[serde(default = "default_max_concurrent_channel_requests")]
    pub max_concurrent_channel_requests: usize,
    #[serde(default = "default_max_msg_bytes")]
    pub max_msg_bytes: usize,
    #[serde(default = "default_max_response_bytes")]
    pub max_response_bytes: usize,
    #[serde(default = "default_per_send_deadline_secs")]
    pub per_send_deadline_secs: u64,
    /// When present, the computed provisional `manifest_hash` MUST equal it — the
    /// node is sealed to a specific manifest (ADR-0013 trust-root posture).
    #[serde(default)]
    pub expected_manifest_hash: Option<String>,
}

/// One membership entry. `endpoints` is PLURAL (a node may advertise clearnet +
/// onion) and matches the endorsement/manifest `transport_endpoints` byte-for-byte.
/// `channel_pubkey` is REQUIRED on every entry.
#[derive(Debug, Deserialize)]
pub struct ChannelNodeConfig {
    pub node_id: u16,
    pub signing_pubkey: String,
    pub channel_pubkey: String,
    pub channel_endorsement: String,
    pub endpoints: Vec<String>,
}

fn default_max_active_candidates() -> usize {
    1024
}
fn default_max_candidate_store_bytes() -> usize {
    67_108_864
}
fn default_per_peer_quota_per_min() -> u64 {
    600
}
fn default_max_concurrent_channel_requests() -> usize {
    64
}
fn default_max_msg_bytes() -> usize {
    1_048_576
}
fn default_max_response_bytes() -> usize {
    65_536
}
fn default_per_send_deadline_secs() -> u64 {
    5
}

/// The subset of resource limits the running node consults after load.
/// `max_response_bytes`/`per_send_deadline_secs` bound the OUTBOUND path, which
/// has no production caller in V0-8a (V0-8b wires it) — read only by tests here.
#[allow(dead_code)]
struct ChannelLimits {
    per_peer_quota_per_min: u64,
    max_msg_bytes: usize,
    max_response_bytes: usize,
    per_send_deadline_secs: u64,
}

// --- canonical byte encoder -------------------------------------------------

/// The one shared canonicalizer. `var` = u32-LE length prefix + bytes;
/// `endpoints` = u32-LE count then each string as `var`; fixed numerics LE, no
/// prefix; fixed byte slices raw, no prefix.
struct Enc(Vec<u8>);

impl Enc {
    fn new() -> Enc {
        Enc(Vec::new())
    }
    fn with_capacity(capacity: usize) -> Enc {
        Enc(Vec::with_capacity(capacity))
    }
    fn fixed(&mut self, b: &[u8]) -> &mut Enc {
        self.0.extend_from_slice(b);
        self
    }
    fn u16(&mut self, v: u16) -> &mut Enc {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    fn u32(&mut self, v: u32) -> &mut Enc {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    fn u64(&mut self, v: u64) -> &mut Enc {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    fn u8(&mut self, v: u8) -> &mut Enc {
        self.0.push(v);
        self
    }
    fn var(&mut self, b: &[u8]) -> &mut Enc {
        push_var(&mut self.0, b);
        self
    }
    fn endpoints(&mut self, eps: &[String]) -> &mut Enc {
        self.u32(eps.len() as u32);
        for ep in eps {
            self.var(ep.as_bytes());
        }
        self
    }
}

// Used by the outbound envelope/payload builders (no production caller in V0-8a).
#[allow(dead_code)]
fn to_hex(b: &[u8]) -> String {
    b.to_lower_hex_string()
}
fn from_hex_vec(s: &str) -> Result<Vec<u8>, Error> {
    Ok(Vec::<u8>::from_hex(s).map_err(|e| format!("bad hex: {e}"))?)
}
fn from_hex_32(s: &str) -> Result<[u8; 32], Error> {
    from_hex_vec(s)?
        .try_into()
        .map_err(|_| "expected 32 bytes".into())
}
fn from_hex_16(s: &str) -> Result<[u8; 16], Error> {
    from_hex_vec(s)?
        .try_into()
        .map_err(|_| "expected 16 bytes".into())
}

/// Unix seconds by the local clock; before-epoch is impossible in practice and
/// reads 0 (fails safe — every real envelope then reads far in the past).
pub(crate) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[allow(dead_code)] // nonce source for the outbound envelope builder (V0-8b caller)
fn random_bytes<const N: usize>() -> Result<[u8; N], Error> {
    let mut buf = [0u8; N];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .map_err(|e| format!("read /dev/urandom: {e}"))?;
    Ok(buf)
}

// --- channel identity (ADR-0012) --------------------------------------------

/// Derive the RAM-only channel secret key from the node's signing key material:
/// `tagged_hash("btc-policy/channel-key/v0", node_seckey)` as a big-endian scalar.
/// Deterministic retry (codex audit): if the digest is zero or ≥ the curve order,
/// re-hash `tagged_hash(tag, node_seckey ‖ counter:u8)` with `counter` from 0 up
/// (a retry has probability ~2^-128; the loop is for total determinism). Never
/// persisted — derived at startup so the setup-time endorsement and the runtime
/// key always agree, and distinct from the signing key.
pub(crate) fn derive_channel_seckey(node_seckey: &SecretKey) -> SecretKey {
    let sk = node_seckey.secret_bytes();
    if let Ok(k) = SecretKey::from_slice(&tagged_hash(CHANNEL_KEY_TAG, &sk)) {
        return k;
    }
    let mut counter: u8 = 0;
    loop {
        let mut input = Vec::with_capacity(33);
        input.extend_from_slice(&sk);
        input.push(counter);
        if let Ok(k) = SecretKey::from_slice(&tagged_hash(CHANNEL_KEY_TAG, &input)) {
            return k;
        }
        counter = counter
            .checked_add(1)
            .expect("channel-key derivation exhausted the u8 retry counter (unreachable: p<2^-128 per step)");
    }
}

pub(crate) fn channel_pubkey_of(sk: &SecretKey) -> PublicKey {
    PublicKey::new(sk.public_key(&Secp256k1::signing_only()))
}

// --- manifest + endorsement preimages ---------------------------------------

/// One membership entry after parsing/validation; indexed by `node_id`.
#[derive(Clone)]
struct ManifestNode {
    node_id: u16,
    signing_pubkey: PublicKey,
    channel_pubkey: PublicKey,
    endpoints: Vec<String>,
}

/// Canonical bytes of the provisional, endorsement-FREE BaseManifest slice
/// (ADR-0013 §4). It still carries V0-8a's limited fields rather than the complete
/// §4 schema: `wallet_id` transitively binds the descriptor, while
/// `policy_version`, `hot_allowlist`, and `escape_descriptor` are not yet explicit
/// preimage fields. Within this minimal V0-9 slice, `channel_pubkey` IS in the
/// hashed structure (deterministic, known at setup), and
/// `coordinator_auth_pubkey` is hashed in right after `protocol_version` as its 33
/// compressed bytes. Every vault is sealed to exactly one coordinator, so changing
/// that key changes `manifest_hash`, i.e. it is a new vault (§7). `nodes` MUST be
/// sorted by `node_id`.
fn base_manifest_bytes(
    wallet_id: &[u8; 32],
    protocol_version: u32,
    coordinator_auth_pubkey: &PublicKey,
    nodes: &[ManifestNode],
) -> Vec<u8> {
    let mut e = Enc::new();
    e.fixed(wallet_id);
    e.u32(protocol_version);
    e.fixed(&coordinator_auth_pubkey.inner.serialize());
    e.u32(nodes.len() as u32);
    for n in nodes {
        e.u16(n.node_id);
        e.fixed(&n.signing_pubkey.inner.serialize());
        e.fixed(&n.channel_pubkey.inner.serialize());
        e.endpoints(&n.endpoints);
    }
    e.0
}

fn compute_manifest_hash(
    wallet_id: &[u8; 32],
    protocol_version: u32,
    coordinator_auth_pubkey: &PublicKey,
    nodes: &[ManifestNode],
) -> [u8; 32] {
    tagged_hash(
        MANIFEST_TAG,
        &base_manifest_bytes(wallet_id, protocol_version, coordinator_auth_pubkey, nodes),
    )
}

/// Canonical bytes of the channel-key endorsement domain (§1): `(wallet_id,
/// manifest_hash, node_id, channel_pubkey, protocol_version, transport_endpoints)`.
fn endorsement_bytes(
    wallet_id: &[u8; 32],
    manifest_hash: &[u8; 32],
    node_id: u16,
    channel_pubkey: &PublicKey,
    protocol_version: u32,
    endpoints: &[String],
) -> Vec<u8> {
    let mut e = Enc::new();
    e.fixed(wallet_id);
    e.fixed(manifest_hash);
    e.u16(node_id);
    e.fixed(&channel_pubkey.inner.serialize());
    e.u32(protocol_version);
    e.endpoints(endpoints);
    e.0
}

fn endorsement_digest(
    wallet_id: &[u8; 32],
    manifest_hash: &[u8; 32],
    node_id: u16,
    channel_pubkey: &PublicKey,
    protocol_version: u32,
    endpoints: &[String],
) -> [u8; 32] {
    tagged_hash(
        ENDORSEMENT_TAG,
        &endorsement_bytes(
            wallet_id,
            manifest_hash,
            node_id,
            channel_pubkey,
            protocol_version,
            endpoints,
        ),
    )
}

/// Canonical envelope signature preimage (§3). `payload_b64` is signed as its raw
/// ASCII bytes, un-decoded.
#[allow(clippy::too_many_arguments)]
fn envelope_preimage(
    msg_type: &str,
    protocol_version: u32,
    wallet_id: &[u8; 32],
    manifest_hash: &[u8; 32],
    sender_node_id: u16,
    recipient_node_id: u16,
    payload_b64: &[u8],
    nonce: &[u8],
    timestamp: u64,
) -> Zeroizing<Vec<u8>> {
    // Three u32 length prefixes, the fixed-width fields, and every variable
    // field. Reserve the complete allocation before copying `payload_b64`, which
    // reversibly contains the PIN, so Vec growth cannot leave a freed plaintext
    // copy behind that the final `Zeroizing` allocation would not wipe.
    const FIXED_BYTES: usize = 3 * 4 + 4 + 2 * 32 + 2 * 2 + 8;
    let capacity = FIXED_BYTES
        .saturating_add(msg_type.len())
        .saturating_add(payload_b64.len())
        .saturating_add(nonce.len());
    let mut e = Enc::with_capacity(capacity);
    let allocation = e.0.as_ptr();
    e.var(msg_type.as_bytes());
    e.u32(protocol_version);
    e.fixed(wallet_id);
    e.fixed(manifest_hash);
    e.u16(sender_node_id);
    e.u16(recipient_node_id);
    e.var(payload_b64);
    e.var(nonce);
    e.u64(timestamp);
    debug_assert_eq!(
        e.0.as_ptr(),
        allocation,
        "secret envelope preimage must not reallocate"
    );
    Zeroizing::new(e.0)
}

fn validate_endpoint(ep: &str) -> Result<SocketAddr, Error> {
    let addr = SocketAddr::from_str(ep).map_err(|e| format!("not a canonical host:port: {e}"))?;
    if ep != addr.to_string() {
        return Err(format!("endpoint {ep:?} is not canonical (expected {addr})").into());
    }
    Ok(addr)
}

// --- wire types -------------------------------------------------------------

/// One channel message. Every field is signed by `channel_sig` (over the
/// [`envelope_preimage`]); hashes/pubkeys are lowercase hex in JSON, raw in the
/// preimage.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Envelope {
    pub(crate) msg_type: String,
    pub(crate) protocol_version: u32,
    pub(crate) wallet_id: String,
    pub(crate) manifest_hash: String,
    pub(crate) sender_node_id: u16,
    pub(crate) recipient_node_id: u16,
    /// Opaque payload bytes encoded for transport. A request payload contains the
    /// plaintext PIN reversibly encoded, so every clone and deserialize-error
    /// intermediate must wipe this allocation on drop.
    pub(crate) payload_b64: Zeroizing<String>,
    pub(crate) nonce: String,
    pub(crate) timestamp: u64,
    pub(crate) channel_sig: String,
}

impl fmt::Debug for Envelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Envelope")
            .field("msg_type", &self.msg_type)
            .field("protocol_version", &self.protocol_version)
            .field("wallet_id", &self.wallet_id)
            .field("manifest_hash", &self.manifest_hash)
            .field("sender_node_id", &self.sender_node_id)
            .field("recipient_node_id", &self.recipient_node_id)
            .field("payload_b64", &"<redacted>")
            .field("nonce", &self.nonce)
            .field("timestamp", &self.timestamp)
            .field("channel_sig", &self.channel_sig)
            .finish()
    }
}

/// The `partial` payload (opaque base64 until the envelope authenticates).
/// `protocol_version` lives on the envelope, not here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PartialPayload {
    pub(crate) commitment_id: String,
    pub(crate) wallet_id: String,
    pub(crate) txid: String,
    pub(crate) input: u32,
    pub(crate) signer_node_id: u16,
    pub(crate) sighash_type: u32,
    pub(crate) spend_purpose: String,
    pub(crate) user_sig_hash: String,
    pub(crate) partial_sig: String,
}

impl PartialPayload {
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("PartialPayload is always serializable")
    }
}

/// What the partial-release gate hands back when a candidate fires (§1): this
/// node's own partials, and how long the fan-out may keep retrying.
pub(crate) struct Release {
    /// One payload per input this node signed.
    pub(crate) payloads: Vec<PartialPayload>,
    /// Last instant the combine window is open; the retry loop stops there rather
    /// than at the commitment expiry, so a fan-out cannot outlive its window.
    pub(crate) deadline: u64,
}

/// The `request` message type (§3): the coordinator-signed tagged request,
/// relayed VERBATIM between nodes.
///
/// This does not make a peer an authority — the signing-oracle prohibition still
/// holds absolutely. The peer is pure transport: authority comes from the
/// COORDINATOR's signature over the canonical request bytes, and the receiving
/// node independently re-runs its own coord-auth + freshness + user-signature +
/// policy gates before anything is registered or signed (ADR-0012). A peer that
/// tampers with a byte simply produces a request whose `coord_sig` no longer
/// verifies, and a rogue node cannot manufacture one at all.
///
/// Why it exists: it makes delivery to ONE node enough. A post-wrench coordinator
/// that selectively delivers cannot leave part of the federation unaware — which
/// is what V0-4b needs so a duress request that reaches one node arms the rest.
pub(crate) const MSG_TYPE_REQUEST: &str = "request";

/// The `partial` message type: one verified partial signature for a registered
/// candidate.
pub(crate) const MSG_TYPE_PARTIAL: &str = "partial";

/// What [`ChannelState::ingest`] resolved a body to.
pub(crate) enum Ingested {
    /// The channel handled it end to end (a `partial`, or any rejection).
    Reply(ChannelReply),
    /// An authenticated `request` envelope. The channel layer deliberately does
    /// NOT process it: it carries policy, and the channel carries signatures and
    /// assembly only. The node applies its own gates (see
    /// [`crate::handle_channel_body`]).
    Request(Box<TaggedRequest>),
}

/// One rejection exit, as an [`Ingested`].
fn reject(reason: RejectReason) -> Ingested {
    Ingested::Reply(ChannelReply::Rejected(reason))
}

/// The setup ceremony's half of the channel manifest (ADR-0013 §4).
///
/// Setup is a distinct role from the node — it collects every node's keys,
/// assembles the manifest, computes `manifest_hash`, and provisions each node with
/// it — but it must compute those bytes **identically** to every node, or the
/// federation it provisions cannot boot. Re-deriving the preimages in the setup
/// tool would make "identical" a coincidence that no test on either side could
/// catch. So the ceremony calls the node's own definitions, here.
///
/// v0 only: the regtest demo is the ceremony. The real ceremony (sealed hosts, no
/// machine holding two node keys) is later work, and it will call these same
/// functions for the same reason.
pub mod ceremony {
    use super::{
        channel_pubkey_of, compute_manifest_hash, derive_channel_seckey, endorsement_digest,
        ManifestNode, PROTOCOL_VERSION_V0,
    };
    use bitcoin::hex::DisplayHex;
    use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
    use bitcoin::PublicKey;

    /// One node as the ceremony knows it, before the manifest exists.
    pub struct CeremonyNode {
        /// Its 0-based position in the descriptor's canonical node-key order (§1).
        pub node_id: u16,
        pub signing_pubkey: PublicKey,
        pub endpoints: Vec<String>,
    }

    /// The channel pubkey a node will derive at startup from its signing key. The
    /// ceremony must publish this in the manifest, and the node re-derives it and
    /// refuses to boot on a mismatch.
    pub fn channel_pubkey(node_seckey: &SecretKey) -> PublicKey {
        channel_pubkey_of(&derive_channel_seckey(node_seckey))
    }

    /// `manifest_hash` over the assembled membership (§4). `nodes` must be sorted
    /// by `node_id`; every entry's `channel_pubkey` comes from [`channel_pubkey`].
    pub fn manifest_hash(
        wallet_id: &[u8; 32],
        coordinator_auth_pubkey: &PublicKey,
        nodes: &[CeremonyNode],
        channel_pubkeys: &[PublicKey],
    ) -> [u8; 32] {
        let manifest = manifest_nodes(nodes, channel_pubkeys);
        compute_manifest_hash(
            wallet_id,
            PROTOCOL_VERSION_V0,
            coordinator_auth_pubkey,
            &manifest,
        )
    }

    /// One node's channel-key endorsement, as lowercase-hex DER: that node's
    /// **Bitcoin signing key** vouching for its channel key over the
    /// domain-separated `(wallet_id, manifest_hash, node_id, channel_pubkey,
    /// protocol_version, endpoints)`. Peers accept a channel identity only because
    /// a key already in the federation signed for it, which is what stops the
    /// coordinator minting a node.
    pub fn endorse(
        node_seckey: &SecretKey,
        wallet_id: &[u8; 32],
        manifest_hash: &[u8; 32],
        node_id: u16,
        endpoints: &[String],
    ) -> String {
        let digest = endorsement_digest(
            wallet_id,
            manifest_hash,
            node_id,
            &channel_pubkey(node_seckey),
            PROTOCOL_VERSION_V0,
            endpoints,
        );
        Secp256k1::new()
            .sign_ecdsa(&Message::from_digest(digest), node_seckey)
            .serialize_der()
            .to_lower_hex_string()
    }

    fn manifest_nodes(nodes: &[CeremonyNode], channel_pubkeys: &[PublicKey]) -> Vec<ManifestNode> {
        nodes
            .iter()
            .zip(channel_pubkeys)
            .map(|(node, channel_pubkey)| ManifestNode {
                node_id: node.node_id,
                signing_pubkey: node.signing_pubkey,
                channel_pubkey: *channel_pubkey,
                endpoints: node.endpoints.clone(),
            })
            .collect()
    }
}

// --- response schema (§5b) --------------------------------------------------

/// Fixed, frozen `REJECTED` reason codes (§5b + module table). SCREAMING_SNAKE on
/// the wire; permanent — the sender does NOT retry a `REJECTED`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RejectReason {
    MalformedJson,
    OversizedBody,
    BadProtocolVersion,
    WrongWallet,
    WrongManifest,
    WrongRecipient,
    UnknownSender,
    BadChannelSig,
    StaleTimestamp,
    ReplayedNonce,
    MalformedPayload,
    UnknownMsgType,
    PayloadWalletMismatch,
    SignerMismatch,
    WrongTxid,
    WrongUserSigHash,
    WrongInput,
    WrongSighashType,
    BadPartialSig,
}

impl RejectReason {
    pub(crate) fn code(self) -> &'static str {
        match self {
            RejectReason::MalformedJson => "MALFORMED_JSON",
            RejectReason::OversizedBody => "OVERSIZED_BODY",
            RejectReason::BadProtocolVersion => "BAD_PROTOCOL_VERSION",
            RejectReason::WrongWallet => "WRONG_WALLET",
            RejectReason::WrongManifest => "WRONG_MANIFEST",
            RejectReason::WrongRecipient => "WRONG_RECIPIENT",
            RejectReason::UnknownSender => "UNKNOWN_SENDER",
            RejectReason::BadChannelSig => "BAD_CHANNEL_SIG",
            RejectReason::StaleTimestamp => "STALE_TIMESTAMP",
            RejectReason::ReplayedNonce => "REPLAYED_NONCE",
            RejectReason::MalformedPayload => "MALFORMED_PAYLOAD",
            RejectReason::UnknownMsgType => "UNKNOWN_MSG_TYPE",
            RejectReason::PayloadWalletMismatch => "PAYLOAD_WALLET_MISMATCH",
            RejectReason::SignerMismatch => "SIGNER_MISMATCH",
            RejectReason::WrongTxid => "WRONG_TXID",
            RejectReason::WrongUserSigHash => "WRONG_USER_SIG_HASH",
            RejectReason::WrongInput => "WRONG_INPUT",
            RejectReason::WrongSighashType => "WRONG_SIGHASH_TYPE",
            RejectReason::BadPartialSig => "BAD_PARTIAL_SIG",
        }
    }
}

/// The four `/channel` outcomes (§5b), each with a fixed HTTP status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ChannelReply {
    /// 200 — envelope verified and the partial stored (or an idempotent re-store).
    Accepted,
    /// 400 — permanent, do NOT retry.
    Rejected(RejectReason),
    /// 409 — envelope valid but the commitment is not (yet) a registered candidate.
    UnknownCandidate,
    /// 429 — per-peer quota or the pre-auth concurrency bound was hit.
    RateLimited { retry_after_secs: u64 },
}

impl ChannelReply {
    /// The fixed `(HTTP status, JSON body)` this reply maps to.
    pub(crate) fn http(&self) -> (u16, String) {
        match self {
            ChannelReply::Accepted => (200, r#"{"status":"ACCEPTED"}"#.to_string()),
            ChannelReply::Rejected(reason) => (
                400,
                format!(r#"{{"status":"REJECTED","reason":"{}"}}"#, reason.code()),
            ),
            ChannelReply::UnknownCandidate => {
                (409, r#"{"status":"UNKNOWN_CANDIDATE"}"#.to_string())
            }
            ChannelReply::RateLimited { retry_after_secs } => (
                429,
                format!(r#"{{"status":"RATE_LIMITED","retry_after_secs":{retry_after_secs}}}"#),
            ),
        }
    }
}

// --- candidate registry (§4/§5) ---------------------------------------------

/// The outcome of a registry insertion (§5 hard capacity cap).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RegisterOutcome {
    Inserted,
    /// The commitment was already a live candidate (idempotent).
    AlreadyPresent,
    /// The same commitment id is already bound to incompatible request state
    /// (for example, a different user-signature instance or paired escape).
    /// The resident candidate is left untouched.
    Conflict,
    /// The count or byte cap was hit — the candidate is NOT inserted, no live
    /// candidate is ever evicted, and the request must be refused before it is
    /// acknowledged (Model B has no coordinator-side fallback).
    AtCapacity,
}

/// Which transaction of a request's mandatory PAIR a candidate is (§4). Every
/// `SpendRequest` carries `{spend, escape}` and both are registered — distinct
/// exact-byte commitments, both signed at ingress — so the escape is already
/// assembled-and-waiting if V0-4b ever arms it. The role is unambiguous and
/// node-derived, never a coordinator label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateRole {
    /// The requested spend. Fires at its Hold expiry (hot-class) or immediately
    /// (escape-class).
    Spend,
    /// The request's mandatory user-signed escape. In V0-8b nothing schedules it:
    /// it is signed, registered, and inert. V0-4b's duress arm is what gives it a
    /// [`FireWindow`] (at `T`), and it then rides this exact same fire path.
    Escape,
}

/// When a candidate's partials may be released, and how long the combine may run
/// (§1). `[fire_at, deadline]` where `deadline = min(commitment_expiry, fire_at +
/// combine_slack_secs)`: outside this window nothing is released and nothing is
/// combined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FireWindow {
    /// The candidate's authorized fire event (unix seconds). Before this instant
    /// NO partial may leave this node — ADR-0012 invariant 7.
    pub(crate) fire_at: u64,
    /// Last instant the combine window is open.
    pub(crate) deadline: u64,
}

impl FireWindow {
    fn is_open(&self, now: u64) -> bool {
        now >= self.fire_at && now <= self.deadline
    }
}

/// A quorum-complete candidate plus the last instant at which this node may
/// broadcast it. Carrying the deadline with the finalized transaction lets the
/// blocking package path re-authorize immediately before `sendrawtransaction`.
pub(crate) struct FinalizedCandidate {
    pub(crate) tx: Transaction,
    pub(crate) deadline: u64,
}

/// One registered candidate — this node's OWN canonical view of a spend, so a
/// peer's partial can be verified against sighashes THIS node recomputed. Keyed
/// by `commitment_id` (the same txid can back several live commitments).
pub(crate) struct Candidate {
    commitment_id: String,
    unsigned_txid: Txid,
    /// This candidate's role in its request's mandatory pair (§4).
    role: CandidateRole,
    /// The sibling candidate's `commitment_id` — the pairing is by request, so a
    /// spend always names its escape and vice versa.
    paired_commitment_id: String,
    /// This node's canonical PSBT; verified peer partials are imported here (never
    /// blind-merged from a peer PSBT). This node's OWN partial is present from
    /// registration: Model B signs at ingress (ADR-0012).
    psbt: Psbt,
    /// Per-input sighash recomputed by THIS node.
    sighashes: Vec<[u8; 32]>,
    /// Tagged SHA-256 over the user's DER signature(s) + sighash-type byte(s), in
    /// input order, as this node verified them at ingress.
    user_sig_hash: [u8; 32],
    /// The commitment's own fixed eviction horizon (no extension in V0-8a).
    expiry: u64,
    /// This candidate's authorized fire event + combine window, or `None` when
    /// nothing has scheduled it (every [`CandidateRole::Escape`] in V0-8b). The
    /// partial-release gate reads THIS and nothing else.
    fire: Option<FireWindow>,
    /// Whether this node has already released its own partials to peers. Set once,
    /// at fire, by [`ChannelState::release_partials`] — so a re-tick re-sends
    /// nothing and the release remains a single authorized event.
    released: bool,
    /// Whether this node has already broadcast this candidate, so a re-tick does
    /// not re-broadcast. (A redundant broadcast of identical bytes is harmless —
    /// peers dedup it — but re-doing the package test every tick is waste.)
    broadcast: bool,
    /// At most one partial per `(input, signer_node_id)` (DER bytes).
    partials: HashMap<(u32, u16), Vec<u8>>,
    /// Byte accounting: stored PSBT + sighashes + user_sig_hash + partials.
    bytes: usize,
    /// Capacity charged at registration: current bytes plus the maximum growth of
    /// every descriptor partial that can arrive during this candidate's lifetime.
    /// This reservation makes the configured byte cap hard without adding a
    /// wire-time capacity rejection.
    capacity_bytes: usize,
}

/// Everything that describes ONE candidate of a request's pair, so registering
/// the spend and registering the escape are the same call with different data.
pub(crate) struct CandidateSpec<'a> {
    /// This node's own decoded PSBT for this transaction.
    pub(crate) psbt: &'a Psbt,
    /// Its exact-byte commitment id (ADR-0012 / V0-2b).
    pub(crate) commitment_id: &'a str,
    /// The sibling's commitment id (the pairing, §4).
    pub(crate) paired_commitment_id: &'a str,
    pub(crate) role: CandidateRole,
    /// The authorized fire window, or `None` for a candidate nothing schedules.
    pub(crate) fire: Option<FireWindow>,
    pub(crate) expiry: u64,
}

/// The node keys a candidate is verified and signed against.
pub(crate) struct CandidateKeys<'a> {
    pub(crate) witness_script: &'a ScriptBuf,
    pub(crate) user_pubkey: &'a PublicKey,
    /// This node's federation signing key — the one partial that is present from
    /// registration.
    pub(crate) self_signing_pubkey: &'a PublicKey,
}

impl Candidate {
    /// Build a candidate from the node's own post-verdict, ingress-SIGNED PSBT:
    /// recompute per-input sighashes and the `user_sig_hash` from the user's
    /// verified partial sigs, and **strip every partial signature the node has not
    /// verified or produced**.
    ///
    /// `verify_user_signatures` validated only the `user_pubkey` entry, so any
    /// federation `partial_sig` the coordinator planted in the request PSBT — under
    /// this node's own signing key or a peer's — is unverified. The canonical PSBT
    /// therefore keeps ONLY the verified user signature plus this node's own real
    /// signature under `self_signing_pubkey`, which Model B added at ingress before
    /// this call; peer partials enter later exclusively through the verified
    /// `accept_partial`. Without this strip a coordinator-planted signature would
    /// blind-import an unverified sig into the canonical view (§5 forbids this),
    /// pinning a forgery under this node's key that suppresses its real signature
    /// and relays as garbage every peer rejects — silently dropping the node from
    /// the combine set (a coordinator gaining power over assembly, which Model B
    /// forbids).
    ///
    /// The candidate is born fully signed and fully WITHHELD: nothing here releases
    /// a partial, and `spec.fire` alone decides when one may (ADR-0012 invariant 7).
    pub(crate) fn build(spec: CandidateSpec, keys: &CandidateKeys) -> Result<Candidate, Error> {
        let mut psbt = spec.psbt.clone();
        for input in &mut psbt.inputs {
            // Finalization metadata is coordinator input, not part of the exact
            // unsigned transaction the user signature commits to. Canonicalize the
            // P2WSH fields from this node's configured descriptor and discard any
            // pre-finalized witness/script so quorum finalization cannot preserve a
            // coordinator-supplied witness or fail because `witness_script` was
            // omitted/replaced. The verified user and node partials below are the
            // only satisfaction material retained at ingress.
            input.witness_script = Some(keys.witness_script.clone());
            input.redeem_script = None;
            input.sighash_type = Some(EcdsaSighashType::All.into());
            input.final_script_sig = None;
            input.final_script_witness = None;
            input
                .partial_sigs
                .retain(|pk, _| pk == keys.user_pubkey || pk == keys.self_signing_pubkey);
        }
        let unsigned_txid = psbt.unsigned_tx.compute_txid();
        let mut cache = SighashCache::new(&psbt.unsigned_tx);
        let mut sighashes = Vec::with_capacity(psbt.inputs.len());
        let mut usig = Enc::new();
        for (i, input) in psbt.inputs.iter().enumerate() {
            let utxo = input
                .witness_utxo
                .as_ref()
                .ok_or_else(|| format!("input {i} has no witness_utxo"))?;
            let sh = cache
                .p2wsh_signature_hash(i, keys.witness_script, utxo.value, EcdsaSighashType::All)
                .map_err(|e| format!("sighash for input {i}: {e}"))?;
            sighashes.push(sh.to_byte_array());
            let sig = input
                .partial_sigs
                .get(keys.user_pubkey)
                .ok_or_else(|| format!("input {i} missing the user partial signature"))?;
            usig.var(&sig.signature.serialize_der());
            usig.u8(sig.sighash_type.to_u32() as u8);
        }
        let user_sig_hash = tagged_hash(USER_SIG_HASH_TAG, &usig.0);
        let bytes = psbt.serialize().len() + sighashes.len() * 32 + 32;
        Ok(Candidate {
            commitment_id: spec.commitment_id.to_string(),
            unsigned_txid,
            role: spec.role,
            paired_commitment_id: spec.paired_commitment_id.to_string(),
            psbt,
            sighashes,
            user_sig_hash,
            expiry: spec.expiry,
            fire: spec.fire,
            released: false,
            broadcast: false,
            partials: HashMap::new(),
            bytes,
            capacity_bytes: bytes,
        })
    }

    /// Distinct valid federation signatures on `input`, counted over this node's
    /// canonical PSBT. Every entry got there either from this node's own ingress
    /// signing or through `accept_partial`'s verification against the recomputed
    /// sighash and the expected descriptor key, so presence IS validity.
    fn signature_count(&self, input: usize, nodes: &[ManifestNode]) -> usize {
        let Some(psbt_input) = self.psbt.inputs.get(input) else {
            return 0;
        };
        nodes
            .iter()
            .filter(|node| psbt_input.partial_sigs.contains_key(&node.signing_pubkey))
            .count()
    }

    /// Whether EVERY input carries at least `t` distinct valid federation
    /// signatures — the combine precondition (§1). Per-input, never a total: a tx
    /// with `t` signatures on input 0 and none on input 1 cannot be finalized, and
    /// a global count would call it ready.
    fn has_quorum(&self, threshold: usize, nodes: &[ManifestNode]) -> bool {
        !self.psbt.inputs.is_empty()
            && (0..self.psbt.inputs.len()).all(|i| self.signature_count(i, nodes) >= threshold)
    }

    /// Whether another registration under this commitment id describes the same
    /// combinable candidate. `fire`/release/broadcast state is deliberately absent:
    /// a later idempotent delivery must retain the resident candidate's original
    /// authorization window and monotonic release state.
    fn matches_registration(&self, other: &Candidate) -> bool {
        self.unsigned_txid == other.unsigned_txid
            && self.role == other.role
            && self.paired_commitment_id == other.paired_commitment_id
            && self.sighashes == other.sighashes
            && self.user_sig_hash == other.user_sig_hash
            && self.expiry == other.expiry
    }

    /// Reserve all future descriptor-signature growth. Peer signatures need one
    /// canonical DER copy in `partials` plus their PSBT entry; this node's own
    /// signature can be added by a later Signed verdict and needs only its PSBT
    /// entry. Existing PSBT entries reserve only their possible growth to the
    /// canonical maximum.
    fn reserve_partial_capacity(&mut self, nodes: &[ManifestNode], self_node_id: u16) {
        let mut capacity = self.bytes;
        for input in &self.psbt.inputs {
            for node in nodes {
                let existing_entry_bytes = input
                    .partial_sigs
                    .get(&node.signing_pubkey)
                    .map(|sig| PSBT_PARTIAL_SIG_FIXED_BYTES + sig.signature.serialize_der().len())
                    .unwrap_or(0);
                capacity = capacity.saturating_add(
                    (PSBT_PARTIAL_SIG_FIXED_BYTES + MAX_ECDSA_DER_BYTES)
                        .saturating_sub(existing_entry_bytes),
                );
                if node.node_id != self_node_id {
                    capacity = capacity.saturating_add(MAX_ECDSA_DER_BYTES);
                }
            }
        }
        self.capacity_bytes = capacity;
    }
}

/// Verified fields of a parsed `partial` payload, ready for the store.
struct ParsedPartial<'a> {
    commitment_id: &'a str,
    txid: Txid,
    user_sig_hash: [u8; 32],
    input: u32,
    signer: u16,
    der: &'a [u8],
}

/// The candidate registry: `commitment_id -> Candidate`, with a hard count + byte
/// cap. No generic FIFO/LRU eviction — a compromised peer must not be able to
/// evict quorum-useful partials; only commitment expiry evicts.
pub(crate) struct PartialStore {
    candidates: HashMap<String, Candidate>,
    /// Worst-case candidate bytes charged at insertion, including reserved future
    /// signature growth. Actual bytes are tracked per `Candidate`.
    reserved_bytes: usize,
    max_active_candidates: usize,
    max_bytes: usize,
}

impl PartialStore {
    /// Register `c` unless the store is at capacity. No live candidate is evicted;
    /// the request-level caller preflights the complete candidate set so this
    /// single-candidate path is used only by focused registry tests.
    ///
    /// A compatible commitment that is already live is left EXACTLY as it is. It
    /// is already fully signed (Model B signs at ingress) and may already hold peer
    /// partials and a fire decision, so overwriting or merging would create ways to
    /// reset `released`/`fire` — i.e. to re-open the partial-release gate after fire.
    /// A same-id registration with a different user-signature instance, sighash, or
    /// paired candidate is a conflict, not idempotency: commitment ids deliberately
    /// bind unsigned transaction bytes, while those request fields live alongside.
    fn register(&mut self, c: Candidate) -> RegisterOutcome {
        if let Some(resident) = self.candidates.get(&c.commitment_id) {
            return if resident.matches_registration(&c) {
                RegisterOutcome::AlreadyPresent
            } else {
                RegisterOutcome::Conflict
            };
        }
        if self.candidates.len() >= self.max_active_candidates
            || self.reserved_bytes.saturating_add(c.capacity_bytes) > self.max_bytes
        {
            return RegisterOutcome::AtCapacity;
        }
        self.reserved_bytes = self.reserved_bytes.saturating_add(c.capacity_bytes);
        self.candidates.insert(c.commitment_id.clone(), c);
        RegisterOutcome::Inserted
    }

    /// Evict every candidate whose commitment expiry is strictly in the past.
    /// Fire windows are inclusive at their deadline, so a candidate remains live
    /// at `now == expiry` for that final authorized second.
    fn prune(&mut self, now: u64) {
        let mut removed = 0usize;
        self.candidates.retain(|_, c| {
            if c.expiry >= now {
                true
            } else {
                removed = removed.saturating_add(c.capacity_bytes);
                false
            }
        });
        self.reserved_bytes = self.reserved_bytes.saturating_sub(removed);
    }

    /// Verify and store a partial against the registered candidate. Enforced at
    /// lookup: an expired candidate is evicted and answered `UnknownCandidate`
    /// (retriable) even with no intervening `/sign` sweep. The expiry boundary is
    /// the SAME one `prune` uses (`expiry < now` is expired, `now == expiry` is the
    /// final authorized second): `FireWindow` is inclusive at its deadline and the
    /// deadline can equal `expiry`, so `broadcast_package` may still push a spend at
    /// `now == expiry`. Evicting on `<= now` here would drop the candidate — and its
    /// quorum-completing partial — in exactly that second, defeating a broadcast the
    /// fire path still intends. Both consumers therefore expire on `< now`.
    fn accept_partial(
        &mut self,
        p: &ParsedPartial,
        nodes: &[ManifestNode],
        now: u64,
    ) -> ChannelReply {
        let expired = match self.candidates.get(p.commitment_id) {
            Some(c) => c.expiry < now,
            None => return ChannelReply::UnknownCandidate,
        };
        if expired {
            let bytes = self
                .candidates
                .remove(p.commitment_id)
                .map(|c| c.capacity_bytes)
                .unwrap_or(0);
            self.reserved_bytes = self.reserved_bytes.saturating_sub(bytes);
            return ChannelReply::UnknownCandidate;
        }
        let c = self.candidates.get_mut(p.commitment_id).expect("present");
        if p.txid != c.unsigned_txid {
            return ChannelReply::Rejected(RejectReason::WrongTxid);
        }
        if p.user_sig_hash != c.user_sig_hash {
            return ChannelReply::Rejected(RejectReason::WrongUserSigHash);
        }
        if (p.input as usize) >= c.sighashes.len() {
            return ChannelReply::Rejected(RejectReason::WrongInput);
        }
        let expected = nodes[p.signer as usize].signing_pubkey;
        let sig = match Signature::from_der(p.der) {
            Ok(s) => s,
            Err(_) => return ChannelReply::Rejected(RejectReason::BadPartialSig),
        };
        let sighash = c.sighashes[p.input as usize];
        if Secp256k1::verification_only()
            .verify_ecdsa(&Message::from_digest(sighash), &sig, &expected.inner)
            .is_err()
        {
            return ChannelReply::Rejected(RejectReason::BadPartialSig);
        }
        // Store: ≤1 per (input, signer); a re-delivery (same or different) is an
        // idempotent no-op that never evicts the first verified partial.
        let key = (p.input, p.signer);
        if c.partials.contains_key(&key) {
            return ChannelReply::Accepted;
        }
        let canonical_der = sig.serialize_der();
        let old_psbt_bytes = c.psbt.serialize().len();
        c.partials.insert(key, canonical_der.to_vec());
        c.psbt.inputs[p.input as usize].partial_sigs.insert(
            expected,
            ecdsa::Signature {
                signature: sig,
                sighash_type: EcdsaSighashType::All,
            },
        );
        let new_psbt_bytes = c.psbt.serialize().len();
        c.bytes = c
            .bytes
            .saturating_sub(old_psbt_bytes)
            .saturating_add(new_psbt_bytes)
            .saturating_add(canonical_der.len());
        // `reserved_bytes` is charged at registration, so no wire-time
        // growth is charged here. The actual canonical bytes must fit that reserve.
        debug_assert!(c.bytes <= c.capacity_bytes);
        ChannelReply::Accepted
    }
}

// --- the running channel state ----------------------------------------------

/// Per-peer rolling-window quota accounting. Accepted charges are retained for
/// exactly one quota window, so a peer cannot take two full fixed-window bursts
/// across a reset boundary. The deque is structurally bounded by the configured
/// per-peer quota.
struct PeerQuota {
    charged_at: VecDeque<u64>,
}

/// Post-auth state whose decision must be atomic. The monotonic high-water mark,
/// timestamp-keyed nonce pruning, replay check, quota charge, and nonce insertion
/// share one lock: no request can use a stale `now` after another request advances
/// the clock and prunes. The quota is charged for EVERY authenticated envelope,
/// including stale and replayed ones, so captures cannot bypass the peer's rate
/// bound or amplify freshness-event queue work. Forged traffic cannot charge a
/// peer because this runs only after the channel signature verifies. The nonce is
/// consumed only for an accepted envelope, before it is dispatched.
#[derive(Default)]
struct IngressGuards {
    high_water: u64,
    seen_nonces: HashMap<(u16, [u8; 16]), u64>,
    quotas: HashMap<u16, PeerQuota>,
}

enum IngressGuardResult {
    Accepted { now: u64 },
    Stale { now: u64 },
    Replayed,
    RateLimited { retry_after_secs: u64 },
}

impl IngressGuards {
    /// Charge one authenticated envelope to `sender`'s quota. Called on every
    /// freshness/replay outcome so a captured signed envelope cannot bypass the
    /// post-auth rate bound. Returns `Some` only when the request is over quota.
    fn charge_quota(
        &mut self,
        sender: u16,
        now: u64,
        quota_per_min: u64,
    ) -> Option<IngressGuardResult> {
        let quota = self.quotas.entry(sender).or_insert(PeerQuota {
            charged_at: VecDeque::new(),
        });
        let horizon = now.saturating_sub(QUOTA_WINDOW_SECS);
        while quota
            .charged_at
            .front()
            .is_some_and(|charged| *charged <= horizon)
        {
            quota.charged_at.pop_front();
        }
        if (quota.charged_at.len() as u64) < quota_per_min {
            quota.charged_at.push_back(now);
            return None;
        }
        let retry_after_secs = quota
            .charged_at
            .front()
            .map(|oldest| {
                oldest
                    .saturating_add(QUOTA_WINDOW_SECS)
                    .saturating_sub(now)
                    .max(1)
            })
            .unwrap_or(QUOTA_WINDOW_SECS);
        Some(IngressGuardResult::RateLimited { retry_after_secs })
    }

    /// Apply every post-auth hygiene guard in one critical section. Nonces are
    /// pruned by the envelope timestamp, NOT receipt time: retain until
    /// `timestamp < now-300` (a future-stamped nonce stays until `now` catches up,
    /// closing the ~60 s reopen).
    fn check_and_consume(
        &mut self,
        sender: u16,
        nonce: [u8; 16],
        timestamp: u64,
        now_input: u64,
        quota_per_min: u64,
    ) -> IngressGuardResult {
        self.high_water = self.high_water.max(now_input);
        let now = self.high_water;
        if timestamp < now.saturating_sub(FRESHNESS_PAST_SECS)
            || timestamp > now.saturating_add(FRESHNESS_FUTURE_SECS)
        {
            if let Some(limited) = self.charge_quota(sender, now, quota_per_min) {
                return limited;
            }
            return IngressGuardResult::Stale { now };
        }

        let horizon = now.saturating_sub(FRESHNESS_PAST_SECS);
        self.seen_nonces.retain(|_, kept| *kept >= horizon);
        let key = (sender, nonce);
        if self.seen_nonces.contains_key(&key) {
            if let Some(limited) = self.charge_quota(sender, now, quota_per_min) {
                return limited;
            }
            return IngressGuardResult::Replayed;
        }

        // Charge before retaining a new nonce. Inserting first would let an
        // authenticated peer exceed its quota with fresh nonces while still
        // growing this map without the quota's bound; every later request also
        // pays the O(n) prune above, so that becomes a combine-window liveness
        // attack. A RATE_LIMITED envelope is not dispatched and therefore has not
        // performed an action to replay. If retried after the quota window, the
        // current message types are either idempotent partial delivery or carry
        // the coordinator's independent single-use request nonce. Any future
        // message type MUST likewise be idempotent or carry independent replay
        // protection; a channel nonce rejected for quota is deliberately reusable.
        if let Some(limited) = self.charge_quota(sender, now, quota_per_min) {
            return limited;
        }
        self.seen_nonces.insert(key, timestamp);
        IngressGuardResult::Accepted { now }
    }
}

/// The node-local channel runtime, built at load from the sealed manifest.
pub struct ChannelState {
    node_id: u16,
    wallet_id: [u8; 32],
    manifest_hash: [u8; 32],
    /// The RAM-only channel keypair (self). Signs OUTBOUND envelopes — no
    /// production caller in V0-8a (V0-8b wires it); `build` validates the pubkey.
    #[allow(dead_code)]
    channel_seckey: SecretKey,
    #[allow(dead_code)]
    channel_pubkey: PublicKey,
    /// All `n` nodes, indexed by `node_id`.
    nodes: Vec<ManifestNode>,
    store: Mutex<PartialStore>,
    ingress_guards: Mutex<IngressGuards>,
    /// Per-peer running freshness-reject count (monotonic; surfaced via `/events`).
    freshness_counts: Mutex<HashMap<u16, u64>>,
    concurrency: Arc<Semaphore>,
    limits: ChannelLimits,
    /// Shared with the node so freshness-reject events surface through `/events`.
    alerts: Arc<Mutex<AlertQueue>>,
}

impl ChannelState {
    /// Build the channel runtime, running every §2 startup invariant. Any failure
    /// is a fatal config error (returned `Err`), never a runtime refusal.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn build(
        cfg: &ChannelConfig,
        node_seckey: &SecretKey,
        node_signing_pubkey: PublicKey,
        wallet_id: [u8; 32],
        descriptor_node_keys: &[PublicKey],
        listen_port: u16,
        // The one coordinator auth key this vault is sealed to (ADR-0013 §2/§4).
        // Hashed into `manifest_hash` (via [`base_manifest_bytes`]) so the sealed
        // manifest binds it: a different coordinator is a different vault.
        coordinator_auth: PublicKey,
        alerts: Arc<Mutex<AlertQueue>>,
    ) -> Result<ChannelState, Error> {
        // Tokio's constructor panics above this implementation limit. Treat a
        // large-but-valid TOML integer like every other channel startup
        // invariant: a fallible configuration error, never a process panic.
        if cfg.max_concurrent_channel_requests > Semaphore::MAX_PERMITS {
            return Err(format!(
                "[channel] max_concurrent_channel_requests exceeds the supported maximum of {}",
                Semaphore::MAX_PERMITS
            )
            .into());
        }
        // A zero per-send deadline is a silent broadcast trap, the same class of
        // invisible failure the `combine_slack_secs == 0` and missing-`[chain_backend]`
        // checks reject at load. `try_endpoints` never *initiates* a send once
        // `now > deadline`, and it caps every send timeout at `per_send_deadline`
        // (see [`ChannelState::per_send_deadline`]); at zero that timeout is
        // `Duration::ZERO`, so every request/partial fan-out fails immediately and
        // no message ever reaches a peer. In a `t > 1` federation `/sign` still
        // returns Accepted, yet no candidate ever reaches quorum or broadcasts —
        // the money silently never moves. Reject it at provisioning.
        if cfg.per_send_deadline_secs == 0 {
            return Err(
                "[channel] per_send_deadline_secs must be greater than 0: a zero send deadline \
                 gives every outbound envelope a zero-duration timeout, so no request or partial \
                 ever reaches a peer and no spend can combine or broadcast"
                    .into(),
            );
        }
        // Channel endpoint consistency is validated before the listener exists.
        // Port zero would be replaced by an OS-selected ephemeral port at bind
        // time, so no manifest endpoint containing `:0` could describe the
        // address actually serving `/channel`.
        if listen_port == 0 {
            return Err("[channel] listen_port must be nonzero so the manifest pins the actual /channel bind address".into());
        }
        let n = descriptor_node_keys.len();
        if cfg.nodes.len() != n {
            return Err(format!(
                "[channel].nodes has {} entries but the descriptor has {n} node keys",
                cfg.nodes.len()
            )
            .into());
        }
        // Canonical node-key order: lexicographic over the full key-EXPRESSION
        // string (§1). For the first-light template's concrete keys that is the
        // compressed-pubkey hex.
        let mut canonical: Vec<PublicKey> = descriptor_node_keys.to_vec();
        canonical.sort_by_key(|k| k.to_string());
        if canonical.windows(2).any(|keys| keys[0] == keys[1]) {
            return Err(
                "[channel] descriptor contains a duplicate federation node key; node_id mapping is ambiguous"
                    .into(),
            );
        }

        // Parse + validate every entry; assert the node_id ↔ canonical-key
        // bijection (a gap, dup, or out-of-range id is fatal).
        let mut by_id: Vec<Option<ManifestNode>> = (0..n).map(|_| None).collect();
        for entry in &cfg.nodes {
            let id = entry.node_id;
            if (id as usize) >= n {
                return Err(format!("[channel] node_id {id} out of range 0..{n}").into());
            }
            if by_id[id as usize].is_some() {
                return Err(format!("[channel] duplicate node_id {id}").into());
            }
            let signing = PublicKey::from_str(&entry.signing_pubkey)
                .map_err(|e| format!("[channel] node {id} bad signing_pubkey: {e}"))?;
            let channel_pk = PublicKey::from_str(&entry.channel_pubkey)
                .map_err(|e| format!("[channel] node {id} bad channel_pubkey: {e}"))?;
            if signing != canonical[id as usize] {
                return Err(format!(
                    "[channel] node {id} signing_pubkey is not the descriptor's canonical node key at position {id}"
                )
                .into());
            }
            // Cross-role reuse is fatal here for the same reason it is for the
            // descriptor's keys (see `Node::from_toml_str`): a node derives its
            // channel seckey from its federation seckey, so a channel_pubkey that
            // doubles as the coordinator auth key would let that one node mint
            // coordinator-authenticated requests for the whole vault.
            // `bitcoin::PublicKey` equality also compares its compressed-encoding
            // flag, but roles are identities on the secp curve. Compare the
            // underlying point so an uncompressed spelling cannot disguise reuse
            // of the manifest's compressed coordinator key.
            if channel_pk.inner == coordinator_auth.inner {
                return Err(format!(
                    "[channel] node {id} channel_pubkey is also the coordinator_auth_pubkey: one \
                     key for both roles lets a single node mint coordinator requests"
                )
                .into());
            }
            if entry.endpoints.is_empty() {
                return Err(format!("[channel] node {id} has no endpoints").into());
            }
            for ep in &entry.endpoints {
                validate_endpoint(ep)
                    .map_err(|e| format!("[channel] node {id} endpoint {ep:?}: {e}"))?;
            }
            by_id[id as usize] = Some(ManifestNode {
                node_id: id,
                signing_pubkey: signing,
                channel_pubkey: channel_pk,
                endpoints: entry.endpoints.clone(),
            });
        }
        let nodes: Vec<ManifestNode> = by_id
            .into_iter()
            .enumerate()
            .map(|(i, o)| o.ok_or_else(|| Error::from(format!("[channel] missing node_id {i}"))))
            .collect::<Result<_, _>>()?;

        let self_id = cfg.node_id;
        if (self_id as usize) >= n {
            return Err(format!("[channel] node_id {self_id} out of range 0..{n}").into());
        }
        if nodes[self_id as usize].signing_pubkey != node_signing_pubkey {
            return Err("[channel] self entry signing_pubkey does not match this node's federation signing key".into());
        }

        let manifest_hash =
            compute_manifest_hash(&wallet_id, PROTOCOL_VERSION_V0, &coordinator_auth, &nodes);
        if let Some(expected) = &cfg.expected_manifest_hash {
            let expected = from_hex_32(expected)
                .map_err(|_| Error::from("[channel] expected_manifest_hash is not 32-byte hex"))?;
            if expected != manifest_hash {
                return Err("[channel] computed manifest_hash does not equal the sealed expected_manifest_hash".into());
            }
        }

        // Verify every node's channel-key endorsement against its signing key
        // (startup, fatal). The wire envelope carries no endorsement — the
        // manifest channel_pubkey is trusted BECAUSE it is endorsed here.
        let secp = Secp256k1::verification_only();
        for node in &nodes {
            let digest = endorsement_digest(
                &wallet_id,
                &manifest_hash,
                node.node_id,
                &node.channel_pubkey,
                PROTOCOL_VERSION_V0,
                &node.endpoints,
            );
            let entry = cfg
                .nodes
                .iter()
                .find(|e| e.node_id == node.node_id)
                .expect("every node_id has a config entry");
            let der = from_hex_vec(&entry.channel_endorsement).map_err(|_| {
                Error::from(format!(
                    "[channel] node {} bad channel_endorsement hex",
                    node.node_id
                ))
            })?;
            let sig = Signature::from_der(&der).map_err(|e| {
                format!(
                    "[channel] node {} channel_endorsement is not DER: {e}",
                    node.node_id
                )
            })?;
            secp.verify_ecdsa(
                &Message::from_digest(digest),
                &sig,
                &node.signing_pubkey.inner,
            )
            .map_err(|_| {
                Error::from(format!(
                    "[channel] node {} channel_endorsement does not verify against its signing key",
                    node.node_id
                ))
            })?;
        }

        // Locally-derived channel key must equal the self entry's channel_pubkey,
        // or this node is permanently unreachable (peers verify against a key it
        // never signs with).
        let channel_seckey = derive_channel_seckey(node_seckey);
        let channel_pubkey = channel_pubkey_of(&channel_seckey);
        if channel_pubkey != nodes[self_id as usize].channel_pubkey {
            return Err(
                "[channel] locally-derived channel pubkey does not match nodes[self].channel_pubkey".into(),
            );
        }

        // Endpoint consistency (codex I4): the self entry must advertise the
        // address the daemon binds /channel on.
        let bind = SocketAddr::from_str(&format!("127.0.0.1:{listen_port}"))
            .map_err(|e| format!("cannot form bind address 127.0.0.1:{listen_port}: {e}"))?;
        let self_binds = nodes[self_id as usize]
            .endpoints
            .iter()
            .any(|ep| SocketAddr::from_str(ep).map(|a| a == bind).unwrap_or(false));
        if !self_binds {
            return Err(format!(
                "[channel] self endpoints {:?} do not include the daemon bind address {bind}",
                nodes[self_id as usize].endpoints
            )
            .into());
        }

        Ok(ChannelState {
            node_id: self_id,
            wallet_id,
            manifest_hash,
            channel_seckey,
            channel_pubkey,
            nodes,
            store: Mutex::new(PartialStore {
                candidates: HashMap::new(),
                reserved_bytes: 0,
                max_active_candidates: cfg.max_active_candidates,
                max_bytes: cfg.max_candidate_store_bytes,
            }),
            ingress_guards: Mutex::new(IngressGuards::default()),
            freshness_counts: Mutex::new(HashMap::new()),
            concurrency: Arc::new(Semaphore::new(cfg.max_concurrent_channel_requests)),
            limits: ChannelLimits {
                per_peer_quota_per_min: cfg.per_peer_quota_per_min,
                max_msg_bytes: cfg.max_msg_bytes,
                max_response_bytes: cfg.max_response_bytes,
                per_send_deadline_secs: cfg.per_send_deadline_secs,
            },
            alerts,
        })
    }

    // -- accessors for the server ------------------------------------------

    pub(crate) fn concurrency(&self) -> Arc<Semaphore> {
        Arc::clone(&self.concurrency)
    }
    pub(crate) fn max_msg_bytes(&self) -> usize {
        self.limits.max_msg_bytes
    }

    // -- the /sign-path registry funnel ------------------------------------

    /// Register one candidate for focused store tests. Production `/sign` uses
    /// [`Self::register_candidates`] so an entire request is admitted atomically.
    #[cfg(test)]
    pub(crate) fn register_candidate(&self, c: Candidate) -> RegisterOutcome {
        let mut c = c;
        c.reserve_partial_capacity(&self.nodes, self.node_id);
        self.store.lock().expect("store lock poisoned").register(c)
    }

    /// Register one request's complete candidate set atomically under one store
    /// lock. A conflict or insufficient count/byte capacity inserts NONE of the
    /// incoming candidates. Model B structurally withholds partials from the
    /// coordinator, so acknowledging a half-registered pair would strand the
    /// request and (for the mandatory escape) break its future duress seam.
    pub(crate) fn register_candidates(
        &self,
        mut candidates: Vec<Candidate>,
    ) -> Vec<RegisterOutcome> {
        for candidate in &mut candidates {
            candidate.reserve_partial_capacity(&self.nodes, self.node_id);
        }
        let mut store = self.store.lock().expect("store lock poisoned");
        if candidates.iter().any(|candidate| {
            store
                .candidates
                .get(&candidate.commitment_id)
                .is_some_and(|resident| !resident.matches_registration(candidate))
        }) {
            return vec![RegisterOutcome::Conflict; candidates.len()];
        }

        let new_candidates: Vec<&Candidate> = candidates
            .iter()
            .filter(|candidate| !store.candidates.contains_key(&candidate.commitment_id))
            .collect();
        let added_bytes = new_candidates.iter().fold(0usize, |total, candidate| {
            total.saturating_add(candidate.capacity_bytes)
        });
        if store.candidates.len().saturating_add(new_candidates.len()) > store.max_active_candidates
            || store.reserved_bytes.saturating_add(added_bytes) > store.max_bytes
        {
            return candidates
                .iter()
                .map(|candidate| {
                    if store.candidates.contains_key(&candidate.commitment_id) {
                        RegisterOutcome::AlreadyPresent
                    } else {
                        RegisterOutcome::AtCapacity
                    }
                })
                .collect();
        }
        candidates
            .into_iter()
            .map(|candidate| store.register(candidate))
            .collect()
    }

    /// Prune expired candidates — driven from the same `/sign` sweep the replay
    /// log runs on (§5); the `/channel` lookup also evicts expired candidates so an
    /// idle node still rejects them.
    pub(crate) fn prune_store(&self, now: u64) {
        self.store.lock().expect("store lock poisoned").prune(now);
    }

    // -- the fire path (§1): release, combine ------------------------------

    /// Every live candidate whose combine window is open at `now`, in stable
    /// (sorted) order. Candidates with no [`FireWindow`] — nothing has scheduled
    /// them — are never returned, so the escape of a normal request stays inert.
    pub(crate) fn due_for_fire(&self, now: u64) -> Vec<String> {
        let store = self.store.lock().expect("store lock poisoned");
        let mut due: Vec<String> = store
            .candidates
            .values()
            .filter(|c| !c.broadcast && c.fire.is_some_and(|window| window.is_open(now)))
            .map(|c| c.commitment_id.clone())
            .collect();
        due.sort();
        due
    }

    /// Whether a scheduled candidate is still worth polling for a peer's
    /// settlement: its fire event has arrived AND `now` is within the bounded
    /// observation window `[fire_at, deadline + SETTLEMENT_OBSERVE_GRACE_SECS]`.
    /// Used ONLY for post-window settlement recognition — it never releases,
    /// finalizes, or broadcasts ([`release_partials`](Self::release_partials) and
    /// [`try_finalize`](Self::try_finalize) still enforce the complete combine
    /// window independently). Past the grace no peer's window is still open, so the
    /// spend can no longer newly settle over the channel; the pending Hold then
    /// lifts on its commitment-expiry backstop rather than a 1 Hz backend poll.
    pub(crate) fn fire_settlement_pollable(&self, commitment_id: &str, now: u64) -> bool {
        self.store
            .lock()
            .expect("store lock poisoned")
            .candidates
            .get(commitment_id)
            .and_then(|candidate| candidate.fire)
            .is_some_and(|window| {
                now >= window.fire_at
                    && now
                        <= window
                            .deadline
                            .saturating_add(SETTLEMENT_OBSERVE_GRACE_SECS)
            })
    }

    /// **The partial-release gate — ADR-0012 invariant 7, the load-bearing one.**
    /// The ONLY way a partial signature leaves this node.
    ///
    /// Returns this node's own partials for `commitment_id` iff the candidate's
    /// authorized fire event has arrived and its combine window is still open;
    /// `None` in every other case, including a candidate that is registered,
    /// signed, and merely waiting. It marks the candidate released, so the release
    /// happens once.
    ///
    /// Why this is not "release at ingress and let the Hold gate the broadcast":
    /// partials in a peer's hands are a finalizable transaction. If a node handed
    /// them out at ingress, ONE compromised node (or a coordinator that could
    /// solicit them) could collect `t` peers' partials during the Hold and
    /// broadcast the spend early — breaking the Hold AND duress silence without
    /// compromising `t` nodes. Withholding until fire is what makes "the escape
    /// fires at T and the frozen spend never settles" enforceable, and it is the
    /// hook V0-4b's arm uses to suppress release entirely.
    pub(crate) fn release_partials(&self, commitment_id: &str, now: u64) -> Option<Release> {
        let mut store = self.store.lock().expect("store lock poisoned");
        let candidate = store.candidates.get_mut(commitment_id)?;
        // The gate. An unscheduled candidate (`fire == None`) never passes; a
        // scheduled one passes only inside its open combine window, and only once.
        let window = candidate.fire?;
        if !window.is_open(now) || candidate.released {
            return None;
        }
        candidate.released = true;
        let signer = self.nodes[self.node_id as usize].signing_pubkey;
        let payloads = (0..candidate.psbt.inputs.len())
            .filter_map(|input| {
                let sig = candidate.psbt.inputs[input].partial_sigs.get(&signer)?;
                Some(PartialPayload {
                    commitment_id: commitment_id.to_string(),
                    wallet_id: to_hex(&self.wallet_id),
                    txid: candidate.unsigned_txid.to_string(),
                    input: input as u32,
                    signer_node_id: self.node_id,
                    sighash_type: EcdsaSighashType::All.to_u32(),
                    // A non-authoritative hint (ADR-0012): every peer derives the
                    // class from the outputs itself and ignores this.
                    spend_purpose: match candidate.role {
                        CandidateRole::Spend => "spend",
                        CandidateRole::Escape => "escape",
                    }
                    .to_string(),
                    user_sig_hash: to_hex(&candidate.user_sig_hash),
                    partial_sig: to_hex(&sig.signature.serialize_der()),
                })
            })
            .collect();
        Some(Release {
            payloads,
            deadline: window.deadline,
        })
    }

    /// The fully-signed transaction for `commitment_id` when its combine window is
    /// open and EVERY input carries ≥ `threshold` distinct valid federation
    /// signatures (§1); `None` otherwise — including when the quorum is not yet
    /// present, which is the ordinary "still collecting" case.
    ///
    /// Finalization runs on a CLONE: the canonical candidate keeps its partials, so
    /// a later tick can retry if the broadcast fails.
    pub(crate) fn try_finalize(
        &self,
        commitment_id: &str,
        threshold: usize,
        now: u64,
    ) -> Option<FinalizedCandidate> {
        let store = self.store.lock().expect("store lock poisoned");
        let candidate = store.candidates.get(commitment_id)?;
        let window = candidate.fire?;
        if !window.is_open(now) || candidate.broadcast {
            return None;
        }
        if !candidate.has_quorum(threshold, &self.nodes) {
            return None;
        }
        let mut psbt = candidate.psbt.clone();
        // miniscript builds the witness from the descriptor + the collected
        // signatures. A failure here is a real inconsistency (a candidate whose
        // signatures do not satisfy its own script), so it is logged and skipped —
        // never a panic on the fire path.
        if let Err(e) = psbt.finalize_mut(&Secp256k1::verification_only()) {
            eprintln!("channel: cannot finalize candidate {commitment_id}: {e:?}");
            return None;
        }
        match psbt.extract_tx() {
            Ok(tx) => Some(FinalizedCandidate {
                tx,
                deadline: window.deadline,
            }),
            Err(e) => {
                eprintln!("channel: cannot extract candidate {commitment_id}: {e}");
                None
            }
        }
    }

    /// Exact txid of a resident candidate, independent of local partial count.
    /// Used to recognize that a peer already settled the transaction even when
    /// this node never received enough partials to finalize its own copy.
    pub(crate) fn candidate_txid(&self, commitment_id: &str) -> Option<Txid> {
        self.store
            .lock()
            .expect("store lock poisoned")
            .candidates
            .get(commitment_id)
            .map(|candidate| candidate.unsigned_txid)
    }

    /// Mark `commitment_id` broadcast so later ticks skip it.
    pub(crate) fn mark_broadcast(&self, commitment_id: &str) {
        if let Some(candidate) = self
            .store
            .lock()
            .expect("store lock poisoned")
            .candidates
            .get_mut(commitment_id)
        {
            candidate.broadcast = true;
        }
    }

    /// A registered candidate's role and the commitment id of its sibling — §4's
    /// "paired by request" link, read back.
    ///
    /// Public because the pairing is protocol state, not an implementation detail:
    /// it is how anything holding one half of a request finds the other. V0-4b's
    /// duress arm is the production reader — it takes the frozen spend it just
    /// suppressed and needs that request's escape to schedule at `T` — and it can
    /// do so through this one link rather than re-deriving a pairing from
    /// transaction shapes, which would be guesswork.
    pub fn pairing(&self, commitment_id: &str) -> Option<(CandidateRole, String)> {
        let store = self.store.lock().expect("store lock poisoned");
        let candidate = store.candidates.get(commitment_id)?;
        Some((candidate.role, candidate.paired_commitment_id.clone()))
    }

    /// Every peer's node id (everyone but self), in manifest order — the fan-out
    /// set for both a partial release and a request propagation.
    pub(crate) fn peer_ids(&self) -> Vec<u16> {
        self.nodes
            .iter()
            .map(|node| node.node_id)
            .filter(|id| *id != self.node_id)
            .collect()
    }

    // -- ingress -----------------------------------------------------------

    fn record_freshness_reject(&self, sender: u16, ts: u64, now: u64) {
        let count = {
            let mut m = self
                .freshness_counts
                .lock()
                .expect("freshness lock poisoned");
            let c = m.entry(sender).or_insert(0);
            *c = c.saturating_add(1);
            *c
        };
        let skew_secs = (i128::from(ts) - i128::from(now))
            .clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64;
        self.alerts
            .lock()
            .expect("alerts lock poisoned")
            .record_freshness(FreshnessEvent {
                kind: FreshnessKind::ChannelFreshnessReject,
                peer_node_id: sender,
                reject_count: count,
                skew_secs,
            });
    }

    /// Process one raw channel body. `now_input` is unix seconds (the server
    /// passes the local clock; tests pass a fixed value); the monotonic high-water
    /// is applied internally.
    ///
    /// Structurally NO path to the signer (signing-oracle prohibition, §7): a
    /// `partial` is verified and stored, and a `request` is handed BACK to the node
    /// unprocessed — this layer never decides to sign anything.
    pub(crate) fn ingest(&self, body: &[u8], now_input: u64) -> Ingested {
        let env: Envelope = match serde_json::from_slice(body) {
            Ok(e) => e,
            Err(_) => return reject(RejectReason::MalformedJson),
        };
        let wallet_id = match from_hex_32(&env.wallet_id) {
            Ok(x) => x,
            Err(_) => return reject(RejectReason::MalformedJson),
        };
        let manifest_hash = match from_hex_32(&env.manifest_hash) {
            Ok(x) => x,
            Err(_) => return reject(RejectReason::MalformedJson),
        };
        let nonce = match from_hex_16(&env.nonce) {
            Ok(x) => x,
            Err(_) => return reject(RejectReason::MalformedJson),
        };
        let sig_der = match from_hex_vec(&env.channel_sig) {
            Ok(x) => x,
            Err(_) => return reject(RejectReason::MalformedJson),
        };

        // 1. protocol_version pinned to the manifest.
        if env.protocol_version != PROTOCOL_VERSION_V0 {
            return reject(RejectReason::BadProtocolVersion);
        }
        // 2. explicit local-vault equality (independent of endorsement validity).
        if wallet_id != self.wallet_id {
            return reject(RejectReason::WrongWallet);
        }
        if manifest_hash != self.manifest_hash {
            return reject(RejectReason::WrongManifest);
        }
        // 3. recipient bind (closes cross-recipient replay for every msg_type).
        if env.recipient_node_id != self.node_id {
            return reject(RejectReason::WrongRecipient);
        }
        // 4. sender must be an in-manifest peer (never self).
        let sender = env.sender_node_id;
        if sender == self.node_id || (sender as usize) >= self.nodes.len() {
            return reject(RejectReason::UnknownSender);
        }
        let peer_channel_pubkey = self.nodes[sender as usize].channel_pubkey;
        // 5. channel_sig over the recomputed preimage (proves possession of the
        //    endorsed channel key — the coordinator cannot mint a node).
        let preimage = envelope_preimage(
            &env.msg_type,
            env.protocol_version,
            &wallet_id,
            &manifest_hash,
            sender,
            env.recipient_node_id,
            env.payload_b64.as_bytes(),
            &nonce,
            env.timestamp,
        );
        let digest = tagged_hash(ENVELOPE_TAG, &preimage);
        let sig = match Signature::from_der(&sig_der) {
            Ok(s) => s,
            Err(_) => return reject(RejectReason::BadChannelSig),
        };
        if Secp256k1::verification_only()
            .verify_ecdsa(
                &Message::from_digest(digest),
                &sig,
                &peer_channel_pubkey.inner,
            )
            .is_err()
        {
            return reject(RejectReason::BadChannelSig);
        }

        // Sender authenticated. Apply freshness, monotonic-clock advancement,
        // timestamp-keyed nonce pruning, replay suppression, and per-peer quota
        // in ONE critical section. Every authenticated outcome is quota-charged;
        // forged traffic cannot burn a peer's quota because the signature was
        // verified above. This closes the race where an older `now`
        // snapshot could reinsert a nonce after a concurrent high-water advance
        // pruned it, and prevents stale/replayed captures from bypassing the
        // post-auth rate bound or amplifying freshness-event queue work.
        // Bind the guard decision to a local so the `MutexGuard` temporary drops at
        // the end of THIS statement — before the match arms run. Otherwise the guard
        // (a scrutinee temporary) would live across every arm, and the `Stale` arm's
        // `record_freshness_reject` (which takes `freshness_counts` + `alerts` and
        // scans the alert queue) would execute while the global ingress lock is held,
        // serializing all peers' `/channel` ingress behind an unrelated queue scan.
        let guard_result = self
            .ingress_guards
            .lock()
            .expect("ingress guards lock poisoned")
            .check_and_consume(
                sender,
                nonce,
                env.timestamp,
                now_input,
                self.limits.per_peer_quota_per_min,
            );
        let now = match guard_result {
            IngressGuardResult::Accepted { now } => now,
            IngressGuardResult::Stale { now } => {
                self.record_freshness_reject(sender, env.timestamp, now);
                return reject(RejectReason::StaleTimestamp);
            }
            IngressGuardResult::Replayed => {
                return reject(RejectReason::ReplayedNonce);
            }
            IngressGuardResult::RateLimited { retry_after_secs } => {
                return Ingested::Reply(ChannelReply::RateLimited { retry_after_secs });
            }
        };
        // 8. only now decode the opaque payload. Request payloads contain the PIN,
        // so the decoded allocation wipes on every dispatch/error exit. Decode
        // straight into a zeroizing buffer via `decode_vec`: `Engine::decode`
        // allocates its own plain `Vec`, decodes the valid base64 prefix into
        // it, and on a malformed tail drops it UNWIPED before we could wrap it —
        // leaking partially-decoded plaintext on the error path. Writing into our
        // own buffer makes both the Ok dispatch and the Err reject wipe on drop.
        let mut payload = Zeroizing::new(Vec::new());
        if STANDARD
            .decode_vec(env.payload_b64.as_bytes(), &mut payload)
            .is_err()
        {
            return reject(RejectReason::MalformedPayload);
        }
        // 9. dispatch. Two msg_types: `partial` (verified + stored here) and
        //    `request` (handed back to the node, which owns every policy gate).
        match env.msg_type.as_str() {
            MSG_TYPE_PARTIAL => {
                Ingested::Reply(self.handle_partial(sender, &payload, &wallet_id, now))
            }
            MSG_TYPE_REQUEST => match serde_json::from_slice::<TaggedRequest>(&payload) {
                Ok(request) => Ingested::Request(Box::new(request)),
                Err(_) => reject(RejectReason::MalformedPayload),
            },
            _ => reject(RejectReason::UnknownMsgType),
        }
    }

    fn handle_partial(
        &self,
        sender: u16,
        payload: &[u8],
        env_wallet_id: &[u8; 32],
        now: u64,
    ) -> ChannelReply {
        let p: PartialPayload = match serde_json::from_slice(payload) {
            Ok(p) => p,
            Err(_) => return ChannelReply::Rejected(RejectReason::MalformedPayload),
        };
        let p_wallet = match from_hex_32(&p.wallet_id) {
            Ok(x) => x,
            Err(_) => return ChannelReply::Rejected(RejectReason::MalformedPayload),
        };
        let user_sig_hash = match from_hex_32(&p.user_sig_hash) {
            Ok(x) => x,
            Err(_) => return ChannelReply::Rejected(RejectReason::MalformedPayload),
        };
        let txid = match Txid::from_str(&p.txid) {
            Ok(x) => x,
            Err(_) => return ChannelReply::Rejected(RejectReason::MalformedPayload),
        };
        let der = match from_hex_vec(&p.partial_sig) {
            Ok(x) => x,
            Err(_) => return ChannelReply::Rejected(RejectReason::MalformedPayload),
        };
        // Equality checks (§5): payload wallet == envelope wallet.
        if &p_wallet != env_wallet_id {
            return ChannelReply::Rejected(RejectReason::PayloadWalletMismatch);
        }
        // Nodes only relay their OWN partials in V0-8a.
        if p.signer_node_id != sender {
            return ChannelReply::Rejected(RejectReason::SignerMismatch);
        }
        // v0 supports only SIGHASH_ALL.
        if p.sighash_type != EcdsaSighashType::All.to_u32() {
            return ChannelReply::Rejected(RejectReason::WrongSighashType);
        }
        let parsed = ParsedPartial {
            commitment_id: &p.commitment_id,
            txid,
            user_sig_hash,
            input: p.input,
            signer: p.signer_node_id,
            der: &der,
        };
        self.store
            .lock()
            .expect("store lock poisoned")
            .accept_partial(&parsed, &self.nodes, now)
    }

    // -- outbound (§6) -----------------------------------------------------

    /// Build a freshly-signed envelope carrying `payload` for `recipient_node_id`.
    /// Each call draws a FRESH nonce + timestamp + `channel_sig`, so a channel
    /// nonce is single-use (consumed on the receiver at first sight).
    pub(crate) fn build_envelope(
        &self,
        msg_type: &str,
        recipient_node_id: u16,
        payload: &[u8],
        timestamp: u64,
    ) -> Result<Envelope, Error> {
        let nonce = random_bytes::<16>()?;
        let payload_b64 = STANDARD.encode(payload);
        let preimage = envelope_preimage(
            msg_type,
            PROTOCOL_VERSION_V0,
            &self.wallet_id,
            &self.manifest_hash,
            self.node_id,
            recipient_node_id,
            payload_b64.as_bytes(),
            &nonce,
            timestamp,
        );
        let digest = tagged_hash(ENVELOPE_TAG, &preimage);
        let sig = Secp256k1::signing_only()
            .sign_ecdsa(&Message::from_digest(digest), &self.channel_seckey);
        Ok(Envelope {
            msg_type: msg_type.to_string(),
            protocol_version: PROTOCOL_VERSION_V0,
            wallet_id: to_hex(&self.wallet_id),
            manifest_hash: to_hex(&self.manifest_hash),
            sender_node_id: self.node_id,
            recipient_node_id,
            payload_b64: payload_b64.into(),
            nonce: to_hex(&nonce),
            timestamp,
            channel_sig: to_hex(&sig.serialize_der()),
        })
    }

    /// Every endorsed canonical base address for `node_id`, in manifest order.
    /// A transport failure on one endpoint must not discard the alternatives.
    pub(crate) fn peer_bases(&self, node_id: u16) -> Option<Vec<String>> {
        self.nodes
            .get(node_id as usize)
            .map(|node| node.endpoints.clone())
            .filter(|endpoints| !endpoints.is_empty())
    }

    fn per_send_deadline(&self) -> Duration {
        Duration::from_secs(self.limits.per_send_deadline_secs)
    }
    fn max_response_bytes(&self) -> usize {
        self.limits.max_response_bytes
    }
}

/// The canonical propagation payload for one request (§3): the coordinator-signed
/// tagged request followed by JSON whitespace padding. `serde_json` accepts the
/// trailing whitespace, so peers recover and authenticate the request verbatim.
///
/// **The constant-observable step.** This is a pure function of the request, so
/// every accepted request produces one message per peer over this one path. For a
/// given candidate pair, the fixed budget hides the encoded lengths of the PIN,
/// nonce, and DER coordinator signature, so unequal-length enrolled PINs still
/// produce identical payload sizes. Nothing about the PIN class or the node's
/// internal fire decision reaches the wire — the property V0-4b's silence rests
/// on (ADR-0012, "pin-independent ingress").
pub(crate) fn request_payload(request: &TaggedRequest) -> Zeroizing<Vec<u8>> {
    // JSON can expand one input byte to six bytes (`\u00xx`). Both PIN and nonce
    // have protocol bounds; an accepted coordinator signature is canonical secp
    // DER rendered as ASCII hex. Serialize the invariant request shape with those
    // fields empty, then reserve their worst-case encoded contents. This produces
    // one exact target length for all valid values without mutating the signed
    // request itself.
    const JSON_BYTE_EXPANSION: usize = 6;
    const MAX_COORD_SIG_HEX_BYTES: usize = MAX_ECDSA_DER_BYTES * 2;

    let mut shape = request.clone();
    let variable_budget = match &mut shape {
        TaggedRequest::Spend(spend) => {
            spend.pin.clear();
            spend.nonce.clear();
            spend.coord_sig.clear();
            JSON_BYTE_EXPANSION * (MAX_PIN_BYTES + MAX_COORD_NONCE_BYTES) + MAX_COORD_SIG_HEX_BYTES
        }
        TaggedRequest::Refresh(refresh) => {
            refresh.nonce.clear();
            refresh.coord_sig.clear();
            JSON_BYTE_EXPANSION * MAX_COORD_NONCE_BYTES + MAX_COORD_SIG_HEX_BYTES
        }
    };
    let target_len = serde_json::to_vec(&shape)
        .expect("TaggedRequest is always serializable")
        .len()
        .saturating_add(variable_budget);
    // Allocate the final secret-bearing buffer at its worst-case size BEFORE the
    // PIN is written. `serde_json::to_vec` grows from a small allocation and can
    // free an earlier buffer containing the plaintext PIN without wiping it; this
    // shape-derived reservation guarantees `to_writer` never reallocates for any
    // protocol-valid request. Serialization errors still drop and wipe `payload`.
    let mut payload = Zeroizing::new(Vec::with_capacity(target_len));
    let allocation = payload.as_ptr();
    serde_json::to_writer(&mut *payload, request).expect("TaggedRequest is always serializable");
    debug_assert_eq!(
        payload.as_ptr(),
        allocation,
        "secret request serialization must not reallocate"
    );
    debug_assert!(
        payload.len() <= target_len,
        "an accepted request's bounded fields must fit the propagation padding budget"
    );
    // Never truncate if a direct unit caller constructs an invalid over-bound DTO;
    // production calls this only after the node's PIN, nonce, and signature gates.
    let padded_len = payload.len().max(target_len);
    payload.resize(padded_len, b' ');
    payload
}

/// Whether a coordinator request can be propagated without its base64 envelope
/// exceeding this node's configured `/channel` body cap.
///
/// `/sign` is allowed to buffer up to 1 MiB, but the signed channel envelope is
/// larger than the request it carries. Use worst-case numeric widths and a maximum
/// DER signature so the admission decision is independent of which peer sends it
/// and of the wall-clock timestamp. A request that fails this preflight must never
/// be acknowledged: after acknowledgement the coordinator has no partials and peer
/// propagation is the only path to a quorum.
pub(crate) fn request_fits_channel_body(request: &TaggedRequest, max_msg_bytes: usize) -> bool {
    const HEX_32_BYTES: usize = 64;
    const HEX_16_BYTES: usize = 32;
    const MAX_CHANNEL_SIG_HEX_BYTES: usize = MAX_ECDSA_DER_BYTES * 2;

    let envelope = Envelope {
        msg_type: MSG_TYPE_REQUEST.to_string(),
        protocol_version: PROTOCOL_VERSION_V0,
        wallet_id: "0".repeat(HEX_32_BYTES),
        manifest_hash: "0".repeat(HEX_32_BYTES),
        sender_node_id: u16::MAX,
        recipient_node_id: u16::MAX,
        payload_b64: STANDARD.encode(request_payload(request)).into(),
        nonce: "0".repeat(HEX_16_BYTES),
        timestamp: u64::MAX,
        channel_sig: "0".repeat(MAX_CHANNEL_SIG_HEX_BYTES),
    };
    envelope_body(&envelope)
        .expect("a channel envelope containing only serializable fields")
        .len()
        <= max_msg_bytes
}

/// One outbound message to one peer: the `(msg_type, payload)` pair the fan-out
/// re-envelopes per attempt. The payload is immutable — each transport attempt
/// draws a fresh nonce + timestamp + signature around these same bytes.
pub(crate) struct Outbound {
    pub(crate) msg_type: &'static str,
    /// Request payloads carry a plaintext PIN; every fan-out clone wipes on drop.
    pub(crate) payload: Zeroizing<Vec<u8>>,
    /// Last instant a send may be *initiated*; the retry loop stops here.
    pub(crate) deadline: u64,
}

impl Release {
    /// This release as one outbound `partial` message per signed input.
    pub(crate) fn outbound(&self) -> Vec<Outbound> {
        self.payloads
            .iter()
            .map(|payload| Outbound {
                msg_type: MSG_TYPE_PARTIAL,
                payload: Zeroizing::new(payload.to_bytes()),
                deadline: self.deadline,
            })
            .collect()
    }
}

/// POST a signed envelope to a peer's `/channel` with a per-send deadline and a
/// bounded response read. A dead/unreachable peer is an `Err`, never a panic, and
/// never blocks other sends (callers fan out concurrently). `base` is the peer's
/// canonical `host:port`; this appends `http://…/channel` exactly once.
///
/// **Partial-release authorization (ADR-0012):** no partial may leave the node
/// before its candidate's authorized fire event. This function is transport only
/// and enforces nothing — the gate is [`ChannelState::release_partials`], which is
/// the single source of every `partial` payload that reaches here.
pub(crate) async fn send_envelope(
    base: &str,
    envelope: &Envelope,
    deadline: Duration,
    max_response_bytes: usize,
) -> Result<OutboundReply, Error> {
    let url = format!("http://{base}/channel");
    let client = reqwest::Client::builder()
        // Manifest-pinned endpoints are the complete routing configuration. Ambient
        // HTTP(S)_PROXY/ALL_PROXY variables must not insert an unendorsed hop;
        // v1 Tor support will add its proxy explicitly.
        .no_proxy()
        // Never follow redirects. A 3xx `Location` is network-provided routing, and no
        // `/channel` endpoint derives authority from reachability — all authority is
        // cryptographic, rooted in the manifest. reqwest follows redirects by default
        // and re-sends this POST body on 307/308, so a compromised or on-path endpoint
        // could otherwise redirect the signed partial to an unendorsed address (SSRF /
        // partial leak, ADR-0012). Disabling it makes a redirect a misbehaving peer:
        // reqwest surfaces the 3xx and `parse_reply` errors, never leaking the partial.
        .redirect(reqwest::redirect::Policy::none())
        .timeout(deadline)
        .build()
        .map_err(|e| format!("build reqwest client: {e}"))?;
    let body = envelope_body(envelope)?;
    // Keep the zeroizing allocation as the HTTP body's owner. Once the last
    // transport clone drops, the serialized envelope (including any PIN) wipes.
    let body = reqwest::Body::from(Bytes::from_owner(body));
    let mut resp = client
        .post(&url)
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .map_err(|e| format!("send to {url}: {e}"))?;
    let status = resp.status().as_u16();
    let mut buf = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| format!("read from {url}: {e}"))?
    {
        if buf.len() + chunk.len() > max_response_bytes {
            return Err(format!(
                "response from {url} exceeds max_response_bytes ({max_response_bytes})"
            )
            .into());
        }
        buf.extend_from_slice(&chunk);
    }
    parse_reply(status, &buf)
}

/// Serialize one channel envelope with enough trailing JSON whitespace to hide
/// the variable DER length of `channel_sig`. Request payload padding alone would
/// not make the HTTP body size-independent of the PIN: changing the signed payload
/// changes the ECDSA signature, whose DER form ranges up to 72 bytes. The nonce and
/// every other envelope identity field already have fixed-width encodings.
fn envelope_body(envelope: &Envelope) -> Result<Zeroizing<Vec<u8>>, Error> {
    const JSON_BYTE_EXPANSION: usize = 6;
    const MAX_CHANNEL_SIG_HEX_BYTES: usize = MAX_ECDSA_DER_BYTES * 2;

    // The base64 payload reversibly contains the PIN. Measure a wiped clone, then
    // reserve for JSON's worst-case string expansion before serializing the real
    // envelope, so no secret-bearing allocation can be freed during Vec growth.
    // Base64/signature text normally needs no escaping; the 6x budget also keeps
    // this safe for direct test callers that construct arbitrary strings.
    let mut shape = envelope.clone();
    shape.payload_b64.zeroize();
    shape.channel_sig.clear();
    let variable_capacity = envelope
        .payload_b64
        .len()
        .saturating_add(envelope.channel_sig.len())
        .saturating_mul(JSON_BYTE_EXPANSION);
    let serialize_capacity = serde_json::to_vec(&shape)
        .map_err(|e| format!("encode envelope shape: {e}"))?
        .len()
        .saturating_add(variable_capacity);
    // Reserve the serialize estimate PLUS the maximum trailing pad up front, so
    // neither `to_writer` nor the later `resize` can reallocate. `to_writer`
    // stays within `serialize_capacity` (asserted below), and the pad adds at
    // most `MAX_CHANNEL_SIG_HEX_BYTES` (channel_sig empty), so this single
    // reservation is a provable upper bound. Without it, a pathologically small
    // payload could make `padded_len > serialize_capacity` and the resize would
    // realloc — leaving an unwiped freed copy of this secret-bearing buffer, the
    // exact hazard the sibling `request_payload`/`canonical_bytes` assert away.
    let capacity = serialize_capacity.saturating_add(MAX_CHANNEL_SIG_HEX_BYTES);
    let mut body = Zeroizing::new(Vec::with_capacity(capacity));
    let allocation = body.as_ptr();
    serde_json::to_writer(&mut *body, envelope).map_err(|e| format!("encode envelope: {e}"))?;
    debug_assert_eq!(
        body.as_ptr(),
        allocation,
        "secret envelope serialization must not reallocate"
    );
    let padded_len = body
        .len()
        .saturating_add(MAX_CHANNEL_SIG_HEX_BYTES.saturating_sub(envelope.channel_sig.len()));
    body.resize(padded_len, b' ');
    debug_assert_eq!(
        body.as_ptr(),
        allocation,
        "secret envelope padding must not reallocate"
    );
    Ok(body)
}

/// Client-side view of a channel reply. A permanent rejection's reason remains
/// the peer's opaque wire string: the retry policy never branches on individual
/// reason codes, so decoding and immediately re-encoding all frozen server enums
/// would add no correctness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum OutboundReply {
    Accepted,
    Rejected(String),
    UnknownCandidate,
    RateLimited { retry_after_secs: u64 },
}

fn parse_reply(status: u16, body: &[u8]) -> Result<OutboundReply, Error> {
    #[derive(Deserialize)]
    struct Tagged {
        status: String,
        #[serde(default)]
        reason: Option<String>,
        #[serde(default)]
        retry_after_secs: Option<u64>,
    }
    let t: Tagged = serde_json::from_slice(body)
        .map_err(|e| format!("bad channel reply (http {status}): {e}"))?;
    // §5b freezes a one-to-one HTTP-status↔tag mapping (200/400/409/429). A genuine
    // peer ALWAYS returns the matching pair; classify by BOTH, never the tag alone.
    // A mismatched pair — HTTP 500, or a 3xx/2xx body carrying `{"status":"ACCEPTED"}`
    // injected on-path — must NOT be read as success: a false `Accepted` would stop
    // the retry loop while the partial was never stored, silently dropping it from
    // the combine set. Any pairing outside the four is a retriable transport anomaly
    // (`Err` → the retry loop backs off and retries with a fresh envelope).
    match (status, t.status.as_str()) {
        (200, "ACCEPTED") => Ok(OutboundReply::Accepted),
        (409, "UNKNOWN_CANDIDATE") => Ok(OutboundReply::UnknownCandidate),
        (429, "RATE_LIMITED") => Ok(OutboundReply::RateLimited {
            retry_after_secs: t.retry_after_secs.unwrap_or(1),
        }),
        (400, "REJECTED") => Ok(OutboundReply::Rejected(
            t.reason.unwrap_or_else(|| "UNKNOWN".to_string()),
        )),
        (code, other) => {
            Err(format!("channel reply status/tag mismatch: http {code} with tag {other:?}").into())
        }
    }
}

/// Bounded retry backoff schedule (§6). Static — not a ceremony knob.
fn default_backoff() -> [Duration; 5] {
    [
        Duration::from_secs(1),
        Duration::from_secs(2),
        Duration::from_secs(5),
        Duration::from_secs(10),
        Duration::from_secs(30),
    ]
}

/// The terminal outcome of a bounded-retry loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RetryOutcome {
    Accepted,
    /// A permanent `REJECTED` — retry stopped immediately.
    Rejected(String),
    /// The commitment expiry was reached before an accept.
    GaveUp,
}

/// The pure retry control loop (codex I1): re-runs `attempt` (which RE-ENVELOPES
/// from the immutable payload with a FRESH nonce+timestamp+sig each call) on
/// `UnknownCandidate`/`RateLimited`/transport error, backing off until the Unix
/// `commitment_expiry`, stopping on `Accepted` or a permanent `Rejected`. The
/// node's wall clock is re-read before every attempt and after every response so
/// NTP steps stay aligned with candidate expiry; sleeps remain monotonic tokio
/// time so clock changes cannot distort an individual backoff.
async fn retry_loop<A, Fut, N>(
    mut attempt: A,
    commitment_expiry: u64,
    mut now: N,
    backoff: &[Duration],
) -> RetryOutcome
where
    A: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<OutboundReply, Error>>,
    N: FnMut() -> u64,
{
    let mut i = 0usize;
    loop {
        if now() > commitment_expiry {
            return RetryOutcome::GaveUp;
        }
        let wait = match attempt().await {
            Ok(OutboundReply::Accepted) => return RetryOutcome::Accepted,
            Ok(OutboundReply::Rejected(reason)) => return RetryOutcome::Rejected(reason),
            Ok(OutboundReply::RateLimited { retry_after_secs }) => {
                Duration::from_secs(retry_after_secs)
            }
            Ok(OutboundReply::UnknownCandidate) | Err(_) => {
                let wait = backoff[i.min(backoff.len().saturating_sub(1))];
                i = i.saturating_add(1);
                wait
            }
        };
        let after_attempt = now();
        if after_attempt > commitment_expiry {
            return RetryOutcome::GaveUp;
        }
        // Unix timestamps name whole seconds and the fire window is inclusive.
        // At `now == deadline`, one final attempt may still start during that
        // second, so its remaining transport budget is one second rather than zero.
        let remaining = Duration::from_secs(
            commitment_expiry
                .saturating_sub(after_attempt)
                .saturating_add(1),
        );
        tokio::time::sleep(wait.max(Duration::from_secs(1)).min(remaining)).await;
    }
}

/// Try every endorsed endpoint for one logical retry attempt. A fresh envelope
/// is built for EACH transport attempt: an endpoint may have consumed the nonce
/// even when its response was lost, so reusing that envelope at an alternative
/// endpoint could self-reject as a replay.
///
/// Bounded-until-deadline (§6) is enforced at ENDPOINT granularity, not just at
/// the retry-loop boundary: the clock is re-read before every endpoint so a send
/// is never *initiated* past `deadline`, and each send's timeout is capped to the
/// remaining lifetime so one stalled endpoint cannot burn the full per-send
/// deadline and push a later endpoint past it.
async fn try_endpoints(
    channel: &ChannelState,
    msg_type: &str,
    recipient_node_id: u16,
    payload: &[u8],
    endpoints: &[String],
    deadline: u64,
) -> Result<OutboundReply, Error> {
    let mut last_error = None;
    for base in endpoints {
        let now = unix_now();
        if now > deadline {
            break;
        }
        let remaining = deadline.saturating_sub(now).saturating_add(1);
        let send_deadline = channel
            .per_send_deadline()
            .min(Duration::from_secs(remaining));
        let envelope = channel.build_envelope(msg_type, recipient_node_id, payload, now)?;
        match send_envelope(base, &envelope, send_deadline, channel.max_response_bytes()).await {
            Ok(reply) => return Ok(reply),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| Error::from("peer has no endpoints")))
}

/// Bounded retry of one `(msg_type, payload)` to `recipient_node_id` until
/// `deadline` (§6). Each attempt re-envelopes the immutable `payload` afresh
/// (single-use nonce) — the helper holds the payload, never the envelope.
///
/// `deadline` is the message's own horizon, not always the commitment expiry: a
/// released partial stops at the end of its COMBINE window (there is no point
/// delivering a partial a peer can no longer combine), while a propagated request
/// runs to the request's expiry.
pub(crate) async fn retry_message_until(
    channel: &ChannelState,
    msg_type: &'static str,
    recipient_node_id: u16,
    payload: &[u8],
    deadline: u64,
) -> Result<(), Error> {
    let endpoints = channel
        .peer_bases(recipient_node_id)
        .ok_or_else(|| Error::from(format!("no endpoint for peer {recipient_node_id}")))?;
    let backoff = default_backoff();
    let outcome = retry_loop(
        || {
            try_endpoints(
                channel,
                msg_type,
                recipient_node_id,
                payload,
                &endpoints,
                deadline,
            )
        },
        deadline,
        unix_now,
        &backoff,
    )
    .await;
    match outcome {
        RetryOutcome::Accepted => Ok(()),
        RetryOutcome::Rejected(reason) => {
            Err(format!("{msg_type} permanently rejected: {reason}").into())
        }
        RetryOutcome::GaveUp => Err(format!("{msg_type} retry gave up at its deadline").into()),
    }
}

#[cfg(test)]
mod fixture {
    //! A reusable channel test fixture: `n` federation keys over one first-light
    //! vault, the derived channel keys, a computed manifest_hash, and per-node
    //! endorsements — everything the `[channel]` config and a real `Node` need.

    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::{sha256, Hash};
    use bitcoin::hex::DisplayHex;
    use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
    use bitcoin::sighash::SighashCache;
    use bitcoin::transaction::Version;
    use bitcoin::{
        ecdsa, Amount, EcdsaSighashType, OutPoint, Psbt, PublicKey, ScriptBuf, Sequence,
        Transaction, TxIn, TxOut, Txid, Witness,
    };
    use miniscript::{Descriptor, DescriptorPublicKey};
    use std::str::FromStr;
    use vault_proto::SignRequest;

    pub(crate) fn keypair(seed: u8) -> (SecretKey, PublicKey) {
        let sk = SecretKey::from_slice(&[seed; 32]).expect("valid sk");
        (
            sk,
            PublicKey::new(sk.public_key(&Secp256k1::signing_only())),
        )
    }

    /// One resolved membership entry (by node_id).
    pub(crate) struct Entry {
        pub(crate) node_id: u16,
        pub(crate) fed_sk: SecretKey,
        pub(crate) fed_pk: PublicKey,
        pub(crate) channel_pk: PublicKey,
        pub(crate) endpoints: Vec<String>,
        pub(crate) endorsement_hex: String,
    }

    pub(crate) struct Fixture {
        pub(crate) user_sk: SecretKey,
        pub(crate) user_pk: PublicKey,
        /// The vault's one coordinator auth identity (ADR-0013 §2/§4): its public
        /// half is hashed into `manifest_hash` and provisioned into every config
        /// this fixture emits; its secret half signs the requests these tests send,
        /// so each one passes the ingress coord-auth gate.
        pub(crate) coord_sk: SecretKey,
        pub(crate) coord_pk: PublicKey,
        pub(crate) descriptor: String,
        pub(crate) witness_script: ScriptBuf,
        pub(crate) wallet_id: [u8; 32],
        pub(crate) manifest_hash: [u8; 32],
        pub(crate) hot_desc: String,
        pub(crate) hot_spk: ScriptBuf,
        pub(crate) escape_desc: String,
        pub(crate) escape_spk: ScriptBuf,
        pub(crate) vault_spk: ScriptBuf,
        pub(crate) entries: Vec<Entry>,
        pub(crate) ports: Vec<u16>,
    }

    impl Fixture {
        /// `t`-of-`n` fixture with explicit listen ports (endpoint = 127.0.0.1:port).
        pub(crate) fn with_ports(t: usize, ports: &[u16]) -> Fixture {
            Fixture::with_ports_seed(t, ports, 0xF0, 1)
        }

        /// A DISTINCT-vault fixture (different user + federation keys ⇒ different
        /// descriptor ⇒ different `wallet_id`), for the cross-vault reject test.
        pub(crate) fn other_vault(t: usize, ports: &[u16]) -> Fixture {
            Fixture::with_ports_seed(t, ports, 0xE0, 100)
        }

        fn with_ports_seed(t: usize, ports: &[u16], user_seed: u8, fed_base: u8) -> Fixture {
            let n = ports.len();
            let (user_sk, user_pk) = keypair(user_seed);
            // The coordinator this fixture's vault is sealed to. Seeded off
            // `user_seed` so a distinct vault also has a distinct coordinator.
            let (coord_sk, coord_pk) = keypair(user_seed.wrapping_add(0x0C));
            let feds: Vec<(SecretKey, PublicKey)> =
                (0..n as u8).map(|i| keypair(fed_base + i)).collect();
            let node_pubkeys: Vec<String> = feds.iter().map(|(_, pk)| pk.to_string()).collect();
            // Throwaway 2-of-3 recovery keyset (seeds 0x30..=0x32), off the normal
            // path these channel tests drive. The node validates the two-branch
            // template (ADR-0013 §1) at startup; the recovery keys never sign here.
            let recovery: Vec<String> = (0x30u8..=0x32).map(|i| keypair(i).1.to_string()).collect();
            let descriptor_str = policy_core::vault_descriptor_string(
                &user_pk.to_string(),
                t,
                &node_pubkeys,
                &recovery,
            );
            let descriptor =
                Descriptor::<PublicKey>::from_str(&descriptor_str).expect("descriptor");
            let canonical = descriptor.to_string();
            let witness_script = descriptor.explicit_script().expect("witness script");
            let vault_spk = ScriptBuf::new_p2wsh(&witness_script.wscript_hash());
            let wallet_id = sha256::Hash::hash(canonical.as_bytes()).to_byte_array();

            let (_, hot_pk) = keypair(0xA0);
            let (_, escape_pk) = keypair(0xB0);
            let hot_desc = Descriptor::<DescriptorPublicKey>::from_str(&format!("wpkh({hot_pk})"))
                .expect("hot")
                .to_string();
            let escape_desc =
                Descriptor::<DescriptorPublicKey>::from_str(&format!("wpkh({escape_pk})"))
                    .expect("escape")
                    .to_string();
            let hot_spk = Descriptor::<PublicKey>::from_str(&format!("wpkh({hot_pk})"))
                .expect("hot p")
                .script_pubkey();
            let escape_spk = Descriptor::<PublicKey>::from_str(&format!("wpkh({escape_pk})"))
                .expect("escape p")
                .script_pubkey();

            // Canonical node order: lexicographic over the key-expression string.
            let mut order: Vec<usize> = (0..n).collect();
            order.sort_by(|&a, &b| feds[a].1.to_string().cmp(&feds[b].1.to_string()));

            let mut nodes: Vec<ManifestNode> = Vec::new();
            let mut chan: Vec<(SecretKey, PublicKey)> = Vec::new();
            for (node_id, &fed_idx) in order.iter().enumerate() {
                let (fsk, fpk) = feds[fed_idx];
                let csk = derive_channel_seckey(&fsk);
                let cpk = channel_pubkey_of(&csk);
                chan.push((csk, cpk));
                nodes.push(ManifestNode {
                    node_id: node_id as u16,
                    signing_pubkey: fpk,
                    channel_pubkey: cpk,
                    endpoints: vec![format!("127.0.0.1:{}", ports[node_id])],
                });
            }
            let manifest_hash =
                compute_manifest_hash(&wallet_id, PROTOCOL_VERSION_V0, &coord_pk, &nodes);

            let mut entries = Vec::new();
            for (node_id, &fed_idx) in order.iter().enumerate() {
                let (fsk, fpk) = feds[fed_idx];
                let (_, cpk) = chan[node_id];
                let digest = endorsement_digest(
                    &wallet_id,
                    &manifest_hash,
                    node_id as u16,
                    &cpk,
                    PROTOCOL_VERSION_V0,
                    &nodes[node_id].endpoints,
                );
                let sig = Secp256k1::signing_only().sign_ecdsa(&Message::from_digest(digest), &fsk);
                entries.push(Entry {
                    node_id: node_id as u16,
                    fed_sk: fsk,
                    fed_pk: fpk,
                    channel_pk: cpk,
                    endpoints: nodes[node_id].endpoints.clone(),
                    endorsement_hex: to_hex(&sig.serialize_der()),
                });
            }

            Fixture {
                user_sk,
                user_pk,
                coord_sk,
                coord_pk,
                descriptor: canonical,
                witness_script,
                wallet_id,
                manifest_hash,
                hot_desc,
                hot_spk,
                escape_desc,
                escape_spk,
                vault_spk,
                entries,
                ports: ports.to_vec(),
            }
        }

        pub(crate) fn new(t: usize, n: usize) -> Fixture {
            let ports: Vec<u16> = (0..n as u16).map(|i| 9000 + i).collect();
            Fixture::with_ports(t, &ports)
        }

        /// Replace one node's endorsed endpoint set and rebuild the manifest plus
        /// every endorsement. Tests use this to exercise multi-endpoint failover
        /// without weakening the production endpoint/endorsement invariants.
        pub(crate) fn replace_endpoints(&mut self, node_id: u16, endpoints: Vec<String>) {
            self.entries[node_id as usize].endpoints = endpoints;
            let nodes: Vec<ManifestNode> = self
                .entries
                .iter()
                .map(|e| ManifestNode {
                    node_id: e.node_id,
                    signing_pubkey: e.fed_pk,
                    channel_pubkey: e.channel_pk,
                    endpoints: e.endpoints.clone(),
                })
                .collect();
            self.manifest_hash =
                compute_manifest_hash(&self.wallet_id, PROTOCOL_VERSION_V0, &self.coord_pk, &nodes);
            for entry in &mut self.entries {
                let digest = endorsement_digest(
                    &self.wallet_id,
                    &self.manifest_hash,
                    entry.node_id,
                    &entry.channel_pk,
                    PROTOCOL_VERSION_V0,
                    &entry.endpoints,
                );
                let sig = Secp256k1::signing_only()
                    .sign_ecdsa(&Message::from_digest(digest), &entry.fed_sk);
                entry.endorsement_hex = to_hex(&sig.serialize_der());
            }
        }

        /// The `[channel]` TOML block for `self_id`, with `opts` (scalar overrides)
        /// spliced in before the `[[channel.nodes]]` array-of-tables.
        pub(crate) fn channel_block(&self, self_id: u16, opts: &str) -> String {
            let mut s = format!("[channel]\nnode_id = {self_id}\n{opts}");
            for e in &self.entries {
                let eps: Vec<String> = e.endpoints.iter().map(|ep| format!("\"{ep}\"")).collect();
                s += &format!(
                    "\n[[channel.nodes]]\nnode_id = {}\nsigning_pubkey = \"{}\"\nchannel_pubkey = \"{}\"\nchannel_endorsement = \"{}\"\nendpoints = [{}]\n",
                    e.node_id,
                    e.fed_pk,
                    e.channel_pk,
                    e.endorsement_hex,
                    eps.join(", "),
                );
            }
            s
        }

        /// A full node config for `self_id` (with `[channel]`).
        pub(crate) fn config(&self, self_id: u16, hold_secs: u64, opts: &str) -> String {
            self.config_with_channel(self_id, hold_secs, &self.channel_block(self_id, opts))
        }

        /// A full node config with an arbitrary channel section (or none).
        pub(crate) fn config_with_channel(
            &self,
            self_id: u16,
            hold_secs: u64,
            channel: &str,
        ) -> String {
            let e = &self.entries[self_id as usize];
            // `[chain_backend]` is present on every fixture config because channel
            // mode REQUIRES one: the nodes combine and broadcast, so a channel node
            // with no chain view of its own is a fatal misconfiguration. Nothing
            // here ever dials it — only `spawn_drivers` does, which these tests do
            // not call — so the address only has to parse. Table headers end the
            // top-level section, so it and `{channel}` come last.
            format!(
                "listen_port = {}\nnode_seckey = \"{}\"\ndescriptor = \"{}\"\nallowlist = [\"{}\", \"{}\"]\nescape_descriptor = \"{}\"\nmax_derivation_index = 5\nhold_secs = {hold_secs}\nmax_commitment_age_secs = 172800\npolicy_version = 1\npin_normal_hash = \"{}\"\npin_duress_hash = \"{}\"\ncoordinator_auth_pubkey = \"{}\"\n\n[chain_backend]\nrpc_addr = \"127.0.0.1:18443\"\nauth = \"dGVzdDp0ZXN0\"\n\n{channel}",
                self.ports[self_id as usize],
                e.fed_sk.display_secret(),
                self.descriptor,
                self.hot_desc,
                self.escape_desc,
                self.escape_desc,
                crate::argon2id_normal_phc("1234"),
                crate::argon2id_duress_phc("9999"),
                self.coord_pk,
            )
        }

        /// Attach a fresh `nonce` and this vault's coordinator signature over the
        /// canonical request bytes (ADR-0013 §2) — what vault-cli does before every
        /// relay. Channel tests reach the node through the real `/sign` ingress, so
        /// each request must clear the coord-auth gate to register a candidate.
        /// `nonce_seed` only has to be unique per request within a test: a
        /// coordinator nonce is single-use, so a repeat is a replay by definition.
        pub(crate) fn coord_sign(&self, request: &mut SignRequest, nonce_seed: &str) {
            request.nonce = nonce_seed.to_string();
            // coord_sig is never part of its own preimage; no clearing needed.
            let digest = request.coord_request().auth_digest();
            let sig =
                Secp256k1::signing_only().sign_ecdsa(&Message::from_digest(digest), &self.coord_sk);
            request.coord_sig = sig.serialize_der().to_lower_hex_string();
        }

        /// A coordinator-authenticated `SpendRequest` for `spend`, carrying the
        /// mandatory escape over the same input. Every `SpendRequest` needs a real
        /// escape-class escape (§4), so this is how channel tests reach `/sign`.
        pub(crate) fn spend_request(
            &self,
            spend: &Psbt,
            expiry: u64,
            nonce_seed: &str,
        ) -> SignRequest {
            let input_txid = spend.unsigned_tx.input[0]
                .previous_output
                .txid
                .to_byte_array()[0];
            let escape = self.spend_psbt(&self.escape_spk, input_txid);
            let mut request = SignRequest {
                psbt: spend.to_string(),
                escape_psbt: escape.to_string(),
                pin: "1234".into(),
                nonce: String::new(),
                expiry,
                policy_version: 1,
                coord_sig: String::new(),
            };
            self.coord_sign(&mut request, nonce_seed);
            request
        }

        /// A user-signed spend PSBT paying `dest_spk`, spending the single vault
        /// UTXO at `outpoint` — for the chained-parent tests, where the input has
        /// to be a specific transaction's output.
        pub(crate) fn spend_psbt_over(&self, dest_spk: &ScriptBuf, outpoint: OutPoint) -> Psbt {
            let mut psbt = self.spend_psbt(dest_spk, 0);
            psbt.unsigned_tx.input[0].previous_output = outpoint;
            self.user_sign_all(&mut psbt);
            psbt
        }

        /// A user-signed TWO-input vault spend paying `dest_spk` — the shape the
        /// per-input quorum rule is about.
        pub(crate) fn two_input_spend_psbt(&self, dest_spk: &ScriptBuf) -> Psbt {
            let mut psbt = self.spend_psbt(dest_spk, 7);
            psbt.unsigned_tx.input.push(TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([8; 32]), 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            });
            let second = psbt.inputs[0].clone();
            psbt.inputs.push(second);
            psbt.unsigned_tx.output[0].value = Amount::from_sat(199_990_000);
            self.user_sign_all(&mut psbt);
            psbt
        }

        /// Re-sign every input with the user key over the CURRENT unsigned tx —
        /// any structural edit above invalidates the signature `spend_psbt` made.
        fn user_sign_all(&self, psbt: &mut Psbt) {
            let unsigned = psbt.unsigned_tx.clone();
            let mut cache = SighashCache::new(&unsigned);
            for (index, input) in psbt.inputs.iter_mut().enumerate() {
                let value = input.witness_utxo.as_ref().expect("witness_utxo").value;
                let sighash = cache
                    .p2wsh_signature_hash(index, &self.witness_script, value, EcdsaSighashType::All)
                    .expect("sighash");
                let sig = Secp256k1::signing_only().sign_ecdsa(
                    &Message::from_digest(sighash.to_byte_array()),
                    &self.user_sk,
                );
                input.partial_sigs.clear();
                input.partial_sigs.insert(
                    self.user_pk,
                    ecdsa::Signature {
                        signature: sig,
                        sighash_type: EcdsaSighashType::All,
                    },
                );
            }
        }

        /// A user-signed spend PSBT paying `dest_spk`, spending one vault UTXO at
        /// `input_txid:0`.
        pub(crate) fn spend_psbt(&self, dest_spk: &ScriptBuf, input_txid: u8) -> Psbt {
            let tx = Transaction {
                version: Version::TWO,
                lock_time: LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint::new(Txid::from_byte_array([input_txid; 32]), 0),
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                output: vec![TxOut {
                    script_pubkey: dest_spk.clone(),
                    value: Amount::from_sat(99_990_000),
                }],
            };
            let mut psbt = Psbt::from_unsigned_tx(tx).expect("unsigned tx");
            let value = Amount::from_sat(100_000_000);
            psbt.inputs[0].witness_utxo = Some(TxOut {
                script_pubkey: self.vault_spk.clone(),
                value,
            });
            psbt.inputs[0].witness_script = Some(self.witness_script.clone());
            let sighash = SighashCache::new(&psbt.unsigned_tx)
                .p2wsh_signature_hash(0, &self.witness_script, value, EcdsaSighashType::All)
                .expect("sighash");
            let sig = Secp256k1::signing_only().sign_ecdsa(
                &Message::from_digest(sighash.to_byte_array()),
                &self.user_sk,
            );
            psbt.inputs[0].partial_sigs.insert(
                self.user_pk,
                ecdsa::Signature {
                    signature: sig,
                    sighash_type: EcdsaSighashType::All,
                },
            );
            psbt
        }

        /// Build a spend-role `Candidate` from a PSBT (this node's own view),
        /// UNSCHEDULED — no fire window, so its partials can never be released.
        /// Models a freshly-registered candidate awaiting peer partials. The
        /// registry tests are about storage and verification, not the fire path —
        /// the `fire` module drives that through the real `/sign` ingress, which is
        /// the only thing that schedules a candidate in production.
        pub(crate) fn candidate(&self, psbt: &Psbt, commitment_id: &str, expiry: u64) -> Candidate {
            Candidate::build(
                CandidateSpec {
                    psbt,
                    commitment_id,
                    // These fixtures register one candidate at a time, so it is its
                    // own pair; `register_pair` is what builds real pairs.
                    paired_commitment_id: commitment_id,
                    role: CandidateRole::Spend,
                    // UNSCHEDULED: nothing here can release a partial.
                    fire: None,
                    expiry,
                },
                &CandidateKeys {
                    witness_script: &self.witness_script,
                    user_pubkey: &self.user_pk,
                    self_signing_pubkey: &self.entries[0].fed_pk,
                },
            )
            .expect("candidate")
        }

        /// A correct `partial` payload from `signer_id` over `psbt`'s `input`.
        pub(crate) fn partial_payload(
            &self,
            psbt: &Psbt,
            commitment_id: &str,
            input: u32,
            signer_id: u16,
        ) -> PartialPayload {
            let c = self.candidate(psbt, commitment_id, u64::MAX);
            let der = self.partial_der(psbt, input, signer_id);
            PartialPayload {
                commitment_id: commitment_id.to_string(),
                wallet_id: to_hex(&self.wallet_id),
                txid: c.unsigned_txid.to_string(),
                input,
                signer_node_id: signer_id,
                sighash_type: EcdsaSighashType::All.to_u32(),
                spend_purpose: "hot".to_string(),
                user_sig_hash: to_hex(&c.user_sig_hash),
                partial_sig: to_hex(&der),
            }
        }

        /// `signer_id`'s DER signature over `psbt`'s `input` sighash.
        pub(crate) fn partial_der(&self, psbt: &Psbt, input: u32, signer_id: u16) -> Vec<u8> {
            let value = psbt.inputs[input as usize]
                .witness_utxo
                .as_ref()
                .expect("witness_utxo")
                .value;
            let sighash = SighashCache::new(&psbt.unsigned_tx)
                .p2wsh_signature_hash(
                    input as usize,
                    &self.witness_script,
                    value,
                    EcdsaSighashType::All,
                )
                .expect("sighash");
            let sk = self.entries[signer_id as usize].fed_sk;
            Secp256k1::signing_only()
                .sign_ecdsa(&Message::from_digest(sighash.to_byte_array()), &sk)
                .serialize_der()
                .to_vec()
        }

        /// Build a `ChannelState` for `self_id` directly (validates the manifest).
        pub(crate) fn channel_state(&self, self_id: u16) -> ChannelState {
            let node = crate::Node::from_toml_str(&self.config(self_id, 0, ""))
                .expect("valid channel config");
            node.channel.expect("channel present")
        }
    }

    /// Envelope `payload` from `sender` to `receiver` at (`ts`) and ingest at (`now`).
    pub(crate) fn deliver(
        sender: &ChannelState,
        receiver: &ChannelState,
        msg_type: &str,
        payload: &[u8],
        ts: u64,
        now: u64,
    ) -> ChannelReply {
        let env = sender
            .build_envelope(msg_type, receiver.node_id, payload, ts)
            .expect("envelope");
        receiver.ingest_reply(&serde_json::to_vec(&env).expect("json"), now)
    }
}

#[cfg(test)]
mod golden {
    //! FROZEN golden vectors (codex B3): per digest, BOTH the expected canonical
    //! preimage bytes AND the resulting digest are hard-coded, so a common-mode
    //! omission (e.g. signer AND verifier both dropping `nonce`) that a
    //! digest-only vector would bless is caught — the preimage bytes change.
    use super::*;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use bitcoin::PublicKey;

    fn pk(seed: u8) -> PublicKey {
        let sk = SecretKey::from_slice(&[seed; 32]).expect("sk");
        PublicKey::new(sk.public_key(&Secp256k1::signing_only()))
    }

    #[test]
    fn channel_key_vector_is_frozen() {
        let sk = [0x11u8; 32];
        assert_eq!(
            to_hex(&sk),
            "1111111111111111111111111111111111111111111111111111111111111111"
        );
        let dig = tagged_hash(CHANNEL_KEY_TAG, &sk);
        assert_eq!(
            to_hex(&dig),
            "39d6dee9b0db353e509ef6daa3885eccb21dc01b4b471369b98cd6f3253f20c7"
        );
        // For this seed the digest is a valid scalar, so the derived key == digest.
        let derived = derive_channel_seckey(&SecretKey::from_slice(&sk).expect("sk"));
        assert_eq!(derived.secret_bytes(), dig);
    }

    #[test]
    fn manifest_vector_is_frozen() {
        let wallet_id = [0x22u8; 32];
        let nodes = vec![
            ManifestNode {
                node_id: 0,
                signing_pubkey: pk(1),
                channel_pubkey: pk(2),
                endpoints: vec!["127.0.0.1:9000".to_string()],
            },
            ManifestNode {
                node_id: 1,
                signing_pubkey: pk(3),
                channel_pubkey: pk(4),
                endpoints: vec!["127.0.0.1:9001".to_string()],
            },
        ];
        // The frozen provisional BaseManifest-slice preimage (ADR-0013 §4):
        // wallet_id[32], protocol_version:u32, coordinator_auth_pubkey[33],
        // node-count:u32, then each node by id. The coordinator key is
        // unconditional — every vault is sealed to exactly one coordinator — so
        // it always occupies offsets 36..69.
        let coord = pk(0xC0);
        let bytes = base_manifest_bytes(&wallet_id, PROTOCOL_VERSION_V0, &coord, &nodes);
        assert_eq!(to_hex(&bytes), "222222222222222222222222222222222222222222222222222222222222222200000000038a3ba5c99568d26602f4cf8038371da3c86057a96eb1b6a8de1b4f1be723c236020000000000031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766010000000e0000003132372e302e302e313a39303030010002531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe33703462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b010000000e0000003132372e302e302e313a39303031");
        assert_eq!(
            bytes[36..69],
            coord.inner.serialize(),
            "the coordinator key is hashed in right after protocol_version"
        );
        assert_eq!(
            to_hex(&tagged_hash(MANIFEST_TAG, &bytes)),
            "29d43399286922650ae70120fa4a954843a7e083c46219f999501c088f406312"
        );
    }

    #[test]
    fn manifest_hash_changes_when_the_coordinator_key_changes() {
        // The acceptance property (ADR-0013 §4/§7): the coordinator_auth_pubkey is
        // in the hashed BaseManifest, so swapping the coordinator — with the
        // membership held identical — is a DIFFERENT vault. This is what makes
        // "rotation = new vault" structural rather than a matter of policy.
        let wallet_id = [0x22u8; 32];
        let nodes = vec![ManifestNode {
            node_id: 0,
            signing_pubkey: pk(1),
            channel_pubkey: pk(2),
            endpoints: vec!["127.0.0.1:9000".to_string()],
        }];
        let with_a = compute_manifest_hash(&wallet_id, PROTOCOL_VERSION_V0, &pk(0xC0), &nodes);
        let with_b = compute_manifest_hash(&wallet_id, PROTOCOL_VERSION_V0, &pk(0xC1), &nodes);
        assert_ne!(
            with_a, with_b,
            "a different coordinator key ⇒ a different vault"
        );
    }

    #[test]
    fn endorsement_vector_is_frozen() {
        let pre = endorsement_bytes(
            &[0x22u8; 32],
            &[0x33u8; 32],
            1,
            &pk(4),
            PROTOCOL_VERSION_V0,
            &["127.0.0.1:9001".to_string()],
        );
        assert_eq!(to_hex(&pre), "22222222222222222222222222222222222222222222222222222222222222223333333333333333333333333333333333333333333333333333333333333333010003462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b00000000010000000e0000003132372e302e302e313a39303031");
        assert_eq!(
            to_hex(&tagged_hash(ENDORSEMENT_TAG, &pre)),
            "51faa376da7236f11c41b5ceeda907bdf4bc67ab58de9a11fb5cf8f828f73acd"
        );
    }

    #[test]
    fn envelope_vector_is_frozen() {
        let pre = envelope_preimage(
            "partial",
            PROTOCOL_VERSION_V0,
            &[0x22u8; 32],
            &[0x33u8; 32],
            1,
            2,
            b"cGFydGlhbA==",
            &[0x44u8; 16],
            1_752_000_000,
        );
        assert_eq!(to_hex(&pre), "070000007061727469616c0000000022222222222222222222222222222222222222222222222222222222222222223333333333333333333333333333333333333333333333333333333333333333010002000c0000006347467964476c6862413d3d100000004444444444444444444444444444444400666d6800000000");
        assert_eq!(
            to_hex(&tagged_hash(ENVELOPE_TAG, &pre)),
            "fb179a1687044a0eb2169ceaee3368df72982e633355b887bfc80580cb9b951a"
        );
    }

    #[test]
    fn user_sig_hash_vector_is_frozen() {
        let der: [u8; 8] = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];
        let mut usig = Enc::new();
        usig.var(&der);
        usig.u8(1);
        assert_eq!(to_hex(&usig.0), "08000000300602010102010101");
        assert_eq!(
            to_hex(&tagged_hash(USER_SIG_HASH_TAG, &usig.0)),
            "23a1d6d547854d3b3729083060a4f454fd21ab87a3b1784ffd541bd076cba457"
        );
    }
}

#[cfg(test)]
mod identity {
    //! Channel identity + manifest/startup invariants (§1/§2).
    use super::fixture::{keypair, Fixture};
    use super::*;
    use bitcoin::secp256k1::{Message, Secp256k1};

    #[test]
    fn channel_key_is_a_pure_function_and_differs_from_the_signing_key() {
        let (sk, pk) = keypair(7);
        let a = derive_channel_seckey(&sk);
        let b = derive_channel_seckey(&sk);
        // Same input ⇒ same channel key (deterministic).
        assert_eq!(a.secret_bytes(), b.secret_bytes());
        // The channel pubkey differs from the signing pubkey.
        assert_ne!(channel_pubkey_of(&a), pk);
    }

    #[test]
    fn a_valid_channel_config_builds() {
        let fx = Fixture::new(2, 3);
        let node = crate::Node::from_toml_str(&fx.config(0, 0, "")).expect("valid config");
        assert!(node.channel.is_some());
    }

    /// Channel mode is what makes a node responsible for BROADCASTING (§5), so a
    /// channel node with no chain view of its own must not boot: it would
    /// authenticate, sign at ingress, reach quorum, and then silently never
    /// broadcast while every `/sign` answer claimed the spend was accepted — a
    /// failure invisible until the user noticed the money never moved.
    ///
    /// The input is the config `a_valid_channel_config_builds` accepts, with only
    /// the `[chain_backend]` block removed, so the missing backend is the sole
    /// variable — this cannot pass because some *other* part of the config went
    /// bad, which is exactly the risk in asserting a fatal.
    #[test]
    fn channel_mode_without_a_chain_backend_is_fatal() {
        let fx = Fixture::new(2, 3);
        let valid = fx.config(0, 0, "");
        let stripped = valid.replace(
            "[chain_backend]\nrpc_addr = \"127.0.0.1:18443\"\nauth = \"dGVzdDp0ZXN0\"\n",
            "",
        );
        assert_ne!(
            stripped, valid,
            "the fixture no longer carries the [chain_backend] block this test strips"
        );
        let err = crate::Node::from_toml_str(&stripped)
            .err()
            .expect("a channel node with no chain backend must fail startup")
            .to_string();
        assert!(
            err.contains("[channel] mode requires a [chain_backend]"),
            "the fatal must name the missing backend, not some other defect: {err}"
        );
    }

    #[test]
    fn an_oversized_concurrency_limit_is_a_config_error_not_a_panic() {
        let fx = Fixture::new(2, 3);
        let cfg = fx.config(
            0,
            0,
            &format!(
                "max_concurrent_channel_requests = {}\n",
                Semaphore::MAX_PERMITS + 1
            ),
        );
        let err = crate::Node::from_toml_str(&cfg)
            .err()
            .expect("oversized semaphore limit must fail startup");
        assert!(
            err.to_string()
                .contains("max_concurrent_channel_requests exceeds"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn a_zero_per_send_deadline_is_a_config_error_not_a_silent_broadcast_trap() {
        // A zero send deadline gives every outbound envelope a zero-duration
        // timeout, so no request or partial ever reaches a peer and no spend can
        // ever combine or broadcast — an invisible failure. It must be fatal at
        // load, exactly like `combine_slack_secs = 0` and a missing chain backend.
        let fx = Fixture::new(2, 3);
        let cfg = fx.config(0, 0, "per_send_deadline_secs = 0\n");
        let err = crate::Node::from_toml_str(&cfg)
            .err()
            .expect("a zero per_send_deadline_secs must fail startup");
        assert!(
            err.to_string()
                .contains("per_send_deadline_secs must be greater than 0"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn a_signing_key_not_in_the_descriptor_fails_startup() {
        // Swap node 0's config signing_pubkey for a stranger — the node_id ↔
        // descriptor-key bijection breaks (fatal), never a runtime refusal.
        let fx = Fixture::new(2, 3);
        let (_, stranger) = keypair(0xEE);
        let cfg = fx.config(0, 0, "");
        // Swap ONLY node 0's manifest signing_pubkey (leave the descriptor intact),
        // so its node_id ↔ descriptor-key mapping breaks.
        let victim = fx.entries[0].fed_pk.to_string();
        let broken = cfg.replacen(
            &format!("signing_pubkey = \"{victim}\""),
            &format!("signing_pubkey = \"{stranger}\""),
            1,
        );
        let err = crate::Node::from_toml_str(&broken)
            .err()
            .expect("must fail startup");
        assert!(
            err.to_string().contains("canonical node key"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn duplicate_descriptor_node_keys_fail_startup() {
        // A repeated federation key cannot occupy two node_id slots: one key
        // holder would otherwise authenticate as two peers and receive two quotas.
        let fx = Fixture::new(2, 3);
        let cfg = fx.config(0, 0, "");
        // A two-branch template whose NORMAL branch repeats a federation key. Since
        // V0-10 the policy-core template check rejects duplicate keys outright (the
        // permanent trust root must have distinct keys), so the duplicate is caught
        // at descriptor parse — earlier than, and in addition to, the node_id
        // bijection check that remains as a backstop.
        let recovery: Vec<String> = (0x30u8..=0x32).map(|i| keypair(i).1.to_string()).collect();
        let dup_nodes = vec![
            fx.entries[0].fed_pk.to_string(),
            fx.entries[0].fed_pk.to_string(),
            fx.entries[2].fed_pk.to_string(),
        ];
        let duplicate_descriptor =
            policy_core::vault_descriptor_string(&fx.user_pk.to_string(), 2, &dup_nodes, &recovery);
        let duplicate = cfg.replacen(
            &format!("descriptor = \"{}\"", fx.descriptor),
            &format!("descriptor = \"{duplicate_descriptor}\""),
            1,
        );
        let err = crate::Node::from_toml_str(&duplicate)
            .err()
            .expect("duplicate descriptor node keys must fail startup");
        assert!(
            err.to_string().contains("appears more than once")
                || err.to_string().contains("duplicate federation node key"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn manifest_hash_is_stable_across_node_order_permutations() {
        // The manifest hash is over nodes ordered by node_id, so the CONFIG order
        // of `[[channel.nodes]]` entries must not change it.
        let fx = Fixture::new(2, 3);
        let base = fx.channel_state(0).manifest_hash;
        // Reverse the config entry order; build must reorder by node_id and hash
        // identically.
        let mut reversed = String::from("[channel]\nnode_id = 0\n");
        for e in fx.entries.iter().rev() {
            let eps: Vec<String> = e.endpoints.iter().map(|ep| format!("\"{ep}\"")).collect();
            reversed += &format!(
                "\n[[channel.nodes]]\nnode_id = {}\nsigning_pubkey = \"{}\"\nchannel_pubkey = \"{}\"\nchannel_endorsement = \"{}\"\nendpoints = [{}]\n",
                e.node_id, e.fed_pk, e.channel_pk, e.endorsement_hex, eps.join(", "),
            );
        }
        let cfg = fx.config_with_channel(0, 0, &reversed);
        let node = crate::Node::from_toml_str(&cfg).expect("valid config");
        assert_eq!(node.channel.expect("channel").manifest_hash, base);
    }

    #[test]
    fn an_endorsement_over_the_wrong_manifest_hash_is_rejected() {
        // Re-sign node 0's endorsement over a DIFFERENT manifest_hash: build must
        // reject it (the endorsement domain binds manifest_hash).
        let fx = Fixture::new(2, 3);
        let wrong_hash = [0x9au8; 32];
        let e = &fx.entries[0];
        let digest = endorsement_digest(
            &fx.wallet_id,
            &wrong_hash,
            0,
            &e.channel_pk,
            PROTOCOL_VERSION_V0,
            &e.endpoints,
        );
        let bad = Secp256k1::signing_only().sign_ecdsa(&Message::from_digest(digest), &e.fed_sk);
        let cfg =
            fx.config(0, 0, "")
                .replacen(&e.endorsement_hex, &to_hex(&bad.serialize_der()), 1);
        let err = crate::Node::from_toml_str(&cfg).err().expect("must reject");
        assert!(err.to_string().contains("endorsement"), "unexpected: {err}");
    }

    #[test]
    fn an_endorsement_by_a_non_member_key_is_rejected() {
        // Node 0's channel key endorsed by a stranger key (not the descriptor's
        // node key) → rejected: the endorsement must verify against the in-manifest
        // signing key.
        let fx = Fixture::new(2, 3);
        let (stranger_sk, _) = keypair(0xCD);
        let e = &fx.entries[0];
        let digest = endorsement_digest(
            &fx.wallet_id,
            &fx.manifest_hash,
            0,
            &e.channel_pk,
            PROTOCOL_VERSION_V0,
            &e.endpoints,
        );
        let bad = Secp256k1::signing_only().sign_ecdsa(&Message::from_digest(digest), &stranger_sk);
        let cfg =
            fx.config(0, 0, "")
                .replacen(&e.endorsement_hex, &to_hex(&bad.serialize_der()), 1);
        let err = crate::Node::from_toml_str(&cfg).err().expect("must reject");
        assert!(err.to_string().contains("endorsement"), "unexpected: {err}");
    }

    #[test]
    fn expected_manifest_hash_seals_the_node_to_a_specific_manifest() {
        let fx = Fixture::new(2, 3);
        // Correct sealed hash builds; a wrong one is fatal.
        let ok = fx.config(
            0,
            0,
            &format!(
                "expected_manifest_hash = \"{}\"\n",
                to_hex(&fx.manifest_hash)
            ),
        );
        assert!(crate::Node::from_toml_str(&ok).is_ok());
        let bad = fx.config(
            0,
            0,
            &format!("expected_manifest_hash = \"{}\"\n", to_hex(&[0u8; 32])),
        );
        let err = crate::Node::from_toml_str(&bad)
            .err()
            .expect("sealed mismatch");
        assert!(err.to_string().contains("sealed"), "unexpected: {err}");
    }

    #[test]
    fn a_coordinator_key_that_is_a_peers_channel_key_is_fatal() {
        // The channel half of the cross-role check `Node::from_toml_str` runs over
        // the descriptor's keys. A node derives its channel seckey from its
        // federation seckey, so a channel_pubkey doubling as the coordinator auth
        // key hands that one node the power to mint coordinator requests for the
        // whole vault — the exact isolation this trust root exists to provide.
        let fx = Fixture::new(2, 3);
        let cfg = fx.config(0, 0, "").replace(
            &fx.coord_pk.to_string(),
            &fx.entries[1].channel_pk.to_string(),
        );
        let err = crate::Node::from_toml_str(&cfg)
            .err()
            .expect("a channel key must be refused as the coordinator key");
        assert!(
            err.to_string()
                .contains("channel_pubkey is also the coordinator_auth_pubkey"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn a_coordinator_key_that_is_the_derived_channel_key_is_fatal_without_a_channel() {
        // Same collapse as the test above, reached with `[channel]` absent — where
        // no manifest, and so no `ChannelState::build`, exists to catch it. The
        // channel key is `derive_channel_seckey(node_seckey)`, a public function of
        // the federation seckey, so pinning it as the coordinator key hands this
        // node's holder coordinator authority over the whole vault while every
        // gate still passes. `Node::from_toml_str` compares its own derived key
        // unconditionally, which is what closes this in absent-channel mode.
        let fx = Fixture::new(2, 3);
        let cfg = fx.config_with_channel(0, 0, "").replace(
            &fx.coord_pk.to_string(),
            &fx.entries[0].channel_pk.to_string(),
        );
        assert!(
            !cfg.contains("[channel]"),
            "this test must exercise the absent-channel path"
        );
        let err = crate::Node::from_toml_str(&cfg)
            .err()
            .expect("the derived channel key must be refused as the coordinator key");
        assert!(
            err.to_string()
                .contains("must not be this node's derived channel key"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn an_uncompressed_channel_key_cannot_disguise_coordinator_key_reuse() {
        let fx = Fixture::new(2, 3);
        let peer = &fx.entries[1];
        let uncompressed_coord = fx
            .coord_pk
            .inner
            .serialize_uncompressed()
            .to_lower_hex_string();
        let cfg =
            fx.config(0, 0, "")
                .replacen(&peer.channel_pk.to_string(), &uncompressed_coord, 1);
        let err = crate::Node::from_toml_str(&cfg)
            .err()
            .expect("the same secp point in another encoding must be refused");
        assert!(
            err.to_string()
                .contains("channel_pubkey is also the coordinator_auth_pubkey"),
            "the cross-role identity check must run before endorsement failure: {err}"
        );
    }

    #[test]
    fn a_sealed_node_will_not_boot_under_a_swapped_coordinator_key() {
        // "Rotation = new vault" (ADR-0013 §7) is ENFORCED, not just stated. The
        // two neighbouring tests each prove one half — that the manifest hash is
        // sensitive to the coordinator key, and that a sealed node dies on a
        // mismatched hash — but neither composes them, and it is the composition
        // that operators actually rely on: you cannot re-point a sealed node at a
        // new coordinator by editing its config. Everything but the coordinator key
        // is held identical here, so nothing else can be producing the refusal.
        let fx = Fixture::new(2, 3);
        let sealed = format!(
            "expected_manifest_hash = \"{}\"\n",
            to_hex(&fx.manifest_hash)
        );
        let rotated = fx
            .config(0, 0, &sealed)
            .replace(&fx.coord_pk.to_string(), &keypair(0xC1).1.to_string());
        let err = crate::Node::from_toml_str(&rotated)
            .err()
            .expect("a sealed node must refuse a rotated coordinator key");
        assert!(err.to_string().contains("sealed"), "unexpected: {err}");
    }

    #[test]
    fn a_local_channel_key_mismatch_is_fatal() {
        // Corrupt node 0's own channel_pubkey entry: its locally-derived channel
        // key won't match, so it would be permanently unreachable → fatal.
        let fx = Fixture::new(2, 3);
        let e = &fx.entries[0];
        let other = fx.entries[1].channel_pk.to_string();
        let cfg = fx
            .config(0, 0, "")
            .replacen(&e.channel_pk.to_string(), &other, 1);
        let err = crate::Node::from_toml_str(&cfg)
            .err()
            .expect("must be fatal");
        // Either the endorsement (over the swapped key) or the self-key check fails.
        assert!(
            err.to_string().contains("endorsement") || err.to_string().contains("channel pubkey"),
            "unexpected: {err}"
        );
    }
}

#[cfg(test)]
impl ChannelState {
    /// [`ChannelState::ingest`] for the envelope tests, which send `partial` and
    /// malformed bodies only: the terminal reply. A `request` envelope has no
    /// terminal reply at this layer BY DESIGN — the node decides it — so one
    /// reaching here is a test wiring mistake, not a case to paper over.
    pub(crate) fn ingest_reply(&self, body: &[u8], now: u64) -> ChannelReply {
        match self.ingest(body, now) {
            Ingested::Reply(reply) => reply,
            Ingested::Request(_) => {
                panic!("a `request` envelope is decided by the node (handle_channel_body)")
            }
        }
    }
    pub(crate) fn store_len(&self) -> usize {
        self.store.lock().expect("store lock").candidates.len()
    }
    /// A candidate's fire window, or `None` when nothing has scheduled it.
    pub(crate) fn fire_window(&self, cid: &str) -> Option<FireWindow> {
        self.store
            .lock()
            .expect("store lock")
            .candidates
            .get(cid)
            .and_then(|c| c.fire)
    }
    /// Whether this node has already released `cid`'s partials.
    pub(crate) fn was_released(&self, cid: &str) -> bool {
        self.store
            .lock()
            .expect("store lock")
            .candidates
            .get(cid)
            .map(|c| c.released)
            .unwrap_or(false)
    }
    pub(crate) fn nonce_len(&self) -> usize {
        self.ingress_guards
            .lock()
            .expect("ingress guards lock")
            .seen_nonces
            .len()
    }
    pub(crate) fn has_candidate(&self, cid: &str) -> bool {
        self.store
            .lock()
            .expect("store lock")
            .candidates
            .contains_key(cid)
    }
    pub(crate) fn partial_stored(&self, cid: &str, input: u32, signer: u16) -> bool {
        self.store
            .lock()
            .expect("store lock")
            .candidates
            .get(cid)
            .map(|c| c.partials.contains_key(&(input, signer)))
            .unwrap_or(false)
    }
    pub(crate) fn stored_partial_der(&self, cid: &str, input: u32, signer: u16) -> Option<Vec<u8>> {
        self.store
            .lock()
            .expect("store lock")
            .candidates
            .get(cid)
            .and_then(|c| c.partials.get(&(input, signer)).cloned())
    }
    pub(crate) fn psbt_has_pubkey(&self, cid: &str, input: u32, pk: &PublicKey) -> bool {
        self.store
            .lock()
            .expect("store lock")
            .candidates
            .get(cid)
            .and_then(|c| c.psbt.inputs.get(input as usize))
            .map(|i| i.partial_sigs.contains_key(pk))
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod ingress {
    //! Every envelope-ingress rejection branch (§3), each its own test.
    use super::fixture::{deliver, Fixture};
    use super::*;
    use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};

    const NOW: u64 = 1_752_000_000;

    fn keypair(seed: u8) -> (SecretKey, bitcoin::PublicKey) {
        super::fixture::keypair(seed)
    }

    /// Build a valid `partial` envelope from `sender` to `recv` and JSON-serialize
    /// it, applying `mutate` to the envelope first.
    fn envelope_bytes(
        fx: &Fixture,
        sender: &ChannelState,
        recv_id: u16,
        cid: &str,
        ts: u64,
        mutate: impl FnOnce(&mut Envelope),
    ) -> Vec<u8> {
        let psbt = fx.spend_psbt(&fx.hot_spk, 7);
        let payload = fx.partial_payload(&psbt, cid, 0, sender.node_id).to_bytes();
        let mut env = sender
            .build_envelope("partial", recv_id, &payload, ts)
            .expect("envelope");
        mutate(&mut env);
        serde_json::to_vec(&env).expect("json")
    }

    #[test]
    fn malformed_json_is_rejected() {
        let fx = Fixture::new(2, 3);
        let recv = fx.channel_state(1);
        assert_eq!(
            recv.ingest_reply(b"definitely not json", NOW),
            ChannelReply::Rejected(RejectReason::MalformedJson)
        );
    }

    #[test]
    fn a_bad_protocol_version_is_rejected() {
        let fx = Fixture::new(2, 3);
        let (send, recv) = (fx.channel_state(0), fx.channel_state(1));
        let bytes = envelope_bytes(&fx, &send, 1, "c", NOW, |e| e.protocol_version = 1);
        assert_eq!(
            recv.ingest_reply(&bytes, NOW),
            ChannelReply::Rejected(RejectReason::BadProtocolVersion)
        );
    }

    #[test]
    fn a_wrong_recipient_is_rejected_closing_cross_recipient_replay() {
        let fx = Fixture::new(2, 3);
        let (send, recv) = (fx.channel_state(0), fx.channel_state(1));
        // A valid envelope DIRECTED at node 2, replayed to node 1, fails the bind.
        let bytes = envelope_bytes(&fx, &send, 2, "c", NOW, |_| {});
        assert_eq!(
            recv.ingest_reply(&bytes, NOW),
            ChannelReply::Rejected(RejectReason::WrongRecipient)
        );
    }

    #[test]
    fn an_unknown_sender_is_rejected() {
        let fx = Fixture::new(2, 3);
        let (send, recv) = (fx.channel_state(0), fx.channel_state(1));
        let bytes = envelope_bytes(&fx, &send, 1, "c", NOW, |e| e.sender_node_id = 99);
        assert_eq!(
            recv.ingest_reply(&bytes, NOW),
            ChannelReply::Rejected(RejectReason::UnknownSender)
        );
    }

    #[test]
    fn a_tampered_payload_b64_fails_the_channel_signature() {
        let fx = Fixture::new(2, 3);
        let (send, recv) = (fx.channel_state(0), fx.channel_state(1));
        // Flip one byte of the SIGNED payload_b64 field — the sig no longer matches.
        let bytes = envelope_bytes(&fx, &send, 1, "c", NOW, |e| {
            let mut b = e.payload_b64.as_bytes().to_vec();
            b[0] ^= 0x01;
            e.payload_b64 = String::from_utf8_lossy(&b).into_owned().into();
        });
        assert_eq!(
            recv.ingest_reply(&bytes, NOW),
            ChannelReply::Rejected(RejectReason::BadChannelSig)
        );
    }

    #[test]
    fn a_cross_vault_wallet_id_is_rejected_before_sender_lookup() {
        // A fully well-formed envelope for a DIFFERENT vault (its own valid sender
        // + endorsement) is refused by the direct local-equality check, independent
        // of endorsement validity.
        let fx1 = Fixture::new(2, 3);
        let fx2 = Fixture::other_vault(2, &[9100, 9101, 9102]);
        let other_sender = fx2.channel_state(0);
        let recv = fx1.channel_state(1);
        let psbt = fx2.spend_psbt(&fx2.hot_spk, 7);
        let payload = fx2.partial_payload(&psbt, "c", 0, 0).to_bytes();
        let env = other_sender
            .build_envelope("partial", 1, &payload, NOW)
            .expect("envelope");
        // fx2.wallet_id != fx1.wallet_id ⇒ WRONG_WALLET, before any sender lookup
        // or endorsement/sig work (the direct local-equality check).
        assert_eq!(
            recv.ingest_reply(&serde_json::to_vec(&env).expect("json"), NOW),
            ChannelReply::Rejected(RejectReason::WrongWallet)
        );
    }

    #[test]
    fn a_foreign_manifest_hash_is_rejected() {
        // Same vault (wallet_id matches), different manifest_hash ⇒ WRONG_MANIFEST.
        let fx = Fixture::new(2, 3);
        let (send, recv) = (fx.channel_state(0), fx.channel_state(1));
        let bytes = envelope_bytes(&fx, &send, 1, "c", NOW, |e| {
            e.manifest_hash = to_hex(&[0x5au8; 32]);
        });
        assert_eq!(
            recv.ingest_reply(&bytes, NOW),
            ChannelReply::Rejected(RejectReason::WrongManifest)
        );
    }

    #[test]
    fn an_envelope_signed_by_the_coordinator_key_is_rejected() {
        // The "coordinator cannot mint a node" property, executable: an envelope
        // whose channel_sig is by a non-endorsed key fails against the manifest
        // channel_pubkey.
        let fx = Fixture::new(2, 3);
        let (send, recv) = (fx.channel_state(0), fx.channel_state(1));
        let (coord_sk, _) = keypair(0xC0);
        let bytes = envelope_bytes(&fx, &send, 1, "c", NOW, |e| {
            let wallet_id = from_hex_32(&e.wallet_id).expect("wid");
            let manifest_hash = from_hex_32(&e.manifest_hash).expect("mh");
            let nonce = from_hex_16(&e.nonce).expect("nonce");
            let preimage = envelope_preimage(
                &e.msg_type,
                e.protocol_version,
                &wallet_id,
                &manifest_hash,
                e.sender_node_id,
                e.recipient_node_id,
                e.payload_b64.as_bytes(),
                &nonce,
                e.timestamp,
            );
            let sig = Secp256k1::signing_only().sign_ecdsa(
                &Message::from_digest(tagged_hash(ENVELOPE_TAG, &preimage)),
                &coord_sk,
            );
            e.channel_sig = to_hex(&sig.serialize_der());
        });
        assert_eq!(
            recv.ingest_reply(&bytes, NOW),
            ChannelReply::Rejected(RejectReason::BadChannelSig)
        );
    }

    #[test]
    fn a_stale_timestamp_is_rejected() {
        let fx = Fixture::new(2, 3);
        let (send, recv) = (fx.channel_state(0), fx.channel_state(1));
        // 400s in the past, outside the 300s past window.
        let bytes = envelope_bytes(&fx, &send, 1, "c", NOW - 400, |_| {});
        assert_eq!(
            recv.ingest_reply(&bytes, NOW),
            ChannelReply::Rejected(RejectReason::StaleTimestamp)
        );
    }

    #[test]
    fn a_future_stamped_nonce_is_retained_until_its_timestamp_leaves_the_window() {
        // A near-future (now+60) envelope is accepted-far-enough to consume its
        // nonce; a replay 60s later (still inside its validity) is caught as replay
        // — pruning by envelope timestamp, not receipt time, closes the ~60s reopen.
        let fx = Fixture::new(2, 3);
        let (send, recv) = (fx.channel_state(0), fx.channel_state(1));
        let psbt = fx.spend_psbt(&fx.hot_spk, 7);
        let payload = fx.partial_payload(&psbt, "c", 0, 0).to_bytes();
        let env = send
            .build_envelope("partial", 1, &payload, NOW + 60)
            .expect("envelope");
        let bytes = serde_json::to_vec(&env).expect("json");
        // First sight at now: passes freshness (ts=now+60), unknown candidate, nonce
        // consumed.
        assert_eq!(
            recv.ingest_reply(&bytes, NOW),
            ChannelReply::UnknownCandidate
        );
        // Replay 60s later, still within the future-stamp's validity → replay.
        assert_eq!(
            recv.ingest_reply(&bytes, NOW + 60),
            ChannelReply::Rejected(RejectReason::ReplayedNonce)
        );
    }

    #[test]
    fn a_replayed_nonce_is_rejected_and_the_cache_prunes_by_timestamp() {
        let fx = Fixture::new(2, 3);
        let (send, recv) = (fx.channel_state(0), fx.channel_state(1));
        let psbt = fx.spend_psbt(&fx.hot_spk, 7);
        let payload = fx.partial_payload(&psbt, "c", 0, 0).to_bytes();
        let env = send
            .build_envelope("partial", 1, &payload, NOW)
            .expect("env");
        let bytes = serde_json::to_vec(&env).expect("json");
        assert_eq!(
            recv.ingest_reply(&bytes, NOW),
            ChannelReply::UnknownCandidate
        );
        assert_eq!(recv.nonce_len(), 1);
        assert_eq!(
            recv.ingest_reply(&bytes, NOW),
            ChannelReply::Rejected(RejectReason::ReplayedNonce)
        );
        // A later fresh envelope prunes the now-old nonce: the set stays bounded.
        let env2 = send
            .build_envelope("partial", 1, &payload, NOW + 400)
            .expect("env2");
        assert_eq!(
            recv.ingest_reply(&serde_json::to_vec(&env2).expect("json"), NOW + 400),
            ChannelReply::UnknownCandidate
        );
        assert_eq!(recv.nonce_len(), 1, "the old nonce pruned by its timestamp");
    }

    #[test]
    fn a_concurrent_high_water_advance_cannot_reopen_a_pruned_nonce() {
        // Race the replay of a cached nonce against a fresh request that advances
        // the high-water clock far enough to prune it. The replay may win first
        // (REPLAYED_NONCE) or lose (STALE_TIMESTAMP), but it must never observe an
        // old clock and then reinsert after the advancing request prunes.
        let fx = Fixture::new(2, 3);
        let send = fx.channel_state(0);
        let recv = Arc::new(fx.channel_state(1));
        let psbt = fx.spend_psbt(&fx.hot_spk, 7);
        let payload = fx.partial_payload(&psbt, "c", 0, 0).to_bytes();

        for round in 0..32u64 {
            let base = NOW + round * 400;
            let replay = send
                .build_envelope("partial", 1, &payload, base)
                .expect("replay envelope");
            let replay_body = serde_json::to_vec(&replay).expect("json");
            assert_eq!(
                recv.ingest_reply(&replay_body, base),
                ChannelReply::UnknownCandidate,
                "first sight consumes the nonce"
            );

            let advancing = send
                .build_envelope("partial", 1, &payload, base + 400)
                .expect("advancing envelope");
            let advancing_body = serde_json::to_vec(&advancing).expect("json");
            let barrier = Arc::new(std::sync::Barrier::new(2));
            let (replay_result, advancing_result) = std::thread::scope(|scope| {
                let old_recv = Arc::clone(&recv);
                let old_barrier = Arc::clone(&barrier);
                let old = scope.spawn(move || {
                    old_barrier.wait();
                    old_recv.ingest_reply(&replay_body, base)
                });
                let new_recv = Arc::clone(&recv);
                let new = scope.spawn(move || {
                    barrier.wait();
                    new_recv.ingest_reply(&advancing_body, base + 400)
                });
                (
                    old.join().expect("replay thread"),
                    new.join().expect("advance thread"),
                )
            });

            assert!(
                matches!(
                    replay_result,
                    ChannelReply::Rejected(RejectReason::ReplayedNonce)
                        | ChannelReply::Rejected(RejectReason::StaleTimestamp)
                ),
                "a pruned nonce must never reopen: {replay_result:?}"
            );
            assert_eq!(advancing_result, ChannelReply::UnknownCandidate);
        }
    }

    #[test]
    fn per_peer_quota_is_enforced_by_authenticated_sender() {
        let fx = Fixture::new(2, 3);
        let send = fx.channel_state(0);
        let node = crate::Node::from_toml_str(&fx.config(1, 0, "per_peer_quota_per_min = 2\n"))
            .expect("config");
        let recv = node.channel.as_ref().expect("channel");
        let psbt = fx.spend_psbt(&fx.hot_spk, 7);
        let payload = fx.partial_payload(&psbt, "c", 0, 0).to_bytes();
        for _ in 0..2 {
            let env = send
                .build_envelope("partial", 1, &payload, NOW)
                .expect("env");
            assert_eq!(
                recv.ingest_reply(&serde_json::to_vec(&env).expect("json"), NOW),
                ChannelReply::UnknownCandidate
            );
        }
        let env = send
            .build_envelope("partial", 1, &payload, NOW)
            .expect("env");
        assert!(matches!(
            recv.ingest_reply(&serde_json::to_vec(&env).expect("json"), NOW),
            ChannelReply::RateLimited { .. }
        ));
    }

    #[test]
    fn fresh_nonces_over_quota_do_not_grow_the_replay_cache() {
        let fx = Fixture::new(2, 3);
        let send = fx.channel_state(0);
        let node = crate::Node::from_toml_str(&fx.config(1, 0, "per_peer_quota_per_min = 2\n"))
            .expect("config");
        let recv = node.channel.as_ref().expect("channel");
        let psbt = fx.spend_psbt(&fx.hot_spk, 7);
        let payload = fx.partial_payload(&psbt, "c", 0, 0).to_bytes();

        for attempt in 0..32 {
            let env = send
                .build_envelope("partial", 1, &payload, NOW)
                .expect("fresh envelope");
            let reply = recv.ingest_reply(&serde_json::to_vec(&env).expect("json"), NOW);
            if attempt < 2 {
                assert_eq!(reply, ChannelReply::UnknownCandidate);
            } else {
                assert!(matches!(reply, ChannelReply::RateLimited { .. }));
            }
        }
        assert_eq!(
            recv.nonce_len(),
            2,
            "only quota-admitted nonces are retained; an authenticated flood stays bounded"
        );
    }

    #[test]
    fn per_peer_quota_has_no_fixed_window_double_burst() {
        let mut guards = IngressGuards::default();
        let quota = 2;

        // One charge opens the old fixed window. A second arrives just before its
        // reset and a third exactly at the old boundary. A rolling window admits
        // the third only because the first has aged out, leaving two live charges.
        assert!(guards.charge_quota(0, NOW, quota).is_none());
        assert!(guards
            .charge_quota(0, NOW + QUOTA_WINDOW_SECS - 1, quota)
            .is_none());
        assert!(guards
            .charge_quota(0, NOW + QUOTA_WINDOW_SECS, quota)
            .is_none());

        // A resettable bucket would also admit this request, producing three
        // charges in one second across the boundary. The rolling window rejects it.
        let limited = guards
            .charge_quota(0, NOW + QUOTA_WINDOW_SECS, quota)
            .expect("the rolling quota is full");
        assert!(matches!(
            limited,
            IngressGuardResult::RateLimited {
                retry_after_secs: 59
            }
        ));
    }

    #[test]
    fn stale_and_replayed_envelopes_are_charged_to_the_authenticated_peer_quota() {
        let fx = Fixture::new(2, 3);
        let send = fx.channel_state(0);
        let psbt = fx.spend_psbt(&fx.hot_spk, 7);
        let payload = fx.partial_payload(&psbt, "c", 0, 0).to_bytes();

        // A captured stale envelope gets one freshness rejection/event, then the
        // same authenticated capture hits the quota instead of amplifying queue
        // work without bound.
        let stale_node =
            crate::Node::from_toml_str(&fx.config(1, 0, "per_peer_quota_per_min = 1\n"))
                .expect("config");
        let stale_recv = stale_node.channel.as_ref().expect("channel");
        let stale = send
            .build_envelope("partial", 1, &payload, NOW - 400)
            .expect("stale envelope");
        let stale_body = serde_json::to_vec(&stale).expect("json");
        assert_eq!(
            stale_recv.ingest_reply(&stale_body, NOW),
            ChannelReply::Rejected(RejectReason::StaleTimestamp)
        );
        assert!(matches!(
            stale_recv.ingest_reply(&stale_body, NOW),
            ChannelReply::RateLimited { .. }
        ));
        assert_eq!(
            stale_node.events(0).0.len(),
            1,
            "quota-limited stale captures must not publish another event"
        );

        // Replay rejection itself is charged as well: one fresh delivery and one
        // replay fill a quota of two, so another replay is rate-limited.
        let replay_node =
            crate::Node::from_toml_str(&fx.config(1, 0, "per_peer_quota_per_min = 2\n"))
                .expect("config");
        let replay_recv = replay_node.channel.as_ref().expect("channel");
        let replay = send
            .build_envelope("partial", 1, &payload, NOW)
            .expect("replay envelope");
        let replay_body = serde_json::to_vec(&replay).expect("json");
        assert_eq!(
            replay_recv.ingest_reply(&replay_body, NOW),
            ChannelReply::UnknownCandidate
        );
        assert_eq!(
            replay_recv.ingest_reply(&replay_body, NOW),
            ChannelReply::Rejected(RejectReason::ReplayedNonce)
        );
        assert!(matches!(
            replay_recv.ingest_reply(&replay_body, NOW),
            ChannelReply::RateLimited { .. }
        ));
    }

    #[test]
    fn a_rate_limited_envelope_can_be_retried_after_the_quota_window() {
        // RATE_LIMITED means the envelope was not dispatched. Retaining every
        // fresh over-quota nonce would let an authenticated peer grow the cache at
        // line rate despite the quota. Retrying later is safe for today's message
        // types: partial delivery is idempotent and request delivery has a second,
        // coordinator-authenticated single-use nonce at the node handler.
        let fx = Fixture::new(2, 3);
        let send = fx.channel_state(0);
        let node = crate::Node::from_toml_str(&fx.config(1, 0, "per_peer_quota_per_min = 1\n"))
            .expect("config");
        let recv = node.channel.as_ref().expect("channel");
        let psbt = fx.spend_psbt(&fx.hot_spk, 7);
        let payload = fx.partial_payload(&psbt, "c", 0, 0).to_bytes();

        // First envelope fills the 1/min quota and consumes exactly one nonce.
        let e1 = send
            .build_envelope("partial", 1, &payload, NOW)
            .expect("e1");
        assert_eq!(
            recv.ingest_reply(&serde_json::to_vec(&e1).expect("json"), NOW),
            ChannelReply::UnknownCandidate
        );
        assert_eq!(recv.nonce_len(), 1);

        // The next distinct envelope is rate-limited without being retained.
        let retry = send
            .build_envelope("partial", 1, &payload, NOW)
            .expect("retry envelope");
        let retry_body = serde_json::to_vec(&retry).expect("json");
        assert!(matches!(
            recv.ingest_reply(&retry_body, NOW),
            ChannelReply::RateLimited { .. }
        ));
        assert_eq!(recv.nonce_len(), 1);

        // Once the rolling quota resets, the same never-dispatched envelope is
        // admitted and retained exactly once.
        assert_eq!(
            recv.ingest_reply(&retry_body, NOW + QUOTA_WINDOW_SECS),
            ChannelReply::UnknownCandidate
        );
        assert_eq!(recv.nonce_len(), 2);
    }

    #[test]
    fn a_payload_wallet_mismatch_is_rejected() {
        let fx = Fixture::new(2, 3);
        let (send, recv) = (fx.channel_state(0), fx.channel_state(1));
        let psbt = fx.spend_psbt(&fx.hot_spk, 7);
        let mut payload = fx.partial_payload(&psbt, "c", 0, 0);
        payload.wallet_id = to_hex(&[0x99u8; 32]);
        assert_eq!(
            deliver(&send, &recv, "partial", &payload.to_bytes(), NOW, NOW),
            ChannelReply::Rejected(RejectReason::PayloadWalletMismatch)
        );
    }

    #[test]
    fn a_signer_that_is_not_the_sender_is_rejected() {
        let fx = Fixture::new(2, 3);
        let (send, recv) = (fx.channel_state(0), fx.channel_state(1));
        let psbt = fx.spend_psbt(&fx.hot_spk, 7);
        // sender is node 0, but the payload claims signer node 1.
        let payload = fx.partial_payload(&psbt, "c", 0, 1);
        assert_eq!(
            deliver(&send, &recv, "partial", &payload.to_bytes(), NOW, NOW),
            ChannelReply::Rejected(RejectReason::SignerMismatch)
        );
    }

    #[test]
    fn an_unknown_msg_type_is_rejected() {
        let fx = Fixture::new(2, 3);
        let (send, recv) = (fx.channel_state(0), fx.channel_state(1));
        assert_eq!(
            deliver(&send, &recv, "combine", b"{}", NOW, NOW),
            ChannelReply::Rejected(RejectReason::UnknownMsgType)
        );
    }

    #[test]
    fn a_malformed_payload_is_rejected() {
        let fx = Fixture::new(2, 3);
        let (send, recv) = (fx.channel_state(0), fx.channel_state(1));
        // Valid envelope, but the payload bytes are not a PartialPayload.
        assert_eq!(
            deliver(&send, &recv, "partial", b"not a partial", NOW, NOW),
            ChannelReply::Rejected(RejectReason::MalformedPayload)
        );
    }

    #[test]
    fn the_signature_verifies_over_raw_payload_b64_without_decoding() {
        // A valid envelope authenticates BEFORE any base64-decode (identity before
        // payload parsing): the sig covers the un-decoded ASCII field.
        let fx = Fixture::new(2, 3);
        let (send, recv) = (fx.channel_state(0), fx.channel_state(1));
        // An UNKNOWN_CANDIDATE outcome proves the envelope authenticated (sig +
        // freshness + nonce all passed) before the payload was even looked up.
        let bytes = envelope_bytes(&fx, &send, 1, "no-such-candidate", NOW, |_| {});
        assert_eq!(
            recv.ingest_reply(&bytes, NOW),
            ChannelReply::UnknownCandidate
        );
    }
}

#[cfg(test)]
mod partial {
    //! Partial-signature verification + storage (§5), and the signature-coverage
    //! + registry-lifecycle guarantees.
    use super::fixture::{deliver, Fixture};
    use super::*;
    use bitcoin::secp256k1::{Message, Secp256k1};
    use bitcoin::{Txid, Witness};
    use vault_proto::SignResponse;

    const NOW: u64 = 1_752_000_000;
    const EXPIRY: u64 = NOW + 3_600;

    #[test]
    fn candidate_build_canonicalizes_coordinator_controlled_finalization_fields() {
        let fx = Fixture::new(2, 3);
        let mut psbt = fx.spend_psbt(&fx.hot_spk, 7);
        psbt.inputs[0].witness_script = None;
        psbt.inputs[0].redeem_script = Some(ScriptBuf::from_bytes(vec![0x51]));
        psbt.inputs[0].sighash_type = Some(EcdsaSighashType::Single.into());
        psbt.inputs[0].final_script_sig = Some(ScriptBuf::from_bytes(vec![0x51]));
        psbt.inputs[0].final_script_witness = Some(Witness::from_slice(&[b"coordinator"]));

        let candidate = fx.candidate(&psbt, "canonical-finalization", EXPIRY);
        let input = &candidate.psbt.inputs[0];
        assert_eq!(
            input.witness_script.as_ref(),
            Some(&fx.witness_script),
            "the node's configured P2WSH script is authoritative"
        );
        assert!(input.redeem_script.is_none());
        assert_eq!(
            input.sighash_type,
            Some(EcdsaSighashType::All.into()),
            "candidate finalization must use the verified SIGHASH_ALL contract"
        );
        assert!(input.final_script_sig.is_none());
        assert!(input.final_script_witness.is_none());
    }

    #[test]
    fn every_signed_envelope_field_is_covered_by_the_channel_signature() {
        // Per-field mutation of the ENVELOPE: recompute the preimage with each
        // signed field flipped and assert the original channel_sig no longer
        // verifies (proves each field is in the preimage — so a nonce/timestamp
        // mutation can't be replayed inside the window).
        let fx = Fixture::new(2, 3);
        let send = fx.channel_state(0);
        let psbt = fx.spend_psbt(&fx.hot_spk, 7);
        let payload = fx.partial_payload(&psbt, "c", 0, 0).to_bytes();
        let env = send
            .build_envelope("partial", 1, &payload, NOW)
            .expect("env");
        let sig = Signature::from_der(&from_hex_vec(&env.channel_sig).expect("der")).expect("sig");
        let channel_pk = fx.entries[0].channel_pk;
        let secp = Secp256k1::verification_only();

        let wallet_id = from_hex_32(&env.wallet_id).expect("wid");
        let manifest_hash = from_hex_32(&env.manifest_hash).expect("mh");
        let nonce = from_hex_16(&env.nonce).expect("nonce");
        // (label, mutated preimage) for each field.
        let variants: Vec<(&str, Zeroizing<Vec<u8>>)> = vec![
            (
                "msg_type",
                envelope_preimage(
                    "combine",
                    0,
                    &wallet_id,
                    &manifest_hash,
                    0,
                    1,
                    env.payload_b64.as_bytes(),
                    &nonce,
                    env.timestamp,
                ),
            ),
            (
                "protocol_version",
                envelope_preimage(
                    "partial",
                    1,
                    &wallet_id,
                    &manifest_hash,
                    0,
                    1,
                    env.payload_b64.as_bytes(),
                    &nonce,
                    env.timestamp,
                ),
            ),
            (
                "wallet_id",
                envelope_preimage(
                    "partial",
                    0,
                    &[0x00; 32],
                    &manifest_hash,
                    0,
                    1,
                    env.payload_b64.as_bytes(),
                    &nonce,
                    env.timestamp,
                ),
            ),
            (
                "manifest_hash",
                envelope_preimage(
                    "partial",
                    0,
                    &wallet_id,
                    &[0x00; 32],
                    0,
                    1,
                    env.payload_b64.as_bytes(),
                    &nonce,
                    env.timestamp,
                ),
            ),
            (
                "sender_node_id",
                envelope_preimage(
                    "partial",
                    0,
                    &wallet_id,
                    &manifest_hash,
                    1,
                    1,
                    env.payload_b64.as_bytes(),
                    &nonce,
                    env.timestamp,
                ),
            ),
            (
                "recipient_node_id",
                envelope_preimage(
                    "partial",
                    0,
                    &wallet_id,
                    &manifest_hash,
                    0,
                    2,
                    env.payload_b64.as_bytes(),
                    &nonce,
                    env.timestamp,
                ),
            ),
            (
                "payload_b64",
                envelope_preimage(
                    "partial",
                    0,
                    &wallet_id,
                    &manifest_hash,
                    0,
                    1,
                    b"tampered",
                    &nonce,
                    env.timestamp,
                ),
            ),
            (
                "nonce",
                envelope_preimage(
                    "partial",
                    0,
                    &wallet_id,
                    &manifest_hash,
                    0,
                    1,
                    env.payload_b64.as_bytes(),
                    &[0xFF; 16],
                    env.timestamp,
                ),
            ),
            (
                "timestamp",
                envelope_preimage(
                    "partial",
                    0,
                    &wallet_id,
                    &manifest_hash,
                    0,
                    1,
                    env.payload_b64.as_bytes(),
                    &nonce,
                    env.timestamp + 1,
                ),
            ),
        ];
        for (label, pre) in variants {
            let digest = tagged_hash(ENVELOPE_TAG, &pre);
            assert!(
                secp.verify_ecdsa(&Message::from_digest(digest), &sig, &channel_pk.inner)
                    .is_err(),
                "mutating {label} must invalidate channel_sig"
            );
        }
        // Control: the un-mutated preimage DOES verify (signer == verifier).
        let base = envelope_preimage(
            "partial",
            0,
            &wallet_id,
            &manifest_hash,
            0,
            1,
            env.payload_b64.as_bytes(),
            &nonce,
            env.timestamp,
        );
        assert!(secp
            .verify_ecdsa(
                &Message::from_digest(tagged_hash(ENVELOPE_TAG, &base)),
                &sig,
                &channel_pk.inner
            )
            .is_ok());
    }

    #[test]
    fn a_valid_partial_over_a_registered_candidate_is_stored() {
        let fx = Fixture::new(2, 3);
        let (send, recv) = (fx.channel_state(0), fx.channel_state(1));
        let psbt = fx.spend_psbt(&fx.hot_spk, 7);
        recv.register_candidate(fx.candidate(&psbt, "cid", EXPIRY));
        let payload = fx.partial_payload(&psbt, "cid", 0, 0);
        assert_eq!(
            deliver(&send, &recv, "partial", &payload.to_bytes(), NOW, NOW),
            ChannelReply::Accepted
        );
        assert!(
            recv.partial_stored("cid", 0, 0),
            "the partial must be stored"
        );
        // The peer's signature was imported into the canonical PSBT under its key.
        assert!(recv.psbt_has_pubkey("cid", 0, &fx.entries[0].fed_pk));
    }

    #[test]
    fn a_partial_by_the_wrong_signer_key_is_rejected() {
        let fx = Fixture::new(2, 3);
        let (send, recv) = (fx.channel_state(0), fx.channel_state(1));
        let psbt = fx.spend_psbt(&fx.hot_spk, 7);
        recv.register_candidate(fx.candidate(&psbt, "cid", EXPIRY));
        // signer_node_id 0 (== sender) but the DER is node 1's signature.
        let mut payload = fx.partial_payload(&psbt, "cid", 0, 0);
        payload.partial_sig = to_hex(&fx.partial_der(&psbt, 0, 1));
        assert_eq!(
            deliver(&send, &recv, "partial", &payload.to_bytes(), NOW, NOW),
            ChannelReply::Rejected(RejectReason::BadPartialSig)
        );
    }

    #[test]
    fn wrong_txid_input_sighash_and_user_sig_hash_are_each_rejected() {
        let fx = Fixture::new(2, 3);
        let (send, recv) = (fx.channel_state(0), fx.channel_state(1));
        let psbt = fx.spend_psbt(&fx.hot_spk, 7);
        recv.register_candidate(fx.candidate(&psbt, "cid", EXPIRY));

        let mut wrong_txid = fx.partial_payload(&psbt, "cid", 0, 0);
        wrong_txid.txid = Txid::from_byte_array([0xAB; 32]).to_string();
        assert_eq!(
            deliver(&send, &recv, "partial", &wrong_txid.to_bytes(), NOW, NOW),
            ChannelReply::Rejected(RejectReason::WrongTxid)
        );

        let mut wrong_input = fx.partial_payload(&psbt, "cid", 0, 0);
        wrong_input.input = 5;
        assert_eq!(
            deliver(&send, &recv, "partial", &wrong_input.to_bytes(), NOW, NOW),
            ChannelReply::Rejected(RejectReason::WrongInput)
        );

        let mut wrong_sighash = fx.partial_payload(&psbt, "cid", 0, 0);
        wrong_sighash.sighash_type = 0;
        assert_eq!(
            deliver(&send, &recv, "partial", &wrong_sighash.to_bytes(), NOW, NOW),
            ChannelReply::Rejected(RejectReason::WrongSighashType)
        );

        let mut wrong_ush = fx.partial_payload(&psbt, "cid", 0, 0);
        wrong_ush.user_sig_hash = to_hex(&[0x7c; 32]);
        assert_eq!(
            deliver(&send, &recv, "partial", &wrong_ush.to_bytes(), NOW, NOW),
            ChannelReply::Rejected(RejectReason::WrongUserSigHash)
        );
    }

    #[test]
    fn a_partial_for_an_unknown_commitment_is_retriable_unknown_candidate() {
        let fx = Fixture::new(2, 3);
        let (send, recv) = (fx.channel_state(0), fx.channel_state(1));
        let psbt = fx.spend_psbt(&fx.hot_spk, 7);
        // No candidate registered for "ghost".
        let payload = fx.partial_payload(&psbt, "ghost", 0, 0);
        assert_eq!(
            deliver(&send, &recv, "partial", &payload.to_bytes(), NOW, NOW),
            ChannelReply::UnknownCandidate
        );
    }

    #[test]
    fn a_re_delivered_partial_is_idempotent_and_never_evicts_the_first() {
        let fx = Fixture::new(2, 3);
        let (send, recv) = (fx.channel_state(0), fx.channel_state(1));
        let psbt = fx.spend_psbt(&fx.hot_spk, 7);
        recv.register_candidate(fx.candidate(&psbt, "cid", EXPIRY));
        let payload = fx.partial_payload(&psbt, "cid", 0, 0);
        assert_eq!(
            deliver(&send, &recv, "partial", &payload.to_bytes(), NOW, NOW),
            ChannelReply::Accepted
        );
        let first = recv.stored_partial_der("cid", 0, 0).expect("stored");
        // A second delivery for the same (candidate, input, signer) is a no-op that
        // retains the first verified partial.
        assert_eq!(
            deliver(&send, &recv, "partial", &payload.to_bytes(), NOW, NOW),
            ChannelReply::Accepted
        );
        assert_eq!(
            recv.stored_partial_der("cid", 0, 0).expect("still stored"),
            first
        );
    }

    #[test]
    fn no_channel_message_ever_triggers_signing() {
        // Signing-oracle prohibition (§7): a partial imports the PEER's signature,
        // never the node's own — and the authorized set is untouched.
        let fx = Fixture::new(2, 3);
        let send = fx.channel_state(0);
        let node = crate::Node::from_toml_str(&fx.config(1, 0, "")).expect("config");
        let recv = node.channel.as_ref().expect("channel");
        let psbt = fx.spend_psbt(&fx.hot_spk, 7);
        recv.register_candidate(fx.candidate(&psbt, "cid", EXPIRY));
        let payload = fx.partial_payload(&psbt, "cid", 0, 0);
        assert_eq!(
            deliver(&send, recv, "partial", &payload.to_bytes(), NOW, NOW),
            ChannelReply::Accepted
        );
        // The node NEVER produced a signature: its own federation key is absent
        // from the candidate PSBT (the fixture registered it unsigned), and it
        // authorized nothing — a peer message cannot make a node accept a spend.
        assert!(!recv.psbt_has_pubkey("cid", 0, &fx.entries[1].fed_pk));
        assert!(node.authorized.lock().expect("authorized").is_empty());
    }

    #[test]
    fn two_live_commitments_over_one_txid_are_distinct_candidates() {
        let fx = Fixture::new(2, 3);
        let recv = fx.channel_state(1);
        let psbt = fx.spend_psbt(&fx.hot_spk, 7);
        // Same txid, two distinct commitment_ids (different expiry instances).
        recv.register_candidate(fx.candidate(&psbt, "cid-a", NOW + 100));
        recv.register_candidate(fx.candidate(&psbt, "cid-b", NOW + 200));
        assert_eq!(recv.store_len(), 2, "keyed by commitment_id, not txid");
        assert!(recv.has_candidate("cid-a") && recv.has_candidate("cid-b"));
    }

    #[test]
    fn each_candidate_expires_on_its_own_commitment_clock() {
        let fx = Fixture::new(2, 3);
        let recv = fx.channel_state(1);
        let psbt = fx.spend_psbt(&fx.hot_spk, 7);
        recv.register_candidate(fx.candidate(&psbt, "cid-a", NOW + 100));
        recv.register_candidate(fx.candidate(&psbt, "cid-b", NOW + 200));
        recv.prune_store(NOW + 150);
        assert!(
            !recv.has_candidate("cid-a"),
            "cid-a expired on its own clock"
        );
        assert!(recv.has_candidate("cid-b"), "cid-b outlives it");
    }

    #[test]
    fn an_expired_candidate_is_rejected_at_channel_lookup_with_no_sweep() {
        let fx = Fixture::new(2, 3);
        let (send, recv) = (fx.channel_state(0), fx.channel_state(1));
        let psbt = fx.spend_psbt(&fx.hot_spk, 7);
        recv.register_candidate(fx.candidate(&psbt, "cid", NOW + 100));
        // No intervening /sign sweep; deliver a partial after expiry.
        let payload = fx.partial_payload(&psbt, "cid", 0, 0);
        assert_eq!(
            deliver(
                &send,
                &recv,
                "partial",
                &payload.to_bytes(),
                NOW + 200,
                NOW + 200
            ),
            ChannelReply::UnknownCandidate
        );
        assert!(
            !recv.has_candidate("cid"),
            "the expired candidate was evicted on lookup"
        );
    }

    #[test]
    fn a_partial_arriving_in_the_final_authorized_second_is_accepted_not_evicted() {
        let fx = Fixture::new(2, 3);
        let (send, recv) = (fx.channel_state(0), fx.channel_state(1));
        let psbt = fx.spend_psbt(&fx.hot_spk, 7);
        // Candidate expiry EXACTLY at the delivery instant. `prune` keeps a candidate
        // live at `now == expiry` (its final authorized second) and `FireWindow` is
        // inclusive at its deadline, so a quorum partial arriving in that second must
        // be verified and stored — not answered UnknownCandidate with the candidate
        // evicted, which would sabotage a broadcast the fire path still authorizes.
        recv.register_candidate(fx.candidate(&psbt, "cid", NOW));
        let payload = fx.partial_payload(&psbt, "cid", 0, 0);
        assert_eq!(
            deliver(&send, &recv, "partial", &payload.to_bytes(), NOW, NOW),
            ChannelReply::Accepted
        );
        assert!(
            recv.has_candidate("cid"),
            "the candidate survives its final authorized second and stores the partial"
        );
    }

    #[test]
    fn at_the_capacity_cap_a_new_candidate_is_not_inserted_and_none_is_evicted() {
        let fx = Fixture::new(2, 3);
        let node = crate::Node::from_toml_str(&fx.config(1, 0, "max_active_candidates = 1\n"))
            .expect("config");
        let recv = node.channel.as_ref().expect("channel");
        let psbt = fx.spend_psbt(&fx.hot_spk, 7);
        assert_eq!(
            recv.register_candidate(fx.candidate(&psbt, "cid-1", EXPIRY)),
            RegisterOutcome::Inserted
        );
        assert_eq!(
            recv.register_candidate(fx.candidate(&psbt, "cid-2", EXPIRY)),
            RegisterOutcome::AtCapacity
        );
        assert_eq!(recv.store_len(), 1);
        assert!(
            recv.has_candidate("cid-1"),
            "the live candidate is never evicted"
        );
    }

    #[test]
    fn the_byte_cap_also_blocks_insertion() {
        let fx = Fixture::new(2, 3);
        let node = crate::Node::from_toml_str(&fx.config(1, 0, "max_candidate_store_bytes = 10\n"))
            .expect("config");
        let recv = node.channel.as_ref().expect("channel");
        let psbt = fx.spend_psbt(&fx.hot_spk, 7);
        assert_eq!(
            recv.register_candidate(fx.candidate(&psbt, "cid", EXPIRY)),
            RegisterOutcome::AtCapacity
        );
        assert_eq!(recv.store_len(), 0);
    }

    #[test]
    fn registration_reserves_capacity_for_every_future_verified_partial() {
        let fx = Fixture::new(2, 3);
        let psbt = fx.spend_psbt(&fx.hot_spk, 7);
        let candidate = fx.candidate(&psbt, "cid", EXPIRY);
        // The current candidate bytes fit exactly, but a peer partial would grow
        // both the canonical PSBT and the separate partial map. Because wire-time
        // capacity rejection is forbidden, insertion must reserve that growth.
        let opts = format!("max_candidate_store_bytes = {}\n", candidate.bytes);
        let node = crate::Node::from_toml_str(&fx.config(1, 0, &opts)).expect("config");
        let recv = node.channel.as_ref().expect("channel");
        assert_eq!(
            recv.register_candidate(candidate),
            RegisterOutcome::AtCapacity
        );
        assert_eq!(recv.store_len(), 0);

        // With the full reservation available, every peer can add its verified
        // partial without growing the charged total beyond the hard cap.
        let probe = fx.channel_state(1);
        let mut reserved_candidate = fx.candidate(&psbt, "reserved", EXPIRY);
        reserved_candidate.reserve_partial_capacity(&probe.nodes, probe.node_id);
        let reserved_bytes = reserved_candidate.capacity_bytes;
        drop(probe);
        let opts = format!("max_candidate_store_bytes = {reserved_bytes}\n");
        let node = crate::Node::from_toml_str(&fx.config(1, 0, &opts)).expect("config");
        let recv = node.channel.as_ref().expect("channel");
        assert_eq!(
            recv.register_candidate(fx.candidate(&psbt, "reserved", EXPIRY)),
            RegisterOutcome::Inserted
        );
        for signer in [0, 2] {
            let sender = fx.channel_state(signer);
            let payload = fx.partial_payload(&psbt, "reserved", 0, signer);
            assert_eq!(
                deliver(&sender, recv, "partial", &payload.to_bytes(), NOW, NOW),
                ChannelReply::Accepted
            );
        }
        let store = recv.store.lock().expect("store");
        let stored = store.candidates.get("reserved").expect("candidate");
        let actual_bytes = stored.psbt.serialize().len()
            + stored.sighashes.len() * 32
            + 32
            + stored.partials.values().map(Vec::len).sum::<usize>();
        assert_eq!(stored.bytes, actual_bytes, "complete actual accounting");
        assert_eq!(
            store.reserved_bytes, reserved_bytes,
            "reservation charged once"
        );
        assert!(stored.bytes <= store.reserved_bytes);
        assert!(store.reserved_bytes <= store.max_bytes);
    }

    /// Model B registers a candidate that is ALREADY fully signed — there is no
    /// Pending→Signed transition to lose anything across. What must still hold is
    /// that a re-send disturbs nothing: the registered candidate keeps its own
    /// signature, keeps any peer partials that arrived, and keeps the user
    /// signature instance those payloads are bound to.
    ///
    /// The re-send here carries a DIFFERENT but equally valid user signature (ECDSA
    /// encodings are not unique, and a user signature is not part of the unsigned
    /// commitment). It must not borrow the first request's cached Accepted verdict:
    /// peers bind partials to `user_sig_hash`, so admitting both instances could
    /// split the combine set. The resident stays untouched and the conflict is
    /// refused.
    #[test]
    fn a_resend_with_a_different_valid_user_signature_is_refused_and_leaves_the_candidate_untouched(
    ) {
        let fx = Fixture::new(2, 3);
        let sender = fx.channel_state(0);
        let node = crate::Node::from_toml_str(&fx.config(1, 10, "")).expect("config");
        let psbt = fx.spend_psbt(&fx.hot_spk, 7);
        let original_user_der = psbt.inputs[0]
            .partial_sigs
            .get(&fx.user_pk)
            .expect("original user signature")
            .signature
            .serialize_der();
        let request = fx.spend_request(&psbt, NOW + 3_600, "changed-user-sig");
        assert!(matches!(
            crate::handle_sign(&node, &request, NOW).expect("accepted verdict"),
            SignResponse::Accepted(_)
        ));
        let channel = node.channel.as_ref().expect("channel");
        let commitment_id = crate::commitment_id_for(&node, &psbt, NOW + 3_600);
        let original_user_sig_hash = channel
            .store
            .lock()
            .expect("store")
            .candidates
            .get(&commitment_id)
            .expect("candidate")
            .user_sig_hash;
        // Sign-at-ingress: this node's own partial is in the candidate already,
        // before any Hold elapses and before any peer says anything.
        assert!(
            channel.psbt_has_pubkey(&commitment_id, 0, &fx.entries[1].fed_pk),
            "Model B signs at ingress: the candidate carries this node's partial from birth"
        );

        let peer_payload = fx.partial_payload(&psbt, &commitment_id, 0, 0);
        assert_eq!(
            deliver(
                &sender,
                channel,
                "partial",
                &peer_payload.to_bytes(),
                NOW,
                NOW
            ),
            ChannelReply::Accepted
        );

        // Re-sign the same SIGHASH_ALL message with extra nonce data: a distinct,
        // valid ECDSA encoding over the same commitment.
        let mut resigned = psbt.clone();
        let value = resigned.inputs[0]
            .witness_utxo
            .as_ref()
            .expect("witness_utxo")
            .value;
        let sighash = SighashCache::new(&resigned.unsigned_tx)
            .p2wsh_signature_hash(0, &fx.witness_script, value, EcdsaSighashType::All)
            .expect("sighash");
        let alternate_user_sig = Secp256k1::signing_only().sign_ecdsa_with_noncedata(
            &Message::from_digest(sighash.to_byte_array()),
            &fx.user_sk,
            &[0x42; 32],
        );
        assert_ne!(alternate_user_sig.serialize_der(), original_user_der);
        resigned.inputs[0].partial_sigs.insert(
            fx.user_pk,
            ecdsa::Signature {
                signature: alternate_user_sig,
                sighash_type: EcdsaSighashType::All,
            },
        );
        // The unsigned commitment is unchanged, but accepted replay identity binds
        // the complete request pair, so this reaches the registry conflict check.
        let resent = fx.spend_request(&resigned, NOW + 3_600, "changed-user-sig-resend");
        let refusal = match crate::handle_sign(&node, &resent, NOW + 10).expect("verdict") {
            SignResponse::Refusal(refusal) => refusal,
            other => panic!("the conflicting user-signature instance must be refused: {other:?}"),
        };
        assert_eq!(refusal.code, vault_proto::RefusalCode::PsbtInconsistent);
        assert_eq!(refusal.check, "candidate_identity");

        let store = channel.store.lock().expect("store");
        let candidate = store
            .candidates
            .get(&commitment_id)
            .expect("candidate remains registered");
        assert_eq!(
            candidate.user_sig_hash, original_user_sig_hash,
            "the candidate retains the user-signature instance peer payloads name"
        );
        assert_eq!(
            candidate.psbt.inputs[0]
                .partial_sigs
                .get(&fx.user_pk)
                .expect("retained user signature")
                .signature
                .serialize_der(),
            original_user_der
        );
        assert!(
            candidate.partials.contains_key(&(0, 0)),
            "the peer partial must survive a re-send"
        );
        assert!(
            candidate.psbt.inputs[0]
                .partial_sigs
                .contains_key(&fx.entries[1].fed_pk),
            "this node's own partial must survive a re-send"
        );
    }

    #[test]
    fn a_resend_with_a_different_mandatory_escape_is_refused_without_repairing_the_pair() {
        let fx = Fixture::new(2, 3);
        let node = crate::Node::from_toml_str(&fx.config(1, 10, "")).expect("config");
        let spend = fx.spend_psbt(&fx.hot_spk, 7);
        let original = fx.spend_request(&spend, NOW + 3_600, "original-pair");
        assert!(matches!(
            crate::handle_sign(&node, &original, NOW).expect("accepted"),
            SignResponse::Accepted(_)
        ));
        let channel = node.channel.as_ref().expect("channel");
        let spend_cid = crate::commitment_id_for(&node, &spend, NOW + 3_600);
        let original_escape = Psbt::from_str(&original.escape_psbt).expect("original escape");
        let original_escape_cid = crate::commitment_id_for(&node, &original_escape, NOW + 3_600);

        // Same exact spend, a different but independently valid escape transaction.
        let replacement_escape = fx.spend_psbt(&fx.escape_spk, 8);
        let replacement_escape_cid =
            crate::commitment_id_for(&node, &replacement_escape, NOW + 3_600);
        assert_ne!(original_escape_cid, replacement_escape_cid);
        let mut conflicting = fx.spend_request(&spend, NOW + 3_600, "replacement-pair");
        conflicting.escape_psbt = replacement_escape.to_string();
        fx.coord_sign(&mut conflicting, "replacement-pair-signed");
        let refusal = match crate::handle_sign(&node, &conflicting, NOW + 1).expect("verdict") {
            SignResponse::Refusal(refusal) => refusal,
            other => panic!("the conflicting mandatory escape must be refused: {other:?}"),
        };
        assert_eq!(refusal.code, vault_proto::RefusalCode::PsbtInconsistent);
        assert_eq!(refusal.check, "candidate_identity");
        assert_eq!(channel.store_len(), 2, "no orphan replacement was inserted");
        assert_eq!(
            channel.pairing(&spend_cid),
            Some((CandidateRole::Spend, original_escape_cid)),
            "the first accepted pair remains authoritative on this node"
        );
        assert!(channel.pairing(&replacement_escape_cid).is_none());
    }

    #[test]
    fn a_coordinator_forged_federation_partial_never_survives_into_the_candidate() {
        // A pure-relay coordinator plants a bogus partial_sig under THIS node's
        // federation signing key in the request PSBT. `verify_user_signatures`
        // checks only the user entry, so the forgery clears ingress. If the
        // candidate kept it, this node would release garbage every peer rejects and
        // drop itself from the combine set — a coordinator gaining power over
        // assembly, which Model B forbids.
        let fx = Fixture::new(2, 3);
        let node = crate::Node::from_toml_str(&fx.config(1, 10, "")).expect("config");
        let mut psbt = fx.spend_psbt(&fx.hot_spk, 7);
        let forged = Secp256k1::signing_only()
            .sign_ecdsa(&Message::from_digest([0xff; 32]), &fx.entries[1].fed_sk);
        psbt.inputs[0].partial_sigs.insert(
            fx.entries[1].fed_pk,
            ecdsa::Signature {
                signature: forged,
                sighash_type: EcdsaSighashType::All,
            },
        );
        let request = fx.spend_request(&psbt, NOW + 3_600, "forged-partial");
        assert!(matches!(
            crate::handle_sign(&node, &request, NOW).expect("accepted verdict"),
            SignResponse::Accepted(_)
        ));
        let channel = node.channel.as_ref().expect("channel");
        let cid = crate::commitment_id_for(&node, &psbt, NOW + 3_600);

        // Fire the candidate so the release gate hands back what this node WOULD
        // relay: its own real signature, never the coordinator's forgery. (The Hold
        // is 10s, so the fire event is NOW + 10.)
        let release = channel
            .release_partials(&cid, NOW + 10)
            .expect("the fire event has arrived");
        let payload: PartialPayload =
            serde_json::from_slice(&release.payloads[0].to_bytes()).expect("payload");
        let der = from_hex_vec(&payload.partial_sig).expect("der hex");
        let sig = Signature::from_der(&der).expect("der");
        let value = psbt.inputs[0]
            .witness_utxo
            .as_ref()
            .expect("witness_utxo")
            .value;
        let sighash = SighashCache::new(&psbt.unsigned_tx)
            .p2wsh_signature_hash(0, &fx.witness_script, value, EcdsaSighashType::All)
            .expect("sighash");
        Secp256k1::verification_only()
            .verify_ecdsa(
                &Message::from_digest(sighash.to_byte_array()),
                &sig,
                &fx.entries[1].fed_pk.inner,
            )
            .expect("the released partial must be this node's real signature, not the forgery");
    }

    #[test]
    fn an_unregistrable_pair_is_refused_atomically_at_capacity() {
        let fx = Fixture::new(2, 3);
        // One slot: the first accepted request's PAIR (spend + escape) already
        // needs two. Neither half may be inserted and the request cannot be
        // acknowledged: the coordinator has no signature fallback in Model B.
        let node = crate::Node::from_toml_str(&fx.config(1, 0, "max_active_candidates = 1\n"))
            .expect("config");
        let psbt = fx.spend_psbt(&fx.hot_spk, 7);
        let req = fx.spend_request(&psbt, NOW + 3_600, "capacity-pair");
        let refusal = match crate::handle_sign(&node, &req, NOW).expect("decodable") {
            SignResponse::Refusal(refusal) => refusal,
            other => panic!("an unregistrable pair must not be acknowledged: {other:?}"),
        };
        assert_eq!(refusal.code, vault_proto::RefusalCode::CandidateCapacity);
        assert_eq!(refusal.check, "candidate_registry_capacity");
        assert_eq!(
            node.channel.as_ref().expect("channel").store_len(),
            0,
            "capacity preflight inserts neither half of the pair"
        );
        assert!(
            node.authorized.lock().expect("authorized").is_empty(),
            "a capacity-refused transaction is not watchtower-recognized or parent-authorized"
        );
        assert!(
            node.outbox.lock().expect("outbox").is_empty(),
            "a refused request is not propagated as accepted work"
        );
    }
}

#[cfg(test)]
mod startup_and_schema {
    //! Absent-channel mode, config/startup fatals, the `/channel` response schema
    //! (§5b), and freshness diagnostics through `/events` (codex I2).
    use super::fixture::Fixture;
    use super::*;
    use crate::watchtower::Event;

    const NOW: u64 = 1_752_000_000;

    #[test]
    fn a_config_without_a_channel_block_runs_in_absent_channel_mode() {
        let fx = Fixture::new(2, 3);
        // No `[channel]` section at all.
        let node = crate::Node::from_toml_str(&fx.config_with_channel(0, 0, ""))
            .expect("absent-channel config loads");
        assert!(
            node.channel.is_none(),
            "absent `[channel]` ⇒ no channel runtime"
        );
    }

    #[test]
    fn an_endpoint_that_disagrees_with_the_bind_address_is_fatal() {
        let fx = Fixture::new(2, 3);
        // Bind on a port the self endpoint does not advertise.
        let cfg = fx
            .config(0, 0, "")
            .replacen("listen_port = 9000", "listen_port = 9999", 1);
        let err = crate::Node::from_toml_str(&cfg)
            .err()
            .expect("must be fatal");
        assert!(
            err.to_string().contains("bind address"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn channel_mode_rejects_an_ephemeral_bind_port() {
        let fx = Fixture::new(2, 3);
        let cfg = fx
            .config(0, 0, "")
            .replacen("listen_port = 9000", "listen_port = 0", 1)
            .replacen("127.0.0.1:9000", "127.0.0.1:0", 1);
        let err = crate::Node::from_toml_str(&cfg)
            .err()
            .expect("channel mode cannot advertise an OS-selected port");
        assert!(err.to_string().contains("nonzero"), "unexpected: {err}");
    }

    #[test]
    fn a_non_canonical_peer_endpoint_is_fatal() {
        let fx = Fixture::new(2, 3);
        // Corrupt a peer endpoint into an unparseable host:port.
        let cfg = fx
            .config(0, 0, "")
            .replacen("127.0.0.1:9001", "127.0.0.1:notaport", 1);
        let err = crate::Node::from_toml_str(&cfg)
            .err()
            .expect("must be fatal");
        assert!(err.to_string().contains("endpoint"), "unexpected: {err}");
    }

    #[test]
    fn the_response_schema_maps_each_outcome_to_its_status_and_body() {
        assert_eq!(
            ChannelReply::Accepted.http(),
            (200, r#"{"status":"ACCEPTED"}"#.to_string())
        );
        assert_eq!(
            ChannelReply::UnknownCandidate.http(),
            (409, r#"{"status":"UNKNOWN_CANDIDATE"}"#.to_string())
        );
        assert_eq!(
            ChannelReply::RateLimited {
                retry_after_secs: 7
            }
            .http(),
            (
                429,
                r#"{"status":"RATE_LIMITED","retry_after_secs":7}"#.to_string()
            )
        );
        assert_eq!(
            ChannelReply::Rejected(RejectReason::ReplayedNonce).http(),
            (
                400,
                r#"{"status":"REJECTED","reason":"REPLAYED_NONCE"}"#.to_string()
            )
        );
        assert_eq!(
            ChannelReply::Rejected(RejectReason::BadPartialSig).http(),
            (
                400,
                r#"{"status":"REJECTED","reason":"BAD_PARTIAL_SIG"}"#.to_string()
            )
        );
    }

    #[test]
    fn freshness_rejections_surface_through_events_with_peer_attribution_and_monotonic_count() {
        let fx = Fixture::new(2, 3);
        let send = fx.channel_state(0);
        let node = crate::Node::from_toml_str(&fx.config(1, 0, "")).expect("config");
        let recv = node.channel.as_ref().expect("channel");
        let psbt = fx.spend_psbt(&fx.hot_spk, 7);
        let payload = fx.partial_payload(&psbt, "c", 0, 0).to_bytes();

        let freshness_count = |node: &crate::Node| -> Option<u64> {
            node.events(0).0.into_iter().find_map(|e| match e {
                Event::ChannelFreshness(fe) if fe.peer_node_id == 0 => Some(fe.reject_count),
                _ => None,
            })
        };

        // Three stale deliveries from peer 0; the surfaced count is monotonic.
        for expected in 1..=3u64 {
            let env = send
                .build_envelope("partial", 1, &payload, NOW - 400)
                .expect("env");
            assert_eq!(
                recv.ingest_reply(&serde_json::to_vec(&env).expect("json"), NOW),
                ChannelReply::Rejected(RejectReason::StaleTimestamp)
            );
            assert_eq!(
                freshness_count(&node),
                Some(expected),
                "peer 0 reject count"
            );
        }
    }

    #[test]
    fn freshness_skew_clamps_authenticated_u64_timestamps_without_overflow() {
        let fx = Fixture::new(2, 3);
        let send = fx.channel_state(0);
        let node = crate::Node::from_toml_str(&fx.config(1, 0, "")).expect("config");
        let recv = node.channel.as_ref().expect("channel");
        let psbt = fx.spend_psbt(&fx.hot_spk, 7);
        let payload = fx.partial_payload(&psbt, "c", 0, 0).to_bytes();
        let env = send
            .build_envelope("partial", 1, &payload, u64::MAX)
            .expect("env");
        assert_eq!(
            recv.ingest_reply(&serde_json::to_vec(&env).expect("json"), NOW),
            ChannelReply::Rejected(RejectReason::StaleTimestamp)
        );
        let skew = node.events(0).0.into_iter().find_map(|event| match event {
            Event::ChannelFreshness(event) => Some(event.skew_secs),
            Event::Watchtower(_) => None,
        });
        assert_eq!(skew, Some(i64::MAX));
    }

    #[test]
    fn a_freshness_event_carries_no_transaction_fields_and_leaves_watchtower_json_intact() {
        use crate::watchtower::{Alert, AlertKind, FreshnessEvent, FreshnessKind};
        // The watchtower alert JSON is byte-for-byte its historical shape...
        let wt = Event::Watchtower(Alert {
            kind: AlertKind::UnrecognizedSpend,
            spend_txid: "ab".repeat(32),
            outpoint: format!("{}:0", "ab".repeat(32)),
            script: "0014dead".to_string(),
        });
        let json = serde_json::to_string(&wt).expect("json");
        assert!(
            json.starts_with(r#"{"kind":"UNRECOGNIZED_SPEND","spend_txid":"#),
            "got {json}"
        );
        // ...and a freshness event serializes to its OWN shape, no txid/outpoint.
        let fe = Event::ChannelFreshness(FreshnessEvent {
            kind: FreshnessKind::ChannelFreshnessReject,
            peer_node_id: 4,
            reject_count: 2,
            skew_secs: -400,
        });
        let fj = serde_json::to_string(&fe).expect("json");
        assert_eq!(
            fj,
            r#"{"kind":"CHANNEL_FRESHNESS_REJECT","peer_node_id":4,"reject_count":2,"skew_secs":-400}"#
        );
    }
}

#[cfg(test)]
mod net {
    //! Real-path (loopback axum + reqwest) and retry-control tests.
    use super::fixture::Fixture;
    use super::*;
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::sync::Mutex as StdMutex;

    use crate::server;
    use vault_proto::{SignResponse, TaggedRequest};

    async fn ephemeral() -> (tokio::net::TcpListener, u16) {
        let l = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind");
        let port = l.local_addr().expect("addr").port();
        (l, port)
    }

    /// §3 end to end over the real network: a request delivered to **ONE** node
    /// reaches the other, which registers the same paired candidates and signs at
    /// ingress — then the two exchange a verified partial over the real `/channel`.
    ///
    /// This is what makes selective delivery useless to a post-wrench coordinator,
    /// and it is what V0-4b will rely on so a duress request that reaches one node
    /// arms the rest.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_request_delivered_to_one_node_propagates_to_the_other_over_the_real_paths() {
        let (l0, p0) = ephemeral().await;
        let (l1, p1) = ephemeral().await;
        let fx = Fixture::with_ports(2, &[p0, p1]);
        let node0 = Arc::new(crate::Node::from_toml_str(&fx.config(0, 0, "")).expect("node0"));
        let node1 = Arc::new(crate::Node::from_toml_str(&fx.config(1, 0, "")).expect("node1"));
        tokio::spawn(server::serve(l0, Arc::clone(&node0)));
        tokio::spawn(server::serve(l1, Arc::clone(&node1)));

        let psbt = fx.spend_psbt(&fx.hot_spk, 7);
        let expiry = unix_now() + 3_600;
        let req = fx.spend_request(&psbt, expiry, "net-propagation");

        // ONE node is told. node1 is never contacted by the "coordinator" here.
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://127.0.0.1:{p0}/sign"))
            .json(&TaggedRequest::Spend(req.clone()))
            .send()
            .await
            .expect("sign send");
        assert!(resp.status().is_success());
        let body: SignResponse = resp.json().await.expect("sign body");
        assert!(matches!(body, SignResponse::Accepted(_)), "got {body:?}");

        let ch0 = node0.channel.as_ref().expect("ch0");
        let ch1 = node1.channel.as_ref().expect("ch1");
        let cid = crate::commitment_id_for(&node0, &psbt, expiry);
        assert!(ch0.has_candidate(&cid), "the delivered node registered it");

        // node1 learns the request from node0's propagation alone.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !ch1.has_candidate(&cid) {
            assert!(
                std::time::Instant::now() < deadline,
                "node1 never learned the request: propagation did not reach it"
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        // It did not merely record it — it ran its OWN gates and signed at ingress,
        // which is what makes it useful to the combine.
        assert!(
            ch1.psbt_has_pubkey(&cid, 0, &fx.entries[1].fed_pk),
            "a propagated request must be validated and signed by the receiving node itself"
        );
        // Both halves of the mandatory pair are registered on the propagated-to
        // node too (§4).
        let escape_cid = crate::commitment_id_for(
            &node1,
            &Psbt::from_str(&req.escape_psbt).expect("escape psbt"),
            expiry,
        );
        assert!(
            ch1.has_candidate(&escape_cid),
            "the escape is registered too"
        );
        assert_eq!(
            ch1.pairing(&cid).expect("pairing").1,
            escape_cid,
            "the spend names its escape"
        );

        // node0 releases at its fire event (hold_secs = 0 ⇒ now) and sends its
        // partial to node1 over the real /channel.
        let release = ch0
            .release_partials(&cid, unix_now())
            .expect("the fire gate opens at ingress under hold_secs = 0");
        let env = ch0
            .build_envelope(
                MSG_TYPE_PARTIAL,
                1,
                &release.payloads[0].to_bytes(),
                unix_now(),
            )
            .expect("envelope");
        let bases = ch0.peer_bases(1).expect("peer bases");
        let base = bases.first().expect("peer base");
        let reply = send_envelope(base, &env, std::time::Duration::from_secs(5), 65_536)
            .await
            .expect("send");
        assert_eq!(reply, OutboundReply::Accepted);
        assert!(
            ch1.partial_stored(&cid, 0, 0),
            "node1 stored node0's partial"
        );
    }

    #[test]
    fn a_relayed_request_rechecks_expiry_after_waiting_for_the_sign_lock() {
        let fx = Fixture::new(2, 3);
        let sender = fx.channel_state(0);
        let node = Arc::new(crate::Node::from_toml_str(&fx.config(1, 0, "")).expect("node"));
        // Escape-class has no hot Hold+slack floor, so only the coordinator expiry
        // decides whether this short-lived request remains admissible.
        let spend = fx.spend_psbt(&fx.escape_spk, 7);
        let received_at = unix_now();
        let expiry = received_at + 1;
        let request = fx.spend_request(&spend, expiry, "relay-lock-expiry");
        let tagged = TaggedRequest::Spend(request);
        let envelope = sender
            .build_envelope(MSG_TYPE_REQUEST, 1, &request_payload(&tagged), received_at)
            .expect("request envelope");
        let body = serde_json::to_vec(&envelope).expect("envelope json");

        let sign_guard = node.sign_state.lock().expect("sign state");
        let worker_node = Arc::clone(&node);
        let worker = std::thread::spawn(move || {
            crate::handle_channel_body(&worker_node, &body, received_at)
        });
        std::thread::sleep(Duration::from_secs(2));
        drop(sign_guard);

        assert_eq!(
            worker.join().expect("relay worker"),
            ChannelReply::Accepted,
            "the peer reply remains policy-opaque"
        );
        let cid = crate::commitment_id_for(&node, &spend, expiry);
        assert!(
            !node.channel.as_ref().expect("channel").has_candidate(&cid),
            "a request that expired while queued must not register or backdate a candidate"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_request_that_finishes_after_http_timeout_still_propagates() {
        let (l0, p0) = ephemeral().await;
        let (l1, p1) = ephemeral().await;
        let fx = Fixture::with_ports(2, &[p0, p1]);
        let node0 = Arc::new(crate::Node::from_toml_str(&fx.config(0, 0, "")).expect("node0"));
        let node1 = Arc::new(crate::Node::from_toml_str(&fx.config(1, 0, "")).expect("node1"));
        let served0 = Arc::clone(&node0);
        tokio::spawn(async move {
            axum::serve(
                l0,
                server::app_with_timeout(served0, std::time::Duration::from_millis(1)),
            )
            .await
            .expect("node0 serve");
        });
        tokio::spawn(server::serve(l1, Arc::clone(&node1)));

        // Hold sign-state past the HTTP deadline. The blocking sign job remains
        // detached; when it eventually commits, that same detached job must drain
        // the newly staged outbox entry.
        let gate = Arc::clone(&node0);
        let (held_tx, held_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let holder = std::thread::spawn(move || {
            let _guard = gate.sign_state.lock().expect("sign_state");
            held_tx.send(()).expect("held signal");
            release_rx.recv().expect("release signal");
        });
        held_rx.recv().expect("sign lock held");

        let psbt = fx.spend_psbt(&fx.hot_spk, 7);
        let expiry = unix_now() + 3_600;
        let request = fx.spend_request(&psbt, expiry, "timeout-propagation");
        let response = reqwest::Client::new()
            .post(format!("http://127.0.0.1:{p0}/sign"))
            .json(&TaggedRequest::Spend(request))
            .send()
            .await
            .expect("sign send");
        assert_eq!(response.status().as_u16(), 408);

        release_tx.send(()).expect("release sign job");
        holder.join().expect("holder thread");

        let cid = crate::commitment_id_for(&node1, &psbt, expiry);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !node1.channel.as_ref().expect("channel").has_candidate(&cid) {
            assert!(
                std::time::Instant::now() < deadline,
                "the post-timeout sign committed but its request never propagated"
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_oversized_channel_body_is_a_tagged_reject_not_an_untagged_413() {
        let (l, p) = ephemeral().await;
        let fx = Fixture::with_ports(2, &[p, p + 1]);
        let node = Arc::new(
            crate::Node::from_toml_str(&fx.config(0, 0, "max_msg_bytes = 100\n")).expect("node"),
        );
        tokio::spawn(server::serve(l, Arc::clone(&node)));
        let resp = reqwest::Client::new()
            .post(format!("http://127.0.0.1:{p}/channel"))
            .body(vec![b'x'; 200])
            .send()
            .await
            .expect("send");
        assert_eq!(resp.status().as_u16(), 400);
        assert!(resp.text().await.expect("body").contains("OVERSIZED_BODY"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_global_concurrency_bound_answers_rate_limited() {
        let (l, p) = ephemeral().await;
        let fx = Fixture::with_ports(2, &[p, p + 1]);
        let node = Arc::new(
            crate::Node::from_toml_str(&fx.config(0, 0, "max_concurrent_channel_requests = 1\n"))
                .expect("node"),
        );
        // Hold the only permit so the handler's pre-auth acquire fails.
        let _permit = node
            .channel
            .as_ref()
            .expect("channel")
            .concurrency()
            .try_acquire_owned()
            .expect("permit");
        tokio::spawn(server::serve(l, Arc::clone(&node)));
        let resp = reqwest::Client::new()
            .post(format!("http://127.0.0.1:{p}/channel"))
            .body("{}")
            .send()
            .await
            .expect("send");
        assert_eq!(resp.status().as_u16(), 429);
        assert!(resp.text().await.expect("body").contains("RATE_LIMITED"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_stalled_channel_body_releases_its_pre_auth_permit() {
        // A peer that promises a body (Content-Length) but never sends it must not
        // pin the pre-auth concurrency permit forever — otherwise §8's DoS *guard*
        // is itself a DoS *vector*. With the ONLY permit and a short body-read
        // deadline, a fresh request is serviced once the stalled body's deadline
        // frees the permit (without the deadline every poll would 429 forever).
        use std::io::Write;
        let (l, p) = ephemeral().await;
        let fx = Fixture::with_ports(2, &[p, p + 1]);
        let node = Arc::new(
            crate::Node::from_toml_str(&fx.config(0, 0, "max_concurrent_channel_requests = 1\n"))
                .expect("node"),
        );
        let app = crate::server::app_with_channel_body_timeout(
            Arc::clone(&node),
            std::time::Duration::from_millis(300),
        );
        tokio::spawn(async move { axum::serve(l, app).await.expect("serve") });

        // Raw connection: headers promise a 1000-byte body (< max_msg_bytes, so it is
        // buffered rather than fast-rejected as oversized) and then send nothing.
        let stalled = tokio::task::spawn_blocking(move || {
            let mut s = std::net::TcpStream::connect(("127.0.0.1", p)).expect("connect");
            s.write_all(
                b"POST /channel HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n\
                  Content-Length: 1000\r\nConnection: close\r\n\r\n",
            )
            .expect("write headers");
            s // hold the socket open with no body
        })
        .await
        .expect("stall task");
        // Let the server accept the stalled connection and acquire the only permit
        // BEFORE any poll competes for it (150ms < the 300ms body-read deadline).
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;

        // Once the stalled body's deadline frees the only permit, a fresh /channel
        // request reaches the handler and returns a tagged reply (400 for `{}`, which
        // fails envelope parse) rather than being 429'd forever.
        let client = reqwest::Client::new();
        let mut serviced = false;
        for _ in 0..60 {
            let resp = client
                .post(format!("http://127.0.0.1:{p}/channel"))
                .body("{}")
                .send()
                .await
                .expect("send");
            if resp.status().as_u16() == 400 {
                serviced = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(
            serviced,
            "the stalled body pinned the only concurrency permit — DoS guard exhausted"
        );
        drop(stalled);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn absent_channel_mode_does_not_mount_the_channel_route() {
        let (l, p) = ephemeral().await;
        let fx = Fixture::with_ports(2, &[p, p + 1]);
        let node = Arc::new(
            crate::Node::from_toml_str(&fx.config_with_channel(0, 0, "")).expect("absent node"),
        );
        assert!(node.channel.is_none());
        // Exercise the parser/router seam directly. The runnable daemon refuses
        // this shape below because Model B has no channel-less completion path.
        tokio::spawn(async move {
            axum::serve(l, server::app(node))
                .await
                .expect("test router");
        });
        let resp = reqwest::Client::new()
            .post(format!("http://127.0.0.1:{p}/channel"))
            .body("{}")
            .send()
            .await
            .expect("send");
        assert_eq!(resp.status().as_u16(), 404, "/channel is not mounted");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_runnable_daemon_rejects_absent_channel_mode_before_serving() {
        let (listener, port) = ephemeral().await;
        let fx = Fixture::with_ports(2, &[port, port + 1]);
        let node = Arc::new(
            crate::Node::from_toml_str(&fx.config_with_channel(0, 0, "")).expect("parsed node"),
        );
        let error = server::serve(listener, node)
            .await
            .expect_err("a channel-less Model-B daemon must not accept /sign traffic");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("[channel] is required"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn send_partial_to_a_dead_peer_errors_while_a_live_peer_still_receives() {
        let (l1, p1) = ephemeral().await;
        let fx = Fixture::with_ports(2, &[9000, p1]);
        let node1 = Arc::new(crate::Node::from_toml_str(&fx.config(1, 0, "")).expect("node1"));
        tokio::spawn(server::serve(l1, Arc::clone(&node1)));
        // Sender state (node 0) — never served; used only to build envelopes.
        let ch0 = fx.channel_state(0);
        let psbt = fx.spend_psbt(&fx.hot_spk, 7);
        let payload = fx.partial_payload(&psbt, "cid", 0, 0).to_bytes();
        let live_env = ch0
            .build_envelope("partial", 1, &payload, unix_now())
            .expect("env");
        let dead_env = ch0
            .build_envelope("partial", 1, &payload, unix_now())
            .expect("env");
        let dl = std::time::Duration::from_secs(2);
        let live_base = format!("127.0.0.1:{p1}");
        // Concurrent fan-out: the dead peer errors, the live peer still replies.
        let (live, dead) = tokio::join!(
            send_envelope(&live_base, &live_env, dl, 65_536),
            send_envelope("127.0.0.1:1", &dead_env, dl, 65_536),
        );
        assert!(live.is_ok(), "the live peer must reply: {live:?}");
        assert!(dead.is_err(), "the dead peer must error, not panic");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn send_partial_never_follows_a_redirect_to_an_unendorsed_address() {
        // A peer endpoint that answers with a 307 redirect must NOT cause the signed
        // partial to be re-sent to the redirect target (SSRF / partial leak). With
        // redirects disabled the 307 is surfaced as a misbehaving-peer error and the
        // unendorsed sink is never contacted.
        let (l_sink, p_sink) = ephemeral().await;
        let (l_redir, p_redir) = ephemeral().await;

        // Sink: the unendorsed address the redirect points at. It records any hit and
        // would ACCEPT — so a followed redirect would look like success AND leak.
        let hits = Arc::new(AtomicUsize::new(0));
        let sink_hits = Arc::clone(&hits);
        let sink_app = axum::Router::new().route(
            "/channel",
            axum::routing::post(move || {
                let hits = Arc::clone(&sink_hits);
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    (axum::http::StatusCode::OK, "{\"status\":\"ACCEPTED\"}")
                }
            }),
        );
        tokio::spawn(async move { axum::serve(l_sink, sink_app).await.expect("sink serve") });

        // Redirector: the "peer" whose endpoint is what we POST to; it 307s to the sink.
        let location = format!("http://127.0.0.1:{p_sink}/channel");
        let redir_app = axum::Router::new().route(
            "/channel",
            axum::routing::post(move || {
                let loc = location.clone();
                async move {
                    (
                        axum::http::StatusCode::TEMPORARY_REDIRECT,
                        [(axum::http::header::LOCATION, loc)],
                        "",
                    )
                }
            }),
        );
        tokio::spawn(async move { axum::serve(l_redir, redir_app).await.expect("redir serve") });

        let fx = Fixture::new(2, 3);
        let ch0 = fx.channel_state(0);
        let psbt = fx.spend_psbt(&fx.hot_spk, 7);
        let payload = fx.partial_payload(&psbt, "cid", 0, 0).to_bytes();
        let env = ch0
            .build_envelope("partial", 1, &payload, unix_now())
            .expect("env");
        let base = format!("127.0.0.1:{p_redir}");
        let result = send_envelope(&base, &env, std::time::Duration::from_secs(2), 65_536).await;

        assert!(
            result.is_err(),
            "a redirect must surface as an error, not a valid reply: {result:?}"
        );
        assert_eq!(
            hits.load(Ordering::SeqCst),
            0,
            "the signed partial must never reach the unendorsed redirect target (SSRF)"
        );
    }

    #[test]
    fn parse_reply_requires_the_http_status_and_tag_to_agree() {
        // The four canonical §5b pairs classify; every other pairing is a retriable
        // transport anomaly (`Err`), never a false success. Crucially, a wrong HTTP
        // status carrying a valid `ACCEPTED` tag (a broken endpoint or on-path
        // injection) must NOT be read as Accepted — otherwise the retry loop stops
        // while the partial was never stored (Reviewer-1 P2).
        assert_eq!(
            parse_reply(200, br#"{"status":"ACCEPTED"}"#).expect("accepted"),
            OutboundReply::Accepted
        );
        assert_eq!(
            parse_reply(409, br#"{"status":"UNKNOWN_CANDIDATE"}"#).expect("unknown"),
            OutboundReply::UnknownCandidate
        );
        assert_eq!(
            parse_reply(429, br#"{"status":"RATE_LIMITED","retry_after_secs":7}"#).expect("rl"),
            OutboundReply::RateLimited {
                retry_after_secs: 7
            }
        );
        assert_eq!(
            parse_reply(400, br#"{"status":"REJECTED","reason":"BAD_PARTIAL_SIG"}"#)
                .expect("rejected"),
            OutboundReply::Rejected("BAD_PARTIAL_SIG".to_string())
        );

        // A valid tag under the WRONG status is an error, not a (false) success.
        for (status, body) in [
            (500u16, br#"{"status":"ACCEPTED"}"#.as_slice()),
            (307, br#"{"status":"ACCEPTED"}"#.as_slice()),
            (
                200,
                br#"{"status":"REJECTED","reason":"BAD_PARTIAL_SIG"}"#.as_slice(),
            ),
            (429, br#"{"status":"ACCEPTED"}"#.as_slice()),
            (200, br#"{"status":"UNKNOWN_CANDIDATE"}"#.as_slice()),
        ] {
            let err = parse_reply(status, body)
                .expect_err("a status/tag mismatch must not classify as a valid reply");
            assert!(
                err.to_string().contains("mismatch"),
                "unexpected error for ({status}): {err}"
            );
        }

        // An unknown tag (even at 200) is still an error.
        assert!(parse_reply(200, br#"{"status":"WAT"}"#).is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn retry_re_envelopes_freshly_each_attempt_and_succeeds_after_registration() {
        // Each retry RE-ENVELOPES from the immutable payload (fresh nonce), and the
        // loop stops as soon as the peer registers the candidate (Accepted).
        let fx = Fixture::new(2, 3);
        let ch = fx.channel_state(0);
        let psbt = fx.spend_psbt(&fx.hot_spk, 7);
        let payload = fx.partial_payload(&psbt, "cid", 0, 0).to_bytes();
        let nonces: StdMutex<Vec<String>> = StdMutex::new(Vec::new());
        let calls = AtomicUsize::new(0);
        let start = tokio::time::Instant::now();
        let wall_start = 10_000;
        let backoff = [std::time::Duration::from_secs(1)];
        let outcome = retry_loop(
            || async {
                let env = ch.build_envelope("partial", 1, &payload, unix_now())?;
                nonces.lock().expect("nonces").push(env.nonce.clone());
                let n = calls.fetch_add(1, Ordering::SeqCst);
                Ok(if n < 2 {
                    OutboundReply::UnknownCandidate
                } else {
                    OutboundReply::Accepted
                })
            },
            wall_start + 3_600,
            || wall_start + tokio::time::Instant::now().duration_since(start).as_secs(),
            &backoff,
        )
        .await;
        assert_eq!(outcome, RetryOutcome::Accepted);
        let ns = nonces.lock().expect("nonces");
        assert_eq!(ns.len(), 3, "three attempts (2 unknown, then accepted)");
        assert_eq!(
            ns.iter().collect::<HashSet<_>>().len(),
            3,
            "each attempt drew a FRESH nonce (single-use)"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn retry_gives_up_at_the_commitment_expiry_and_honors_backoff() {
        let calls = AtomicUsize::new(0);
        let start = tokio::time::Instant::now();
        let wall_start = 10_000;
        let backoff = [std::time::Duration::from_secs(1)];
        let outcome = retry_loop(
            || async {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(OutboundReply::UnknownCandidate)
            },
            wall_start + 5,
            || wall_start + tokio::time::Instant::now().duration_since(start).as_secs(),
            &backoff,
        )
        .await;
        assert_eq!(outcome, RetryOutcome::GaveUp);
        // 1s backoff over a 5s budget ⇒ ~5 attempts (never unbounded), and time
        // actually advanced to the deadline.
        let n = calls.load(Ordering::SeqCst);
        assert!((4..=6).contains(&n), "backoff honored: {n} attempts");
        assert!(tokio::time::Instant::now() - start >= Duration::from_secs(5));
    }

    #[tokio::test(start_paused = true)]
    async fn retry_may_attempt_in_the_inclusive_deadline_second() {
        let calls = AtomicUsize::new(0);
        let outcome = retry_loop(
            || async {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(OutboundReply::Accepted)
            },
            10_000,
            || 10_000,
            &[Duration::from_secs(1)],
        )
        .await;

        assert_eq!(outcome, RetryOutcome::Accepted);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "the final legal second must initiate one delivery attempt"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn rate_limited_retry_honors_the_peer_retry_after() {
        let calls = AtomicUsize::new(0);
        let start = tokio::time::Instant::now();
        let wall_start = 10_000;
        let static_backoff = [std::time::Duration::from_secs(10)];
        let outcome = retry_loop(
            || async {
                let n = calls.fetch_add(1, Ordering::SeqCst);
                Ok(if n == 0 {
                    OutboundReply::RateLimited {
                        retry_after_secs: 1,
                    }
                } else {
                    OutboundReply::Accepted
                })
            },
            wall_start + 3,
            || wall_start + tokio::time::Instant::now().duration_since(start).as_secs(),
            &static_backoff,
        )
        .await;
        assert_eq!(outcome, RetryOutcome::Accepted);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(tokio::time::Instant::now() - start, Duration::from_secs(1));
    }

    #[tokio::test(start_paused = true)]
    async fn retry_rechecks_wall_clock_after_forward_and_backward_steps() {
        // A forward step expires the same candidate the receiver would evict, so
        // no second transport attempt may start under the old monotonic deadline.
        let forward_clock = Arc::new(AtomicU64::new(100));
        let forward_attempt_clock = Arc::clone(&forward_clock);
        let forward_now_clock = Arc::clone(&forward_clock);
        let forward_calls = AtomicUsize::new(0);
        let outcome = retry_loop(
            || async {
                forward_calls.fetch_add(1, Ordering::SeqCst);
                forward_attempt_clock.store(111, Ordering::SeqCst);
                Ok(OutboundReply::UnknownCandidate)
            },
            110,
            || forward_now_clock.load(Ordering::SeqCst),
            &[Duration::from_secs(1)],
        )
        .await;
        assert_eq!(outcome, RetryOutcome::GaveUp);
        assert_eq!(forward_calls.load(Ordering::SeqCst), 1);

        // A backward step extends the candidate's wall-clock lifetime. The retry
        // therefore survives past the one-time monotonic deadline the old code
        // would have computed, while its six-second backoff remains monotonic.
        let backward_start = tokio::time::Instant::now();
        let backward_clock = Arc::new(AtomicU64::new(100));
        let backward_attempt_clock = Arc::clone(&backward_clock);
        let backward_now_clock = Arc::clone(&backward_clock);
        let backward_calls = AtomicUsize::new(0);
        let outcome = retry_loop(
            || async {
                let call = backward_calls.fetch_add(1, Ordering::SeqCst);
                if call == 0 {
                    backward_attempt_clock.store(95, Ordering::SeqCst);
                    Ok(OutboundReply::UnknownCandidate)
                } else {
                    Ok(OutboundReply::Accepted)
                }
            },
            105,
            || backward_now_clock.load(Ordering::SeqCst),
            &[Duration::from_secs(6)],
        )
        .await;
        assert_eq!(outcome, RetryOutcome::Accepted);
        assert_eq!(backward_calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            tokio::time::Instant::now() - backward_start,
            Duration::from_secs(6)
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn retry_fails_over_from_a_dead_endorsed_endpoint_to_a_live_one() {
        let (dead_listener, dead_port) = ephemeral().await;
        let (sender_listener, sender_port) = ephemeral().await;
        let (live_listener, live_port) = ephemeral().await;
        // Hold all three binds until their addresses are distinct, then release
        // only the two endpoints intended to be unreachable/unserved.
        drop(dead_listener);
        drop(sender_listener);
        let mut fx = Fixture::with_ports(2, &[sender_port, live_port]);
        fx.replace_endpoints(
            1,
            vec![
                format!("127.0.0.1:{dead_port}"),
                format!("127.0.0.1:{live_port}"),
            ],
        );
        let sender = fx.channel_state(0);
        let receiver = Arc::new(crate::Node::from_toml_str(&fx.config(1, 0, "")).expect("node"));
        let psbt = fx.spend_psbt(&fx.hot_spk, 7);
        receiver
            .channel
            .as_ref()
            .expect("channel")
            .register_candidate(fx.candidate(&psbt, "cid", unix_now() + 30));
        tokio::spawn(server::serve(live_listener, Arc::clone(&receiver)));
        let payload = fx.partial_payload(&psbt, "cid", 0, 0);

        retry_message_until(
            &sender,
            MSG_TYPE_PARTIAL,
            1,
            &payload.to_bytes(),
            unix_now() + 5,
        )
        .await
        .expect("the second endorsed endpoint is live");
        assert!(receiver
            .channel
            .as_ref()
            .expect("channel")
            .partial_stored("cid", 0, 0));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn try_partial_endpoints_never_initiates_a_send_past_commitment_expiry() {
        // §6 bounded-until-expiry at ENDPOINT granularity: once the commitment has
        // expired, no endpoint is contacted at all — even a live, candidate-ready
        // peer stores nothing. A live expiry over the identical setup DOES store,
        // proving the expiry gate (not a broken endpoint) suppressed the send.
        let (sender_listener, sender_port) = ephemeral().await;
        let (live_listener, live_port) = ephemeral().await;
        drop(sender_listener);
        let fx = Fixture::with_ports(2, &[sender_port, live_port]);
        let sender = fx.channel_state(0);
        let receiver = Arc::new(crate::Node::from_toml_str(&fx.config(1, 0, "")).expect("node"));
        let psbt = fx.spend_psbt(&fx.hot_spk, 7);
        receiver
            .channel
            .as_ref()
            .expect("channel")
            .register_candidate(fx.candidate(&psbt, "cid", unix_now() + 30));
        tokio::spawn(server::serve(live_listener, Arc::clone(&receiver)));
        let payload = fx.partial_payload(&psbt, "cid", 0, 0).to_bytes();
        let endpoints = sender.peer_bases(1).expect("peer endpoints");

        // A deadline strictly in the past breaks before any send is initiated.
        let expired = try_endpoints(
            &sender,
            MSG_TYPE_PARTIAL,
            1,
            &payload,
            &endpoints,
            unix_now().saturating_sub(1),
        )
        .await;
        assert!(
            expired.is_err(),
            "no send may start once the commitment has expired"
        );
        assert!(
            !receiver
                .channel
                .as_ref()
                .expect("channel")
                .partial_stored("cid", 0, 0),
            "an expired commitment contacts no endpoint, so nothing is stored"
        );

        // A live expiry over the identical endpoint reaches the peer and stores.
        let live = try_endpoints(
            &sender,
            MSG_TYPE_PARTIAL,
            1,
            &payload,
            &endpoints,
            unix_now() + 30,
        )
        .await
        .expect("a live commitment reaches the endorsed endpoint");
        assert_eq!(live, OutboundReply::Accepted);
        assert!(
            receiver
                .channel
                .as_ref()
                .expect("channel")
                .partial_stored("cid", 0, 0),
            "a live send stores the partial"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn retry_stops_immediately_on_a_permanent_rejection() {
        let calls = AtomicUsize::new(0);
        let start = tokio::time::Instant::now();
        let wall_start = 10_000;
        let backoff = [std::time::Duration::from_secs(1)];
        let outcome = retry_loop(
            || async {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(OutboundReply::Rejected("BAD_PARTIAL_SIG".to_string()))
            },
            wall_start + 3_600,
            || wall_start + tokio::time::Instant::now().duration_since(start).as_secs(),
            &backoff,
        )
        .await;
        assert_eq!(
            outcome,
            RetryOutcome::Rejected("BAD_PARTIAL_SIG".to_string())
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1, "a REJECTED is not retried");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn saturated_channel_load_does_not_starve_events() {
        // The isolation the async migration bought: a burst of /channel work must
        // not block /events (independent locks + spawn_blocking).
        let (l, p) = ephemeral().await;
        let fx = Fixture::with_ports(2, &[p, p + 1]);
        let node = Arc::new(crate::Node::from_toml_str(&fx.config(0, 0, "")).expect("node"));
        tokio::spawn(server::serve(l, Arc::clone(&node)));
        let client = reqwest::Client::new();
        // Fire a burst of channel requests (they reject fast; the point is load).
        let mut burst = Vec::new();
        for _ in 0..64 {
            let c = client.clone();
            burst.push(tokio::spawn(async move {
                let _ = c
                    .post(format!("http://127.0.0.1:{p}/channel"))
                    .body("{}")
                    .send()
                    .await;
            }));
        }
        // /events must answer promptly despite the concurrent channel load.
        let events = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.get(format!("http://127.0.0.1:{p}/events")).send(),
        )
        .await
        .expect("/events was starved by channel load")
        .expect("events send");
        assert!(events.status().is_success());
        // The watchtower tick must also run to completion under the same load
        // (channel ingest shares no lock the scan needs for more than a moment).
        let backend = crate::chain::mock::MockBackend {
            spends: vec![],
            ..Default::default()
        };
        let node = Arc::clone(&node);
        let tick = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            tokio::task::spawn_blocking(move || node.watchtower_tick(&backend, 0)),
        )
        .await
        .expect("watchtower tick was starved by channel load")
        .expect("tick task");
        assert!(tick.is_ok(), "watchtower tick completed under channel load");
        for j in burst {
            let _ = j.await;
        }
    }
}

#[cfg(test)]
mod fire {
    //! The V0-8b spine: **release only at fire** (ADR-0012 invariant 7), then
    //! combine + broadcast behind package acceptance.
    use super::fixture::{deliver, Fixture};
    use super::*;
    use crate::chain::{mock::MockBackend, Prevout};
    use bitcoin::consensus::encode::serialize;
    use bitcoin::{Amount, OutPoint, TxOut};
    use vault_proto::SignResponse;

    const NOW: u64 = 1_752_000_000;
    const HOLD: u64 = 3_600;
    const EXPIRY: u64 = NOW + 172_800;

    /// A 3-of-5 vault whose node 0 has ACCEPTED one honest hot spend under a Hold,
    /// plus the spend's commitment id and its PSBT.
    fn accepted_hot_spend(hold_secs: u64) -> (Fixture, crate::Node, String, Psbt) {
        let fx = Fixture::new(3, 5);
        let node = crate::Node::from_toml_str(&fx.config(0, hold_secs, "")).expect("config");
        let psbt = fx.spend_psbt(&fx.hot_spk, 7);
        let request = fx.spend_request(&psbt, EXPIRY, "fire-fixture");
        assert!(matches!(
            crate::handle_sign(&node, &request, NOW).expect("decodable"),
            SignResponse::Accepted(_)
        ));
        let cid = crate::commitment_id_for(&node, &psbt, EXPIRY);
        (fx, node, cid, psbt)
    }

    /// A backend whose chain view has `psbt`'s single prevout confirmed — so
    /// package assembly needs no ancestor.
    fn backend_for(psbt: &Psbt) -> MockBackend {
        let mut backend = MockBackend::default();
        backend.prevouts.insert(
            psbt.unsigned_tx.input[0].previous_output,
            Prevout {
                txout: psbt.inputs[0]
                    .witness_utxo
                    .clone()
                    .expect("fixture witness_utxo"),
                confirmed: true,
            },
        );
        backend
    }

    /// Give `cid` `count` peer partials on input 0 (node 0 signed at ingress, so
    /// `count = threshold - 1` reaches quorum).
    fn deliver_peer_partials(
        fx: &Fixture,
        channel: &ChannelState,
        psbt: &Psbt,
        cid: &str,
        count: u16,
    ) {
        for signer in 1..=count {
            let payload = fx.partial_payload(psbt, cid, 0, signer);
            assert_eq!(
                deliver(
                    &fx.channel_state(signer),
                    channel,
                    MSG_TYPE_PARTIAL,
                    &payload.to_bytes(),
                    NOW,
                    NOW
                ),
                ChannelReply::Accepted,
                "peer {signer}'s partial must verify and store"
            );
        }
    }

    // -- the partial-release gate (§1, ADR-0012 invariant 7) -----------------

    /// **The load-bearing test.** A node signs at ingress but releases NOTHING
    /// until its candidate's authorized fire event.
    ///
    /// Releasing at ingress would let one compromised node (or anything that could
    /// solicit a partial) collect `t` peers' partials during the Hold and broadcast
    /// early — breaking the Hold AND duress silence without compromising `t` nodes.
    #[test]
    fn no_partial_is_released_before_the_candidate_fires() {
        let (_fx, node, cid, _psbt) = accepted_hot_spend(HOLD);
        let channel = node.channel.as_ref().expect("channel");

        // Signed at ingress — the partial exists...
        assert!(
            channel.psbt_has_pubkey(&cid, 0, &node.pubkey),
            "Model B signs at ingress"
        );
        // ...and is withheld for the whole Hold. Every instant before fire.
        for now in [NOW, NOW + 1, NOW + HOLD / 2, NOW + HOLD - 1] {
            assert!(
                channel.release_partials(&cid, now).is_none(),
                "a partial escaped at {now}, {}s before the fire event",
                (NOW + HOLD) - now
            );
        }
        assert!(!channel.was_released(&cid));
    }

    /// The same gate from the attacker's side: a compromised peer that has the
    /// candidate registered and asks for partials during the Hold gets none. The
    /// only door is `release_partials`, and it is shut until fire.
    #[test]
    fn a_compromised_peer_cannot_obtain_a_partial_before_fire() {
        let (fx, node, cid, psbt) = accepted_hot_spend(HOLD);
        let channel = node.channel.as_ref().expect("channel");

        // The compromised peer floods the node with its own partials — a
        // `partial` message is the only thing it can send about this candidate.
        // Storing them tells it nothing: nothing goes back.
        deliver_peer_partials(&fx, channel, &psbt, &cid, 2);
        assert!(
            channel.release_partials(&cid, NOW + HOLD - 1).is_none(),
            "no peer action can open the release gate early"
        );
        assert!(!channel.was_released(&cid), "nothing left the node");
    }

    #[test]
    fn at_its_fire_event_the_node_releases_its_partial_exactly_once() {
        let (_fx, node, cid, psbt) = accepted_hot_spend(HOLD);
        let channel = node.channel.as_ref().expect("channel");

        let release = channel
            .release_partials(&cid, NOW + HOLD)
            .expect("the fire event has arrived");
        assert_eq!(release.payloads.len(), psbt.inputs.len());
        assert_eq!(release.payloads[0].signer_node_id, 0);
        assert!(channel.was_released(&cid));
        // Once. A re-tick must not re-send.
        assert!(
            channel.release_partials(&cid, NOW + HOLD + 1).is_none(),
            "release is a single authorized event, not a repeatable one"
        );
    }

    /// The combine deadline is inclusive. In the equality case required by
    /// `EXPIRY_TOO_SHORT`, pruning must not delete a quorum-complete candidate
    /// before its final authorized fire pass.
    #[tokio::test]
    async fn a_quorum_at_commitment_expiry_still_broadcasts_in_the_final_legal_second() {
        let fx = Fixture::new(3, 5);
        let node = crate::Node::from_toml_str(&fx.config(0, 0, "")).expect("config");
        let psbt = fx.spend_psbt(&fx.hot_spk, 7);
        let expiry = NOW + 60;
        let request = fx.spend_request(&psbt, expiry, "inclusive-expiry");
        assert!(matches!(
            crate::handle_sign(&node, &request, NOW).expect("decodable"),
            SignResponse::Accepted(_)
        ));
        let cid = crate::commitment_id_for(&node, &psbt, expiry);
        deliver_peer_partials(&fx, node.channel.as_ref().expect("channel"), &psbt, &cid, 2);

        assert_eq!(
            crate::fire_tick(Arc::new(node), Arc::new(backend_for(&psbt)), expiry).await,
            1,
            "expiry == deadline remains an authorized combine+broadcast instant"
        );
    }

    /// The combine window closes at `min(expiry, fire_at + combine_slack_secs)`:
    /// past it there is no point releasing a partial nobody can still combine.
    #[test]
    fn nothing_is_released_after_the_combine_window_closes() {
        let (_fx, node, cid, _psbt) = accepted_hot_spend(HOLD);
        let channel = node.channel.as_ref().expect("channel");
        let window = channel.fire_window(&cid).expect("the spend is scheduled");
        assert_eq!(window.fire_at, NOW + HOLD);
        assert_eq!(
            window.deadline,
            NOW + HOLD + 60,
            "the default combine slack"
        );
        assert!(channel
            .release_partials(&cid, window.deadline + 1)
            .is_none());
    }

    // -- the mandatory pair (§4) --------------------------------------------

    /// Every SpendRequest registers TWO distinct exact-byte candidates, both
    /// signed at ingress, each naming the other. The spend carries a fire window;
    /// the escape carries NONE — nothing in V0-8b schedules it, so its partials can
    /// never be released. V0-4b's arm is what gives it one, and it then rides this
    /// same path.
    #[test]
    fn a_spend_request_registers_a_paired_spend_and_escape_both_signed_and_only_the_spend_fires() {
        let (fx, node, spend_cid, _psbt) = accepted_hot_spend(HOLD);
        let channel = node.channel.as_ref().expect("channel");
        let escape_psbt = fx.spend_psbt(&fx.escape_spk, 7);
        let escape_cid = crate::commitment_id_for(&node, &escape_psbt, EXPIRY);

        assert_ne!(spend_cid, escape_cid, "two distinct exact-byte commitments");
        assert_eq!(
            channel.store_len(),
            2,
            "the pair is registered, not just the spend"
        );

        // Roles, and the pairing in both directions.
        assert_eq!(
            channel.pairing(&spend_cid).expect("spend registered"),
            (CandidateRole::Spend, escape_cid.clone())
        );
        assert_eq!(
            channel.pairing(&escape_cid).expect("escape registered"),
            (CandidateRole::Escape, spend_cid.clone())
        );

        // BOTH signed at ingress.
        assert!(channel.psbt_has_pubkey(&spend_cid, 0, &node.pubkey));
        assert!(
            channel.psbt_has_pubkey(&escape_cid, 0, &node.pubkey),
            "the escape is signed at ingress too, so it is ready if V0-4b ever arms it"
        );

        // Only the spend is scheduled. The escape is inert — signed, registered,
        // and unreleasable at every instant.
        assert!(channel.fire_window(&spend_cid).is_some());
        assert!(
            channel.fire_window(&escape_cid).is_none(),
            "V0-8b schedules no escape; V0-4b's duress arm does"
        );
        for now in [NOW, NOW + HOLD, EXPIRY - 1] {
            assert!(
                channel.release_partials(&escape_cid, now).is_none(),
                "an unscheduled escape must never release, not even at {now}"
            );
        }
    }

    // -- combine + broadcast (§1, §5) ---------------------------------------

    #[test]
    fn with_quorum_on_every_input_the_node_package_validates_then_broadcasts() {
        let (fx, node, cid, psbt) = accepted_hot_spend(0);
        let channel = node.channel.as_ref().expect("channel");
        let backend = backend_for(&psbt);
        assert!(
            node.sign_state
                .lock()
                .expect("sign_state")
                .pending
                .has_any(NOW),
            "an accepted hot spend starts pending"
        );

        // Node 0 signed at ingress; two peers make 3-of-5.
        deliver_peer_partials(&fx, channel, &psbt, &cid, 2);
        let broadcast =
            crate::combine_and_broadcast(&node, &backend, std::slice::from_ref(&cid), NOW);
        assert_eq!(broadcast, 1);
        assert!(
            !node
                .sign_state
                .lock()
                .expect("sign_state")
                .pending
                .has_any(NOW),
            "successful node broadcast settles the pending spend so refreshes can resume"
        );

        // The package was tested BEFORE the broadcast, and it is the spend alone
        // (its prevout is confirmed, so it carries no ancestor).
        let packages = backend.packages_tested.lock().expect("packages");
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].len(), 1);
        let broadcasts = backend.broadcasts.lock().expect("broadcasts");
        assert_eq!(broadcasts.len(), 1);
        let tx: bitcoin::Transaction =
            bitcoin::consensus::deserialize(&broadcasts[0]).expect("a real transaction");
        assert_eq!(
            tx.compute_txid(),
            psbt.unsigned_tx.compute_txid(),
            "the broadcast tx is the exact transaction the user signed"
        );
        assert!(
            !tx.input[0].witness.is_empty(),
            "the broadcast tx is finalized, not a bare unsigned tx"
        );
    }

    #[test]
    fn below_quorum_nothing_is_broadcast_and_the_candidate_stays_collectable() {
        let (fx, node, cid, psbt) = accepted_hot_spend(0);
        let channel = node.channel.as_ref().expect("channel");
        let backend = backend_for(&psbt);

        // Node 0 + one peer = 2 of the 3 needed.
        deliver_peer_partials(&fx, channel, &psbt, &cid, 1);
        assert_eq!(
            crate::combine_and_broadcast(&node, &backend, std::slice::from_ref(&cid), NOW),
            0,
            "t-1 signatures must not combine"
        );
        assert!(backend.packages_tested.lock().expect("p").is_empty());
        assert!(backend.broadcasts.lock().expect("b").is_empty());

        // Still collectable: the late third partial completes it.
        deliver_peer_partials(&fx, channel, &psbt, &cid, 2);
        assert_eq!(
            crate::combine_and_broadcast(&node, &backend, &[cid], NOW),
            1,
            "a late partial must still complete the combine"
        );
    }

    /// Quorum is per INPUT, never a total. A transaction with `t` signatures on
    /// input 0 and none on input 1 cannot be finalized, and a global count would
    /// wrongly call it ready.
    #[test]
    fn quorum_is_required_on_every_input_of_a_multi_input_spend() {
        let fx = Fixture::new(3, 5);
        let node = crate::Node::from_toml_str(&fx.config(0, 0, "")).expect("config");
        let psbt = fx.two_input_spend_psbt(&fx.hot_spk);
        let escape = fx.two_input_spend_psbt(&fx.escape_spk);
        let mut request = fx.spend_request(&psbt, EXPIRY, "multi-input");
        request.escape_psbt = escape.to_string();
        fx.coord_sign(&mut request, "multi-input-resign");
        assert!(matches!(
            crate::handle_sign(&node, &request, NOW).expect("decodable"),
            SignResponse::Accepted(_)
        ));
        let cid = crate::commitment_id_for(&node, &psbt, EXPIRY);
        let channel = node.channel.as_ref().expect("channel");
        let mut backend = MockBackend::default();
        for input in &psbt.inputs {
            // Both prevouts confirmed.
            backend.prevouts.insert(
                psbt.unsigned_tx.input[psbt
                    .inputs
                    .iter()
                    .position(|i| std::ptr::eq(i, input))
                    .unwrap_or(0)]
                .previous_output,
                Prevout {
                    txout: input.witness_utxo.clone().expect("witness_utxo"),
                    confirmed: true,
                },
            );
        }
        for (index, txin) in psbt.unsigned_tx.input.iter().enumerate() {
            backend.prevouts.insert(
                txin.previous_output,
                Prevout {
                    txout: psbt.inputs[index]
                        .witness_utxo
                        .clone()
                        .expect("witness_utxo"),
                    confirmed: true,
                },
            );
        }

        // Quorum on input 0 ONLY: node 0 signed both at ingress, two peers sign
        // just input 0.
        for signer in 1..=2u16 {
            let payload = fx.partial_payload(&psbt, &cid, 0, signer);
            assert_eq!(
                deliver(
                    &fx.channel_state(signer),
                    channel,
                    MSG_TYPE_PARTIAL,
                    &payload.to_bytes(),
                    NOW,
                    NOW
                ),
                ChannelReply::Accepted
            );
        }
        assert_eq!(
            crate::combine_and_broadcast(&node, &backend, std::slice::from_ref(&cid), NOW),
            0,
            "input 1 has only this node's signature: t-of-n is per input"
        );

        // Complete input 1 and it combines.
        for signer in 1..=2u16 {
            let payload = fx.partial_payload(&psbt, &cid, 1, signer);
            assert_eq!(
                deliver(
                    &fx.channel_state(signer),
                    channel,
                    MSG_TYPE_PARTIAL,
                    &payload.to_bytes(),
                    NOW,
                    NOW
                ),
                ChannelReply::Accepted
            );
        }
        assert_eq!(
            crate::combine_and_broadcast(&node, &backend, &[cid], NOW),
            1,
            "with quorum on EVERY input the multi-input spend finalizes"
        );
    }

    /// A backend that refuses the package: nothing is broadcast, nothing panics,
    /// and the candidate stays eligible for the next tick.
    #[test]
    fn a_backend_that_rejects_the_package_broadcasts_nothing_and_does_not_panic() {
        let (fx, node, cid, psbt) = accepted_hot_spend(0);
        let channel = node.channel.as_ref().expect("channel");
        let mut backend = backend_for(&psbt);
        backend.package_rejection = Some("insufficient fee".to_string());

        deliver_peer_partials(&fx, channel, &psbt, &cid, 2);
        assert_eq!(
            crate::combine_and_broadcast(&node, &backend, std::slice::from_ref(&cid), NOW),
            0
        );
        assert_eq!(
            backend.packages_tested.lock().expect("p").len(),
            1,
            "the package WAS tested"
        );
        assert!(
            backend.broadcasts.lock().expect("b").is_empty(),
            "a rejected package must not be broadcast"
        );

        // Not marked broadcast: a later tick against a healed backend still fires.
        let healthy = backend_for(&psbt);
        assert_eq!(
            crate::combine_and_broadcast(&node, &healthy, &[cid], NOW),
            1,
            "a package rejection is transient, not terminal"
        );
    }

    /// Blocking prevout/package RPCs may start inside the combine window and finish
    /// after it. The node must re-read its clock immediately before broadcast; a
    /// pass-start timestamp is not continuing authorization to send late.
    #[test]
    fn a_candidate_that_crosses_its_deadline_during_package_checks_is_not_broadcast() {
        use std::cell::Cell;

        let (fx, node, cid, psbt) = accepted_hot_spend(0);
        let channel = node.channel.as_ref().expect("channel");
        let backend = backend_for(&psbt);
        deliver_peer_partials(&fx, channel, &psbt, &cid, 2);

        let reads = Cell::new(0usize);
        let clock = || {
            let read = reads.get();
            reads.set(read + 1);
            match read {
                // Quorum/finalization begins inside the inclusive window.
                0 => NOW,
                // The package RPC completed after the default 60s deadline.
                _ => NOW + 61,
            }
        };
        assert_eq!(
            crate::combine_and_broadcast_with_clock(
                &node,
                &backend,
                std::slice::from_ref(&cid),
                clock,
            ),
            0
        );
        assert_eq!(
            backend.packages_tested.lock().expect("p").len(),
            1,
            "the deadline crossed during the blocking package path"
        );
        assert!(
            backend.broadcasts.lock().expect("b").is_empty(),
            "sendrawtransaction must not run after the combine deadline"
        );
    }

    /// ADR-0012 build-over-mempool, through the real broadcast path: a spend that
    /// chains off this vault's own unconfirmed spend-change carries that parent in
    /// its package and broadcasts.
    #[test]
    fn a_spend_over_a_vault_authorized_unconfirmed_parent_broadcasts_against_the_mempool_chain() {
        let fx = Fixture::new(3, 5);
        let node = crate::Node::from_toml_str(&fx.config(0, 0, "")).expect("config");

        // The parent: an accepted vault spend, so its txid is authorized.
        let parent = fx.spend_psbt(&fx.hot_spk, 7);
        let parent_request = fx.spend_request(&parent, EXPIRY, "chain-parent");
        assert!(matches!(
            crate::handle_sign(&node, &parent_request, NOW).expect("decodable"),
            SignResponse::Accepted(_)
        ));
        let parent_txid = parent.unsigned_tx.compute_txid();
        assert!(
            node.authorized
                .lock()
                .expect("authorized")
                .contains(&parent_txid),
            "an accepted spend is vault-authorized"
        );

        // The child spends the parent's (unconfirmed) output.
        let child = fx.spend_psbt_over(&fx.hot_spk, OutPoint::new(parent_txid, 0));
        let child_escape = fx.spend_psbt_over(&fx.escape_spk, OutPoint::new(parent_txid, 0));
        let mut child_request = fx.spend_request(&child, EXPIRY, "chain-child");
        child_request.escape_psbt = child_escape.to_string();
        fx.coord_sign(&mut child_request, "chain-child-resign");
        assert!(matches!(
            crate::handle_sign(&node, &child_request, NOW).expect("decodable"),
            SignResponse::Accepted(_)
        ));
        let child_cid = crate::commitment_id_for(&node, &child, EXPIRY);
        let channel = node.channel.as_ref().expect("channel");
        deliver_peer_partials(&fx, channel, &child, &child_cid, 2);

        let mut backend = MockBackend::default();
        backend.prevouts.insert(
            OutPoint::new(parent_txid, 0),
            Prevout {
                txout: TxOut {
                    script_pubkey: fx.vault_spk.clone(),
                    value: Amount::from_sat(100_000_000),
                },
                // UNCONFIRMED — the common case for vault spend-change.
                confirmed: false,
            },
        );
        backend
            .raw_txs
            .insert(parent_txid, serialize(&parent.unsigned_tx));
        // Deliberately do NOT expose the parent's own input through `prevout`.
        // Real bitcoind's gettxout returns null because the mempool parent already
        // spent it; the ancestor walk must stop via mempool membership instead.

        assert_eq!(
            crate::combine_and_broadcast(&node, &backend, &[child_cid], NOW),
            1
        );
        let packages = backend.packages_tested.lock().expect("p");
        assert_eq!(
            packages[0].len(),
            1,
            "the authorized parent is already in the mempool, so Core tests only the new child"
        );
        let tested: Transaction =
            bitcoin::consensus::deserialize(&packages[0][0]).expect("tested transaction");
        assert_eq!(
            tested.compute_txid(),
            child.unsigned_tx.compute_txid(),
            "the finalized candidate is tested against Core's existing ancestor view"
        );
    }

    /// The toxic-deposit rule through the real broadcast path: a spend chaining off
    /// an unconfirmed deposit this node never authorized is not broadcast at all.
    #[test]
    fn a_spend_over_an_external_unconfirmed_deposit_is_never_broadcast() {
        let fx = Fixture::new(3, 5);
        let node = crate::Node::from_toml_str(&fx.config(0, 0, "")).expect("config");
        let deposit_txid = bitcoin::Txid::from_byte_array([0xEE; 32]);
        let spend = fx.spend_psbt_over(&fx.hot_spk, OutPoint::new(deposit_txid, 0));
        let escape = fx.spend_psbt_over(&fx.escape_spk, OutPoint::new(deposit_txid, 0));
        let mut request = fx.spend_request(&spend, EXPIRY, "toxic-deposit");
        request.escape_psbt = escape.to_string();
        fx.coord_sign(&mut request, "toxic-deposit-resign");
        assert!(matches!(
            crate::handle_sign(&node, &request, NOW).expect("decodable"),
            SignResponse::Accepted(_)
        ));
        let cid = crate::commitment_id_for(&node, &spend, EXPIRY);
        let channel = node.channel.as_ref().expect("channel");
        deliver_peer_partials(&fx, channel, &spend, &cid, 2);

        let mut backend = MockBackend::default();
        backend.prevouts.insert(
            OutPoint::new(deposit_txid, 0),
            Prevout {
                txout: TxOut {
                    script_pubkey: fx.vault_spk.clone(),
                    value: Amount::from_sat(100_000_000),
                },
                confirmed: false,
            },
        );
        // The deposit is NOT in the node's authorized set: nobody validated it.
        assert!(!node
            .authorized
            .lock()
            .expect("authorized")
            .contains(&deposit_txid));

        assert_eq!(
            crate::combine_and_broadcast(&node, &backend, &[cid], NOW),
            0,
            "an external unconfirmed deposit's parent can be replaced out from under \
             this spend, so it is excluded"
        );
        assert!(backend.broadcasts.lock().expect("b").is_empty());
    }

    /// A candidate registered LATE (its peer's partials arrived first) still
    /// combines: an early partial is answered UNKNOWN_CANDIDATE and retried, and
    /// once the candidate exists the retry lands.
    #[test]
    fn a_partial_arriving_before_its_candidate_is_retriable_not_lost() {
        let fx = Fixture::new(3, 5);
        let node = crate::Node::from_toml_str(&fx.config(0, 0, "")).expect("config");
        let psbt = fx.spend_psbt(&fx.hot_spk, 7);
        let cid = crate::commitment_id_for(&node, &psbt, EXPIRY);
        let channel = node.channel.as_ref().expect("channel");

        // The peer is ahead of us: no candidate yet.
        let payload = fx.partial_payload(&psbt, &cid, 0, 1);
        assert_eq!(
            deliver(
                &fx.channel_state(1),
                channel,
                MSG_TYPE_PARTIAL,
                &payload.to_bytes(),
                NOW,
                NOW
            ),
            ChannelReply::UnknownCandidate,
            "a partial for an unregistered candidate is retriable, never a permanent reject"
        );

        // Our own ingress catches up, and the peer's retry lands.
        let request = fx.spend_request(&psbt, EXPIRY, "late-registration");
        assert!(matches!(
            crate::handle_sign(&node, &request, NOW).expect("decodable"),
            SignResponse::Accepted(_)
        ));
        deliver_peer_partials(&fx, channel, &psbt, &cid, 2);
        let backend = backend_for(&psbt);
        assert_eq!(
            crate::combine_and_broadcast(&node, &backend, &[cid], NOW),
            1
        );
    }

    /// A dead peer costs redundancy, never the spend. With 3-of-5, this node plus
    /// two live peers is a quorum — the other two can be silent, unreachable, or
    /// rebooted, and the combine proceeds without them. (The fan-out's own
    /// dead-peer behaviour — an `Err`, never a panic, and never blocking a live
    /// send — is covered in `net`.)
    #[test]
    fn a_dead_peer_costs_redundancy_but_not_the_combine() {
        let (fx, node, cid, psbt) = accepted_hot_spend(0);
        let channel = node.channel.as_ref().expect("channel");
        let backend = backend_for(&psbt);

        // Peers 3 and 4 never answer. Peers 1 and 2 do.
        deliver_peer_partials(&fx, channel, &psbt, &cid, 2);
        assert_eq!(
            crate::combine_and_broadcast(&node, &backend, std::slice::from_ref(&cid), NOW),
            1,
            "2 of 4 peers is enough for 3-of-5: the silent two are not needed"
        );
    }

    /// The redundant-broadcast steady state (ADR-0012): every node fires on its own
    /// clock, so all but the race winner find the exact spend already in their
    /// mempool. A node that treated that as a failure would never clear its pending
    /// Hold and would wrongly subordinate refreshes until commitment expiry. The
    /// losing node instead recognizes settlement independently of local quorum — it
    /// marks the candidate broadcast and clears the pending spend while pushing
    /// nothing of its own.
    #[test]
    fn a_peer_winning_the_broadcast_race_settles_even_without_local_quorum() {
        let (_fx, node, cid, psbt) = accepted_hot_spend(0);
        let mut backend = backend_for(&psbt);
        // A peer already broadcast this exact tx: it sits in THIS node's mempool.
        backend.raw_txs.insert(
            psbt.unsigned_tx.compute_txid(),
            serialize(&psbt.unsigned_tx),
        );
        // No peer partial reached this node: it has only its own ingress signature,
        // strictly below the 3-of-5 threshold.
        assert!(
            node.sign_state
                .lock()
                .expect("sign_state")
                .pending
                .has_any(NOW),
            "the accepted hot spend starts pending"
        );

        // This node pushes NOTHING (the peer already did), but still settles.
        assert_eq!(
            crate::combine_and_broadcast(&node, &backend, std::slice::from_ref(&cid), NOW),
            0,
            "the returned count is this node's own broadcasts, and it made none"
        );
        assert!(
            backend.broadcasts.lock().expect("b").is_empty(),
            "a lost race must not re-push the already-settled tx"
        );
        assert!(
            !node
                .sign_state
                .lock()
                .expect("sign_state")
                .pending
                .has_any(NOW),
            "recognizing settlement clears the pending Hold so refreshes resume"
        );
        // Marked broadcast: a later tick does not re-attempt.
        assert_eq!(
            crate::combine_and_broadcast(&node, &backend, &[cid], NOW),
            0
        );
        assert!(backend.broadcasts.lock().expect("b").is_empty());
    }

    #[tokio::test]
    async fn a_peer_settlement_seen_after_the_combine_window_still_clears_pending() {
        let (_fx, node, cid, psbt) = accepted_hot_spend(0);
        let node = std::sync::Arc::new(node);
        let mut backend = backend_for(&psbt);
        backend.raw_txs.insert(
            psbt.unsigned_tx.compute_txid(),
            serialize(&psbt.unsigned_tx),
        );
        let backend: std::sync::Arc<dyn crate::chain::ChainBackend + Send + Sync> =
            std::sync::Arc::new(backend);

        // The default combine deadline was NOW + 60. This pass starts after it,
        // with no peer partials, so it may only recognize the peer's settlement —
        // never release, finalize, or broadcast locally.
        assert_eq!(
            crate::fire_tick(std::sync::Arc::clone(&node), backend, NOW + 61).await,
            0
        );
        assert!(
            !node
                .sign_state
                .lock()
                .expect("sign_state")
                .pending
                .has_any(NOW + 61),
            "settlement releases refresh subordination even after the combine window"
        );
        assert!(
            !node.channel.as_ref().expect("channel").was_released(&cid),
            "post-window settlement recognition must not reopen partial release"
        );
    }

    #[tokio::test]
    async fn post_window_settlement_polling_stops_after_the_observation_grace() {
        // The candidate fires at NOW (hold 0) and its combine window closes at
        // NOW + 60; the settlement-observation window extends that by
        // SETTLEMENT_OBSERVE_GRACE_SECS (360) to NOW + 420. Its commitment expiry
        // (EXPIRY = NOW + 172_800) is far beyond, so it is still resident — the ONLY
        // reason a pass past the grace skips it is the bound. Even with the exact tx
        // confirmed on-chain, one second past the grace this node no longer polls
        // it, so it does not recognize the (impossible-in-practice) settlement and
        // falls back to the commitment-expiry prune. This is what stops a candidate
        // that missed its window from polling the backend at 1 Hz for hours.
        let (_fx, node, _cid, psbt) = accepted_hot_spend(0);
        let node = std::sync::Arc::new(node);
        let mut backend = backend_for(&psbt);
        backend
            .confirmed_txs
            .insert(psbt.unsigned_tx.compute_txid());
        let backend: std::sync::Arc<dyn crate::chain::ChainBackend + Send + Sync> =
            std::sync::Arc::new(backend);

        let past_grace = NOW + 60 + super::SETTLEMENT_OBSERVE_GRACE_SECS + 1;
        assert_eq!(
            crate::fire_tick(std::sync::Arc::clone(&node), backend, past_grace).await,
            0
        );
        assert!(
            node.sign_state
                .lock()
                .expect("sign_state")
                .pending
                .has_any(past_grace),
            "past the observation grace a stuck candidate is no longer polled, so its \
             pending Hold survives to its commitment-expiry backstop instead of being \
             cleared by an unbounded 1 Hz settlement poll"
        );
    }

    /// The peer winner may be mined before this node's next fire pass. In that
    /// case the exact transaction has left the mempool and every candidate input
    /// is now spent, so package assembly cannot identify settlement from prevouts.
    /// Confirmation lookup must settle the local Hold before assembly is attempted.
    #[test]
    fn a_peer_copy_confirmed_before_our_fire_pass_settles_the_candidate_here_too() {
        let (_fx, node, cid, psbt) = accepted_hot_spend(0);
        let mut backend = backend_for(&psbt);
        let txid = psbt.unsigned_tx.compute_txid();
        backend.confirmed_txs.insert(txid);
        // Once mined, the candidate's input is spent and no longer appears in the
        // UTXO view. This proves the confirmed-transaction shortcut runs before
        // package assembly's unknown/spent-prevout error.
        backend.prevouts.clear();
        // Confirmation itself settles the candidate; this node need not have
        // received the peer quorum that assembled the mined transaction.

        assert_eq!(
            crate::combine_and_broadcast(&node, &backend, std::slice::from_ref(&cid), NOW),
            0,
            "the peer confirmed it, so this node pushes nothing"
        );
        assert!(
            backend.packages_tested.lock().expect("p").is_empty(),
            "an already-confirmed candidate needs no package test"
        );
        assert!(
            backend.broadcasts.lock().expect("b").is_empty(),
            "an already-confirmed candidate must not be re-broadcast"
        );
        assert!(
            !node
                .sign_state
                .lock()
                .expect("sign_state")
                .pending
                .has_any(NOW),
            "confirmation settles the pending Hold so refreshes resume"
        );
        assert_eq!(
            crate::combine_and_broadcast(&node, &backend, &[cid], NOW),
            0,
            "the candidate was marked settled and is not retried"
        );
    }

    /// An escape-class spend whose mandatory escape is byte-identical to it (the
    /// spend already sweeps to the escape wallet) is ACCEPTED — the pair collapses
    /// to one candidate, which is correct: an escape-class spend fires immediately
    /// under either pin and has no duress path that needs a distinct escape. This
    /// pins that equal commitment ids are benign, not a rejected request.
    #[test]
    fn an_escape_class_spend_that_equals_its_own_escape_registers_one_candidate() {
        let fx = Fixture::new(3, 5);
        let node = crate::Node::from_toml_str(&fx.config(0, 0, "")).expect("config");
        let tx = fx.spend_psbt(&fx.escape_spk, 7);
        let mut request = fx.spend_request(&tx, EXPIRY, "self-paired");
        request.escape_psbt = tx.to_string();
        fx.coord_sign(&mut request, "self-paired-resign");
        assert!(
            matches!(
                crate::handle_sign(&node, &request, NOW).expect("decodable"),
                SignResponse::Accepted(_)
            ),
            "an escape-class spend that is its own escape is accepted"
        );
        assert_eq!(
            node.channel.as_ref().expect("channel").store_len(),
            1,
            "the pair collapses to one candidate when spend and escape are identical"
        );
    }

    /// The whole pass end to end: `fire_tick` opens the gate at the fire event,
    /// then combines and broadcasts once quorum is present. The driver runs exactly
    /// this on its interval.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fire_tick_releases_then_combines_and_broadcasts() {
        let (fx, node, cid, psbt) = accepted_hot_spend(HOLD);
        let node = std::sync::Arc::new(node);
        let channel = node.channel.as_ref().expect("channel");
        let backend: std::sync::Arc<dyn crate::chain::ChainBackend + Send + Sync> =
            std::sync::Arc::new(backend_for(&psbt));
        deliver_peer_partials(&fx, channel, &psbt, &cid, 2);

        // Before the fire event: nothing is released, nothing is broadcast — even
        // though the quorum is already sitting there.
        assert_eq!(
            crate::fire_tick(
                std::sync::Arc::clone(&node),
                std::sync::Arc::clone(&backend),
                NOW + HOLD - 1
            )
            .await,
            0
        );
        assert!(
            !channel.was_released(&cid),
            "quorum present is not authorization: the Hold has not expired"
        );

        // At the fire event: released and broadcast.
        assert_eq!(
            crate::fire_tick(std::sync::Arc::clone(&node), backend, NOW + HOLD).await,
            1,
            "at its fire event the candidate combines and broadcasts"
        );
        assert!(node.channel.as_ref().expect("channel").was_released(&cid));
    }

    // -- request propagation (§3) -------------------------------------------

    /// The constant-observable step: a normal-PIN and a duress-PIN request
    /// propagate over the identical path, to the identical peers, in the identical
    /// message count, at the identical size.
    ///
    /// V0-4b's silence rests on this. If a duress request propagated differently —
    /// more messages, a different size, a different peer set — a coordinator-
    /// controlling attacker could read the duress bit straight off the wire without
    /// compromising a single node.
    #[test]
    fn both_pins_propagate_over_an_identical_path_count_and_size() {
        let fx = Fixture::new(3, 5);
        let node = crate::Node::from_toml_str(&fx.config(0, 0, "")).expect("config");
        let psbt = fx.spend_psbt(&fx.hot_spk, 7);

        let mut normal = fx.spend_request(&psbt, EXPIRY, "pin-normal");
        normal.pin = "1234".into();
        fx.coord_sign(&mut normal, "pin-normal-signed");
        let mut duress = fx.spend_request(&psbt, EXPIRY, "pin-duress");
        duress.pin = "999999999999".into();
        fx.coord_sign(&mut duress, "pin-duress-signed");
        assert_ne!(
            normal.pin, duress.pin,
            "the two requests differ ONLY in the pin"
        );

        assert_ne!(
            normal.pin.len(),
            duress.pin.len(),
            "the regression must cover unequal-length enrolled PINs"
        );
        let normal_request = TaggedRequest::Spend(normal);
        let duress_request = TaggedRequest::Spend(duress);
        let normal_payload = request_payload(&normal_request);
        let duress_payload = request_payload(&duress_request);
        assert_eq!(
            normal_payload.len(),
            duress_payload.len(),
            "a duress request must be the same size on the wire as a normal one"
        );
        assert_eq!(
            serde_json::from_slice::<TaggedRequest>(&normal_payload)
                .expect("padded normal request"),
            normal_request,
            "padding must preserve the coordinator-signed request verbatim"
        );
        assert_eq!(
            serde_json::from_slice::<TaggedRequest>(&duress_payload)
                .expect("padded duress request"),
            duress_request,
            "padding must preserve the coordinator-signed request verbatim"
        );

        // Identical peer set (the path + the count), every time, from one pure
        // function of the manifest — nothing about the pin can reach it.
        let channel = node.channel.as_ref().expect("channel");
        assert_eq!(channel.peer_ids(), vec![1, 2, 3, 4]);
        let normal_envelope = channel
            .build_envelope(MSG_TYPE_REQUEST, 1, &normal_payload, NOW)
            .expect("normal envelope");
        let duress_envelope = channel
            .build_envelope(MSG_TYPE_REQUEST, 1, &duress_payload, NOW)
            .expect("duress envelope");
        assert_eq!(
            envelope_body(&normal_envelope).expect("normal body").len(),
            envelope_body(&duress_envelope).expect("duress body").len(),
            "variable DER channel signatures must not reintroduce a wire-size PIN oracle"
        );
    }

    #[test]
    fn pin_bearing_channel_payloads_are_zeroizable() {
        let fx = Fixture::new(3, 5);
        let psbt = fx.spend_psbt(&fx.hot_spk, 7);
        let request = TaggedRequest::Spend(fx.spend_request(&psbt, EXPIRY, "wipe-pin"));
        let mut payload = request_payload(&request);
        assert!(payload.windows(3).any(|window| window == b"123"));
        zeroize::Zeroize::zeroize(&mut payload);
        assert!(
            payload.iter().all(|byte| *byte == 0),
            "the serialized propagation allocation must be overwritten"
        );
    }

    /// A request can fit `/sign`'s 1 MiB JSON cap yet exceed `max_msg_bytes` after
    /// request padding, base64, and envelope metadata. Such a request must fail
    /// before acknowledgement because peer propagation is the only quorum path.
    #[test]
    fn a_request_that_cannot_fit_its_channel_envelope_is_not_accepted() {
        let fx = Fixture::new(3, 5);
        let node =
            crate::Node::from_toml_str(&fx.config(0, 0, "max_msg_bytes = 100\n")).expect("config");
        let psbt = fx.spend_psbt(&fx.hot_spk, 7);
        let request = fx.spend_request(&psbt, EXPIRY, "oversized-propagation");

        let error = crate::handle_sign(&node, &request, NOW)
            .expect_err("an unpropagatable request must not receive Accepted");
        assert!(
            error.0.contains("max_msg_bytes"),
            "unexpected error: {error:?}"
        );
        assert_eq!(node.channel.as_ref().expect("channel").store_len(), 0);
        assert!(node.outbox.lock().expect("outbox").is_empty());
        assert!(node.authorized.lock().expect("authorized").is_empty());
    }

    /// Loop suppression: a node propagates only what it just ACCEPTED, and
    /// acceptance consumes the request's coordinator nonce. The copy that comes
    /// back from a peer is refused as a replay and is never propagated again, so
    /// the fan-out dies after one round instead of ringing forever.
    #[test]
    fn a_request_that_comes_back_from_a_peer_is_not_propagated_again() {
        let fx = Fixture::new(3, 5);
        let node = crate::Node::from_toml_str(&fx.config(0, 0, "")).expect("config");
        let psbt = fx.spend_psbt(&fx.hot_spk, 7);
        let request = fx.spend_request(&psbt, EXPIRY, "loop-suppression");

        // First sight: accepted, and staged for every peer.
        assert!(matches!(
            crate::handle_sign(&node, &request, NOW).expect("decodable"),
            SignResponse::Accepted(_)
        ));
        assert_eq!(
            node.outbox.lock().expect("outbox").len(),
            1,
            "an accepted request is staged for propagation"
        );
        node.outbox.lock().expect("outbox").clear();

        // The same request arriving again (a peer echoing it back) is refused on
        // its consumed nonce and stages nothing.
        assert!(matches!(
            crate::handle_sign(&node, &request, NOW).expect("decodable"),
            SignResponse::Refusal(r) if r.code == vault_proto::RefusalCode::NonceReplayed
        ));
        assert!(
            node.outbox.lock().expect("outbox").is_empty(),
            "an echo must not re-propagate, or the fan-out never terminates"
        );
    }
}
