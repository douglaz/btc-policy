//! The node-to-node channel (V0-8a): authenticated peer messaging + a verified
//! partial-signature exchange. ADR-0012 ("The node-to-node channel") is the
//! authoritative security spec; ADR-0013 §4 is the manifest root.
//!
//! This is the CHANNEL LAYER ONLY. It carries signatures and assembly, **never
//! policy**. It does NOT combine/broadcast (V0-8b) or run the duress state
//! machine (V0-4). It provides the primitives those tasks drive: a
//! self-authenticating **signed envelope** (possession proven per message — the
//! fresh nonce+timestamp IS the challenge; there is no session handshake) and a
//! **partial** message verified against this node's own registered candidate.
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
//!   dispatch on msg_type ───── not "partial" ▶ REJECTED(UNKNOWN_MSG_TYPE)
//!         │  (partial)
//!   payload.wallet_id == envelope ───── ne ──▶ REJECTED(PAYLOAD_WALLET_MISMATCH)
//!   signer_node_id == sender_node_id ── ne ──▶ REJECTED(SIGNER_MISMATCH)
//!   candidate(commitment_id) present ── no ──▶ UNKNOWN_CANDIDATE   (retriable)
//!   txid / user_sig_hash / input / sighash ─▶ REJECTED(WRONG_*)
//!   verify partial vs expected pubkey ─ no ──▶ REJECTED(BAD_PARTIAL_SIG)
//!         │
//!   store (≤1 per (input,signer), no evict) ▶ ACCEPTED
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
//! | manifest     `btc-policy/manifest/v0`           | `wallet_id[32]`, `protocol_version:u32`, node-count:u32, per node(by id): `node_id:u16`, `signing_pubkey[33]`, `channel_pubkey[33]`, `endpoints:eps` |
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
use std::io::Read;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::hex::{DisplayHex, FromHex};
use bitcoin::secp256k1::{ecdsa::Signature, Message, Secp256k1, SecretKey};
use bitcoin::sighash::SighashCache;
use bitcoin::{ecdsa, EcdsaSighashType, Psbt, PublicKey, ScriptBuf, Txid};
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;

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
        self.u32(b.len() as u32);
        self.0.extend_from_slice(b);
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

/// BIP340-style tagged SHA-256: `SHA256(SHA256(tag) || SHA256(tag) || msg)`.
fn tagged_hash(tag: &str, msg: &[u8]) -> [u8; 32] {
    let th = sha256::Hash::hash(tag.as_bytes());
    let mut e = sha256::Hash::engine();
    e.input(th.as_ref());
    e.input(th.as_ref());
    e.input(msg);
    sha256::Hash::from_engine(e).to_byte_array()
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

fn channel_pubkey_of(sk: &SecretKey) -> PublicKey {
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

/// Canonical bytes of the endorsement-FREE BaseManifest (§2). `channel_pubkey`
/// IS in the hashed structure (deterministic, known at setup). v0-provisional to
/// V0-9. `nodes` MUST be sorted by `node_id`.
fn base_manifest_bytes(
    wallet_id: &[u8; 32],
    protocol_version: u32,
    nodes: &[ManifestNode],
) -> Vec<u8> {
    let mut e = Enc::new();
    e.fixed(wallet_id);
    e.u32(protocol_version);
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
    nodes: &[ManifestNode],
) -> [u8; 32] {
    tagged_hash(
        MANIFEST_TAG,
        &base_manifest_bytes(wallet_id, protocol_version, nodes),
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
) -> Vec<u8> {
    let mut e = Enc::new();
    e.var(msg_type.as_bytes());
    e.u32(protocol_version);
    e.fixed(wallet_id);
    e.fixed(manifest_hash);
    e.u16(sender_node_id);
    e.u16(recipient_node_id);
    e.var(payload_b64);
    e.var(nonce);
    e.u64(timestamp);
    e.0
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Envelope {
    pub(crate) msg_type: String,
    pub(crate) protocol_version: u32,
    pub(crate) wallet_id: String,
    pub(crate) manifest_hash: String,
    pub(crate) sender_node_id: u16,
    pub(crate) recipient_node_id: u16,
    pub(crate) payload_b64: String,
    pub(crate) nonce: String,
    pub(crate) timestamp: u64,
    pub(crate) channel_sig: String,
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
    #[allow(dead_code)] // canonical payload bytes for the outbound envelope (V0-8b caller)
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("PartialPayload is always serializable")
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
    /// The count or byte cap was hit — the candidate is NOT inserted, no live
    /// candidate is ever evicted, and the `/sign` verdict is unchanged (V0-8a).
    AtCapacity,
}

/// One registered candidate — this node's OWN canonical view of a spend, so a
/// peer's partial can be verified against sighashes THIS node recomputed. Keyed
/// by `commitment_id` (the same txid can back several live commitments).
pub(crate) struct Candidate {
    commitment_id: String,
    unsigned_txid: Txid,
    /// This node's canonical PSBT; verified peer partials are imported here (never
    /// blind-merged from a peer PSBT).
    psbt: Psbt,
    /// Per-input sighash recomputed by THIS node.
    sighashes: Vec<[u8; 32]>,
    /// Tagged SHA-256 over the user's DER signature(s) + sighash-type byte(s), in
    /// input order, as this node verified them at ingress.
    user_sig_hash: [u8; 32],
    /// The commitment's own fixed eviction horizon (no extension in V0-8a).
    expiry: u64,
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

impl Candidate {
    /// Build a candidate from the node's own post-verdict PSBT: recompute per-input
    /// sighashes and the `user_sig_hash` from the user's verified partial sigs, and
    /// **strip every partial signature the node has not verified or produced**.
    ///
    /// `verify_user_signatures` validated only the `user_pubkey` entry, so any
    /// federation `partial_sig` the coordinator planted in the request PSBT — under
    /// this node's own signing key or a peer's — is unverified. The canonical PSBT
    /// therefore keeps ONLY the verified user signature plus, once this node has
    /// actually signed (`node_signed`), its own real signature under
    /// `self_signing_pubkey`; peer partials enter later exclusively through the
    /// verified `accept_partial`. Without
    /// this strip a coordinator-planted signature would (a) blind-import an
    /// unverified sig into the canonical view (§5 forbids this) and (b) survive the
    /// Pending→Signed `or_insert` merge, pinning a forgery under this node's key that
    /// suppresses its real signature and relays as garbage every peer rejects —
    /// silently dropping the node from the combine set (a coordinator gaining power
    /// over assembly, which Model B forbids).
    pub(crate) fn build(
        psbt: &Psbt,
        commitment_id: &str,
        expiry: u64,
        witness_script: &ScriptBuf,
        user_pubkey: &PublicKey,
        self_signing_pubkey: &PublicKey,
        node_signed: bool,
    ) -> Result<Candidate, Error> {
        let mut psbt = psbt.clone();
        for input in &mut psbt.inputs {
            input
                .partial_sigs
                .retain(|pk, _| pk == user_pubkey || (node_signed && pk == self_signing_pubkey));
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
                .p2wsh_signature_hash(i, witness_script, utxo.value, EcdsaSighashType::All)
                .map_err(|e| format!("sighash for input {i}: {e}"))?;
            sighashes.push(sh.to_byte_array());
            let sig = input
                .partial_sigs
                .get(user_pubkey)
                .ok_or_else(|| format!("input {i} missing the user partial signature"))?;
            usig.var(&sig.signature.serialize_der());
            usig.u8(sig.sighash_type.to_u32() as u8);
        }
        let user_sig_hash = tagged_hash(USER_SIG_HASH_TAG, &usig.0);
        let bytes = psbt.serialize().len() + sighashes.len() * 32 + 32;
        Ok(Candidate {
            commitment_id: commitment_id.to_string(),
            unsigned_txid,
            psbt,
            sighashes,
            user_sig_hash,
            expiry,
            partials: HashMap::new(),
            bytes,
            capacity_bytes: bytes,
        })
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

    /// Merge signatures created by this node after a Pending candidate transitions
    /// to Signed. Preserve peer partials already received during the Hold and never
    /// extend the candidate's original expiry/capacity reservation. A valid ECDSA
    /// user signature is not unique and is not commitment-bound witness data. When
    /// a resubmission carries a different valid encoding, retain the original user
    /// signature/hash (which existing peer partials name) while importing this
    /// node's new signature over the identical registered sighash.
    fn merge_post_verdict(&mut self, newer: &Candidate) {
        if self.unsigned_txid != newer.unsigned_txid
            || self.sighashes != newer.sighashes
            || self.expiry != newer.expiry
            || self.psbt.inputs.len() != newer.psbt.inputs.len()
        {
            return;
        }
        let old_psbt_bytes = self.psbt.serialize().len();
        for (existing, update) in self.psbt.inputs.iter_mut().zip(&newer.psbt.inputs) {
            for (pubkey, signature) in &update.partial_sigs {
                existing.partial_sigs.entry(*pubkey).or_insert(*signature);
            }
        }
        let new_psbt_bytes = self.psbt.serialize().len();
        self.bytes = self
            .bytes
            .saturating_sub(old_psbt_bytes)
            .saturating_add(new_psbt_bytes);
        debug_assert!(self.bytes <= self.capacity_bytes);
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
    /// Register `c` unless the store is at capacity (§5: at capacity the candidate
    /// is simply NOT inserted — no eviction; the `/sign` verdict is unchanged).
    fn register(&mut self, c: Candidate) -> RegisterOutcome {
        if let Some(existing) = self.candidates.get_mut(&c.commitment_id) {
            existing.merge_post_verdict(&c);
            return RegisterOutcome::AlreadyPresent;
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

    /// Evict every candidate whose commitment has expired (its own clock).
    fn prune(&mut self, now: u64) {
        let mut removed = 0usize;
        self.candidates.retain(|_, c| {
            if c.expiry > now {
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
    /// (retriable) even with no intervening `/sign` sweep.
    fn accept_partial(
        &mut self,
        p: &ParsedPartial,
        nodes: &[ManifestNode],
        now: u64,
    ) -> ChannelReply {
        let expired = match self.candidates.get(p.commitment_id) {
            Some(c) => c.expiry <= now,
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

        // Consume the nonce for ANY authenticated + fresh envelope, BEFORE the
        // quota check — so a rate-limited (but authenticated) envelope cannot be
        // replayed after the quota window resets (codex adversarial 2026-07-17:
        // charging quota first let a captured RATE_LIMITED envelope replay once
        // the window reset). Replay-safety must NOT rest on message idempotency:
        // a future non-idempotent msg_type (V0-8b/V0-4) would inherit the hole,
        // so the nonce is consumed unconditionally here. Cache growth stays
        // bounded: entries prune at the freshness horizon (above) and the
        // per-peer quota caps the rate at which a peer can add fresh nonces.
        self.seen_nonces.insert(key, timestamp);
        if let Some(limited) = self.charge_quota(sender, now, quota_per_min) {
            return limited;
        }
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
    pub(crate) fn build(
        cfg: &ChannelConfig,
        node_seckey: &SecretKey,
        node_signing_pubkey: PublicKey,
        wallet_id: [u8; 32],
        descriptor_node_keys: &[PublicKey],
        listen_port: u16,
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

        let manifest_hash = compute_manifest_hash(&wallet_id, PROTOCOL_VERSION_V0, &nodes);
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

    /// Register a candidate on a non-refused `/sign` verdict (§4). At capacity the
    /// candidate is simply not inserted (logged by the caller).
    pub(crate) fn register_candidate(&self, c: Candidate) -> RegisterOutcome {
        let mut c = c;
        c.reserve_partial_capacity(&self.nodes, self.node_id);
        self.store.lock().expect("store lock poisoned").register(c)
    }

    /// Prune expired candidates — driven from the same `/sign` sweep the replay
    /// log runs on (§5); the `/channel` lookup also evicts expired candidates so an
    /// idle node still rejects them.
    pub(crate) fn prune_store(&self, now: u64) {
        self.store.lock().expect("store lock poisoned").prune(now);
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
    /// is applied internally. Purely verify-and-store — structurally NO path to the
    /// signer (signing-oracle prohibition, §7).
    pub(crate) fn ingest(&self, body: &[u8], now_input: u64) -> ChannelReply {
        let env: Envelope = match serde_json::from_slice(body) {
            Ok(e) => e,
            Err(_) => return ChannelReply::Rejected(RejectReason::MalformedJson),
        };
        let wallet_id = match from_hex_32(&env.wallet_id) {
            Ok(x) => x,
            Err(_) => return ChannelReply::Rejected(RejectReason::MalformedJson),
        };
        let manifest_hash = match from_hex_32(&env.manifest_hash) {
            Ok(x) => x,
            Err(_) => return ChannelReply::Rejected(RejectReason::MalformedJson),
        };
        let nonce = match from_hex_16(&env.nonce) {
            Ok(x) => x,
            Err(_) => return ChannelReply::Rejected(RejectReason::MalformedJson),
        };
        let sig_der = match from_hex_vec(&env.channel_sig) {
            Ok(x) => x,
            Err(_) => return ChannelReply::Rejected(RejectReason::MalformedJson),
        };

        // 1. protocol_version pinned to the manifest.
        if env.protocol_version != PROTOCOL_VERSION_V0 {
            return ChannelReply::Rejected(RejectReason::BadProtocolVersion);
        }
        // 2. explicit local-vault equality (independent of endorsement validity).
        if wallet_id != self.wallet_id {
            return ChannelReply::Rejected(RejectReason::WrongWallet);
        }
        if manifest_hash != self.manifest_hash {
            return ChannelReply::Rejected(RejectReason::WrongManifest);
        }
        // 3. recipient bind (closes cross-recipient replay for every msg_type).
        if env.recipient_node_id != self.node_id {
            return ChannelReply::Rejected(RejectReason::WrongRecipient);
        }
        // 4. sender must be an in-manifest peer (never self).
        let sender = env.sender_node_id;
        if sender == self.node_id || (sender as usize) >= self.nodes.len() {
            return ChannelReply::Rejected(RejectReason::UnknownSender);
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
            Err(_) => return ChannelReply::Rejected(RejectReason::BadChannelSig),
        };
        if Secp256k1::verification_only()
            .verify_ecdsa(
                &Message::from_digest(digest),
                &sig,
                &peer_channel_pubkey.inner,
            )
            .is_err()
        {
            return ChannelReply::Rejected(RejectReason::BadChannelSig);
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
                return ChannelReply::Rejected(RejectReason::StaleTimestamp);
            }
            IngressGuardResult::Replayed => {
                return ChannelReply::Rejected(RejectReason::ReplayedNonce);
            }
            IngressGuardResult::RateLimited { retry_after_secs } => {
                return ChannelReply::RateLimited { retry_after_secs };
            }
        };
        // 8. only now decode the opaque payload.
        let payload = match STANDARD.decode(env.payload_b64.as_bytes()) {
            Ok(p) => p,
            Err(_) => return ChannelReply::Rejected(RejectReason::MalformedPayload),
        };
        // 9. dispatch. V0-8a registers exactly one msg_type: `partial`.
        match env.msg_type.as_str() {
            "partial" => self.handle_partial(sender, &payload, &wallet_id, now),
            _ => ChannelReply::Rejected(RejectReason::UnknownMsgType),
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

    // -- outbound (§6) — no production caller in V0-8a; tests + V0-8b drive it --

    /// Build a freshly-signed envelope carrying `payload` for `recipient_node_id`.
    /// Each call draws a FRESH nonce + timestamp + `channel_sig`, so a channel
    /// nonce is single-use (consumed on the receiver at first sight).
    #[allow(dead_code)]
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
            payload_b64,
            nonce: to_hex(&nonce),
            timestamp,
            channel_sig: to_hex(&sig.serialize_der()),
        })
    }

    /// Build a `partial` payload for `(commitment_id, input)` from this node's own
    /// registered candidate + its own signature — no test-only injection.
    #[allow(dead_code)]
    pub(crate) fn partial_payload_for(
        &self,
        commitment_id: &str,
        input: u32,
    ) -> Option<PartialPayload> {
        let store = self.store.lock().expect("store lock poisoned");
        let c = store.candidates.get(commitment_id)?;
        let expected = self.nodes[self.node_id as usize].signing_pubkey;
        let sig = c
            .psbt
            .inputs
            .get(input as usize)?
            .partial_sigs
            .get(&expected)?;
        Some(PartialPayload {
            commitment_id: commitment_id.to_string(),
            wallet_id: to_hex(&self.wallet_id),
            txid: c.unsigned_txid.to_string(),
            input,
            signer_node_id: self.node_id,
            sighash_type: EcdsaSighashType::All.to_u32(),
            spend_purpose: "hot".to_string(),
            user_sig_hash: to_hex(&c.user_sig_hash),
            partial_sig: to_hex(&sig.signature.serialize_der()),
        })
    }

    /// Every endorsed canonical base address for `node_id`, in manifest order.
    /// A transport failure on one endpoint must not discard the alternatives.
    #[allow(dead_code)]
    pub(crate) fn peer_bases(&self, node_id: u16) -> Option<Vec<String>> {
        self.nodes
            .get(node_id as usize)
            .map(|node| node.endpoints.clone())
            .filter(|endpoints| !endpoints.is_empty())
    }

    #[allow(dead_code)]
    fn per_send_deadline(&self) -> Duration {
        Duration::from_secs(self.limits.per_send_deadline_secs)
    }
    #[allow(dead_code)]
    fn max_response_bytes(&self) -> usize {
        self.limits.max_response_bytes
    }
}

/// POST a signed envelope to a peer's `/channel` with a per-send deadline and a
/// bounded response read. A dead/unreachable peer is an `Err`, never a panic, and
/// never blocks other sends (callers fan out concurrently). `base` is the peer's
/// canonical `host:port`; this appends `http://…/channel` exactly once.
///
/// **Partial-release authorization (ADR-0012):** no partial may leave the node
/// before its candidate's authorized fire event. V0-8a has NO production caller —
/// V0-8b must add the fire-authorization gate before wiring one. Tests are the
/// only callers here; hence `pub(crate)` + `#[allow(dead_code)]`.
#[allow(dead_code)]
pub(crate) async fn send_partial(
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
    let body = serde_json::to_vec(envelope).map_err(|e| format!("encode envelope: {e}"))?;
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

/// Client-side view of a channel reply. A permanent rejection's reason remains
/// the peer's opaque wire string: the retry policy never branches on individual
/// reason codes, so decoding and immediately re-encoding all frozen server enums
/// would add no correctness.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum OutboundReply {
    Accepted,
    Rejected(String),
    UnknownCandidate,
    RateLimited { retry_after_secs: u64 },
}

#[allow(dead_code)] // outbound reply parser (no production caller in V0-8a)
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
#[allow(dead_code)]
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
#[allow(dead_code)]
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
#[allow(dead_code)]
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
        if now() >= commitment_expiry {
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
        let remaining = Duration::from_secs(commitment_expiry.saturating_sub(now()));
        if remaining.is_zero() {
            return RetryOutcome::GaveUp;
        }
        tokio::time::sleep(wait.max(Duration::from_secs(1)).min(remaining)).await;
    }
}

/// Try every endorsed endpoint for one logical retry attempt. A fresh envelope
/// is built for EACH transport attempt: an endpoint may have consumed the nonce
/// even when its response was lost, so reusing that envelope at an alternative
/// endpoint could self-reject as a replay.
///
/// Bounded-until-expiry (§6) is enforced at ENDPOINT granularity, not just at the
/// retry-loop boundary: the clock is re-read before every endpoint so a send is
/// never *initiated* past `commitment_expiry`, and each send's deadline is capped
/// to the remaining lifetime so one stalled endpoint cannot burn the full
/// per-send deadline and push a later endpoint past expiry.
#[allow(dead_code)]
async fn try_partial_endpoints(
    channel: &ChannelState,
    recipient_node_id: u16,
    payload: &[u8],
    endpoints: &[String],
    commitment_expiry: u64,
) -> Result<OutboundReply, Error> {
    let mut last_error = None;
    for base in endpoints {
        let now = unix_now();
        let remaining = commitment_expiry.saturating_sub(now);
        if remaining == 0 {
            break;
        }
        let deadline = channel
            .per_send_deadline()
            .min(Duration::from_secs(remaining));
        let envelope = channel.build_envelope("partial", recipient_node_id, payload, now)?;
        match send_partial(base, &envelope, deadline, channel.max_response_bytes()).await {
            Ok(reply) => return Ok(reply),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| Error::from("peer has no endpoints")))
}

/// Bounded retry to `recipient_node_id` until `commitment_expiry` (§6). Each
/// attempt re-envelopes the immutable `payload` afresh (single-use nonce) — the
/// helper holds the payload, never the envelope. Returns `Ok(())` on accept,
/// `Err` on permanent rejection or on giving up at expiry.
#[allow(dead_code)]
pub(crate) async fn retry_partial_until(
    channel: &ChannelState,
    recipient_node_id: u16,
    payload: &PartialPayload,
    commitment_expiry: u64,
) -> Result<(), Error> {
    let endpoints = channel
        .peer_bases(recipient_node_id)
        .ok_or_else(|| Error::from(format!("no endpoint for peer {recipient_node_id}")))?;
    let backoff = default_backoff();
    let payload_bytes = payload.to_bytes();
    let outcome = retry_loop(
        || {
            try_partial_endpoints(
                channel,
                recipient_node_id,
                &payload_bytes,
                &endpoints,
                commitment_expiry,
            )
        },
        commitment_expiry,
        unix_now,
        &backoff,
    )
    .await;
    match outcome {
        RetryOutcome::Accepted => Ok(()),
        RetryOutcome::Rejected(reason) => {
            Err(format!("partial permanently rejected: {reason}").into())
        }
        RetryOutcome::GaveUp => Err("partial retry gave up at commitment expiry".into()),
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
    use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
    use bitcoin::sighash::SighashCache;
    use bitcoin::transaction::Version;
    use bitcoin::{
        ecdsa, Amount, EcdsaSighashType, OutPoint, Psbt, PublicKey, ScriptBuf, Sequence,
        Transaction, TxIn, TxOut, Txid, Witness,
    };
    use miniscript::{Descriptor, DescriptorPublicKey};
    use std::str::FromStr;

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
        pub(crate) descriptor: String,
        pub(crate) witness_script: ScriptBuf,
        pub(crate) wallet_id: [u8; 32],
        pub(crate) manifest_hash: [u8; 32],
        pub(crate) hot_desc: String,
        pub(crate) hot_spk: ScriptBuf,
        pub(crate) escape_desc: String,
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
            let feds: Vec<(SecretKey, PublicKey)> =
                (0..n as u8).map(|i| keypair(fed_base + i)).collect();
            let node_pubkeys: Vec<String> = feds.iter().map(|(_, pk)| pk.to_string()).collect();
            let descriptor_str = format!(
                "wsh(and_v(v:pk({user_pk}),multi({t},{})))",
                node_pubkeys.join(",")
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
            let manifest_hash = compute_manifest_hash(&wallet_id, PROTOCOL_VERSION_V0, &nodes);

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
                descriptor: canonical,
                witness_script,
                wallet_id,
                manifest_hash,
                hot_desc,
                hot_spk,
                escape_desc,
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
                compute_manifest_hash(&self.wallet_id, PROTOCOL_VERSION_V0, &nodes);
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
            format!(
                "listen_port = {}\nnode_seckey = \"{}\"\ndescriptor = \"{}\"\nallowlist = [\"{}\", \"{}\"]\nescape_descriptor = \"{}\"\nmax_derivation_index = 5\nhold_secs = {hold_secs}\nmax_commitment_age_secs = 172800\npolicy_version = 1\npin_normal_hash = \"{}\"\npin_duress_hash = \"{}\"\n\n{channel}",
                self.ports[self_id as usize],
                e.fed_sk.display_secret(),
                self.descriptor,
                self.hot_desc,
                self.escape_desc,
                self.escape_desc,
                sha256::Hash::hash(b"1234"),
                sha256::Hash::hash(b"9999"),
            )
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

        /// Build a `Candidate` from a spend PSBT (this node's own view). Models a
        /// freshly-registered candidate awaiting peer partials (`node_signed = false`);
        /// the spend PSBT carries only the user signature, so no self entry exists.
        pub(crate) fn candidate(&self, psbt: &Psbt, commitment_id: &str, expiry: u64) -> Candidate {
            Candidate::build(
                psbt,
                commitment_id,
                expiry,
                &self.witness_script,
                &self.user_pk,
                &self.entries[0].fed_pk,
                false,
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
        receiver.ingest(&serde_json::to_vec(&env).expect("json"), now)
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
        let pre = base_manifest_bytes(&wallet_id, PROTOCOL_VERSION_V0, &nodes);
        assert_eq!(to_hex(&pre), "222222222222222222222222222222222222222222222222222222222222222200000000020000000000031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766010000000e0000003132372e302e302e313a39303030010002531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe33703462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b010000000e0000003132372e302e302e313a39303031");
        assert_eq!(
            to_hex(&tagged_hash(MANIFEST_TAG, &pre)),
            "53b94e258ac8ba1cffdd3fdb18748638b33962eca7b4fd7d1de88320bb66a474"
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
        let duplicate_descriptor = format!(
            "wsh(and_v(v:pk({}),multi(2,{},{},{})))",
            fx.user_pk, fx.entries[0].fed_pk, fx.entries[0].fed_pk, fx.entries[2].fed_pk,
        );
        let duplicate = cfg.replacen(
            &format!("descriptor = \"{}\"", fx.descriptor),
            &format!("descriptor = \"{duplicate_descriptor}\""),
            1,
        );
        let err = crate::Node::from_toml_str(&duplicate)
            .err()
            .expect("duplicate descriptor node keys must fail startup");
        assert!(
            err.to_string().contains("duplicate federation node key"),
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
    pub(crate) fn store_len(&self) -> usize {
        self.store.lock().expect("store lock").candidates.len()
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
            recv.ingest(b"definitely not json", NOW),
            ChannelReply::Rejected(RejectReason::MalformedJson)
        );
    }

    #[test]
    fn a_bad_protocol_version_is_rejected() {
        let fx = Fixture::new(2, 3);
        let (send, recv) = (fx.channel_state(0), fx.channel_state(1));
        let bytes = envelope_bytes(&fx, &send, 1, "c", NOW, |e| e.protocol_version = 1);
        assert_eq!(
            recv.ingest(&bytes, NOW),
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
            recv.ingest(&bytes, NOW),
            ChannelReply::Rejected(RejectReason::WrongRecipient)
        );
    }

    #[test]
    fn an_unknown_sender_is_rejected() {
        let fx = Fixture::new(2, 3);
        let (send, recv) = (fx.channel_state(0), fx.channel_state(1));
        let bytes = envelope_bytes(&fx, &send, 1, "c", NOW, |e| e.sender_node_id = 99);
        assert_eq!(
            recv.ingest(&bytes, NOW),
            ChannelReply::Rejected(RejectReason::UnknownSender)
        );
    }

    #[test]
    fn a_tampered_payload_b64_fails_the_channel_signature() {
        let fx = Fixture::new(2, 3);
        let (send, recv) = (fx.channel_state(0), fx.channel_state(1));
        // Flip one byte of the SIGNED payload_b64 field — the sig no longer matches.
        let bytes = envelope_bytes(&fx, &send, 1, "c", NOW, |e| {
            let mut b = e.payload_b64.clone().into_bytes();
            b[0] ^= 0x01;
            e.payload_b64 = String::from_utf8_lossy(&b).into_owned();
        });
        assert_eq!(
            recv.ingest(&bytes, NOW),
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
            recv.ingest(&serde_json::to_vec(&env).expect("json"), NOW),
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
            recv.ingest(&bytes, NOW),
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
            recv.ingest(&bytes, NOW),
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
            recv.ingest(&bytes, NOW),
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
        assert_eq!(recv.ingest(&bytes, NOW), ChannelReply::UnknownCandidate);
        // Replay 60s later, still within the future-stamp's validity → replay.
        assert_eq!(
            recv.ingest(&bytes, NOW + 60),
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
        assert_eq!(recv.ingest(&bytes, NOW), ChannelReply::UnknownCandidate);
        assert_eq!(recv.nonce_len(), 1);
        assert_eq!(
            recv.ingest(&bytes, NOW),
            ChannelReply::Rejected(RejectReason::ReplayedNonce)
        );
        // A later fresh envelope prunes the now-old nonce: the set stays bounded.
        let env2 = send
            .build_envelope("partial", 1, &payload, NOW + 400)
            .expect("env2");
        assert_eq!(
            recv.ingest(&serde_json::to_vec(&env2).expect("json"), NOW + 400),
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
                recv.ingest(&replay_body, base),
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
                    old_recv.ingest(&replay_body, base)
                });
                let new_recv = Arc::clone(&recv);
                let new = scope.spawn(move || {
                    barrier.wait();
                    new_recv.ingest(&advancing_body, base + 400)
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
                recv.ingest(&serde_json::to_vec(&env).expect("json"), NOW),
                ChannelReply::UnknownCandidate
            );
        }
        let env = send
            .build_envelope("partial", 1, &payload, NOW)
            .expect("env");
        assert!(matches!(
            recv.ingest(&serde_json::to_vec(&env).expect("json"), NOW),
            ChannelReply::RateLimited { .. }
        ));
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
            stale_recv.ingest(&stale_body, NOW),
            ChannelReply::Rejected(RejectReason::StaleTimestamp)
        );
        assert!(matches!(
            stale_recv.ingest(&stale_body, NOW),
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
            replay_recv.ingest(&replay_body, NOW),
            ChannelReply::UnknownCandidate
        );
        assert_eq!(
            replay_recv.ingest(&replay_body, NOW),
            ChannelReply::Rejected(RejectReason::ReplayedNonce)
        );
        assert!(matches!(
            replay_recv.ingest(&replay_body, NOW),
            ChannelReply::RateLimited { .. }
        ));
    }

    #[test]
    fn rate_limited_envelopes_still_consume_their_nonce_so_replay_stays_closed() {
        // codex adversarial 2026-07-17: a rate-limited authenticated envelope must
        // STILL consume its nonce, so it cannot be captured and replayed after the
        // quota window resets. Replay-safety must not rest on message idempotency
        // (a future non-idempotent msg_type would inherit the hole), so the nonce
        // is consumed for any authenticated + fresh envelope BEFORE the quota
        // check. Cache growth stays bounded by the freshness-horizon prune
        // (FRESHNESS_PAST_SECS) plus the per-peer rate, not by dropping nonces.
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
            recv.ingest(&serde_json::to_vec(&e1).expect("json"), NOW),
            ChannelReply::UnknownCandidate
        );
        assert_eq!(recv.nonce_len(), 1);

        // A flood of distinct rate-limited envelopes is REJECTED for rate, but each
        // still records its nonce (replay-closed) — the cache grows with the flood
        // and is bounded by the freshness prune, not by dropping unrecorded nonces.
        let mut last = Vec::new();
        for i in 0..64 {
            let e = send.build_envelope("partial", 1, &payload, NOW).expect("e");
            last = serde_json::to_vec(&e).expect("json");
            assert!(matches!(
                recv.ingest(&last, NOW),
                ChannelReply::RateLimited { .. }
            ));
            assert_eq!(recv.nonce_len(), 2 + i as usize);
        }

        // Replaying the last rate-limited envelope after the quota window resets is
        // caught as a REPLAY (its nonce was recorded), not admitted — the fix.
        assert_eq!(
            recv.ingest(&last, NOW + QUOTA_WINDOW_SECS),
            ChannelReply::Rejected(RejectReason::ReplayedNonce)
        );
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
        assert_eq!(recv.ingest(&bytes, NOW), ChannelReply::UnknownCandidate);
    }
}

#[cfg(test)]
mod partial {
    //! Partial-signature verification + storage (§5), and the signature-coverage
    //! + registry-lifecycle guarantees.
    use super::fixture::{deliver, Fixture};
    use super::*;
    use bitcoin::secp256k1::{Message, Secp256k1};
    use bitcoin::Txid;

    const NOW: u64 = 1_752_000_000;
    const EXPIRY: u64 = NOW + 3_600;

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
        let variants: Vec<(&str, Vec<u8>)> = vec![
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
        // never the node's own — and the sign log is untouched.
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
        // from the candidate PSBT, and its sign log is empty.
        assert!(!recv.psbt_has_pubkey("cid", 0, &fx.entries[1].fed_pk));
        assert!(node.sign_log.lock().expect("sign_log").is_empty());
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

    #[test]
    fn a_pending_candidate_gains_the_local_signature_without_losing_peer_partials() {
        use vault_proto::{SignRequest, SignResponse};

        let fx = Fixture::new(2, 3);
        let sender = fx.channel_state(0);
        let node = crate::Node::from_toml_str(&fx.config(1, 10, "")).expect("config");
        let psbt = fx.spend_psbt(&fx.hot_spk, 7);
        let request = SignRequest {
            psbt: psbt.to_string(),
            escape_psbt: psbt.to_string(),
            pin: "1234".to_string(),
            expiry: NOW + 3_600,
            policy_version: 1,
        };
        assert!(matches!(
            crate::handle_sign(&node, &request, NOW).expect("pending verdict"),
            SignResponse::Pending(_)
        ));
        let channel = node.channel.as_ref().expect("channel");
        let commitment_id = channel
            .candidate_ids()
            .into_iter()
            .next()
            .expect("pending candidate");
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

        assert!(matches!(
            crate::handle_sign(&node, &request, NOW + 10).expect("signed verdict"),
            SignResponse::Signed(_)
        ));
        assert!(
            channel.partial_stored(&commitment_id, 0, 0),
            "the peer partial received during Hold must survive the signed verdict"
        );
        assert!(
            channel.partial_payload_for(&commitment_id, 0).is_some(),
            "the signed verdict must add this node's own partial to the candidate"
        );
    }

    #[test]
    fn a_changed_valid_user_signature_does_not_drop_the_local_or_peer_partial() {
        use vault_proto::{SignRequest, SignResponse};

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
        let request = SignRequest {
            psbt: psbt.to_string(),
            escape_psbt: psbt.to_string(),
            pin: "1234".to_string(),
            expiry: NOW + 3_600,
            policy_version: 1,
        };
        assert!(matches!(
            crate::handle_sign(&node, &request, NOW).expect("pending verdict"),
            SignResponse::Pending(_)
        ));
        let channel = node.channel.as_ref().expect("channel");
        let commitment_id = channel
            .candidate_ids()
            .into_iter()
            .next()
            .expect("pending candidate");
        let original_user_sig_hash = channel
            .store
            .lock()
            .expect("store")
            .candidates
            .get(&commitment_id)
            .expect("candidate")
            .user_sig_hash;

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

        // Re-sign the same SIGHASH_ALL message with extra nonce data. This is a
        // distinct, valid ECDSA encoding over the same commitment.
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
        let resigned_request = SignRequest {
            psbt: resigned.to_string(),
            escape_psbt: resigned.to_string(),
            ..request
        };
        assert!(matches!(
            crate::handle_sign(&node, &resigned_request, NOW + 10).expect("signed verdict"),
            SignResponse::Signed(_)
        ));

        let store = channel.store.lock().expect("store");
        let candidate = store
            .candidates
            .get(&commitment_id)
            .expect("candidate remains registered");
        assert_eq!(
            candidate.user_sig_hash, original_user_sig_hash,
            "the candidate retains the user-signature instance named by peer payloads"
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
            "the peer partial received during Hold must survive"
        );
        assert!(
            candidate.psbt.inputs[0]
                .partial_sigs
                .contains_key(&fx.entries[1].fed_pk),
            "the signed verdict must import this node's new local partial"
        );
    }

    #[test]
    fn a_coordinator_forged_federation_partial_never_survives_into_the_candidate() {
        use vault_proto::{SignRequest, SignResponse};

        // A pure-relay coordinator plants a bogus partial_sig under THIS node's
        // federation signing key in the request PSBT. `verify_user_signatures`
        // checks only the user entry, so the forgery clears ingress. If the candidate
        // kept it, the Pending→Signed `or_insert` merge would pin the forgery over
        // this node's real signature — relaying garbage every peer rejects and
        // silently dropping the node from the combine set (a coordinator gaining
        // power over assembly, which Model B forbids).
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
        let request = SignRequest {
            psbt: psbt.to_string(),
            escape_psbt: psbt.to_string(),
            pin: "1234".to_string(),
            expiry: NOW + 3_600,
            policy_version: 1,
        };
        // Pending registers the candidate; the forged self entry must be stripped.
        assert!(matches!(
            crate::handle_sign(&node, &request, NOW).expect("pending verdict"),
            SignResponse::Pending(_)
        ));
        // The Hold elapses and the node signs; its OWN real partial must reach the
        // candidate, not the coordinator's forgery.
        assert!(matches!(
            crate::handle_sign(&node, &request, NOW + 10).expect("signed verdict"),
            SignResponse::Signed(_)
        ));
        let channel = node.channel.as_ref().expect("channel");
        let cid = channel
            .candidate_ids()
            .into_iter()
            .next()
            .expect("candidate");
        let payload = channel
            .partial_payload_for(&cid, 0)
            .expect("this node's own partial");
        // The relayed partial must be this node's REAL signature: it verifies against
        // node 1's federation key over the node's own recomputed sighash. The forged
        // sig (over a different digest) would fail this check.
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
            .expect("the relayed partial must be this node's real signature");
    }

    #[test]
    fn the_sign_verdict_is_unchanged_when_the_store_is_at_capacity() {
        use vault_proto::{SignRequest, SignResponse};
        let fx = Fixture::new(2, 3);
        let node = crate::Node::from_toml_str(&fx.config(1, 0, "max_active_candidates = 1\n"))
            .expect("config");
        let sign = |txid: u8| {
            let psbt = fx.spend_psbt(&fx.hot_spk, txid);
            let req = SignRequest {
                psbt: psbt.to_string(),
                escape_psbt: psbt.to_string(),
                pin: "1234".to_string(),
                expiry: NOW + 3_600,
                policy_version: 1,
            };
            crate::handle_sign(&node, &req, NOW).expect("decodable")
        };
        // Both spends sign; the second is not registered (store full) but its
        // verdict is unchanged — capacity gates the registry slot, not the sign.
        assert!(matches!(sign(7), SignResponse::Signed(_)));
        assert!(matches!(sign(8), SignResponse::Signed(_)));
        assert_eq!(node.channel.as_ref().expect("channel").store_len(), 1);
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
                recv.ingest(&serde_json::to_vec(&env).expect("json"), NOW),
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
            recv.ingest(&serde_json::to_vec(&env).expect("json"), NOW),
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
impl ChannelState {
    pub(crate) fn candidate_ids(&self) -> Vec<String> {
        self.store
            .lock()
            .expect("store lock")
            .candidates
            .keys()
            .cloned()
            .collect()
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
    use vault_proto::{SignRequest, SignResponse};

    async fn ephemeral() -> (tokio::net::TcpListener, u16) {
        let l = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind");
        let port = l.local_addr().expect("addr").port();
        (l, port)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_nodes_exchange_a_verified_partial_through_the_real_sign_and_channel_paths() {
        let (l0, p0) = ephemeral().await;
        let (l1, p1) = ephemeral().await;
        let fx = Fixture::with_ports(2, &[p0, p1]);
        let node0 = Arc::new(crate::Node::from_toml_str(&fx.config(0, 0, "")).expect("node0"));
        let node1 = Arc::new(crate::Node::from_toml_str(&fx.config(1, 0, "")).expect("node1"));
        tokio::spawn(server::serve(l0, Arc::clone(&node0)));
        tokio::spawn(server::serve(l1, Arc::clone(&node1)));

        let psbt = fx.spend_psbt(&fx.hot_spk, 7);
        let req = SignRequest {
            psbt: psbt.to_string(),
            escape_psbt: psbt.to_string(),
            pin: "1234".to_string(),
            expiry: unix_now() + 3_600,
            policy_version: 1,
        };
        // Each node receives the spend via the REAL POST /sign, registering the
        // candidate (no test-only injection).
        let client = reqwest::Client::new();
        for port in [p0, p1] {
            let resp = client
                .post(format!("http://127.0.0.1:{port}/sign"))
                .json(&req)
                .send()
                .await
                .expect("sign send");
            assert!(resp.status().is_success());
            let body: SignResponse = resp.json().await.expect("sign body");
            assert!(matches!(body, SignResponse::Signed(_)), "got {body:?}");
        }

        let ch0 = node0.channel.as_ref().expect("ch0");
        let ch1 = node1.channel.as_ref().expect("ch1");
        let cid = ch0
            .candidate_ids()
            .first()
            .cloned()
            .expect("node0 candidate");
        assert!(
            ch1.has_candidate(&cid),
            "both nodes registered the same commitment"
        );

        // node0 sends its partial to node1 over the real /channel.
        let payload = ch0.partial_payload_for(&cid, 0).expect("payload");
        let env = ch0
            .build_envelope("partial", 1, &payload.to_bytes(), unix_now())
            .expect("envelope");
        let bases = ch0.peer_bases(1).expect("peer bases");
        let base = bases.first().expect("peer base");
        let reply = send_partial(base, &env, std::time::Duration::from_secs(5), 65_536)
            .await
            .expect("send");
        assert_eq!(reply, OutboundReply::Accepted);
        assert!(
            ch1.partial_stored(&cid, 0, 0),
            "node1 stored node0's partial"
        );
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
        tokio::spawn(server::serve(l, Arc::clone(&node)));
        let resp = reqwest::Client::new()
            .post(format!("http://127.0.0.1:{p}/channel"))
            .body("{}")
            .send()
            .await
            .expect("send");
        assert_eq!(resp.status().as_u16(), 404, "/channel is not mounted");
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
            send_partial(&live_base, &live_env, dl, 65_536),
            send_partial("127.0.0.1:1", &dead_env, dl, 65_536),
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
        let result = send_partial(&base, &env, std::time::Duration::from_secs(2), 65_536).await;

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

        retry_partial_until(&sender, 1, &payload, unix_now() + 5)
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

        // Already-expired commitment ⇒ remaining == 0 on the first endpoint ⇒ the
        // loop breaks before any send is initiated.
        let expired = try_partial_endpoints(&sender, 1, &payload, &endpoints, unix_now()).await;
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
        let live = try_partial_endpoints(&sender, 1, &payload, &endpoints, unix_now() + 30)
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
