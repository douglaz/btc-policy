//! Wire types shared by coordinator and nodes; drift is a compile error.
//!
//! `/sign` carries the coordinator-authenticated tagged request of ADR-0013 §2
//! (`{spend, escape, pin, …}` or the pin-less `{refresh, …}`) and answers
//! **accepted | refusal** — never a signature. Under Model B (ADR-0012) the node
//! signs at ingress, withholds the partial until the candidate's authorized fire
//! event, and the NODES combine and broadcast; the coordinator is a pure relay
//! that never holds a finalizable transaction. See [`SignResponse`].
//!
//! Refusals are policy *outcomes*, not transport errors: nodes answer them
//! with HTTP 200. Only input the node cannot decode earns a 400.

use bitcoin::hashes::{sha256, Hash, HashEngine};
use serde::{Deserialize, Serialize};

/// Maximum plaintext PIN length accepted by the v0 request protocol.
///
/// Besides bounding ingress memory, this gives the node channel a fixed budget
/// with which to pad the coordinator-authenticated request payload. The payload
/// size must not disclose whether the submitted PIN was the normal or duress PIN.
pub const MAX_PIN_BYTES: usize = 64;

/// The exact-transaction binding a node evaluates and signs against
/// (DESIGN.md, "Transaction commitment"; CONTEXT.md "Commitment"). Built
/// identically on coordinator and node from the same PSBT + config, it keys
/// the anti-replay log by content — **never** by outpoint set, so an RBF
/// replacement or rebroadcast is a fresh commitment, not a blocked replay.
///
/// The fields are plain owned types (not `bitcoin` types) so the struct is
/// serde-native without pulling in `bitcoin`'s serde feature; the canonical
/// byte encoding lives in [`Commitment::canonical_bytes`], not in serde.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commitment {
    /// Hash of the vault descriptor: which vault this spend belongs to.
    pub wallet_id: [u8; 32],
    /// The unsigned transaction's `version` (nVersion). Bound so two txs that
    /// differ only in version get distinct ids (ADR-0012, "the commitment binds
    /// the exact unsigned transaction").
    pub version: i32,
    /// The unsigned transaction's `nLockTime`. Bound for the same reason as
    /// [`Commitment::version`].
    pub lock_time: u32,
    /// Every input the transaction spends, in transaction order.
    pub inputs: Vec<CommitmentInput>,
    /// Every output the transaction pays, in transaction order.
    pub outputs: Vec<CommitmentOutput>,
    /// Absolute fee in satoshis (Σ input value − Σ output value).
    pub fee: u64,
    /// Coordinator-proposed expiry (unix seconds); the node caps it against
    /// its own clock so a hostile coordinator can't inflate retention.
    pub expiry: u64,
    /// The baked-at-setup policy identifier (policy never changes).
    pub policy_version: u32,
}

/// One transaction input, by outpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitmentInput {
    /// Previous-output txid as its raw 32 bytes.
    pub txid: [u8; 32],
    /// Previous-output index.
    pub vout: u32,
    /// This input's `nSequence`. Bound so two txs that differ only in a single
    /// input's sequence get distinct ids (ADR-0012).
    pub sequence: u32,
}

/// One transaction output, by scriptPubKey and amount.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitmentOutput {
    /// Raw scriptPubKey bytes.
    pub script_pubkey: Vec<u8>,
    /// Amount in satoshis.
    pub amount: u64,
}

impl Commitment {
    /// The deterministic, byte-identical encoding both sides hash. Every field
    /// is written at a fixed width, big-endian, with explicit length prefixes,
    /// so the bytes are unambiguous and two constructions of the same logical
    /// commitment produce identical output. The encoding is greenfield until
    /// v1 (DESIGN.md, "Wire format is greenfield until v1").
    ///
    /// Crate-private: the cross-crate contract is delivered through
    /// [`Commitment::commitment_id`]; nothing outside this crate hashes the
    /// bytes directly, so the encoding is not (yet) public surface.
    pub(crate) fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.wallet_id);
        // Header region: the transaction-level fields (nVersion, nLockTime).
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.lock_time.to_be_bytes());
        out.extend_from_slice(&(self.inputs.len() as u32).to_be_bytes());
        for input in &self.inputs {
            out.extend_from_slice(&input.txid);
            out.extend_from_slice(&input.vout.to_be_bytes());
            // Each input's nSequence, alongside its outpoint.
            out.extend_from_slice(&input.sequence.to_be_bytes());
        }
        out.extend_from_slice(&(self.outputs.len() as u32).to_be_bytes());
        for output in &self.outputs {
            out.extend_from_slice(&(output.script_pubkey.len() as u32).to_be_bytes());
            out.extend_from_slice(&output.script_pubkey);
            out.extend_from_slice(&output.amount.to_be_bytes());
        }
        out.extend_from_slice(&self.fee.to_be_bytes());
        out.extend_from_slice(&self.expiry.to_be_bytes());
        out.extend_from_slice(&self.policy_version.to_be_bytes());
        out
    }

    /// Lowercase-hex SHA-256 of [`Commitment::canonical_bytes`]. This is the
    /// key the anti-replay log records verdicts under.
    pub fn commitment_id(&self) -> String {
        sha256::Hash::hash(&self.canonical_bytes()).to_string()
    }
}

/// Domain-separation tag for the coordinator-request signature (ADR-0013 §2).
/// The coordinator signs `tagged_hash(COORD_REQUEST_TAG, canonical_bytes(request))`
/// with its auth key; a node verifies against its pinned
/// `coordinator_auth_pubkey`.
pub const COORD_REQUEST_TAG: &str = "btc-policy/coord-request/v0";

/// BIP340-style tagged SHA-256, `SHA256(SHA256(tag) ‖ SHA256(tag) ‖ msg)` — the
/// exact construction the node-to-node channel uses (docs/adr/0013 §4), so an
/// independent derivation on the coordinator and the node agree byte-for-byte.
///
/// The channel calls THIS function rather than keeping its own copy: "agree
/// byte-for-byte" is a claim two identical definitions can only make by luck, and
/// a drift between them would be invisible to either side's golden tests.
pub fn tagged_hash(tag: &str, msg: &[u8]) -> [u8; 32] {
    let th = sha256::Hash::hash(tag.as_bytes());
    let mut e = sha256::Hash::engine();
    e.input(th.as_ref());
    e.input(th.as_ref());
    e.input(msg);
    sha256::Hash::from_engine(e).to_byte_array()
}

/// Append `b` under a u32-LE length prefix — the channel's `var` convention
/// (docs/adr/0013 §2, "the same length-prefix conventions the channel uses"),
/// reused so the coordinator-request preimage follows the one length-prefix rule
/// the whole protocol shares. The channel's `Enc::var` delegates here, so that
/// "one rule" is a single definition rather than two copies of it.
pub fn push_var(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_le_bytes());
    out.extend_from_slice(b);
}

/// The coordinator-authenticated request (ADR-0013 §2): a tagged union the
/// coordinator signs over its **full** canonical bytes with the auth key each node
/// is provisioned with (`coordinator_auth_pubkey`, §5). A borrowing view over the
/// wire DTOs so the exact bytes signed on the coordinator and verified on the node
/// come from ONE place — drift is impossible.
///
/// **How far the pin goes today.** The key always reaches a node as config: no
/// code path sources it from a manifest. Channel mode additionally hashes it into
/// the base manifest (§4), so a node provisioned with an `expected_manifest_hash`
/// is *bound* to it — swap the coordinator and the node will not boot. ADR-0013 §4's
/// full chain — a node trusts the coordinator key BECAUSE it is in the manifest the
/// node was sealed with — therefore closes only for a channel node with sealing
/// provisioned; both are optional, and `demo first-light` has neither. That is the
/// provisional trust root this slice builds: the key is pinned per node and the
/// gate is un-bypassable, while the sealing ceremony that makes the pin
/// unforgeable-by-config-edit is later V0-9 work.
///
/// Each variant's canonical encoding begins with a distinct tag byte, so a Spend
/// and a Refresh with otherwise-identical fields can never share a digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoordRequest<'a> {
    /// `SpendRequest{spend, escape, pin, nonce, expiry, policy_version}` (§2).
    Spend {
        spend_psbt: &'a str,
        escape_psbt: &'a str,
        pin: &'a str,
        nonce: &'a str,
        expiry: u64,
        policy_version: u32,
    },
    /// `RefreshRequest{refresh, nonce, expiry, policy_version}` — no escape, no
    /// pin (§2). A node authenticates a refresh exactly like a spend before its
    /// first-class refresh path applies.
    Refresh {
        refresh_psbt: &'a str,
        nonce: &'a str,
        expiry: u64,
        policy_version: u32,
    },
}

impl<'a> CoordRequest<'a> {
    /// Variant tag bytes: the first byte of every canonical preimage, so the two
    /// variants live in disjoint digest spaces.
    const SPEND_TAG: u8 = 0x01;
    const REFRESH_TAG: u8 = 0x02;

    /// The single-use freshness nonce, read back out of the same value whose
    /// canonical bytes [`Self::auth_digest`] covers.
    ///
    /// The node's freshness gate reads `nonce`/`expiry` through these accessors
    /// rather than taking them alongside the request: the two would then be free
    /// to disagree, and the gate would be checking a nonce or window the
    /// signature never authenticated. Sourcing them from the signed value makes
    /// that mismatch unrepresentable — the same reason `tagged_hash`/`push_var`
    /// live here rather than in per-crate copies.
    pub fn nonce(&self) -> &'a str {
        match *self {
            CoordRequest::Spend { nonce, .. } | CoordRequest::Refresh { nonce, .. } => nonce,
        }
    }

    /// The coordinator-proposed commitment expiry; see [`Self::nonce`] for why the
    /// gate reads it from the signed request rather than beside it.
    pub fn expiry(&self) -> u64 {
        match *self {
            CoordRequest::Spend { expiry, .. } | CoordRequest::Refresh { expiry, .. } => expiry,
        }
    }

    /// The deterministic preimage the coordinator signs and the node verifies: a
    /// variant tag byte, then each field in fixed order — PSBTs, pin, and nonce as
    /// their raw bytes under a u32-LE length prefix; numerics little-endian. The
    /// PSBTs are bound as their exact base64 ASCII (un-decoded), exactly as the
    /// channel binds its opaque payload, so both sides commit to the identical
    /// string without a re-serialization round trip.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match *self {
            CoordRequest::Spend {
                spend_psbt,
                escape_psbt,
                pin,
                nonce,
                expiry,
                policy_version,
            } => {
                out.push(Self::SPEND_TAG);
                push_var(&mut out, spend_psbt.as_bytes());
                push_var(&mut out, escape_psbt.as_bytes());
                push_var(&mut out, pin.as_bytes());
                push_var(&mut out, nonce.as_bytes());
                out.extend_from_slice(&expiry.to_le_bytes());
                out.extend_from_slice(&policy_version.to_le_bytes());
            }
            CoordRequest::Refresh {
                refresh_psbt,
                nonce,
                expiry,
                policy_version,
            } => {
                out.push(Self::REFRESH_TAG);
                push_var(&mut out, refresh_psbt.as_bytes());
                push_var(&mut out, nonce.as_bytes());
                out.extend_from_slice(&expiry.to_le_bytes());
                out.extend_from_slice(&policy_version.to_le_bytes());
            }
        }
        out
    }

    /// The 32-byte digest the coordinator signs (`tagged_hash(COORD_REQUEST_TAG,
    /// canonical_bytes)`). A node verifies `coord_sig` against it and its pinned
    /// `coordinator_auth_pubkey`.
    pub fn auth_digest(&self) -> [u8; 32] {
        tagged_hash(COORD_REQUEST_TAG, &self.canonical_bytes())
    }
}

/// Body of `POST /sign`. Every submission carries both the primary PSBT and
/// the user-signed escape variant (same-inputs sweep to the escape wallet),
/// plus a PIN — the two-transaction ceremony of ADR-0008 — and a fresh `nonce`
/// with the coordinator's `coord_sig` over the canonical [`CoordRequest::Spend`]
/// bytes (ADR-0013 §2). Every vault is sealed to one coordinator, so the sig and
/// nonce are not optional: a node checks them at ingress, before the PIN.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignRequest {
    /// Base64 PSBT of the spend being requested. On the wire this is `spend`:
    /// ADR-0013 §2 names the tagged arm's fields `{spend, escape, pin, nonce,
    /// expiry, policy_version}` and supersedes the old untagged `{psbt,
    /// escape_psbt, pin}` body. The Rust name is left alone (it is the whole
    /// workspace's word for this PSBT); only the wire is pinned to the ADR. The
    /// coord-auth preimage is unaffected either way — [`CoordRequest::canonical_bytes`]
    /// is positional, never serde-driven.
    #[serde(rename = "spend")]
    pub psbt: String,
    /// Base64 PSBT of the escape variant (same inputs, swept to the escape wallet).
    /// Wire name `escape` (ADR-0013 §2; see [`SignRequest::psbt`]).
    #[serde(rename = "escape")]
    pub escape_psbt: String,
    /// PIN in plaintext (hash-compared on the node; ADR-0008 accepts this for MVP).
    #[serde(default)]
    pub pin: String,
    /// Fresh, single-use per-**transmission** nonce, bound into the
    /// coordinator-auth canonical bytes; a node rejects a nonce it has already
    /// seen (ADR-0013 §2/§3 freshness gate). A coordinator re-sending the same
    /// spend (past a Hold, or retrying a lost call) issues a NEW nonce and
    /// re-signs; idempotency is keyed on the commitment, not on this, so the two
    /// compose. `#[serde(default)]` so a body that omits it still decodes — into
    /// an empty nonce that no coordinator ever signs, hence a refusal, never an
    /// admission.
    #[serde(default)]
    pub nonce: String,
    /// Coordinator-proposed commitment expiry (unix seconds). The node caps it
    /// against its own clock and `max_commitment_age_secs` (DESIGN.md).
    #[serde(default)]
    pub expiry: u64,
    /// Baked policy identifier, bound into the commitment (policy never changes).
    #[serde(default)]
    pub policy_version: u32,
    /// The coordinator's ECDSA signature (DER, hex) over
    /// `tagged_hash(COORD_REQUEST_TAG, canonical_bytes(SpendRequest))`, verified
    /// against the node's pinned `coordinator_auth_pubkey` (see [`CoordRequest`]).
    /// Every node is provisioned with a coordinator, so an empty or malformed
    /// `coord_sig` is simply an authentication failure (`COORD_AUTH_INVALID`) —
    /// there is no un-gated mode.
    #[serde(default)]
    pub coord_sig: String,
}

impl SignRequest {
    /// This spend request as the tagged [`CoordRequest::Spend`] whose canonical
    /// bytes the coordinator signed — the single place the signed preimage is built.
    pub fn coord_request(&self) -> CoordRequest<'_> {
        CoordRequest::Spend {
            spend_psbt: &self.psbt,
            escape_psbt: &self.escape_psbt,
            pin: &self.pin,
            nonce: &self.nonce,
            expiry: self.expiry,
            policy_version: self.policy_version,
        }
    }
}

/// ADR-0013's name for the spend arm of [`TaggedRequest`], which is where this
/// alias is used: the tagged boundary is the one place the spec's Spend/Refresh
/// vocabulary is load-bearing, so it spells the ADR's name. `SignRequest` stays
/// the name in handler and call-site code. No rename is in flight — the two
/// names are one type on purpose, not a migration waiting to finish.
pub type SpendRequest = SignRequest;

/// Body of a pin-less refresh (ADR-0013 §2): a self-spend that resets the
/// recovery timelock. Carries no escape and no pin. A first-class coordinator-
/// authenticated request — a node authenticates it exactly like a
/// [`SignRequest`] before applying the instant self-spend signing path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefreshRequest {
    /// Base64 PSBT of the refresh self-spend (every output pays the vault).
    /// Wire name `refresh` (ADR-0013 §2; see [`SignRequest::psbt`]).
    #[serde(rename = "refresh")]
    pub refresh_psbt: String,
    /// Fresh, single-use per-**transmission** nonce; see [`SignRequest::nonce`] for
    /// the freshness rule this shares (the wire constrains length, not encoding).
    #[serde(default)]
    pub nonce: String,
    /// Coordinator-proposed commitment expiry (unix seconds).
    #[serde(default)]
    pub expiry: u64,
    /// Baked policy identifier.
    #[serde(default)]
    pub policy_version: u32,
    /// The coordinator's signature over the canonical [`CoordRequest::Refresh`]
    /// bytes; see [`SignRequest::coord_sig`].
    #[serde(default)]
    pub coord_sig: String,
}

impl RefreshRequest {
    /// This refresh request as the tagged [`CoordRequest::Refresh`] the coordinator signed.
    pub fn coord_request(&self) -> CoordRequest<'_> {
        CoordRequest::Refresh {
            refresh_psbt: &self.refresh_psbt,
            nonce: &self.nonce,
            expiry: self.expiry,
            policy_version: self.policy_version,
        }
    }
}

/// The wire-level tagged union from ADR-0013 §2. Serde's external tag produces
/// exactly one top-level arm — `{ "spend": { ... } }` or
/// `{ "refresh": { ... } }` — so a pin-less refresh can never be decoded as a
/// malformed spend before it reaches the shared coordinator-auth gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaggedRequest {
    Spend(SpendRequest),
    Refresh(RefreshRequest),
}

/// The two `/sign` outcomes: `{"accepted":{...}}` or `{"refusal":{...}}`.
///
/// **There is no signature-bearing variant, and that absence is the security
/// property** (ADR-0012, "the coordinator is a pure relay, always"). Under
/// Model B the node signs its partial(s) at ingress but releases them ONLY to
/// its peers, ONLY at the candidate's authorized fire event; the nodes combine
/// and broadcast. A `/sign` response that could carry a partial would hand a
/// post-wrench coordinator a way to collect `t` of them and finalize a coerced
/// spend itself — breaking both the Hold and duress silence without compromising
/// a single node. Deleting the coordinator's finalize code would not close that:
/// the response type itself must make the partial unrepresentable, so no
/// handler, no future caller, and no hostile relay can obtain one here.
///
/// The former `Signed(String)` variant is therefore GONE, not deprecated. Do not
/// re-add a signature-carrying variant: partials leave a node exclusively through
/// the fire-gated `/channel` `partial` message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignResponse {
    /// The node authenticated, validated, and ACCEPTED the request: it registered
    /// the candidate(s), signed its partial(s) at ingress, and is withholding them
    /// until fire. Carries no signature — see the type docs.
    #[serde(rename = "accepted")]
    Accepted(Accepted),
    /// The node refuses to sign, with a machine-readable reason.
    #[serde(rename = "refusal")]
    Refusal(Refusal),
}

/// The fixed acknowledgement an accepted request earns — **the same fields with
/// the same shape under every transaction class and under either PIN** (ADR-0012,
/// "constant-observable ingress" / "response cover"). It reports only what the
/// coordinator already knows (which commitment, when this node first saw it, and
/// the remaining Hold), never which transaction will fire or when a duress escape
/// is scheduled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Accepted {
    /// The spend's commitment id (the exact-tx binding, ADR-0012).
    pub commitment_id: String,
    /// Unix seconds when this node first saw the commitment.
    pub first_seen: u64,
    /// Seconds measured **from `first_seen`** until this node's Hold expires and
    /// the spend becomes fire-eligible; the absolute fire time is
    /// `first_seen + remaining_secs`. Fixed at first acceptance and replayed
    /// verbatim on an idempotent resubmission (the Hold schedule the first
    /// acceptance fixed is never reset), so it is NOT a live countdown from the
    /// response instant — mid-Hold, seconds-left is `first_seen + remaining_secs −
    /// now`. `0` for a class that fires immediately (escape-class, refresh).
    pub remaining_secs: u64,
}

/// A node's structured decision not to sign.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Refusal {
    pub code: RefusalCode,
    /// Which policy check refused (e.g. "destination_allowlist").
    pub check: String,
    /// Human-readable specifics.
    pub detail: String,
}

/// The refusal-code enum from DESIGN.md ("/sign wire contract"). All variants
/// are declared even where first light never emits them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RefusalCode {
    WrongDescriptor,
    UnknownInput,
    DestNotAllowed,
    ChangeNotDerivable,
    FeeExceedsCap,
    BadSighash,
    UserSigInvalid,
    CommitmentExpired,
    PsbtInconsistent,
    BadPin,
    FraudSuspected,
    /// The coordinator authentication failed: `coord_sig` is absent, malformed,
    /// or does not verify against the node's pinned `coordinator_auth_pubkey`
    /// over the canonical request bytes (ADR-0013 §2).
    CoordAuthInvalid,
    /// The request's `nonce` was already seen by this node: a replay of a
    /// coordinator-signed request (ADR-0013 §2/§3 freshness gate).
    NonceReplayed,
    /// The bounded authenticated-nonce cache is full. No new request is admitted
    /// until an older nonce expires; existing entries are never evicted early.
    CoordNonceCapacity,
    /// The node's bounded candidate registry cannot atomically admit every new
    /// member of this request's candidate set. In channel mode an acknowledgement
    /// is valid only after the node can retain its ingress signature(s) for the
    /// fire-time quorum, so capacity is a refusal rather than a dropped candidate.
    CandidateCapacity,
    /// A hot-class spend whose commitment expiry does not outlive this node's
    /// Hold plus its combine window (`now + hold_secs + combine_slack_secs`,
    /// ADR-0013 §6). Distinct from [`RefusalCode::CommitmentExpired`], which is
    /// the ingress acceptance window: this one says the commitment would die
    /// mid-flight — the node would sign at ingress, hold the partial, and find the
    /// candidate pruned before it could ever combine. Refusing up front beats
    /// accepting a spend that can only silently fail. Equality passes.
    ExpiryTooShort,
    /// A refresh of a coin refreshed less than `refresh_min_interval_secs` ago
    /// (ADR-0013 §6). The refresh path is pin-less and instant, so it has neither
    /// the Hold nor the PIN that ADR-0006 leans on for its burn defense; this
    /// interval is half of what replaces them.
    RefreshTooSoon,
    /// A refresh paying more than `refresh_max_feerate` (ADR-0013 §6) — the other
    /// half of the refresh burn bound. A real self-spend pays a normal feerate,
    /// never the 10% `max_fee_pct` a hot-class spend may use.
    RefreshFeeExceedsCap,
    /// A refresh submitted while a spend is pending on this node (ADR-0012,
    /// "refreshes are subordinate to pending spends"). Retriable: resubmit once
    /// the pending spend settles. The rule is deliberately COARSE — any pending
    /// spend blocks every refresh.
    RefreshSubordinated,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_request_round_trips() {
        let req = SignRequest {
            psbt: "cHNidP8B".into(),
            escape_psbt: "cHNidP8C".into(),
            pin: "482913".into(),
            nonce: "ab12".into(),
            expiry: 1_752_500_000,
            policy_version: 1,
            coord_sig: "deadbeef".into(),
        };
        let json = serde_json::to_string(&req).expect("serialize");
        assert_eq!(
            json,
            r#"{"spend":"cHNidP8B","escape":"cHNidP8C","pin":"482913","nonce":"ab12","expiry":1752500000,"policy_version":1,"coord_sig":"deadbeef"}"#
        );
        let back: SignRequest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, req);
    }

    #[test]
    fn tagged_request_round_trips_both_variants() {
        let spend = TaggedRequest::Spend(SignRequest {
            psbt: "spend".into(),
            escape_psbt: "escape".into(),
            pin: "482913".into(),
            nonce: "spend-nonce".into(),
            expiry: 1_752_500_000,
            policy_version: 1,
            coord_sig: "spend-sig".into(),
        });
        let spend_json = serde_json::to_string(&spend).expect("serialize spend arm");
        // ADR-0013 §2's exact shape: outer tag `spend`, inner fields `spend`/`escape`.
        assert!(spend_json.starts_with(r#"{"spend":{"spend":"spend","escape":"escape","#));
        assert_eq!(
            serde_json::from_str::<TaggedRequest>(&spend_json).expect("deserialize spend arm"),
            spend
        );

        let refresh = TaggedRequest::Refresh(RefreshRequest {
            refresh_psbt: "refresh".into(),
            nonce: "refresh-nonce".into(),
            expiry: 1_752_500_000,
            policy_version: 1,
            coord_sig: "refresh-sig".into(),
        });
        let refresh_json = serde_json::to_string(&refresh).expect("serialize refresh arm");
        // ADR-0013 §2's exact shape: outer tag `refresh`, inner field `refresh`.
        assert!(refresh_json.starts_with(r#"{"refresh":{"refresh":"refresh","#));
        assert_eq!(
            serde_json::from_str::<TaggedRequest>(&refresh_json).expect("deserialize refresh arm"),
            refresh
        );
    }

    /// A commitment with distinct, non-trivial data in every field, built twice
    /// from the same logical inputs (helper below).
    fn sample_commitment(outputs: Vec<CommitmentOutput>) -> Commitment {
        Commitment {
            wallet_id: [0x11; 32],
            version: 2,
            lock_time: 500_001,
            inputs: vec![
                CommitmentInput {
                    txid: [0x22; 32],
                    vout: 0,
                    sequence: 0xffff_fffd,
                },
                CommitmentInput {
                    txid: [0x33; 32],
                    vout: 7,
                    sequence: 0xffff_ffff,
                },
            ],
            outputs,
            fee: 10_000,
            expiry: 1_752_500_000,
            policy_version: 1,
        }
    }

    fn hot_output() -> CommitmentOutput {
        CommitmentOutput {
            script_pubkey: vec![0x00, 0x14, 0xAB, 0xCD],
            amount: 99_990_000,
        }
    }

    #[test]
    fn commitment_serialization_is_deterministic() {
        // Two independent constructions of the same logical commitment.
        let a = sample_commitment(vec![hot_output()]);
        let b = sample_commitment(vec![hot_output()]);
        assert_eq!(a.canonical_bytes(), b.canonical_bytes());
        assert_eq!(a.commitment_id(), b.commitment_id());
        // The id is a 32-byte hash rendered as lowercase hex.
        assert_eq!(a.commitment_id().len(), 64);
    }

    #[test]
    fn commitment_survives_serde_json() {
        let commitment = sample_commitment(vec![hot_output()]);
        let json = serde_json::to_string(&commitment).expect("serialize");
        let back: Commitment = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, commitment);
        // Serde is a transport, not the identity: the recovered value hashes
        // to the same commitment id.
        assert_eq!(back.commitment_id(), commitment.commitment_id());
    }

    #[test]
    fn commitment_is_not_keyed_by_outpoint_set() {
        // Same inputs (outpoints), different outputs and fee: an RBF-style
        // replacement. It MUST hash to a different id, so the log never blocks
        // a legitimate replacement (DESIGN.md, "anti-replay log").
        let original = sample_commitment(vec![hot_output()]);
        let mut replacement = sample_commitment(vec![CommitmentOutput {
            script_pubkey: vec![0x00, 0x14, 0xAB, 0xCD],
            amount: 99_980_000, // fee bump: less to the destination
        }]);
        replacement.fee = 20_000;
        assert_eq!(
            original.inputs, replacement.inputs,
            "the two txs spend the identical outpoints"
        );
        assert_ne!(original.commitment_id(), replacement.commitment_id());
    }

    #[test]
    fn missing_pin_decodes_as_empty_pin() {
        let json = r#"{"spend":"cHNidP8B","escape":"cHNidP8C"}"#;
        let back: SignRequest = serde_json::from_str(json).expect("deserialize");
        assert_eq!(back.pin, "");
    }

    #[test]
    fn accepted_response_round_trips() {
        let resp = SignResponse::Accepted(Accepted {
            commitment_id: "c0ffee".into(),
            first_seen: 1_752_500_000,
            remaining_secs: 86_400,
        });
        let json = serde_json::to_string(&resp).expect("serialize");
        assert_eq!(
            json,
            r#"{"accepted":{"commitment_id":"c0ffee","first_seen":1752500000,"remaining_secs":86400}}"#
        );
        let back: SignResponse = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, resp);
    }

    /// The structural half of "the coordinator is a pure relay" (§2): no `/sign`
    /// response can carry a node signature, because no variant can hold one. A
    /// hostile coordinator that collects every node's response therefore holds
    /// nothing it can finalize.
    ///
    /// This asserts over the SERIALIZED forms of both variants rather than
    /// pattern-matching the enum: a future variant carrying a PSBT would compile
    /// and pass a match-based test, but it cannot pass this one without putting
    /// base64 PSBT data on the wire. The old `{"signed_psbt":"..."}` shape must
    /// also no longer decode — a node speaking it would be a downgrade.
    #[test]
    fn no_sign_response_can_carry_a_node_signature() {
        let accepted = SignResponse::Accepted(Accepted {
            commitment_id: "c0ffee".into(),
            first_seen: 1_752_500_000,
            remaining_secs: 0,
        });
        let refusal = SignResponse::Refusal(Refusal {
            code: RefusalCode::BadPin,
            check: "pin".into(),
            detail: "nope".into(),
        });
        for response in [&accepted, &refusal] {
            let json = serde_json::to_string(response).expect("serialize");
            assert!(
                !json.contains("psbt") && !json.contains("cHNidP"),
                "a /sign response must never carry PSBT/signature data: {json}"
            );
        }
        assert!(
            serde_json::from_str::<SignResponse>(r#"{"signed_psbt":"cHNidP8B"}"#).is_err(),
            "the retired signature-bearing response must no longer decode"
        );
    }

    #[test]
    fn refusal_response_round_trips_with_screaming_snake_code() {
        let resp = SignResponse::Refusal(Refusal {
            code: RefusalCode::DestNotAllowed,
            check: "destination_allowlist".into(),
            detail: "output 0 pays a scriptPubKey outside the allowlist".into(),
        });
        let json = serde_json::to_string(&resp).expect("serialize");
        assert_eq!(
            json,
            r#"{"refusal":{"code":"DEST_NOT_ALLOWED","check":"destination_allowlist","detail":"output 0 pays a scriptPubKey outside the allowlist"}}"#
        );
        let back: SignResponse = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, resp);
    }

    // --- coordinator-request authentication (ADR-0013 §2) --------------------

    use bitcoin::secp256k1::{
        ecdsa::Signature, Message, PublicKey as SecpPublicKey, Secp256k1, SecretKey,
    };

    fn coord_keypair(seed: u8) -> (SecretKey, SecpPublicKey) {
        let sk = SecretKey::from_slice(&[seed; 32]).expect("32 nonzero bytes");
        (sk, sk.public_key(&Secp256k1::new()))
    }

    /// A fixed Spend request over `nonce`, the baseline the tamper cases mutate.
    fn sample_spend(nonce: &str) -> CoordRequest<'_> {
        CoordRequest::Spend {
            spend_psbt: "cHNidP8BSPEND",
            escape_psbt: "cHNidP8BESCAPE",
            pin: "246802",
            nonce,
            expiry: 1_752_500_000,
            policy_version: 1,
        }
    }

    /// The coordinator's role: sign the request digest with the auth key.
    fn coord_sign(req: &CoordRequest, sk: &SecretKey) -> Signature {
        Secp256k1::new().sign_ecdsa(&Message::from_digest(req.auth_digest()), sk)
    }

    /// The node's role: verify a DER sig against a candidate coordinator pubkey.
    fn coord_verify(req: &CoordRequest, sig: &Signature, pk: &SecpPublicKey) -> bool {
        Secp256k1::new()
            .verify_ecdsa(&Message::from_digest(req.auth_digest()), sig, pk)
            .is_ok()
    }

    #[test]
    fn coord_canonical_bytes_and_digest_are_deterministic() {
        let a = sample_spend("aa");
        let b = sample_spend("aa");
        assert_eq!(a.canonical_bytes(), b.canonical_bytes());
        assert_eq!(a.auth_digest(), b.auth_digest());
    }

    #[test]
    fn a_correctly_signed_request_verifies_but_a_wrong_key_does_not() {
        let (sk, pk) = coord_keypair(0xC0);
        let (_, wrong_pk) = coord_keypair(0xC1);
        let req = sample_spend("nonce-1");
        let sig = coord_sign(&req, &sk);
        assert!(coord_verify(&req, &sig, &pk), "the signing key must verify");
        assert!(
            !coord_verify(&req, &sig, &wrong_pk),
            "a coordinator key that did not sign must never verify"
        );
    }

    #[test]
    fn tampering_any_signed_field_breaks_the_signature() {
        let (sk, pk) = coord_keypair(0xC0);
        let base = sample_spend("nonce-1");
        let sig = coord_sign(&base, &sk);
        assert!(coord_verify(&base, &sig, &pk));

        // Each entry mutates exactly ONE signed field of the baseline; every one
        // must fail verification under the original signature (spend, escape, pin,
        // nonce, expiry, policy_version are all bound).
        let tampered = [
            CoordRequest::Spend {
                spend_psbt: "cHNidP8BTAMPER",
                escape_psbt: "cHNidP8BESCAPE",
                pin: "246802",
                nonce: "nonce-1",
                expiry: 1_752_500_000,
                policy_version: 1,
            },
            CoordRequest::Spend {
                spend_psbt: "cHNidP8BSPEND",
                escape_psbt: "cHNidP8BTAMPER",
                pin: "246802",
                nonce: "nonce-1",
                expiry: 1_752_500_000,
                policy_version: 1,
            },
            CoordRequest::Spend {
                spend_psbt: "cHNidP8BSPEND",
                escape_psbt: "cHNidP8BESCAPE",
                pin: "999999",
                nonce: "nonce-1",
                expiry: 1_752_500_000,
                policy_version: 1,
            },
            CoordRequest::Spend {
                spend_psbt: "cHNidP8BSPEND",
                escape_psbt: "cHNidP8BESCAPE",
                pin: "246802",
                nonce: "nonce-2",
                expiry: 1_752_500_000,
                policy_version: 1,
            },
            CoordRequest::Spend {
                spend_psbt: "cHNidP8BSPEND",
                escape_psbt: "cHNidP8BESCAPE",
                pin: "246802",
                nonce: "nonce-1",
                expiry: 1_752_500_001,
                policy_version: 1,
            },
            CoordRequest::Spend {
                spend_psbt: "cHNidP8BSPEND",
                escape_psbt: "cHNidP8BESCAPE",
                pin: "246802",
                nonce: "nonce-1",
                expiry: 1_752_500_000,
                policy_version: 2,
            },
        ];
        for t in &tampered {
            assert!(
                !coord_verify(t, &sig, &pk),
                "a tampered field must break verification: {t:?}"
            );
        }
    }

    #[test]
    fn spend_and_refresh_never_share_a_digest() {
        // Same nonce/expiry/policy and a shared PSBT string: only the tag byte
        // (and the missing escape/pin) distinguishes them, which must suffice.
        let spend = CoordRequest::Spend {
            spend_psbt: "P",
            escape_psbt: "",
            pin: "",
            nonce: "n",
            expiry: 7,
            policy_version: 1,
        };
        let refresh = CoordRequest::Refresh {
            refresh_psbt: "P",
            nonce: "n",
            expiry: 7,
            policy_version: 1,
        };
        assert_ne!(spend.auth_digest(), refresh.auth_digest());
    }

    #[test]
    fn a_refresh_request_authenticates_like_a_spend() {
        let (sk, pk) = coord_keypair(0xC0);
        let (_, wrong_pk) = coord_keypair(0xC1);
        let req = CoordRequest::Refresh {
            refresh_psbt: "cHNidP8BREFRESH",
            nonce: "r-1",
            expiry: 1_752_500_000,
            policy_version: 1,
        };
        let sig = coord_sign(&req, &sk);
        assert!(coord_verify(&req, &sig, &pk));
        assert!(!coord_verify(&req, &sig, &wrong_pk));
    }
}
