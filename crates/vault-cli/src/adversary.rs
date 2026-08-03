//! The adversary's own channel implementation: what a **compromised node**
//! (`c ≤ t−1`, the soft-vault tolerance) can say and see on the node-to-node
//! channel.
//!
//! This exists because the duress safety property is not observable any other
//! way. ADR-0012's constant-observable ingress deliberately leaks nothing about
//! armed state over `/sign` or `/events`, so a harness cannot ask a node "are you
//! frozen?" — and a harness that could ask would be testing a seam production does
//! not have. What it CAN do is stand where the attacker stands: hold `t−1` node
//! identities, receive everything honest nodes push to those identities, and count
//! the partials that actually arrive.
//!
//! That count IS the safety property. ADR-0012's release-gate says no candidate
//! partial leaves a node before that candidate's authorized fire event, and that
//! arming suppresses every hot-partial release under the same store lock. So for a
//! coerced spend the adversary should collect ZERO honest partials, leaving it
//! holding only its own `t−1` — never a signing quorum. [`Wiretap::honest_partials_for`]
//! is where a harness reads that off.
//!
//! **Nothing here is a signing oracle.** Be exact about what that prohibition says,
//! because the arm-split scenarios depend on the difference. It is NOT "a relayed
//! message never results in a signature": a propagated carrier is the *user's*
//! authorization in transit, and `vault-node/src/lib.rs:2606` dispatches it to the
//! same `handle_sign_after_lock` a direct `/sign` reaches, so an honest node that
//! receives a valid carrier over this channel does sign it at ingress — pin-
//! independently, which is what keeps signing itself from being a duress oracle.
//!
//! What ADR-0012 prohibits absolutely is a peer *claim* carrying authority: a node
//! signs only after independently receiving and accepting the full user-authorized
//! request against its own policy, pin, and Hold/duress state, and "I validated" or
//! "broadcast now" from this adversary buys nothing. So what this module cannot do
//! is EXTRACT: relay, withhold, forge its own receipts, and listen as it may, no
//! candidate's partial reaches these endpoints before that candidate's authorized
//! fire event, and arming suppresses that release outright. The scenarios that try
//! to pull a partial out early are precisely the ones that must fail — and a
//! coerced carrier that every honest node signed but none released is the coupling
//! holding, not a violation of it.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use bitcoin::hex::{DisplayHex, FromHex};
use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::secp256k1::{All, Message, Secp256k1, SecretKey};
use bitcoin::{PublicKey, Txid};
use serde_json::{json, Value};
use vault_node::channel::{ceremony, PROTOCOL_VERSION_V0};
use vault_proto::{push_var, tagged_hash, TaggedRequest};

use crate::fed::{unix_now, Actor};
use crate::http::{self, Error};

/// Domain tags and wire constants, mirrored from `vault_node::channel`. They are
/// `pub(crate)` there, so the adversary re-states them — which is what a real
/// compromised-node operator would do anyway, having only the wire to work from.
///
/// Drift in a mirrored value is caught, but by two different mechanisms, and it is
/// worth being exact about which covers what:
///
///  - `CHANNEL_KEY_TAG` is checked STATICALLY at bring-up: [`CompromisedNode::new`]
///    asserts the re-derived channel pubkey equals `ceremony::channel_pubkey`, so a
///    tag or derivation change fails locally with a precise message.
///  - `ENVELOPE_TAG`, [`envelope_preimage`]'s field layout and the message tags have
///    no such local oracle — they are checked LIVE, by an honest node
///    accepting an envelope this module built. That check is only as good as the
///    callers, so every caller of [`CompromisedNode::relay_request`] — today all of them
///    reach it through [`CompromisedNode::relay_request_awaiting_ruling`], which returns
///    the final response — and of [`CompromisedNode::relay_partial`] must inspect the
///    returned status rather than
///    discarding it: an envelope a node rejected proves the mirror drifted, and
///    silently dropping that turns an attack into a vacuous pass. A drifted inbound
///    message tag is filed under `undecoded`, which every absence-based assertion
///    refuses. [`USER_SIG_HASH_TAG`] likewise only recomputes what an honest node put
///    in an observed partial, so drift fails the binding check in
///    `validate_observed_partial` loudly rather than silently.
///
/// `PROTOCOL_VERSION_V0` is deliberately NOT mirrored: `vault_node::channel` exports
/// it, so importing it removes a value from this list entirely.
const CHANNEL_KEY_TAG: &str = "btc-policy/channel-key/v0";
const ENVELOPE_TAG: &str = "btc-policy/channel-envelope/v0";
const MSG_TYPE_REQUEST: &str = "request";
const MSG_TYPE_PARTIAL: &str = "partial";
const WIRETAP_BARRIER_FIELD: &str = "btc_policy_wiretap_barrier";
static WIRETAP_BARRIER_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// The domain tag binding a partial to the exact user signatures on its candidate
/// (`vault_node::channel::USER_SIG_HASH_TAG`, crate-private there).
pub(crate) const USER_SIG_HASH_TAG: &str = "btc-policy/user-sig-hash/v0";

/// The channel secret key a node derives at startup from its signing key
/// (`vault_node::channel::derive_channel_seckey`). A compromised node's operator
/// holds the signing key, so it holds this too.
fn derive_channel_seckey(node_seckey: &SecretKey) -> SecretKey {
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
            .expect("channel-key derivation exhausted the u8 retry counter");
    }
}

/// The signed envelope preimage (`vault_node::channel::envelope_preimage`): three
/// length-prefixed variable fields around the fixed ones, all little-endian.
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
    let mut e = Vec::new();
    push_var(&mut e, msg_type.as_bytes());
    e.extend_from_slice(&protocol_version.to_le_bytes());
    e.extend_from_slice(wallet_id);
    e.extend_from_slice(manifest_hash);
    e.extend_from_slice(&sender_node_id.to_le_bytes());
    e.extend_from_slice(&recipient_node_id.to_le_bytes());
    push_var(&mut e, payload_b64);
    push_var(&mut e, nonce);
    e.extend_from_slice(&timestamp.to_le_bytes());
    e
}

fn from_hex_32(s: &str) -> Result<[u8; 32], Error> {
    Vec::<u8>::from_hex(s)
        .map_err(|e| format!("not hex: {e}"))?
        .try_into()
        .map_err(|_| "expected a 32-byte hex string".into())
}

fn from_hex_16(s: &str) -> Result<[u8; 16], Error> {
    Vec::<u8>::from_hex(s)
        .map_err(|e| format!("not hex: {e}"))?
        .try_into()
        .map_err(|_| "expected a 16-byte hex string".into())
}

// ---------------------------------------------------------------------------
// One compromised node identity

/// One node identity the adversary controls: its channel key, its **Bitcoin
/// signing key**, its `node_id`, and the listener standing in for the daemon that
/// would otherwise run there.
///
/// Taking over a node means taking its keys, both of them. The signing key is what
/// makes `c = t−1` a real compromise rather than a wiretap: it is the adversary's
/// own share of every candidate, and it is what
/// `Vault::combine_with_compromised` uses to show that ONE honest share on top of
/// these `t−1` finalizes to a transaction Core will accept.
pub(crate) struct CompromisedNode {
    pub(crate) node_id: u16,
    pub(crate) port: u16,
    channel_seckey: SecretKey,
    /// The node's descriptor key. Held for the same reason a real attacker holds
    /// it: to combine.
    signer: Actor,
    wallet_id: [u8; 32],
    manifest_hash: [u8; 32],
    wiretap: Arc<Wiretap>,
    shutdown: Arc<AtomicBool>,
    /// Cleared when the accept loop leaves, by unwind or by return. A listener that
    /// died is DEAF, and a deaf listener reports zero partials for every commitment
    /// — the one failure mode that reads as safety. Every absence-based assertion
    /// checks this (`Vault::assert_wiretap_decoded`).
    alive: Arc<AtomicBool>,
    /// Connection handlers that the accept loop has handed off but that have not yet
    /// finished decoding and recording their body. An absence read is trustworthy
    /// only after this reaches zero: listener liveness alone says nothing about an
    /// already-accepted partial that is still in `read_channel_body`.
    active_handlers: Arc<AtomicUsize>,
}

impl CompromisedNode {
    /// Take over `actor`'s node identity and start listening on `port`.
    ///
    /// `port` must be the endpoint the manifest pins for this `node_id`: endpoints
    /// are sealed (ADR-0013 §4, anti-redirection), so the adversary cannot move its
    /// own node — it can only be what answers at the sealed address.
    pub(crate) fn new(
        secp: &Secp256k1<All>,
        actor: &Actor,
        node_id: u16,
        port: u16,
        wallet_id: [u8; 32],
        manifest_hash_hex: &str,
        channel_pubkeys: &[PublicKey],
    ) -> Result<CompromisedNode, Error> {
        let channel_seckey = derive_channel_seckey(&actor.seckey);
        // Check the mirrored derivation against the node's own definition before a
        // single envelope is signed, so drift fails loudly and locally.
        let derived = PublicKey::new(channel_seckey.public_key(secp));
        let expected = ceremony::channel_pubkey(&actor.seckey);
        if derived != expected {
            return Err(format!(
                "adversary channel-key derivation drifted from vault_node::channel::ceremony \
                 (derived {derived}, node derives {expected}) — re-sync CHANNEL_KEY_TAG"
            )
            .into());
        }
        // Decode the manifest hash BEFORE binding. A listener spawned first and then
        // abandoned by a `?` here would never be reached by `Drop` (no
        // `CompromisedNode` exists to drop), so its thread would hold the sealed port
        // for the rest of the process — and the port is this identity's only address.
        let manifest_hash = from_hex_32(manifest_hash_hex)?;
        let wiretap = Arc::new(Wiretap::new(
            wallet_id,
            manifest_hash,
            node_id,
            channel_pubkeys,
        ));
        let shutdown = Arc::new(AtomicBool::new(false));
        let alive = Arc::new(AtomicBool::new(true));
        let active_handlers = Arc::new(AtomicUsize::new(0));
        spawn_listener(
            port,
            Arc::clone(&wiretap),
            Arc::clone(&shutdown),
            Arc::clone(&alive),
            Arc::clone(&active_handlers),
        )?;
        Ok(CompromisedNode {
            node_id,
            port,
            channel_seckey,
            signer: Actor {
                seckey: actor.seckey,
                pubkey: actor.pubkey,
            },
            wallet_id,
            manifest_hash,
            wiretap,
            shutdown,
            alive,
            active_handlers,
        })
    }

    pub(crate) fn wiretap(&self) -> Arc<Wiretap> {
        Arc::clone(&self.wiretap)
    }

    /// This identity's descriptor key, for combining.
    pub(crate) fn signer(&self) -> &Actor {
        &self.signer
    }

    /// Whether this identity's listener is still accepting. False means the accept
    /// loop is gone — the port is dark and nothing more will ever be recorded, so
    /// any zero read off [`Self::wiretap`] afterwards is an artefact.
    pub(crate) fn listener_alive(&self) -> bool {
        self.alive.load(Ordering::SeqCst)
    }

    /// Number of accepted connections whose bodies have not yet been completely
    /// decoded and recorded. Used by the harness's absence barrier.
    pub(crate) fn active_handlers(&self) -> usize {
        self.active_handlers.load(Ordering::SeqCst)
    }

    /// Round-trip a marker through this listener's accept loop.
    ///
    /// `active_handlers == 0` alone cannot see a completed TCP connection that is
    /// still queued in the kernel's listen backlog. Once this marker is answered,
    /// every connection queued ahead of it has at least been accepted; the caller
    /// can then use `active_handlers` to wait for those decoders to finish.
    pub(crate) fn wiretap_barrier(&self) -> Result<(), Error> {
        let sequence = WIRETAP_BARRIER_SEQUENCE.fetch_add(1, Ordering::SeqCst);
        let token = format!("{}-{sequence}", self.node_id);
        let body = serde_json::to_vec(&json!({ WIRETAP_BARRIER_FIELD: token }))?;
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, self.port));
        let response = http::post_json(
            addr,
            "/wiretap-barrier",
            &body,
            None,
            Duration::from_secs(5),
        )?;
        let echoed = serde_json::from_str::<Value>(&response.body)
            .ok()
            .and_then(|value| {
                value
                    .get(WIRETAP_BARRIER_FIELD)
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            });
        if response.status != 200 || echoed.as_deref() != Some(token.as_str()) {
            return Err(format!(
                "wiretap barrier for node_id {} returned HTTP {} {}",
                self.node_id, response.status, response.body
            )
            .into());
        }
        Ok(())
    }

    /// Sign one envelope as this node and POST it to `peer`.
    ///
    /// Returns the peer's `/channel` reply verbatim. A rejection is data, not an
    /// error: several scenarios attack precisely by producing envelopes a peer
    /// should refuse, and the refusal is the evidence.
    fn send(
        &self,
        secp: &Secp256k1<All>,
        peer: SocketAddr,
        msg_type: &str,
        payload: &[u8],
        recipient: u16,
    ) -> Result<http::Response, Error> {
        let payload_b64 = STANDARD.encode(payload);
        // Channel-envelope nonces are exactly 16 bytes (ADR-0013 §5), unlike the
        // coordinator request's 32-byte nonce. Keeping the two generators separate
        // prevents a compromised-peer test message from being rejected as malformed
        // before its authenticated holder receipt reaches the state machine.
        let mut nonce_bytes = [0u8; 16];
        std::fs::File::open("/dev/urandom")?.read_exact(&mut nonce_bytes)?;
        let nonce = nonce_bytes.to_lower_hex_string();
        let timestamp = unix_now()?;
        let preimage = envelope_preimage(
            msg_type,
            PROTOCOL_VERSION_V0,
            &self.wallet_id,
            &self.manifest_hash,
            self.node_id,
            recipient,
            payload_b64.as_bytes(),
            &nonce_bytes,
            timestamp,
        );
        let sig = secp.sign_ecdsa(
            &Message::from_digest(tagged_hash(ENVELOPE_TAG, &preimage)),
            &self.channel_seckey,
        );
        let envelope = serde_json::json!({
            "msg_type": msg_type,
            "protocol_version": PROTOCOL_VERSION_V0,
            "wallet_id": self.wallet_id.to_lower_hex_string(),
            "manifest_hash": self.manifest_hash.to_lower_hex_string(),
            "sender_node_id": self.node_id,
            "recipient_node_id": recipient,
            "payload_b64": payload_b64,
            "nonce": nonce,
            "timestamp": timestamp,
            "channel_sig": sig.serialize_der().to_lower_hex_string(),
        });
        let body = serde_json::to_vec(&envelope)?;
        http::post_json(peer, "/channel", &body, None, Duration::from_secs(10))
    }

    /// Relay a coordinator-signed request to one peer AS THIS NODE — the receipt
    /// that counts toward that peer's `t`-holder set (ADR-0012 §0).
    ///
    /// This is the adversary's most interesting primitive: it can manufacture the
    /// *appearance* of federation-wide holding without any honest node having seen
    /// the carrier. The scenarios use it to try to drive a coerced spend's carrier
    /// to `t` holders at ONE honest node while the rest stay dark. It still yields
    /// nothing, because a holder receipt opens a candidate's release only at that
    /// node, and at that node the same carrier's duress PIN armed the freeze under
    /// the same lock.
    pub(crate) fn relay_request(
        &self,
        secp: &Secp256k1<All>,
        peer: SocketAddr,
        recipient: u16,
        request: &TaggedRequest,
    ) -> Result<http::Response, Error> {
        let payload = serde_json::to_vec(request)?;
        self.send(secp, peer, MSG_TYPE_REQUEST, &payload, recipient)
    }

    /// [`Self::relay_request`], honouring the channel's own `RATE_LIMITED` contract.
    ///
    /// `RATE_LIMITED` means TRY AGAIN, not "rejected". The production sender loops on it
    /// and returns only on `Accepted`/`Rejected` (`vault_node::channel`'s `retry_loop`),
    /// so a harness that read the first `429` as a refusal would be asserting a contract
    /// the protocol never made — and would fail intermittently, on load, for a reason
    /// that has nothing to do with the safety property under test.
    ///
    /// It became reachable for a holder confirmation with bead btc-policy-9zs: a request
    /// whose nonce is claimed by a `/sign` handler still inside its out-of-lock PIN
    /// window is answered `RATE_LIMITED` deliberately, because the node has consumed the
    /// nonce but not yet RULED on it. Answering `ACCEPTED` there is the silent false
    /// positive that variant exists to close — the sender would believe a peer holds a
    /// carrier it never recorded — so the retry is the correct client behaviour, not a
    /// workaround. Each attempt builds a FRESH envelope (new nonce and timestamp), so a
    /// retry is never a channel replay.
    ///
    /// BOUNDED ON TOTAL WAIT, not on attempt count, so a node that never rules still
    /// fails its caller rather than hanging the scenario. The node's legitimate
    /// claimed-but-unruled span is not just the PIN window: it ends when the handler
    /// does, so it also covers the out-of-lock chain preflight, whose two RPC batches are
    /// each bounded by `vault_node::chain`'s 60s timeout. An attempt cap of 10 against
    /// the fixed 1s the node sends bounded the wait at 9s — INSIDE that span, so a slow
    /// backend or a loaded box failed the scenario for exactly the reason this helper
    /// exists to eliminate. The attempt cap survives only as a guard against a
    /// pathological zero-wait loop; the wait ceiling is what actually binds.
    pub(crate) fn relay_request_awaiting_ruling(
        &self,
        secp: &Secp256k1<All>,
        peer: SocketAddr,
        recipient: u16,
        request: &TaggedRequest,
    ) -> Result<http::Response, Error> {
        const MAX_ATTEMPTS: usize = 256;
        const MAX_TOTAL_WAIT: Duration = Duration::from_secs(150);

        let mut waited = Duration::ZERO;
        let mut response = self.relay_request(secp, peer, recipient, request)?;
        for _ in 1..MAX_ATTEMPTS {
            if response.status != 429 {
                break;
            }
            // Honour the server's own value rather than a guess; every in-flight site
            // sends the fixed 1s, and the floor keeps a malformed body from spinning.
            // The body is the node's, so it is parsed as untrusted: the ceiling below
            // uses `saturating_add`, or a value near `u64::MAX` would panic the harness
            // in `Duration`'s `Add` instead of failing its caller.
            let wait = serde_json::from_str::<Value>(&response.body)
                .ok()
                .and_then(|body| body.get("retry_after_secs").and_then(Value::as_u64))
                .map_or(Duration::from_secs(1), |secs| {
                    Duration::from_secs(secs.max(1))
                });
            if waited.saturating_add(wait) > MAX_TOTAL_WAIT {
                break;
            }
            std::thread::sleep(wait);
            waited += wait;
            response = self.relay_request(secp, peer, recipient, request)?;
        }
        Ok(response)
    }

    /// Push one partial payload as this compromised signer. The live harness uses
    /// this to give an honest daemon a complete candidate quorum before fire, so the
    /// daemon's Armed combine/broadcast gates are exercised rather than passing only
    /// because its local candidate never had enough peer shares.
    pub(crate) fn relay_partial(
        &self,
        secp: &Secp256k1<All>,
        peer: SocketAddr,
        recipient: u16,
        partial: &Value,
    ) -> Result<http::Response, Error> {
        let payload = serde_json::to_vec(partial)?;
        self.send(secp, peer, MSG_TYPE_PARTIAL, &payload, recipient)
    }
}

impl Drop for CompromisedNode {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        // Unblock the accept loop so the thread observes the flag and exits.
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, self.port));
        let _ = TcpStream::connect_timeout(&addr, Duration::from_millis(100));
    }
}

// ---------------------------------------------------------------------------
// What the adversary sees

/// Everything honest nodes pushed to the adversary's identities.
///
/// The counts here are the harness's primary evidence. In particular
/// [`Wiretap::honest_partials_for`] is the releasable-partial count for a
/// commitment: a partial in this table is one the adversary HAS and can combine.
pub(crate) struct Wiretap {
    inner: Mutex<WiretapInner>,
    wallet_id: [u8; 32],
    manifest_hash: [u8; 32],
    recipient_node_id: u16,
    /// Endorsed channel keys in canonical `node_id` order. Relay evidence is counted
    /// only after the envelope signature proves which member sent it.
    channel_pubkeys: Vec<PublicKey>,
}

#[derive(Default)]
struct WiretapInner {
    /// `commitment_id -> set of honest signer node_ids whose partial we hold`.
    partials: HashMap<String, Vec<PartialSeen>>,
    /// Every `request` envelope relayed to us, by the sender that relayed it.
    requests: Vec<RequestSeen>,
    /// Envelopes we could not PARSE — counted so a scenario can tell "nothing was
    /// sent" from "something was sent and we mis-read it".
    ///
    /// Authentication failures land here too. The harness counts distinct request
    /// senders as proof of processing, so trusting an unsigned `sender_node_id` would
    /// let one malformed local POST impersonate the whole honest set. A zero partial
    /// count is evidence only while every received envelope both decoded and proved
    /// its manifest identity.
    undecoded: usize,
}

#[derive(Clone, Debug)]
pub(crate) struct PartialSeen {
    pub(crate) commitment_id: String,
    pub(crate) wallet_id: [u8; 32],
    pub(crate) txid: Txid,
    pub(crate) signer_node_id: u16,
    pub(crate) sender_node_id: u16,
    pub(crate) input: u32,
    pub(crate) sighash_type: u32,
    pub(crate) spend_purpose: String,
    pub(crate) user_sig_hash: [u8; 32],
    pub(crate) partial_sig: Signature,
}

impl PartialSeen {
    /// One line of evidence for a failure message. A coupling break is the most
    /// serious thing this harness can report, so it names exactly which signature
    /// on which input of which candidate reached the adversary.
    pub(crate) fn describe(&self) -> String {
        format!(
            "signer node_id {} sent input {} of {} ({}) via node_id {}",
            self.signer_node_id,
            self.input,
            self.commitment_id,
            self.spend_purpose,
            self.sender_node_id
        )
    }
}

#[derive(Clone, Debug)]
pub(crate) struct RequestSeen {
    pub(crate) sender_node_id: u16,
    pub(crate) nonce: String,
}

impl Wiretap {
    fn new(
        wallet_id: [u8; 32],
        manifest_hash: [u8; 32],
        recipient_node_id: u16,
        channel_pubkeys: &[PublicKey],
    ) -> Wiretap {
        Wiretap {
            inner: Mutex::new(WiretapInner::default()),
            wallet_id,
            manifest_hash,
            recipient_node_id,
            channel_pubkeys: channel_pubkeys.to_vec(),
        }
    }

    /// Every partial the adversary RECEIVED for `commitment_id`, in arrival order.
    ///
    /// Not deduplicated: an honest node retries a send whose transport failed, so
    /// the same (signer, input) can legitimately appear more than once. Callers that
    /// need distinct signers use [`Wiretap::honest_signers_for`], which dedupes;
    /// callers that need "did anything leak" only ever test emptiness. Honest
    /// signers only — the adversary's own nodes never push to themselves.
    pub(crate) fn honest_partials_for(&self, commitment_id: &str) -> Vec<PartialSeen> {
        self.inner
            .lock()
            .expect("wiretap lock poisoned")
            .partials
            .get(commitment_id)
            .cloned()
            .unwrap_or_default()
    }

    /// The distinct honest nodes that released ANY partial for `commitment_id`.
    /// This is the number ADR-0012's coupling bounds: it must stay at zero for a
    /// coerced candidate, leaving the adversary with only its own `t−1`.
    pub(crate) fn honest_signers_for(&self, commitment_id: &str) -> Vec<u16> {
        let mut signers: Vec<u16> = self
            .honest_partials_for(commitment_id)
            .into_iter()
            .map(|p| p.signer_node_id)
            .collect();
        signers.sort_unstable();
        signers.dedup();
        signers
    }

    /// Every commitment for which the adversary holds at least one honest partial.
    pub(crate) fn commitments_with_partials(&self) -> Vec<String> {
        let mut ids: Vec<String> = self
            .inner
            .lock()
            .expect("wiretap lock poisoned")
            .partials
            .keys()
            .cloned()
            .collect();
        ids.sort();
        ids
    }

    /// The distinct honest nodes that relayed a request carrying `nonce` — i.e.
    /// the nodes that provably RECEIVED and PROCESSED that carrier, since a node
    /// propagates only after processing (ADR-0012 §0).
    pub(crate) fn relayers_of(&self, nonce: &str) -> Vec<u16> {
        let inner = self.inner.lock().expect("wiretap lock poisoned");
        let mut senders: Vec<u16> = inner
            .requests
            .iter()
            .filter(|r| r.nonce == nonce)
            .map(|r| r.sender_node_id)
            .collect();
        senders.sort_unstable();
        senders.dedup();
        senders
    }

    pub(crate) fn undecoded(&self) -> usize {
        self.inner.lock().expect("wiretap lock poisoned").undecoded
    }

    /// Account for a connection whose bytes could not be read at all. Same bucket as
    /// a malformed envelope, and for the same reason: the adversary knows something
    /// was sent and cannot say what, which is exactly the state in which an
    /// absence-based count stops being evidence.
    fn record_unreadable(&self) {
        self.inner.lock().expect("wiretap lock poisoned").undecoded += 1;
    }

    fn authenticate(&self, envelope: &Value) -> Result<(u16, String, Vec<u8>), Error> {
        let Some(msg_type) = envelope.get("msg_type").and_then(Value::as_str) else {
            return Err("channel envelope has no msg_type".into());
        };
        let Some(protocol_version) = envelope
            .get("protocol_version")
            .and_then(Value::as_u64)
            .and_then(|v| u32::try_from(v).ok())
        else {
            return Err("channel envelope has no valid protocol_version".into());
        };
        let wallet_id = from_hex_32(
            envelope
                .get("wallet_id")
                .and_then(Value::as_str)
                .ok_or("channel envelope has no wallet_id")?,
        )?;
        let manifest_hash = from_hex_32(
            envelope
                .get("manifest_hash")
                .and_then(Value::as_str)
                .ok_or("channel envelope has no manifest_hash")?,
        )?;
        let Some(sender) = envelope
            .get("sender_node_id")
            .and_then(Value::as_u64)
            .and_then(|v| u16::try_from(v).ok())
        else {
            return Err("channel envelope has no valid sender_node_id".into());
        };
        let Some(recipient) = envelope
            .get("recipient_node_id")
            .and_then(Value::as_u64)
            .and_then(|v| u16::try_from(v).ok())
        else {
            return Err("channel envelope has no valid recipient_node_id".into());
        };
        let payload_b64 = envelope
            .get("payload_b64")
            .and_then(Value::as_str)
            .ok_or("channel envelope has no payload_b64")?;
        let nonce = from_hex_16(
            envelope
                .get("nonce")
                .and_then(Value::as_str)
                .ok_or("channel envelope has no nonce")?,
        )?;
        let timestamp = envelope
            .get("timestamp")
            .and_then(Value::as_u64)
            .ok_or("channel envelope has no timestamp")?;
        let channel_sig = envelope
            .get("channel_sig")
            .and_then(Value::as_str)
            .ok_or("channel envelope has no channel_sig")?;

        if protocol_version != PROTOCOL_VERSION_V0 {
            return Err("channel envelope has the wrong protocol version".into());
        }
        if wallet_id != self.wallet_id {
            return Err("channel envelope has the wrong wallet".into());
        }
        if manifest_hash != self.manifest_hash {
            return Err("channel envelope has the wrong manifest".into());
        }
        if recipient != self.recipient_node_id {
            return Err("channel envelope has the wrong recipient".into());
        }
        if sender == recipient {
            return Err("channel envelope names its recipient as sender".into());
        }
        let sender_pubkey = self
            .channel_pubkeys
            .get(sender as usize)
            .ok_or("channel envelope names a sender outside the manifest")?;
        let signature = Signature::from_der(&Vec::<u8>::from_hex(channel_sig)?)?;
        let preimage = envelope_preimage(
            msg_type,
            protocol_version,
            &wallet_id,
            &manifest_hash,
            sender,
            recipient,
            payload_b64.as_bytes(),
            &nonce,
            timestamp,
        );
        Secp256k1::verification_only().verify_ecdsa(
            &Message::from_digest(tagged_hash(ENVELOPE_TAG, &preimage)),
            &signature,
            &sender_pubkey.inner,
        )?;
        let payload = STANDARD.decode(payload_b64)?;
        Ok((sender, msg_type.to_string(), payload))
    }

    fn record(&self, envelope: &Value) {
        let (sender, msg_type, payload) = match self.authenticate(envelope) {
            Ok(authenticated) => authenticated,
            Err(_) => {
                self.record_unreadable();
                return;
            }
        };
        let mut inner = self.inner.lock().expect("wiretap lock poisoned");
        match msg_type.as_str() {
            // Every field below is decoded STRICTLY. Defaulting a missing or
            // wrong-typed field would silently file a leaked partial under the empty
            // commitment id — invisible to `spend_partials_outside`, and counted
            // nowhere. Since every coupling assertion in the harness is an argument
            // from absence ("no honest partial for this commitment reached the
            // adversary"), a malformed partial that decodes to a blank record is
            // precisely a leak that reads as safety. It must land in `undecoded`,
            // which the scenarios assert is zero.
            MSG_TYPE_PARTIAL => match serde_json::from_slice::<Value>(&payload) {
                Ok(p) => {
                    let fields = (
                        p.get("commitment_id").and_then(Value::as_str),
                        p.get("wallet_id").and_then(Value::as_str),
                        p.get("txid").and_then(Value::as_str),
                        p.get("signer_node_id").and_then(Value::as_u64),
                        p.get("input").and_then(Value::as_u64),
                        p.get("sighash_type").and_then(Value::as_u64),
                        p.get("spend_purpose").and_then(Value::as_str),
                        p.get("user_sig_hash").and_then(Value::as_str),
                        p.get("partial_sig").and_then(Value::as_str),
                    );
                    let (
                        Some(commitment_id),
                        Some(wallet_id),
                        Some(txid),
                        Some(signer_node_id),
                        Some(input),
                        Some(sighash_type),
                        Some(spend_purpose),
                        Some(user_sig_hash),
                        Some(partial_sig),
                    ) = fields
                    else {
                        inner.undecoded += 1;
                        return;
                    };
                    let decoded = (
                        from_hex_32(wallet_id),
                        Txid::from_str(txid).map_err(|e| e.to_string()),
                        u16::try_from(signer_node_id).map_err(|e| e.to_string()),
                        u32::try_from(input).map_err(|e| e.to_string()),
                        u32::try_from(sighash_type).map_err(|e| e.to_string()),
                        from_hex_32(user_sig_hash),
                        Vec::<u8>::from_hex(partial_sig)
                            .map_err(|e| e.to_string())
                            .and_then(|der| Signature::from_der(&der).map_err(|e| e.to_string())),
                    );
                    let (
                        Ok(wallet_id),
                        Ok(txid),
                        Ok(signer_node_id),
                        Ok(input),
                        Ok(sighash_type),
                        Ok(user_sig_hash),
                        Ok(partial_sig),
                    ) = decoded
                    else {
                        inner.undecoded += 1;
                        return;
                    };
                    let seen = PartialSeen {
                        commitment_id: commitment_id.to_string(),
                        wallet_id,
                        txid,
                        signer_node_id,
                        sender_node_id: sender,
                        input,
                        sighash_type,
                        spend_purpose: spend_purpose.to_string(),
                        user_sig_hash,
                        partial_sig,
                    };
                    inner
                        .partials
                        .entry(commitment_id.to_string())
                        .or_default()
                        .push(seen);
                }
                Err(_) => inner.undecoded += 1,
            },
            MSG_TYPE_REQUEST => match serde_json::from_slice::<Value>(&payload) {
                Ok(r) => {
                    // The tagged request is `{"spend":{…}}` or `{"refresh":{…}}`;
                    // either way the coordinator nonce identifies the carrier. A
                    // request whose nonce is missing cannot be attributed to a
                    // carrier, so it is undecoded rather than a blank relay record —
                    // `relayers_of` is what the coupling scenarios count.
                    let nonce = r
                        .get("spend")
                        .or_else(|| r.get("refresh"))
                        .and_then(|body| body.get("nonce"))
                        .and_then(Value::as_str);
                    let Some(nonce) = nonce else {
                        inner.undecoded += 1;
                        return;
                    };
                    inner.requests.push(RequestSeen {
                        sender_node_id: sender,
                        nonce: nonce.to_string(),
                    });
                }
                Err(_) => inner.undecoded += 1,
            },
            _ => inner.undecoded += 1,
        }
    }
}

// ---------------------------------------------------------------------------
// The listener

/// Stand up a minimal `/channel` endpoint on `port` that accepts everything and
/// records it. Hand-rolled over `std::net` to match `http.rs` — the adversary
/// needs one route and no concurrency beyond "do not drop a peer's send".
fn spawn_listener(
    port: u16,
    wiretap: Arc<Wiretap>,
    shutdown: Arc<AtomicBool>,
    alive: Arc<AtomicBool>,
    active_handlers: Arc<AtomicUsize>,
) -> Result<(), Error> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port))
        .map_err(|e| format!("compromised node cannot bind 127.0.0.1:{port}: {e}"))?;
    std::thread::spawn(move || {
        // Clearing `alive` on the way OUT — including on unwind — is what makes a
        // dead listener loud. The per-connection `std::thread::spawn` below panics
        // rather than returning an error if the OS refuses a thread, and without
        // this guard that panic would unwind the accept loop silently: the port
        // stops answering, every later `honest_partials_for` returns empty, and
        // `undecoded` stays at zero. A wiretap that hears nothing because it is
        // deaf must never be indistinguishable from one that heard nothing because
        // nothing was sent.
        let _alive = AliveUntilDropped(alive);
        for stream in listener.incoming() {
            if shutdown.load(Ordering::SeqCst) {
                return;
            }
            let stream = match stream {
                Ok(stream) => stream,
                Err(_) => {
                    // A failed `accept` is a connection an honest node opened and
                    // this listener never read — indistinguishable, from the
                    // outside, from a peer that pushed a partial on it. Skipping it
                    // silently would leave `alive` set and `undecoded` at zero, so a
                    // port that is failing every accept would report the same clean
                    // zero as a port nobody sent to. Account for it exactly as an
                    // unreadable body is accounted for, so `assert_wiretap_decoded`
                    // refuses the absence argument instead of blessing it.
                    wiretap.record_unreadable();
                    continue;
                }
            };
            let wiretap = Arc::clone(&wiretap);
            let active = ActiveHandler::new(Arc::clone(&active_handlers));
            // One thread per connection: an honest node fans out to all peers
            // concurrently and blocks on a per-send deadline, so serializing here
            // would inject latency into the very timing the probe scenario measures.
            // `serve_one` accounts for everything it reads before it can fail, so a
            // discarded error here cannot hide a send (see its doc comment).
            std::thread::spawn(move || {
                let _active = active;
                let _ = serve_one(stream, &wiretap);
            });
        }
    });
    Ok(())
}

/// Clears the liveness flag when the accept loop leaves, however it leaves.
struct AliveUntilDropped(Arc<AtomicBool>);

impl Drop for AliveUntilDropped {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

/// Counts one accepted connection until its decoder leaves, including through an
/// unwind. Constructed before `spawn` so a spawn panic also rolls the count back.
struct ActiveHandler(Arc<AtomicUsize>);

impl ActiveHandler {
    fn new(active: Arc<AtomicUsize>) -> ActiveHandler {
        active.fetch_add(1, Ordering::SeqCst);
        ActiveHandler(active)
    }
}

impl Drop for ActiveHandler {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Read one HTTP request body off `stream`, or `None` if the peer sent nothing at
/// all. Headers first, then exactly `Content-Length` body bytes: the peer sets
/// `Connection: close`, but waiting for EOF would hold its per-send deadline open
/// for no reason.
fn read_channel_body(stream: &mut TcpStream) -> Result<Option<Vec<u8>>, Error> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    let mut raw = Vec::new();
    let mut buf = [0u8; 8192];
    let body_start = loop {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            break None;
        }
        raw.extend_from_slice(&buf[..n]);
        if let Some(split) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break Some(split + 4);
        }
        if raw.len() > 8 * 1024 * 1024 {
            break None;
        }
    };
    let Some(body_start) = body_start else {
        // Either no bytes at all (the `Drop` poke) or a header block so large it was
        // abandoned. Neither is a decodable send, and the first is routine.
        return Ok(if raw.is_empty() {
            None
        } else {
            Some(Vec::new())
        });
    };
    let head = String::from_utf8_lossy(&raw[..body_start]).to_lowercase();
    let content_length: usize = head
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0);
    while raw.len() - body_start < content_length {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            break;
        }
        raw.extend_from_slice(&buf[..n]);
    }
    Ok(Some(raw[body_start..].to_vec()))
}

/// Serve one `/channel` connection, accounting for it exactly once.
///
/// The accounting is the delicate part. Every coupling assertion in the harness is
/// an argument from absence, so a send this listener FAILED to read must not be
/// indistinguishable from no send at all — otherwise a leaked partial on a
/// connection that then broke would read as safety, the one failure mode that must
/// never be silent. So a read failure is recorded as `undecoded` HERE, before the
/// error propagates, and the caller is free to discard the error. A connection that
/// carried no bytes at all is a different thing and is deliberately not counted:
/// `Drop` pokes each listener with an empty connection to unblock its accept loop.
fn serve_one(mut stream: TcpStream, wiretap: &Wiretap) -> Result<(), Error> {
    let body = match read_channel_body(&mut stream) {
        Ok(None) => return Ok(()),
        Ok(Some(body)) => body,
        Err(e) => {
            wiretap.record_unreadable();
            return Err(e);
        }
    };
    let envelope = serde_json::from_slice::<Value>(&body);
    let barrier = envelope.as_ref().ok().and_then(|value| {
        let object = value.as_object()?;
        if object.len() != 1 {
            return None;
        }
        object
            .get(WIRETAP_BARRIER_FIELD)
            .and_then(Value::as_str)
            .map(str::to_owned)
    });
    let response_body = if let Some(token) = barrier {
        serde_json::to_vec(&json!({ WIRETAP_BARRIER_FIELD: token }))?
    } else if let Ok(envelope) = envelope {
        wiretap.record(&envelope);
        br#"{"status":"ACCEPTED"}"#.to_vec()
    } else {
        wiretap.record(&Value::Null);
        br#"{"status":"ACCEPTED"}"#.to_vec()
    };
    // Answer exactly what a healthy node answers, so the honest peer's fan-out
    // completes rather than retrying — a retrying peer would distort the timing
    // observables the silence probe measures.
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response_body.len()
    );
    stream.write_all(response.as_bytes())?;
    stream.write_all(&response_body)?;
    stream.flush()?;
    Ok(())
}
