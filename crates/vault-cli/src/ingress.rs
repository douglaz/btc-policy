//! The stage-1 federation ingress client (bead btc-policy-mby-sealed-vault-ingress-s7u).
//!
//! Given ONE already-formed coordinator-authenticated request it serializes once and offers the
//! EXACT same signed body — same nonce, same signature — to each manifest-pinned loopback
//! endpoint in node/endpoint order (only the per-endpoint `Host` header differs), keeping one
//! sticky disposition over the typed transport phases of [`http::Attempt`]. No error-string
//! matching, no RPC escape hatch, no user or coordinator secret, no PIN, no broadcast path.
//! Each attempt also leaves one typed [`EndpointFact`] so an all-down federation is still
//! diagnosable; those facts are written from the typed outcome and never read back.
//!
//! **No outcome here is quorum or final-success evidence.** At loop end
//! [`Delivery::PossiblyDeliveredExact`] starts M4's conservative Core watch, and only that
//! Core observation decides whether a command succeeded. btc-policy-imb owns confidential
//! authenticated transport from stage 2 onward.

use std::net::SocketAddr;
use std::time::Duration;

use vault_proto::{Accepted, RefusalCode, SignResponse, TaggedRequest};

use crate::http::{self, Attempt, Error};

/// Whether this exact request may already have reached a node. Sticky: it never moves
/// backward, because "not sent" is the claim that authorizes reissuing a command, and a
/// wrong one is a double submission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Delivery {
    /// No signable command was accepted or staged. NOT a claim that nothing reached a
    /// node: before answering 400 one may consume a coordinator nonce and record the
    /// spend arm's per-carrier intent — bookkeeping no `stage`/`confirm` can resolve.
    /// That is why a NEW logical retry re-signs with a fresh nonce, not this one.
    DefinitelyNotSent,
    PossiblyDeliveredExact,
}

/// What the endpoint loop observed: the sticky disposition, one typed fact per
/// attempt, and — when a node accepted — that node's complete acknowledgement
/// (M5 depends on the payload).
pub(crate) struct Ingress {
    pub(crate) delivery: Delivery,
    pub(crate) accepted: Option<Accepted>,
    /// In attempt order, so an all-down federation still reports WHICH endpoint
    /// failed and HOW. Reporting only: nothing here is read back below.
    pub(crate) attempts: Vec<EndpointFact>,
}

/// One attempt as a typed fact, derived from the typed outcome and never consulted
/// again. It carries no response body and therefore no refusal detail, no PIN and no
/// key material — only the address and the phase or status that address reached.
#[derive(Debug)]
pub(crate) struct EndpointFact {
    pub(crate) endpoint: SocketAddr,
    pub(crate) outcome: Outcome,
}

/// The transport phase or HTTP status one attempt reached. The two error variants
/// carry the transport's OWN message (address plus errno); a peer's bytes do not.
#[derive(Debug)]
pub(crate) enum Outcome {
    NotSent(String),
    NoStatus(String),
    Status(u16),
}

/// Offer `request` to `endpoints` in order, stopping on `Accepted`, on HTTP 413,
/// or on a `NONCE_REPLAYED` that follows a possible delivery of this same request.
pub(crate) fn deliver(
    endpoints: &[SocketAddr],
    request: &TaggedRequest,
    timeout: Duration,
) -> Result<Ingress, Error> {
    // Serialized ONCE: every endpoint gets byte-identical bytes, so a node that
    // accepts and a node that never answers are answering about the same request.
    let body = crate::fed::encode_request(request)?;
    let mut delivery = Delivery::DefinitelyNotSent;
    let mut accepted = None;
    let mut attempts = Vec::new();
    for addr in endpoints {
        // The disposition BEFORE this attempt: a replay stops only when an EARLIER
        // attempt already made this exact request possibly delivered.
        let prior = delivery;
        let attempt = http::post_json_attempt(*addr, "/sign", &body, timeout);
        // Recorded from the TYPED outcome, then never read back: every arm below
        // decides on `attempt` itself, so no diagnostic can move a transition.
        attempts.push(EndpointFact {
            endpoint: *addr,
            outcome: match &attempt {
                Attempt::NotSent(e) => Outcome::NotSent(e.to_string()),
                Attempt::NoStatus(e) => Outcome::NoStatus(e.to_string()),
                Attempt::Status { status, .. } => Outcome::Status(*status),
            },
        });
        match attempt {
            // Nothing was written, so this endpoint decides nothing.
            Attempt::NotSent(_) => continue,
            // A write may have happened and no status came back.
            Attempt::NoStatus(_) => delivery = Delivery::PossiblyDeliveredExact,
            // Explicit no-delivery for this endpoint, body read or not.
            Attempt::Status { status: 400, .. } => continue,
            // Oversized for the 1 MiB transport cap every node compiles in (the
            // manifest cap answers 400), so stop — an earlier delivery still stands.
            Attempt::Status { status: 413, .. } => break,
            Attempt::Status {
                status: 200,
                body: answer,
            } => {
                delivery = Delivery::PossiblyDeliveredExact;
                match answer.as_deref().map(serde_json::from_str::<SignResponse>) {
                    Some(Ok(SignResponse::Accepted(ack))) => {
                        accepted = Some(ack);
                        break;
                    }
                    // The ONE refusal code with a transport meaning: it proves a nonce was
                    // consumed, never by WHICH body. After a possible delivery of this request
                    // that is most likely ours, so stop; on a first attempt it is someone else's
                    // and the loop goes on. No other refusal is read here: some node-local
                    // refusals still stage and propagate while federation-uniform ones do not,
                    // so an incomplete taxonomy would act on that difference wrongly.
                    Some(Ok(SignResponse::Refusal(refusal)))
                        if refusal.code == RefusalCode::NonceReplayed
                            && prior == Delivery::PossiblyDeliveredExact =>
                    {
                        break
                    }
                    _ => {}
                }
            }
            // 408, 5xx and any other unexpected status: the body may have been read.
            Attempt::Status { .. } => delivery = Delivery::PossiblyDeliveredExact,
        }
    }
    Ok(Ingress {
        delivery,
        accepted,
        attempts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::Secp256k1;
    use std::io::{Read, Write};
    use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
    use std::sync::{Arc, Mutex};
    use vault_proto::SignRequest;

    const WAIT: Duration = Duration::from_secs(5);

    /// Port 0 is unassignable, so the kernel refuses a connect to it immediately and
    /// deterministically. That is what `gone` uses instead of binding an ephemeral port
    /// and dropping it: nothing is reserved, so nothing races a parallel test for it.
    const REFUSED: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

    /// The canned reply a script tag stands for, as the exact bytes a node writes.
    /// `hangup` reads the request and closes without a status line; anything else is
    /// a status. `gone` never reaches here — it is [`REFUSED`], with no responder.
    fn canned(tag: &str) -> String {
        let ok = |body: &str| format!("HTTP/1.1 200 OK\r\n\r\n{body}");
        let refusal = |code: &str| {
            ok(&format!(
                "{{\"refusal\":{{\"code\":\"{code}\",\"check\":\"x\",\"detail\":\"y\"}}}}"
            ))
        };
        match tag {
            "hangup" => String::new(),
            "accepted" => ok(
                "{\"accepted\":{\"commitment_id\":\"c0d3\",\"first_seen\":7,\"remaining_secs\":11}}",
            ),
            "garbage" => ok("not json"),
            "refusal" => refusal("DEST_NOT_ALLOWED"),
            "capacity" => refusal("COORD_NONCE_CAPACITY"),
            "replayed" => refusal("NONCE_REPLAYED"),
            "400-truncated" => "HTTP/1.1 400 Bad Request\r\n".into(),
            status => format!("HTTP/1.1 {status}\r\n\r\n"),
        }
    }

    /// Read one HTTP request and return its BODY, so byte identity is compared
    /// over the signed bytes and not the per-address `Host` header.
    fn read_request(stream: &mut TcpStream) -> Vec<u8> {
        let (mut head, mut byte) = (Vec::new(), [0u8; 1]);
        while !head.ends_with(b"\r\n\r\n") {
            if stream.read(&mut byte).unwrap_or(0) == 0 {
                return Vec::new();
            }
            head.extend_from_slice(&byte);
        }
        let text = String::from_utf8_lossy(&head).to_lowercase();
        let len = text
            .split("content-length:")
            .nth(1)
            .and_then(|rest| rest.split("\r\n").next())
            .and_then(|value| value.trim().parse().ok())
            .unwrap_or(0);
        let mut body = vec![0u8; len];
        stream
            .read_exact(&mut body)
            .map(|()| body)
            .unwrap_or_default()
    }

    /// The exact request body each canned responder saw.
    type Seen = Arc<Mutex<Vec<Vec<u8>>>>;

    /// One canned responder per script tag, in order.
    fn federation(script: &[&str]) -> (Vec<SocketAddr>, Seen) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let mut endpoints = Vec::new();
        for tag in script {
            if *tag == "gone" {
                endpoints.push(REFUSED);
                continue;
            }
            let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
            endpoints.push(listener.local_addr().expect("addr"));
            let reply = canned(tag);
            let seen = Arc::clone(&seen);
            std::thread::spawn(move || {
                if let Ok((mut stream, _)) = listener.accept() {
                    let body = read_request(&mut stream);
                    seen.lock().expect("lock").push(body);
                    let _ = stream.write_all(reply.as_bytes());
                }
            });
        }
        (endpoints, seen)
    }

    /// ONE already-formed coordinator-authenticated request. Its nonce is the
    /// existing 32-byte `/dev/urandom` draw; the client never re-signs.
    fn signed_request() -> TaggedRequest {
        let secp = Secp256k1::new();
        let mut urandom = std::fs::File::open("/dev/urandom").expect("urandom");
        let coordinator =
            crate::fed::Coordinator::random(&secp, &mut urandom).expect("coordinator");
        let request = SignRequest {
            psbt: "cHNidP8BAA".into(),
            escape_psbt: "cHNidP8BAB".into(),
            escape_bumps: Vec::new(),
            pin: vault_proto::Pin::from(""),
            nonce: String::new(),
            expiry: 0,
            policy_version: 1,
            coord_sig: String::new(),
        };
        let signed = coordinator.authorize(&secp, &[7u8; 32], request);
        TaggedRequest::Spend(signed.expect("authorize"))
    }

    fn nonce_of(request: &TaggedRequest) -> String {
        match request {
            TaggedRequest::Spend(spend) => spend.nonce.clone(),
            TaggedRequest::Refresh(refresh) => refresh.nonce.clone(),
        }
    }

    /// The whole typed state machine, one row per observable. The last column — how
    /// many endpoints were actually contacted — proves a stop stops and a continue
    /// continues; the payload assertion proves an acceptance carries the full ack.
    #[rustfmt::skip]
    #[test]
    fn the_sticky_disposition_follows_the_typed_transport_phases() {
        use Delivery::{DefinitelyNotSent as NotSent, PossiblyDeliveredExact as Possibly};
        let cases: [(&str, &[&str], Delivery, bool, usize); 15] = [
            ("connect refused, then a 400",            &["gone", "400 Bad"],                          NotSent,  false, 1),
            ("HTTP 400 is explicit no-delivery",       &["400 Bad", "400 Bad"],                       NotSent,  false, 2),
            ("a 400 whose body read fails",            &["400-truncated", "400 Bad"],                 NotSent,  false, 2),
            ("an ambiguous write/read, then a 400",    &["hangup", "400 Bad"],                        Possibly, false, 2),
            ("an HTTP 200 refusal",                    &["refusal", "400 Bad"],                       Possibly, false, 2),
            ("HTTP 408",                               &["408 Timeout", "400 Bad"],                   Possibly, false, 2),
            ("HTTP 5xx",                               &["503 Unavailable", "400 Bad"],               Possibly, false, 2),
            ("an unexpected non-5xx status",           &["418 Teapot", "400 Bad"],                    Possibly, false, 2),
            ("an unparseable 200 body",                &["garbage", "400 Bad"],                       Possibly, false, 2),
            ("Accepted stops",                         &["accepted", "refusal"],                      Possibly, true,  1),
            ("413 stops, inventing no delivery",       &["400 Bad", "413 Large", "accepted"],         NotSent,  false, 2),
            ("413 cannot erase a possible delivery",   &["503 Unavailable", "413 Large", "accepted"], Possibly, false, 2),
            ("pre-staging capacity, then Accepted",    &["capacity", "accepted"],                     Possibly, true,  2),
            ("a refusal, then a peer's replay, stops", &["refusal", "replayed", "accepted"],          Possibly, false, 2),
            ("a first-attempt replay continues",       &["replayed", "accepted"],                     Possibly, true,  2),
        ];
        for (name, script, delivery, payload, contacted) in cases {
            let (endpoints, seen) = federation(script);
            let out = deliver(&endpoints, &signed_request(), WAIT).expect(name);
            assert_eq!(out.delivery, delivery, "{name}: disposition");
            assert_eq!(out.accepted.is_some(), payload, "{name}: payload");
            assert_eq!(seen.lock().expect("lock").len(), contacted, "{name}: contacted");
            if let Some(ack) = out.accepted {
                assert_eq!(ack.commitment_id, "c0d3", "{name}");
                assert_eq!((ack.first_seen, ack.remaining_secs), (7, 11), "{name}");
            }
        }
    }

    /// Failover reuses the EXACT signed bytes, and one logical command draws
    /// exactly one 32-byte OS-CSPRNG nonce; a NEW logical request draws another.
    #[test]
    fn every_attempt_is_byte_identical_and_one_command_draws_one_nonce() {
        let (endpoints, seen) = federation(&["refusal", "503 Unavailable", "accepted"]);
        let request = signed_request();
        deliver(&endpoints, &request, WAIT).expect("deliver");
        let bodies = seen.lock().expect("lock").clone();
        assert_eq!(bodies.len(), 3);
        assert!(
            bodies.windows(2).all(|pair| pair[0] == pair[1]),
            "same-command failover must offer byte-identical bodies"
        );
        let nonce = nonce_of(&request);
        assert_eq!(nonce.len(), 64, "one 32-byte nonce, lowercase hex");
        for body in &bodies {
            let text = String::from_utf8_lossy(body);
            assert_eq!(text.matches(&nonce).count(), 1, "one nonce per command");
        }
        assert_ne!(
            nonce,
            nonce_of(&signed_request()),
            "a new logical retry re-signs"
        );
    }

    /// An all-down federation still reports WHICH endpoint failed and HOW, per attempt and
    /// in order, while the disposition stays the one that authorizes a reissue. The facts
    /// carry no peer bytes: the refusal detail every responder here writes (`"check":"x"`,
    /// `"detail":"y"`) and the request's own nonce are absent from all of them.
    #[test]
    fn every_attempt_leaves_an_endpoint_fact_that_carries_no_peer_bytes() {
        let (down, _) = federation(&["gone", "gone"]);
        let out = deliver(&down, &signed_request(), WAIT).expect("deliver");
        assert_eq!(out.delivery, Delivery::DefinitelyNotSent);
        let addresses: Vec<SocketAddr> = out.attempts.iter().map(|f| f.endpoint).collect();
        assert_eq!(addresses, down, "one fact per endpoint, in attempt order");
        for fact in &out.attempts {
            let Outcome::NotSent(detail) = &fact.outcome else {
                panic!("a refused connect is NotSent, not {:?}", fact.outcome);
            };
            assert!(detail.contains(&fact.endpoint.to_string()), "{detail}");
        }

        let (endpoints, _) = federation(&["hangup", "refusal", "503 Up", "400 Bad", "accepted"]);
        let request = signed_request();
        let out = deliver(&endpoints, &request, WAIT).expect("deliver");
        let Outcome::NoStatus(why) = &out.attempts[0].outcome else {
            panic!("a hangup after the write is NoStatus")
        };
        assert!(why.contains(&out.attempts[0].endpoint.to_string()), "{why}");
        let statuses: Vec<u16> = out.attempts[1..]
            .iter()
            .map(|f| match &f.outcome {
                Outcome::Status(status) => *status,
                other => panic!("expected a status, got {other:?}"),
            })
            .collect();
        assert_eq!(statuses, [200, 503, 400, 200], "one fact per attempt");
        let nonce = nonce_of(&request);
        for fact in &out.attempts {
            let text = format!("{fact:?}");
            for absent in [nonce.as_str(), "\"detail\"", "DEST_NOT_ALLOWED"] {
                assert!(!text.contains(absent), "{text} retained {absent}");
            }
        }
    }

    /// Structural separation: the production half NAMES no broadcast surface, no key type,
    /// no PIN — neither `Pin` nor the `pin` field of the `TaggedRequest` it relays as opaque
    /// bytes — and no `Coordinator`/`authorize`, the pair that would let it MINT its own
    /// authority. `sealed`/`LiveVault` are banned for COUPLING, not custody: the policy half
    /// holds no secret, but a relay reaching it by any name grows a second trust hierarchy.
    #[test]
    fn the_client_holds_no_key_and_cannot_broadcast() {
        let source = include_str!("ingress.rs");
        let code: Vec<&str> = source
            .split("#[cfg(test)]")
            .next()
            .unwrap_or(source)
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect();
        let code = code.join("\n");
        let banned = "sendrawtransaction broadcast SecretKey seckey sign_ecdsa Pin pin \
                      coordinator Coordinator authorize LiveVault sealed";
        for name in banned.split_whitespace() {
            assert!(!code.contains(name), "the client must not name {name}");
        }
    }
}
