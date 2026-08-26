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

use vault_proto::{Accepted, RefusalCode, TaggedRequest};

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

/// The MINIMAL view of a `/sign` answer: the two numbers an acknowledgement is built
/// from, the peer's commitment string BORROWED from the bounded zeroizing response
/// bytes, and the one refusal field with a transport meaning. A refusal's `check` and
/// `detail` are skipped, so no peer-chosen text — one echoing the operator's typed
/// secret above all — is ever allocated, retained or printed here. Serde may use
/// non-zeroizing scratch while skipping an escaped string; that documented library
/// residual reaches no fact, acknowledgement or output below. A commitment string
/// spelled with escapes fails to borrow and is therefore a non-acceptance that
/// continues the loop, never an acceptance.
#[derive(serde::Deserialize)]
enum Answer<'a> {
    #[serde(rename = "accepted")]
    Accepted {
        #[serde(borrow)]
        commitment_id: &'a str,
        first_seen: u64,
        remaining_secs: u64,
    },
    #[serde(rename = "refusal")]
    Refusal { code: RefusalCode },
}

/// Offer `request` to `endpoints` in order, stopping on an `Accepted` for the caller's
/// expected commitment, on HTTP 413, or on a `NONCE_REPLAYED` that follows a possible
/// delivery of this same request.
///
/// `expected_commitment_id` is the caller's OWN id for these exact request bytes,
/// computed and passed in by M4; nothing here derives it from the request, and only
/// this local string can ever be retained.
pub(crate) fn deliver(
    endpoints: &[SocketAddr],
    request: &TaggedRequest,
    expected_commitment_id: &str,
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
        let attempt =
            http::post_attempt(*addr, "/sign", &body, None, http::Policy::ingress(timeout));
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
                match answer.as_deref().map(|bytes| serde_json::from_slice(bytes)) {
                    Some(Ok(Answer::Accepted {
                        commitment_id,
                        first_seen,
                        remaining_secs,
                    })) if commitment_id == expected_commitment_id => {
                        // The peer's string is compared while BORROWED from the bounded
                        // zeroizing bytes and then dropped; what is RETAINED is the
                        // caller's own id, so no endpoint can reflect text of its own
                        // choosing into an acknowledgement. A mismatch is not acceptance:
                        // it falls through, keeps this 200's possible delivery, and the
                        // loop goes on to the next endpoint.
                        accepted = Some(Accepted {
                            commitment_id: expected_commitment_id.to_owned(),
                            first_seen,
                            remaining_secs,
                        });
                        break;
                    }
                    // The ONE refusal code with a transport meaning: it proves a nonce was
                    // consumed, never by WHICH body. After a possible delivery of this request
                    // that is most likely ours, so stop; on a first attempt it is someone else's
                    // and the loop goes on. No other refusal is read here: some node-local
                    // refusals still stage and propagate while federation-uniform ones do not,
                    // so an incomplete taxonomy would act on that difference wrongly.
                    Some(Ok(Answer::Refusal { code }))
                        if code == RefusalCode::NonceReplayed
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
    use vault_proto::{Refusal, SignRequest, SignResponse};

    const WAIT: Duration = Duration::from_secs(5);

    /// Port 0 is unassignable, so the kernel refuses a connect to it immediately and
    /// deterministically. That is what `gone` uses instead of binding an ephemeral port
    /// and dropping it: nothing is reserved, so nothing races a parallel test for it.
    const REFUSED: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

    /// The commitment id the CALLER computed for these exact request bytes. Every
    /// acceptance below has to equal it, and what is retained is this string.
    const EXPECTED: &str = "c0d3";

    /// A canary shaped like the one secret an operator types. Every reflection row
    /// below puts it where a hostile endpoint would: in a refusal's `check`/`detail`
    /// and in an `Accepted`'s commitment id.
    const TYPED_SECRET: &str = "8271-typed-at-the-terminal";

    #[test]
    fn borrowed_answer_stays_in_lockstep_with_the_protocol_wire_shape() {
        let accepted = SignResponse::Accepted(Accepted {
            commitment_id: EXPECTED.into(),
            first_seen: 7,
            remaining_secs: 11,
        });
        let wire = serde_json::to_vec(&accepted).expect("serialize protocol acceptance");
        let decoded: Answer<'_> =
            serde_json::from_slice(&wire).expect("borrowed answer must decode protocol acceptance");
        match decoded {
            Answer::Accepted {
                commitment_id,
                first_seen,
                remaining_secs,
            } => assert_eq!(
                (commitment_id, first_seen, remaining_secs),
                (EXPECTED, 7, 11)
            ),
            Answer::Refusal { .. } => panic!("protocol acceptance decoded as refusal"),
        }

        let refusal = SignResponse::Refusal(Refusal {
            code: RefusalCode::NonceReplayed,
            check: TYPED_SECRET.into(),
            detail: TYPED_SECRET.into(),
        });
        let wire = serde_json::to_vec(&refusal).expect("serialize protocol refusal");
        let decoded: Answer<'_> =
            serde_json::from_slice(&wire).expect("borrowed answer must decode protocol refusal");
        match decoded {
            Answer::Refusal { code } => assert_eq!(code, RefusalCode::NonceReplayed),
            Answer::Accepted { .. } => panic!("protocol refusal decoded as acceptance"),
        }
    }

    /// The canned reply a script tag stands for, as the exact bytes a node writes.
    /// `hangup` reads the request and closes without a status line; anything else is
    /// a status. `gone` never reaches here — it is [`REFUSED`], with no responder.
    fn canned(tag: &str) -> String {
        let framed = |body: &str| {
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
        };
        let ok = |body: &str| format!("HTTP/1.1 200 OK\r\n\r\n{body}");
        let refusal = |code: &str| {
            ok(&format!(
                "{{\"refusal\":{{\"code\":\"{code}\",\"check\":\"x\",\"detail\":\"y\"}}}}"
            ))
        };
        let accepted = |id: &str| {
            format!("{{\"accepted\":{{\"commitment_id\":\"{id}\",\"first_seen\":7,\"remaining_secs\":11}}}}")
        };
        match tag {
            "hangup" => String::new(),
            "accepted" => ok(&accepted(EXPECTED)),
            // Correctly framed by a real node's rules — `Content-Length` and all — so
            // the framing path is exercised beside the EOF-only one above.
            "accepted-framed" => framed(&accepted(EXPECTED)),
            // A well-formed acceptance for SOMEONE ELSE'S commitment.
            "accepted-elsewhere" => ok(&accepted("f00d")),
            // An acceptance echoing the operator's typed secret back as the id.
            "accepted-reflecting" => ok(&accepted(TYPED_SECRET)),
            // A complete acceptance with trailing bytes: a parseable PREFIX is not a
            // framed answer, and this must not be read as one.
            "accepted-plus" => ok(&format!("{}{}", accepted(EXPECTED), "{\"more\":1}")),
            // An IMPECCABLE acceptance, padded past the 64 KiB ingress cap. The JSON is
            // exactly what a real node writes, so what refuses it is the cap and only
            // the cap: loosen that one number and this row becomes an acceptance.
            "oversize" => ok(&format!(
                "{{\"accepted\":{{\"commitment_id\":\"{EXPECTED}\",\"first_seen\":7,\
                 \"remaining_secs\":11,\"pad\":\"{}\"}}}}",
                "x".repeat(64 * 1024)
            )),
            "garbage" => ok("not json"),
            "refusal" => refusal("DEST_NOT_ALLOWED"),
            // A refusal whose peer-chosen text is the operator's typed secret.
            "refusal-reflecting" => ok(&format!(
                "{{\"refusal\":{{\"code\":\"BAD_PIN\",\"check\":\"{TYPED_SECRET}\",\
                 \"detail\":\"{TYPED_SECRET}\"}}}}"
            )),
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

    /// The gap a `drip` responder leaves between bytes, and how long it keeps that up.
    /// Every gap is comfortably inside any per-READ inactivity timeout, which is the
    /// whole point: only a deadline over the WHOLE exchange can end this endpoint.
    const DRIP_GAP: Duration = Duration::from_millis(60);
    const DRIP_FOR: Duration = Duration::from_secs(30);

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
            let dripping = *tag == "drip";
            let reply = canned(if dripping { "accepted" } else { tag });
            let seen = Arc::clone(&seen);
            std::thread::spawn(move || {
                if let Ok((mut stream, _)) = listener.accept() {
                    let body = read_request(&mut stream);
                    seen.lock().expect("lock").push(body);
                    if !dripping {
                        let _ = stream.write_all(reply.as_bytes());
                        return;
                    }
                    let started = std::time::Instant::now();
                    // One byte at a time, forever from the client's point of view: the
                    // answer is never finished and the socket is never closed.
                    while started.elapsed() < DRIP_FOR {
                        if stream.write_all(b"H").is_err() {
                            return;
                        }
                        std::thread::sleep(DRIP_GAP);
                    }
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
        let cases: [(&str, &[&str], Delivery, bool, usize); 21] = [
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
            // The bounded transport's own rows. Every one of them is a 200, so each
            // still records a possible delivery — none of them is an acceptance.
            ("a fully framed Accepted stops",          &["accepted-framed", "refusal"],               Possibly, true,  1),
            ("an Accepted for another commitment",     &["accepted-elsewhere", "400 Bad"],            Possibly, false, 2),
            ("an Accepted echoing the typed secret",   &["accepted-reflecting", "400 Bad"],           Possibly, false, 2),
            ("an Accepted with trailing bytes",        &["accepted-plus", "400 Bad"],                 Possibly, false, 2),
            ("a 200 past the 64 KiB cap",              &["oversize", "400 Bad"],                      Possibly, false, 2),
            ("a refusal whose text is the secret",     &["refusal-reflecting", "400 Bad"],            Possibly, false, 2),
        ];
        for (name, script, delivery, payload, contacted) in cases {
            let (endpoints, seen) = federation(script);
            let out = deliver(&endpoints, &signed_request(), EXPECTED, WAIT).expect(name);
            assert_eq!(out.delivery, delivery, "{name}: disposition");
            assert_eq!(out.accepted.is_some(), payload, "{name}: payload");
            assert_eq!(seen.lock().expect("lock").len(), contacted, "{name}: contacted");
            if let Some(ack) = out.accepted {
                assert_eq!(ack.commitment_id, EXPECTED, "{name}");
                assert_eq!((ack.first_seen, ack.remaining_secs), (7, 11), "{name}");
            }
        }
    }

    /// A first endpoint that DRIPS cannot suppress an honest second one. Every gap it
    /// leaves is inside a per-read inactivity timeout, so only the deadline over the
    /// whole exchange ends it — and it ends it in about one deadline, not in the thirty
    /// seconds this endpoint is prepared to keep dripping for.
    #[test]
    fn a_dripping_first_endpoint_cannot_suppress_an_honest_second() {
        let deadline = Duration::from_millis(400);
        let (endpoints, seen) = federation(&["drip", "accepted"]);
        let started = std::time::Instant::now();
        let out = deliver(&endpoints, &signed_request(), EXPECTED, deadline).expect("deliver");
        let elapsed = started.elapsed();
        let ack = out.accepted.expect("the honest endpoint must be reached");
        assert_eq!(ack.commitment_id, EXPECTED);
        assert_eq!(out.delivery, Delivery::PossiblyDeliveredExact);
        assert_eq!(seen.lock().expect("lock").len(), 2, "both were contacted");
        assert!(
            elapsed < DRIP_FOR / 3,
            "the dripper must cost one deadline, not its own patience: {elapsed:?}"
        );
        // The dripper wrote bytes and never a whole response, so it decided nothing on
        // its own account beyond making delivery possible.
        let Outcome::NoStatus(_) = out.attempts[0].outcome else {
            panic!(
                "a drip that never framed a status is NoStatus: {:?}",
                out.attempts[0]
            )
        };
    }

    /// A hostile endpoint cannot put text of its own choosing into a retained
    /// acknowledgement, a fact, or an operator-visible rendering of either — not
    /// through a refusal's `check`/`detail`, and not through an `Accepted` whose
    /// commitment id is the operator's typed secret.
    #[test]
    fn no_peer_chosen_text_survives_into_an_acknowledgement_or_a_fact() {
        let script = &["refusal-reflecting", "accepted-reflecting", "accepted"];
        let (endpoints, _) = federation(script);
        let out = deliver(&endpoints, &signed_request(), EXPECTED, WAIT).expect("deliver");
        let ack = out.accepted.expect("the third endpoint accepts");
        // The retained id is the LOCAL one, and it is the local one even though an
        // endpoint offered a perfectly well-formed acceptance carrying the secret.
        assert_eq!(
            ack.commitment_id, EXPECTED,
            "the retained id must be the caller's own"
        );
        let rendered = format!("{:?} {:?} {:?}", ack, out.delivery, out.attempts);
        assert!(
            !rendered.contains(TYPED_SECRET),
            "peer text reached retained state: {rendered}"
        );
        for absent in ["BAD_PIN", "\"check\"", "\"detail\""] {
            assert!(!rendered.contains(absent), "{rendered} retained {absent}");
        }
        let statuses: Vec<u16> = out
            .attempts
            .iter()
            .map(|fact| match fact.outcome {
                Outcome::Status(status) => status,
                _ => panic!("every endpoint answered a status: {:?}", fact.outcome),
            })
            .collect();
        assert_eq!(statuses, [200, 200, 200], "all three were reached");
    }

    /// Failover reuses the EXACT signed bytes, and one logical command draws
    /// exactly one 32-byte OS-CSPRNG nonce; a NEW logical request draws another.
    #[test]
    fn every_attempt_is_byte_identical_and_one_command_draws_one_nonce() {
        let (endpoints, seen) = federation(&["refusal", "503 Unavailable", "accepted"]);
        let request = signed_request();
        deliver(&endpoints, &request, EXPECTED, WAIT).expect("deliver");
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
        let out = deliver(&down, &signed_request(), EXPECTED, WAIT).expect("deliver");
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
        let out = deliver(&endpoints, &request, EXPECTED, WAIT).expect("deliver");
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
