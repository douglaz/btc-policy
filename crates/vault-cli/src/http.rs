//! Minimal HTTP/1.1 client over std::net (`Connection: close`).
//! Talks to two loopback servers only — vault-node (`/sign`, `/events`,
//! `/pending`, `/channel`) and bitcoind's JSON-RPC — which does not buy an HTTP crate its
//! keep.
//!
//! Two policies share one synchronous exchange (bead
//! btc-policy-http-bounded-ingress-response-qhe). [`Policy::Legacy`] is what every pre-M3
//! caller keeps: a fixed connect, a per-READ inactivity timeout, an unbounded read to
//! close, and a lossy `String` body. The BOUNDED policies — [`Policy::ingress`] for
//! ordered stage-1 delivery, [`Policy::core`] for the closed read-only Core reads — carry
//! ONE ABSOLUTE `Instant` deadline, recompute the time left before every blocking
//! operation, cap the WHOLE raw response (status line, headers, separator and body) with
//! cap+1 detection, and complete only at EOF inside both bounds. They hand back BYTES in a
//! zeroizing allocation: what peer text means is the consumer's decision, not this
//! module's.

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

pub type Error = Box<dyn std::error::Error + Send + Sync + 'static>;

pub struct Response {
    pub status: u16,
    pub body: String,
}

/// What ONE exchange observed, split by the only phase distinction the stage-1
/// ingress client needs: whether a request byte can already have reached the peer.
/// Every other caller collapses this back to `Result<Response, Error>` below.
pub enum Attempt {
    /// Connect or socket setup failed BEFORE any request byte was written.
    NotSent(Error),
    /// A write may have happened and no status line came back.
    NoStatus(Error),
    /// A status line came back. `body` is `None` when the rest failed after it —
    /// the status is still KNOWN, which is what keeps a 400 an explicit
    /// no-delivery even when its body never arrives. Bytes, not text: a Core reply
    /// must decode STRICTLY and an ingress reply must not materialize peer text at
    /// all, and neither is expressible once this has been through `from_utf8_lossy`.
    Status {
        status: u16,
        body: Option<Zeroizing<Vec<u8>>>,
    },
}

/// One `SignResponse` is three small fields; 64 KiB is orders of magnitude of slack.
const INGRESS_CAP: usize = 64 * 1024;
/// A consensus-maximum raw transaction as JSON hex, plus envelope. This is a RAW WIRE
/// cap, not a bound on what decoding that many bytes then costs in heap.
const CORE_CAP: usize = 16 * 1024 * 1024;
/// The WHOLE exchange for the seven reads that are not the scan, where the funnel this
/// replaced spent 600 seconds per READ and could spend them again on the next one. No
/// measurement is claimed for the value: those seven are Core's own local index and disk
/// reads, and `scantxoutset` — the one that actually scans — keeps that 600 below.
const CORE_DEADLINE: Duration = Duration::from_secs(60);
/// The node backend's existing 600-second synchronous-scan precedent, reused rather
/// than an unmeasured mainnet duration asserted.
const CORE_SCAN_DEADLINE: Duration = Duration::from_secs(600);
/// The legacy connect ceiling. Under a bounded policy it is spent INSIDE the remaining
/// deadline, never in addition to it.
const CONNECT_CEILING: Duration = Duration::from_secs(5);

/// Which bound one exchange runs under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Policy {
    /// Pre-M3 semantics: a per-READ inactivity timeout, no whole-exchange deadline and
    /// no cap, so a peer that answers one byte at a time holds the call open forever.
    Legacy(Duration),
    /// One absolute deadline over connect, writes and the whole response, plus a cap on
    /// the entire raw response.
    Bounded { deadline: Instant, cap: usize },
}

impl Policy {
    /// Ordered stage-1 ingress: the CALLER's own ABSOLUTE deadline, and 64 KiB.
    pub fn ingress(deadline: Instant) -> Policy {
        Policy::Bounded {
            deadline,
            cap: INGRESS_CAP,
        }
    }

    /// The closed read-only Core reads. `scantxoutset` is the ONE typed exception, and
    /// deliberately not the first row of a per-method deadline table.
    pub fn core(method: &str) -> Policy {
        let budget = match method {
            "scantxoutset" => CORE_SCAN_DEADLINE,
            _ => CORE_DEADLINE,
        };
        // Absolute from here, and CHECKED: a clock near the representable end clamps to an
        // already-expired deadline rather than panicking inside a read-only Core call.
        let now = Instant::now();
        Policy::Bounded {
            deadline: now.checked_add(budget).unwrap_or(now),
            cap: CORE_CAP,
        }
    }
}

/// One request built directly into ONE pre-reserved zeroizing allocation. The encoded
/// credential and the body — which carries the demo's plaintext PIN — therefore exist
/// here and in no ordinary head `String`, and every path wipes them. `post` is `None`
/// for the node's `/events` pull, which carries neither content headers nor auth.
fn request(
    addr: SocketAddr,
    path: &str,
    post: Option<&[u8]>,
    auth: Option<&str>,
) -> Zeroizing<Vec<u8>> {
    let host = addr.to_string();
    let length = post.map(|body| body.len().to_string()).unwrap_or_default();
    let verb: &[u8] = if post.is_some() { b"POST " } else { b"GET " };
    let mut pieces: Vec<&[u8]> = vec![
        verb,
        path.as_bytes(),
        b" HTTP/1.1\r\nHost: ",
        host.as_bytes(),
        b"\r\n",
    ];
    if post.is_some() {
        pieces.push(b"Content-Type: application/json\r\nContent-Length: ");
        pieces.push(length.as_bytes());
        pieces.push(b"\r\n");
    }
    if let Some(credentials) = auth {
        pieces.push(b"Authorization: Basic ");
        pieces.push(credentials.as_bytes());
        pieces.push(b"\r\n");
    }
    pieces.push(b"Connection: close\r\n\r\n");
    pieces.push(post.unwrap_or_default());
    let capacity = pieces.iter().map(|piece| piece.len()).sum();
    let mut request = Zeroizing::new(Vec::with_capacity(capacity));
    let allocation = request.as_ptr();
    for piece in pieces {
        request.extend_from_slice(piece);
    }
    debug_assert_eq!(
        (request.as_ptr(), request.len()),
        (allocation, capacity),
        "the secret-bearing request must be exactly reserved and never move"
    );
    request
}

pub fn post_json(
    addr: SocketAddr,
    path: &str,
    body: &[u8],
    basic_auth: Option<&str>,
    timeout: Duration,
) -> Result<Response, Error> {
    let request = request(addr, path, Some(body), basic_auth);
    collapse(addr, exchange(addr, &request, Policy::Legacy(timeout)))
}

/// `POST` reporting the phase it failed in, under the caller's own policy. The stage-1
/// ingress client and the Core adapter use it; both decode the bytes themselves.
pub fn post_attempt(
    addr: SocketAddr,
    path: &str,
    body: &[u8],
    basic_auth: Option<&str>,
    policy: Policy,
) -> Attempt {
    let request = request(addr, path, Some(body), basic_auth);
    exchange(addr, &request, policy)
}

/// The phase-free view every other caller wants.
fn collapse(addr: SocketAddr, attempt: Attempt) -> Result<Response, Error> {
    match attempt {
        Attempt::NotSent(e) | Attempt::NoStatus(e) => Err(e),
        Attempt::Status { status, body } => match body {
            // LOSSY, exactly as every pre-M3 caller has always been: a byte that is not
            // UTF-8 becomes U+FFFD here rather than refusing the response.
            Some(bytes) => Ok(Response {
                status,
                body: String::from_utf8_lossy(&bytes).into_owned(),
            }),
            None => Err(format!("truncated HTTP {status} response from {addr}").into()),
        },
    }
}

/// `GET` with no body — the node's `/events` alert pull (ADR-0002). No auth
/// header: `/events` is loopback-only like the rest of the node surface.
pub fn get_json(addr: SocketAddr, path: &str, timeout: Duration) -> Result<Response, Error> {
    let request = request(addr, path, None, None);
    collapse(addr, exchange(addr, &request, Policy::Legacy(timeout)))
}

/// The one entry to the socket. Both verbs and both policies arrive here.
fn exchange(addr: SocketAddr, request: &[u8], policy: Policy) -> Attempt {
    match policy {
        Policy::Legacy(timeout) => legacy(addr, request, timeout),
        Policy::Bounded { deadline, cap } => bounded(addr, request, deadline, cap, &Instant::now),
    }
}

/// The pre-M3 exchange, unchanged. `raw` is deliberately an ORDINARY `Vec` that
/// `read_to_end` grows: legacy callers keep today's exposure rather than gaining a
/// zeroization claim that a reallocating read cannot honour.
fn legacy(addr: SocketAddr, request: &[u8], timeout: Duration) -> Attempt {
    let connect = || -> Result<TcpStream, Error> {
        let stream = TcpStream::connect_timeout(&addr, CONNECT_CEILING)
            .map_err(|e| format!("connect {addr}: {e}"))?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        Ok(stream)
    };
    let mut stream = match connect() {
        Ok(stream) => stream,
        Err(e) => return Attempt::NotSent(e),
    };
    if let Err(e) = stream.write_all(request) {
        return Attempt::NoStatus(format!("write request to {addr}: {e}").into());
    }
    let mut raw = Vec::new();
    let read = stream.read_to_end(&mut raw);
    match (status_of(&raw), position(&raw, b"\r\n\r\n")) {
        // A header block that parsed says nothing about the body FINISHING.
        (Some(status), Some(split)) => Attempt::Status {
            status,
            body: read
                .is_ok()
                .then(|| Zeroizing::new(raw[split + 4..].to_vec())),
        },
        // A parse failure with a readable status line is still a decided status.
        (Some(status), None) => Attempt::Status { status, body: None },
        (None, separator) => Attempt::NoStatus(match read {
            Err(io) => format!("read response from {addr}: {io}").into(),
            // The pre-M3 parser told these two apart and so does this: a head that
            // TERMINATED and still has no readable status line is a status-line
            // defect, while nothing recognizable at all is a response defect.
            Ok(_) if separator.is_some() => {
                format!("malformed HTTP status line from {addr}").into()
            }
            Ok(_) => format!("malformed HTTP response from {addr}").into(),
        }),
    }
}

/// ONE bounded exchange over the caller's own ABSOLUTE deadline: the time left is
/// recomputed against that instant before every blocking operation, so connect, each
/// partial write and the whole response spend the SAME deadline and no phase rebases it
/// from a remaining duration. `now` is injected because a deadline silently RESET at each
/// phase still finishes on time under any sleep a test could write.
fn bounded(
    addr: SocketAddr,
    request: &[u8],
    deadline: Instant,
    cap: usize,
    now: &dyn Fn() -> Instant,
) -> Attempt {
    // `None` is EXPIRED, and zero counts as expired: the socket API refuses a zero
    // timeout, and a zero-length wait is not a wait.
    let left = || match deadline.checked_duration_since(now()) {
        Some(left) if !left.is_zero() => Some(left),
        _ => None,
    };
    let Some(first) = left() else {
        return Attempt::NotSent(format!("connect {addr}: the deadline expired first").into());
    };
    let mut stream = match TcpStream::connect_timeout(&addr, first.min(CONNECT_CEILING)) {
        Ok(stream) => stream,
        Err(e) => return Attempt::NotSent(format!("connect {addr}: {e}").into()),
    };
    // THE LAST `NotSent` IS ABOVE. A request byte may now be on the wire, so every
    // failure below is `NoStatus` or `Status` — including a write that reports no
    // progress at all. Reissue authority ends at the line above this comment.
    // `send` can only ever fail with `NoStatus`, and the binding says so: naming this
    // one `unsent` under the comment above would read as the outcome it cannot be.
    if let Err(no_status) = send(&mut stream, request, addr, &left) {
        return no_status;
    }
    // The WHOLE raw response in ONE allocation of exactly cap+1 bytes: crossing the cap
    // is then observable as a full buffer, and nothing oversized is ever held. It must
    // never grow — zeroize cannot wipe an allocation `Vec` has already abandoned.
    let mut raw = Zeroizing::new(vec![0u8; cap + 1]);
    let allocation = raw.as_ptr();
    let mut filled = 0;
    let closed = loop {
        if filled == raw.len() {
            break Err(format!("response from {addr} is over its {cap}-byte cap"));
        }
        let Some(wait) = left() else {
            break Err(format!("response from {addr}: the deadline expired"));
        };
        if let Err(e) = stream.set_read_timeout(Some(wait)) {
            break Err(format!("read response from {addr}: {e}"));
        }
        match stream.read(&mut raw[filled..]) {
            // EOF inside the deadline and the cap: the only completion there is. A
            // parseable PREFIX is not one, however complete it looks. The budget is
            // re-read HERE as well, because the socket timeout that bounded this read
            // is rounded and the thread waking from it can be descheduled: an EOF
            // OBSERVED after the absolute deadline is not completion inside it.
            Ok(0) if left().is_none() => {
                break Err(format!("response from {addr}: the deadline expired"))
            }
            Ok(0) => break Ok(()),
            Ok(bytes) => filled += bytes,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => break Err(format!("read response from {addr}: {e}")),
        }
    };
    // Both halves, because a pointer alone is not the invariant: `realloc` on an
    // allocation this size is an `mremap`, which is free to extend it IN PLACE and
    // return the same address, so a future edit that grew this buffer could leave the
    // pointer intact while the capacity moved.
    debug_assert_eq!(
        (raw.as_ptr(), raw.capacity()),
        (allocation, cap + 1),
        "the bounded response allocation must never move or grow"
    );
    let raw = &raw[..filled];
    match closed.and_then(|()| frame(raw, addr)) {
        Ok((status, body)) => Attempt::Status {
            status,
            body: Some(body),
        },
        // A STRICTLY valid status is known even when the rest of the response is not,
        // and a cap, a deadline or a framing defect cannot erase it afterwards.
        Err(why) => match strict_status(raw) {
            Some(status) => Attempt::Status { status, body: None },
            None => Attempt::NoStatus(why.into()),
        },
    }
}

/// The two socket operations the bounded WRITE loop performs. It is a trait so that a
/// scripted writer can drive the arms a real `TcpStream` cannot be made to take — a
/// write reporting NO progress, an `EINTR` restart, a timeout that will not arm —
/// because "no post-connect failure is `NotSent`" is a claim about exactly those arms.
/// Production has one implementor, immediately below.
trait Wire: Write {
    fn arm(&self, left: Duration) -> std::io::Result<()>;
}

impl Wire for TcpStream {
    fn arm(&self, left: Duration) -> std::io::Result<()> {
        self.set_write_timeout(Some(left))
    }
}

/// The post-connect write loop, in partial writes rather than `write_all`, re-reading
/// the ONE budget before each of them and after every interruption. Its every failure
/// is `NoStatus`: a request byte may already be on the wire, so the reissue authority
/// `NotSent` carries ended when connect returned.
fn send(
    stream: &mut dyn Wire,
    request: &[u8],
    addr: SocketAddr,
    left: &dyn Fn() -> Option<Duration>,
) -> Result<(), Attempt> {
    let no_status = |what: String| Err(Attempt::NoStatus(what.into()));
    let mut written = 0;
    while written < request.len() {
        let Some(left) = left() else {
            return no_status(format!("write request to {addr}: the deadline expired"));
        };
        if let Err(e) = stream.arm(left) {
            return no_status(format!("write request to {addr}: {e}"));
        }
        match stream.write(&request[written..]) {
            Ok(0) => return no_status(format!("write request to {addr}: no progress")),
            Ok(bytes) => written += bytes,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return no_status(format!("write request to {addr}: {e}")),
        }
    }
    Ok(())
}

/// The whole response at EOF: a strict status line, a header block that terminates and
/// whose every line is `token ":" OWS value`, no `Transfer-Encoding`, at most one
/// `Content-Length`, and a body exactly as long as a present `Content-Length` says.
fn frame(raw: &[u8], addr: SocketAddr) -> Result<(u16, Zeroizing<Vec<u8>>), String> {
    let bad = |what: &str| format!("malformed HTTP response from {addr}: {what}");
    let status = strict_status(raw).ok_or_else(|| bad("its status line is not strict HTTP/1.x"))?;
    let line = position(raw, b"\r\n").ok_or_else(|| bad("its status line does not end"))?;
    let split = line
        + position(&raw[line..], b"\r\n\r\n")
            .ok_or_else(|| bad("its header block does not end"))?;
    // CRLF and nothing else terminates a line here. Without this the FIRST CRLF — which
    // is what bounds the status line above and starts the header scan below — can sit
    // after a line the peer ended with HALF a terminator, and every line before it is
    // then invisible to the rules underneath: that is the peer, not this client,
    // choosing the framing. A lone CR hides a line exactly as a lone LF does.
    let head = &raw[..split + 4];
    if head.iter().enumerate().any(|(at, byte)| match byte {
        b'\r' => head.get(at + 1) != Some(&b'\n'),
        b'\n' => at == 0 || head[at - 1] != b'\r',
        _ => false,
    }) {
        return Err(bad("a head line does not end in CRLF"));
    }
    let mut declared = None;
    let mut headers = &raw[line + 2..split + 2];
    while !headers.is_empty() {
        let end = position(headers, b"\r\n").unwrap_or(headers.len());
        let (header, rest) = headers.split_at(end);
        headers = rest.get(2..).unwrap_or_default();
        let colon = header
            .iter()
            .position(|byte| *byte == b':')
            .ok_or_else(|| bad("a header line carries no colon"))?;
        let (name, value) = header.split_at(colon);
        // One rule refuses obs-fold and whitespace before the colon alike: neither a
        // continuation line's leading space nor any other space is a token character.
        if name.is_empty() || !name.iter().all(|byte| is_token(*byte)) {
            return Err(bad("a header name is not a token"));
        }
        let value = trim_ows(&value[1..]);
        if name.eq_ignore_ascii_case(b"transfer-encoding") {
            return Err(bad("this client accepts no Transfer-Encoding"));
        }
        if name.eq_ignore_ascii_case(b"content-length") {
            if declared.is_some() {
                return Err(bad("it carries more than one Content-Length"));
            }
            declared =
                Some(content_length(value).ok_or_else(|| bad("its Content-Length is malformed"))?);
        }
    }
    let body = &raw[split + 4..];
    // No `Content-Length` at all is legitimate: EOF is then the boundary, which is
    // exactly what this exchange waited for.
    if declared.is_some_and(|declared| declared != body.len()) {
        return Err(bad("its body length disagrees with its Content-Length"));
    }
    Ok((status, Zeroizing::new(body.to_vec())))
}

/// The status of a STRICTLY valid status line: exactly `HTTP/1.0` or `HTTP/1.1`, one
/// space, exactly three digits in `100..=599`, then a space or that line's own CRLF.
/// `garbage 400` is not a status line, and neither is `HTTP/1.1 4000 x`.
fn strict_status(raw: &[u8]) -> Option<u16> {
    let rest = raw
        .strip_prefix(b"HTTP/1.1 ")
        .or_else(|| raw.strip_prefix(b"HTTP/1.0 "))?;
    let digits = rest.get(..3)?;
    if !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    match rest.get(3..) {
        Some([b' ', ..]) | Some([b'\r', b'\n', ..]) => {}
        _ => return None,
    }
    let code: u16 = std::str::from_utf8(digits).ok()?.parse().ok()?;
    (100..=599).contains(&code).then_some(code)
}

/// The status code of the response's first line, if it has one. LEGACY ONLY: it accepts
/// anything whose second whitespace-separated word parses, which is what pre-M3 callers
/// have always run on.
fn status_of(raw: &[u8]) -> Option<u16> {
    let end = position(raw, b"\r\n")?;
    String::from_utf8_lossy(&raw[..end])
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

fn position(raw: &[u8], needle: &[u8]) -> Option<usize> {
    raw.windows(needle.len())
        .position(|window| window == needle)
}

/// RFC 7230 `tchar`.
fn is_token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

fn trim_ows(mut value: &[u8]) -> &[u8] {
    while let [b' ' | b'\t', rest @ ..] = value {
        value = rest;
    }
    while let [rest @ .., b' ' | b'\t'] = value {
        value = rest;
    }
    value
}

/// A `Content-Length` is ASCII digits and nothing else — no sign, no comma, no second
/// value, no empty value — and it must fit a `usize` without wrapping.
fn content_length(value: &[u8]) -> Option<usize> {
    if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
        return None;
    }
    // The guard above is what makes `parse` safe to reach for: it has already excluded
    // the sign, the separator, the radix prefix and the empty value, and `parse` itself
    // is what refuses a run of digits too long for a `usize`.
    std::str::from_utf8(value).ok()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    /// A body-read that FAILS after the status line is an ERROR for `post_json`/`get_json`, never
    /// a short body. A peer closing cleanly mid-body instead fails the caller's JSON decode.
    #[test]
    fn a_stalled_body_is_not_a_complete_response() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let addr = listener.local_addr().expect("addr");
        let timeout = Duration::from_secs(1);
        let client = std::thread::spawn(move || post_json(addr, "/sign", b"{}", None, timeout));
        // Held open past the client's read timeout, so the body never finishes arriving.
        let (mut stream, _) = listener.accept().expect("accept");
        stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").expect("write");
        let error = client.join().expect("join").err().expect("not a response");
        assert!(error.to_string().contains("truncated HTTP 200"), "{error}");
    }

    // =================================================================================
    // The bounded transport (bead btc-policy-http-bounded-ingress-response-qhe).
    // =================================================================================

    /// A deadline every green row has slack under, and one every timeout row is measured
    /// against. Both are wall-clock only where the fake clock cannot serve: a REAL socket
    /// timeout is what a deadline row must observe, and a socket cannot be faked.
    const SLACK: Duration = Duration::from_secs(10);
    const SHORT: Duration = Duration::from_millis(300);
    /// Small enough that whole-response arithmetic is exact and readable.
    const CAP: usize = 256;

    /// One scripted reply: `chunks` written `gap` apart, then EOF — or, with `hold`, the
    /// connection kept open, which is the drip only a deadline can end.
    struct Reply {
        chunks: Vec<Vec<u8>>,
        gap: Duration,
        hold: Option<Duration>,
    }

    impl Reply {
        /// Written at once, then closed.
        fn eof(bytes: &[u8]) -> Reply {
            Reply {
                chunks: vec![bytes.to_vec()],
                gap: Duration::ZERO,
                hold: None,
            }
        }

        /// Written at once, then held open: EOF never arrives.
        fn held(bytes: &[u8]) -> Reply {
            Reply::closes_after(bytes, SLACK)
        }

        /// Written at once, then held open for `hold` and only THEN closed, so the EOF
        /// itself can be placed at a chosen moment.
        fn closes_after(bytes: &[u8], hold: Duration) -> Reply {
            Reply {
                hold: Some(hold),
                ..Reply::eof(bytes)
            }
        }

        /// One byte at a time, `gap` apart, then closed. Each individual read lands well
        /// inside any per-read inactivity timeout, which is exactly why a per-read
        /// timeout cannot end it — only a deadline over the whole exchange can.
        fn drip(bytes: &[u8], gap: Duration) -> Reply {
            Reply {
                chunks: bytes.iter().map(|byte| vec![*byte]).collect(),
                gap,
                hold: None,
            }
        }
    }

    struct Peer {
        addr: SocketAddr,
        connections: Arc<AtomicUsize>,
        seen: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl Peer {
        fn connections(&self) -> usize {
            self.connections.load(Ordering::SeqCst)
        }

        fn request(&self) -> Vec<u8> {
            self.seen
                .lock()
                .expect("lock")
                .first()
                .cloned()
                .unwrap_or_default()
        }
    }

    /// A loopback peer answering one scripted reply per connection, recording every raw
    /// request and every connection — so "nothing was sent" is observed at the peer
    /// rather than inferred from the client's own report.
    fn peer(replies: Vec<Reply>) -> Peer {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let addr = listener.local_addr().expect("addr");
        let connections = Arc::new(AtomicUsize::new(0));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (counted, recorded) = (Arc::clone(&connections), Arc::clone(&seen));
        std::thread::spawn(move || {
            for reply in replies {
                let Ok((mut stream, _)) = listener.accept() else {
                    return;
                };
                counted.fetch_add(1, Ordering::SeqCst);
                recorded
                    .lock()
                    .expect("lock")
                    .push(whole_request(&mut stream));
                let Reply { chunks, gap, hold } = reply;
                for chunk in chunks {
                    if stream.write_all(&chunk).is_err() {
                        break;
                    }
                    std::thread::sleep(gap);
                }
                if let Some(hold) = hold {
                    std::thread::sleep(hold);
                }
            }
        });
        Peer {
            addr,
            connections,
            seen,
        }
    }

    /// One whole request: the head, then exactly the body length it declares.
    fn whole_request(stream: &mut TcpStream) -> Vec<u8> {
        let (mut raw, mut byte) = (Vec::new(), [0u8; 1]);
        while !raw.ends_with(b"\r\n\r\n") {
            match stream.read(&mut byte) {
                Ok(1) => raw.push(byte[0]),
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                _ => return raw,
            }
        }
        let len = String::from_utf8_lossy(&raw)
            .split("Content-Length: ")
            .nth(1)
            .and_then(|rest| rest.split("\r\n").next())
            .and_then(|value| value.parse().ok())
            .unwrap_or(0);
        let mut body = vec![0u8; len];
        if stream.read_exact(&mut body).is_ok() {
            raw.extend_from_slice(&body);
        }
        raw
    }

    /// A complete response: `headers` is CRLF-terminated per line, and the separator
    /// plus `body` follow it.
    fn response(headers: &str, body: &str) -> Vec<u8> {
        format!("HTTP/1.1 200 OK\r\n{headers}\r\n{body}").into_bytes()
    }

    /// Drive one bounded exchange, with the real clock and the real request builder.
    /// `budget` is spelled as a duration for readability and turned into the ABSOLUTE
    /// instant the exchange now takes here, at the one place a row starts.
    fn probe(peer: &Peer, budget: Duration, cap: usize) -> Attempt {
        let request = request(peer.addr, "/sign", Some(b"{}"), None);
        bounded(
            peer.addr,
            &request,
            Instant::now() + budget,
            cap,
            &Instant::now,
        )
    }

    /// `(status, body as text)`. `None` status is `NoStatus`, and `NotSent` PANICS: every
    /// row below has already connected, so this is the watch-authority assertion the
    /// whole bounded suite carries — no post-connect failure may claim reissue authority.
    fn observed(attempt: Attempt) -> (Option<u16>, Option<String>) {
        match attempt {
            Attempt::NotSent(e) => panic!("a post-connect exchange reported NotSent: {e}"),
            Attempt::NoStatus(_) => (None, None),
            Attempt::Status { status, body } => (
                Some(status),
                body.map(|bytes| String::from_utf8_lossy(&bytes).into_owned()),
            ),
        }
    }

    /// This file's PRODUCTION half, comment lines removed: what the two structural
    /// controls below read is code, never a sentence about code.
    fn production_source() -> String {
        include_str!("http.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap_or_default()
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<&str>>()
            .join("\n")
    }

    /// A monotonic clock that advances by a fixed step on every read and counts them.
    /// This is the seam the phase evidence needs: a deadline created ONCE and consulted
    /// per phase and one silently RESET per phase both finish on time under any sleep a
    /// test could write, and are told apart only by what the clock is asked.
    struct FakeClock {
        base: Instant,
        step: Duration,
        reads: Mutex<u32>,
    }

    impl FakeClock {
        fn new(step: Duration) -> FakeClock {
            FakeClock {
                base: Instant::now(),
                step,
                reads: Mutex::new(0),
            }
        }

        fn now(&self) -> Instant {
            let mut reads = self.reads.lock().expect("lock");
            let elapsed = self.step * *reads;
            *reads += 1;
            self.base + elapsed
        }

        fn reads(&self) -> u32 {
            *self.reads.lock().expect("lock")
        }

        /// `budget` after this clock's own base: the absolute deadline a row hands the
        /// exchange, computed WITHOUT consuming a sample.
        fn at(&self, budget: Duration) -> Instant {
            self.base + budget
        }
    }

    /// A monotonic clock that runs FAST: real elapsed time multiplied by `factor`. The
    /// step-per-sample clock above cannot express the terminal-EOF row, because there
    /// the budget has to run out DURING one blocking read of a real socket rather than
    /// between two samples — and the socket timeout that bounds that read is computed
    /// from the same budget, so it must still be generous in real time.
    struct ScaledClock {
        started: Instant,
        factor: u32,
    }

    impl ScaledClock {
        fn new(factor: u32) -> ScaledClock {
            ScaledClock {
                started: Instant::now(),
                factor,
            }
        }

        fn now(&self) -> Instant {
            self.started + self.started.elapsed() * self.factor
        }

        fn at(&self, budget: Duration) -> Instant {
            self.started + budget
        }
    }

    /// A scripted write half. `steps` answers successive `write` calls and runs out into
    /// "wrote everything offered"; `refuse_arm` fails the timeout instead. This is the
    /// only way into the arms a real `TcpStream` cannot be driven to take — `Ok(0)` and
    /// `ErrorKind::Interrupted` — and those arms are exactly where the claim that no
    /// post-connect failure is `NotSent` would be broken.
    struct Scripted {
        steps: Vec<std::io::Result<usize>>,
        refuse_arm: Option<ErrorKind>,
        written: Vec<u8>,
        writes: u32,
    }

    impl Scripted {
        fn new(steps: Vec<std::io::Result<usize>>) -> Scripted {
            Scripted {
                steps,
                refuse_arm: None,
                written: Vec::new(),
                writes: 0,
            }
        }
    }

    impl Write for Scripted {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.writes += 1;
            let step = if self.steps.is_empty() {
                Ok(buf.len())
            } else {
                self.steps.remove(0)
            };
            if let Ok(bytes) = step {
                self.written.extend_from_slice(&buf[..bytes]);
            }
            step
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Wire for Scripted {
        fn arm(&self, _left: Duration) -> std::io::Result<()> {
            match self.refuse_arm {
                Some(kind) => Err(std::io::Error::from(kind)),
                None => Ok(()),
            }
        }
    }

    /// What the write loop reported, with `NotSent` as a PANIC: reissue authority ended
    /// when connect returned, so that is the assertion every row below carries.
    fn sent(outcome: Result<(), Attempt>) -> Option<String> {
        match outcome {
            Ok(()) => None,
            Err(Attempt::NoStatus(why)) => Some(why.to_string()),
            Err(Attempt::NotSent(e)) => {
                panic!("a post-connect write claimed reissue authority: {e}")
            }
            Err(Attempt::Status { status, .. }) => {
                panic!("the write loop cannot decide a status: {status}")
            }
        }
    }

    /// 1. The ONE deadline the CALLER supplies already covers connect, and is consulted
    ///    again before every blocking operation, never restarted. The injected clock is
    ///    what makes the difference observable: it advances a third of the budget per
    ///    read, so a correct exchange runs out on a HEALTHY peer that answers instantly,
    ///    while a deadline restarted per phase — or set once and never re-read — completes.
    #[test]
    fn the_bounded_deadline_starts_before_connect_and_is_never_restarted() {
        // A deadline already spent before connect: nothing may be written, and no
        // connection may even be made, so `NotSent` is the honest answer here.
        let closed = peer(vec![Reply::eof(&response("", "{}"))]);
        let clock = FakeClock::new(SLACK);
        let sent = request(closed.addr, "/sign", Some(b"{}"), None);
        let spent = clock.at(Duration::ZERO);
        let attempt = bounded(closed.addr, &sent, spent, CAP, &|| clock.now());
        let Attempt::NotSent(why) = attempt else {
            panic!("an expired deadline must not connect");
        };
        assert!(why.to_string().contains("deadline expired"), "{why}");
        assert_eq!(closed.connections(), 0, "the peer must see no connection");
        assert_eq!(
            clock.reads(),
            1,
            "one sample, against a deadline already reached"
        );

        // Past connect, on a peer that answers a COMPLETE response instantly: the budget
        // still runs out, because connect, the write and the read all spend the same one.
        // Which PHASE it runs out in depends on how many reads the socket needed, so what
        // is asserted is the invariant every ordering shares — the exchange does not
        // finish — rather than one particular phase. A deadline restarted per phase, or
        // sampled once and never re-read, finishes it.
        let fast = peer(vec![Reply::eof(&response("Content-Length: 2\r\n", "{}"))]);
        let clock = FakeClock::new(SLACK / 3);
        let sent = request(fast.addr, "/sign", Some(b"{}"), None);
        let deadline = clock.at(SLACK);
        let (_, unfinished) = observed(bounded(fast.addr, &sent, deadline, CAP, &|| clock.now()));
        assert_eq!(
            unfinished, None,
            "a deadline that covers connect, write and read must expire mid-exchange"
        );
        assert!(
            clock.reads() >= 4,
            "the time left must be recomputed per phase, not once: {} reads",
            clock.reads()
        );

        // The adjacent control: the SAME peer script under the real clock completes.
        let green = peer(vec![Reply::eof(&response("Content-Length: 2\r\n", "{}"))]);
        assert_eq!(
            observed(probe(&green, SLACK, CAP)),
            (Some(200), Some("{}".into())),
            "the same exchange completes when its deadline is not spent"
        );
    }

    /// 1b. The deadline covers the WRITE as well, and an exchange that has connected can
    ///     never report `NotSent` again — not even when no request byte got out.
    #[test]
    fn a_deadline_spent_after_connect_is_no_status_and_never_not_sent() {
        let listening = peer(vec![Reply::eof(&response("", "{}"))]);
        // One whole step per sample: the pre-connect check passes on the clock's own base,
        // and the write's next sample has reached the deadline.
        let clock = FakeClock::new(SLACK);
        let sent = request(listening.addr, "/sign", Some(b"{}"), None);
        let deadline = clock.at(SLACK);
        let attempt = bounded(listening.addr, &sent, deadline, CAP, &|| clock.now());
        let Attempt::NoStatus(why) = attempt else {
            panic!("a post-connect deadline is NoStatus, never NotSent");
        };
        assert!(why.to_string().contains("write request"), "{why}");
    }

    /// 1c. Completion is EOF INSIDE the deadline, and that is re-checked AT the EOF.
    ///     A peer that answers in full and then closes late enough that the budget ran
    ///     out while the read was blocked has not completed an exchange: the socket
    ///     timeout is rounded to microseconds and the woken thread can be descheduled,
    ///     so the last thing this transport does before calling a response whole is
    ///     read the same monotonic budget once more.
    #[test]
    fn an_eof_observed_after_the_deadline_is_not_a_completed_response() {
        // The peer answers at once and closes LATE. The budget is generous in REAL
        // time — the blocked read waits `BUDGET` for an EOF that comes at `LATE`, and
        // therefore never times out — while the injected clock, running `FACTOR` times
        // as fast, has spent that same budget by the time the EOF lands.
        const LATE: Duration = Duration::from_millis(300);
        const BUDGET: Duration = Duration::from_millis(2000);
        const FACTOR: u32 = 8;

        let whole = response("Content-Length: 2\r\n", "{}");
        let late = peer(vec![Reply::closes_after(&whole, LATE)]);
        let sent = request(late.addr, "/sign", Some(b"{}"), None);
        let clock = ScaledClock::new(FACTOR);
        let started = Instant::now();
        let deadline = clock.at(BUDGET);
        let refused = observed(bounded(late.addr, &sent, deadline, CAP, &|| clock.now()));
        let blocked = started.elapsed();
        assert_eq!(
            refused,
            (Some(200), None),
            "an EOF observed past the absolute deadline is not completion inside it"
        );
        // This row only says anything about the TERMINAL re-check if the exchange really
        // did block through the EOF, and that holds only while the scaled budget is still
        // unspent at the loop top before the last read — `BUDGET / FACTOR` = 250 ms of
        // REAL time, which is what `LATE` is set above. An exchange that ran out at a
        // loop top instead returns AT ONCE and asserts the same pair for another reason,
        // so the row would go on passing while the mutation it exists to kill survived.
        // Measured rather than assumed: raising `FACTOR` to 40000 shrinks the margin to
        // 50 µs, and this assertion then fires on an exchange that returned after 139 µs
        // — with the pair above still green, which is the whole point. So what this row
        // actually needs is ~140 µs of the 250 ms it has.
        assert!(
            blocked >= LATE,
            "the deadline that refused this must be the one re-read AT the EOF, not one \
             already spent before the last read began: {blocked:?}"
        );

        // The adjacent control, which is also what rules out the row above having
        // merely timed the SOCKET out: the same peer, the same real budget, the real
        // clock — and it completes with its whole body.
        let punctual = peer(vec![Reply::closes_after(&whole, LATE)]);
        assert_eq!(
            observed(probe(&punctual, BUDGET, CAP)),
            (Some(200), Some("{}".into())),
            "the same close, under a clock that does not outrun it, completes"
        );
    }

    /// 1d. The READ phases the one deadline covers, one row each: a budget spent while
    ///     the STATUS line is still arriving decides nothing, one spent inside the
    ///     HEADERS keeps the status it already has, and one spent inside the BODY keeps
    ///     it too. With connect (class 1), the write (1b) and the terminal EOF (1c),
    ///     that is every blocking operation `bounded` performs.
    #[test]
    fn the_deadline_covers_the_status_header_and_body_reads_alike() {
        // Inside the STATUS line: at one byte per 80 ms nothing strict has arrived
        // within SHORT, so there is nothing to preserve.
        let whole = response("Content-Length: 2\r\n", "{}");
        let mid_status = peer(vec![Reply::drip(&whole, Duration::from_millis(80))]);
        assert_eq!(
            observed(probe(&mid_status, SHORT, CAP)),
            (None, None),
            "a deadline spent before a strict status line decides nothing"
        );

        // Inside the HEADERS: the status line is whole, so the status survives even
        // though the header block never terminates.
        let mid_headers = peer(vec![Reply::held(b"HTTP/1.1 413 Payload Too Large\r\n")]);
        assert_eq!(
            observed(probe(&mid_headers, SHORT, CAP)),
            (Some(413), None),
            "a deadline spent inside the headers cannot erase the status"
        );

        // Inside the BODY: the head is whole and the declared body never finishes.
        let mid_body = peer(vec![Reply::held(
            b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nab",
        )]);
        assert_eq!(
            observed(probe(&mid_body, SHORT, CAP)),
            (Some(200), None),
            "a deadline spent inside the body cannot erase the status either"
        );
    }

    /// 2. The cap covers the ENTIRE raw response — status line, headers, separator and
    ///    body — and is detected at cap+1. A body-only cap passes every oversize row
    ///    whose headers do the overflowing.
    #[test]
    fn the_whole_raw_response_is_capped_with_cap_plus_one_detection() {
        // A response whose WHOLE raw length is exactly `total`, grown by its body. The
        // declared length is written at the width of `total` first, so adding the body
        // cannot widen the header and overshoot.
        let pad = |total: usize| -> Vec<u8> {
            let head = response(&format!("Content-Length: {total}\r\n"), "").len();
            let body = total - head;
            response(&format!("Content-Length: {body}\r\n"), &"x".repeat(body))
        };
        let exact = pad(CAP);
        assert_eq!(exact.len(), CAP, "the row must sit exactly on the cap");
        let at = peer(vec![Reply::eof(&exact)]);
        let (status, body) = observed(probe(&at, SLACK, CAP));
        assert_eq!(
            status,
            Some(200),
            "a response ON the cap is a whole response"
        );
        assert_eq!(
            body.map(|body| body.len()),
            Some(CAP - response(&format!("Content-Length: {CAP}\r\n"), "").len()),
            "and its whole body arrived"
        );

        // One byte more, and the status is still KNOWN while the body is not. A cap that
        // TRUNCATED instead of refusing would hand back a body here, which is the
        // `Read::take` shape this transport may never have.
        let over = peer(vec![Reply::eof(&pad(CAP + 1))]);
        assert_eq!(
            observed(probe(&over, SLACK, CAP)),
            (Some(200), None),
            "one byte past the cap is an ambiguous failure, not a shorter response"
        );

        // And when the cap is crossed before a strict status line even exists, there is
        // no status to preserve.
        let early = peer(vec![Reply::eof(&response("", "{}"))]);
        assert_eq!(
            observed(probe(&early, SLACK, 4)),
            (None, None),
            "a cap crossed before any status decides nothing"
        );
    }

    /// 2b. The cap counts the ENTIRE raw response, headers included — the row that a
    ///     BODY-only cap, or one that gives the head an allowance of its own, lets
    ///     through. Its header block alone is past the cap and its body is empty, so
    ///     nothing but a whole-wire cap can refuse it. It is its own class because it is
    ///     the ONLY assertion a body-only cap breaks: a cap+1 response whose bulk is
    ///     BODY is refused by both kinds, and would hide the difference.
    #[test]
    fn the_cap_counts_the_headers_and_not_only_the_body() {
        let bloated = peer(vec![Reply::eof(&response(
            &format!("X-Pad: {}\r\n", "y".repeat(CAP)),
            "",
        ))]);
        assert_eq!(
            observed(probe(&bloated, SLACK, CAP)),
            (Some(200), None),
            "the cap covers the headers too"
        );

        // The adjacent control: the same shape INSIDE the cap frames whole, so what
        // refuses the row above is the cap and not the padding header itself.
        let slim = peer(vec![Reply::eof(&response(
            &format!("X-Pad: {}\r\nContent-Length: 2\r\n", "y".repeat(CAP / 4)),
            "{}",
        ))]);
        assert_eq!(
            observed(probe(&slim, SLACK, CAP)),
            (Some(200), Some("{}".into())),
            "a padded header inside the cap is an ordinary response"
        );
    }

    /// 3. Completion is EOF inside the deadline. A peer that answers FULLY and then
    ///    holds the connection open costs exactly one deadline and keeps its status,
    ///    and a parseable prefix is never accepted as a finished response.
    #[test]
    fn a_peer_that_answers_fully_and_holds_open_costs_one_deadline_and_keeps_its_status() {
        let holding = peer(vec![Reply::held(&response("Content-Length: 2\r\n", "{}"))]);
        let started = Instant::now();
        assert_eq!(
            observed(probe(&holding, SHORT, CAP)),
            (Some(200), None),
            "a complete-looking prefix without EOF is not a complete response"
        );
        assert!(
            started.elapsed() < SHORT * 20,
            "it must cost ONE deadline, not an unbounded wait"
        );
    }

    /// 4. Every framing defect at EOF, one row per deviation. A green row keeps its
    ///    body; a red row keeps its STATUS and drops the body, which is what makes a
    ///    400 an explicit no-delivery even when nothing else about it parsed.
    #[test]
    fn every_header_content_length_and_transfer_encoding_defect_is_framed_at_eof() {
        let whole: [(&str, &str, &str); 9] = [
            ("an exact Content-Length", "Content-Length: 2\r\n", "{}"),
            ("a zero Content-Length", "Content-Length: 0\r\n", ""),
            ("no Content-Length at all, so EOF is the boundary", "", "{}"),
            ("no headers and no body", "", ""),
            // hyper — every real vault-node answer — writes its header names in lower
            // case, so case-insensitive matching is the difference between framing a
            // real ingress reply and refusing every one of them.
            ("a lower-case content-length", "content-length: 2\r\n", "{}"),
            ("a mixed-case CoNtEnT-LeNgTh", "CoNtEnT-LeNgTh: 2\r\n", "{}"),
            (
                "an upper-case CONTENT-LENGTH",
                "CONTENT-LENGTH: 2\r\n",
                "{}",
            ),
            ("OWS around the value", "Content-Length: \t2 \r\n", "{}"),
            (
                "other headers beside it",
                "Server: x\r\nContent-Length: 2\r\nConnection: close\r\n",
                "{}",
            ),
        ];
        for (what, headers, body) in whole {
            let peer = peer(vec![Reply::eof(&response(headers, body))]);
            assert_eq!(
                observed(probe(&peer, SLACK, CAP)),
                (Some(200), Some(body.into())),
                "{what} must frame"
            );
        }

        let refused: [(&str, &str, &str); 24] = [
            (
                "a Content-Length under the body",
                "Content-Length: 1\r\n",
                "{}",
            ),
            (
                "a Content-Length over the body",
                "Content-Length: 3\r\n",
                "{}",
            ),
            (
                "two equal Content-Lengths",
                "Content-Length: 2\r\nContent-Length: 2\r\n",
                "{}",
            ),
            (
                "two conflicting Content-Lengths",
                "Content-Length: 2\r\nContent-Length: 9\r\n",
                "{}",
            ),
            (
                "a differently-cased duplicate",
                "Content-Length: 2\r\ncontent-length: 2\r\n",
                "{}",
            ),
            ("a signed Content-Length", "Content-Length: +2\r\n", "{}"),
            ("a negative Content-Length", "Content-Length: -2\r\n", "{}"),
            (
                "a comma-listed Content-Length",
                "Content-Length: 2,2\r\n",
                "{}",
            ),
            ("an empty Content-Length", "Content-Length: \r\n", "{}"),
            (
                "a Content-Length past usize",
                "Content-Length: 99999999999999999999999999\r\n",
                "{}",
            ),
            ("a hex Content-Length", "Content-Length: 0x2\r\n", "{}"),
            (
                "Transfer-Encoding alone",
                "Transfer-Encoding: chunked\r\n",
                "{}",
            ),
            (
                "a lower-case transfer-encoding beside a valid length",
                "transfer-encoding: chunked\r\nContent-Length: 2\r\n",
                "{}",
            ),
            (
                "Transfer-Encoding: identity",
                "Transfer-Encoding: identity\r\n",
                "{}",
            ),
            (
                "a mixed-case TrAnSfEr-EnCoDiNg",
                "TrAnSfEr-EnCoDiNg: chunked\r\n",
                "{}",
            ),
            (
                "an obs-fold continuation line",
                "Content-Length: 2\r\n\tstill the length\r\n",
                "{}",
            ),
            (
                "whitespace before the colon",
                "Content-Length : 2\r\n",
                "{}",
            ),
            ("a header line with no colon", "Content-Length 2\r\n", "{}"),
            // Non-`tchar` bytes in the NAME, one row per shape a hostile or broken peer
            // reaches for. RFC 7230 makes each of these illegal, and each is a byte a
            // permissive splitter would hand on as a field name.
            (
                "a control byte inside the header name",
                "Content\u{1}Length: 2\r\n",
                "{}",
            ),
            (
                "a space inside the header name",
                "Content Length: 2\r\n",
                "{}",
            ),
            (
                "a double quote inside the header name",
                "Cont\"ent-Length: 2\r\n",
                "{}",
            ),
            (
                "a comma inside the header name",
                "X,Pad: 1\r\nContent-Length: 2\r\n",
                "{}",
            ),
            (
                "a non-ASCII byte inside the header name",
                "Cont\u{e9}nt-Length: 2\r\n",
                "{}",
            ),
            ("an empty header name", ": 2\r\n", "{}"),
        ];
        for (what, headers, body) in refused {
            let peer = peer(vec![Reply::eof(&response(headers, body))]);
            assert_eq!(
                observed(probe(&peer, SLACK, CAP)),
                (Some(200), None),
                "{what} must keep its status and drop its body"
            );
        }

        // An unterminated header block is the same refusal, and it is the one a peer
        // that simply stops mid-headers produces.
        let cut = peer(vec![Reply::eof(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n",
        )]);
        assert_eq!(observed(probe(&cut, SLACK, CAP)), (Some(200), None));

        // A head line ended with a LONE LF or a LONE CR, which the CRLF rows above
        // cannot reach. Each of these puts the head scan's FIRST CRLF after a line the
        // peer ended with half a terminator, so that line is invisible to every check
        // above — which is a peer choosing this exchange's framing if it is not refused
        // here. Both halves matter: a lone CR hides a line exactly as a lone LF does.
        let lone: [(&str, &[u8]); 6] = [
            (
                "a status line ended with a bare LF, hiding a Transfer-Encoding",
                b"HTTP/1.1 200 OK\nTransfer-Encoding: chunked\r\n\r\n{}",
            ),
            (
                "a header line ended with a bare LF, hiding a Transfer-Encoding",
                b"HTTP/1.1 200 OK\r\nX: y\nTransfer-Encoding: chunked\r\n\r\n{}",
            ),
            (
                "a bare LF hiding a Content-Length that disagrees with the body",
                b"HTTP/1.1 200 OK\nContent-Length: 9\r\n\r\n{}",
            ),
            (
                "a status line ended with a bare CR, hiding a Transfer-Encoding",
                b"HTTP/1.1 200 OK\rTransfer-Encoding: chunked\r\n\r\n{}",
            ),
            (
                "a header line ended with a bare CR, hiding a Transfer-Encoding",
                b"HTTP/1.1 200 OK\r\nX: y\rTransfer-Encoding: chunked\r\n\r\n{}",
            ),
            (
                "a bare CR hiding a Content-Length that disagrees with the body",
                b"HTTP/1.1 200 OK\rContent-Length: 9\r\n\r\n{}",
            ),
        ];
        for (what, raw) in lone {
            let peer = peer(vec![Reply::eof(raw)]);
            assert_eq!(
                observed(probe(&peer, SLACK, CAP)),
                (Some(200), None),
                "{what} must keep its status and drop its body"
            );
        }
    }

    /// 5. Only a STRICT status line is a status. The lookalikes matter because the
    ///    legacy parser accepts every one of them: it takes the second whitespace-
    ///    separated word of the first line and parses it.
    #[test]
    fn only_a_strict_http_1_0_or_1_1_status_line_is_a_status() {
        let strict: [(&str, u16); 6] = [
            ("HTTP/1.1 200 OK\r\n\r\n", 200),
            ("HTTP/1.0 200 OK\r\n\r\n", 200),
            ("HTTP/1.1 100 Continue\r\n\r\n", 100),
            ("HTTP/1.1 599 Nonstandard\r\n\r\n", 599),
            ("HTTP/1.1 400 \r\n\r\n", 400),
            ("HTTP/1.1 413\r\n\r\n", 413),
        ];
        for (raw, status) in strict {
            assert_eq!(strict_status(raw.as_bytes()), Some(status), "{raw:?}");
            let peer = peer(vec![Reply::eof(raw.as_bytes())]);
            assert_eq!(
                observed(probe(&peer, SLACK, CAP)),
                (Some(status), Some(String::new())),
                "{raw:?} must frame"
            );
        }

        let lookalikes = [
            "garbage 400\r\n\r\n",
            "HTTP/1.2 200 OK\r\n\r\n",
            "HTTP/2 200 OK\r\n\r\n",
            "http/1.1 200 OK\r\n\r\n",
            "HTTP/1.1  200 OK\r\n\r\n",
            "HTTP/1.1 099 x\r\n\r\n",
            "HTTP/1.1 600 x\r\n\r\n",
            "HTTP/1.1 20 x\r\n\r\n",
            "HTTP/1.1 2000 x\r\n\r\n",
            "HTTP/1.1 2o0 x\r\n\r\n",
            "HTTP/1.1 +20 x\r\n\r\n",
            "HTTP/1.1 200",
            "HTTP/1.1 200\r",
            "200 OK\r\n\r\n",
            "",
        ];
        for raw in lookalikes {
            assert_eq!(
                strict_status(raw.as_bytes()),
                None,
                "{raw:?} is not a status"
            );
            let peer = peer(vec![Reply::eof(raw.as_bytes())]);
            assert_eq!(
                observed(probe(&peer, SLACK, CAP)),
                (None, None),
                "{raw:?} must decide nothing"
            );
        }

        // The legacy parser really does accept them, which is why the bounded one has
        // its own: this is a statement about what pre-M3 callers run on, not a defect
        // being introduced here.
        assert_eq!(status_of(b"garbage 400\r\n\r\n"), Some(400));
        assert_eq!(status_of(b"HTTP/1.2 200 OK\r\n\r\n"), Some(200));
    }

    /// 6. Each caller's policy is the one its bead names, and `scantxoutset` is the ONE
    ///    method that gets the long deadline.
    #[test]
    fn every_policy_is_the_one_its_caller_was_given() {
        // Ingress carries the CALLER's own absolute instant through untouched: nothing
        // here derives it, and nothing here may rebuild it from a duration.
        let chosen = Instant::now() + SHORT;
        assert_eq!(
            Policy::ingress(chosen),
            Policy::Bounded {
                deadline: chosen,
                cap: 64 * 1024,
            },
            "ordered ingress runs on the CALLER's absolute deadline and 64 KiB"
        );
        // Core derives its own instant, so what a row can pin is the BUDGET it derived:
        // the deadline has to land inside the window the construction itself spanned.
        let derived = |method: &str, budget: Duration, what: &str| {
            let before = Instant::now();
            let policy = Policy::core(method);
            let after = Instant::now();
            let Policy::Bounded { deadline, cap } = policy else {
                panic!("{method}: a Core policy is bounded");
            };
            assert_eq!(cap, 16 * 1024 * 1024, "{method}");
            assert!(
                deadline >= before + budget && deadline <= after + budget,
                "{method}: {what}"
            );
        };
        derived(
            "scantxoutset",
            Duration::from_secs(600),
            "scantxoutset is the ONE long Core deadline",
        );
        // The other seven closed reads, named so a table cannot drift from the seam.
        for method in [
            "getblockchaininfo",
            "getbestblockhash",
            "gettxout",
            "getblockhash",
            "getrawtransaction",
            "estimatesmartfee",
            "getmempoolinfo",
        ] {
            derived(
                method,
                Duration::from_secs(60),
                "the ordinary Core deadline",
            );
        }
    }

    /// 6b. Legacy is what it always was, and the contrast is behavioural rather than a
    ///     claim: the SAME peer that a bounded policy refuses is answered by
    ///     `post_json`, because Legacy has neither a whole-response cap nor a deadline
    ///     over the exchange. Moving any legacy caller onto a bounded policy changes
    ///     these two outcomes.
    #[test]
    fn legacy_keeps_its_uncapped_read_to_close_and_its_per_read_timeout() {
        // No cap: a body far past the bounded ingress cap still arrives whole.
        let big = "x".repeat(64 * 1024 + 1);
        let uncapped = peer(vec![Reply::eof(&response(
            &format!("Content-Length: {}\r\n", big.len()),
            &big,
        ))]);
        let answer = post_json(uncapped.addr, "/sign", b"{}", None, SLACK).expect("legacy");
        assert_eq!((answer.status, answer.body.len()), (200, big.len()));

        // No absolute deadline: a drip whose every gap is inside the per-READ timeout
        // holds the exchange open for as long as the peer keeps dripping.
        let whole = response("Content-Length: 2\r\n", "{}");
        let gap = Duration::from_millis(40);
        let dripping = peer(vec![Reply::drip(&whole, gap)]);
        let started = Instant::now();
        let answer = post_json(dripping.addr, "/sign", b"{}", None, SLACK).expect("legacy");
        assert_eq!((answer.status, answer.body), (200, "{}".into()));
        let dripped = started.elapsed();
        assert!(
            dripped > gap * u32::try_from(whole.len()).expect("a small response") / 2,
            "the drip really did outlast a single read: {dripped:?}"
        );

        // The same drip under a bounded policy ends on the deadline instead, with
        // whatever it had already read and no completed body.
        let bounded_drip = peer(vec![Reply::drip(&whole, gap)]);
        let started = Instant::now();
        let (_, unfinished) = observed(probe(&bounded_drip, SHORT, CAP));
        assert_eq!(unfinished, None, "a bounded exchange ends the drip");
        assert!(
            started.elapsed() < dripped,
            "and ends it EARLY: {dripped:?}"
        );

        // And Legacy stays LOSSY where the bounded transport is byte-preserving: the
        // same invalid byte is U+FFFD to a legacy caller and itself to a bounded one.
        let invalid = [b"HTTP/1.1 200 OK\r\n\r\n".as_slice(), &[0xff, 0xfe]].concat();
        let lossy = peer(vec![Reply::eof(&invalid)]);
        let answer = post_json(lossy.addr, "/sign", b"{}", None, SLACK).expect("legacy");
        assert_eq!(answer.body, "\u{fffd}\u{fffd}", "legacy replaces the bytes");
        let preserved = peer(vec![Reply::eof(&invalid)]);
        let Attempt::Status {
            body: Some(bytes), ..
        } = probe(&preserved, SLACK, CAP)
        else {
            panic!("the bounded exchange must frame this reply");
        };
        assert_eq!(bytes.as_slice(), &[0xff, 0xfe], "bytes, not replacements");
    }

    /// 6c. Legacy's TWO malformed-response diagnostics stay distinct, exactly as the
    ///     pre-M3 parser made them. This is not cosmetic: the wording is the only thing
    ///     that separates "the head terminated and its first line is not a status line"
    ///     from "nothing recognizable arrived at all", and collapsing them is a silent
    ///     change to what every legacy caller reports.
    #[test]
    fn legacy_names_a_malformed_status_line_apart_from_a_malformed_response() {
        // A head that TERMINATES, whose first line carries no parseable status.
        let unreadable = peer(vec![Reply::eof(b"nonsense\r\n\r\nbody")]);
        let error = post_json(unreadable.addr, "/sign", b"{}", None, SLACK)
            .err()
            .expect("no status is not a response");
        assert_eq!(
            error.to_string(),
            format!("malformed HTTP status line from {}", unreadable.addr),
            "a terminated head with no readable status line is a STATUS-LINE defect"
        );

        // Nothing that terminates at all.
        let shapeless = peer(vec![Reply::eof(b"nonsense\r\n")]);
        let error = post_json(shapeless.addr, "/sign", b"{}", None, SLACK)
            .err()
            .expect("no status is not a response");
        assert_eq!(
            error.to_string(),
            format!("malformed HTTP response from {}", shapeless.addr),
            "and an unterminated head is a RESPONSE defect"
        );
    }

    /// 7. `NotSent` is the pre-connect answer and nothing else. The behavioural rows
    ///    cover every failure a real socket can produce after connect; the structural
    ///    one covers the arms a socket cannot be made to take, including a write that
    ///    reports no progress at all.
    #[test]
    fn no_post_connect_failure_can_claim_not_sent() {
        // Port 0 is unassignable, so this connect is refused immediately and nothing
        // is reserved that a parallel test could race for.
        let refused = SocketAddr::from(([127, 0, 0, 1], 0));
        let sent = request(refused, "/sign", Some(b"{}"), None);
        let attempt = bounded(refused, &sent, Instant::now() + SHORT, CAP, &Instant::now);
        let Attempt::NotSent(why) = attempt else {
            panic!("a refused connect is the one NotSent there is");
        };
        assert!(why.to_string().contains("connect"), "{why}");

        // Every post-connect failure, through `observed`, which panics on NotSent.
        let hangup = peer(vec![Reply::eof(b"")]);
        assert_eq!(observed(probe(&hangup, SLACK, CAP)), (None, None));
        let lookalike = peer(vec![Reply::eof(b"garbage 400\r\n\r\n")]);
        assert_eq!(observed(probe(&lookalike, SLACK, CAP)), (None, None));
        let silent = peer(vec![Reply::held(b"")]);
        assert_eq!(observed(probe(&silent, SHORT, CAP)), (None, None));

        // A request bigger than any socket buffer, to a peer that accepts and never
        // reads: the write makes partial progress and then runs out of deadline.
        let deaf = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let addr = deaf.local_addr().expect("addr");
        let held = std::thread::spawn(move || {
            let accepted = deaf.accept().expect("accept");
            std::thread::sleep(SLACK / 5);
            drop(accepted);
        });
        let huge = request(addr, "/sign", Some(&vec![b'x'; 8 * 1024 * 1024]), None);
        let attempt = bounded(addr, &huge, Instant::now() + SHORT, CAP, &Instant::now);
        let Attempt::NoStatus(why) = attempt else {
            panic!("a stalled write is NoStatus, never NotSent");
        };
        assert!(why.to_string().contains("write request"), "{why}");
        held.join().expect("join");

        // The arms a socket cannot be driven into — `Ok(0)` from `write`, an EINTR
        // restart, a `set_*_timeout` failure — are DRIVEN in class 7b below, through
        // the write loop's own seam. This last check is the cheap complement to it:
        // nothing after the connect result in `bounded` may name `NotSent` at all.
        let code = production_source();
        let body = code
            .split("fn bounded(")
            .nth(1)
            .and_then(|rest| rest.split("\nfn ").next())
            .expect("the bounded exchange");
        let after_connect = body
            .split("Err(e) => return Attempt::NotSent")
            .nth(1)
            .expect("the connect result");
        assert!(
            !after_connect.contains("NotSent"),
            "reissue authority ends at connect: {after_connect}"
        );
    }

    /// 7b. The write loop's every outcome, DRIVEN rather than argued: a write reporting
    ///     no progress at all, a partial write finished by a second call, a partial
    ///     write that then stalls, an `EINTR` restart, a timeout, a refused socket
    ///     timeout, and an expired budget. A real `TcpStream` answers `WouldBlock` or
    ///     `TimedOut` and never `Ok(0)` or `Interrupted`, so these two arms exist only
    ///     behind this seam — and they are the arms where a bounded-denial bug would
    ///     become a DOUBLE-SUBMISSION bug, because `NotSent` is reissue authority.
    #[test]
    fn every_write_loop_outcome_including_zero_progress_is_never_not_sent() {
        let addr = SocketAddr::from(([127, 0, 0, 1], 18443));
        let request = b"POST /sign HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}";
        let alive = || Some(SLACK);

        // Zero progress. The write returns `Ok(0)` forever, so treating it as anything
        // but a failure is an infinite loop, and treating it as `NotSent` is a licence
        // to send the same signed request twice.
        let mut stalled = Scripted::new(vec![Ok(0)]);
        assert_eq!(
            sent(send(&mut stalled, request, addr, &alive)).as_deref(),
            Some(format!("write request to {addr}: no progress").as_str()),
            "a write reporting no progress is a post-connect failure"
        );
        assert!(stalled.written.is_empty(), "and nothing reached the wire");

        // A PARTIAL write, finished by the next call: the loop resumes at the offset it
        // reached rather than rewriting from the start.
        let mut partial = Scripted::new(vec![Ok(4), Ok(9)]);
        assert_eq!(
            sent(send(&mut partial, request, addr, &alive)),
            None,
            "a partial write is resumed, not reported"
        );
        assert_eq!(partial.written, request, "the whole request, written once");
        assert_eq!(partial.writes, 3, "in three partial writes");

        // A partial write that then stalls: still `NoStatus`, and the bytes already
        // gone are exactly why it can never be `NotSent`.
        let mut halfway = Scripted::new(vec![Ok(4), Ok(0)]);
        assert_eq!(
            sent(send(&mut halfway, request, addr, &alive)).as_deref(),
            Some(format!("write request to {addr}: no progress").as_str())
        );
        assert_eq!(halfway.written, &request[..4], "and four bytes did go out");

        // `EINTR`: retried, not reported, and the retry re-reads the budget.
        let budget_reads = std::cell::Cell::new(0u32);
        let counted = || {
            budget_reads.set(budget_reads.get() + 1);
            Some(SLACK)
        };
        let mut interrupted = Scripted::new(vec![
            Err(std::io::Error::from(ErrorKind::Interrupted)),
            Ok(6),
            Err(std::io::Error::from(ErrorKind::Interrupted)),
        ]);
        assert_eq!(
            sent(send(&mut interrupted, request, addr, &counted)),
            None,
            "an interrupted write is retried, not reported"
        );
        assert_eq!(interrupted.written, request, "an interrupted write resumes");
        assert_eq!(
            budget_reads.get(),
            interrupted.writes,
            "the ONE budget is re-read before every write, interruptions included"
        );

        // A real socket's own failures, and a `set_write_timeout` that will not arm.
        for kind in [
            ErrorKind::TimedOut,
            ErrorKind::WouldBlock,
            ErrorKind::BrokenPipe,
        ] {
            let mut failing = Scripted::new(vec![Err(std::io::Error::from(kind))]);
            let why = sent(send(&mut failing, request, addr, &alive)).expect("a failure");
            assert!(
                why.starts_with(&format!("write request to {addr}: ")),
                "{why}"
            );
        }
        let mut unarmable = Scripted::new(Vec::new());
        unarmable.refuse_arm = Some(ErrorKind::InvalidInput);
        let why = sent(send(&mut unarmable, request, addr, &alive)).expect("a failure");
        assert!(
            why.starts_with(&format!("write request to {addr}: ")),
            "{why}"
        );
        assert!(unarmable.written.is_empty(), "and nothing was written");

        // An expired budget before the first write: a request byte may already be on
        // the wire from a PREVIOUS partial write, so this is not `NotSent` either.
        let mut untouched = Scripted::new(Vec::new());
        assert_eq!(
            sent(send(&mut untouched, request, addr, &|| None)).as_deref(),
            Some(format!("write request to {addr}: the deadline expired").as_str())
        );
        assert_eq!(untouched.writes, 0, "and it did not even try");
    }

    /// 8. The request is ONE exactly-reserved zeroizing allocation, byte-identical to
    ///    what every legacy caller has always written, and the encoded credential is
    ///    copied into it from a borrowed `&str` — there is no ordinary `String` head or
    ///    `Authorization` header value for it to be left in.
    #[test]
    fn one_exactly_reserved_zeroizing_allocation_carries_the_credential_and_the_body() {
        let addr = SocketAddr::from(([127, 0, 0, 1], 18443));
        let authorized = request(addr, "/", Some(b"{\"id\":1}"), Some("Y29va2ll"));
        assert_eq!(
            String::from_utf8_lossy(&authorized),
            "POST / HTTP/1.1\r\nHost: 127.0.0.1:18443\r\nContent-Type: application/json\r\n\
             Content-Length: 8\r\nAuthorization: Basic Y29va2ll\r\nConnection: close\r\n\r\n\
             {\"id\":1}"
        );
        // Exactly reserved: a request that grew would leave the credential and the PIN
        // in an allocation `Vec` has already abandoned, which zeroize cannot reach.
        assert_eq!(authorized.len(), authorized.capacity(), "exactly reserved");

        let plain = request(addr, "/sign", Some(b"{}"), None);
        assert_eq!(
            String::from_utf8_lossy(&plain),
            "POST /sign HTTP/1.1\r\nHost: 127.0.0.1:18443\r\nContent-Type: application/json\r\n\
             Content-Length: 2\r\nConnection: close\r\n\r\n{}"
        );
        let pull = request(addr, "/events?since=0", None, None);
        assert_eq!(
            String::from_utf8_lossy(&pull),
            "GET /events?since=0 HTTP/1.1\r\nHost: 127.0.0.1:18443\r\nConnection: close\r\n\r\n"
        );

        // Structural, because the guarantee is about what does NOT exist: the header
        // name is a byte literal this file interpolates nothing into, so no formatted
        // `String` ever holds the credential.
        let code = production_source();
        assert_eq!(
            code.matches("Authorization").count(),
            1,
            "the credential's header must appear once, as a literal"
        );
        assert!(
            code.contains("pieces.push(b\"Authorization: Basic \");"),
            "the credential's header must be pushed as a byte literal, never formatted"
        );
    }

    /// 8b. What the peer receives is what was built: the recorded request off the wire
    ///     carries the credential and the exact body, so "no ordinary copy exists" is
    ///     not bought by failing to send it.
    #[test]
    fn the_credential_and_body_reach_the_wire_from_that_one_allocation() {
        let listening = peer(vec![Reply::eof(&response("Content-Length: 2\r\n", "{}"))]);
        let sent = request(listening.addr, "/", Some(b"{\"m\":1}"), Some("Y29va2ll"));
        assert_eq!(
            observed(bounded(
                listening.addr,
                &sent,
                Instant::now() + SLACK,
                CAP,
                &Instant::now
            )),
            (Some(200), Some("{}".into()))
        );
        let seen = String::from_utf8_lossy(&listening.request()).into_owned();
        assert!(seen.contains("Authorization: Basic Y29va2ll\r\n"), "{seen}");
        assert!(seen.ends_with("\r\n\r\n{\"m\":1}"), "{seen}");
    }
}
