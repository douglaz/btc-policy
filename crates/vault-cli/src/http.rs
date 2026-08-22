//! Minimal HTTP/1.1 client over std::net (`Connection: close`).
//! Talks to two loopback servers only — vault-node (`/sign`, `/events`,
//! `/pending`, `/channel`) and bitcoind's JSON-RPC — which does not buy an HTTP crate its
//! keep.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;
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
    /// A status line came back. `body` is `None` when the read failed after it —
    /// the status is still KNOWN, which is what keeps a 400 an explicit
    /// no-delivery even when its body never arrives.
    Status { status: u16, body: Option<String> },
}

fn post_head(addr: SocketAddr, path: &str, len: usize, basic_auth: Option<&str>) -> String {
    let auth_header = match basic_auth {
        Some(credentials) => format!("Authorization: Basic {credentials}\r\n"),
        None => String::new(),
    };
    format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {addr}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {len}\r\n\
         {auth_header}Connection: close\r\n\r\n"
    )
}

pub fn post_json(
    addr: SocketAddr,
    path: &str,
    body: &[u8],
    basic_auth: Option<&str>,
    timeout: Duration,
) -> Result<Response, Error> {
    let head = post_head(addr, path, body.len(), basic_auth);
    collapse(addr, attempt(addr, &head, body, timeout))
}

/// `POST` reporting the phase it failed in. Only the stage-1 ingress client uses
/// it; it owns no key and no retry policy of its own.
pub fn post_json_attempt(addr: SocketAddr, path: &str, body: &[u8], timeout: Duration) -> Attempt {
    let head = post_head(addr, path, body.len(), None);
    attempt(addr, &head, body, timeout)
}

/// The phase-free view every other caller wants.
fn collapse(addr: SocketAddr, attempt: Attempt) -> Result<Response, Error> {
    match attempt {
        Attempt::NotSent(e) | Attempt::NoStatus(e) => Err(e),
        Attempt::Status { status, body } => match body {
            Some(body) => Ok(Response { status, body }),
            None => Err(format!("truncated HTTP {status} response from {addr}").into()),
        },
    }
}

/// `GET` with no body — the node's `/events` alert pull (ADR-0002). No auth
/// header: `/events` is loopback-only like the rest of the node surface.
pub fn get_json(addr: SocketAddr, path: &str, timeout: Duration) -> Result<Response, Error> {
    let head = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {addr}\r\n\
         Connection: close\r\n\r\n"
    );
    collapse(addr, attempt(addr, &head, &[], timeout))
}

/// One connect/write/read-to-close exchange. Both verbs differ only in the request
/// line and headers, so the socket handling lives here once.
fn attempt(addr: SocketAddr, head: &str, body: &[u8], timeout: Duration) -> Attempt {
    let connect = || -> Result<TcpStream, Error> {
        let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))
            .map_err(|e| format!("connect {addr}: {e}"))?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        Ok(stream)
    };
    let mut stream = match connect() {
        Ok(stream) => stream,
        Err(e) => return Attempt::NotSent(e),
    };
    // This generic client also carries the demo's plaintext PIN. Keep the full
    // serialized request in a zeroizing allocation and write it by reference, so
    // success and every socket-error path wipe the application-owned copy.
    let mut serialized = Zeroizing::new(Vec::with_capacity(head.len() + body.len()));
    serialized.extend_from_slice(head.as_bytes());
    serialized.extend_from_slice(body);
    if let Err(e) = stream.write_all(&serialized) {
        return Attempt::NoStatus(format!("write request to {addr}: {e}").into());
    }
    let mut raw = Vec::new();
    let read = stream.read_to_end(&mut raw);
    match parse_response(&raw, addr) {
        Ok(response) => Attempt::Status {
            status: response.status,
            // A header block that parsed says nothing about the body FINISHING.
            body: read.is_ok().then_some(response.body),
        },
        // A parse failure with a readable status line is still a decided status.
        Err(e) => match status_of(&raw) {
            Some(status) => Attempt::Status { status, body: None },
            None => Attempt::NoStatus(match read {
                Err(io) => format!("read response from {addr}: {io}").into(),
                Ok(_) => e,
            }),
        },
    }
}

/// The status code of the response's first line, if it has one.
fn status_of(raw: &[u8]) -> Option<u16> {
    let end = raw.windows(2).position(|w| w == b"\r\n")?;
    String::from_utf8_lossy(&raw[..end])
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

fn parse_response(raw: &[u8], addr: SocketAddr) -> Result<Response, Error> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| format!("malformed HTTP response from {addr}"))?;
    let status = status_of(raw).ok_or_else(|| format!("malformed HTTP status line from {addr}"))?;
    let body = String::from_utf8_lossy(&raw[split + 4..]).into_owned();
    Ok(Response { status, body })
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
