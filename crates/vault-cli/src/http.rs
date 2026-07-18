//! Minimal HTTP/1.1 POST client over std::net (`Connection: close`).
//! Talks to two loopback servers only — vault-node /sign and bitcoind's
//! JSON-RPC — which does not buy an HTTP crate its keep.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;
use zeroize::Zeroizing;

pub type Error = Box<dyn std::error::Error + Send + Sync + 'static>;

pub struct Response {
    pub status: u16,
    pub body: String,
}

pub fn post_json(
    addr: SocketAddr,
    path: &str,
    body: &[u8],
    basic_auth: Option<&str>,
    timeout: Duration,
) -> Result<Response, Error> {
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))
        .map_err(|e| format!("connect {addr}: {e}"))?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let auth_header = match basic_auth {
        Some(credentials) => format!("Authorization: Basic {credentials}\r\n"),
        None => String::new(),
    };
    let head = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {addr}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         {auth_header}Connection: close\r\n\r\n",
        body.len()
    );
    // This generic client also carries the demo's plaintext PIN. Keep the full
    // serialized request in a zeroizing allocation and write it by reference, so
    // success and every socket-error path wipe the application-owned copy.
    let mut request = Zeroizing::new(Vec::with_capacity(head.len() + body.len()));
    request.extend_from_slice(head.as_bytes());
    request.extend_from_slice(body);
    stream.write_all(&request)?;
    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .map_err(|e| format!("read response from {addr}: {e}"))?;
    parse_response(&raw, addr)
}

fn parse_response(raw: &[u8], addr: SocketAddr) -> Result<Response, Error> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| format!("malformed HTTP response from {addr}"))?;
    let head = String::from_utf8_lossy(&raw[..split]);
    let status: u16 = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| format!("malformed HTTP status line from {addr}"))?;
    let body = String::from_utf8_lossy(&raw[split + 4..]).into_owned();
    Ok(Response { status, body })
}
