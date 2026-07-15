//! Minimal HTTP/1.1 server over std::net — one request per connection,
//! `Connection: close`. Hand-rolled on purpose: the /sign surface is one
//! POST route on loopback, which does not buy a server crate its keep.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use vault_proto::SignRequest;

use crate::{handle_sign, Node};

/// Cap on request line + headers, so a client that never sends the blank-line
/// terminator cannot grow the head buffer without bound.
const MAX_HEADER_BYTES: usize = 8 * 1024;
/// Cap on the request body before allocation. A `{psbt, escape_psbt, pin}`
/// pair is a few KiB of base64; 1 MiB is generous and bounds a hostile or
/// malformed `Content-Length` (a local client must not be able to OOM the node).
const MAX_BODY_BYTES: usize = 1024 * 1024;
/// Per-connection read deadline, so a stalled client cannot occupy the single
/// serve loop forever and wedge later signing requests.
const READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Serve `/sign` forever. Per-connection failures are answered (best
/// effort) and never take the node down.
pub fn serve(listener: TcpListener, node: &Node) {
    for mut stream in listener.incoming().flatten() {
        handle_connection(&mut stream, node);
    }
}

fn handle_connection(stream: &mut TcpStream, node: &Node) {
    // Bound how long a single malformed/stalled client can hold the loop.
    let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
    let (status, body) = respond(stream, node);
    let _ = write_response(stream, status, &body);
}

/// Compute the (status, JSON body) answer for one request.
fn respond(stream: &mut TcpStream, node: &Node) -> (u16, String) {
    let request = match read_request(stream) {
        Ok(request) => request,
        Err(detail) => return (400, error_body(&detail)),
    };
    // Route on (method, path). The path prefix isolates `/events` from its query
    // string (`/events?since=`); `/sign` takes no query.
    match (request.method.as_str(), request.path.as_str()) {
        ("POST", "/sign") => respond_sign(node, &request.body),
        ("GET", path) if path == "/events" || path.starts_with("/events?") => {
            respond_events(node, path)
        }
        _ => (404, error_body("only POST /sign and GET /events exist")),
    }
}

/// Handle `POST /sign`.
fn respond_sign(node: &Node, body: &[u8]) -> (u16, String) {
    let sign_request: SignRequest = match serde_json::from_slice(body) {
        Ok(sign_request) => sign_request,
        Err(e) => return (400, error_body(&format!("cannot decode request body: {e}"))),
    };
    // The node's OWN clock caps the coordinator-proposed expiry and drives
    // anti-replay pruning. A clock before the epoch is impossible in practice;
    // treating it as 0 fails safe (every commitment reads as expired).
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    match handle_sign(node, &sign_request, now) {
        Ok(response) => match serde_json::to_string(&response) {
            Ok(body) => (200, body),
            Err(e) => (500, error_body(&format!("cannot encode response: {e}"))),
        },
        Err(bad_request) => (400, error_body(&bad_request.0)),
    }
}

/// Handle `GET /events?since=<cursor>` (ADR-0002 pull API): the queued alerts
/// after `since`, plus the new cursor. A missing or unparseable `since` reads as
/// 0 (return everything) — a fresh puller has no cursor yet.
fn respond_events(node: &Node, path: &str) -> (u16, String) {
    let since = parse_since(path);
    let (alerts, cursor) = node.events(since);
    let body = serde_json::json!({ "alerts": alerts, "cursor": cursor });
    match serde_json::to_string(&body) {
        Ok(body) => (200, body),
        Err(e) => (500, error_body(&format!("cannot encode events: {e}"))),
    }
}

/// Parse the `since` cursor from a `/events?since=<n>` path. Absent or
/// unparseable ⇒ 0.
fn parse_since(path: &str) -> u64 {
    path.strip_prefix("/events?since=")
        .and_then(|value| value.parse().ok())
        .unwrap_or(0)
}

struct Request {
    method: String,
    path: String,
    body: Vec<u8>,
}

fn read_request(stream: &mut TcpStream) -> Result<Request, String> {
    // Read the head: request line + headers, up to the blank line.
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= MAX_HEADER_BYTES {
            return Err("request head exceeds maximum size".into());
        }
        match stream.read(&mut byte) {
            Ok(1) => head.push(byte[0]),
            Ok(_) => return Err("connection closed mid-request".into()),
            Err(e) => return Err(format!("read error: {e}")),
        }
    }
    let head = String::from_utf8_lossy(&head);
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let path = parts.next().unwrap_or_default().to_string();
    if method.is_empty() || path.is_empty() {
        return Err("malformed request line".into());
    }
    let mut content_length = 0usize;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                content_length = value
                    .trim()
                    .parse()
                    .map_err(|_| "bad content-length".to_string())?;
            }
        }
    }
    if content_length > MAX_BODY_BYTES {
        return Err(format!(
            "content-length {content_length} exceeds maximum {MAX_BODY_BYTES}"
        ));
    }
    let mut body = vec![0u8; content_length];
    stream
        .read_exact(&mut body)
        .map_err(|e| format!("read body: {e}"))?;
    Ok(Request { method, path, body })
}

fn write_response(stream: &mut TcpStream, status: u16, body: &str) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        _ => "Internal Server Error",
    };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()
}

fn error_body(detail: &str) -> String {
    serde_json::json!({ "error": detail }).to_string()
}

#[cfg(test)]
mod tests {
    use super::parse_since;

    #[test]
    fn parse_since_reads_the_cursor_or_defaults_to_zero() {
        assert_eq!(parse_since("/events?since=42"), 42);
        // No query, empty query, or a non-numeric cursor all read as 0.
        assert_eq!(parse_since("/events"), 0);
        assert_eq!(parse_since("/events?since="), 0);
        assert_eq!(parse_since("/events?since=abc"), 0);
    }
}
