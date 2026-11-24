//! One DAV connection: HTTP/1.1 keep-alive, Basic auth against the
//! bridge password, and the protocol-agnostic part of WebDAV.
//!
//! Every request must carry valid credentials (`401` otherwise). A
//! request without credentials costs nothing — clients probe that way —
//! but each wrong one waits `login_failure_delay` while holding the
//! listener-wide login gate, and the connection closes after
//! `max_login_attempts` of them, the IMAP/POP3/SMTP posture. A
//! connection that has not authenticated within `pre_auth_timeout`
//! closes.
//!
//! Hygiene: log lines carry the handler's fixed label, fixed text and
//! counters only — never a user name, a password, a path or a body.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use secrecy::SecretString;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, BufWriter};
use tokio::sync::Mutex;
use tokio::time::{sleep, timeout, timeout_at, Instant};
use zeroize::Zeroizing;

use super::handler::{
    etag_matches, DavHandler, DavMethod, DavRequest, DavResponse, Depth, WellKnown, TEXT_PLAIN,
};
use super::http::{read_request, write_response, HttpRequest, Incoming, RequestBounds};
use super::xml::{parse_propfind, parse_report};
use crate::adapters::stall::StallGuard;
use crate::domain::{Error, Result};
use crate::ports::imap_backend::ImapBackend;

/// The bounds of one DAV connection.
#[derive(Clone)]
pub struct DavLimits {
    /// How long a connection may go without one authenticated request,
    /// measured from the handshake.
    pub pre_auth_timeout: Duration,
    /// Keep-alive: how long to wait for the next request.
    pub idle_timeout: Duration,
    /// How long one request may take to arrive once it has started.
    pub request_timeout: Duration,
    /// How long one write may make no progress before the connection
    /// ends: a client that stops reading does not pin its slot.
    pub write_timeout: Duration,
    /// The delay every failed login waits out, one at a time across
    /// every listener sharing `login_gate`.
    pub login_failure_delay: Duration,
    /// Failed logins tolerated per connection before it is closed.
    pub max_login_attempts: u32,
    /// Serializes failed-login delays across connections and protocols.
    pub login_gate: Arc<Mutex<()>>,
    /// The largest request body accepted (`413` beyond).
    pub max_body_bytes: usize,
    /// The largest request line plus headers accepted (`431` beyond).
    pub max_head_bytes: usize,
    /// The most header fields accepted (`431` beyond).
    pub max_headers: usize,
}

impl Default for DavLimits {
    fn default() -> Self {
        Self {
            pre_auth_timeout: Duration::from_secs(60),
            idle_timeout: Duration::from_secs(120),
            request_timeout: Duration::from_secs(30),
            write_timeout: Duration::from_secs(60),
            login_failure_delay: Duration::from_secs(3),
            max_login_attempts: 3,
            login_gate: Arc::new(Mutex::new(())),
            max_body_bytes: 1024 * 1024,
            max_head_bytes: 16 * 1024,
            max_headers: 64,
        }
    }
}

/// The methods every handler serves through the generic layer.
const BASE_METHODS: &str = "OPTIONS, GET, HEAD, PROPFIND, REPORT";

/// Methods that would change something and that no feature serves:
/// always `403`. `PUT` and `DELETE` are handed to the handler, which
/// answers the same fixed refusal when it does not write.
const WRITE_METHODS: &[&str] = &[
    "PROPPATCH",
    "MKCOL",
    "MKCALENDAR",
    "MOVE",
    "COPY",
    "LOCK",
    "UNLOCK",
    "POST",
    "ACL",
];

/// Methods HTTP defines that this server does not allow (`405`); any
/// other unknown method is `501`.
const DISALLOWED_METHODS: &[&str] = &["TRACE", "CONNECT", "PATCH"];

const REALM: &str = "Basic realm=\"tuta-bridge\", charset=\"UTF-8\"";

enum Auth {
    /// Valid credentials; the header value that carried them.
    Valid(Zeroizing<String>),
    /// No `Authorization` header.
    Missing,
    /// Wrong or malformed credentials.
    Failed,
}

/// Serve one DAV connection over `stream` until the client closes it,
/// asks to close, idles out, or fails to log in too often.
pub async fn run_dav_session<S>(
    stream: S,
    auth: Arc<dyn ImapBackend>,
    handler: Arc<dyn DavHandler>,
    limits: DavLimits,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let label = handler.label();
    let (reader, writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);
    let mut writer = BufWriter::new(StallGuard::new(writer, limits.write_timeout));
    let bounds = RequestBounds {
        max_head_bytes: limits.max_head_bytes,
        max_headers: limits.max_headers,
        max_body_bytes: limits.max_body_bytes,
    };
    let pre_auth_deadline = Instant::now() + limits.pre_auth_timeout;
    let mut authenticated: Option<Zeroizing<String>> = None;
    let mut ever_authenticated = false;
    let mut failed_logins = 0u32;
    let mut served = 0u64;
    loop {
        // Wait for the first byte of the next request.
        let idle_deadline = Instant::now() + limits.idle_timeout;
        let deadline = if ever_authenticated {
            idle_deadline
        } else {
            idle_deadline.min(pre_auth_deadline)
        };
        match timeout_at(deadline, reader.fill_buf()).await {
            Err(_) => break,
            Ok(Err(_)) => break,
            Ok(Ok([])) => break,
            Ok(Ok(_)) => {}
        }
        let request = match timeout(
            limits.request_timeout,
            read_request(&mut reader, &mut writer, bounds),
        )
        .await
        {
            Err(_) => {
                respond_fixed(&mut writer, 408, "request timeout", true).await?;
                break;
            }
            Ok(result) => match result? {
                Incoming::Eof => break,
                Incoming::Reject(status) => {
                    tracing::debug!(protocol = label, status, "dav request rejected");
                    respond_fixed(&mut writer, status, rejection_text(status), true).await?;
                    break;
                }
                Incoming::Request(request) => request,
            },
        };
        let mut close = request.wants_close();

        match authenticate(&*auth, &request, authenticated.as_ref()).await? {
            Auth::Valid(header) => {
                authenticated = Some(header);
                ever_authenticated = true;
            }
            Auth::Missing => {
                authenticated = None;
                let close = close || (!ever_authenticated && Instant::now() >= pre_auth_deadline);
                respond_unauthorized(&mut writer, close).await?;
                if close {
                    break;
                }
                continue;
            }
            Auth::Failed => {
                authenticated = None;
                failed_logins += 1;
                tracing::warn!(
                    protocol = label,
                    attempt = failed_logins,
                    "dav login failed"
                );
                {
                    let _gate = limits.login_gate.lock().await;
                    sleep(limits.login_failure_delay).await;
                }
                let close = close || failed_logins >= limits.max_login_attempts;
                respond_unauthorized(&mut writer, close).await?;
                if close {
                    break;
                }
                continue;
            }
        }

        let head = request.method == "HEAD";
        let response = dispatch(&*handler, request).await;
        served += 1;
        // A failing backend is not retried on this connection.
        if matches!(response.status, 500 | 503) {
            close = true;
        }
        write_response(
            &mut writer,
            response.status,
            &response.headers,
            &response.body,
            head,
            close,
        )
        .await?;
        if close {
            break;
        }
    }
    tracing::debug!(protocol = label, requests = served, "dav session ended");
    writer.shutdown().await.ok();
    Ok(())
}

/// Check the request's Basic credentials. The same header value that
/// already passed on this connection is not checked again.
async fn authenticate(
    auth: &dyn ImapBackend,
    request: &HttpRequest,
    known: Option<&Zeroizing<String>>,
) -> Result<Auth> {
    let Some(header) = request.header("authorization") else {
        return Ok(Auth::Missing);
    };
    if known.is_some_and(|known| known.as_str() == header) {
        return Ok(Auth::Valid(Zeroizing::new(header.to_string())));
    }
    let Some((scheme, encoded)) = header.split_once(' ') else {
        return Ok(Auth::Failed);
    };
    if !scheme.eq_ignore_ascii_case("basic") {
        return Ok(Auth::Failed);
    }
    let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded.trim()) else {
        return Ok(Auth::Failed);
    };
    let decoded = Zeroizing::new(decoded);
    let Ok(text) = std::str::from_utf8(&decoded) else {
        return Ok(Auth::Failed);
    };
    let Some((user, password)) = text.split_once(':') else {
        return Ok(Auth::Failed);
    };
    let password = SecretString::new(password.to_string().into_boxed_str());
    if auth.login(user, &password).await? {
        Ok(Auth::Valid(Zeroizing::new(header.to_string())))
    } else {
        Ok(Auth::Failed)
    }
}

/// Answer one authenticated request: the generic parts here, the reads
/// and writes through the handler.
async fn dispatch(handler: &dyn DavHandler, request: HttpRequest) -> DavResponse {
    let method = request.method.as_str();
    if WRITE_METHODS.contains(&method) {
        return DavResponse::text(403, "forbidden: this server is read-only");
    }
    if method == "OPTIONS" {
        return options(handler);
    }
    if DISALLOWED_METHODS.contains(&method) {
        return DavResponse::text(405, "method not allowed").with_header("Allow", allow(handler));
    }
    if !matches!(
        method,
        "GET" | "HEAD" | "PROPFIND" | "REPORT" | "PUT" | "DELETE"
    ) {
        return DavResponse::text(501, "method not implemented");
    }
    if let Some(service) = well_known(&request.path) {
        return match handler.well_known(service) {
            Some(target) => {
                DavResponse::text(301, "moved permanently").with_header("Location", target)
            }
            None => DavResponse::not_found(),
        };
    }
    if request.path == "*" {
        return DavResponse::text(400, "bad request");
    }

    let depth = match request.header("depth").map(parse_depth) {
        None => None,
        Some(Some(depth)) => Some(depth),
        Some(None) => return DavResponse::text(400, "invalid depth header"),
    };
    let parsed = match method {
        "PROPFIND" => parse_propfind(&request.body).map(DavMethod::Propfind),
        "REPORT" => parse_report(&request.body).map(|report| DavMethod::Report(Box::new(report))),
        "PUT" => Ok(DavMethod::Put),
        "DELETE" => Ok(DavMethod::Delete),
        _ => Ok(DavMethod::Get),
    };
    let Ok(parsed) = parsed else {
        return DavResponse::text(400, "malformed xml body");
    };
    let if_none_match = request.header("if-none-match").map(str::to_string);
    let conditional = matches!(parsed, DavMethod::Get);
    let dav_request = DavRequest {
        method: parsed,
        path: request.path,
        depth,
        if_none_match,
        headers: request
            .headers
            .into_iter()
            .filter(|(name, _)| name != "authorization")
            .collect(),
        body: request.body,
    };
    let response = match handler.handle(&dav_request).await {
        Ok(response) => response,
        Err(Error::Network(_)) => {
            tracing::warn!(protocol = handler.label(), "dav handler unavailable");
            return DavResponse::text(503, "temporarily unavailable")
                .with_header("Retry-After", "30");
        }
        Err(_) => {
            tracing::warn!(protocol = handler.label(), "dav handler failed");
            return DavResponse::text(500, "internal error");
        }
    };
    if conditional && response.status == 200 {
        if let (Some(condition), Some(etag)) = (
            dav_request.if_none_match.as_deref(),
            response.header("etag"),
        ) {
            if etag_matches(condition, etag) {
                let etag = etag.to_string();
                return DavResponse::new(304).with_etag(&etag);
            }
        }
    }
    response
}

fn options(handler: &dyn DavHandler) -> DavResponse {
    let mut dav = String::from("1, 3");
    for class in handler.compliance_classes() {
        dav.push_str(", ");
        dav.push_str(class);
    }
    DavResponse::new(200)
        .with_header("DAV", dav)
        .with_header("Allow", allow(handler))
}

fn allow(handler: &dyn DavHandler) -> String {
    let mut allow = String::from(BASE_METHODS);
    for method in handler.extra_methods() {
        allow.push_str(", ");
        allow.push_str(method);
    }
    allow
}

fn well_known(path: &str) -> Option<WellKnown> {
    match path.trim_end_matches('/') {
        "/.well-known/carddav" => Some(WellKnown::CardDav),
        "/.well-known/caldav" => Some(WellKnown::CalDav),
        _ => None,
    }
}

fn parse_depth(value: &str) -> Option<Depth> {
    match value.trim() {
        "0" => Some(Depth::Zero),
        "1" => Some(Depth::One),
        other if other.eq_ignore_ascii_case("infinity") => Some(Depth::Infinity),
        _ => None,
    }
}

fn rejection_text(status: u16) -> &'static str {
    match status {
        411 => "chunked request bodies are not accepted",
        413 => "request body too large",
        417 => "expectation not supported",
        431 => "request header too large",
        _ => "bad request",
    }
}

async fn respond_fixed<W: AsyncWrite + Unpin>(
    writer: &mut W,
    status: u16,
    text: &'static str,
    close: bool,
) -> Result<()> {
    let response = DavResponse::text(status, text);
    write_response(
        writer,
        status,
        &response.headers,
        &response.body,
        false,
        close,
    )
    .await
}

async fn respond_unauthorized<W: AsyncWrite + Unpin>(writer: &mut W, close: bool) -> Result<()> {
    let headers = vec![
        ("WWW-Authenticate".to_string(), REALM.to_string()),
        ("Content-Type".to_string(), TEXT_PLAIN.to_string()),
    ];
    write_response(
        writer,
        401,
        &headers,
        b"authentication required\n",
        false,
        close,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn etag_matching_is_weak_and_handles_lists() {
        assert!(etag_matches("\"a\"", "\"a\""));
        assert!(etag_matches("W/\"a\"", "\"a\""));
        assert!(etag_matches("\"x\", \"a\"", "W/\"a\""));
        assert!(etag_matches("*", "\"a\""));
        assert!(!etag_matches("\"b\"", "\"a\""));
    }

    #[test]
    fn depth_values() {
        assert_eq!(parse_depth("0"), Some(Depth::Zero));
        assert_eq!(parse_depth(" 1 "), Some(Depth::One));
        assert_eq!(parse_depth("Infinity"), Some(Depth::Infinity));
        assert_eq!(parse_depth("2"), None);
    }

    #[test]
    fn well_known_paths() {
        assert_eq!(well_known("/.well-known/carddav"), Some(WellKnown::CardDav));
        assert_eq!(well_known("/.well-known/caldav/"), Some(WellKnown::CalDav));
        assert_eq!(well_known("/.well-known/other"), None);
    }
}
