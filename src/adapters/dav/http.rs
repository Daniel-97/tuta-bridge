//! The server side of HTTP/1.1 that a DAV client needs, by hand.
//!
//! Requests: a request line, headers bounded in count and total size,
//! and a `Content-Length` body with a hard cap. `Transfer-Encoding`
//! request bodies are refused (`411`), so there is no chunked decoder
//! to get wrong. Responses always carry `Content-Length` (except where
//! HTTP forbids a body) and are written in one buffered flush.
//!
//! Nothing here logs; rejections are status codes the session answers
//! with a fixed body.

use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::domain::{Error, Result};

/// The text of the connection's own io error.
pub(crate) const IO_FAILED: &str = "dav connection io failed";

pub(crate) fn io_failed(_: std::io::Error) -> Error {
    Error::Network(IO_FAILED.into())
}

/// The size bounds of one request.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RequestBounds {
    pub max_head_bytes: usize,
    pub max_headers: usize,
    pub max_body_bytes: usize,
}

/// One parsed request.
#[derive(Debug)]
pub(crate) struct HttpRequest {
    pub method: String,
    /// The path of the request target: query and fragment removed, an
    /// absolute-form target reduced to its path; `*` for
    /// `OPTIONS *`. Still percent-encoded.
    pub path: String,
    /// HTTP/1.0: the connection closes after the response.
    pub http10: bool,
    /// Header names lowercased, values trimmed, in arrival order.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpRequest {
    /// The first value of the header `name` (lowercase).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    /// Whether the client asked for the connection to close.
    pub fn wants_close(&self) -> bool {
        let close = self
            .headers
            .iter()
            .filter(|(key, _)| key == "connection")
            .flat_map(|(_, value)| value.split(','))
            .any(|token| token.trim().eq_ignore_ascii_case("close"));
        close || self.http10
    }
}

/// The outcome of reading one request.
pub(crate) enum Incoming {
    Request(HttpRequest),
    /// The stream ended cleanly between requests.
    Eof,
    /// A request that cannot be served: answer with this status and
    /// close, since the stream may be out of step.
    Reject(u16),
}

enum Line {
    Bytes(Vec<u8>),
    TooLong,
    Eof,
}

/// Read one LF-terminated line (the CR, if any, removed), charging its
/// bytes to `budget`.
async fn read_line<R: AsyncBufRead + Unpin>(reader: &mut R, budget: &mut usize) -> Result<Line> {
    let mut bytes = Vec::new();
    loop {
        let available = reader.fill_buf().await.map_err(io_failed)?;
        if available.is_empty() {
            return Ok(Line::Eof);
        }
        let (chunk, done) = match available.iter().position(|byte| *byte == b'\n') {
            Some(at) => (&available[..=at], true),
            None => (available, false),
        };
        let used = chunk.len();
        if used > *budget {
            return Ok(Line::TooLong);
        }
        *budget -= used;
        bytes.extend_from_slice(chunk);
        reader.consume(used);
        if done {
            break;
        }
    }
    bytes.pop();
    if bytes.last() == Some(&b'\r') {
        bytes.pop();
    }
    Ok(Line::Bytes(bytes))
}

/// Read one request: head, then (after a `100 Continue` when the client
/// expects one) its body. `writer` is only used for that interim
/// response.
pub(crate) async fn read_request<R, W>(
    reader: &mut R,
    writer: &mut W,
    bounds: RequestBounds,
) -> Result<Incoming>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut budget = bounds.max_head_bytes;
    // RFC 9112 §2.2: ignore empty lines before the request line.
    let request_line = loop {
        match read_line(reader, &mut budget).await? {
            Line::Eof => return Ok(Incoming::Eof),
            Line::TooLong => return Ok(Incoming::Reject(431)),
            Line::Bytes(line) if line.is_empty() => continue,
            Line::Bytes(line) => break line,
        }
    };
    let Some((method, path, http10)) = parse_request_line(&request_line) else {
        return Ok(Incoming::Reject(400));
    };
    let mut headers = Vec::new();
    loop {
        let line = match read_line(reader, &mut budget).await? {
            Line::Eof => return Ok(Incoming::Reject(400)),
            Line::TooLong => return Ok(Incoming::Reject(431)),
            Line::Bytes(line) => line,
        };
        if line.is_empty() {
            break;
        }
        if headers.len() == bounds.max_headers {
            return Ok(Incoming::Reject(431));
        }
        match parse_header(&line) {
            Some(header) => headers.push(header),
            None => return Ok(Incoming::Reject(400)),
        }
    }
    let mut request = HttpRequest {
        method,
        path,
        http10,
        headers,
        body: Vec::new(),
    };

    if request.header("transfer-encoding").is_some() {
        return Ok(Incoming::Reject(
            if request.header("content-length").is_some() {
                400
            } else {
                411
            },
        ));
    }
    let length = match content_length(&request) {
        Ok(length) => length,
        Err(status) => return Ok(Incoming::Reject(status)),
    };
    if length > bounds.max_body_bytes {
        return Ok(Incoming::Reject(413));
    }
    if let Some(expect) = request.header("expect") {
        if !expect.eq_ignore_ascii_case("100-continue") {
            return Ok(Incoming::Reject(417));
        }
        if length > 0 && !request.http10 {
            writer
                .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
                .await
                .map_err(io_failed)?;
            writer.flush().await.map_err(io_failed)?;
        }
    }
    let mut body = vec![0; length];
    match reader.read_exact(&mut body).await {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Ok(Incoming::Reject(400))
        }
        Err(error) => return Err(io_failed(error)),
    }
    request.body = body;
    Ok(Incoming::Request(request))
}

/// The declared body length: 0 without the header, `Err(400)` for an
/// invalid or conflicting value, `Err(413)` for one too large to count.
fn content_length(request: &HttpRequest) -> std::result::Result<usize, u16> {
    let mut length: Option<usize> = None;
    for (_, value) in request
        .headers
        .iter()
        .filter(|(key, _)| key == "content-length")
    {
        for part in value.split(',') {
            let part = part.trim();
            if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(400);
            }
            let parsed: usize = part.parse().map_err(|_| 413u16)?;
            if length.is_some_and(|known| known != parsed) {
                return Err(400);
            }
            length = Some(parsed);
        }
    }
    Ok(length.unwrap_or(0))
}

/// `method SP target SP version`; `None` for a malformed line.
fn parse_request_line(line: &[u8]) -> Option<(String, String, bool)> {
    let line = std::str::from_utf8(line).ok()?;
    let mut parts = line.split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    if method.is_empty() || !method.bytes().all(is_tchar) {
        return None;
    }
    let http10 = match version {
        "HTTP/1.1" => false,
        "HTTP/1.0" => true,
        _ => return None,
    };
    let path = target_path(target)?;
    Some((method.to_string(), path, http10))
}

/// The path of an origin-form or absolute-form target, or `*`.
fn target_path(target: &str) -> Option<String> {
    if target.is_empty() || !target.bytes().all(|byte| byte.is_ascii_graphic()) {
        return None;
    }
    if target == "*" {
        return Some(target.to_string());
    }
    let without_scheme = target
        .strip_prefix("https://")
        .or_else(|| target.strip_prefix("http://"));
    let origin = match without_scheme {
        Some(rest) => match rest.find('/') {
            Some(at) => &rest[at..],
            None => "/",
        },
        None => target,
    };
    if !origin.starts_with('/') {
        return None;
    }
    let end = origin.find(['?', '#']).unwrap_or(origin.len());
    Some(origin[..end].to_string())
}

fn parse_header(line: &[u8]) -> Option<(String, String)> {
    // Obsolete line folding (RFC 9112 §5.2) is refused.
    if matches!(line.first(), Some(b' ' | b'\t')) {
        return None;
    }
    let colon = line.iter().position(|byte| *byte == b':')?;
    let (name, value) = (&line[..colon], &line[colon + 1..]);
    if name.is_empty() || !name.iter().copied().all(is_tchar) {
        return None;
    }
    if value
        .iter()
        .any(|byte| matches!(byte, b'\r' | b'\n' | b'\0'))
    {
        return None;
    }
    let name = String::from_utf8_lossy(name).to_ascii_lowercase();
    let value = String::from_utf8_lossy(value)
        .trim_matches([' ', '\t'])
        .to_string();
    Some((name, value))
}

fn is_tchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

/// Write one response. Headers whose name the framing owns
/// (`content-length`, `connection`, `transfer-encoding`) or whose name
/// or value could break the framing are dropped. `head` sends the
/// headers of `body` without it; 1xx, 204 and 304 carry neither a body
/// nor a `Content-Length`.
pub(crate) async fn write_response<W: AsyncWrite + Unpin>(
    writer: &mut W,
    status: u16,
    headers: &[(String, String)],
    body: &[u8],
    head: bool,
    close: bool,
) -> Result<()> {
    let mut out = format!("HTTP/1.1 {status} {}\r\n", reason_phrase(status));
    for (name, value) in headers {
        let owned = ["content-length", "connection", "transfer-encoding"]
            .iter()
            .any(|owned| name.eq_ignore_ascii_case(owned));
        let unsafe_value = value
            .bytes()
            .any(|byte| matches!(byte, b'\r' | b'\n' | b'\0'));
        if owned || unsafe_value || name.is_empty() || !name.bytes().all(is_tchar) {
            continue;
        }
        out.push_str(name);
        out.push_str(": ");
        out.push_str(value);
        out.push_str("\r\n");
    }
    let bodiless = status < 200 || status == 204 || status == 304;
    if !bodiless {
        out.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    if close {
        out.push_str("Connection: close\r\n");
    }
    out.push_str("\r\n");
    writer.write_all(out.as_bytes()).await.map_err(io_failed)?;
    if !bodiless && !head {
        writer.write_all(body).await.map_err(io_failed)?;
    }
    writer.flush().await.map_err(io_failed)
}

/// The reason phrase of the statuses this server sends.
pub fn reason_phrase(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        207 => "Multi-Status",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        411 => "Length Required",
        412 => "Precondition Failed",
        413 => "Content Too Large",
        415 => "Unsupported Media Type",
        417 => "Expectation Failed",
        422 => "Unprocessable Content",
        424 => "Failed Dependency",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        505 => "HTTP Version Not Supported",
        507 => "Insufficient Storage",
        _ => "Status",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOUNDS: RequestBounds = RequestBounds {
        max_head_bytes: 256,
        max_headers: 4,
        max_body_bytes: 16,
    };

    async fn read(input: &[u8]) -> (Incoming, Vec<u8>) {
        let mut reader = input;
        let mut written = Vec::new();
        let incoming = read_request(&mut reader, &mut written, BOUNDS)
            .await
            .unwrap();
        (incoming, written)
    }

    fn status(incoming: Incoming) -> u16 {
        match incoming {
            Incoming::Reject(status) => status,
            Incoming::Eof => 0,
            Incoming::Request(_) => 1,
        }
    }

    #[tokio::test]
    async fn parses_a_request_with_a_body() {
        let (incoming, written) = read(
            b"\r\nPROPFIND http://localhost:9932/a/b?x=1 HTTP/1.1\r\nHost: x\r\nDepth:  1 \r\nContent-Length: 3\r\n\r\nabcrest",
        )
        .await;
        let Incoming::Request(request) = incoming else {
            panic!("a request");
        };
        assert_eq!(request.method, "PROPFIND");
        assert_eq!(request.path, "/a/b");
        assert_eq!(request.header("depth"), Some("1"));
        assert_eq!(request.body, b"abc");
        assert!(!request.wants_close());
        assert!(written.is_empty());
    }

    #[tokio::test]
    async fn rejections() {
        assert_eq!(status(read(b"").await.0), 0);
        assert_eq!(status(read(b"GET / HTTP/2.0\r\n\r\n").await.0), 400);
        assert_eq!(status(read(b"GET  / HTTP/1.1\r\n\r\n").await.0), 400);
        assert_eq!(status(read(b"GET relative HTTP/1.1\r\n\r\n").await.0), 400);
        assert_eq!(
            status(read(b"GET / HTTP/1.1\r\n folded\r\n\r\n").await.0),
            400
        );
        assert_eq!(
            status(read(b"GET / HTTP/1.1\r\nBad Name: x\r\n\r\n").await.0),
            400
        );
        assert_eq!(
            status(
                read(b"PUT / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n")
                    .await
                    .0
            ),
            411
        );
        assert_eq!(
            status(
                read(b"PUT / HTTP/1.1\r\nContent-Length: 17\r\n\r\n")
                    .await
                    .0
            ),
            413
        );
        assert_eq!(
            status(
                read(b"PUT / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n")
                    .await
                    .0
            ),
            400
        );
        assert_eq!(
            status(
                read(b"PUT / HTTP/1.1\r\nContent-Length: -1\r\n\r\n")
                    .await
                    .0
            ),
            400
        );
        assert_eq!(
            status(
                read(b"PUT / HTTP/1.1\r\nContent-Length: 5\r\n\r\nab")
                    .await
                    .0
            ),
            400
        );
        assert_eq!(
            status(read(b"GET / HTTP/1.1\r\nExpect: magic\r\n\r\n").await.0),
            417
        );
        let many = b"GET / HTTP/1.1\r\na: 1\r\nb: 1\r\nc: 1\r\nd: 1\r\ne: 1\r\n\r\n";
        assert_eq!(status(read(many).await.0), 431);
        let mut long = b"GET / HTTP/1.1\r\nx: ".to_vec();
        long.extend(std::iter::repeat_n(b'a', 300));
        long.extend_from_slice(b"\r\n\r\n");
        assert_eq!(status(read(&long).await.0), 431);
    }

    #[tokio::test]
    async fn expect_continue_sends_the_interim_response() {
        let (incoming, written) =
            read(b"PUT / HTTP/1.1\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\nhi").await;
        assert!(matches!(incoming, Incoming::Request(ref r) if r.body == b"hi"));
        assert_eq!(written, b"HTTP/1.1 100 Continue\r\n\r\n");
    }

    #[tokio::test]
    async fn http10_and_connection_close() {
        let Incoming::Request(request) = read(b"GET / HTTP/1.0\r\n\r\n").await.0 else {
            panic!("a request");
        };
        assert!(request.wants_close());
        let Incoming::Request(request) =
            read(b"GET / HTTP/1.1\r\nConnection: keep-alive, Close\r\n\r\n")
                .await
                .0
        else {
            panic!("a request");
        };
        assert!(request.wants_close());
    }

    #[tokio::test]
    async fn responses_frame_and_filter_headers() {
        let mut out = Vec::new();
        let headers = vec![
            ("ETag".to_string(), "\"1\"".to_string()),
            ("Content-Length".to_string(), "99".to_string()),
            ("X-Bad".to_string(), "a\r\nInjected: 1".to_string()),
        ];
        write_response(&mut out, 200, &headers, b"body", false, true)
            .await
            .unwrap();
        assert_eq!(
            out,
            b"HTTP/1.1 200 OK\r\nETag: \"1\"\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbody"
        );
        let mut out = Vec::new();
        write_response(&mut out, 200, &[], b"body", true, false)
            .await
            .unwrap();
        assert_eq!(out, b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n");
        let mut out = Vec::new();
        write_response(&mut out, 304, &[], b"", false, false)
            .await
            .unwrap();
        assert_eq!(out, b"HTTP/1.1 304 Not Modified\r\n\r\n");
    }
}
