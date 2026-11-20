//! The seam a DAV feature (CardDAV, CalDAV) implements.
//!
//! The generic session authenticates the request, answers everything
//! protocol-agnostic itself (`OPTIONS`, `/.well-known/*`, writes,
//! unknown methods, `HEAD`, `If-None-Match` on `GET`), parses
//! `PROPFIND`/`REPORT` bodies, and hands the handler only an
//! authenticated read: `GET`, `PROPFIND` or `REPORT`.

use async_trait::async_trait;

use super::xml::{render_multistatus, MultiStatusEntry, PropRequest, Report};
use crate::domain::Result;

/// The `Depth` header (RFC 4918 §10.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Depth {
    Zero,
    One,
    Infinity,
}

/// The `/.well-known` service a client is discovering (RFC 6764).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WellKnown {
    CardDav,
    CalDav,
}

/// The read a handler serves, with its parsed body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DavMethod {
    /// `GET`, and `HEAD` too: the session strips the body of a `HEAD`.
    Get,
    /// `PROPFIND`; an empty body arrives as allprop.
    Propfind(PropRequest),
    /// `REPORT`, any report name.
    Report(Box<Report>),
}

/// One authenticated request.
#[derive(Debug, Clone)]
pub struct DavRequest {
    pub method: DavMethod,
    /// The request path: absolute, query removed, still percent-encoded
    /// exactly as the client sent it (compare it with the hrefs the
    /// handler hands out). It may contain ids: never log it.
    pub path: String,
    /// `None` when the client sent no `Depth`: RFC 4918 reads that as
    /// infinity for `PROPFIND` and RFC 3253 as `0` for `REPORT`. A
    /// handler that does not serve infinity answers `403` or treats it
    /// as `1`.
    pub depth: Option<Depth>,
    /// The raw `If-None-Match` value. The session already turns a `200`
    /// `GET` whose `ETag` matches it into `304`; a handler may use it to
    /// skip rendering.
    pub if_none_match: Option<String>,
    /// Every other request header, names lowercased (`prefer`,
    /// `content-type`, ...). `authorization` is never included.
    pub headers: Vec<(String, String)>,
    /// The raw body (already parsed into `method` for PROPFIND/REPORT).
    pub body: Vec<u8>,
}

impl DavRequest {
    /// The first value of the header `name` (lowercase).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
}

/// A handler's answer. The session adds `Content-Length` and
/// `Connection`; header names or values with CR/LF are dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DavResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// The fixed `text/plain` content type of every generic body.
pub const TEXT_PLAIN: &str = "text/plain; charset=utf-8";
/// The content type of a multistatus body.
pub const XML_CONTENT_TYPE: &str = "application/xml; charset=utf-8";

impl DavResponse {
    /// A bare status with no body.
    pub fn new(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    /// `200` with a body of `content_type`.
    pub fn ok(content_type: &str, body: Vec<u8>) -> Self {
        Self::new(200)
            .with_header("Content-Type", content_type)
            .with_body(body)
    }

    /// `207 Multi-Status` rendered from `entries`.
    pub fn multistatus(entries: &[MultiStatusEntry], sync_token: Option<&str>) -> Self {
        Self::new(207)
            .with_header("Content-Type", XML_CONTENT_TYPE)
            .with_body(render_multistatus(entries, sync_token))
    }

    /// A status with a fixed `text/plain` body. `text` must be fixed
    /// text: never a path, a name or an id.
    pub fn text(status: u16, text: &'static str) -> Self {
        Self::new(status)
            .with_header("Content-Type", TEXT_PLAIN)
            .with_body(format!("{text}\n").into_bytes())
    }

    /// `404` with a fixed body.
    pub fn not_found() -> Self {
        Self::text(404, "not found")
    }

    /// `403` with a fixed body.
    pub fn forbidden() -> Self {
        Self::text(403, "forbidden")
    }

    /// The same response with one more header.
    pub fn with_header(mut self, name: &str, value: impl Into<String>) -> Self {
        self.headers.push((name.to_string(), value.into()));
        self
    }

    /// The same response with an `ETag` (`etag` is the full quoted
    /// value, `"abc"`).
    pub fn with_etag(self, etag: &str) -> Self {
        self.with_header("ETag", etag)
    }

    /// The same response with this body.
    pub fn with_body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }

    /// The first value of the header `name`, case-insensitively.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// A DAV feature: what is served under its root.
#[async_trait]
pub trait DavHandler: Send + Sync {
    /// A fixed label for log lines (`"carddav"`, `"caldav"`).
    fn label(&self) -> &'static str {
        "dav"
    }

    /// Compliance classes appended to `DAV: 1, 3` in `OPTIONS`
    /// (`"addressbook"`, `"calendar-access"`).
    fn compliance_classes(&self) -> &'static [&'static str] {
        &[]
    }

    /// Methods appended to the generic `Allow` list (`OPTIONS, GET,
    /// HEAD, PROPFIND, REPORT`).
    fn extra_methods(&self) -> &'static [&'static str] {
        &[]
    }

    /// Where `/.well-known/carddav` or `/.well-known/caldav` redirects
    /// (`301`), usually the principal or the collection root; `None`
    /// answers `404`.
    fn well_known(&self, service: WellKnown) -> Option<String>;

    /// Serve one authenticated read. Errors become a fixed-text `503`
    /// (`Error::Network`) or `500` (anything else); the error text is
    /// never sent or logged.
    async fn handle(&self, request: &DavRequest) -> Result<DavResponse>;
}
