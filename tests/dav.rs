//! Integration contract for the shared DAV layer: HTTP/1.1 framing and
//! keep-alive, Basic auth against the bridge password (failure delay,
//! the shared login gate, lockout), the generic answers (OPTIONS,
//! well-known redirects, read-only writes, unknown methods, 304), and
//! PROPFIND/REPORT routed to a scripted handler — over an in-memory
//! duplex, plus one round through the TLS accept loop.

mod support;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use tokio::io::{split, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;
use tokio::time::Instant;
use tuta_bridge::adapters::dav::xml::{props, MultiStatusEntry, PropName, PropRequest, CARDDAV_NS};
use tuta_bridge::adapters::dav::{
    run_dav_session, serve_dav, DavHandler, DavLimits, DavMethod, DavRequest, DavResponse,
    DavServeLimits, Depth, WellKnown,
};
use tuta_bridge::adapters::imap::server::{ensure_certificate, tls_acceptor, Accept};
use tuta_bridge::domain::{Error, Result};
use tuta_bridge::ports::imap_backend::ImapBackend;

use support::FakeImapBackend;

const USER: &str = "user@example.invalid";
const PASSWORD: &str = "hunter2";

fn basic(user: &str, password: &str) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"));
    format!("Basic {encoded}")
}

fn good_auth() -> String {
    basic(USER, PASSWORD)
}

// ---------------------------------------------------------------------------
// The scripted handler
// ---------------------------------------------------------------------------

const ITEM: &str = "/card/book/a.vcf";
const ITEM_ETAG: &str = "\"etag-a\"";
const VCARD: &str = "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:A\r\nEND:VCARD\r\n";

#[derive(Default)]
struct FakeHandler {
    seen: Mutex<Vec<DavRequest>>,
}

impl FakeHandler {
    fn seen(&self) -> Vec<DavRequest> {
        self.seen.lock().unwrap().clone()
    }

    fn item_props() -> Vec<tuta_bridge::adapters::dav::xml::XmlNode> {
        vec![
            props::getetag(ITEM_ETAG),
            props::getcontenttype("text/vcard; charset=utf-8"),
            props::resourcetype(false, &[]),
        ]
    }
}

#[async_trait]
impl DavHandler for FakeHandler {
    fn label(&self) -> &'static str {
        "carddav"
    }

    fn compliance_classes(&self) -> &'static [&'static str] {
        &["addressbook"]
    }

    fn well_known(&self, service: WellKnown) -> Option<String> {
        match service {
            WellKnown::CardDav => Some("/card/".into()),
            WellKnown::CalDav => None,
        }
    }

    async fn handle(&self, request: &DavRequest) -> Result<DavResponse> {
        self.seen.lock().unwrap().push(request.clone());
        if request.path == "/fail" {
            return Err(Error::Network("secret detail".into()));
        }
        if request.path == "/broken" {
            return Err(Error::Storage("secret detail".into()));
        }
        match &request.method {
            DavMethod::Get if request.path == ITEM => {
                Ok(DavResponse::ok("text/vcard; charset=utf-8", VCARD.into()).with_etag(ITEM_ETAG))
            }
            DavMethod::Get => Ok(DavResponse::not_found()),
            DavMethod::Propfind(wanted) => {
                let collection = vec![
                    props::displayname("Tom & Jerry <friends>"),
                    props::resourcetype(true, &[PropName::carddav("addressbook")]),
                    props::getctag("ctag-1"),
                ];
                let mut entries = vec![MultiStatusEntry::for_request(
                    "/card/book/",
                    wanted,
                    collection,
                )];
                if request.depth == Some(Depth::One) {
                    entries.push(MultiStatusEntry::for_request(
                        ITEM,
                        wanted,
                        Self::item_props(),
                    ));
                }
                Ok(DavResponse::multistatus(&entries, None))
            }
            DavMethod::Report(report) => {
                assert!(report.is(CARDDAV_NS, "addressbook-multiget"));
                let wanted = report.props.clone().unwrap_or(PropRequest::PropName);
                let entries: Vec<_> = report
                    .hrefs
                    .iter()
                    .map(|href| {
                        if href == ITEM {
                            MultiStatusEntry::for_request(href.clone(), &wanted, Self::item_props())
                        } else {
                            MultiStatusEntry::status(href.clone(), 404)
                        }
                    })
                    .collect();
                Ok(DavResponse::multistatus(&entries, None))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The wire
// ---------------------------------------------------------------------------

struct Response {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl Response {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

struct Wire<R, W> {
    reader: BufReader<R>,
    writer: W,
}

impl<R, W> Wire<R, W>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    async fn send_raw(&mut self, bytes: &[u8]) {
        self.writer.write_all(bytes).await.unwrap();
        self.writer.flush().await.unwrap();
    }

    /// Send one request; `headers` are full lines without CRLF.
    async fn send(&mut self, method: &str, path: &str, headers: &[&str], body: &str) {
        let mut request = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\n");
        for header in headers {
            request.push_str(header);
            request.push_str("\r\n");
        }
        if !body.is_empty() {
            request.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
        request.push_str("\r\n");
        request.push_str(body);
        self.send_raw(request.as_bytes()).await;
    }

    async fn line(&mut self) -> String {
        let mut buf = Vec::new();
        let read = self.reader.read_until(b'\n', &mut buf).await.unwrap();
        assert!(read > 0, "the server closed the stream unexpectedly");
        let text = String::from_utf8(buf).unwrap();
        assert!(text.ends_with("\r\n"), "lines end with CRLF: {text:?}");
        text.trim_end_matches("\r\n").to_string()
    }

    /// Read one response; `head` responses carry no body.
    async fn response_of(&mut self, head: bool) -> Response {
        let status_line = self.line().await;
        let mut parts = status_line.splitn(3, ' ');
        assert_eq!(parts.next(), Some("HTTP/1.1"));
        let status: u16 = parts.next().unwrap().parse().unwrap();
        let mut headers = Vec::new();
        loop {
            let line = self.line().await;
            if line.is_empty() {
                break;
            }
            let (name, value) = line.split_once(": ").unwrap();
            headers.push((name.to_string(), value.to_string()));
        }
        let mut response = Response {
            status,
            headers,
            body: String::new(),
        };
        if !head {
            if let Some(length) = response.header("Content-Length") {
                let mut body = vec![0; length.parse().unwrap()];
                self.reader.read_exact(&mut body).await.unwrap();
                response.body = String::from_utf8(body).unwrap();
            }
        }
        response
    }

    async fn response(&mut self) -> Response {
        self.response_of(false).await
    }

    async fn request(
        &mut self,
        method: &str,
        path: &str,
        headers: &[&str],
        body: &str,
    ) -> Response {
        self.send(method, path, headers, body).await;
        self.response().await
    }

    async fn expect_eof(&mut self) {
        let mut probe = [0u8; 1];
        assert_eq!(self.reader.read(&mut probe).await.unwrap(), 0);
    }
}

type DuplexWire = Wire<
    tokio::io::ReadHalf<tokio::io::DuplexStream>,
    tokio::io::WriteHalf<tokio::io::DuplexStream>,
>;

fn fast_limits() -> DavLimits {
    DavLimits {
        login_failure_delay: Duration::from_millis(1),
        ..DavLimits::default()
    }
}

fn spawn_with(
    handler: Arc<FakeHandler>,
    limits: DavLimits,
) -> (DuplexWire, tokio::task::JoinHandle<Result<()>>) {
    let backend = Arc::new(FakeImapBackend::new(USER, PASSWORD));
    let (client, server) = tokio::io::duplex(256 * 1024);
    let session = tokio::spawn(run_dav_session(
        server,
        backend as Arc<dyn ImapBackend>,
        handler as Arc<dyn DavHandler>,
        limits,
    ));
    let (reader, writer) = split(client);
    (
        Wire {
            reader: BufReader::new(reader),
            writer,
        },
        session,
    )
}

fn spawn() -> (
    Arc<FakeHandler>,
    DuplexWire,
    tokio::task::JoinHandle<Result<()>>,
) {
    let handler = Arc::new(FakeHandler::default());
    let (wire, session) = spawn_with(Arc::clone(&handler), fast_limits());
    (handler, wire, session)
}

fn auth_header() -> String {
    format!("Authorization: {}", good_auth())
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

#[tokio::test]
async fn requests_without_credentials_get_a_basic_challenge_and_cost_nothing() {
    let (handler, mut wire, session) = spawn();
    for _ in 0..5 {
        let response = wire.request("PROPFIND", "/card/", &[], "").await;
        assert_eq!(response.status, 401);
        assert_eq!(
            response.header("WWW-Authenticate"),
            Some("Basic realm=\"tuta-bridge\", charset=\"UTF-8\"")
        );
        assert_eq!(response.body, "authentication required\n");
        assert!(response.header("Connection").is_none());
    }
    // Still open: the client may now send credentials.
    let auth = auth_header();
    let response = wire.request("OPTIONS", "/card/", &[&auth], "").await;
    assert_eq!(response.status, 200);
    assert!(
        handler.seen().is_empty(),
        "nothing reached the handler unauthenticated"
    );
    drop(wire);
    session.await.unwrap().unwrap();
}

#[tokio::test]
async fn failed_logins_are_bounded_and_close_the_connection() {
    let (handler, mut wire, session) = spawn();
    let wrong = format!("Authorization: {}", basic(USER, "wrong"));
    for attempt in 1..=3 {
        let response = wire.request("PROPFIND", "/card/", &[&wrong], "").await;
        assert_eq!(response.status, 401);
        let closing = response.header("Connection") == Some("close");
        assert_eq!(closing, attempt == 3);
    }
    wire.expect_eof().await;
    session.await.unwrap().unwrap();
    assert!(handler.seen().is_empty());
}

#[tokio::test]
async fn malformed_credentials_count_as_failures() {
    let (_, mut wire, session) = spawn();
    for header in [
        "Authorization: Bearer abc",
        "Authorization: Basic !!!",
        "Authorization: Basic dXNlcg==", // "user", no colon
    ] {
        let response = wire.request("GET", ITEM, &[header], "").await;
        assert_eq!(response.status, 401);
    }
    wire.expect_eof().await;
    session.await.unwrap().unwrap();
}

#[tokio::test]
async fn a_failed_login_waits_out_the_delay_holding_the_shared_gate() {
    let gate = Arc::new(tokio::sync::Mutex::new(()));
    let limits = DavLimits {
        login_failure_delay: Duration::from_millis(150),
        login_gate: Arc::clone(&gate),
        ..DavLimits::default()
    };
    let (mut wire, session) = spawn_with(Arc::new(FakeHandler::default()), limits);
    let wrong = format!("Authorization: {}", basic(USER, "wrong"));

    // Another listener holds the gate: the answer waits for it.
    let held = gate.lock().await;
    wire.send("GET", ITEM, &[&wrong], "").await;
    let early = tokio::time::timeout(Duration::from_millis(100), wire.line()).await;
    assert!(early.is_err(), "no answer while the gate is held");
    drop(held);
    let started = Instant::now();
    let status = wire.line().await;
    assert_eq!(status, "HTTP/1.1 401 Unauthorized");
    assert!(started.elapsed() >= Duration::from_millis(100));
    drop(wire);
    session.await.unwrap().unwrap();
}

#[tokio::test]
async fn the_user_name_is_checked_too() {
    let (_, mut wire, session) = spawn();
    let other = format!(
        "Authorization: {}",
        basic("other@example.invalid", PASSWORD)
    );
    assert_eq!(wire.request("GET", ITEM, &[&other], "").await.status, 401);
    let auth = auth_header();
    assert_eq!(wire.request("GET", ITEM, &[&auth], "").await.status, 200);
    drop(wire);
    session.await.unwrap().unwrap();
}

// ---------------------------------------------------------------------------
// Generic answers
// ---------------------------------------------------------------------------

#[tokio::test]
async fn options_lists_compliance_classes_and_methods() {
    let (handler, mut wire, session) = spawn();
    let auth = auth_header();
    let response = wire.request("OPTIONS", "/card/", &[&auth], "").await;
    assert_eq!(response.status, 200);
    assert_eq!(response.header("DAV"), Some("1, 3, addressbook"));
    assert_eq!(
        response.header("Allow"),
        Some("OPTIONS, GET, HEAD, PROPFIND, REPORT")
    );
    assert_eq!(response.header("Content-Length"), Some("0"));
    let response = wire.request("OPTIONS", "*", &[&auth], "").await;
    assert_eq!(response.status, 200);
    assert!(handler.seen().is_empty());
    drop(wire);
    session.await.unwrap().unwrap();
}

#[tokio::test]
async fn well_known_redirects_to_the_handler_root() {
    let (_, mut wire, session) = spawn();
    let auth = auth_header();
    let response = wire
        .request("PROPFIND", "/.well-known/carddav", &[&auth, "Depth: 0"], "")
        .await;
    assert_eq!(response.status, 301);
    assert_eq!(response.header("Location"), Some("/card/"));
    let response = wire
        .request("GET", "/.well-known/carddav/", &[&auth], "")
        .await;
    assert_eq!(response.status, 301);
    let response = wire
        .request("GET", "/.well-known/caldav", &[&auth], "")
        .await;
    assert_eq!(response.status, 404);
    drop(wire);
    session.await.unwrap().unwrap();
}

#[tokio::test]
async fn every_write_method_is_forbidden_with_a_fixed_body() {
    let (handler, mut wire, session) = spawn();
    let auth = auth_header();
    for method in [
        "PUT",
        "DELETE",
        "PROPPATCH",
        "MKCOL",
        "MKCALENDAR",
        "MOVE",
        "COPY",
        "LOCK",
        "UNLOCK",
        "POST",
    ] {
        let response = wire
            .request(method, ITEM, &[&auth, "Content-Type: text/vcard"], VCARD)
            .await;
        assert_eq!(response.status, 403, "{method}");
        assert_eq!(response.body, "forbidden: this server is read-only\n");
        assert_eq!(
            response.header("Content-Type"),
            Some("text/plain; charset=utf-8")
        );
    }
    assert!(handler.seen().is_empty());
    drop(wire);
    session.await.unwrap().unwrap();
}

#[tokio::test]
async fn unknown_and_disallowed_methods() {
    let (handler, mut wire, session) = spawn();
    let auth = auth_header();
    let response = wire.request("BREW", "/card/", &[&auth], "").await;
    assert_eq!(response.status, 501);
    let response = wire.request("TRACE", "/card/", &[&auth], "").await;
    assert_eq!(response.status, 405);
    assert_eq!(
        response.header("Allow"),
        Some("OPTIONS, GET, HEAD, PROPFIND, REPORT")
    );
    assert!(handler.seen().is_empty());
    drop(wire);
    session.await.unwrap().unwrap();
}

#[tokio::test]
async fn if_none_match_turns_a_matching_get_into_304() {
    let (handler, mut wire, session) = spawn();
    let auth = auth_header();
    let response = wire.request("GET", ITEM, &[&auth], "").await;
    assert_eq!(response.status, 200);
    assert_eq!(response.header("ETag"), Some(ITEM_ETAG));
    assert_eq!(response.body, VCARD);

    let condition = format!("If-None-Match: {ITEM_ETAG}");
    let response = wire.request("GET", ITEM, &[&auth, &condition], "").await;
    assert_eq!(response.status, 304);
    assert_eq!(response.header("ETag"), Some(ITEM_ETAG));
    assert!(response.header("Content-Length").is_none());
    assert!(response.body.is_empty());

    let response = wire
        .request("GET", ITEM, &[&auth, "If-None-Match: \"stale\""], "")
        .await;
    assert_eq!(response.status, 200);

    // The handler saw the condition, and never the credentials.
    let seen = handler.seen();
    assert_eq!(seen[1].if_none_match.as_deref(), Some(ITEM_ETAG));
    assert!(seen
        .iter()
        .all(|request| request.header("authorization").is_none()));
    drop(wire);
    session.await.unwrap().unwrap();
}

#[tokio::test]
async fn head_sends_the_headers_of_get_without_the_body() {
    let (handler, mut wire, session) = spawn();
    let auth = auth_header();
    wire.send("HEAD", ITEM, &[&auth], "").await;
    let response = wire.response_of(true).await;
    assert_eq!(response.status, 200);
    assert_eq!(
        response.header("Content-Length"),
        Some(VCARD.len().to_string().as_str())
    );
    // The next response follows immediately: no body bytes in between.
    let response = wire.request("GET", "/card/missing.vcf", &[&auth], "").await;
    assert_eq!(response.status, 404);
    assert_eq!(handler.seen()[0].method, DavMethod::Get);
    drop(wire);
    session.await.unwrap().unwrap();
}

// ---------------------------------------------------------------------------
// PROPFIND and REPORT
// ---------------------------------------------------------------------------

const PROPFIND_BODY: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<d:propfind xmlns:d="DAV:" xmlns:cs="http://calendarserver.org/ns/">
  <d:prop><d:displayname/><d:resourcetype/><d:getetag/><cs:getctag/></d:prop>
</d:propfind>"#;

#[tokio::test]
async fn propfind_depth_0_and_1_reach_the_handler() {
    let (handler, mut wire, session) = spawn();
    let auth = auth_header();
    let response = wire
        .request(
            "PROPFIND",
            "/card/book/",
            &[&auth, "Depth: 0"],
            PROPFIND_BODY,
        )
        .await;
    assert_eq!(response.status, 207);
    assert_eq!(
        response.header("Content-Type"),
        Some("application/xml; charset=utf-8")
    );
    assert_eq!(response.body.matches("<d:response>").count(), 1);
    assert!(response
        .body
        .contains("<d:displayname>Tom &amp; Jerry &lt;friends&gt;</d:displayname>"));
    assert!(response.body.contains("<cs:getctag>ctag-1</cs:getctag>"));
    // The collection has no getetag: a 404 propstat.
    assert!(response.body.contains(
        "<d:propstat><d:prop><d:getetag/></d:prop><d:status>HTTP/1.1 404 Not Found</d:status></d:propstat>"
    ));

    let response = wire
        .request(
            "PROPFIND",
            "/card/book/",
            &[&auth, "Depth: 1"],
            PROPFIND_BODY,
        )
        .await;
    assert_eq!(response.status, 207);
    assert_eq!(response.body.matches("<d:response>").count(), 2);
    assert!(response
        .body
        .contains("<d:href>/card/book/a.vcf</d:href><d:propstat><d:prop><d:resourcetype/><d:getetag>&quot;etag-a&quot;</d:getetag></d:prop>"));

    let seen = handler.seen();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].depth, Some(Depth::Zero));
    assert_eq!(seen[1].depth, Some(Depth::One));
    assert_eq!(seen[0].path, "/card/book/");
    let DavMethod::Propfind(PropRequest::Prop(names)) = &seen[0].method else {
        panic!("a prop list");
    };
    assert_eq!(names.len(), 4);
    assert_eq!(names[3], PropName::calserver("getctag"));
    drop(wire);
    session.await.unwrap().unwrap();
}

#[tokio::test]
async fn an_empty_propfind_is_allprop_and_bad_input_is_400() {
    let (handler, mut wire, session) = spawn();
    let auth = auth_header();
    let response = wire.request("PROPFIND", "/card/book/", &[&auth], "").await;
    assert_eq!(response.status, 207);
    assert_eq!(
        handler.seen()[0].method,
        DavMethod::Propfind(PropRequest::AllProp {
            include: Vec::new()
        })
    );
    assert_eq!(handler.seen()[0].depth, None);

    let response = wire
        .request("PROPFIND", "/card/book/", &[&auth], "<d:propfind")
        .await;
    assert_eq!(response.status, 400);
    assert_eq!(response.body, "malformed xml body\n");
    let response = wire
        .request("PROPFIND", "/card/book/", &[&auth, "Depth: 2"], "")
        .await;
    assert_eq!(response.status, 400);
    assert_eq!(handler.seen().len(), 1);
    drop(wire);
    session.await.unwrap().unwrap();
}

#[tokio::test]
async fn multiget_report_is_parsed_and_missing_hrefs_are_404() {
    let (handler, mut wire, session) = spawn();
    let auth = auth_header();
    let body = r#"<?xml version="1.0" encoding="utf-8"?>
<C:addressbook-multiget xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav">
  <D:prop><D:getetag/><C:address-data/></D:prop>
  <D:href>/card/book/a.vcf</D:href>
  <D:href>/card/book/gone&amp;away.vcf</D:href>
</C:addressbook-multiget>"#;
    let response = wire
        .request("REPORT", "/card/book/", &[&auth, "Depth: 1"], body)
        .await;
    assert_eq!(response.status, 207);
    assert!(response.body.contains(
        "<d:response><d:href>/card/book/gone&amp;away.vcf</d:href><d:status>HTTP/1.1 404 Not Found</d:status></d:response>"
    ));
    assert!(response
        .body
        .contains("<d:getetag>&quot;etag-a&quot;</d:getetag>"));
    assert!(response.body.contains(
        "<d:propstat><d:prop><card:address-data/></d:prop><d:status>HTTP/1.1 404 Not Found</d:status></d:propstat>"
    ));

    let seen = handler.seen();
    let DavMethod::Report(report) = &seen[0].method else {
        panic!("a report");
    };
    assert_eq!(
        report.hrefs,
        vec!["/card/book/a.vcf", "/card/book/gone&away.vcf"]
    );

    // A REPORT needs a body.
    let response = wire.request("REPORT", "/card/book/", &[&auth], "").await;
    assert_eq!(response.status, 400);
    drop(wire);
    session.await.unwrap().unwrap();
}

#[tokio::test]
async fn handler_failures_answer_fixed_text_and_close() {
    let (_, mut wire, session) = spawn();
    let auth = auth_header();
    let response = wire.request("GET", "/fail", &[&auth], "").await;
    assert_eq!(response.status, 503);
    assert_eq!(response.header("Retry-After"), Some("30"));
    assert_eq!(response.body, "temporarily unavailable\n");
    assert_eq!(response.header("Connection"), Some("close"));
    wire.expect_eof().await;
    session.await.unwrap().unwrap();

    let (_, mut wire, session) = spawn();
    let response = wire.request("GET", "/broken", &[&auth], "").await;
    assert_eq!(response.status, 500);
    assert_eq!(response.body, "internal error\n");
    assert!(!response.body.contains("secret"));
    wire.expect_eof().await;
    session.await.unwrap().unwrap();
}

// ---------------------------------------------------------------------------
// HTTP framing
// ---------------------------------------------------------------------------

#[tokio::test]
async fn keep_alive_serves_two_requests_then_honours_connection_close() {
    let (handler, mut wire, session) = spawn();
    let auth = auth_header();
    // Both requests pipelined in one write.
    let one = format!("GET {ITEM} HTTP/1.1\r\nHost: x\r\n{auth}\r\n\r\n");
    let two = format!("GET {ITEM} HTTP/1.1\r\nHost: x\r\n{auth}\r\nConnection: close\r\n\r\n");
    wire.send_raw(format!("{one}{two}").as_bytes()).await;
    let first = wire.response().await;
    assert_eq!(first.status, 200);
    assert!(first.header("Connection").is_none());
    let second = wire.response().await;
    assert_eq!(second.status, 200);
    assert_eq!(second.header("Connection"), Some("close"));
    wire.expect_eof().await;
    session.await.unwrap().unwrap();
    assert_eq!(handler.seen().len(), 2);
}

#[tokio::test]
async fn an_oversized_body_is_413_and_closes() {
    let handler = Arc::new(FakeHandler::default());
    let limits = DavLimits {
        max_body_bytes: 64,
        ..fast_limits()
    };
    let (mut wire, session) = spawn_with(Arc::clone(&handler), limits);
    let auth = auth_header();
    let body = "x".repeat(65);
    let response = wire.request("PROPFIND", "/card/", &[&auth], &body).await;
    assert_eq!(response.status, 413);
    assert_eq!(response.header("Connection"), Some("close"));
    wire.expect_eof().await;
    session.await.unwrap().unwrap();
    assert!(handler.seen().is_empty());
}

#[tokio::test]
async fn a_chunked_body_is_411_and_closes() {
    let (handler, mut wire, session) = spawn();
    let auth = auth_header();
    let response = wire
        .request(
            "REPORT",
            "/card/",
            &[&auth, "Transfer-Encoding: chunked"],
            "",
        )
        .await;
    assert_eq!(response.status, 411);
    assert_eq!(response.body, "chunked request bodies are not accepted\n");
    wire.expect_eof().await;
    session.await.unwrap().unwrap();
    assert!(handler.seen().is_empty());
}

#[tokio::test]
async fn a_garbage_request_line_is_400_and_closes() {
    let (_, mut wire, session) = spawn();
    wire.send_raw(b"hello there\r\n\r\n").await;
    let response = wire.response().await;
    assert_eq!(response.status, 400);
    wire.expect_eof().await;
    session.await.unwrap().unwrap();
}

#[tokio::test(start_paused = true)]
async fn an_idle_connection_is_closed() {
    let (_, mut wire, session) = spawn();
    let auth = auth_header();
    assert_eq!(wire.request("GET", ITEM, &[&auth], "").await.status, 200);
    tokio::time::sleep(DavLimits::default().idle_timeout + Duration::from_secs(1)).await;
    wire.expect_eof().await;
    session.await.unwrap().unwrap();
}

#[tokio::test(start_paused = true)]
async fn an_unauthenticated_connection_is_closed_after_the_pre_auth_timeout() {
    let (_, mut wire, session) = spawn();
    assert_eq!(wire.request("GET", ITEM, &[], "").await.status, 401);
    tokio::time::sleep(DavLimits::default().pre_auth_timeout + Duration::from_secs(1)).await;
    wire.expect_eof().await;
    session.await.unwrap().unwrap();
}

// ---------------------------------------------------------------------------
// The TLS accept loop
// ---------------------------------------------------------------------------

struct ChannelListener(mpsc::UnboundedReceiver<tokio::io::DuplexStream>);

impl Accept for ChannelListener {
    type Stream = tokio::io::DuplexStream;

    async fn accept(&mut self) -> std::io::Result<tokio::io::DuplexStream> {
        match self.0.recv().await {
            Some(stream) => Ok(stream),
            None => std::future::pending().await,
        }
    }
}

/// A test-only verifier that accepts any server certificate; production
/// code never disables verification.
#[derive(Debug)]
struct AcceptAll(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AcceptAll {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[tokio::test]
async fn serve_dav_answers_over_tls() {
    let dir = tempfile::tempdir().unwrap();
    let (cert_pem, key_pem) = ensure_certificate(dir.path()).unwrap();
    let tls = tls_acceptor(&cert_pem, &key_pem).unwrap();
    let (incoming, accepted) = mpsc::unbounded_channel();
    let handler = Arc::new(FakeHandler::default());
    tokio::spawn(serve_dav(
        ChannelListener(accepted),
        tls,
        Arc::new(FakeImapBackend::new(USER, PASSWORD)) as Arc<dyn ImapBackend>,
        Arc::clone(&handler) as Arc<dyn DavHandler>,
        DavServeLimits::default(),
    ));

    let (client, server) = tokio::io::duplex(64 * 1024);
    incoming.send(server).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAll(provider)))
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let server_name = rustls::pki_types::ServerName::try_from("localhost".to_string()).unwrap();
    let tls_client = connector.connect(server_name, client).await.unwrap();
    let (reader, writer) = split(tls_client);
    let mut wire = Wire {
        reader: BufReader::new(reader),
        writer,
    };
    let auth = auth_header();
    let response = wire.request("GET", ITEM, &[&auth], "").await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, VCARD);
    assert_eq!(handler.seen().len(), 1);
}
