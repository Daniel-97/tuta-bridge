//! CardDAV listener contract: the Thunderbird flow (discovery, PROPFIND
//! with ctag/ETags, multiget), GET with a stable strong ETag and `304`,
//! `addressbook-query`, `sync-collection`, read-only writes — through
//! `run_dav_session` over an in-memory duplex, against an in-memory
//! SQLite cache and a fake contact source. Plus the address book's
//! event processing.

mod support;

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use tokio::io::{split, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tuta_bridge::adapters::carddav::vcard::{render_vcard, vcard_etag};
use tuta_bridge::adapters::carddav::CardDavHandler;
use tuta_bridge::adapters::dav::{run_dav_session, DavHandler, DavLimits};
use tuta_bridge::adapters::sqlite_state::SqliteStateStore;
use tuta_bridge::app::contacts::ContactBook;
use tuta_bridge::domain::{
    ContactCard, ContactField, ContactFieldKind, EntityEvent, EntityOperation, Error, EventBatch,
    CONTACT_TYPE_ID, MAIL_TYPE_ID, TUTANOTA_APP,
};
use tuta_bridge::ports::contact_source::ContactSource;
use tuta_bridge::ports::imap_backend::ImapBackend;
use tuta_bridge::ports::state_store::StateStore;

use support::{FakeContactSource, FakeImapBackend, FakeStateStore};

const USER: &str = "user@example.invalid";
const PASSWORD: &str = "hunter2";
const LIST: &str = "contact-list";

fn card(element_id: &str, first: &str, last: &str, email: &str) -> ContactCard {
    ContactCard {
        list_id: LIST.into(),
        element_id: element_id.into(),
        first_name: first.into(),
        last_name: last.into(),
        emails: vec![ContactField {
            kind: ContactFieldKind::Work,
            value: email.into(),
        }],
        ..ContactCard::default()
    }
}

fn three_cards() -> Vec<ContactCard> {
    vec![
        card("c1", "Ada", "Lovelace", "ada@example.invalid"),
        card("c2", "Alan", "Turing", "alan@example.invalid"),
        card("c3", "Grace", "Hopper", "grace@navy.invalid"),
    ]
}

async fn book_with(cards: Vec<ContactCard>) -> (Arc<ContactBook>, Arc<FakeContactSource>) {
    let state = Arc::new(SqliteStateStore::open_in_memory().await.unwrap());
    let account = state.upsert_account(USER).await.unwrap();
    let source = Arc::new(FakeContactSource::new(cards));
    let book = ContactBook::new(
        account,
        state as Arc<dyn StateStore>,
        Arc::clone(&source) as Arc<dyn ContactSource>,
    )
    .unwrap();
    (Arc::new(book), source)
}

fn contact_batch(events: &[(&str, EntityOperation)]) -> EventBatch {
    EventBatch {
        batch_id: "batch".into(),
        owner_group_id: "contact-group".into(),
        application_types_hash: "hash".into(),
        events: events
            .iter()
            .map(|(element, operation)| EntityEvent {
                application: TUTANOTA_APP.into(),
                type_id: CONTACT_TYPE_ID,
                list_id: LIST.into(),
                element_id: element.to_string(),
                operation: *operation,
            })
            .collect(),
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

struct Wire {
    reader: BufReader<tokio::io::ReadHalf<tokio::io::DuplexStream>>,
    writer: tokio::io::WriteHalf<tokio::io::DuplexStream>,
}

impl Wire {
    async fn line(&mut self) -> String {
        let mut buf = Vec::new();
        let read = self.reader.read_until(b'\n', &mut buf).await.unwrap();
        assert!(read > 0, "the server closed the stream unexpectedly");
        String::from_utf8(buf)
            .unwrap()
            .trim_end_matches("\r\n")
            .to_string()
    }

    async fn request(
        &mut self,
        method: &str,
        path: &str,
        headers: &[&str],
        body: &str,
    ) -> Response {
        let credentials =
            base64::engine::general_purpose::STANDARD.encode(format!("{USER}:{PASSWORD}"));
        let mut request = format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic {credentials}\r\n"
        );
        for header in headers {
            request.push_str(header);
            request.push_str("\r\n");
        }
        if !body.is_empty() {
            request.push_str(&format!(
                "Content-Type: application/xml\r\nContent-Length: {}\r\n",
                body.len()
            ));
        }
        request.push_str("\r\n");
        request.push_str(body);
        self.writer.write_all(request.as_bytes()).await.unwrap();
        self.writer.flush().await.unwrap();

        let status_line = self.line().await;
        let status: u16 = status_line.split(' ').nth(1).unwrap().parse().unwrap();
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
        if let Some(length) = response.header("Content-Length") {
            let mut body = vec![0; length.parse().unwrap()];
            self.reader.read_exact(&mut body).await.unwrap();
            response.body = String::from_utf8(body).unwrap();
        }
        response
    }
}

fn spawn(book: Arc<ContactBook>) -> Wire {
    let backend = Arc::new(FakeImapBackend::new(USER, PASSWORD));
    let handler = Arc::new(CardDavHandler::new(book));
    let (client, server) = tokio::io::duplex(1024 * 1024);
    tokio::spawn(run_dav_session(
        server,
        backend as Arc<dyn ImapBackend>,
        handler as Arc<dyn DavHandler>,
        DavLimits {
            login_failure_delay: Duration::from_millis(1),
            ..DavLimits::default()
        },
    ));
    let (reader, writer) = split(client);
    Wire {
        reader: BufReader::new(reader),
        writer,
    }
}

/// The text of the first `<name>…</name>` (any prefix) after `from`.
fn element_text<'a>(body: &'a str, local: &str) -> Option<&'a str> {
    let open = format!(":{local}>");
    let start = body.find(&open)? + open.len();
    let end = body[start..].find("</")? + start;
    Some(&body[start..end])
}

/// The `(href, getetag)` pairs of a multistatus, in order; responses
/// without an ETag are left out.
fn hrefs_with_etags(body: &str) -> Vec<(String, String)> {
    body.split("<d:response>")
        .skip(1)
        .filter_map(|response| {
            let href = element_text(response, "href")?.to_string();
            let etag = element_text(response, "getetag")?.replace("&quot;", "\"");
            Some((href, etag))
        })
        .collect()
}

const THUNDERBIRD_LISTING: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<propfind xmlns="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav" xmlns:cs="http://calendarserver.org/ns/">
  <prop><resourcetype/><getetag/><cs:getctag/></prop>
</propfind>"#;

fn multiget(hrefs: &[&str]) -> String {
    let hrefs: String = hrefs
        .iter()
        .map(|href| format!("<d:href>{href}</d:href>"))
        .collect();
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<card:addressbook-multiget xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav">
  <d:prop><d:getetag/><card:address-data/></d:prop>{hrefs}
</card:addressbook-multiget>"#
    )
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

#[tokio::test]
async fn discovery_leads_from_the_root_to_the_address_book() {
    let (book, _) = book_with(three_cards()).await;
    let mut wire = spawn(book);

    let options = wire.request("OPTIONS", "/", &[], "").await;
    assert_eq!(options.status, 200);
    assert!(options.header("DAV").unwrap().contains("addressbook"));

    let well_known = wire
        .request("PROPFIND", "/.well-known/carddav", &[], "")
        .await;
    assert_eq!(well_known.status, 301);
    assert_eq!(well_known.header("Location"), Some("/principal/"));

    let body = r#"<propfind xmlns="DAV:"><prop><current-user-principal/></prop></propfind>"#;
    let root = wire.request("PROPFIND", "/", &["Depth: 0"], body).await;
    assert_eq!(root.status, 207);
    assert!(root
        .body
        .contains("<d:current-user-principal><d:href>/principal/</d:href>"));

    let body = r#"<propfind xmlns="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav"><prop><card:addressbook-home-set/></prop></propfind>"#;
    let principal = wire
        .request("PROPFIND", "/principal/", &["Depth: 0"], body)
        .await;
    assert_eq!(principal.status, 207);
    assert!(principal
        .body
        .contains("<card:addressbook-home-set><d:href>/addressbooks/</d:href>"));

    let body = r#"<propfind xmlns="DAV:"><prop><resourcetype/><displayname/><current-user-privilege-set/></prop></propfind>"#;
    let home = wire
        .request("PROPFIND", "/addressbooks/", &["Depth: 1"], body)
        .await;
    assert_eq!(home.status, 207);
    assert!(home
        .body
        .contains("<d:href>/addressbooks/contacts/</d:href>"));
    assert!(home.body.contains("<card:addressbook/>"));
    assert!(home.body.contains("Tuta contacts"));
    // Read only: no write privilege is advertised.
    assert!(home.body.contains("<d:read/>"));
    assert!(!home.body.contains("<d:write"));

    let missing = wire
        .request("PROPFIND", "/nowhere/", &["Depth: 0"], "")
        .await;
    assert_eq!(missing.status, 404);
}

#[tokio::test]
async fn the_book_advertises_its_reports_and_address_data_type() {
    let (book, _) = book_with(three_cards()).await;
    let mut wire = spawn(book);
    let body = r#"<propfind xmlns="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav"><prop><supported-report-set/><card:supported-address-data/><sync-token/><card:max-image-size/></prop></propfind>"#;
    let response = wire
        .request("PROPFIND", "/addressbooks/contacts/", &["Depth: 0"], body)
        .await;
    assert_eq!(response.status, 207);
    assert!(response.body.contains("<card:addressbook-multiget/>"));
    assert!(response.body.contains("<card:addressbook-query/>"));
    assert!(response.body.contains("<d:sync-collection/>"));
    assert!(response
        .body
        .contains("content-type=\"text/vcard\" version=\"4.0\""));
    assert!(response.body.contains("urn:tuta-bridge:carddav:sync:"));
    // An unknown property is reported missing.
    assert!(response.body.contains("404 Not Found"));
}

// ---------------------------------------------------------------------------
// The Thunderbird flow
// ---------------------------------------------------------------------------

#[tokio::test]
async fn thunderbird_lists_etags_then_multigets_the_cards() {
    let (book, source) = book_with(three_cards()).await;
    let mut wire = spawn(Arc::clone(&book));

    // The listing loads the book once (it was never loaded) and answers
    // from the cache: ctag on the collection, an ETag per card.
    let listing = wire
        .request(
            "PROPFIND",
            "/addressbooks/contacts/",
            &["Depth: 1"],
            THUNDERBIRD_LISTING,
        )
        .await;
    assert_eq!(listing.status, 207);
    let ctag = element_text(&listing.body, "getctag").unwrap().to_string();
    let cards = hrefs_with_etags(&listing.body);
    assert_eq!(
        cards
            .iter()
            .map(|(href, _)| href.as_str())
            .collect::<Vec<_>>(),
        [
            "/addressbooks/contacts/c1.vcf",
            "/addressbooks/contacts/c2.vcf",
            "/addressbooks/contacts/c3.vcf"
        ]
    );
    assert_eq!(source.full_loads(), 1);
    // No body was rendered for the listing beyond the cache fill.
    assert!(!listing.body.contains("BEGIN:VCARD"));

    // The multiget returns the vCards with the same ETags, and a 404 for
    // an href that is not in the book.
    let response = wire
        .request(
            "REPORT",
            "/addressbooks/contacts/",
            &["Depth: 1"],
            &multiget(&[
                "/addressbooks/contacts/c1.vcf",
                "/addressbooks/contacts/c3.vcf",
                "/addressbooks/contacts/zz.vcf",
            ]),
        )
        .await;
    assert_eq!(response.status, 207);
    assert!(response.body.contains("FN:Ada Lovelace"));
    assert!(response.body.contains("FN:Grace Hopper"));
    assert!(!response.body.contains("FN:Alan Turing"));
    assert!(response.body.contains("UID:tuta-contact-c1"));
    assert!(response.body.contains(
        "<d:href>/addressbooks/contacts/zz.vcf</d:href><d:status>HTTP/1.1 404 Not Found</d:status>"
    ));
    let fetched = hrefs_with_etags(&response.body);
    assert_eq!(fetched.len(), 2);
    for (href, etag) in &fetched {
        assert!(
            cards.contains(&(href.clone(), etag.clone())),
            "{href} keeps its ETag"
        );
    }

    // A second sync: nothing changed, so the ctag and every ETag stay,
    // even across a full reload.
    book.reload().await.unwrap();
    let again = wire
        .request(
            "PROPFIND",
            "/addressbooks/contacts/",
            &["Depth: 1"],
            THUNDERBIRD_LISTING,
        )
        .await;
    assert_eq!(element_text(&again.body, "getctag").unwrap(), ctag);
    assert_eq!(hrefs_with_etags(&again.body), cards);

    // A changed contact changes its ETag and the ctag, and nothing else.
    source.put(card("c2", "Alan", "Turing", "turing@example.invalid"));
    book.reload().await.unwrap();
    let changed = wire
        .request(
            "PROPFIND",
            "/addressbooks/contacts/",
            &["Depth: 1"],
            THUNDERBIRD_LISTING,
        )
        .await;
    assert_ne!(element_text(&changed.body, "getctag").unwrap(), ctag);
    let after = hrefs_with_etags(&changed.body);
    assert_eq!(after[0], cards[0]);
    assert_ne!(after[1], cards[1]);
    assert_eq!(after[2], cards[2]);
}

#[tokio::test]
async fn propfind_depth_infinity_is_served_as_depth_one() {
    let (book, _) = book_with(three_cards()).await;
    let mut wire = spawn(book);
    for depth in [&["Depth: infinity"][..], &[][..]] {
        let response = wire
            .request(
                "PROPFIND",
                "/addressbooks/contacts/",
                depth,
                THUNDERBIRD_LISTING,
            )
            .await;
        assert_eq!(response.status, 207);
        assert_eq!(hrefs_with_etags(&response.body).len(), 3);
    }
    let zero = wire
        .request(
            "PROPFIND",
            "/addressbooks/contacts/",
            &["Depth: 0"],
            THUNDERBIRD_LISTING,
        )
        .await;
    assert!(hrefs_with_etags(&zero.body).is_empty());
    assert!(element_text(&zero.body, "getctag").is_some());
}

#[tokio::test]
async fn get_serves_one_vcard_with_a_stable_strong_etag() {
    let cards = three_cards();
    let expected = render_vcard(&cards[0]);
    let (book, _) = book_with(cards).await;
    book.reload().await.unwrap();
    let mut wire = spawn(book);

    let response = wire
        .request("GET", "/addressbooks/contacts/c1.vcf", &[], "")
        .await;
    assert_eq!(response.status, 200);
    assert_eq!(
        response.header("Content-Type"),
        Some("text/vcard; charset=utf-8")
    );
    assert_eq!(response.body, expected);
    let etag = response.header("ETag").unwrap().to_string();
    assert_eq!(etag, vcard_etag(&expected));
    assert!(!etag.starts_with("W/"));

    let again = wire
        .request("GET", "/addressbooks/contacts/c1.vcf", &[], "")
        .await;
    assert_eq!(again.header("ETag"), Some(etag.as_str()));

    let header = format!("If-None-Match: {etag}");
    let cached = wire
        .request("GET", "/addressbooks/contacts/c1.vcf", &[&header], "")
        .await;
    assert_eq!(cached.status, 304);

    let missing = wire
        .request("GET", "/addressbooks/contacts/nope.vcf", &[], "")
        .await;
    assert_eq!(missing.status, 404);
}

#[tokio::test]
async fn writes_are_refused() {
    let (book, source) = book_with(three_cards()).await;
    let mut wire = spawn(book);
    let vcard = "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:X\r\nEND:VCARD\r\n";
    for method in ["PUT", "DELETE", "PROPPATCH", "MKCOL"] {
        let response = wire
            .request(method, "/addressbooks/contacts/c1.vcf", &[], vcard)
            .await;
        assert_eq!(response.status, 403, "{method}");
        // A refused write may close the connection: start a fresh one.
        wire = spawn(book_with(three_cards()).await.0);
    }
    assert_eq!(source.full_loads() + source.single_loads(), 0);
}

// ---------------------------------------------------------------------------
// addressbook-query
// ---------------------------------------------------------------------------

#[tokio::test]
async fn query_without_filter_lists_every_card() {
    let (book, _) = book_with(three_cards()).await;
    let mut wire = spawn(book);
    let body = r#"<card:addressbook-query xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav"><d:prop><d:getetag/></d:prop></card:addressbook-query>"#;
    let response = wire
        .request("REPORT", "/addressbooks/contacts/", &["Depth: 1"], body)
        .await;
    assert_eq!(response.status, 207);
    assert_eq!(hrefs_with_etags(&response.body).len(), 3);
    assert!(!response.body.contains("BEGIN:VCARD"));
}

#[tokio::test]
async fn query_filters_by_text_match_on_email_and_fn() {
    let (book, _) = book_with(three_cards()).await;
    let mut wire = spawn(book);
    let body = r#"<card:addressbook-query xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav">
      <d:prop><d:getetag/><card:address-data/></d:prop>
      <card:filter test="anyof">
        <card:prop-filter name="EMAIL"><card:text-match match-type="ends-with">@NAVY.invalid</card:text-match></card:prop-filter>
        <card:prop-filter name="FN"><card:text-match match-type="starts-with">ada</card:text-match></card:prop-filter>
      </card:filter>
    </card:addressbook-query>"#;
    let response = wire
        .request("REPORT", "/addressbooks/contacts/", &["Depth: 1"], body)
        .await;
    assert_eq!(response.status, 207);
    let hrefs: Vec<String> = hrefs_with_etags(&response.body)
        .into_iter()
        .map(|(href, _)| href)
        .collect();
    assert_eq!(
        hrefs,
        [
            "/addressbooks/contacts/c1.vcf",
            "/addressbooks/contacts/c3.vcf"
        ]
    );
    assert!(response.body.contains("FN:Grace Hopper"));

    // allof + negate: Alan only.
    let body = r#"<card:addressbook-query xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav">
      <d:prop><d:getetag/></d:prop>
      <card:filter test="allof">
        <card:prop-filter name="EMAIL"><card:text-match negate-condition="yes">navy</card:text-match></card:prop-filter>
        <card:prop-filter name="FN"><card:text-match>turing</card:text-match></card:prop-filter>
      </card:filter>
      <card:limit><card:nresults>5</card:nresults></card:limit>
    </card:addressbook-query>"#;
    let response = wire
        .request("REPORT", "/addressbooks/contacts/", &["Depth: 1"], body)
        .await;
    let hrefs = hrefs_with_etags(&response.body);
    assert_eq!(hrefs.len(), 1);
    assert_eq!(hrefs[0].0, "/addressbooks/contacts/c2.vcf");
}

#[tokio::test]
async fn query_limits_and_unsupported_filters() {
    let (book, _) = book_with(three_cards()).await;
    let mut wire = spawn(book);
    let body = r#"<card:addressbook-query xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav"><d:prop><d:getetag/></d:prop><card:limit><card:nresults>2</card:nresults></card:limit></card:addressbook-query>"#;
    let response = wire
        .request("REPORT", "/addressbooks/contacts/", &["Depth: 1"], body)
        .await;
    assert_eq!(hrefs_with_etags(&response.body).len(), 2);
    assert!(response.body.contains("507"));

    let body = r#"<card:addressbook-query xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav"><d:prop><d:getetag/></d:prop><card:filter><card:prop-filter name="X-CUSTOM"/></card:filter></card:addressbook-query>"#;
    let response = wire
        .request("REPORT", "/addressbooks/contacts/", &["Depth: 1"], body)
        .await;
    assert_eq!(response.status, 403);
    assert!(response.body.contains("<card:supported-filter/>"));

    let body = r#"<d:expand-property xmlns:d="DAV:"/>"#;
    let response = wire
        .request("REPORT", "/addressbooks/contacts/", &["Depth: 0"], body)
        .await;
    assert_eq!(response.status, 403);
    assert!(response.body.contains("<d:supported-report/>"));
}

// ---------------------------------------------------------------------------
// sync-collection
// ---------------------------------------------------------------------------

fn sync_body(token: &str) -> String {
    format!(
        r#"<d:sync-collection xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav"><d:sync-token>{token}</d:sync-token><d:sync-level>1</d:sync-level><d:prop><d:getetag/></d:prop></d:sync-collection>"#
    )
}

#[tokio::test]
async fn sync_collection_reports_changes_and_deletions_since_a_token() {
    let (book, source) = book_with(three_cards()).await;
    let mut wire = spawn(Arc::clone(&book));

    let initial = wire
        .request("REPORT", "/addressbooks/contacts/", &[], &sync_body(""))
        .await;
    assert_eq!(initial.status, 207);
    assert_eq!(hrefs_with_etags(&initial.body).len(), 3);
    let token = element_text(&initial.body, "sync-token")
        .unwrap()
        .to_string();

    // Nothing changed: an empty answer with the same token.
    let quiet = wire
        .request("REPORT", "/addressbooks/contacts/", &[], &sync_body(&token))
        .await;
    assert!(hrefs_with_etags(&quiet.body).is_empty());
    assert_eq!(element_text(&quiet.body, "sync-token").unwrap(), token);

    // c1 changes, c3 is deleted, c4 is new: the event batch updates the
    // cache, and the next sync names exactly those.
    source.put(card("c1", "Ada", "King", "ada@example.invalid"));
    source.remove("c3");
    source.put(card("c4", "Katherine", "Johnson", "kj@example.invalid"));
    let report = book
        .apply_batch(&contact_batch(&[
            ("c1", EntityOperation::Update),
            ("c3", EntityOperation::Delete),
            ("c4", EntityOperation::Create),
        ]))
        .await;
    assert!(!report.failed);
    assert_eq!(
        (
            report.counts.added,
            report.counts.updated,
            report.counts.removed
        ),
        (1, 1, 1)
    );

    let delta = wire
        .request("REPORT", "/addressbooks/contacts/", &[], &sync_body(&token))
        .await;
    let changed: Vec<String> = hrefs_with_etags(&delta.body)
        .into_iter()
        .map(|(href, _)| href)
        .collect();
    assert_eq!(
        changed,
        [
            "/addressbooks/contacts/c1.vcf",
            "/addressbooks/contacts/c4.vcf"
        ]
    );
    assert!(delta.body.contains(
        "<d:href>/addressbooks/contacts/c3.vcf</d:href><d:status>HTTP/1.1 404 Not Found</d:status>"
    ));
    assert_ne!(element_text(&delta.body, "sync-token").unwrap(), token);

    let invalid = wire
        .request(
            "REPORT",
            "/addressbooks/contacts/",
            &[],
            &sync_body("urn:tuta-bridge:carddav:sync:other-1"),
        )
        .await;
    assert_eq!(invalid.status, 403);
    assert!(invalid.body.contains("<d:valid-sync-token/>"));
}

// ---------------------------------------------------------------------------
// Loading and events
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_unloaded_book_that_cannot_load_answers_503() {
    let (book, source) = book_with(three_cards()).await;
    source.set_failing(true);
    let mut wire = spawn(book);
    let response = wire
        .request(
            "PROPFIND",
            "/addressbooks/contacts/",
            &["Depth: 1"],
            THUNDERBIRD_LISTING,
        )
        .await;
    assert_eq!(response.status, 503);
    // Fixed text only.
    assert!(!response.body.contains("contacts"));
}

#[tokio::test]
async fn a_stale_book_reloads_but_serves_the_cache_when_the_reload_fails() {
    let (book, source) = book_with(three_cards()).await;
    book.reload().await.unwrap();
    book.mark_stale();
    source.set_failing(true);
    let mut wire = spawn(Arc::clone(&book));
    let response = wire
        .request(
            "PROPFIND",
            "/addressbooks/contacts/",
            &["Depth: 1"],
            THUNDERBIRD_LISTING,
        )
        .await;
    assert_eq!(response.status, 207);
    assert_eq!(hrefs_with_etags(&response.body).len(), 3);
    assert!(book.is_stale());

    source.set_failing(false);
    source.remove("c2");
    let response = wire
        .request(
            "PROPFIND",
            "/addressbooks/contacts/",
            &["Depth: 1"],
            THUNDERBIRD_LISTING,
        )
        .await;
    assert_eq!(hrefs_with_etags(&response.body).len(), 2);
    assert!(!book.is_stale());
}

#[tokio::test]
async fn contact_events_refresh_only_the_affected_rows() {
    let (book, source) = book_with(three_cards()).await;
    book.reload().await.unwrap();
    let before = book.listing().await.unwrap();
    let revision = book.state().await.unwrap().revision;

    // Only c2 really changed; c1's update renders the same card.
    source.put(card("c2", "Alan", "Turing", "new@example.invalid"));
    let report = book
        .apply_batch(&contact_batch(&[
            ("c1", EntityOperation::Update),
            ("c2", EntityOperation::Create),
            ("c2", EntityOperation::Update),
        ]))
        .await;
    assert_eq!(report.events, 2);
    assert_eq!(report.counts.updated, 1);
    assert_eq!(source.single_loads(), 2);
    assert_eq!(source.full_loads(), 1);
    let after = book.listing().await.unwrap();
    assert_eq!(after[0], before[0]);
    assert_ne!(after[1].etag, before[1].etag);
    assert_eq!(after[2], before[2]);
    assert_eq!(book.state().await.unwrap().revision, revision + 1);

    // An update for a contact that is gone removes it.
    source.remove("c1");
    let report = book
        .apply_batch(&contact_batch(&[("c1", EntityOperation::Update)]))
        .await;
    assert_eq!(report.counts.removed, 1);
    assert!(book.lookup("c1").await.unwrap().is_none());
}

#[tokio::test]
async fn non_contact_and_foreign_list_events_are_ignored() {
    let (book, source) = book_with(three_cards()).await;
    book.reload().await.unwrap();
    let mut batch = contact_batch(&[("c1", EntityOperation::Delete)]);
    batch.events[0].type_id = MAIL_TYPE_ID;
    let mut foreign = contact_batch(&[("c2", EntityOperation::Delete)])
        .events
        .remove(0);
    foreign.list_id = "shared-list".into();
    batch.events.push(foreign);
    let report = book.apply_batch(&batch).await;
    assert_eq!(report.events, 1);
    assert!(report.counts.is_empty());
    assert_eq!(book.listing().await.unwrap().len(), 3);
    assert_eq!(source.single_loads(), 0);
}

#[tokio::test]
async fn a_failed_event_refresh_marks_the_book_stale() {
    let (book, source) = book_with(three_cards()).await;
    book.reload().await.unwrap();
    source.set_failing(true);
    let report = book
        .apply_batch(&contact_batch(&[("c1", EntityOperation::Update)]))
        .await;
    assert!(report.failed);
    assert!(book.is_stale());
    source.set_failing(false);
    book.ensure_fresh().await.unwrap();
    assert!(!book.is_stale());
    assert_eq!(source.full_loads(), 2);
}

#[tokio::test]
async fn a_book_needs_a_store_with_a_contact_cache() {
    let state = Arc::new(FakeStateStore::new()) as Arc<dyn StateStore>;
    let source = Arc::new(FakeContactSource::new(Vec::new())) as Arc<dyn ContactSource>;
    match ContactBook::new(1, state, source) {
        Err(Error::Config(_)) => {}
        _ => panic!("expected a configuration error"),
    }
}
