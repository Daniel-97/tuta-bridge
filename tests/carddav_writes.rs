//! CardDAV write contract: PUT/DELETE through `run_dav_session` against an
//! in-memory SQLite cache, a fake contact source and a fake contact writer.

mod support;

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use tokio::io::{split, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tuta_bridge::adapters::carddav::import::ImportError;
use tuta_bridge::adapters::carddav::vcard::render_vcard;
use tuta_bridge::adapters::carddav::CardDavHandler;
use tuta_bridge::adapters::dav::{run_dav_session, DavHandler, DavLimits};
use tuta_bridge::adapters::sqlite_state::SqliteStateStore;
use tuta_bridge::app::contacts::ContactBook;
use tuta_bridge::domain::{
    ContactCard, ContactField, ContactFieldKind, EntityEvent, EntityOperation, EventBatch,
    CONTACT_TYPE_ID, TUTANOTA_APP,
};
use tuta_bridge::ports::contact_source::ContactSource;
use tuta_bridge::ports::imap_backend::ImapBackend;
use tuta_bridge::ports::state_store::StateStore;
use tuta_bridge::ports::{ContactRef, ContactWriter, DeleteOutcome};

use support::{FakeContactSource, FakeContactWriter, FakeImapBackend};

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
                "Content-Type: text/vcard\r\nContent-Length: {}\r\n",
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

fn spawn(book: Arc<ContactBook>, writer: Arc<FakeContactWriter>) -> Wire {
    let backend = Arc::new(FakeImapBackend::new(USER, PASSWORD));
    let handler = Arc::new(CardDavHandler::with_writer(
        book,
        Arc::clone(&writer) as Arc<dyn ContactWriter>,
    ));
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

fn sync_body(token: &str) -> String {
    format!(
        r#"<d:sync-collection xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav"><d:sync-token>{token}</d:sync-token><d:sync-level>1</d:sync-level><d:prop><d:getetag/></d:prop></d:sync-collection>"#
    )
}

/// The book's ctag, read with a depth-0 PROPFIND.
async fn ctag_of(wire: &mut Wire) -> String {
    let response = wire
        .request(
            "PROPFIND",
            "/addressbooks/contacts/",
            &["Depth: 0"],
            THUNDERBIRD_LISTING,
        )
        .await;
    assert_eq!(response.status, 207);
    element_text(&response.body, "getctag").unwrap().to_string()
}

// ---------------------------------------------------------------------------
// Creates
// ---------------------------------------------------------------------------

#[tokio::test]
async fn put_creates_on_the_servers_generated_id() {
    let (book, source) = book_with(three_cards()).await;
    let writer = Arc::new(FakeContactWriter::new().answering_create(LIST, "srv-77"));
    let mut wire = spawn(Arc::clone(&book), Arc::clone(&writer));

    let baseline = ctag_of(&mut wire).await;

    let created = card("client-made-up-id", "New", "Person", "new@example.invalid");
    let body = render_vcard(&created);
    let response = wire
        .request(
            "PUT",
            "/addressbooks/contacts/client-made-up-id.vcf",
            &[],
            &body,
        )
        .await;
    assert_eq!(response.status, 201);
    assert_eq!(
        response.header("Location"),
        Some("/addressbooks/contacts/srv-77.vcf")
    );
    let etag = response.header("ETag").unwrap().to_string();

    let stored = book.lookup("srv-77").await.unwrap().unwrap();
    assert_eq!(stored.etag, etag);
    assert_eq!(stored.list_id, LIST);
    // The client's invented href id is never stored.
    assert!(book.lookup("client-made-up-id").await.unwrap().is_none());

    assert!(writer.put_calls() == [(LIST.to_string(), None)]);
    let after_put = ctag_of(&mut wire).await;
    assert_ne!(after_put, baseline);

    let missing = wire
        .request(
            "GET",
            "/addressbooks/contacts/client-made-up-id.vcf",
            &[],
            "",
        )
        .await;
    assert_eq!(missing.status, 404);

    // Coherence: the PUT's ETag is the one the reader serves.
    let mirrored = ContactCard {
        element_id: "srv-77".into(),
        ..created.clone()
    };
    source.put(mirrored.clone());
    let fetched = wire
        .request("GET", "/addressbooks/contacts/srv-77.vcf", &[], "")
        .await;
    assert_eq!(fetched.status, 200);
    assert_eq!(fetched.body, render_vcard(&mirrored));
    assert_eq!(fetched.header("ETag"), Some(etag.as_str()));

    // The create echo re-renders the same card: the identical ETag
    // skips the upsert, so nothing counts and the ctag stays.
    let report = book
        .apply_batch(&contact_batch(&[("srv-77", EntityOperation::Create)]))
        .await;
    assert!(!report.failed);
    assert!(report.counts.is_empty());
    assert_eq!(ctag_of(&mut wire).await, after_put);
}

// ---------------------------------------------------------------------------
// Updates and echoes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn put_updates_in_place_and_the_echo_counts_once() {
    let (book, source) = book_with(three_cards()).await;
    let writer = Arc::new(FakeContactWriter::new());
    let mut wire = spawn(Arc::clone(&book), Arc::clone(&writer));

    let baseline = ctag_of(&mut wire).await;
    let listing = wire
        .request(
            "PROPFIND",
            "/addressbooks/contacts/",
            &["Depth: 1"],
            THUNDERBIRD_LISTING,
        )
        .await;
    assert_eq!(listing.status, 207);
    let cards = hrefs_with_etags(&listing.body);
    let (href, listed_etag) = cards
        .iter()
        .find(|(href, _)| href == "/addressbooks/contacts/c1.vcf")
        .unwrap()
        .clone();

    let updated = card("c1", "Ada", "Lovelace", "new-ada@example.invalid");
    let body = render_vcard(&updated);
    let response = wire.request("PUT", &href, &[], &body).await;
    assert_eq!(response.status, 204);
    let etag = response.header("ETag").unwrap().to_string();
    assert_ne!(etag, listed_etag);
    assert_eq!(book.lookup("c1").await.unwrap().unwrap().etag, etag);
    assert!(
        writer.put_calls()
            == [(
                LIST.to_string(),
                Some(ContactRef {
                    list_id: LIST.into(),
                    element_id: "c1".into(),
                }),
            )]
    );
    let after_put = ctag_of(&mut wire).await;
    assert_ne!(after_put, baseline);

    // The echo of the same change is skipped: no count, no new revision.
    source.put(updated.clone());
    let report = book
        .apply_batch(&contact_batch(&[("c1", EntityOperation::Update)]))
        .await;
    assert!(report.counts.is_empty());
    assert_eq!(ctag_of(&mut wire).await, after_put);

    // The client's retry: same ETag, no revision change, a second
    // remote write (remote first).
    let retry = wire.request("PUT", &href, &[], &body).await;
    assert_eq!(retry.status, 204);
    assert_eq!(retry.header("ETag"), Some(etag.as_str()));
    assert_eq!(ctag_of(&mut wire).await, after_put);
    assert_eq!(writer.put_calls().len(), 2);
}

#[tokio::test]
async fn put_preconditions_run_against_the_stored_row() {
    let (book, _) = book_with(three_cards()).await;
    let writer = Arc::new(FakeContactWriter::new());
    let mut wire = spawn(Arc::clone(&book), Arc::clone(&writer));

    let listing = wire
        .request(
            "PROPFIND",
            "/addressbooks/contacts/",
            &["Depth: 1"],
            THUNDERBIRD_LISTING,
        )
        .await;
    let cards = hrefs_with_etags(&listing.body);
    let etag = cards
        .iter()
        .find(|(href, _)| href == "/addressbooks/contacts/c1.vcf")
        .unwrap()
        .1
        .clone();

    let href = "/addressbooks/contacts/c1.vcf";
    let b1 = "BEGIN:VCARD\r\nVERSION:4.0\r\nN:Doe;Jane;;;\r\nEND:VCARD\r\n";

    // The resource exists: `If-None-Match: *` refuses the overwrite.
    let conflict = wire.request("PUT", href, &["If-None-Match: *"], b1).await;
    assert_eq!(conflict.status, 412);
    assert!(writer.put_calls().is_empty());

    // A concrete stored ETag in `If-None-Match` refuses it too.
    let with_etag = format!("If-None-Match: {etag}");
    let conflict = wire.request("PUT", href, &[&with_etag], b1).await;
    assert_eq!(conflict.status, 412);
    assert!(writer.put_calls().is_empty());

    let stale = wire
        .request("PUT", href, &["If-Match: \"stale\""], b1)
        .await;
    assert_eq!(stale.status, 412);
    assert!(writer.put_calls().is_empty());

    // A changed body passes `If-Match` on the STORED ETag: the
    // precondition is never the body's render.
    let condition = format!("If-Match: {etag}");
    let changed = "BEGIN:VCARD\r\nVERSION:4.0\r\nN:Other;Person;;;\r\nEND:VCARD\r\n";
    let updated = wire.request("PUT", href, &[&condition], changed).await;
    assert_eq!(updated.status, 204);
    assert_eq!(writer.put_calls().len(), 1);

    // A fresh href has no current representation.
    let fresh = wire
        .request(
            "PUT",
            "/addressbooks/contacts/fresh.vcf",
            &["If-None-Match: *"],
            b1,
        )
        .await;
    assert_eq!(fresh.status, 201);
    assert_eq!(writer.put_calls().len(), 2);
}

#[tokio::test]
async fn a_body_that_is_no_vcard_is_refused_before_the_writer() {
    let (book, _) = book_with(three_cards()).await;
    let writer = Arc::new(FakeContactWriter::new());
    let mut wire = spawn(Arc::clone(&book), Arc::clone(&writer));

    let baseline = ctag_of(&mut wire).await;
    let href = "/addressbooks/contacts/c1.vcf";

    let not_a_card = wire.request("PUT", href, &[], "x").await;
    assert_eq!(not_a_card.status, 400);
    assert_eq!(
        not_a_card.body,
        format!("{}\n", ImportError::NoVcard.message())
    );

    let bad_date = wire
        .request(
            "PUT",
            href,
            &[],
            "BEGIN:VCARD\r\nVERSION:4.0\r\nBDAY:April\r\nEND:VCARD\r\n",
        )
        .await;
    assert_eq!(bad_date.status, 400);
    assert_eq!(
        bad_date.body,
        format!("{}\n", ImportError::BadDate.message())
    );

    assert!(writer.put_calls().is_empty());
    assert_eq!(ctag_of(&mut wire).await, baseline);
}

#[tokio::test]
async fn a_failed_remote_write_leaves_the_cache_untouched() {
    let (book, _) = book_with(three_cards()).await;
    let writer = Arc::new(FakeContactWriter::new());
    let mut wire = spawn(Arc::clone(&book), Arc::clone(&writer));

    let baseline = ctag_of(&mut wire).await;
    let stored = book.lookup("c1").await.unwrap().unwrap();
    writer.set_failing(true);

    let changed = render_vcard(&card("c1", "Ada", "Lovelace", "changed@example.invalid"));
    let response = wire
        .request("PUT", "/addressbooks/contacts/c1.vcf", &[], &changed)
        .await;
    assert_eq!(response.status, 503);
    assert_eq!(response.body, "temporarily unavailable\n");
    assert_eq!(response.header("Retry-After"), Some("30"));
    drop(wire);

    // A fresh connection: the cache never saw the failed write.
    let mut wire = spawn(Arc::clone(&book), Arc::clone(&writer));
    assert_eq!(book.lookup("c1").await.unwrap().unwrap().etag, stored.etag);
    assert_eq!(ctag_of(&mut wire).await, baseline);
    assert_eq!(writer.put_calls().len(), 1);

    let response = wire
        .request("DELETE", "/addressbooks/contacts/c1.vcf", &[], "")
        .await;
    assert_eq!(response.status, 503);
    assert!(book.lookup("c1").await.unwrap().is_some());
}

// ---------------------------------------------------------------------------
// Deletes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn delete_tombstones_only_a_row_that_existed() {
    let (book, _) = book_with(three_cards()).await;
    let writer = Arc::new(FakeContactWriter::new());
    let mut wire = spawn(Arc::clone(&book), Arc::clone(&writer));

    let initial = wire
        .request("REPORT", "/addressbooks/contacts/", &[], &sync_body(""))
        .await;
    let token = element_text(&initial.body, "sync-token")
        .unwrap()
        .to_string();
    let cards = hrefs_with_etags(&initial.body);
    let etag = cards
        .iter()
        .find(|(href, _)| href == "/addressbooks/contacts/c1.vcf")
        .unwrap()
        .1
        .clone();
    let baseline = ctag_of(&mut wire).await;

    let stale = wire
        .request(
            "DELETE",
            "/addressbooks/contacts/c1.vcf",
            &["If-Match: \"stale\""],
            "",
        )
        .await;
    assert_eq!(stale.status, 412);
    assert!(writer.delete_calls().is_empty());

    let condition = format!("If-Match: {etag}");
    let deleted = wire
        .request("DELETE", "/addressbooks/contacts/c1.vcf", &[&condition], "")
        .await;
    assert_eq!(deleted.status, 204);
    assert!(book.lookup("c1").await.unwrap().is_none());

    let delta = wire
        .request("REPORT", "/addressbooks/contacts/", &[], &sync_body(&token))
        .await;
    assert!(delta.body.contains(
        "<d:href>/addressbooks/contacts/c1.vcf</d:href><d:status>HTTP/1.1 404 Not Found</d:status>"
    ));
    let after_delete = ctag_of(&mut wire).await;
    assert_ne!(after_delete, baseline);

    // The delete echo removes an already-tombstoned row: a no-op.
    let report = book
        .apply_batch(&contact_batch(&[("c1", EntityOperation::Delete)]))
        .await;
    assert!(!report.failed);
    assert!(report.counts.is_empty());
    assert_eq!(ctag_of(&mut wire).await, after_delete);

    // A href that never existed answers 404 and writes no tombstone.
    let missing = wire
        .request("DELETE", "/addressbooks/contacts/never-there.vcf", &[], "")
        .await;
    assert_eq!(missing.status, 404);
    assert_eq!(writer.delete_calls().len(), 1);

    let after = wire
        .request("REPORT", "/addressbooks/contacts/", &[], &sync_body(&token))
        .await;
    assert_eq!(after.body.matches("HTTP/1.1 404 Not Found").count(), 1);
    assert!(after.body.contains("/addressbooks/contacts/c1.vcf"));
    assert!(!after.body.contains("never-there"));
}

#[tokio::test]
async fn a_remote_contact_already_gone_still_deletes() {
    let (book, _) = book_with(three_cards()).await;
    let writer = Arc::new(FakeContactWriter::new());
    *writer.delete_outcome.lock().unwrap() = DeleteOutcome::Gone;
    let mut wire = spawn(Arc::clone(&book), Arc::clone(&writer));

    let baseline = ctag_of(&mut wire).await;
    let stored = book.lookup("c1").await.unwrap().unwrap();
    let condition = format!("If-Match: {}", stored.etag);
    let response = wire
        .request("DELETE", "/addressbooks/contacts/c1.vcf", &[&condition], "")
        .await;
    assert_eq!(response.status, 204);
    assert!(book.lookup("c1").await.unwrap().is_none());
    assert!(
        writer.delete_calls()
            == [ContactRef {
                list_id: LIST.into(),
                element_id: "c1".into(),
            }]
    );
    assert_ne!(ctag_of(&mut wire).await, baseline);
}

// ---------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------

// The 409 is belt-and-braces: per the plan's decision 10 the book
// load/refresh records the contact list id structurally (Task 6
// wiring), so an unknown list can only mean the book has not been
// loaded yet.
#[tokio::test]
async fn a_create_without_a_known_list_answers_409() {
    let (book, _) = book_with(Vec::new()).await;
    let writer = Arc::new(FakeContactWriter::new());
    let mut wire = spawn(Arc::clone(&book), Arc::clone(&writer));

    let body = render_vcard(&card("fresh", "New", "Person", "new@example.invalid"));
    let response = wire
        .request("PUT", "/addressbooks/contacts/fresh.vcf", &[], &body)
        .await;
    assert_eq!(response.status, 409);
    assert!(writer.put_calls().is_empty());

    let listing = wire
        .request(
            "PROPFIND",
            "/addressbooks/contacts/",
            &["Depth: 1"],
            THUNDERBIRD_LISTING,
        )
        .await;
    assert_eq!(listing.status, 207);
    assert!(hrefs_with_etags(&listing.body).is_empty());
}

#[tokio::test]
async fn write_methods_are_advertised_and_collections_refuse_writes() {
    let (book, _) = book_with(three_cards()).await;
    let writer = Arc::new(FakeContactWriter::new());
    let mut wire = spawn(Arc::clone(&book), Arc::clone(&writer));

    let options = wire.request("OPTIONS", "/", &[], "").await;
    assert_eq!(options.status, 200);
    let allow = options.header("Allow").unwrap();
    assert!(allow.contains("PUT"));
    assert!(allow.contains("DELETE"));

    // Collections are not writable, whatever the body.
    let body = render_vcard(&card("x", "A", "B", "x@example.invalid"));
    let put = wire
        .request("PUT", "/addressbooks/contacts/", &[], &body)
        .await;
    assert_eq!(put.status, 403);
    let delete = wire
        .request("DELETE", "/addressbooks/contacts/", &[], "")
        .await;
    assert_eq!(delete.status, 403);
    assert!(writer.put_calls().is_empty());
    assert!(writer.delete_calls().is_empty());
}
