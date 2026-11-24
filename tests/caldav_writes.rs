//! CalDAV write contract: PUT/DELETE through `run_dav_session` against
//! an in-memory SQLite cache, a fake calendar source and a fake
//! calendar writer. The bodies the tests PUT are rendered from their
//! own fixed fixtures; the assertions pin statuses, headers and cache
//! state, never live event content.

mod support;

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use tokio::io::{split, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tuta_bridge::adapters::caldav::import::ImportError;
use tuta_bridge::adapters::caldav::{ical, CalDavHandler};
use tuta_bridge::adapters::dav::{run_dav_session, DavHandler, DavLimits};
use tuta_bridge::adapters::sqlite_state::SqliteStateStore;
use tuta_bridge::app::calendar_sync::CalendarSync;
use tuta_bridge::domain::calendar::{split_resource_name, DAY_MS};
use tuta_bridge::domain::{
    CalendarEvent, CalendarInfo, CalendarRow, EntityEvent, EntityOperation, EventBatch,
    EventPerson, RepeatRule, CALENDAR_EVENT_TYPE_ID, TUTANOTA_APP,
};
use tuta_bridge::ports::calendar::CalendarStore;
use tuta_bridge::ports::clock::Clock;
use tuta_bridge::ports::imap_backend::ImapBackend;
use tuta_bridge::ports::state_store::StateStore;
use tuta_bridge::ports::{CalendarRef, CalendarWriter, DeleteOutcome, EventRef};

use support::{FakeCalendarSource, FakeCalendarWriter, FakeImapBackend};

const USER: &str = "user@example.invalid";
const PASSWORD: &str = "hunter2";
/// 2025-01-06 08:00:00 UTC.
const NOW_MS: i64 = 1_736_150_400_000;
const HOUR: i64 = 3_600_000;

struct TestClock(AtomicI64);

impl Clock for TestClock {
    fn now_ms(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

fn calendar(id: &str) -> CalendarInfo {
    CalendarInfo {
        calendar_id: id.into(),
        name: format!("Calendar {id}"),
        color: "2196f3".into(),
        short_list_id: format!("{id}-short"),
        long_list_id: format!("{id}-long"),
    }
}

/// A never-ending weekly rule in Berlin, the reader's own fixture
/// shape.
fn weekly() -> RepeatRule {
    RepeatRule {
        frequency: 1,
        interval: 1,
        end_type: 0,
        end_value: None,
        time_zone: "Europe/Berlin".into(),
        excluded_ms: Vec::new(),
        advanced: Vec::new(),
    }
}

/// One plain personal event: no organizer, no attendees, no alarms.
fn plain_event(element: &str, uid: &str, start_ms: i64) -> CalendarEvent {
    CalendarEvent {
        list_id: "work-short".into(),
        element_id: element.into(),
        uid: Some(uid.into()),
        summary: "Fixture summary".into(),
        description: String::new(),
        location: String::new(),
        start_ms,
        end_ms: start_ms + HOUR,
        sequence: 0,
        recurrence_id_ms: None,
        repeat: None,
        alarm_ids: Vec::new(),
        organizer: None,
        attendees: Vec::new(),
    }
}

/// The iCalendar body the reader serves for `event`: the form the
/// importer accepts back.
fn body_of(event: &CalendarEvent) -> String {
    let no_alarms: [String; 0] = [];
    ical::render_calendar(&[ical::EventToRender {
        event,
        modified_ms: NOW_MS,
        alarms: &no_alarms,
    }])
}

fn calendar_ref() -> CalendarRef {
    CalendarRef {
        group_id: "work".into(),
        short_list_id: "work-short".into(),
        long_list_id: "work-long".into(),
    }
}

fn event_ref(list_id: &str, element_id: &str) -> EventRef {
    EventRef {
        list_id: list_id.into(),
        element_id: element_id.into(),
    }
}

fn calendar_batch(operation: EntityOperation, element_id: &str) -> EventBatch {
    EventBatch {
        batch_id: "batch".into(),
        owner_group_id: "work".into(),
        application_types_hash: String::new(),
        events: vec![EntityEvent {
            application: TUTANOTA_APP.into(),
            type_id: CALENDAR_EVENT_TYPE_ID,
            list_id: "work-short".into(),
            element_id: element_id.into(),
            operation,
        }],
    }
}

struct Fixture {
    source: Arc<FakeCalendarSource>,
    store: Arc<SqliteStateStore>,
    sync: Arc<CalendarSync>,
    account_id: i64,
}

/// The sync and cache over `source`, after a reload.
async fn over(source: Arc<FakeCalendarSource>) -> Fixture {
    let store = Arc::new(SqliteStateStore::open_in_memory().await.unwrap());
    let account_id = store.upsert_account(USER).await.unwrap();
    let clock = Arc::new(TestClock(AtomicI64::new(NOW_MS)));
    let sync = Arc::new(CalendarSync::new(
        account_id,
        Arc::clone(&store) as Arc<dyn CalendarStore>,
        Arc::clone(&source) as _,
        Arc::clone(&clock) as Arc<dyn Clock>,
    ));
    sync.reload().await.unwrap();
    Fixture {
        source,
        store,
        sync,
        account_id,
    }
}

/// One calendar "work" with one plain event.
async fn fixture() -> Fixture {
    let source = Arc::new(FakeCalendarSource::new());
    source.add_calendar(calendar("work"));
    source.put_event(plain_event("e1", "uid-1", NOW_MS + DAY_MS));
    over(source).await
}

/// The cached row of one element of the "work" calendar.
async fn row_of(fixture: &Fixture, element: &str) -> Option<CalendarRow> {
    fixture
        .store
        .calendar_rows(fixture.account_id, "work")
        .await
        .unwrap()
        .into_iter()
        .find(|row| row.element_id == element)
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
            request.push_str(&format!("Content-Length: {}\r\n", body.len()));
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

    async fn propfind(&mut self, path: &str, depth: &str, body: &str) -> Response {
        let depth = format!("Depth: {depth}");
        self.request("PROPFIND", path, &[&depth], body).await
    }
}

/// The writable handler over the fixture's sync, on a fresh duplex.
fn spawn_writable(
    fixture: &Fixture,
    writer: Arc<FakeCalendarWriter>,
    organizers: Vec<String>,
) -> Wire {
    let handler = Arc::new(CalDavHandler::with_writer(
        Arc::clone(&fixture.sync),
        USER.to_string(),
        Arc::clone(&writer) as Arc<dyn CalendarWriter>,
        organizers,
    ));
    spawn_handler(handler)
}

/// The read-only handler over the fixture's sync, on a fresh duplex.
fn spawn_readonly(fixture: &Fixture) -> Wire {
    spawn_handler(Arc::new(CalDavHandler::new(
        Arc::clone(&fixture.sync),
        USER.to_string(),
    )))
}

fn spawn_handler(handler: Arc<dyn DavHandler>) -> Wire {
    let backend = Arc::new(FakeImapBackend::new(USER, PASSWORD));
    let (client, server) = tokio::io::duplex(1024 * 1024);
    tokio::spawn(run_dav_session(
        server,
        backend as Arc<dyn ImapBackend>,
        handler,
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

/// Every `<d:href>` value of a multistatus, in order.
fn hrefs(body: &str) -> Vec<String> {
    body.split("<d:href>")
        .skip(1)
        .map(|part| part.split("</d:href>").next().unwrap().to_string())
        .collect()
}

/// The text of the first `<tag>` after `href` in a multistatus.
fn prop_after(body: &str, href: &str, tag: &str) -> Option<String> {
    let at = body.find(&format!("<d:href>{href}</d:href>"))?;
    let rest = &body[at..];
    let end = rest.find("</d:response>").unwrap_or(rest.len());
    let rest = &rest[..end];
    let open = format!("<{tag}>");
    let start = rest.find(&open)? + open.len();
    let stop = rest[start..].find(&format!("</{tag}>"))?;
    Some(rest[start..start + stop].to_string())
}

fn unescape(xml: &str) -> String {
    xml.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&#xD;", "\r")
        .replace("&amp;", "&")
}

const ETAG_PROPFIND: &str = r#"<?xml version="1.0"?><d:propfind xmlns:d="DAV:"><d:prop><d:getetag/><d:resourcetype/></d:prop></d:propfind>"#;

/// The (href, etag) pairs of a Depth-1 calendar listing.
async fn listing(wire: &mut Wire, calendar: &str) -> Vec<(String, String)> {
    let response = wire
        .propfind(
            &format!("/caldav/calendars/{calendar}/"),
            "1",
            ETAG_PROPFIND,
        )
        .await;
    assert_eq!(response.status, 207);
    hrefs(&response.body)
        .into_iter()
        .filter(|href| href.ends_with(".ics"))
        .map(|href| {
            let etag = unescape(&prop_after(&response.body, &href, "d:getetag").unwrap());
            (href, etag)
        })
        .collect()
}

/// The calendar's ctag, read with a depth-0 PROPFIND.
async fn ctag(wire: &mut Wire, calendar: &str) -> String {
    let response = wire
        .propfind(
            &format!("/caldav/calendars/{calendar}/"),
            "0",
            r#"<d:propfind xmlns:d="DAV:" xmlns:cs="http://calendarserver.org/ns/"><d:prop><cs:getctag/></d:prop></d:propfind>"#,
        )
        .await;
    assert_eq!(response.status, 207);
    prop_after(
        &response.body,
        &format!("/caldav/calendars/{calendar}/"),
        "cs:getctag",
    )
    .unwrap()
}

// ---------------------------------------------------------------------------
// Updates and echoes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn put_updates_in_place_and_the_echo_counts_once() {
    let fixture = fixture().await;
    let writer = Arc::new(FakeCalendarWriter::new());
    let mut wire = spawn_writable(&fixture, Arc::clone(&writer), vec![USER.to_string()]);

    let listed = listing(&mut wire, "work").await;
    assert_eq!(listed.len(), 1);
    let (href, listed_etag) = listed[0].clone();
    let baseline = ctag(&mut wire, "work").await;

    // The write's new state, staged the way a held write leaves it.
    let mut edited = plain_event("e1", "uid-1", NOW_MS + DAY_MS);
    edited.summary = "Edited summary".into();
    fixture.source.put_event(edited.clone());

    let response = wire.request("PUT", &href, &[], &body_of(&edited)).await;
    assert_eq!(response.status, 204);
    let etag = response.header("ETag").unwrap().to_string();
    assert_ne!(etag, listed_etag);
    assert!(writer.put_calls() == [(calendar_ref(), Some(event_ref("work-short", "e1")))]);
    let row = row_of(&fixture, "e1").await.unwrap();
    assert_eq!(
        row.fingerprint,
        edited.fingerprint(),
        "the row is refreshed"
    );
    let after_put = ctag(&mut wire, "work").await;
    assert_ne!(after_put, baseline, "the write advanced the ctag once");

    // The echo of the same change is a no-op: the row is identical and
    // the ctag stays. (The batch counts the upsert regardless; the
    // idempotence lives in the row and the ctag.)
    fixture
        .sync
        .apply(&calendar_batch(EntityOperation::Update, "e1"))
        .await
        .unwrap();
    let echoed = row_of(&fixture, "e1").await.unwrap();
    assert_eq!(echoed.fingerprint, row.fingerprint);
    assert_eq!(
        echoed.modified_ms, row.modified_ms,
        "the echo does not re-stamp"
    );
    assert_eq!(ctag(&mut wire, "work").await, after_put);

    // Coherence: the PUT's ETag is the one the reader serves.
    let fetched = wire.request("GET", &href, &[], "").await;
    assert_eq!(fetched.status, 200);
    assert_eq!(fetched.header("ETag"), Some(etag.as_str()));
    assert_eq!(fetched.body, body_of(&edited));
    let relisted = listing(&mut wire, "work").await;
    assert_eq!(relisted[0].1, etag);

    // A full re-refresh of identical data changes nothing either.
    fixture.sync.reload().await.unwrap();
    assert_eq!(ctag(&mut wire, "work").await, after_put);

    // A repeated PUT is a second remote write (remote first) and is
    // accepted: the real writer bumps the event's sequence on every
    // edit, so the row behind a retry is a new edit, not a no-op — the
    // fake writer cannot model that bump, so only the acceptance and
    // the second write are pinned here, never the ETag or the ctag.
    let retry = wire.request("PUT", &href, &[], &body_of(&edited)).await;
    assert_eq!(retry.status, 204);
    assert_eq!(writer.put_calls().len(), 2);
}

#[tokio::test]
async fn put_on_a_row_that_does_not_exist_refuses_creation() {
    let fixture = fixture().await;
    let writer = Arc::new(FakeCalendarWriter::new());
    let mut wire = spawn_writable(&fixture, Arc::clone(&writer), vec![USER.to_string()]);

    let baseline = ctag(&mut wire, "work").await;
    let body = body_of(&plain_event("fresh", "fresh-uid", NOW_MS + DAY_MS));

    // A made-up href in a real calendar: no row, no creation dance.
    let response = wire
        .request("PUT", "/caldav/calendars/work/never-there.ics", &[], &body)
        .await;
    assert_eq!(response.status, 403);
    assert_eq!(
        response.body,
        "creating events is not supported: create them in the Tuta client, then edit them here\n"
    );
    assert!(writer.put_calls().is_empty());

    // The refusal is unconditional: preconditions cannot turn a
    // creation into something else.
    let conditioned = wire
        .request(
            "PUT",
            "/caldav/calendars/work/never-there.ics",
            &["If-None-Match: *"],
            &body,
        )
        .await;
    assert_eq!(conditioned.status, 403);
    assert_eq!(conditioned.body, response.body);

    // A calendar the account does not have: no row can exist there.
    let elsewhere = wire
        .request("PUT", "/caldav/calendars/nope/new.ics", &[], &body)
        .await;
    assert_eq!(elsewhere.status, 403);
    assert_eq!(elsewhere.body, response.body);

    assert!(writer.put_calls().is_empty());
    assert_eq!(listing(&mut wire, "work").await.len(), 1);
    assert_eq!(ctag(&mut wire, "work").await, baseline);
}

#[tokio::test]
async fn put_preconditions_run_against_the_stored_row() {
    let fixture = fixture().await;
    let writer = Arc::new(FakeCalendarWriter::new());
    let mut wire = spawn_writable(&fixture, Arc::clone(&writer), vec![USER.to_string()]);

    let listed = listing(&mut wire, "work").await;
    let (href, etag) = listed[0].clone();
    let body = body_of(&plain_event("e1", "uid-1", NOW_MS + DAY_MS));

    // The resource exists: `If-None-Match: *` refuses the overwrite.
    let conflict = wire
        .request("PUT", &href, &["If-None-Match: *"], &body)
        .await;
    assert_eq!(conflict.status, 412);
    assert_eq!(conflict.body, "precondition failed\n");
    assert!(writer.put_calls().is_empty());

    // A concrete stored ETag in `If-None-Match` refuses it too.
    let with_etag = format!("If-None-Match: {etag}");
    let conflict = wire.request("PUT", &href, &[&with_etag], &body).await;
    assert_eq!(conflict.status, 412);
    assert!(writer.put_calls().is_empty());

    let stale = wire
        .request("PUT", &href, &["If-Match: \"stale\""], &body)
        .await;
    assert_eq!(stale.status, 412);
    assert!(writer.put_calls().is_empty());

    // A changed body passes `If-Match` on the STORED ETag: the
    // precondition is never the body's render.
    let mut edited = plain_event("e1", "uid-1", NOW_MS + DAY_MS);
    edited.summary = "Edited summary".into();
    fixture.source.put_event(edited.clone());
    let condition = format!("If-Match: {etag}");
    let updated = wire
        .request("PUT", &href, &[&condition], &body_of(&edited))
        .await;
    assert_eq!(updated.status, 204);
    assert_eq!(writer.put_calls().len(), 1);
}

#[tokio::test]
async fn a_body_that_is_no_vevent_is_refused_before_the_writer() {
    let fixture = fixture().await;
    let writer = Arc::new(FakeCalendarWriter::new());
    let mut wire = spawn_writable(&fixture, Arc::clone(&writer), vec![USER.to_string()]);

    let baseline = ctag(&mut wire, "work").await;
    let listed = listing(&mut wire, "work").await;
    let (href, _) = listed[0].clone();

    let not_an_event = wire.request("PUT", &href, &[], "x").await;
    assert_eq!(not_an_event.status, 400);
    assert_eq!(
        not_an_event.body,
        format!("{}\n", ImportError::NoVevent.message())
    );

    let missing_end = wire
        .request(
            "PUT",
            &href,
            &[],
            "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nDTSTART:20250107T080000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n",
        )
        .await;
    assert_eq!(missing_end.status, 400);
    assert_eq!(
        missing_end.body,
        format!("{}\n", ImportError::BadTimes.message())
    );

    assert!(writer.put_calls().is_empty());
    assert_eq!(ctag(&mut wire, "work").await, baseline);
}

#[tokio::test]
async fn an_organizer_outside_the_account_refuses_the_put() {
    let fixture = fixture().await;
    let writer = Arc::new(FakeCalendarWriter::new());
    let mut wire = spawn_writable(&fixture, Arc::clone(&writer), vec![USER.to_string()]);

    let listed = listing(&mut wire, "work").await;
    let (href, _) = listed[0].clone();

    // An organizer that is not one of the account's addresses: no
    // silent re-attribution.
    let mut outsider = plain_event("e1", "uid-1", NOW_MS + DAY_MS);
    outsider.organizer = Some(EventPerson {
        name: String::new(),
        address: "someone-else@example.invalid".into(),
    });
    let response = wire.request("PUT", &href, &[], &body_of(&outsider)).await;
    assert_eq!(response.status, 403);
    assert_eq!(
        response.body,
        "the organizer is not an address of this account\n"
    );
    assert!(writer.put_calls().is_empty());

    // The match is case-insensitive; an event without an organizer
    // (the plain-event happy path) is a personal one and passes.
    let mut own = plain_event("e1", "uid-1", NOW_MS + DAY_MS);
    own.organizer = Some(EventPerson {
        name: String::new(),
        address: "USER@EXAMPLE.INVALID".into(),
    });
    fixture.source.put_event(own.clone());
    let response = wire.request("PUT", &href, &[], &body_of(&own)).await;
    assert_eq!(response.status, 204);
    assert_eq!(writer.put_calls().len(), 1);
    let row = row_of(&fixture, "e1").await.unwrap();
    assert_eq!(row.fingerprint, own.fingerprint());
}

#[tokio::test]
async fn a_failed_remote_write_leaves_the_cache_untouched() {
    let fixture = fixture().await;
    let writer = Arc::new(FakeCalendarWriter::new());
    let mut wire = spawn_writable(&fixture, Arc::clone(&writer), vec![USER.to_string()]);

    let baseline = ctag(&mut wire, "work").await;
    let row = row_of(&fixture, "e1").await.unwrap();
    let listed = listing(&mut wire, "work").await;
    let (href, _) = listed[0].clone();
    writer.set_failing(true);

    let mut edited = plain_event("e1", "uid-1", NOW_MS + DAY_MS);
    edited.summary = "Edited summary".into();
    let response = wire.request("PUT", &href, &[], &body_of(&edited)).await;
    assert_eq!(response.status, 503);
    assert_eq!(response.body, "temporarily unavailable\n");
    assert_eq!(response.header("Retry-After"), Some("30"));
    assert_eq!(writer.put_calls().len(), 1);
    drop(wire);

    // A fresh connection: the cache never saw the failed write.
    let mut wire = spawn_writable(&fixture, Arc::clone(&writer), vec![USER.to_string()]);
    let after = row_of(&fixture, "e1").await.unwrap();
    assert_eq!(after.fingerprint, row.fingerprint);
    assert_eq!(ctag(&mut wire, "work").await, baseline);

    let response = wire.request("DELETE", &href, &[], "").await;
    assert_eq!(response.status, 503);
    assert_eq!(response.body, "temporarily unavailable\n");
    assert_eq!(writer.delete_calls().len(), 1);
    assert!(row_of(&fixture, "e1").await.is_some());
    drop(wire);

    // A 503 closes the connection: a third one confirms the ctag
    // never moved.
    let mut wire = spawn_writable(&fixture, Arc::clone(&writer), vec![USER.to_string()]);
    assert_eq!(ctag(&mut wire, "work").await, baseline);
}

#[tokio::test]
async fn a_write_whose_new_state_cannot_be_read_answers_503_and_keeps_the_row() {
    let fixture = fixture().await;
    let writer = Arc::new(FakeCalendarWriter::new());
    let mut wire = spawn_writable(&fixture, Arc::clone(&writer), vec![USER.to_string()]);

    let baseline = ctag(&mut wire, "work").await;
    let row = row_of(&fixture, "e1").await.unwrap();
    let listed = listing(&mut wire, "work").await;
    let (href, _) = listed[0].clone();

    // The write holds, but the new state cannot be read back: the
    // optimistic row is not landed and the client retries.
    fixture.source.remove_event("work-short", "e1");
    let mut edited = plain_event("e1", "uid-1", NOW_MS + DAY_MS);
    edited.summary = "Edited summary".into();
    let response = wire.request("PUT", &href, &[], &body_of(&edited)).await;
    assert_eq!(response.status, 503);
    assert_eq!(response.body, "temporarily unavailable\n");
    assert_eq!(writer.put_calls().len(), 1);
    drop(wire);

    let mut wire = spawn_writable(&fixture, Arc::clone(&writer), vec![USER.to_string()]);
    let after = row_of(&fixture, "e1").await.unwrap();
    assert_eq!(after.fingerprint, row.fingerprint);
    assert_eq!(ctag(&mut wire, "work").await, baseline);
}

#[tokio::test]
async fn put_on_a_series_updates_the_master_and_the_etag_covers_every_row() {
    let source = Arc::new(FakeCalendarSource::new());
    source.add_calendar(calendar("work"));
    let mut master = plain_event("series", "series-uid", NOW_MS);
    master.list_id = "work-long".into();
    master.repeat = Some(weekly());
    let mut moved = plain_event("moved", "series-uid", NOW_MS + 7 * DAY_MS + 2 * HOUR);
    moved.list_id = "work-long".into();
    moved.recurrence_id_ms = Some(NOW_MS + 7 * DAY_MS);
    source.put_event(master.clone());
    source.put_event(moved.clone());
    let fixture = over(source).await;
    let writer = Arc::new(FakeCalendarWriter::new());
    let mut wire = spawn_writable(&fixture, Arc::clone(&writer), vec![USER.to_string()]);

    // One resource behind one href, two events behind it.
    let listed = listing(&mut wire, "work").await;
    assert_eq!(listed.len(), 1);
    let (href, _) = listed[0].clone();

    let mut edited = master.clone();
    edited.summary = "Edited summary".into();
    fixture.source.put_event(edited.clone());

    let response = wire.request("PUT", &href, &[], &body_of(&edited)).await;
    assert_eq!(response.status, 204);
    let etag = response.header("ETag").unwrap().to_string();
    // The plain-VEVENT body describes the series' own master, and only
    // the master's event is written.
    assert!(writer.put_calls() == [(calendar_ref(), Some(event_ref("work-long", "series")))]);
    let series_row = row_of(&fixture, "series").await.unwrap();
    assert_eq!(series_row.fingerprint, edited.fingerprint());
    let moved_row = row_of(&fixture, "moved").await.unwrap();
    assert_eq!(
        moved_row.fingerprint,
        moved.fingerprint(),
        "the occurrence is untouched"
    );

    // The ETag answers for the whole resource, altered occurrence
    // included, and the reader agrees.
    let fetched = wire.request("GET", &href, &[], "").await;
    assert_eq!(fetched.status, 200);
    assert_eq!(fetched.header("ETag"), Some(etag.as_str()));
    assert_eq!(fetched.body.matches("BEGIN:VEVENT").count(), 2);
}

#[tokio::test]
async fn put_on_a_split_series_second_href_updates_its_own_master() {
    // "Edit this and all future events": the original series ends
    // before week 4, a second master with the same uid starts there.
    let source = Arc::new(FakeCalendarSource::new());
    source.add_calendar(calendar("work"));
    let mut original = plain_event("original", "series-uid", NOW_MS);
    original.list_id = "work-long".into();
    let mut bounded = weekly();
    bounded.end_type = 2;
    bounded.end_value = Some(NOW_MS + 4 * 7 * DAY_MS);
    original.repeat = Some(bounded);
    let mut future = plain_event("future", "series-uid", NOW_MS + 4 * 7 * DAY_MS + HOUR);
    future.list_id = "work-long".into();
    future.repeat = Some(weekly());
    source.put_event(original.clone());
    source.put_event(future.clone());
    let fixture = over(source).await;
    let writer = Arc::new(FakeCalendarWriter::new());
    let mut wire = spawn_writable(&fixture, Arc::clone(&writer), vec![USER.to_string()]);

    // One uid, two hrefs: the series' own name and the split's.
    let first = format!("/caldav/calendars/work/{}.ics", original.resource_name());
    let second = format!(
        "/caldav/calendars/work/{}.ics",
        split_resource_name(&original.resource_name(), "work-long", "future")
    );
    let listed = listing(&mut wire, "work").await;
    assert_eq!(listed.len(), 2);
    assert!(listed.iter().any(|(href, _)| *href == first));
    assert!(listed.iter().any(|(href, _)| *href == second));

    let mut edited = future.clone();
    edited.summary = "Edited summary".into();
    fixture.source.put_event(edited.clone());

    let response = wire.request("PUT", &second, &[], &body_of(&edited)).await;
    assert_eq!(response.status, 204);
    let etag = response.header("ETag").unwrap().to_string();
    // The split's own master is the event the write updated.
    assert!(writer.put_calls() == [(calendar_ref(), Some(event_ref("work-long", "future")))]);
    let future_row = row_of(&fixture, "future").await.unwrap();
    assert_eq!(future_row.fingerprint, edited.fingerprint());
    let original_row = row_of(&fixture, "original").await.unwrap();
    assert_eq!(
        original_row.fingerprint,
        original.fingerprint(),
        "the other half of the split is untouched"
    );

    // The reader agrees with the answered ETag, on the split's href.
    let fetched = wire.request("GET", &second, &[], "").await;
    assert_eq!(fetched.status, 200);
    assert_eq!(fetched.header("ETag"), Some(etag.as_str()));
    assert_eq!(listing(&mut wire, "work").await.len(), 2);
}

#[tokio::test]
async fn a_legacy_uid_repair_moves_the_row_and_answers_no_etag() {
    let source = Arc::new(FakeCalendarSource::new());
    source.add_calendar(calendar("work"));
    // A legacy event stored without a uid: its resource name derives
    // from its ids, not from a uid.
    let mut legacy = plain_event("e1", "uid-1", NOW_MS + DAY_MS);
    legacy.uid = None;
    source.put_event(legacy);
    let fixture = over(source).await;
    let writer = Arc::new(FakeCalendarWriter::new());
    let mut wire = spawn_writable(&fixture, Arc::clone(&writer), vec![USER.to_string()]);

    let listed = listing(&mut wire, "work").await;
    assert_eq!(listed.len(), 1);
    let (href, _) = listed[0].clone();

    // The write repairs the uid, the way the writer does for a legacy
    // event: the staged new state carries one, so the row moves to
    // the uid's own href.
    let mut repaired = plain_event("e1", "uid-1", NOW_MS + DAY_MS);
    repaired.summary = "Repaired summary".into();
    fixture.source.put_event(repaired.clone());

    let response = wire.request("PUT", &href, &[], &body_of(&repaired)).await;
    assert_eq!(response.status, 204);
    assert!(
        response.header("ETag").is_none(),
        "no ETag for a row this href no longer serves"
    );
    assert_eq!(writer.put_calls().len(), 1);
    let row = row_of(&fixture, "e1").await.unwrap();
    assert_eq!(row.fingerprint, repaired.fingerprint());
    assert_eq!(row.resource, repaired.resource_name());

    // The PUT's href no longer serves anything; the uid's href does.
    let gone = wire.request("GET", &href, &[], "").await;
    assert_eq!(gone.status, 404);
    let relisted = listing(&mut wire, "work").await;
    assert_eq!(relisted.len(), 1);
    assert_ne!(relisted[0].0, href);
    let moved = format!("/caldav/calendars/work/{}.ics", repaired.resource_name());
    assert_eq!(relisted[0].0, moved);
    let fetched = wire.request("GET", &moved, &[], "").await;
    assert_eq!(fetched.status, 200);
}

// ---------------------------------------------------------------------------
// Deletes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn delete_removes_the_resource_and_the_echo_is_a_noop() {
    let fixture = fixture().await;
    let writer = Arc::new(FakeCalendarWriter::new());
    let mut wire = spawn_writable(&fixture, Arc::clone(&writer), vec![USER.to_string()]);

    let listed = listing(&mut wire, "work").await;
    let (href, etag) = listed[0].clone();
    let baseline = ctag(&mut wire, "work").await;

    let stale = wire
        .request("DELETE", &href, &["If-Match: \"stale\""], "")
        .await;
    assert_eq!(stale.status, 412);
    assert!(writer.delete_calls().is_empty());

    let condition = format!("If-Match: {etag}");
    let deleted = wire.request("DELETE", &href, &[&condition], "").await;
    assert_eq!(deleted.status, 204);
    assert!(writer.delete_calls() == [(calendar_ref(), event_ref("work-short", "e1"))]);
    assert!(row_of(&fixture, "e1").await.is_none());
    let gone = wire.request("GET", &href, &[], "").await;
    assert_eq!(gone.status, 404);
    let after_delete = ctag(&mut wire, "work").await;
    assert_ne!(after_delete, baseline);

    // The delete echo of an already-removed row: a no-op.
    let report = fixture
        .sync
        .apply(&calendar_batch(EntityOperation::Delete, "e1"))
        .await
        .unwrap();
    assert_eq!(report.updated + report.removed, 0);
    assert_eq!(ctag(&mut wire, "work").await, after_delete);

    // A href that never existed answers 404 and deletes nothing.
    let missing = wire
        .request("DELETE", "/caldav/calendars/work/never-there.ics", &[], "")
        .await;
    assert_eq!(missing.status, 404);
    let elsewhere = wire
        .request("DELETE", "/caldav/calendars/nope/x.ics", &[], "")
        .await;
    assert_eq!(elsewhere.status, 404);
    assert_eq!(writer.delete_calls().len(), 1);
}

#[tokio::test]
async fn delete_removes_every_event_of_a_series_resource() {
    let source = Arc::new(FakeCalendarSource::new());
    source.add_calendar(calendar("work"));
    let mut master = plain_event("series", "series-uid", NOW_MS);
    master.list_id = "work-long".into();
    master.repeat = Some(RepeatRule {
        frequency: 1,
        interval: 1,
        end_type: 0,
        end_value: None,
        time_zone: "Europe/Berlin".into(),
        excluded_ms: Vec::new(),
        advanced: Vec::new(),
    });
    let mut moved = plain_event("moved", "series-uid", NOW_MS + 7 * DAY_MS + 2 * HOUR);
    moved.list_id = "work-long".into();
    moved.recurrence_id_ms = Some(NOW_MS + 7 * DAY_MS);
    source.put_event(master);
    source.put_event(moved);
    let fixture = over(source).await;
    let writer = Arc::new(FakeCalendarWriter::new());
    let mut wire = spawn_writable(&fixture, Arc::clone(&writer), vec![USER.to_string()]);

    // One resource behind one href, two events behind it.
    let listed = listing(&mut wire, "work").await;
    assert_eq!(listed.len(), 1);
    let (href, _) = listed[0].clone();

    let deleted = wire.request("DELETE", &href, &[], "").await;
    assert_eq!(deleted.status, 204);
    // Every event of the series is deleted, in the store's row order.
    assert!(
        writer.delete_calls()
            == [
                (calendar_ref(), event_ref("work-long", "moved")),
                (calendar_ref(), event_ref("work-long", "series")),
            ]
    );
    assert!(listing(&mut wire, "work").await.is_empty());
    assert!(fixture
        .store
        .calendar_rows(fixture.account_id, "work")
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn a_remote_event_already_gone_still_deletes() {
    let fixture = fixture().await;
    let writer = Arc::new(FakeCalendarWriter::new());
    *writer.delete_outcome.lock().unwrap() = DeleteOutcome::Gone;
    let mut wire = spawn_writable(&fixture, Arc::clone(&writer), vec![USER.to_string()]);

    let baseline = ctag(&mut wire, "work").await;
    let listed = listing(&mut wire, "work").await;
    let (href, etag) = listed[0].clone();

    let condition = format!("If-Match: {etag}");
    let response = wire.request("DELETE", &href, &[&condition], "").await;
    assert_eq!(response.status, 204);
    assert!(row_of(&fixture, "e1").await.is_none());
    assert!(writer.delete_calls() == [(calendar_ref(), event_ref("work-short", "e1"))]);
    assert_ne!(ctag(&mut wire, "work").await, baseline);
}

// ---------------------------------------------------------------------------
// Advertised methods, read-only answers, collections
// ---------------------------------------------------------------------------

#[tokio::test]
async fn write_methods_are_advertised_and_collections_refuse_writes() {
    let fixture = fixture().await;
    let writer = Arc::new(FakeCalendarWriter::new());
    let mut wire = spawn_writable(&fixture, Arc::clone(&writer), vec![USER.to_string()]);

    let options = wire.request("OPTIONS", "/", &[], "").await;
    assert_eq!(options.status, 200);
    assert_eq!(options.header("DAV"), Some("1, 3, calendar-access"));
    let allow = options.header("Allow").unwrap();
    assert!(allow.contains("PUT"));
    assert!(allow.contains("DELETE"));

    // Collections are not writable, whatever the body.
    let body = body_of(&plain_event("x", "uid-x", NOW_MS + DAY_MS));
    let put = wire
        .request("PUT", "/caldav/calendars/work/", &[], &body)
        .await;
    assert_eq!(put.status, 403);
    let root = wire.request("PUT", "/", &[], &body).await;
    assert_eq!(root.status, 403);
    let delete = wire
        .request("DELETE", "/caldav/calendars/work/", &[], "")
        .await;
    assert_eq!(delete.status, 403);
    assert!(writer.put_calls().is_empty());
    assert!(writer.delete_calls().is_empty());

    // Without a writer the same Allow is served and both answers are
    // byte-identical to the read-only refusal the session used.
    let mut readonly = spawn_readonly(&fixture);
    let options = readonly.request("OPTIONS", "/", &[], "").await;
    assert!(options.header("Allow").unwrap().contains("PUT"));
    let listed = listing(&mut readonly, "work").await;
    let (href, _) = listed[0].clone();
    let put = readonly.request("PUT", &href, &[], &body).await;
    assert_eq!(put.status, 403);
    assert_eq!(put.body, "forbidden: this server is read-only\n");
    let delete = readonly.request("DELETE", &href, &[], "").await;
    assert_eq!(delete.status, 403);
    assert_eq!(delete.body, "forbidden: this server is read-only\n");
}
