//! Integration contract for the read-only CalDAV server: the handler
//! over the shared DAV session (in-memory duplex), backed by the real
//! SQLite metadata cache and a fake calendar source. Covers the
//! Thunderbird flow — discovery, ctag/getetag listing, multiget — plus
//! calendar-query with a time range, GET with ETag/304, the read-only
//! answers, and ETag stability across reloads.

mod support;

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use tokio::io::{split, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tuta_bridge::adapters::caldav::CalDavHandler;
use tuta_bridge::adapters::dav::{run_dav_session, DavHandler, DavLimits};
use tuta_bridge::adapters::sqlite_state::SqliteStateStore;
use tuta_bridge::app::calendar_sync::CalendarSync;
use tuta_bridge::domain::calendar::DAY_MS;
use tuta_bridge::domain::{
    CalendarEvent, CalendarInfo, EntityEvent, EntityOperation, EventAttendee, EventBatch,
    EventPerson, RepeatRule, Result, CALENDAR_EVENT_TYPE_ID, TUTANOTA_APP,
};
use tuta_bridge::ports::calendar::CalendarStore;
use tuta_bridge::ports::clock::Clock;
use tuta_bridge::ports::imap_backend::ImapBackend;
use tuta_bridge::ports::state_store::StateStore;

use support::{FakeCalendarSource, FakeImapBackend};

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

fn calendar(id: &str, name: &str) -> CalendarInfo {
    CalendarInfo {
        calendar_id: id.into(),
        name: name.into(),
        color: "2196f3".into(),
        short_list_id: format!("{id}-short"),
        long_list_id: format!("{id}-long"),
    }
}

fn event(calendar_id: &str, element: &str, uid: &str, start_ms: i64) -> CalendarEvent {
    CalendarEvent {
        list_id: format!("{calendar_id}-short"),
        element_id: element.into(),
        uid: Some(uid.into()),
        summary: format!("Event {element}"),
        description: String::new(),
        location: "Room 1".into(),
        start_ms,
        end_ms: start_ms + HOUR,
        sequence: 0,
        recurrence_id_ms: None,
        repeat: None,
        alarm_ids: vec![("alarms".into(), format!("alarm-{element}"))],
        organizer: Some(EventPerson {
            name: "Ann".into(),
            address: "ann@example.invalid".into(),
        }),
        attendees: vec![EventAttendee {
            person: EventPerson {
                name: "Bob".into(),
                address: "bob@example.invalid".into(),
            },
            status: 2,
        }],
    }
}

struct Fixture {
    source: Arc<FakeCalendarSource>,
    store: Arc<SqliteStateStore>,
    sync: Arc<CalendarSync>,
    clock: Arc<TestClock>,
    handler: Arc<CalDavHandler>,
}

/// One calendar "work" with a weekly series (master + one moved
/// occurrence, sharing a UID), a meeting tomorrow, and one next month;
/// plus an empty second calendar.
async fn fixture() -> Fixture {
    let source = Arc::new(FakeCalendarSource::new());
    source.add_calendar(calendar("work", "Work"));
    source.add_calendar(calendar("home", ""));

    let mut master = event("work", "series", "series-uid", NOW_MS);
    master.list_id = "work-long".into();
    master.repeat = Some(RepeatRule {
        frequency: 1,
        interval: 1,
        end_type: 0,
        end_value: None,
        time_zone: "Europe/Berlin".into(),
        excluded_ms: vec![NOW_MS + 7 * DAY_MS],
        advanced: Vec::new(),
    });
    let mut moved = event(
        "work",
        "moved",
        "series-uid",
        NOW_MS + 7 * DAY_MS + 2 * HOUR,
    );
    moved.recurrence_id_ms = Some(NOW_MS + 7 * DAY_MS);
    source.put_event(master);
    source.put_event(moved);
    source.put_event(event("work", "tomorrow", "tomorrow-uid", NOW_MS + DAY_MS));
    source.put_event(event("work", "later", "later-uid", NOW_MS + 30 * DAY_MS));
    source.put_alarm("alarms", "alarm-tomorrow", "15M");

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
    let handler = Arc::new(CalDavHandler {
        account_id,
        user_address: USER.into(),
        store: Arc::clone(&store) as Arc<dyn CalendarStore>,
        source: Arc::clone(&source) as _,
        clock: Arc::clone(&clock) as Arc<dyn Clock>,
    });
    Fixture {
        source,
        store,
        sync,
        clock,
        handler,
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
        if method != "HEAD" {
            if let Some(length) = response.header("Content-Length") {
                let mut body = vec![0; length.parse().unwrap()];
                self.reader.read_exact(&mut body).await.unwrap();
                response.body = String::from_utf8(body).unwrap();
            }
        }
        response
    }

    async fn line(&mut self) -> String {
        let mut buf = Vec::new();
        let read = self.reader.read_until(b'\n', &mut buf).await.unwrap();
        assert!(read > 0, "the server closed the stream unexpectedly");
        String::from_utf8(buf)
            .unwrap()
            .trim_end_matches("\r\n")
            .to_string()
    }

    async fn propfind(&mut self, path: &str, depth: &str, body: &str) -> Response {
        let depth = format!("Depth: {depth}");
        self.request(
            "PROPFIND",
            path,
            &[&depth, "Content-Type: application/xml"],
            body,
        )
        .await
    }

    async fn report(&mut self, path: &str, body: &str) -> Response {
        self.request(
            "REPORT",
            path,
            &["Depth: 1", "Content-Type: application/xml"],
            body,
        )
        .await
    }
}

fn spawn(handler: &Arc<CalDavHandler>) -> (Wire, tokio::task::JoinHandle<Result<()>>) {
    let backend = Arc::new(FakeImapBackend::new(USER, PASSWORD));
    let (client, server) = tokio::io::duplex(1024 * 1024);
    let limits = DavLimits {
        login_failure_delay: Duration::from_millis(1),
        ..DavLimits::default()
    };
    let session = tokio::spawn(run_dav_session(
        server,
        backend as Arc<dyn ImapBackend>,
        Arc::clone(handler) as Arc<dyn DavHandler>,
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

const ETAG_PROPFIND: &str = r#"<?xml version="1.0"?><d:propfind xmlns:d="DAV:"><d:prop><d:getetag/><d:resourcetype/><d:getcontenttype/></d:prop></d:propfind>"#;

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

async fn ctag(wire: &mut Wire, calendar: &str) -> String {
    let response = wire
        .propfind(
            &format!("/caldav/calendars/{calendar}/"),
            "0",
            r#"<d:propfind xmlns:d="DAV:" xmlns:cs="http://calendarserver.org/ns/"><d:prop><cs:getctag/><d:sync-token/></d:prop></d:propfind>"#,
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
// Discovery
// ---------------------------------------------------------------------------

#[tokio::test]
async fn thunderbird_discovery_finds_every_calendar() {
    let fixture = fixture().await;
    let (mut wire, _session) = spawn(&fixture.handler);

    let response = wire.request("OPTIONS", "/", &[], "").await;
    assert_eq!(response.header("DAV"), Some("1, 3, calendar-access"));

    let response = wire
        .request("PROPFIND", "/.well-known/caldav", &["Depth: 0"], "")
        .await;
    assert_eq!(response.status, 301);
    assert_eq!(response.header("Location"), Some("/caldav/principal/"));

    // The URL the user typed: the root names the principal and home.
    let response = wire
        .propfind(
            "/",
            "0",
            r#"<d:propfind xmlns:d="DAV:"><d:prop><d:current-user-principal/><d:resourcetype/></d:prop></d:propfind>"#,
        )
        .await;
    assert_eq!(response.status, 207);
    assert!(response.body.contains(
        "<d:current-user-principal><d:href>/caldav/principal/</d:href></d:current-user-principal>"
    ));

    let response = wire
        .propfind(
            "/caldav/principal/",
            "0",
            r#"<d:propfind xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:prop><c:calendar-home-set/><c:calendar-user-address-set/><d:resourcetype/></d:prop></d:propfind>"#,
        )
        .await;
    assert!(response.body.contains(
        "<cal:calendar-home-set><d:href>/caldav/calendars/</d:href></cal:calendar-home-set>"
    ));
    assert!(response
        .body
        .contains("<d:href>mailto:user@example.invalid</d:href>"));
    assert!(response.body.contains("<d:principal/>"));

    let response = wire
        .propfind(
            "/caldav/calendars/",
            "1",
            r#"<d:propfind xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav" xmlns:cs="http://calendarserver.org/ns/" xmlns:i="http://apple.com/ns/ical/"><d:prop><d:resourcetype/><d:displayname/><i:calendar-color/><c:supported-calendar-component-set/><d:current-user-privilege-set/><cs:getctag/><d:supported-report-set/></d:prop></d:propfind>"#,
        )
        .await;
    assert_eq!(response.status, 207);
    let listed = hrefs(&response.body);
    assert_eq!(
        listed,
        vec![
            "/caldav/calendars/".to_string(),
            "/caldav/calendars/home/".to_string(),
            "/caldav/calendars/work/".to_string(),
        ]
    );
    let work = &response.body[response.body.find("/caldav/calendars/work/").unwrap()..];
    assert!(work.contains("<d:resourcetype><d:collection/><cal:calendar/></d:resourcetype>"));
    assert!(work.contains("<d:displayname>Work</d:displayname>"));
    assert!(work.contains("<ical:calendar-color>#2196F3</ical:calendar-color>"));
    assert!(work.contains(
        "<cal:supported-calendar-component-set><cal:comp name=\"VEVENT\"/></cal:supported-calendar-component-set>"
    ));
    assert!(work.contains(
        "<d:current-user-privilege-set><d:privilege><d:read/></d:privilege></d:current-user-privilege-set>"
    ));
    assert!(work.contains("<cal:calendar-multiget/>"));
    assert!(work.contains("<cal:calendar-query/>"));
    assert!(!work.contains("sync-collection"));
    // The unnamed default calendar gets a fixed name.
    assert_eq!(
        prop_after(&response.body, "/caldav/calendars/home/", "d:displayname").as_deref(),
        Some("Calendar")
    );
}

#[tokio::test]
async fn a_calendar_lists_one_resource_per_uid() {
    let fixture = fixture().await;
    let (mut wire, _session) = spawn(&fixture.handler);
    let listed = listing(&mut wire, "work").await;
    // series + moved share one resource; tomorrow and later.
    assert_eq!(listed.len(), 3);
    for (href, etag) in &listed {
        assert!(href.starts_with("/caldav/calendars/work/"));
        assert!(etag.starts_with('"') && etag.ends_with('"'));
    }
    let response = wire
        .propfind("/caldav/calendars/work/", "1", ETAG_PROPFIND)
        .await;
    assert!(response.body.contains(
        "<d:getcontenttype>text/calendar; charset=utf-8; component=VEVENT</d:getcontenttype>"
    ));
    // Infinity is served as one level.
    let infinite = wire
        .propfind("/caldav/calendars/work/", "infinity", ETAG_PROPFIND)
        .await;
    assert_eq!(hrefs(&infinite.body).len(), 4);
    assert!(listing(&mut wire, "home").await.is_empty());
    let missing = wire.propfind("/caldav/calendars/nope/", "0", "").await;
    assert_eq!(missing.status, 404);
}

// ---------------------------------------------------------------------------
// Reports
// ---------------------------------------------------------------------------

#[tokio::test]
async fn multiget_returns_calendar_data_matching_the_listed_etags() {
    let fixture = fixture().await;
    let (mut wire, _session) = spawn(&fixture.handler);
    let listed = listing(&mut wire, "work").await;
    let mut body = String::from(
        r#"<c:calendar-multiget xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:prop><d:getetag/><c:calendar-data/></d:prop>"#,
    );
    for (href, _) in &listed {
        body.push_str(&format!("<d:href>{href}</d:href>"));
    }
    body.push_str("<d:href>/caldav/calendars/work/ffff.ics</d:href></c:calendar-multiget>");
    let response = wire.report("/caldav/calendars/work/", &body).await;
    assert_eq!(response.status, 207);
    for (href, etag) in &listed {
        let served = unescape(&prop_after(&response.body, href, "d:getetag").unwrap());
        assert_eq!(&served, etag, "multiget etag equals the listing etag");
        let data = unescape(&prop_after(&response.body, href, "cal:calendar-data").unwrap());
        assert!(data.starts_with("BEGIN:VCALENDAR"));
        assert!(data.trim_end().ends_with("END:VCALENDAR"));
    }
    let series = listed
        .iter()
        .map(|(href, _)| unescape(&prop_after(&response.body, href, "cal:calendar-data").unwrap()))
        .find(|data| data.contains("RRULE"))
        .expect("the series resource");
    assert_eq!(series.matches("BEGIN:VEVENT").count(), 2);
    assert!(series.contains("RRULE:FREQ=WEEKLY"));
    assert!(series.contains("DTSTART;TZID=Europe/Berlin:20250106T090000"));
    assert!(series.contains("RECURRENCE-ID:20250113T080000Z"));
    assert!(series.contains("BEGIN:VTIMEZONE"));
    assert!(response.body.contains(
        "<d:response><d:href>/caldav/calendars/work/ffff.ics</d:href><d:status>HTTP/1.1 404 Not Found</d:status></d:response>"
    ));
}

#[tokio::test]
async fn calendar_query_honours_the_time_range_and_component() {
    let fixture = fixture().await;
    let (mut wire, _session) = spawn(&fixture.handler);
    let query = |start: &str, end: &str, component: &str| {
        format!(
            r#"<c:calendar-query xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:prop><d:getetag/></d:prop><c:filter><c:comp-filter name="VCALENDAR"><c:comp-filter name="{component}"><c:time-range start="{start}" end="{end}"/></c:comp-filter></c:comp-filter></c:filter></c:calendar-query>"#
        )
    };
    // Tomorrow only, plus the open-ended series.
    let response = wire
        .report(
            "/caldav/calendars/work/",
            &query("20250107T000000Z", "20250108T000000Z", "VEVENT"),
        )
        .await;
    assert_eq!(response.status, 207);
    assert_eq!(hrefs(&response.body).len(), 2);
    // Next month: the later event and the series.
    let response = wire
        .report(
            "/caldav/calendars/work/",
            &query("20250201T000000Z", "20250210T000000Z", "VEVENT"),
        )
        .await;
    assert_eq!(hrefs(&response.body).len(), 2);
    // Before everything: nothing.
    let response = wire
        .report(
            "/caldav/calendars/work/",
            &query("20240101T000000Z", "20240102T000000Z", "VEVENT"),
        )
        .await;
    assert!(hrefs(&response.body).is_empty());
    // Tasks: none.
    let response = wire
        .report(
            "/caldav/calendars/work/",
            &query("20250101T000000Z", "20260101T000000Z", "VTODO"),
        )
        .await;
    assert_eq!(response.status, 207);
    assert!(hrefs(&response.body).is_empty());
    // Other reports are refused.
    let response = wire
        .report(
            "/caldav/calendars/work/",
            r#"<d:sync-collection xmlns:d="DAV:"><d:sync-token/><d:prop><d:getetag/></d:prop></d:sync-collection>"#,
        )
        .await;
    assert_eq!(response.status, 403);
}

// ---------------------------------------------------------------------------
// GET
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_serves_icalendar_with_a_stable_etag_and_304() {
    let fixture = fixture().await;
    let (mut wire, _session) = spawn(&fixture.handler);
    let listed = listing(&mut wire, "work").await;
    let mut found_alarm = false;
    for (href, etag) in &listed {
        let response = wire.request("GET", href, &[], "").await;
        assert_eq!(response.status, 200);
        assert_eq!(
            response.header("Content-Type"),
            Some("text/calendar; charset=utf-8")
        );
        assert_eq!(response.header("ETag"), Some(etag.as_str()));
        let unfolded = response.body.replace("\r\n ", "");
        assert!(unfolded.contains("\r\nORGANIZER;CN=Ann:mailto:ann@example.invalid\r\n"));
        assert!(unfolded.contains("PARTSTAT=ACCEPTED:mailto:bob@example.invalid\r\n"));
        assert!(unfolded.contains("\r\nLOCATION:Room 1\r\n"));
        found_alarm |= unfolded.contains("TRIGGER:-PT15M");
        let again = wire.request("GET", href, &[], "").await;
        assert_eq!(again.body, response.body, "byte-identical for one ETag");
        let header = format!("If-None-Match: {etag}");
        let cached = wire.request("GET", href, &[&header], "").await;
        assert_eq!(cached.status, 304);
    }
    assert!(found_alarm);
    let missing = wire
        .request("GET", "/caldav/calendars/work/0000.ics", &[], "")
        .await;
    assert_eq!(missing.status, 404);
    let collection = wire
        .request("GET", "/caldav/calendars/work/", &[], "")
        .await;
    assert_eq!(collection.status, 405);
}

#[tokio::test]
async fn writes_are_forbidden() {
    let fixture = fixture().await;
    let (mut wire, _session) = spawn(&fixture.handler);
    let listed = listing(&mut wire, "work").await;
    let ics = "BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n";
    for method in ["PUT", "DELETE", "MKCALENDAR", "PROPPATCH"] {
        let response = wire
            .request(method, &listed[0].0, &["Content-Type: text/calendar"], ics)
            .await;
        assert_eq!(response.status, 403, "{method}");
    }
    let put_new = wire
        .request(
            "PUT",
            "/caldav/calendars/work/new.ics",
            &["Content-Type: text/calendar"],
            ics,
        )
        .await;
    assert_eq!(put_new.status, 403);
    assert_eq!(fixture.source.events.lock().unwrap().len(), 4);
}

// ---------------------------------------------------------------------------
// Freshness
// ---------------------------------------------------------------------------

fn calendar_batch(operation: EntityOperation, list_id: &str, element_id: &str) -> EventBatch {
    EventBatch {
        batch_id: "batch".into(),
        owner_group_id: "work".into(),
        application_types_hash: String::new(),
        events: vec![EntityEvent {
            application: TUTANOTA_APP.into(),
            type_id: CALENDAR_EVENT_TYPE_ID,
            list_id: list_id.into(),
            element_id: element_id.into(),
            operation,
        }],
    }
}

#[tokio::test]
async fn a_reload_keeps_etags_and_the_ctag_and_an_edit_changes_them() {
    let fixture = fixture().await;
    let (mut wire, _session) = spawn(&fixture.handler);
    let before = listing(&mut wire, "work").await;
    let ctag_before = ctag(&mut wire, "work").await;

    // A later reload of unchanged data changes nothing.
    fixture.clock.0.store(NOW_MS + HOUR, Ordering::SeqCst);
    fixture.sync.reload().await.unwrap();
    assert_eq!(listing(&mut wire, "work").await, before);
    assert_eq!(ctag(&mut wire, "work").await, ctag_before);

    // An edit delivered by the event bus changes one ETag and the ctag.
    let mut edited = event("work", "tomorrow", "tomorrow-uid", NOW_MS + DAY_MS);
    edited.summary = "Moved meeting".into();
    fixture.source.put_event(edited);
    fixture
        .sync
        .apply(&calendar_batch(
            EntityOperation::Update,
            "work-short",
            "tomorrow",
        ))
        .await
        .unwrap();
    let after = listing(&mut wire, "work").await;
    assert_eq!(after.len(), 3);
    let changed: Vec<_> = after.iter().filter(|pair| !before.contains(pair)).collect();
    assert_eq!(changed.len(), 1);
    let body = wire.request("GET", &changed[0].0, &[], "").await.body;
    assert!(body.contains("SUMMARY:Moved meeting"));
    let ctag_after = ctag(&mut wire, "work").await;
    assert_ne!(ctag_after, ctag_before);

    // A delete removes the resource.
    fixture.source.remove_event("work-short", "tomorrow");
    fixture
        .sync
        .apply(&calendar_batch(
            EntityOperation::Delete,
            "work-short",
            "tomorrow",
        ))
        .await
        .unwrap();
    assert_eq!(listing(&mut wire, "work").await.len(), 2);
}

#[tokio::test]
async fn a_get_ahead_of_the_event_bus_updates_the_cached_etag() {
    let fixture = fixture().await;
    let (mut wire, _session) = spawn(&fixture.handler);
    let before = listing(&mut wire, "work").await;
    let (href, old_etag) = before[0].clone();
    // Edit every event behind the cache's back.
    let edited: Vec<CalendarEvent> = fixture
        .source
        .events
        .lock()
        .unwrap()
        .iter()
        .cloned()
        .map(|mut event| {
            event.location = "Room 2".into();
            event
        })
        .collect();
    for event in edited {
        fixture.source.put_event(event);
    }
    let response = wire.request("GET", &href, &[], "").await;
    assert_eq!(response.status, 200);
    assert!(response.body.contains("LOCATION:Room 2"));
    let new_etag = response.header("ETag").unwrap().to_string();
    assert_ne!(new_etag, old_etag);
    // The listing now agrees with the body served.
    let after = listing(&mut wire, "work").await;
    let listed = after.iter().find(|(h, _)| h == &href).unwrap();
    assert_eq!(listed.1, new_etag);
    let rows = fixture.store.calendar_rows(1, "work").await.unwrap();
    assert!(!rows.is_empty());
}

// ---------------------------------------------------------------------------
// Multiget bodies survive a conforming XML parser (CRLF kept)
// ---------------------------------------------------------------------------

/// The text of every element named `local` (any prefix) in `body`, read
/// the way a conforming XML parser does: line ends normalized (XML 1.0
/// §2.11), entities and character references resolved.
fn parsed_element_texts(body: &str, local: &str) -> Vec<String> {
    use quick_xml::events::Event;
    let mut reader = quick_xml::Reader::from_str(body);
    let mut texts = Vec::new();
    let mut current: Option<String> = None;
    loop {
        match reader.read_event().unwrap() {
            Event::Start(start) if start.local_name().as_ref() == local.as_bytes() => {
                current = Some(String::new());
            }
            Event::End(end) if end.local_name().as_ref() == local.as_bytes() => {
                texts.extend(current.take());
            }
            Event::Text(text) => {
                if let Some(current) = current.as_mut() {
                    current.push_str(&text.xml10_content().unwrap());
                }
            }
            Event::GeneralRef(reference) => {
                if let Some(current) = current.as_mut() {
                    let character = match reference.resolve_char_ref().unwrap() {
                        Some(character) => character,
                        None => match &*reference.decode().unwrap() {
                            "amp" => '&',
                            "lt" => '<',
                            "gt" => '>',
                            "quot" => '"',
                            "apos" => '\'',
                            other => panic!("unexpected entity {other}"),
                        },
                    };
                    current.push(character);
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }
    texts
}

#[tokio::test]
async fn multiget_calendar_data_is_byte_identical_to_get_after_xml_parsing() {
    let fixture = fixture().await;
    let (mut wire, _session) = spawn(&fixture.handler);
    let listed = listing(&mut wire, "work").await;
    assert!(!listed.is_empty());
    for (href, _) in &listed {
        let get = wire.request("GET", href, &[], "").await;
        assert_eq!(get.status, 200);
        assert!(get.body.contains("\r\n"));
        let body = format!(
            r#"<c:calendar-multiget xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:prop><d:getetag/><c:calendar-data/></d:prop><d:href>{href}</d:href></c:calendar-multiget>"#
        );
        let response = wire.report("/caldav/calendars/work/", &body).await;
        assert_eq!(response.status, 207);
        let data = parsed_element_texts(&response.body, "calendar-data");
        assert_eq!(data.len(), 1);
        assert_eq!(data[0], get.body, "multiget body equals GET for {href}");
    }
}
