//! Integration contract for the CalDAV metadata cache upkeep: the
//! baseline reload (loading window, unreadable and out-of-window
//! events), calendar entity updates from event-bus batches, calendar
//! list changes, failure handling (stale cache, full reload), and the
//! mail processor leaving calendar events alone.

mod support;

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

use tuta_bridge::adapters::sqlite_state::SqliteStateStore;
use tuta_bridge::app::calendar_sync::{CalendarSync, WINDOW_FUTURE_MS, WINDOW_PAST_MS};
use tuta_bridge::app::event_sync::EventProcessor;
use tuta_bridge::domain::calendar::{DAY_MS, SYS_APP, USER_TYPE_ID};
use tuta_bridge::domain::{
    CalendarEvent, CalendarInfo, EntityEvent, EntityOperation, EventBatch, RepeatRule,
    CALENDAR_EVENT_TYPE_ID, TUTANOTA_APP,
};
use tuta_bridge::ports::calendar::CalendarStore;
use tuta_bridge::ports::clock::Clock;
use tuta_bridge::ports::state_store::StateStore;

use support::{FakeCalendarSource, FakeEventLookup, FakeStateStore};

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
        name: id.into(),
        color: "aabbcc".into(),
        short_list_id: format!("{id}-short"),
        long_list_id: format!("{id}-long"),
    }
}

fn event(list_id: &str, element: &str, start_ms: i64) -> CalendarEvent {
    CalendarEvent {
        list_id: list_id.into(),
        element_id: element.into(),
        uid: Some(format!("uid-{element}")),
        summary: "Title".into(),
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

fn weekly() -> RepeatRule {
    RepeatRule {
        frequency: 1,
        interval: 1,
        end_type: 0,
        end_value: None,
        time_zone: "UTC".into(),
        excluded_ms: Vec::new(),
        advanced: Vec::new(),
    }
}

fn update(
    application: &str,
    type_id: i64,
    operation: EntityOperation,
    list: &str,
    element: &str,
) -> EntityEvent {
    EntityEvent {
        application: application.into(),
        type_id,
        list_id: list.into(),
        element_id: element.into(),
        operation,
    }
}

fn calendar_event(operation: EntityOperation, list: &str, element: &str) -> EntityEvent {
    update(
        TUTANOTA_APP,
        CALENDAR_EVENT_TYPE_ID,
        operation,
        list,
        element,
    )
}

fn batch(events: Vec<EntityEvent>) -> EventBatch {
    EventBatch {
        batch_id: "b1".into(),
        owner_group_id: "g1".into(),
        application_types_hash: String::new(),
        events,
    }
}

struct Fixture {
    source: Arc<FakeCalendarSource>,
    store: Arc<SqliteStateStore>,
    clock: Arc<TestClock>,
    sync: CalendarSync,
    account: i64,
}

async fn fixture() -> Fixture {
    let source = Arc::new(FakeCalendarSource::new());
    source.add_calendar(calendar("work"));
    let store = Arc::new(SqliteStateStore::open_in_memory().await.unwrap());
    let account = store.upsert_account("user@example.invalid").await.unwrap();
    let clock = Arc::new(TestClock(AtomicI64::new(NOW_MS)));
    let sync = CalendarSync::new(
        account,
        Arc::clone(&store) as Arc<dyn CalendarStore>,
        Arc::clone(&source) as _,
        Arc::clone(&clock) as Arc<dyn Clock>,
    );
    Fixture {
        source,
        store,
        clock,
        sync,
        account,
    }
}

async fn elements(fixture: &Fixture, calendar_id: &str) -> Vec<String> {
    let mut ids: Vec<String> = fixture
        .store
        .calendar_rows(fixture.account, calendar_id)
        .await
        .unwrap()
        .into_iter()
        .map(|row| row.element_id)
        .collect();
    ids.sort();
    ids
}

#[tokio::test]
async fn the_baseline_loads_the_window_and_every_running_series() {
    let fixture = fixture().await;
    fixture.source.put_event(event("work-short", "now", NOW_MS));
    fixture.source.put_event(event(
        "work-short",
        "too-old",
        NOW_MS - WINDOW_PAST_MS - DAY_MS,
    ));
    fixture.source.put_event(event(
        "work-short",
        "too-far",
        NOW_MS + WINDOW_FUTURE_MS + DAY_MS,
    ));
    let mut series = event("work-long", "old-series", NOW_MS - 5 * WINDOW_PAST_MS);
    series.repeat = Some(weekly());
    fixture.source.put_event(series);
    let mut ended = event("work-long", "ended-series", NOW_MS - 5 * WINDOW_PAST_MS);
    ended.repeat = Some(RepeatRule {
        end_type: 2,
        end_value: Some(NOW_MS - 4 * WINDOW_PAST_MS),
        ..weekly()
    });
    fixture.source.put_event(ended);

    assert!(fixture.sync.is_stale());
    let report = fixture.sync.reload().await.unwrap();
    assert!(!fixture.sync.is_stale());
    assert_eq!(report.calendars, 1);
    assert_eq!(report.events, 2);
    assert_eq!(
        report.summary().as_deref(),
        Some("calendars loaded: 1 calendars, 2 events")
    );
    assert_eq!(elements(&fixture, "work").await, vec!["now", "old-series"]);
    let rows = fixture
        .store
        .calendar_rows(fixture.account, "work")
        .await
        .unwrap();
    let series_row = rows.iter().find(|r| r.element_id == "old-series").unwrap();
    assert!(series_row.recurring);
    assert_eq!(series_row.series_end_ms, None);
}

#[tokio::test]
async fn reloads_keep_unchanged_rows_byte_for_byte() {
    let fixture = fixture().await;
    fixture.source.put_event(event("work-short", "a", NOW_MS));
    fixture.sync.reload().await.unwrap();
    let first = fixture
        .store
        .calendar_rows(fixture.account, "work")
        .await
        .unwrap();
    fixture.clock.0.store(NOW_MS + DAY_MS, Ordering::SeqCst);
    fixture.sync.reload().await.unwrap();
    let second = fixture
        .store
        .calendar_rows(fixture.account, "work")
        .await
        .unwrap();
    assert!(first == second, "a reload of unchanged data changes no row");
}

#[tokio::test]
async fn batches_create_update_and_delete_rows() {
    let fixture = fixture().await;
    fixture.sync.reload().await.unwrap();

    fixture.source.put_event(event("work-short", "new", NOW_MS));
    let report = fixture
        .sync
        .apply(&batch(vec![calendar_event(
            EntityOperation::Create,
            "work-short",
            "new",
        )]))
        .await
        .unwrap();
    assert_eq!((report.updated, report.removed), (1, 0));
    assert_eq!(
        report.summary().as_deref(),
        Some("calendar events: 1 updated, 0 removed")
    );
    let stamp = fixture
        .store
        .calendar_rows(fixture.account, "work")
        .await
        .unwrap()[0]
        .modified_ms;

    // An update with new content restamps the row; one without does not.
    fixture.clock.0.store(NOW_MS + HOUR, Ordering::SeqCst);
    fixture
        .sync
        .apply(&batch(vec![calendar_event(
            EntityOperation::Update,
            "work-short",
            "new",
        )]))
        .await
        .unwrap();
    assert_eq!(
        fixture
            .store
            .calendar_rows(fixture.account, "work")
            .await
            .unwrap()[0]
            .modified_ms,
        stamp
    );
    let mut edited = event("work-short", "new", NOW_MS);
    edited.summary = "Edited".into();
    fixture.source.put_event(edited);
    fixture
        .sync
        .apply(&batch(vec![calendar_event(
            EntityOperation::Update,
            "work-short",
            "new",
        )]))
        .await
        .unwrap();
    assert_eq!(
        fixture
            .store
            .calendar_rows(fixture.account, "work")
            .await
            .unwrap()[0]
            .modified_ms,
        NOW_MS + HOUR
    );

    // Moved far into the future: out of the window, out of the cache.
    fixture.source.put_event(event(
        "work-short",
        "new",
        NOW_MS + WINDOW_FUTURE_MS + DAY_MS,
    ));
    let report = fixture
        .sync
        .apply(&batch(vec![calendar_event(
            EntityOperation::Update,
            "work-short",
            "new",
        )]))
        .await
        .unwrap();
    assert_eq!(report.removed, 1);
    assert!(elements(&fixture, "work").await.is_empty());

    fixture
        .source
        .put_event(event("work-short", "gone", NOW_MS));
    fixture
        .sync
        .apply(&batch(vec![calendar_event(
            EntityOperation::Create,
            "work-short",
            "gone",
        )]))
        .await
        .unwrap();
    let report = fixture
        .sync
        .apply(&batch(vec![calendar_event(
            EntityOperation::Delete,
            "work-short",
            "gone",
        )]))
        .await
        .unwrap();
    assert_eq!(report.removed, 1);
    assert!(elements(&fixture, "work").await.is_empty());

    // Mail-only batches cost nothing.
    let calls = fixture.source.calls().len();
    let report = fixture
        .sync
        .apply(&batch(vec![update(
            TUTANOTA_APP,
            97,
            EntityOperation::Create,
            "m",
            "e",
        )]))
        .await
        .unwrap();
    assert_eq!(report.summary(), None);
    assert_eq!(fixture.source.calls().len(), calls);
}

#[tokio::test]
async fn an_unknown_list_and_a_membership_change_refresh_the_calendar_list() {
    let fixture = fixture().await;
    fixture.sync.reload().await.unwrap();

    // A calendar shared with the user after the baseline.
    fixture.source.add_calendar(calendar("shared"));
    fixture
        .source
        .put_event(event("shared-short", "s1", NOW_MS));
    fixture.source.put_event(event("shared-long", "s2", NOW_MS));
    fixture
        .sync
        .apply(&batch(vec![calendar_event(
            EntityOperation::Create,
            "shared-short",
            "s1",
        )]))
        .await
        .unwrap();
    assert_eq!(elements(&fixture, "shared").await, vec!["s1", "s2"]);

    // Leaving it: the User update refreshes the list and drops its rows.
    fixture
        .source
        .calendars
        .lock()
        .unwrap()
        .retain(|c| c.calendar_id != "shared");
    let report = fixture
        .sync
        .apply(&batch(vec![update(
            SYS_APP,
            USER_TYPE_ID,
            EntityOperation::Update,
            "",
            "u",
        )]))
        .await
        .unwrap();
    assert_eq!(report.calendars, 1);
    assert!(elements(&fixture, "shared").await.is_empty());
    assert_eq!(
        fixture
            .store
            .calendars(fixture.account)
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn a_failed_lookup_marks_the_cache_stale_and_the_next_batch_reloads() {
    let fixture = fixture().await;
    fixture.sync.reload().await.unwrap();
    fixture.source.put_event(event("work-short", "x", NOW_MS));

    fixture.source.fail_next(1);
    let failed = fixture
        .sync
        .apply(&batch(vec![calendar_event(
            EntityOperation::Create,
            "work-short",
            "x",
        )]))
        .await;
    assert!(failed.is_err());
    assert!(fixture.sync.is_stale());
    assert!(elements(&fixture, "work").await.is_empty());

    // Any next batch (even an unrelated one) reloads everything.
    let report = fixture.sync.apply(&batch(Vec::new())).await.unwrap();
    assert!(report.reloaded);
    assert!(!fixture.sync.is_stale());
    assert_eq!(elements(&fixture, "work").await, vec!["x"]);

    // A failed reload leaves the old cache in place.
    fixture.source.remove_event("work-short", "x");
    fixture.source.fail_next(2);
    assert!(fixture.sync.reload().await.is_err());
    assert!(fixture.sync.is_stale());
    assert_eq!(elements(&fixture, "work").await, vec!["x"]);
}

#[tokio::test]
async fn the_mail_processor_skips_calendar_events() {
    let store = Arc::new(FakeStateStore::new());
    let account = store.upsert_account("user@example.invalid").await.unwrap();
    let lookup = FakeEventLookup::new();
    let report = EventProcessor::new(Arc::clone(&store) as Arc<dyn StateStore>)
        .apply(
            account,
            &lookup,
            7,
            &batch(vec![calendar_event(
                EntityOperation::Create,
                "work-short",
                "e",
            )]),
        )
        .await
        .unwrap();
    assert_eq!(report.changes, 0);
    assert_eq!(report.skipped, 1);
    assert_eq!(report.lookup_failures, 0);
    assert!(report.touched_mailboxes.is_empty());
    assert!(
        lookup.calls().is_empty(),
        "no mail lookup for a calendar event"
    );
}
