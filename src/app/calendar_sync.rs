//! Keep the CalDAV metadata cache in step with Tuta.
//!
//! [`CalendarSync::reload`] is the baseline: it lists the calendars and
//! loads every event that may overlap the loading window — two years
//! back to two years ahead of now, every repeating event whose rule has
//! not ended before the window — then replaces the cached rows. Rows
//! whose content did not change keep their stamp, so a reload never
//! changes an ETag.
//!
//! [`CalendarSync::apply`] handles the calendar entity updates of one
//! event-bus batch (the mail processor skips them): an event created or
//! updated is reloaded and its row upserted (or dropped when it left
//! the window or became unreadable), a deleted one loses its row, and a
//! change to the calendar list itself (membership, names, colours)
//! refreshes the list. A lookup that fails marks the cache stale and
//! the next batch reloads it in full instead.
//!
//! Reports carry counters only.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::domain::calendar::{
    CALENDAR_GROUP_ROOT_TYPE_ID, DAY_MS, GROUP_INFO_TYPE_ID, SYS_APP,
    USER_SETTINGS_GROUP_ROOT_TYPE_ID, USER_TYPE_ID,
};
use crate::domain::{
    CalendarInfo, EntityEvent, EntityOperation, EventBatch, Result, CALENDAR_EVENT_TYPE_ID,
    TUTANOTA_APP,
};
use crate::ports::calendar::{CalendarSource, CalendarStore};
use crate::ports::clock::Clock;

/// How far back the window reaches.
pub const WINDOW_PAST_MS: i64 = 730 * DAY_MS;
/// How far ahead the window reaches.
pub const WINDOW_FUTURE_MS: i64 = 730 * DAY_MS;

/// What one reload or batch did, as counters.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CalendarReport {
    /// Calendars listed (a reload or a list refresh), else 0.
    pub calendars: usize,
    /// Events stored by a reload.
    pub events: usize,
    /// Rows inserted or updated by a batch.
    pub updated: usize,
    /// Rows removed by a batch.
    pub removed: usize,
    /// Whether this was a full reload.
    pub reloaded: bool,
}

impl CalendarReport {
    /// A fixed-text line with the counters, or `None` when nothing
    /// worth printing happened.
    pub fn summary(&self) -> Option<String> {
        if self.reloaded {
            return Some(format!(
                "calendars loaded: {} calendars, {} events",
                self.calendars, self.events
            ));
        }
        if self.updated + self.removed > 0 {
            return Some(format!(
                "calendar events: {} updated, {} removed",
                self.updated, self.removed
            ));
        }
        None
    }
}

/// Whether `event` is a calendar event update.
pub fn is_calendar_event(event: &EntityEvent) -> bool {
    event.application == TUTANOTA_APP && event.type_id == CALENDAR_EVENT_TYPE_ID
}

/// Whether `event` may change the list of calendars, their names or
/// their colours.
pub fn changes_calendar_list(event: &EntityEvent) -> bool {
    (event.application == TUTANOTA_APP
        && matches!(
            event.type_id,
            USER_SETTINGS_GROUP_ROOT_TYPE_ID | CALENDAR_GROUP_ROOT_TYPE_ID
        ))
        || (event.application == SYS_APP
            && matches!(event.type_id, USER_TYPE_ID | GROUP_INFO_TYPE_ID))
}

/// Keeps one account's calendar cache current.
pub struct CalendarSync {
    pub account_id: i64,
    pub store: Arc<dyn CalendarStore>,
    pub source: Arc<dyn CalendarSource>,
    pub clock: Arc<dyn Clock>,
    /// A full reload is due: nothing loaded yet, or a lookup failed.
    stale: AtomicBool,
}

impl CalendarSync {
    pub fn new(
        account_id: i64,
        store: Arc<dyn CalendarStore>,
        source: Arc<dyn CalendarSource>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            account_id,
            store,
            source,
            clock,
            stale: AtomicBool::new(true),
        }
    }

    /// Whether the next [`Self::apply`] reloads everything.
    pub fn is_stale(&self) -> bool {
        self.stale.load(Ordering::SeqCst)
    }

    /// Force a full reload at the next [`Self::apply`].
    pub fn mark_stale(&self) {
        self.stale.store(true, Ordering::SeqCst);
    }

    /// The loading window around now.
    pub fn window(&self) -> (i64, i64) {
        let now = self.clock.now_ms();
        (
            now.saturating_sub(WINDOW_PAST_MS),
            now.saturating_add(WINDOW_FUTURE_MS),
        )
    }

    /// Load every calendar and its events and replace the cache. The
    /// cache stays stale when this fails.
    pub async fn reload(&self) -> Result<CalendarReport> {
        self.mark_stale();
        let calendars = self.source.calendars().await?;
        // Load everything before writing: a failure leaves the old
        // cache untouched.
        let (from, to) = self.window();
        let mut loaded = Vec::with_capacity(calendars.len());
        for calendar in &calendars {
            loaded.push(self.source.events(calendar, from, to).await?);
        }
        self.store
            .replace_calendars(self.account_id, &calendars)
            .await?;
        let now = self.clock.now_ms();
        let mut events = 0;
        for (calendar, calendar_events) in calendars.iter().zip(loaded) {
            let rows: Vec<_> = calendar_events
                .iter()
                .map(|event| event.row(&calendar.calendar_id, now))
                .collect();
            events += rows.len();
            self.store
                .replace_calendar_rows(self.account_id, &calendar.calendar_id, &rows)
                .await?;
        }
        self.stale.store(false, Ordering::SeqCst);
        Ok(CalendarReport {
            calendars: calendars.len(),
            events,
            reloaded: true,
            ..CalendarReport::default()
        })
    }

    /// Apply the calendar updates of one batch. A stale cache is
    /// reloaded in full instead; a failed lookup marks it stale and
    /// returns the error.
    pub async fn apply(&self, batch: &EventBatch) -> Result<CalendarReport> {
        let calendar_events: Vec<&EntityEvent> = batch
            .events
            .iter()
            .filter(|e| is_calendar_event(e))
            .collect();
        let list_changed = batch.events.iter().any(changes_calendar_list);
        if self.is_stale() {
            return self.reload().await;
        }
        if calendar_events.is_empty() && !list_changed {
            return Ok(CalendarReport::default());
        }
        let result = self.apply_events(&calendar_events, list_changed).await;
        if result.is_err() {
            self.mark_stale();
        }
        result
    }

    async fn apply_events(
        &self,
        events: &[&EntityEvent],
        list_changed: bool,
    ) -> Result<CalendarReport> {
        let mut report = CalendarReport::default();
        let mut calendars = self.store.calendars(self.account_id).await?;
        let mut refreshed = false;
        if list_changed {
            calendars = self.refresh_calendars(&mut report).await?;
            refreshed = true;
        }
        let (from, to) = self.window();
        for event in events {
            let mut owner = owning_calendar(&calendars, &event.list_id);
            if owner.is_none() && !refreshed && event.operation != EntityOperation::Delete {
                // A list no stored calendar owns: a calendar this cache
                // has not seen yet.
                calendars = self.refresh_calendars(&mut report).await?;
                refreshed = true;
                owner = owning_calendar(&calendars, &event.list_id);
            }
            match event.operation {
                EntityOperation::Delete => {
                    if self
                        .store
                        .remove_calendar_row(self.account_id, &event.list_id, &event.element_id)
                        .await?
                    {
                        report.removed += 1;
                    }
                }
                EntityOperation::Create | EntityOperation::Update => {
                    let Some(calendar_id) = owner else {
                        continue;
                    };
                    match self.source.event(&event.list_id, &event.element_id).await? {
                        Some(loaded) if loaded.may_overlap(from, to) => {
                            let row = loaded.row(&calendar_id, self.clock.now_ms());
                            self.store
                                .upsert_calendar_row(self.account_id, &row)
                                .await?;
                            report.updated += 1;
                        }
                        // Gone, unreadable or outside the window.
                        _ => {
                            if self
                                .store
                                .remove_calendar_row(
                                    self.account_id,
                                    &event.list_id,
                                    &event.element_id,
                                )
                                .await?
                            {
                                report.removed += 1;
                            }
                        }
                    }
                }
            }
        }
        Ok(report)
    }

    /// Re-read the calendar list; a calendar new to the cache gets its
    /// events loaded.
    async fn refresh_calendars(&self, report: &mut CalendarReport) -> Result<Vec<CalendarInfo>> {
        let stored = self.store.calendars(self.account_id).await?;
        let calendars = self.source.calendars().await?;
        let (from, to) = self.window();
        let mut added = Vec::new();
        for calendar in calendars
            .iter()
            .filter(|c| !stored.iter().any(|s| s.calendar_id == c.calendar_id))
        {
            added.push((calendar, self.source.events(calendar, from, to).await?));
        }
        self.store
            .replace_calendars(self.account_id, &calendars)
            .await?;
        let now = self.clock.now_ms();
        for (calendar, events) in added {
            let rows: Vec<_> = events
                .iter()
                .map(|event| event.row(&calendar.calendar_id, now))
                .collect();
            report.updated += rows.len();
            self.store
                .replace_calendar_rows(self.account_id, &calendar.calendar_id, &rows)
                .await?;
        }
        report.calendars = calendars.len();
        Ok(calendars)
    }
}

fn owning_calendar(calendars: &[CalendarInfo], list_id: &str) -> Option<String> {
    calendars
        .iter()
        .find(|calendar| calendar.short_list_id == list_id || calendar.long_list_id == list_id)
        .map(|calendar| calendar.calendar_id.clone())
}
