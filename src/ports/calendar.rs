//! The calendar seams of the CalDAV server: where events come from
//! ([`CalendarSource`]) and where their metadata is cached
//! ([`CalendarStore`]).

use crate::domain::{CalendarEvent, CalendarInfo, CalendarRow, Result};

/// Read access to the account's calendars.
///
/// Errors carry fixed text only. `Error::Network` means "try again
/// later"; nothing from an event or an id reaches an error string.
#[async_trait::async_trait]
pub trait CalendarSource: Send + Sync {
    /// Every calendar the user is a member of. Synthetic calendars
    /// (Tuta's client-side birthday calendar) are not included.
    async fn calendars(&self) -> Result<Vec<CalendarInfo>>;

    /// The events of `calendar` that may overlap `[from_ms, to_ms)`:
    /// every repeating event whose rule has not ended before `from_ms`,
    /// and every other event overlapping the range. Unreadable events
    /// are left out.
    async fn events(
        &self,
        calendar: &CalendarInfo,
        from_ms: i64,
        to_ms: i64,
    ) -> Result<Vec<CalendarEvent>>;

    /// One event, or `Ok(None)` when it no longer exists or cannot be
    /// decrypted.
    async fn event(&self, list_id: &str, element_id: &str) -> Result<Option<CalendarEvent>>;

    /// The alarm triggers (`"15M"`, `"1H"`, `"1D"`, `"1W"`, ...) of the
    /// given `UserAlarmInfo` ids that belong to the user; alarms of
    /// other users are not readable and are skipped.
    async fn alarm_triggers(&self, alarm_ids: &[(String, String)]) -> Result<Vec<String>>;
}

/// The calendar metadata cache. Rows carry ids, times and fingerprints:
/// never a title, a description or an address.
#[async_trait::async_trait]
pub trait CalendarStore: Send + Sync {
    /// Replace the stored calendar list; calendars absent from
    /// `calendars` lose their rows.
    async fn replace_calendars(&self, account_id: i64, calendars: &[CalendarInfo]) -> Result<()>;

    /// The stored calendars, ordered by id.
    async fn calendars(&self, account_id: i64) -> Result<Vec<CalendarInfo>>;

    /// Replace every row of one calendar. A row whose fingerprint is
    /// unchanged keeps its stored `modified_ms`, so a reload never
    /// changes an ETag.
    async fn replace_calendar_rows(
        &self,
        account_id: i64,
        calendar_id: &str,
        rows: &[CalendarRow],
    ) -> Result<()>;

    /// Insert or update one row (same `modified_ms` rule) and return it
    /// as stored.
    async fn upsert_calendar_row(&self, account_id: i64, row: &CalendarRow) -> Result<CalendarRow>;

    /// Remove one row; whether it existed.
    async fn remove_calendar_row(
        &self,
        account_id: i64,
        list_id: &str,
        element_id: &str,
    ) -> Result<bool>;

    /// Every row of one calendar.
    async fn calendar_rows(&self, account_id: i64, calendar_id: &str) -> Result<Vec<CalendarRow>>;
}
