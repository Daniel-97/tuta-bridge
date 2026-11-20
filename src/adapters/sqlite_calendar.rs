//! The CalDAV metadata cache, in the state database (schema step 8).
//!
//! Two tables: `calendars` (one row per Tuta calendar: name, colour and
//! the two event lists that map an event back to its calendar) and
//! `calendar_events` (one row per Tuta event: ids, the resource it
//! belongs to, times, a recurrence flag, a content fingerprint and the
//! time the bridge first saw that fingerprint). Event titles, texts,
//! attendees and iCalendar bodies are never stored: bodies are rendered
//! on demand from the SDK.

use sqlx::Row;

use crate::adapters::sqlite_state::{storage_error, SqliteStateStore};
use crate::domain::{CalendarInfo, CalendarRow, Result};
use crate::ports::calendar::CalendarStore;

/// Schema step 8. `IF NOT EXISTS` keeps it idempotent like every step.
pub(crate) const CALENDAR_SCHEMA_STATEMENTS: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS calendars (
        account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
        calendar_id TEXT NOT NULL,          -- the calendar group id
        name TEXT NOT NULL,
        color TEXT NOT NULL,
        short_list_id TEXT NOT NULL,
        long_list_id TEXT NOT NULL,
        PRIMARY KEY (account_id, calendar_id)
    )",
    "CREATE TABLE IF NOT EXISTS calendar_events (
        account_id INTEGER NOT NULL,
        calendar_id TEXT NOT NULL,
        list_id TEXT NOT NULL,
        element_id TEXT NOT NULL,
        resource TEXT NOT NULL,             -- hashed UID: the .ics name
        start_ms INTEGER NOT NULL,
        end_ms INTEGER NOT NULL,
        recurring INTEGER NOT NULL,
        series_end_ms INTEGER,              -- NULL: open-ended rule
        fingerprint TEXT NOT NULL,          -- hash of the rendered content
        modified_ms INTEGER NOT NULL,       -- first seen with this fingerprint
        PRIMARY KEY (account_id, list_id, element_id),
        FOREIGN KEY (account_id, calendar_id)
            REFERENCES calendars(account_id, calendar_id) ON DELETE CASCADE
    )",
    "CREATE INDEX IF NOT EXISTS calendar_events_by_calendar
        ON calendar_events (account_id, calendar_id, resource)",
];

const UPSERT_CALENDAR_SQL: &str = "INSERT INTO calendars
        (account_id, calendar_id, name, color, short_list_id, long_list_id)
     VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT (account_id, calendar_id) DO UPDATE SET
        name = excluded.name,
        color = excluded.color,
        short_list_id = excluded.short_list_id,
        long_list_id = excluded.long_list_id";

/// An unchanged fingerprint keeps the stored `modified_ms`: it is the
/// `DTSTAMP` and part of the ETag, which a reload must not change.
const UPSERT_ROW_SQL: &str = "INSERT INTO calendar_events
        (account_id, calendar_id, list_id, element_id, resource, start_ms, end_ms,
         recurring, series_end_ms, fingerprint, modified_ms)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT (account_id, list_id, element_id) DO UPDATE SET
        calendar_id = excluded.calendar_id,
        resource = excluded.resource,
        start_ms = excluded.start_ms,
        end_ms = excluded.end_ms,
        recurring = excluded.recurring,
        series_end_ms = excluded.series_end_ms,
        modified_ms = CASE
            WHEN calendar_events.fingerprint = excluded.fingerprint
            THEN calendar_events.modified_ms
            ELSE excluded.modified_ms
        END,
        fingerprint = excluded.fingerprint";

const SELECT_ROWS_SQL: &str = "SELECT calendar_id, list_id, element_id, resource, start_ms,
        end_ms, recurring, series_end_ms, fingerprint, modified_ms
     FROM calendar_events WHERE account_id = ? AND calendar_id = ?
     ORDER BY resource, list_id, element_id";

const SELECT_ROW_SQL: &str = "SELECT calendar_id, list_id, element_id, resource, start_ms,
        end_ms, recurring, series_end_ms, fingerprint, modified_ms
     FROM calendar_events WHERE account_id = ? AND list_id = ? AND element_id = ?";

fn row_from(row: &sqlx::sqlite::SqliteRow) -> CalendarRow {
    CalendarRow {
        calendar_id: row.get("calendar_id"),
        list_id: row.get("list_id"),
        element_id: row.get("element_id"),
        resource: row.get("resource"),
        start_ms: row.get("start_ms"),
        end_ms: row.get("end_ms"),
        recurring: row.get::<i64, _>("recurring") != 0,
        series_end_ms: row.get("series_end_ms"),
        fingerprint: row.get("fingerprint"),
        modified_ms: row.get("modified_ms"),
    }
}

async fn upsert_row<'e, E>(executor: E, account_id: i64, row: &CalendarRow) -> Result<()>
where
    E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
{
    sqlx::query(UPSERT_ROW_SQL)
        .bind(account_id)
        .bind(&row.calendar_id)
        .bind(&row.list_id)
        .bind(&row.element_id)
        .bind(&row.resource)
        .bind(row.start_ms)
        .bind(row.end_ms)
        .bind(i64::from(row.recurring))
        .bind(row.series_end_ms)
        .bind(&row.fingerprint)
        .bind(row.modified_ms)
        .execute(executor)
        .await
        .map_err(storage_error)?;
    Ok(())
}

#[async_trait::async_trait]
impl CalendarStore for SqliteStateStore {
    async fn replace_calendars(&self, account_id: i64, calendars: &[CalendarInfo]) -> Result<()> {
        let mut transaction = self
            .pool()
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(storage_error)?;
        let stored: Vec<String> =
            sqlx::query_scalar("SELECT calendar_id FROM calendars WHERE account_id = ?")
                .bind(account_id)
                .fetch_all(&mut *transaction)
                .await
                .map_err(storage_error)?;
        for gone in stored
            .iter()
            .filter(|id| !calendars.iter().any(|c| &c.calendar_id == *id))
        {
            // Rows first: the cascade needs foreign keys on, which a
            // pool connection has, but the order makes it independent.
            sqlx::query("DELETE FROM calendar_events WHERE account_id = ? AND calendar_id = ?")
                .bind(account_id)
                .bind(gone)
                .execute(&mut *transaction)
                .await
                .map_err(storage_error)?;
            sqlx::query("DELETE FROM calendars WHERE account_id = ? AND calendar_id = ?")
                .bind(account_id)
                .bind(gone)
                .execute(&mut *transaction)
                .await
                .map_err(storage_error)?;
        }
        for calendar in calendars {
            sqlx::query(UPSERT_CALENDAR_SQL)
                .bind(account_id)
                .bind(&calendar.calendar_id)
                .bind(&calendar.name)
                .bind(&calendar.color)
                .bind(&calendar.short_list_id)
                .bind(&calendar.long_list_id)
                .execute(&mut *transaction)
                .await
                .map_err(storage_error)?;
        }
        transaction.commit().await.map_err(storage_error)
    }

    async fn calendars(&self, account_id: i64) -> Result<Vec<CalendarInfo>> {
        let rows = sqlx::query(
            "SELECT calendar_id, name, color, short_list_id, long_list_id
             FROM calendars WHERE account_id = ? ORDER BY calendar_id",
        )
        .bind(account_id)
        .fetch_all(self.pool())
        .await
        .map_err(storage_error)?;
        Ok(rows
            .iter()
            .map(|row| CalendarInfo {
                calendar_id: row.get("calendar_id"),
                name: row.get("name"),
                color: row.get("color"),
                short_list_id: row.get("short_list_id"),
                long_list_id: row.get("long_list_id"),
            })
            .collect())
    }

    async fn replace_calendar_rows(
        &self,
        account_id: i64,
        calendar_id: &str,
        rows: &[CalendarRow],
    ) -> Result<()> {
        let mut transaction = self
            .pool()
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(storage_error)?;
        let stored: Vec<(String, String)> = sqlx::query_as(
            "SELECT list_id, element_id FROM calendar_events
             WHERE account_id = ? AND calendar_id = ?",
        )
        .bind(account_id)
        .bind(calendar_id)
        .fetch_all(&mut *transaction)
        .await
        .map_err(storage_error)?;
        for (list_id, element_id) in stored.iter().filter(|(list_id, element_id)| {
            !rows
                .iter()
                .any(|row| &row.list_id == list_id && &row.element_id == element_id)
        }) {
            sqlx::query(
                "DELETE FROM calendar_events
                 WHERE account_id = ? AND list_id = ? AND element_id = ?",
            )
            .bind(account_id)
            .bind(list_id)
            .bind(element_id)
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;
        }
        for row in rows {
            let mut row = row.clone();
            row.calendar_id = calendar_id.to_string();
            upsert_row(&mut *transaction, account_id, &row).await?;
        }
        transaction.commit().await.map_err(storage_error)
    }

    async fn upsert_calendar_row(&self, account_id: i64, row: &CalendarRow) -> Result<CalendarRow> {
        let mut transaction = self
            .pool()
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(storage_error)?;
        upsert_row(&mut *transaction, account_id, row).await?;
        let stored = sqlx::query(SELECT_ROW_SQL)
            .bind(account_id)
            .bind(&row.list_id)
            .bind(&row.element_id)
            .fetch_one(&mut *transaction)
            .await
            .map_err(storage_error)?;
        let stored = row_from(&stored);
        transaction.commit().await.map_err(storage_error)?;
        Ok(stored)
    }

    async fn remove_calendar_row(
        &self,
        account_id: i64,
        list_id: &str,
        element_id: &str,
    ) -> Result<bool> {
        let result = sqlx::query(
            "DELETE FROM calendar_events WHERE account_id = ? AND list_id = ? AND element_id = ?",
        )
        .bind(account_id)
        .bind(list_id)
        .bind(element_id)
        .execute(self.pool())
        .await
        .map_err(storage_error)?;
        Ok(result.rows_affected() > 0)
    }

    async fn calendar_rows(&self, account_id: i64, calendar_id: &str) -> Result<Vec<CalendarRow>> {
        let rows = sqlx::query(SELECT_ROWS_SQL)
            .bind(account_id)
            .bind(calendar_id)
            .fetch_all(self.pool())
            .await
            .map_err(storage_error)?;
        Ok(rows.iter().map(row_from).collect())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::ports::StateStore;

    fn calendar(id: &str) -> CalendarInfo {
        CalendarInfo {
            calendar_id: id.into(),
            name: format!("name {id}"),
            color: "2196f3".into(),
            short_list_id: format!("{id}-short"),
            long_list_id: format!("{id}-long"),
        }
    }

    fn row(
        calendar_id: &str,
        element_id: &str,
        fingerprint: &str,
        modified_ms: i64,
    ) -> CalendarRow {
        CalendarRow {
            calendar_id: calendar_id.into(),
            list_id: format!("{calendar_id}-short"),
            element_id: element_id.into(),
            resource: format!("res-{element_id}"),
            start_ms: 1_000,
            end_ms: 2_000,
            recurring: false,
            series_end_ms: Some(2_000),
            fingerprint: fingerprint.into(),
            modified_ms,
        }
    }

    async fn store() -> (Arc<SqliteStateStore>, i64) {
        let store = Arc::new(SqliteStateStore::open_in_memory().await.unwrap());
        let account = store.upsert_account("user@example.invalid").await.unwrap();
        (store, account)
    }

    #[tokio::test]
    async fn the_state_store_hands_out_its_calendar_cache() {
        let (store, _) = store().await;
        assert!((store as Arc<dyn StateStore>).calendar_store().is_some());
    }

    #[tokio::test]
    async fn calendars_are_replaced_and_drop_their_rows() {
        let (store, account) = store().await;
        store
            .replace_calendars(account, &[calendar("a"), calendar("b")])
            .await
            .unwrap();
        store
            .replace_calendar_rows(account, "b", &[row("b", "e1", "f", 1)])
            .await
            .unwrap();
        let mut renamed = calendar("a");
        renamed.name = "renamed".into();
        store.replace_calendars(account, &[renamed]).await.unwrap();
        let stored = store.calendars(account).await.unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].name, "renamed");
        assert!(store.calendar_rows(account, "b").await.unwrap().is_empty());
        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM calendar_events")
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(total, 0);
    }

    #[tokio::test]
    async fn a_reload_keeps_modified_ms_of_unchanged_rows() {
        let (store, account) = store().await;
        store
            .replace_calendars(account, &[calendar("a")])
            .await
            .unwrap();
        store
            .replace_calendar_rows(
                account,
                "a",
                &[row("a", "e1", "f1", 100), row("a", "e2", "f2", 100)],
            )
            .await
            .unwrap();
        // Reload at a later time: e1 unchanged, e2 changed, e3 new, e2... e1 kept.
        store
            .replace_calendar_rows(
                account,
                "a",
                &[row("a", "e1", "f1", 500), row("a", "e3", "f3", 500)],
            )
            .await
            .unwrap();
        let rows = store.calendar_rows(account, "a").await.unwrap();
        assert_eq!(rows.len(), 2);
        let e1 = rows.iter().find(|r| r.element_id == "e1").unwrap();
        assert_eq!(e1.modified_ms, 100, "unchanged fingerprint keeps its stamp");
        let e3 = rows.iter().find(|r| r.element_id == "e3").unwrap();
        assert_eq!(e3.modified_ms, 500);

        let updated = store
            .upsert_calendar_row(account, &row("a", "e1", "changed", 900))
            .await
            .unwrap();
        assert_eq!(updated.modified_ms, 900);
        let same = store
            .upsert_calendar_row(account, &row("a", "e1", "changed", 1_200))
            .await
            .unwrap();
        assert_eq!(same.modified_ms, 900);

        assert!(store
            .remove_calendar_row(account, "a-short", "e1")
            .await
            .unwrap());
        assert!(!store
            .remove_calendar_row(account, "a-short", "e1")
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn step_8_migrates_a_version_6_database_and_replays_idempotently() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.sqlite3");
        {
            // A database as a version-6 binary left it: no calendar
            // tables, user_version 6.
            let store = SqliteStateStore::open(&path).await.unwrap();
            sqlx::query("DROP TABLE calendar_events")
                .execute(store.pool())
                .await
                .unwrap();
            sqlx::query("DROP TABLE calendars")
                .execute(store.pool())
                .await
                .unwrap();
            sqlx::query("PRAGMA user_version = 6")
                .execute(store.pool())
                .await
                .unwrap();
            store.pool().close().await;
        }
        let store = Arc::new(SqliteStateStore::open(&path).await.unwrap());
        let version: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(version, crate::adapters::sqlite_state::SCHEMA_VERSION);
        assert_eq!(version, 8);
        let account = store.upsert_account("user@example.invalid").await.unwrap();
        store
            .replace_calendars(account, &[calendar("a")])
            .await
            .unwrap();
        store
            .replace_calendar_rows(account, "a", &[row("a", "e1", "f", 1)])
            .await
            .unwrap();
        // An older binary re-stamps version 2; replaying every step
        // keeps the calendar cache.
        sqlx::query("PRAGMA user_version = 2")
            .execute(store.pool())
            .await
            .unwrap();
        store.pool().close().await;
        let store = Arc::new(SqliteStateStore::open(&path).await.unwrap());
        assert_eq!(store.calendar_rows(account, "a").await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn rows_store_no_content() {
        let (store, _) = store().await;
        let columns: Vec<String> =
            sqlx::query_scalar("SELECT name FROM pragma_table_info('calendar_events')")
                .fetch_all(store.pool())
                .await
                .unwrap();
        for forbidden in ["summary", "description", "location", "uid", "attendees"] {
            assert!(!columns.iter().any(|c| c == forbidden));
        }
    }
}
