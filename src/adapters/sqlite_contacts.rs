//! The CardDAV contact cache in the SQLite state database (schema
//! step 7).
//!
//! Metadata only: per contact its list and element id, a strong ETag
//! derived from the rendered vCard, the book revision at which it last
//! changed, and a tombstone flag. No name, address or vCard body is
//! stored; bodies are rendered from the SDK on demand.

use rand_core::{OsRng, RngCore};
use sqlx::Row;

use crate::adapters::sqlite_state::{storage_error, SqliteStateStore};
use crate::domain::Result;
use crate::ports::contact_store::{
    ContactBookState, ContactCounts, ContactEntry, ContactStore, StoredContact,
};

/// Schema step 7: the contact book and its rows.
///
/// `IF NOT EXISTS` keeps the step idempotent for the migration ladder's
/// replays. Both tables cascade with their account.
pub(crate) const CONTACT_SCHEMA_STATEMENTS: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS contact_books (
        account_id INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
        epoch TEXT NOT NULL,                -- random; scopes sync tokens
        revision INTEGER NOT NULL DEFAULT 0, -- ctag / sync-token counter
        loaded INTEGER NOT NULL DEFAULT 0,  -- a full load has run
        list_id TEXT                        -- Tuta contact list, when known
    )",
    "CREATE TABLE IF NOT EXISTS contacts (
        account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
        element_id TEXT NOT NULL,
        list_id TEXT NOT NULL,
        etag TEXT NOT NULL,
        revision INTEGER NOT NULL,
        deleted INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (account_id, element_id)
    )",
    "CREATE INDEX IF NOT EXISTS contacts_by_revision ON contacts (account_id, revision)",
];

const INSERT_BOOK_SQL: &str =
    "INSERT INTO contact_books (account_id, epoch) VALUES (?, ?) ON CONFLICT(account_id) DO NOTHING";

const SELECT_BOOK_SQL: &str =
    "SELECT epoch, revision, loaded, list_id FROM contact_books WHERE account_id = ?";

const SELECT_LIVE_ROWS_SQL: &str = "\
SELECT list_id, element_id, etag, revision, deleted FROM contacts
WHERE account_id = ? AND deleted = 0 ORDER BY element_id";

const SELECT_ROW_SQL: &str = "\
SELECT list_id, element_id, etag, revision, deleted FROM contacts
WHERE account_id = ? AND element_id = ?";

const SELECT_CHANGES_SQL: &str = "\
SELECT list_id, element_id, etag, revision, deleted FROM contacts
WHERE account_id = ? AND revision > ? ORDER BY revision";

const UPSERT_ROW_SQL: &str = "\
INSERT INTO contacts (account_id, element_id, list_id, etag, revision, deleted)
VALUES (?, ?, ?, ?, ?, 0)
ON CONFLICT(account_id, element_id) DO UPDATE SET
    list_id = excluded.list_id, etag = excluded.etag,
    revision = excluded.revision, deleted = 0";

const TOMBSTONE_ROW_SQL: &str =
    "UPDATE contacts SET deleted = 1, revision = ? WHERE account_id = ? AND element_id = ?";

const UPDATE_BOOK_SQL: &str = "UPDATE contact_books SET revision = ? WHERE account_id = ?";

const MARK_LOADED_SQL: &str =
    "UPDATE contact_books SET loaded = 1, list_id = COALESCE(?, list_id) WHERE account_id = ?";

/// A fresh random book epoch (16 hex digits).
fn new_epoch() -> String {
    let mut bytes = [0u8; 8];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn stored(row: &sqlx::sqlite::SqliteRow) -> StoredContact {
    StoredContact {
        list_id: row.get(0),
        element_id: row.get(1),
        etag: row.get(2),
        revision: row.get(3),
        deleted: row.get::<i64, _>(4) != 0,
    }
}

/// One write transaction's bookkeeping: the book revision it started
/// from and the counts of what it changed.
struct Writer {
    revision: i64,
    counts: ContactCounts,
}

impl Writer {
    async fn upsert(
        &mut self,
        executor: &mut sqlx::SqliteConnection,
        account_id: i64,
        entry: &ContactEntry,
    ) -> Result<()> {
        let existing = sqlx::query(SELECT_ROW_SQL)
            .bind(account_id)
            .bind(&entry.element_id)
            .fetch_optional(&mut *executor)
            .await
            .map_err(storage_error)?
            .map(|row| stored(&row));
        match &existing {
            Some(row) if !row.deleted && row.etag == entry.etag && row.list_id == entry.list_id => {
                return Ok(());
            }
            Some(row) if !row.deleted => self.counts.updated += 1,
            _ => self.counts.added += 1,
        }
        self.revision += 1;
        sqlx::query(UPSERT_ROW_SQL)
            .bind(account_id)
            .bind(&entry.element_id)
            .bind(&entry.list_id)
            .bind(&entry.etag)
            .bind(self.revision)
            .execute(&mut *executor)
            .await
            .map_err(storage_error)?;
        Ok(())
    }

    async fn remove(
        &mut self,
        executor: &mut sqlx::SqliteConnection,
        account_id: i64,
        element_id: &str,
    ) -> Result<()> {
        let live = sqlx::query(SELECT_ROW_SQL)
            .bind(account_id)
            .bind(element_id)
            .fetch_optional(&mut *executor)
            .await
            .map_err(storage_error)?
            .is_some_and(|row| row.get::<i64, _>(4) == 0);
        if !live {
            return Ok(());
        }
        self.revision += 1;
        self.counts.removed += 1;
        sqlx::query(TOMBSTONE_ROW_SQL)
            .bind(self.revision)
            .bind(account_id)
            .bind(element_id)
            .execute(&mut *executor)
            .await
            .map_err(storage_error)?;
        Ok(())
    }
}

impl SqliteStateStore {
    /// Start a contact write: ensure the book row and read its revision.
    async fn begin_contact_write(
        &self,
        account_id: i64,
    ) -> Result<(sqlx::Transaction<'static, sqlx::Sqlite>, Writer)> {
        let mut transaction = self
            .pool()
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(storage_error)?;
        sqlx::query(INSERT_BOOK_SQL)
            .bind(account_id)
            .bind(new_epoch())
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;
        let revision: i64 =
            sqlx::query_scalar("SELECT revision FROM contact_books WHERE account_id = ?")
                .bind(account_id)
                .fetch_one(&mut *transaction)
                .await
                .map_err(storage_error)?;
        Ok((
            transaction,
            Writer {
                revision,
                counts: ContactCounts::default(),
            },
        ))
    }

    async fn finish_contact_write(
        &self,
        mut transaction: sqlx::Transaction<'static, sqlx::Sqlite>,
        account_id: i64,
        writer: &Writer,
    ) -> Result<()> {
        sqlx::query(UPDATE_BOOK_SQL)
            .bind(writer.revision)
            .bind(account_id)
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;
        transaction.commit().await.map_err(storage_error)
    }
}

#[async_trait::async_trait]
impl ContactStore for SqliteStateStore {
    async fn contact_book(&self, account_id: i64) -> Result<ContactBookState> {
        sqlx::query(INSERT_BOOK_SQL)
            .bind(account_id)
            .bind(new_epoch())
            .execute(self.pool())
            .await
            .map_err(storage_error)?;
        let row = sqlx::query(SELECT_BOOK_SQL)
            .bind(account_id)
            .fetch_one(self.pool())
            .await
            .map_err(storage_error)?;
        Ok(ContactBookState {
            epoch: row.get(0),
            revision: row.get(1),
            loaded: row.get::<i64, _>(2) != 0,
            list_id: row.get(3),
        })
    }

    async fn replace_contacts(
        &self,
        account_id: i64,
        list_id: Option<&str>,
        entries: &[ContactEntry],
    ) -> Result<ContactCounts> {
        let (mut transaction, mut writer) = self.begin_contact_write(account_id).await?;
        for entry in entries {
            writer.upsert(&mut transaction, account_id, entry).await?;
        }
        let current: std::collections::HashSet<&str> = entries
            .iter()
            .map(|entry| entry.element_id.as_str())
            .collect();
        let rows = sqlx::query(SELECT_LIVE_ROWS_SQL)
            .bind(account_id)
            .fetch_all(&mut *transaction)
            .await
            .map_err(storage_error)?;
        let gone: Vec<String> = rows
            .iter()
            .map(stored)
            .filter(|row| !current.contains(row.element_id.as_str()))
            .map(|row| row.element_id)
            .collect();
        for element_id in &gone {
            writer
                .remove(&mut transaction, account_id, element_id)
                .await?;
        }
        sqlx::query(MARK_LOADED_SQL)
            .bind(list_id)
            .bind(account_id)
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;
        self.finish_contact_write(transaction, account_id, &writer)
            .await?;
        Ok(writer.counts)
    }

    async fn update_contacts(
        &self,
        account_id: i64,
        upserts: &[ContactEntry],
        removals: &[String],
    ) -> Result<ContactCounts> {
        let (mut transaction, mut writer) = self.begin_contact_write(account_id).await?;
        for entry in upserts {
            writer.upsert(&mut transaction, account_id, entry).await?;
        }
        for element_id in removals {
            writer
                .remove(&mut transaction, account_id, element_id)
                .await?;
        }
        self.finish_contact_write(transaction, account_id, &writer)
            .await?;
        Ok(writer.counts)
    }

    async fn contacts(&self, account_id: i64) -> Result<Vec<StoredContact>> {
        let rows = sqlx::query(SELECT_LIVE_ROWS_SQL)
            .bind(account_id)
            .fetch_all(self.pool())
            .await
            .map_err(storage_error)?;
        Ok(rows.iter().map(stored).collect())
    }

    async fn contact(&self, account_id: i64, element_id: &str) -> Result<Option<StoredContact>> {
        let row = sqlx::query(SELECT_ROW_SQL)
            .bind(account_id)
            .bind(element_id)
            .fetch_optional(self.pool())
            .await
            .map_err(storage_error)?;
        Ok(row.map(|row| stored(&row)).filter(|row| !row.deleted))
    }

    async fn contact_changes_since(
        &self,
        account_id: i64,
        revision: i64,
    ) -> Result<(i64, Vec<StoredContact>)> {
        let mut transaction = self.pool().begin().await.map_err(storage_error)?;
        let current: Option<i64> =
            sqlx::query_scalar("SELECT revision FROM contact_books WHERE account_id = ?")
                .bind(account_id)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(storage_error)?;
        let rows = sqlx::query(SELECT_CHANGES_SQL)
            .bind(account_id)
            .bind(revision)
            .fetch_all(&mut *transaction)
            .await
            .map_err(storage_error)?;
        transaction.commit().await.map_err(storage_error)?;
        Ok((current.unwrap_or(0), rows.iter().map(stored).collect()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::sqlite_state::SCHEMA_VERSION;
    use crate::ports::StateStore;

    fn entry(element_id: &str, etag: &str) -> ContactEntry {
        ContactEntry {
            list_id: "list".into(),
            element_id: element_id.into(),
            etag: etag.into(),
        }
    }

    async fn store() -> (SqliteStateStore, i64) {
        let store = SqliteStateStore::open_in_memory().await.unwrap();
        let account = store.upsert_account("user@example.invalid").await.unwrap();
        (store, account)
    }

    #[tokio::test]
    async fn a_new_book_is_empty_and_not_loaded() {
        let (store, account) = store().await;
        let book = store.contact_book(account).await.unwrap();
        assert_eq!(book.revision, 0);
        assert!(!book.loaded);
        assert_eq!(book.list_id, None);
        assert_eq!(book.epoch.len(), 16);
        // The epoch is fixed once created.
        assert_eq!(store.contact_book(account).await.unwrap().epoch, book.epoch);
        assert!(store.contacts(account).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_full_reload_keeps_unchanged_rows_and_tombstones_the_missing() {
        let (store, account) = store().await;
        let counts = store
            .replace_contacts(
                account,
                Some("list"),
                &[entry("a", "\"1\""), entry("b", "\"2\"")],
            )
            .await
            .unwrap();
        assert_eq!((counts.added, counts.updated, counts.removed), (2, 0, 0));
        let book = store.contact_book(account).await.unwrap();
        assert!(book.loaded);
        assert_eq!(book.revision, 2);
        assert_eq!(book.list_id.as_deref(), Some("list"));

        // The same listing again changes nothing: no revision, no ETag.
        let counts = store
            .replace_contacts(
                account,
                Some("list"),
                &[entry("a", "\"1\""), entry("b", "\"2\"")],
            )
            .await
            .unwrap();
        assert!(counts.is_empty());
        assert_eq!(store.contact_book(account).await.unwrap().revision, 2);

        // `a` changed, `b` vanished, `c` is new.
        let counts = store
            .replace_contacts(
                account,
                Some("list"),
                &[entry("a", "\"1b\""), entry("c", "\"3\"")],
            )
            .await
            .unwrap();
        assert_eq!((counts.added, counts.updated, counts.removed), (1, 1, 1));
        let live = store.contacts(account).await.unwrap();
        let ids: Vec<&str> = live.iter().map(|row| row.element_id.as_str()).collect();
        assert_eq!(ids, ["a", "c"]);
        assert_eq!(live[0].etag, "\"1b\"");
        assert!(store.contact(account, "b").await.unwrap().is_none());

        let (revision, changes) = store.contact_changes_since(account, 2).await.unwrap();
        assert_eq!(revision, 5);
        assert_eq!(changes.len(), 3);
        assert!(changes
            .iter()
            .any(|row| row.element_id == "b" && row.deleted));
    }

    #[tokio::test]
    async fn updates_upsert_then_remove_and_revive_tombstones() {
        let (store, account) = store().await;
        store
            .update_contacts(account, &[entry("a", "\"1\"")], &[])
            .await
            .unwrap();
        let counts = store
            .update_contacts(account, &[], &["a".to_string(), "missing".to_string()])
            .await
            .unwrap();
        assert_eq!(counts.removed, 1);
        assert!(store.contacts(account).await.unwrap().is_empty());
        // Removing a tombstone again changes nothing.
        let counts = store
            .update_contacts(account, &[], &["a".to_string()])
            .await
            .unwrap();
        assert!(counts.is_empty());
        let counts = store
            .update_contacts(account, &[entry("a", "\"2\"")], &[])
            .await
            .unwrap();
        assert_eq!(counts.added, 1);
        assert_eq!(
            store.contact(account, "a").await.unwrap().unwrap().etag,
            "\"2\""
        );
        // Events never mark the book loaded.
        assert!(!store.contact_book(account).await.unwrap().loaded);
    }

    #[tokio::test]
    async fn the_cache_goes_with_its_account() {
        let (store, account) = store().await;
        store
            .replace_contacts(account, None, &[entry("a", "\"1\"")])
            .await
            .unwrap();
        sqlx::query("DELETE FROM accounts WHERE id = ?")
            .bind(account)
            .execute(store.pool())
            .await
            .unwrap();
        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM contacts")
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(rows, 0);
    }

    #[tokio::test]
    async fn a_version_six_database_gains_the_contact_tables() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.sqlite");
        {
            let store = SqliteStateStore::open(&path).await.unwrap();
            // Roll the database back to the version before this step.
            for statement in [
                "DROP TABLE contacts",
                "DROP TABLE contact_books",
                "PRAGMA user_version = 6",
            ] {
                sqlx::query(statement).execute(store.pool()).await.unwrap();
            }
        }
        let store = SqliteStateStore::open(&path).await.unwrap();
        let version: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        let account = store.upsert_account("user@example.invalid").await.unwrap();
        store
            .update_contacts(account, &[entry("a", "\"1\"")], &[])
            .await
            .unwrap();
        assert_eq!(store.contacts(account).await.unwrap().len(), 1);

        // Replaying the step over a schema that has it is harmless.
        drop(store);
        {
            let store = SqliteStateStore::open(&path).await.unwrap();
            sqlx::query("PRAGMA user_version = 6")
                .execute(store.pool())
                .await
                .unwrap();
        }
        let store = SqliteStateStore::open(&path).await.unwrap();
        assert_eq!(store.contacts(account).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn the_state_store_exposes_its_contact_cache() {
        let (store, _) = store().await;
        assert!(store.contact_store().is_some());
    }
}
