use std::fs;
use std::path::Path;

use anyhow::Context;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::SqlitePool;

/// Schema statements executed in order on every open.
///
/// `IF NOT EXISTS` keeps reopening an existing database idempotent.
const SCHEMA_STATEMENTS: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS accounts (
        id INTEGER PRIMARY KEY,
        mail_address TEXT NOT NULL UNIQUE
    )",
    "CREATE TABLE IF NOT EXISTS mailboxes (
        id INTEGER PRIMARY KEY,
        account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
        list_id TEXT NOT NULL,              -- entry list of the folder
        name TEXT NOT NULL,
        kind TEXT NOT NULL,                 -- inbox/sent/drafts/trash/junk/archive/custom
        parent_list_id TEXT,
        uidvalidity INTEGER NOT NULL,
        next_uid INTEGER NOT NULL,
        UNIQUE (account_id, list_id)
    )",
    "CREATE TABLE IF NOT EXISTS messages (
        mailbox_id INTEGER NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
        uid INTEGER NOT NULL,
        tuta_list_id TEXT NOT NULL,
        tuta_element_id TEXT NOT NULL,
        received_at_ms INTEGER NOT NULL,
        sent_at_ms INTEGER NOT NULL DEFAULT 0,
        subject TEXT NOT NULL,
        from_name TEXT,
        from_address TEXT NOT NULL,
        recipients_json TEXT,               -- to/cc/bcc/reply_to; NULL until enriched
        unread INTEGER NOT NULL,
        message_id TEXT,
        in_reply_to TEXT,
        references_json TEXT NOT NULL,
        rfc822_size INTEGER,                -- computed at first rendering
        envelope_complete INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (mailbox_id, uid),
        UNIQUE (mailbox_id, tuta_list_id, tuta_element_id)
    )",
    "CREATE TABLE IF NOT EXISTS sync_state (
        account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
        group_id TEXT NOT NULL,
        last_batch_id TEXT NOT NULL,
        initial_sync_done INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (account_id, group_id)
    )",
];

/// SQLite-backed protocol state and header index.
///
/// The store keeps only protocol metadata and message headers. It never
/// stores bodies, attachments, inline images, or complete `.eml` messages.
pub struct SqliteStateStore {
    pool: SqlitePool,
}

impl SqliteStateStore {
    /// Open the database at `path`, creating it and the schema if missing.
    pub async fn open(path: &Path) -> anyhow::Result<Self> {
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await?;
        set_owner_only(path)?;
        let store = Self { pool };
        store.apply_schema().await?;
        Ok(store)
    }

    /// Open a throwaway in-memory database with the same schema.
    pub async fn open_in_memory() -> anyhow::Result<Self> {
        let options = SqliteConnectOptions::new()
            .in_memory(true)
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await?;
        let store = Self { pool };
        store.apply_schema().await?;
        Ok(store)
    }

    /// The underlying connection pool, exposed for tests.
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    async fn apply_schema(&self) -> anyhow::Result<()> {
        for statement in SCHEMA_STATEMENTS {
            sqlx::query(statement).execute(&self.pool).await?;
        }
        sqlx::query("PRAGMA user_version = 1")
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

/// Tighten the database file to owner-only access on Unix.
#[cfg(unix)]
fn set_owner_only(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("failed to tighten permissions on {}", path.display()))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_owner_only(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn creates_schema_and_sets_user_version() {
        let store = SqliteStateStore::open_in_memory().await.unwrap();
        let tables: Vec<String> =
            sqlx::query_scalar("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
                .fetch_all(store.pool())
                .await
                .unwrap();
        for table in ["accounts", "mailboxes", "messages", "sync_state"] {
            assert!(tables.contains(&table.to_string()), "missing {table}");
        }
        let version: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(version, 1);
    }

    #[tokio::test]
    async fn opens_file_database_privately_and_reopens_existing_schema() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.sqlite3");

        {
            let store = SqliteStateStore::open(&path).await.unwrap();
            let journal_mode: String = sqlx::query_scalar("PRAGMA journal_mode")
                .fetch_one(store.pool())
                .await
                .unwrap();
            assert_eq!(journal_mode.to_lowercase(), "wal");
        }

        assert_private_file(&path);

        // Reopening an existing database must keep the schema instead of
        // failing on already-created tables.
        let store = SqliteStateStore::open(&path).await.unwrap();
        let tables: Vec<String> =
            sqlx::query_scalar("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
                .fetch_all(store.pool())
                .await
                .unwrap();
        assert_eq!(tables.len(), 4);
        let version: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(version, 1);
    }

    #[cfg(unix)]
    fn assert_private_file(path: &std::path::Path) {
        use std::os::unix::fs::PermissionsExt;

        let mode = std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "database file must be owner-only");
    }

    #[cfg(not(unix))]
    fn assert_private_file(_path: &std::path::Path) {}
}
