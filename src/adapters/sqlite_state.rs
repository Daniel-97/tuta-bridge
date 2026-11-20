use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context;
use serde::{Deserialize, Serialize};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteRow};
use sqlx::{Connection, Row, Sqlite, SqliteConnection, SqlitePool};

use crate::domain::{
    Address, BatchOutcome, Error, Folder, FolderKind, MailboxId, MessageHeader, Result,
    StateChange, StoredMailbox, StoredMessage,
};
use crate::ports::StateStore;

/// Schema version this binary reads and writes, stored in SQLite's
/// `user_version`.
///
/// Opening migrates an older database forward inside one transaction and
/// refuses a newer one: a binary that does not know a later schema must
/// not write to it.
pub const SCHEMA_VERSION: i64 = 6;

/// The database carries a schema version newer than [`SCHEMA_VERSION`].
#[derive(Debug, thiserror::Error)]
#[error(
    "state database has schema version {found}, but this tuta-bridge only supports \
     versions up to {supported}; upgrade tuta-bridge"
)]
pub struct SchemaTooNew {
    pub found: i64,
    pub supported: i64,
}

/// Fail when `version` was written by a newer binary.
fn check_schema_version(version: i64) -> std::result::Result<(), SchemaTooNew> {
    if version > SCHEMA_VERSION {
        return Err(SchemaTooNew {
            found: version,
            supported: SCHEMA_VERSION,
        });
    }
    Ok(())
}

/// Version 1 schema statements.
///
/// `IF NOT EXISTS` lets the same statements create a fresh database and
/// adopt one that predates version stamping.
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
        mime_structure TEXT,                -- precomputed BODYSTRUCTURE; NULL until enriched
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
    /// Held for the store's lifetime when it was opened exclusively.
    _lock: Option<StateLock>,
}

/// Another process holds the state database's writer lock.
#[derive(Debug, thiserror::Error)]
#[error(
    "the state database is in use by another tuta-bridge process \
     (sync, resync, watch or serve); stop it first"
)]
pub struct StateInUse;

/// Exclusive advisory lock on the state database, released on drop.
///
/// `sync` compares a folder snapshot taken over many requests with the
/// stored rows, and `watch` rewrites those rows from live events; run
/// side by side, a sync deletes mail the watcher just filed and files
/// mail it just removed. The commands that write the index therefore
/// exclude each other through this lock on a `.lock` file beside the
/// database. The kernel drops it when the process ends, however it
/// ends, so a crash never leaves a stale lock behind.
pub struct StateLock {
    _file: fs::File,
}

impl StateLock {
    /// Take the lock without waiting; [`StateInUse`] when it is held.
    #[cfg(unix)]
    fn acquire(path: &Path) -> anyhow::Result<Self> {
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::io::AsRawFd;

        let file = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("failed to open {}", path.display()))?;
        // SAFETY: `flock` only takes the descriptor of the file opened
        // above, which stays open for the duration of the call.
        let locked = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if locked != 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::WouldBlock {
                return Err(StateInUse.into());
            }
            return Err(error).with_context(|| format!("failed to lock {}", path.display()));
        }
        Ok(Self { _file: file })
    }

    /// Platforms without `flock` run unlocked.
    #[cfg(not(unix))]
    fn acquire(path: &Path) -> anyhow::Result<Self> {
        let file = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(path)
            .with_context(|| format!("failed to open {}", path.display()))?;
        Ok(Self { _file: file })
    }
}

impl SqliteStateStore {
    /// Open the database at `path` as its only writer.
    ///
    /// Like [`Self::open`], but first takes the [`StateLock`] next to the
    /// database and keeps it until the store is dropped. A second
    /// exclusive open — from this or any other process — fails with
    /// [`StateInUse`] instead of waiting.
    pub async fn open_exclusive(path: &Path) -> anyhow::Result<Self> {
        restrict_process_umask();
        let mut lock_path = path.as_os_str().to_owned();
        lock_path.push(".lock");
        let lock = StateLock::acquire(Path::new(&lock_path))?;
        let mut store = Self::open(path).await?;
        store._lock = Some(lock);
        Ok(store)
    }

    /// Open the database at `path`, creating it and the schema if missing.
    ///
    /// On Unix this sets the process umask to `0o077` before SQLite creates
    /// any file. The umask is process-global and is intentionally left in
    /// place: if SQLite ever recreates a WAL sidecar, it must not become
    /// group- or world-readable.
    pub async fn open(path: &Path) -> anyhow::Result<Self> {
        restrict_process_umask();
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .foreign_keys(true)
            .busy_timeout(Duration::from_secs(5));
        let pool = pool_options().connect_with(options).await?;
        tighten_state_files(path)?;
        let store = Self { pool, _lock: None };
        store.apply_schema().await?;
        // SQLite creates the WAL/SHM sidecars itself; tighten them once the
        // schema has forced them into existence.
        tighten_state_files(path)?;
        Ok(store)
    }

    /// Open a throwaway in-memory database with the same schema.
    ///
    /// This applies the same private umask as [`Self::open`] for consistent
    /// process-wide protection. It creates no sidecar files itself.
    pub async fn open_in_memory() -> anyhow::Result<Self> {
        restrict_process_umask();
        let options = SqliteConnectOptions::new()
            .in_memory(true)
            .foreign_keys(true)
            .busy_timeout(Duration::from_secs(5));
        let pool = pool_options().connect_with(options).await?;
        let store = Self { pool, _lock: None };
        store.apply_schema().await?;
        Ok(store)
    }

    /// The underlying connection pool, exposed for tests.
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Bring the schema to [`SCHEMA_VERSION`].
    ///
    /// A database already at the current version is only read. An older
    /// one is migrated forward; a newer one is refused with
    /// [`SchemaTooNew`] and left untouched.
    async fn apply_schema(&self) -> anyhow::Result<()> {
        let version: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(&self.pool)
            .await?;
        check_schema_version(version)?;
        if version == SCHEMA_VERSION {
            return Ok(());
        }
        let mut connection = self.pool.acquire().await?;
        // Rebuilding a table that other tables reference needs foreign
        // keys off, and the pragma is ignored inside a transaction, so it
        // brackets the migration. `migrate` checks the references itself
        // before it commits.
        sqlx::query("PRAGMA foreign_keys = OFF")
            .execute(&mut *connection)
            .await?;
        let migrated = migrate(&mut connection).await;
        sqlx::query("PRAGMA foreign_keys = ON")
            .execute(&mut *connection)
            .await?;
        migrated
    }

    /// Start a write transaction that holds the write lock from its first
    /// statement.
    ///
    /// Every transaction here reads before it writes. A deferred `BEGIN`
    /// would take a read snapshot first and fail the later write at once —
    /// without honouring the busy timeout — whenever another connection
    /// committed in between. `BEGIN IMMEDIATE` waits for the lock up
    /// front instead, so the read and the write see the same state.
    async fn begin_write(&self) -> Result<sqlx::Transaction<'static, Sqlite>> {
        self.pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(storage_error)
    }

    /// Create or refresh a mailbox on `executor` and return its id.
    ///
    /// A new mailbox, and one whose name changed, gets a UIDVALIDITY no
    /// mailbox of the account has ever carried: IMAP clients key their
    /// caches by mailbox name and UIDVALIDITY, so a folder re-created
    /// under an old name, or renamed onto one, must never present the
    /// pair an earlier folder used. An unchanged mailbox keeps its value
    /// and its UID sequence. A mailbox stored with an empty name was
    /// never addressable by name, so naming it is not a rename.
    async fn upsert_mailbox_in(
        &self,
        executor: &mut SqliteConnection,
        account_id: i64,
        folder: &Folder,
        uidvalidity: u32,
    ) -> Result<MailboxId> {
        let existing: Option<(i64, String)> = sqlx::query_as(SELECT_MAILBOX_NAME_SQL)
            .bind(account_id)
            .bind(&folder.list_id)
            .fetch_optional(&mut *executor)
            .await
            .map_err(storage_error)?;

        match existing {
            Some((id, name)) if name == folder.name || name.is_empty() => {
                sqlx::query(UPDATE_MAILBOX_SQL)
                    .bind(&folder.name)
                    .bind(folder.kind.as_db_str())
                    .bind(id)
                    .execute(&mut *executor)
                    .await
                    .map_err(storage_error)?;
                Ok(MailboxId(id))
            }
            Some((id, _)) => {
                let uidvalidity = self
                    .allocate_uidvalidity_in(&mut *executor, account_id, uidvalidity)
                    .await?;
                sqlx::query(RENAME_MAILBOX_SQL)
                    .bind(&folder.name)
                    .bind(folder.kind.as_db_str())
                    .bind(i64::from(uidvalidity))
                    .bind(id)
                    .execute(&mut *executor)
                    .await
                    .map_err(storage_error)?;
                Ok(MailboxId(id))
            }
            None => {
                let uidvalidity = self
                    .allocate_uidvalidity_in(&mut *executor, account_id, uidvalidity)
                    .await?;
                let result = sqlx::query(INSERT_MAILBOX_SQL)
                    .bind(account_id)
                    .bind(&folder.list_id)
                    .bind(&folder.name)
                    .bind(folder.kind.as_db_str())
                    .bind(i64::from(uidvalidity))
                    .execute(&mut *executor)
                    .await
                    .map_err(storage_error)?;
                Ok(MailboxId(result.last_insert_rowid()))
            }
        }
    }

    /// Reserve a UIDVALIDITY the account has never used.
    ///
    /// `at_least` is the caller's wall-clock suggestion. The result is
    /// that value or the account's high-water mark plus one, whichever is
    /// greater, and becomes the new mark; the mark lives on the account
    /// row, so it survives deleted mailboxes and a full reset. The result
    /// is never 0, which IMAP does not allow.
    async fn allocate_uidvalidity_in(
        &self,
        executor: &mut SqliteConnection,
        account_id: i64,
        at_least: u32,
    ) -> Result<u32> {
        let floor: Option<i64> = sqlx::query_scalar(SELECT_UIDVALIDITY_FLOOR_SQL)
            .bind(account_id)
            .fetch_optional(&mut *executor)
            .await
            .map_err(storage_error)?;
        let floor =
            floor.ok_or_else(|| Error::Storage("account not found in state database".into()))?;
        let next = floor
            .checked_add(1)
            .map(|next| next.max(i64::from(at_least)))
            .and_then(|next| u32::try_from(next).ok())
            .ok_or_else(|| Error::Storage("UIDVALIDITY exhausted".into()))?;
        sqlx::query(UPDATE_UIDVALIDITY_FLOOR_SQL)
            .bind(i64::from(next))
            .bind(account_id)
            .execute(&mut *executor)
            .await
            .map_err(storage_error)?;
        Ok(next)
    }

    /// Assign a stable UID or refresh an existing header on `executor`.
    ///
    /// Callers own the transaction and its commit, which lets
    /// `apply_batch` reuse the same code path without nesting transactions.
    async fn assign_uid_in(
        &self,
        executor: &mut SqliteConnection,
        mailbox: MailboxId,
        header: &MessageHeader,
    ) -> Result<u32> {
        let existing: Option<i64> = sqlx::query_scalar(SELECT_UID_BY_ELEMENT_SQL)
            .bind(mailbox.0)
            .bind(&header.list_id)
            .bind(&header.element_id)
            .fetch_optional(&mut *executor)
            .await
            .map_err(storage_error)?;

        match existing {
            Some(uid) => {
                let uid = u32_from_i64(uid)?;
                if header.envelope_complete {
                    write_message_metadata(&mut *executor, mailbox, uid, header, None).await?;
                } else {
                    write_partial_metadata(&mut *executor, mailbox, uid, header).await?;
                }
                Ok(uid)
            }
            None => {
                let next_uid: Option<i64> = sqlx::query_scalar(SELECT_NEXT_UID_SQL)
                    .bind(mailbox.0)
                    .fetch_optional(&mut *executor)
                    .await
                    .map_err(storage_error)?;
                let next_uid = next_uid
                    .ok_or_else(|| Error::Storage("mailbox not found in state database".into()))?;
                let uid = u32_from_i64(next_uid)?;

                let (recipients_json, references_json) = serialize_header(header)?;
                sqlx::query(INSERT_MESSAGE_SQL)
                    .bind(mailbox.0)
                    .bind(i64::from(uid))
                    .bind(&header.list_id)
                    .bind(&header.element_id)
                    .bind(header.received_at_ms)
                    .bind(header.sent_at_ms)
                    .bind(&header.subject)
                    .bind(header.from.name.as_deref())
                    .bind(&header.from.address)
                    .bind(recipients_json)
                    .bind(bool_to_int(header.unread))
                    .bind(header.message_id.as_deref())
                    .bind(header.in_reply_to.as_deref())
                    .bind(references_json)
                    .bind(bool_to_int(header.envelope_complete))
                    .execute(&mut *executor)
                    .await
                    .map_err(storage_error)?;

                sqlx::query(INCREMENT_NEXT_UID_SQL)
                    .bind(mailbox.0)
                    .execute(&mut *executor)
                    .await
                    .map_err(storage_error)?;

                Ok(uid)
            }
        }
    }

    /// Delete the placements of `element_id` outside `keep_list_ids` on
    /// `executor` and return the mailboxes that lost a row.
    ///
    /// An empty `keep_list_ids` removes every placement of the element
    /// in the account, exactly like [`StateChange::RemoveHeaderEverywhere`].
    /// The mailboxes are listed before the delete so the outcome can
    /// attribute the removed rows; both statements run in the caller's
    /// transaction, so the list cannot drift from what is deleted.
    async fn remove_placements_in(
        &self,
        executor: &mut SqliteConnection,
        account_id: i64,
        element_id: &str,
        keep_list_ids: &[String],
    ) -> Result<Vec<MailboxId>> {
        if keep_list_ids.is_empty() {
            let mailbox_ids: Vec<i64> = sqlx::query_scalar(SELECT_ELEMENT_MAILBOXES_SQL)
                .bind(element_id)
                .bind(account_id)
                .fetch_all(&mut *executor)
                .await
                .map_err(storage_error)?;
            let result = sqlx::query(DELETE_ELEMENT_HEADERS_SQL)
                .bind(element_id)
                .bind(account_id)
                .execute(&mut *executor)
                .await
                .map_err(storage_error)?;
            return Ok(mailboxes_touched_by_removal(
                mailbox_ids,
                result.rows_affected(),
            ));
        }

        let placeholders = vec!["?"; keep_list_ids.len()].join(", ");
        let filter_sql = format!(
            "tuta_element_id = ? AND mailbox_id IN ( \
                SELECT id FROM mailboxes \
                WHERE account_id = ? AND list_id NOT IN ({placeholders}) \
            )"
        );
        let select_sql = format!(
            "SELECT DISTINCT mailbox_id FROM messages WHERE {filter_sql} ORDER BY mailbox_id"
        );
        let mut select = sqlx::query_scalar::<_, i64>(&select_sql)
            .bind(element_id)
            .bind(account_id);
        for list_id in keep_list_ids {
            select = select.bind(list_id);
        }
        let mailbox_ids: Vec<i64> = select
            .fetch_all(&mut *executor)
            .await
            .map_err(storage_error)?;

        let delete_sql = format!("DELETE FROM messages WHERE {filter_sql}");
        let mut delete = sqlx::query(&delete_sql).bind(element_id).bind(account_id);
        for list_id in keep_list_ids {
            delete = delete.bind(list_id);
        }
        let result = delete
            .execute(&mut *executor)
            .await
            .map_err(storage_error)?;

        Ok(mailboxes_touched_by_removal(
            mailbox_ids,
            result.rows_affected(),
        ))
    }
}

/// Migrate the schema forward to [`SCHEMA_VERSION`] in one transaction.
///
/// `BEGIN IMMEDIATE` takes the write lock first and the version is read
/// again under it, so two processes opening the same old database
/// migrate it once. Every step and the new version commit together: a
/// failed or interrupted migration leaves the database at its old
/// version.
///
/// Every step is idempotent. Binaries from before the version gate
/// stamp `user_version = 2` on every open without reading it, so a
/// database this binary migrated is re-stamped to 2 by one run of an
/// older build, and the next open here replays steps 3 to 6 over a
/// schema that already has them.
async fn migrate(connection: &mut SqliteConnection) -> anyhow::Result<()> {
    let mut transaction = connection.begin_with("BEGIN IMMEDIATE").await?;
    let version: i64 = sqlx::query_scalar("PRAGMA user_version")
        .fetch_one(&mut *transaction)
        .await?;
    check_schema_version(version)?;

    if version < 1 {
        for statement in SCHEMA_STATEMENTS {
            sqlx::query(statement).execute(&mut *transaction).await?;
        }
    }
    if version < 2 {
        add_mime_structure_column(&mut transaction).await?;
    }
    if version < 3 {
        rebuild_mailboxes_with_autoincrement(&mut transaction).await?;
    }
    if version < 4 {
        add_uidvalidity_floor_column(&mut transaction).await?;
    }
    if version < 5 {
        sqlx::query(MESSAGES_BY_ELEMENT_INDEX_SQL)
            .execute(&mut *transaction)
            .await?;
    }
    if version < 6 {
        sqlx::query(RESET_ENRICHMENT_SQL)
            .execute(&mut *transaction)
            .await?;
    }

    // The caller switched foreign keys off for the table rebuild; nothing
    // may commit with a dangling reference.
    let violations = sqlx::query("PRAGMA foreign_key_check")
        .fetch_all(&mut *transaction)
        .await?;
    anyhow::ensure!(
        violations.is_empty(),
        "state database migration left dangling references"
    );

    // PRAGMA arguments cannot be bound; the value is a constant.
    sqlx::query(&format!("PRAGMA user_version = {SCHEMA_VERSION}"))
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;
    Ok(())
}

/// v3 migration: rebuild `mailboxes` with an `AUTOINCREMENT` id.
///
/// A plain `INTEGER PRIMARY KEY` hands the id of a deleted mailbox to the
/// next one created, so anything still holding the old id — an IMAP
/// session, a queued change notification — would silently address a
/// different folder. `AUTOINCREMENT` cannot be added in place, so the
/// table is copied with every id, `uidvalidity`, and `next_uid` intact;
/// `messages` keeps referencing the table by name.
const MAILBOX_AUTOINCREMENT_STATEMENTS: &[&str] = &[
    "CREATE TABLE mailboxes_rebuilt (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
        list_id TEXT NOT NULL,              -- entry list of the folder
        name TEXT NOT NULL,
        kind TEXT NOT NULL,                 -- inbox/sent/drafts/trash/junk/archive/custom
        parent_list_id TEXT,
        uidvalidity INTEGER NOT NULL,
        next_uid INTEGER NOT NULL,
        UNIQUE (account_id, list_id)
    )",
    "INSERT INTO mailboxes_rebuilt
        (id, account_id, list_id, name, kind, parent_list_id, uidvalidity, next_uid)
     SELECT id, account_id, list_id, name, kind, parent_list_id, uidvalidity, next_uid
     FROM mailboxes",
    "DROP TABLE mailboxes",
    "ALTER TABLE mailboxes_rebuilt RENAME TO mailboxes",
];

/// Run the v3 rebuild unless `mailboxes` already uses `AUTOINCREMENT`.
///
/// Rebuilding an `AUTOINCREMENT` table again would not be harmless: the
/// dropped table takes its `sqlite_sequence` row with it, and the copy
/// restarts the sequence at the highest id still present — handing out
/// again the ids of mailboxes deleted since.
async fn rebuild_mailboxes_with_autoincrement(
    connection: &mut SqliteConnection,
) -> anyhow::Result<()> {
    let definition: String = sqlx::query_scalar(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'mailboxes'",
    )
    .fetch_one(&mut *connection)
    .await?;
    if definition.to_ascii_uppercase().contains("AUTOINCREMENT") {
        return Ok(());
    }
    for statement in MAILBOX_AUTOINCREMENT_STATEMENTS {
        sqlx::query(statement).execute(&mut *connection).await?;
    }
    Ok(())
}

/// v6 migration: forget every stored enrichment.
///
/// Earlier binaries decoded mail details without their To/Cc/Bcc
/// recipients, so enriched rows hold an incomplete envelope and a size
/// and BODYSTRUCTURE measured on a message rendered without them — and
/// being marked complete, they would never be loaded again. Clearing the
/// completeness mark together with the two derived columns is exactly
/// what the enricher and the IMAP backend test before loading content,
/// so each message is enriched again on its next body-class fetch. UIDs,
/// flags, and every header field stay as they are; a size a client
/// already cached can therefore change once.
const RESET_ENRICHMENT_SQL: &str =
    "UPDATE messages SET envelope_complete = 0, rfc822_size = NULL, mime_structure = NULL";

/// v5 migration: index messages by Tuta element id.
///
/// Every mail event removes placements by element id across the
/// account's mailboxes. The table's own indexes lead with the mailbox
/// and the list id, so without this one each removal scanned every
/// stored message of the account.
const MESSAGES_BY_ELEMENT_INDEX_SQL: &str =
    "CREATE INDEX IF NOT EXISTS messages_by_element ON messages (tuta_element_id, mailbox_id)";

/// v4 migration: a per-account UIDVALIDITY high-water mark.
///
/// The mark starts at the highest value any stored mailbox carries, so
/// existing mailboxes keep their UIDVALIDITY and every mailbox created or
/// renamed from now on gets a greater one. The column is added only when
/// missing, and an existing mark is never lowered: a replay after an
/// older binary deleted the mailbox that carried the highest value must
/// not hand that value out again.
async fn add_uidvalidity_floor_column(connection: &mut SqliteConnection) -> anyhow::Result<()> {
    let columns: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pragma_table_info('accounts') WHERE name = 'uidvalidity_floor'",
    )
    .fetch_one(&mut *connection)
    .await?;
    if columns == 0 {
        sqlx::query("ALTER TABLE accounts ADD COLUMN uidvalidity_floor INTEGER NOT NULL DEFAULT 0")
            .execute(&mut *connection)
            .await?;
    }
    sqlx::query(
        "UPDATE accounts SET uidvalidity_floor = MAX(uidvalidity_floor, COALESCE(
            (SELECT MAX(uidvalidity) FROM mailboxes WHERE account_id = accounts.id), 0))",
    )
    .execute(&mut *connection)
    .await?;
    Ok(())
}

/// v2 migration: add the metadata-only `mime_structure` column.
///
/// A database created at version 1 gains the column here; its rows keep
/// `NULL`, which reads back as "not enriched yet". The check keeps the
/// step idempotent: a table created by the version 1 statements of this
/// binary already carries the column.
async fn add_mime_structure_column(connection: &mut SqliteConnection) -> anyhow::Result<()> {
    let columns: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pragma_table_info('messages') WHERE name = 'mime_structure'",
    )
    .fetch_one(&mut *connection)
    .await?;
    if columns == 0 {
        sqlx::query("ALTER TABLE messages ADD COLUMN mime_structure TEXT")
            .execute(&mut *connection)
            .await?;
    }
    Ok(())
}

const UPSERT_ACCOUNT_SQL: &str = "\
INSERT INTO accounts (mail_address) VALUES (?)
ON CONFLICT(mail_address) DO NOTHING";

const SELECT_ACCOUNT_ID_SQL: &str = "SELECT id FROM accounts WHERE mail_address = ?";

const INSERT_MAILBOX_SQL: &str = "\
INSERT INTO mailboxes (account_id, list_id, name, kind, uidvalidity, next_uid)
VALUES (?, ?, ?, ?, ?, 1)";

const SELECT_MAILBOX_NAME_SQL: &str =
    "SELECT id, name FROM mailboxes WHERE account_id = ? AND list_id = ?";

const UPDATE_MAILBOX_SQL: &str = "UPDATE mailboxes SET name = ?, kind = ? WHERE id = ?";

const RENAME_MAILBOX_SQL: &str =
    "UPDATE mailboxes SET name = ?, kind = ?, uidvalidity = ? WHERE id = ?";

const SELECT_UIDVALIDITY_FLOOR_SQL: &str = "SELECT uidvalidity_floor FROM accounts WHERE id = ?";

const UPDATE_UIDVALIDITY_FLOOR_SQL: &str = "UPDATE accounts SET uidvalidity_floor = ? WHERE id = ?";

const SELECT_MAILBOX_ID_SQL: &str = "SELECT id FROM mailboxes WHERE account_id = ? AND list_id = ?";

const LIST_MAILBOXES_SQL: &str = "\
SELECT id, account_id, list_id, name, kind, uidvalidity, next_uid
FROM mailboxes WHERE account_id = ? ORDER BY id";

const SELECT_UID_BY_ELEMENT_SQL: &str = "\
SELECT uid FROM messages
WHERE mailbox_id = ? AND tuta_list_id = ? AND tuta_element_id = ?";

const SELECT_NEXT_UID_SQL: &str = "SELECT next_uid FROM mailboxes WHERE id = ?";

const INSERT_MESSAGE_SQL: &str = "\
INSERT INTO messages (
    mailbox_id, uid, tuta_list_id, tuta_element_id, received_at_ms, sent_at_ms,
    subject, from_name, from_address, recipients_json, unread, message_id,
    in_reply_to, references_json, rfc822_size, envelope_complete
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)";

const UPDATE_MESSAGE_SQL: &str = "\
UPDATE messages SET
    received_at_ms = ?, sent_at_ms = ?, subject = ?, from_name = ?, from_address = ?,
    recipients_json = ?, unread = ?, message_id = ?, in_reply_to = ?, references_json = ?,
    envelope_complete = ?, rfc822_size = COALESCE(?, rfc822_size)
WHERE mailbox_id = ? AND uid = ?";

/// Refresh only the fields present on a list-level (partial) header.
///
/// Envelope fields enriched from decrypted details are left untouched so a
/// later sync cannot regress them, and `rfc822_size` is preserved.
const UPDATE_PARTIAL_MESSAGE_SQL: &str = "\
UPDATE messages SET
    received_at_ms = ?, subject = ?, from_name = ?, from_address = ?, unread = ?
WHERE mailbox_id = ? AND uid = ?";

const INCREMENT_NEXT_UID_SQL: &str = "UPDATE mailboxes SET next_uid = next_uid + 1 WHERE id = ?";

const LIST_MESSAGES_SQL: &str = "\
SELECT uid, tuta_list_id, tuta_element_id, received_at_ms, sent_at_ms, subject,
       from_name, from_address, recipients_json, unread, message_id, in_reply_to,
       references_json, rfc822_size, envelope_complete, mime_structure
FROM messages WHERE mailbox_id = ? ORDER BY uid";

const SELECT_MESSAGE_BY_UID_SQL: &str = "\
SELECT uid, tuta_list_id, tuta_element_id, received_at_ms, sent_at_ms, subject,
       from_name, from_address, recipients_json, unread, message_id, in_reply_to,
       references_json, rfc822_size, envelope_complete, mime_structure
FROM messages WHERE mailbox_id = ? AND uid = ?";

const SET_MIME_STRUCTURE_SQL: &str = "\
UPDATE messages SET mime_structure = ? WHERE mailbox_id = ? AND uid = ?";

/// Two integer columns walked in primary-key order: no header text is
/// read and no JSON is decoded.
const LIST_MESSAGE_UIDS_SQL: &str =
    "SELECT uid, unread FROM messages WHERE mailbox_id = ? ORDER BY uid";

const LIST_MESSAGE_KEYS_SQL: &str =
    "SELECT uid, tuta_list_id, tuta_element_id FROM messages WHERE mailbox_id = ?";

const DELETE_MESSAGE_SQL: &str = "DELETE FROM messages WHERE mailbox_id = ? AND uid = ?";

const SELECT_LAST_BATCH_SQL: &str =
    "SELECT last_batch_id FROM sync_state WHERE account_id = ? AND group_id = ?";

const UPSERT_LAST_BATCH_SQL: &str = "\
INSERT INTO sync_state (account_id, group_id, last_batch_id) VALUES (?, ?, ?)
ON CONFLICT(account_id, group_id) DO UPDATE SET last_batch_id = excluded.last_batch_id";

const DELETE_ACCOUNT_MESSAGES_SQL: &str = "\
DELETE FROM messages WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE account_id = ?)";

const DELETE_ACCOUNT_MAILBOXES_SQL: &str = "DELETE FROM mailboxes WHERE account_id = ?";

const DELETE_ACCOUNT_SYNC_STATE_SQL: &str = "DELETE FROM sync_state WHERE account_id = ?";

const DELETE_ELEMENT_HEADERS_SQL: &str = "\
DELETE FROM messages
WHERE tuta_element_id = ?
  AND mailbox_id IN (SELECT id FROM mailboxes WHERE account_id = ?)";

const SELECT_ELEMENT_MAILBOXES_SQL: &str = "\
SELECT DISTINCT mailbox_id FROM messages
WHERE tuta_element_id = ?
  AND mailbox_id IN (SELECT id FROM mailboxes WHERE account_id = ?)
ORDER BY mailbox_id";

const DELETE_MAILBOX_MESSAGES_SQL: &str = "\
DELETE FROM messages
WHERE mailbox_id = ?
  AND mailbox_id IN (SELECT id FROM mailboxes WHERE account_id = ?)";

const DELETE_MAILBOX_SQL: &str = "DELETE FROM mailboxes WHERE id = ? AND account_id = ?";

#[derive(Serialize, Deserialize)]
struct AddressJson {
    name: Option<String>,
    address: String,
}

impl From<&Address> for AddressJson {
    fn from(address: &Address) -> Self {
        Self {
            name: address.name.clone(),
            address: address.address.clone(),
        }
    }
}

impl From<AddressJson> for Address {
    fn from(address: AddressJson) -> Self {
        Self {
            name: address.name,
            address: address.address,
        }
    }
}

#[derive(Default, Serialize, Deserialize)]
struct RecipientsJson {
    #[serde(default)]
    to: Vec<AddressJson>,
    #[serde(default)]
    cc: Vec<AddressJson>,
    #[serde(default)]
    bcc: Vec<AddressJson>,
    #[serde(default)]
    reply_to: Vec<AddressJson>,
}

impl RecipientsJson {
    fn from_header(header: &MessageHeader) -> Self {
        Self {
            to: header.to.iter().map(AddressJson::from).collect(),
            cc: header.cc.iter().map(AddressJson::from).collect(),
            bcc: header.bcc.iter().map(AddressJson::from).collect(),
            reply_to: header.reply_to.iter().map(AddressJson::from).collect(),
        }
    }
}

fn serialize_header(header: &MessageHeader) -> Result<(String, String)> {
    let recipients = serde_json::to_string(&RecipientsJson::from_header(header))
        .map_err(|_| Error::Storage("failed to encode message metadata".into()))?;
    let references = serde_json::to_string(&header.references)
        .map_err(|_| Error::Storage("failed to encode message metadata".into()))?;
    Ok((recipients, references))
}

/// Message of the storage error for a database another connection keeps
/// locked past the busy timeout.
pub const STATE_BUSY_MESSAGE: &str = "state database is busy";

/// Map a database failure to a fixed message.
///
/// SQL text and bound values never appear in it. A lock held by another
/// connection (`SQLITE_BUSY`, `SQLITE_LOCKED`) gets its own message
/// because it is transient, unlike every other failure.
fn storage_error(error: sqlx::Error) -> Error {
    let busy = error
        .as_database_error()
        .and_then(|database| database.code())
        .and_then(|code| code.parse::<i64>().ok())
        // The low byte of an extended result code is the primary code.
        .is_some_and(|code| matches!(code & 0xff, 5 | 6));
    if busy {
        return Error::Storage(STATE_BUSY_MESSAGE.into());
    }
    Error::Storage("state database error".into())
}

fn metadata_error() -> Error {
    Error::Storage("invalid message metadata in state database".into())
}

fn bool_to_int(value: bool) -> i64 {
    if value {
        1
    } else {
        0
    }
}

fn u32_from_i64(value: i64) -> Result<u32> {
    u32::try_from(value).map_err(|_| Error::Storage("invalid UID value in state database".into()))
}

fn u64_from_i64(value: i64) -> Result<u64> {
    u64::try_from(value)
        .map_err(|_| Error::Storage("invalid message size in state database".into()))
}

/// Record `mailbox` in `touched` unless it is already listed.
///
/// The outcome keeps insertion order, so a mailbox touched by several
/// changes of one batch appears once, at its first change.
fn touch_mailbox(touched: &mut Vec<MailboxId>, mailbox: MailboxId) {
    if !touched.contains(&mailbox) {
        touched.push(mailbox);
    }
}

/// Mailboxes a removal statement actually deleted rows from.
///
/// `mailbox_ids` lists the mailboxes the rows to delete belonged to;
/// they count only when the delete removed at least one row.
fn mailboxes_touched_by_removal(mailbox_ids: Vec<i64>, deleted_rows: u64) -> Vec<MailboxId> {
    if deleted_rows == 0 {
        return Vec::new();
    }
    mailbox_ids.into_iter().map(MailboxId).collect()
}

fn stored_mailbox_from_row(row: &SqliteRow) -> Result<StoredMailbox> {
    let kind: String = row.try_get("kind").map_err(storage_error)?;
    let kind = FolderKind::from_db_str(&kind)
        .ok_or_else(|| Error::Storage("invalid mailbox kind in state database".into()))?;
    Ok(StoredMailbox {
        id: MailboxId(row.try_get("id").map_err(storage_error)?),
        account_id: row.try_get("account_id").map_err(storage_error)?,
        list_id: row.try_get("list_id").map_err(storage_error)?,
        name: row.try_get("name").map_err(storage_error)?,
        kind,
        uidvalidity: u32_from_i64(row.try_get("uidvalidity").map_err(storage_error)?)?,
        next_uid: u32_from_i64(row.try_get("next_uid").map_err(storage_error)?)?,
    })
}

/// Map one stored message row to its domain value.
///
/// The columns are metadata only; `mime_structure` is `NULL` until the
/// first enrichment and bodies are never selected because none exist.
fn stored_message_from_row(row: &SqliteRow) -> Result<StoredMessage> {
    let recipients_json: Option<String> = row.try_get("recipients_json").map_err(storage_error)?;
    let recipients = match recipients_json {
        Some(json) => {
            serde_json::from_str::<RecipientsJson>(&json).map_err(|_| metadata_error())?
        }
        None => RecipientsJson::default(),
    };
    let references_json: String = row.try_get("references_json").map_err(storage_error)?;
    let references: Vec<String> =
        serde_json::from_str(&references_json).map_err(|_| metadata_error())?;
    let rfc822_size: Option<i64> = row.try_get("rfc822_size").map_err(storage_error)?;
    let RecipientsJson {
        to,
        cc,
        bcc,
        reply_to,
    } = recipients;

    Ok(StoredMessage {
        uid: u32_from_i64(row.try_get("uid").map_err(storage_error)?)?,
        header: MessageHeader {
            list_id: row.try_get("tuta_list_id").map_err(storage_error)?,
            element_id: row.try_get("tuta_element_id").map_err(storage_error)?,
            received_at_ms: row.try_get("received_at_ms").map_err(storage_error)?,
            sent_at_ms: row.try_get("sent_at_ms").map_err(storage_error)?,
            subject: row.try_get("subject").map_err(storage_error)?,
            from: Address {
                name: row.try_get("from_name").map_err(storage_error)?,
                address: row.try_get("from_address").map_err(storage_error)?,
            },
            to: to.into_iter().map(Address::from).collect(),
            cc: cc.into_iter().map(Address::from).collect(),
            bcc: bcc.into_iter().map(Address::from).collect(),
            reply_to: reply_to.into_iter().map(Address::from).collect(),
            unread: row.try_get::<i64, _>("unread").map_err(storage_error)? != 0,
            message_id: row.try_get("message_id").map_err(storage_error)?,
            in_reply_to: row.try_get("in_reply_to").map_err(storage_error)?,
            references,
            envelope_complete: row
                .try_get::<i64, _>("envelope_complete")
                .map_err(storage_error)?
                != 0,
        },
        rfc822_size: rfc822_size.map(u64_from_i64).transpose()?,
        mime_structure: row.try_get("mime_structure").map_err(storage_error)?,
    })
}

async fn write_message_metadata<'e, E>(
    executor: E,
    mailbox: MailboxId,
    uid: u32,
    header: &MessageHeader,
    rfc822_size: Option<u64>,
) -> Result<()>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    let (recipients_json, references_json) = serialize_header(header)?;
    let rfc822_size = rfc822_size
        .map(|size| {
            i64::try_from(size).map_err(|_| Error::Storage("message size out of range".into()))
        })
        .transpose()?;

    let result = sqlx::query(UPDATE_MESSAGE_SQL)
        .bind(header.received_at_ms)
        .bind(header.sent_at_ms)
        .bind(&header.subject)
        .bind(header.from.name.as_deref())
        .bind(&header.from.address)
        .bind(recipients_json)
        .bind(bool_to_int(header.unread))
        .bind(header.message_id.as_deref())
        .bind(header.in_reply_to.as_deref())
        .bind(references_json)
        .bind(bool_to_int(header.envelope_complete))
        .bind(rfc822_size)
        .bind(mailbox.0)
        .bind(i64::from(uid))
        .execute(executor)
        .await
        .map_err(storage_error)?;

    if result.rows_affected() == 0 {
        return Err(Error::Storage("message UID not found".into()));
    }
    Ok(())
}

async fn write_partial_metadata<'e, E>(
    executor: E,
    mailbox: MailboxId,
    uid: u32,
    header: &MessageHeader,
) -> Result<()>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    let result = sqlx::query(UPDATE_PARTIAL_MESSAGE_SQL)
        .bind(header.received_at_ms)
        .bind(&header.subject)
        .bind(header.from.name.as_deref())
        .bind(&header.from.address)
        .bind(bool_to_int(header.unread))
        .bind(mailbox.0)
        .bind(i64::from(uid))
        .execute(executor)
        .await
        .map_err(storage_error)?;

    if result.rows_affected() == 0 {
        return Err(Error::Storage("message UID not found".into()));
    }
    Ok(())
}

#[async_trait::async_trait]
impl StateStore for SqliteStateStore {
    async fn upsert_account(&self, mail_address: &str) -> Result<i64> {
        sqlx::query(UPSERT_ACCOUNT_SQL)
            .bind(mail_address)
            .execute(&self.pool)
            .await
            .map_err(storage_error)?;
        sqlx::query_scalar(SELECT_ACCOUNT_ID_SQL)
            .bind(mail_address)
            .fetch_one(&self.pool)
            .await
            .map_err(storage_error)
    }

    async fn upsert_mailbox(
        &self,
        account_id: i64,
        folder: &Folder,
        uidvalidity: u32,
    ) -> Result<MailboxId> {
        let mut transaction = self.begin_write().await?;
        let mailbox = self
            .upsert_mailbox_in(&mut transaction, account_id, folder, uidvalidity)
            .await?;
        transaction.commit().await.map_err(storage_error)?;
        Ok(mailbox)
    }

    async fn mailboxes(&self, account_id: i64) -> Result<Vec<StoredMailbox>> {
        let rows = sqlx::query(LIST_MAILBOXES_SQL)
            .bind(account_id)
            .fetch_all(&self.pool)
            .await
            .map_err(storage_error)?;
        rows.iter().map(stored_mailbox_from_row).collect()
    }

    async fn assign_uid(&self, mailbox: MailboxId, header: &MessageHeader) -> Result<u32> {
        let mut transaction = self.begin_write().await?;
        let uid = self
            .assign_uid_in(&mut transaction, mailbox, header)
            .await?;
        transaction.commit().await.map_err(storage_error)?;
        Ok(uid)
    }

    async fn store_page(
        &self,
        mailbox: MailboxId,
        headers: &[MessageHeader],
        keep: &[(String, String)],
        reconcile: bool,
    ) -> Result<usize> {
        // One transaction per page: a folder costs one commit instead of
        // one per message, and a failure leaves the mailbox untouched.
        let mut transaction = self.begin_write().await?;
        for header in headers {
            self.assign_uid_in(&mut transaction, mailbox, header)
                .await?;
        }

        let mut removed = 0;
        if reconcile {
            let fetched: HashSet<(&str, &str)> = headers
                .iter()
                .map(|header| (header.list_id.as_str(), header.element_id.as_str()))
                .chain(
                    keep.iter()
                        .map(|(list_id, element_id)| (list_id.as_str(), element_id.as_str())),
                )
                .collect();
            let stored: Vec<(i64, String, String)> = sqlx::query_as(LIST_MESSAGE_KEYS_SQL)
                .bind(mailbox.0)
                .fetch_all(&mut *transaction)
                .await
                .map_err(storage_error)?;
            for (uid, list_id, element_id) in stored {
                if fetched.contains(&(list_id.as_str(), element_id.as_str())) {
                    continue;
                }
                sqlx::query(DELETE_MESSAGE_SQL)
                    .bind(mailbox.0)
                    .bind(uid)
                    .execute(&mut *transaction)
                    .await
                    .map_err(storage_error)?;
                removed += 1;
            }
        }

        transaction.commit().await.map_err(storage_error)?;
        Ok(removed)
    }

    async fn apply_batch(
        &self,
        account_id: i64,
        group_id: &str,
        batch_id: &str,
        changes: &[StateChange],
    ) -> Result<BatchOutcome> {
        let mut transaction = self.begin_write().await?;
        // Mailboxes whose rows this transaction changes, deduplicated
        // and in first-touch order.
        let mut touched: Vec<MailboxId> = Vec::new();

        // Folders go first so a new folder and its mail can arrive in the same
        // batch regardless of the order the events were produced in.
        for change in changes {
            if let StateChange::UpsertMailbox {
                folder,
                uidvalidity,
            } = change
            {
                let mailbox = self
                    .upsert_mailbox_in(&mut transaction, account_id, folder, *uidvalidity)
                    .await?;
                // The upsert either created the row or refreshed its
                // name and kind; both count as a change.
                touch_mailbox(&mut touched, mailbox);
            }
        }

        // New UIDs must follow arrival time, not event order, so headers are
        // applied oldest-first. Existing UIDs are never reassigned.
        let mut headers: Vec<(&str, &MessageHeader)> = changes
            .iter()
            .filter_map(|change| match change {
                StateChange::UpsertHeader {
                    mailbox_list_id,
                    header,
                } => Some((mailbox_list_id.as_str(), header)),
                _ => None,
            })
            .collect();
        headers.sort_by(|(mailbox_a, header_a), (mailbox_b, header_b)| {
            mailbox_a
                .cmp(mailbox_b)
                .then_with(|| header_a.received_at_ms.cmp(&header_b.received_at_ms))
                .then_with(|| header_a.element_id.cmp(&header_b.element_id))
        });

        for (mailbox_list_id, header) in headers {
            // `header.list_id` is the Mail's own list id, stored in
            // `messages.tuta_list_id` for later content reloads; the mailbox
            // is resolved by the placement's `mailbox_list_id`, never by the
            // header's list id.
            let mailbox: Option<i64> = sqlx::query_scalar(SELECT_MAILBOX_ID_SQL)
                .bind(account_id)
                .bind(mailbox_list_id)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(storage_error)?;
            if let Some(mailbox) = mailbox {
                // A successful write always inserts or updates a row.
                self.assign_uid_in(&mut transaction, MailboxId(mailbox), header)
                    .await?;
                touch_mailbox(&mut touched, MailboxId(mailbox));
            }
        }

        // Removals run after header refreshes so a placement that is kept by
        // the same batch is written before stale placements are pruned.
        for change in changes {
            match change {
                StateChange::RemoveHeaderEverywhere { element_id } => {
                    let removed_from = self
                        .remove_placements_in(&mut transaction, account_id, element_id, &[])
                        .await?;
                    for mailbox in removed_from {
                        touch_mailbox(&mut touched, mailbox);
                    }
                }
                StateChange::RemoveOtherPlacements {
                    element_id,
                    keep_list_ids,
                } => {
                    let removed_from = self
                        .remove_placements_in(
                            &mut transaction,
                            account_id,
                            element_id,
                            keep_list_ids,
                        )
                        .await?;
                    for mailbox in removed_from {
                        touch_mailbox(&mut touched, mailbox);
                    }
                }
                StateChange::UpsertMailbox { .. } | StateChange::UpsertHeader { .. } => {}
            }
        }

        sqlx::query(UPSERT_LAST_BATCH_SQL)
            .bind(account_id)
            .bind(group_id)
            .bind(batch_id)
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;

        transaction.commit().await.map_err(storage_error)?;
        Ok(BatchOutcome { touched })
    }

    async fn remove_mailbox(&self, account_id: i64, mailbox: MailboxId) -> Result<()> {
        let mut transaction = self.begin_write().await?;
        sqlx::query(DELETE_MAILBOX_MESSAGES_SQL)
            .bind(mailbox.0)
            .bind(account_id)
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;
        sqlx::query(DELETE_MAILBOX_SQL)
            .bind(mailbox.0)
            .bind(account_id)
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;
        transaction.commit().await.map_err(storage_error)?;
        Ok(())
    }

    async fn update_metadata(
        &self,
        mailbox: MailboxId,
        uid: u32,
        header: &MessageHeader,
        rfc822_size: Option<u64>,
    ) -> Result<()> {
        write_message_metadata(&self.pool, mailbox, uid, header, rfc822_size).await
    }

    async fn set_mime_structure(
        &self,
        mailbox: MailboxId,
        uid: u32,
        structure: &str,
    ) -> Result<()> {
        let result = sqlx::query(SET_MIME_STRUCTURE_SQL)
            .bind(structure)
            .bind(mailbox.0)
            .bind(i64::from(uid))
            .execute(&self.pool)
            .await
            .map_err(storage_error)?;
        if result.rows_affected() == 0 {
            return Err(Error::Storage("message UID not found".into()));
        }
        Ok(())
    }

    async fn remove_message(&self, mailbox: MailboxId, uid: u32) -> Result<()> {
        sqlx::query(DELETE_MESSAGE_SQL)
            .bind(mailbox.0)
            .bind(i64::from(uid))
            .execute(&self.pool)
            .await
            .map_err(storage_error)?;
        Ok(())
    }

    async fn messages(&self, mailbox: MailboxId) -> Result<Vec<StoredMessage>> {
        let rows = sqlx::query(LIST_MESSAGES_SQL)
            .bind(mailbox.0)
            .fetch_all(&self.pool)
            .await
            .map_err(storage_error)?;

        rows.iter().map(stored_message_from_row).collect()
    }

    async fn message_uids(&self, mailbox: MailboxId) -> Result<Vec<(u32, bool)>> {
        let rows: Vec<(i64, i64)> = sqlx::query_as(LIST_MESSAGE_UIDS_SQL)
            .bind(mailbox.0)
            .fetch_all(&self.pool)
            .await
            .map_err(storage_error)?;
        rows.into_iter()
            .map(|(uid, unread)| Ok((u32_from_i64(uid)?, unread != 0)))
            .collect()
    }

    async fn message_by_uid(&self, mailbox: MailboxId, uid: u32) -> Result<Option<StoredMessage>> {
        let row = sqlx::query(SELECT_MESSAGE_BY_UID_SQL)
            .bind(mailbox.0)
            .bind(i64::from(uid))
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_error)?;
        row.as_ref().map(stored_message_from_row).transpose()
    }

    async fn last_batch(&self, account_id: i64, group_id: &str) -> Result<Option<String>> {
        sqlx::query_scalar(SELECT_LAST_BATCH_SQL)
            .bind(account_id)
            .bind(group_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_error)
    }

    async fn set_last_batch(&self, account_id: i64, group_id: &str, batch_id: &str) -> Result<()> {
        sqlx::query(UPSERT_LAST_BATCH_SQL)
            .bind(account_id)
            .bind(group_id)
            .bind(batch_id)
            .execute(&self.pool)
            .await
            .map_err(storage_error)?;
        Ok(())
    }

    async fn reset_account(&self, account_id: i64) -> Result<()> {
        let mut transaction = self.begin_write().await?;
        sqlx::query(DELETE_ACCOUNT_MESSAGES_SQL)
            .bind(account_id)
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;
        sqlx::query(DELETE_ACCOUNT_MAILBOXES_SQL)
            .bind(account_id)
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;
        sqlx::query(DELETE_ACCOUNT_SYNC_STATE_SQL)
            .bind(account_id)
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;
        transaction.commit().await.map_err(storage_error)?;
        Ok(())
    }
}

/// Candidate paths for the main database file and SQLite's WAL sidecars.
#[cfg(unix)]
fn state_file_paths(path: &Path) -> [PathBuf; 3] {
    ["", "-wal", "-shm"].map(|suffix| {
        let mut candidate = path.as_os_str().to_owned();
        candidate.push(suffix);
        PathBuf::from(candidate)
    })
}

/// Tighten the database file and its WAL sidecars to owner-only access.
///
/// On Unix the actual strategy is two-layered: [`restrict_process_umask`] sets
/// the process umask to `0o077` before SQLite creates anything, so any sidecar
/// SQLite later recreates is already owner-only, and this function re-applies
/// `0o600` after schema creation has forced `-wal`/`-shm` into existence. The
/// pool also disables connection recycling (see [`pool_options`]) so a
/// recycled connection cannot reopen SQLite behind our back. Files that do not
/// exist are skipped.
#[cfg(unix)]
fn tighten_state_files(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    for candidate in state_file_paths(path) {
        match fs::set_permissions(&candidate, fs::Permissions::from_mode(0o600)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("failed to tighten permissions on {}", candidate.display())
                });
            }
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn tighten_state_files(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

/// Pool settings shared by the file and in-memory stores.
///
/// The store uses one connection for its whole lifetime and explicitly
/// disables connection recycling. A recycled connection would reopen SQLite
/// and let it recreate `-wal`/`-shm`, bypassing the permission tightening in
/// `SqliteStateStore::open`.
fn pool_options() -> SqlitePoolOptions {
    SqlitePoolOptions::new()
        .max_connections(1)
        .max_lifetime(None)
        .idle_timeout(None)
}

/// Set a restrictive process umask so files created by SQLite are owner-only.
///
/// The umask is process-global and intentionally left at `0o077`: SQLite may
/// recreate WAL sidecars after a connection error or checkpoint, and those
/// files contain plaintext header metadata.
#[cfg(unix)]
fn restrict_process_umask() {
    // SAFETY: `umask` only updates a process-global permission setting and
    // cannot violate memory safety.
    unsafe {
        libc::umask(0o077);
    }
}

#[cfg(not(unix))]
fn restrict_process_umask() {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{Address, Folder, FolderKind, MailboxId, MessageHeader};
    use crate::ports::StateStore;

    fn header(list_id: &str, element_id: &str) -> MessageHeader {
        MessageHeader {
            list_id: list_id.into(),
            element_id: element_id.into(),
            received_at_ms: 1_700_000_000_000,
            sent_at_ms: 0,
            subject: "subject".into(),
            from: Address {
                name: Some("Alice".into()),
                address: "alice@example.invalid".into(),
            },
            to: vec![Address {
                name: None,
                address: "bob@example.invalid".into(),
            }],
            cc: vec![],
            bcc: vec![],
            reply_to: vec![],
            unread: true,
            message_id: Some("<m1@example.invalid>".into()),
            in_reply_to: None,
            references: vec!["<r1@example.invalid>".into()],
            envelope_complete: true,
        }
    }

    fn folder(list_id: &str, name: &str, kind: FolderKind) -> Folder {
        Folder {
            list_id: list_id.into(),
            name: name.into(),
            kind,
        }
    }

    async fn account_and_mailbox(store: &SqliteStateStore) -> (i64, MailboxId) {
        let account = store.upsert_account("owner@example.invalid").await.unwrap();
        let mailbox = store
            .upsert_mailbox(account, &folder("entries", "Inbox", FolderKind::Inbox), 100)
            .await
            .unwrap();
        (account, mailbox)
    }

    #[tokio::test]
    async fn upsert_account_is_idempotent() {
        let store = SqliteStateStore::open_in_memory().await.unwrap();
        let first = store.upsert_account("a@b.c").await.unwrap();
        let second = store.upsert_account("a@b.c").await.unwrap();
        assert_eq!(first, second);
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM accounts")
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn upsert_mailbox_updates_kind_without_touching_uid_state() {
        let store = SqliteStateStore::open_in_memory().await.unwrap();
        let (account, mailbox) = account_and_mailbox(&store).await;
        assert_eq!(
            store
                .assign_uid(mailbox, &header("entries", "e1"))
                .await
                .unwrap(),
            1
        );

        let again = store
            .upsert_mailbox(
                account,
                &folder("entries", "Inbox", FolderKind::Archive),
                999,
            )
            .await
            .unwrap();
        assert_eq!(again, mailbox);

        let boxes = store.mailboxes(account).await.unwrap();
        assert_eq!(boxes.len(), 1);
        assert_eq!(boxes[0].id, mailbox);
        assert_eq!(boxes[0].name, "Inbox");
        assert_eq!(boxes[0].kind, FolderKind::Archive);
        assert_eq!(boxes[0].uidvalidity, 100);
        assert_eq!(boxes[0].next_uid, 2);
    }

    #[tokio::test]
    async fn every_mailbox_gets_its_own_uidvalidity() {
        let store = SqliteStateStore::open_in_memory().await.unwrap();
        let (account, first) = account_and_mailbox(&store).await;
        // The same requested value, as one sync hands to every folder.
        let second = store
            .upsert_mailbox(account, &folder("other", "Other", FolderKind::Custom), 100)
            .await
            .unwrap();
        // An older requested value never goes below the high-water mark.
        let third = store
            .upsert_mailbox(account, &folder("third", "Third", FolderKind::Custom), 5)
            .await
            .unwrap();

        let validity = |boxes: &[StoredMailbox], id: MailboxId| {
            boxes
                .iter()
                .find(|mailbox| mailbox.id == id)
                .map(|mailbox| mailbox.uidvalidity)
                .unwrap()
        };
        let boxes = store.mailboxes(account).await.unwrap();
        assert_eq!(validity(&boxes, first), 100);
        assert_eq!(validity(&boxes, second), 101);
        assert_eq!(validity(&boxes, third), 102);
    }

    #[tokio::test]
    async fn renaming_a_mailbox_gives_it_a_fresh_uidvalidity_and_keeps_its_uids() {
        let store = SqliteStateStore::open_in_memory().await.unwrap();
        let (account, old_a) = account_and_mailbox(&store).await;
        let b = store
            .upsert_mailbox(account, &folder("b", "B", FolderKind::Custom), 100)
            .await
            .unwrap();
        store.assign_uid(b, &header("mail", "e1")).await.unwrap();
        let before = store.mailboxes(account).await.unwrap();

        // Folder "Inbox" is deleted and "B" is renamed onto its name.
        store.remove_mailbox(account, old_a).await.unwrap();
        let renamed = store
            .upsert_mailbox(account, &folder("b", "Inbox", FolderKind::Custom), 100)
            .await
            .unwrap();
        assert_eq!(renamed, b);

        let after = store.mailboxes(account).await.unwrap();
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].name, "Inbox");
        // The name "Inbox" never shows a UIDVALIDITY it had before.
        assert!(before
            .iter()
            .all(|mailbox| mailbox.uidvalidity != after[0].uidvalidity));
        // The messages and the UID sequence are untouched.
        assert_eq!(after[0].next_uid, 2);
        assert_eq!(store.messages(b).await.unwrap()[0].uid, 1);
    }

    #[tokio::test]
    async fn a_recreated_mailbox_never_repeats_a_uidvalidity() {
        let store = SqliteStateStore::open_in_memory().await.unwrap();
        let account = store.upsert_account("owner@example.invalid").await.unwrap();
        // One watch run stamps every folder event with the same value.
        let event_uidvalidity = 700;
        let changes = |list_id: &str| {
            vec![StateChange::UpsertMailbox {
                folder: folder(list_id, "Tmp", FolderKind::Custom),
                uidvalidity: event_uidvalidity,
            }]
        };

        store
            .apply_batch(account, "group", "batch-1", &changes("tmp-1"))
            .await
            .unwrap();
        let first = store.mailboxes(account).await.unwrap()[0].clone();
        store.remove_mailbox(account, first.id).await.unwrap();

        // The folder is created again under the same name.
        store
            .apply_batch(account, "group", "batch-2", &changes("tmp-2"))
            .await
            .unwrap();
        let second = store.mailboxes(account).await.unwrap()[0].clone();
        assert_eq!(second.name, first.name);
        assert_ne!(second.uidvalidity, first.uidvalidity);

        // A full reset does not forget the values already used either.
        store.reset_account(account).await.unwrap();
        store
            .apply_batch(account, "group", "batch-3", &changes("tmp-3"))
            .await
            .unwrap();
        let third = store.mailboxes(account).await.unwrap()[0].clone();
        assert!(third.uidvalidity > second.uidvalidity);
    }

    #[tokio::test]
    async fn migrated_mailboxes_keep_their_uidvalidity_and_new_ones_get_a_higher_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.sqlite3");
        version_two_database(&path).await;
        let store = SqliteStateStore::open(&path).await.unwrap();

        // A sync with an older requested value still lands above every
        // value the legacy mailboxes share.
        let created = store
            .upsert_mailbox(1, &folder("entries-c", "New", FolderKind::Custom), 50)
            .await
            .unwrap();
        let validities: Vec<(i64, u32)> = store
            .mailboxes(1)
            .await
            .unwrap()
            .iter()
            .map(|mailbox| (mailbox.id.0, mailbox.uidvalidity))
            .collect();
        assert_eq!(validities, vec![(1, 100), (2, 100), (created.0, 101)]);
    }

    #[tokio::test]
    async fn apply_batch_writes_changes_and_last_batch_in_one_transaction() {
        let store = SqliteStateStore::open_in_memory().await.unwrap();
        let account = store.upsert_account("owner@example.invalid").await.unwrap();
        let folder = Folder {
            list_id: "list".into(),
            name: "Inbox".into(),
            kind: FolderKind::Inbox,
        };
        store
            .apply_batch(
                account,
                "group",
                "batch-1",
                &[
                    StateChange::UpsertMailbox {
                        folder,
                        uidvalidity: 7,
                    },
                    StateChange::UpsertHeader {
                        mailbox_list_id: "list".into(),
                        header: header("mail-list", "e1"),
                    },
                ],
            )
            .await
            .unwrap();

        let mailbox = store.mailboxes(account).await.unwrap().remove(0);
        assert_eq!(mailbox.uidvalidity, 7);
        assert_eq!(store.messages(mailbox.id).await.unwrap()[0].uid, 1);
        assert_eq!(
            store.last_batch(account, "group").await.unwrap().as_deref(),
            Some("batch-1")
        );
    }

    #[tokio::test]
    async fn apply_batch_rolls_back_updates_when_a_later_change_fails() {
        let store = SqliteStateStore::open_in_memory().await.unwrap();
        let account = store.upsert_account("owner@example.invalid").await.unwrap();
        sqlx::query(
            "CREATE TRIGGER fail_insert BEFORE INSERT ON messages
             BEGIN SELECT RAISE(ABORT, 'forced'); END",
        )
        .execute(store.pool())
        .await
        .unwrap();
        let folder = Folder {
            list_id: "list".into(),
            name: "Inbox".into(),
            kind: FolderKind::Inbox,
        };
        let error = store
            .apply_batch(
                account,
                "group",
                "batch-1",
                &[
                    StateChange::UpsertMailbox {
                        folder,
                        uidvalidity: 7,
                    },
                    StateChange::UpsertHeader {
                        mailbox_list_id: "list".into(),
                        header: header("mail-list", "e1"),
                    },
                ],
            )
            .await
            // `BatchOutcome` deliberately has no `Debug`, so the outcome is
            // discarded without `unwrap_err`.
            .err()
            .expect("apply_batch must fail");
        assert!(matches!(error, Error::Storage(_)));
        assert!(store.mailboxes(account).await.unwrap().is_empty());
        assert_eq!(store.last_batch(account, "group").await.unwrap(), None);
    }

    #[tokio::test]
    async fn apply_batch_persists_empty_batches() {
        let store = SqliteStateStore::open_in_memory().await.unwrap();
        let account = store.upsert_account("owner@example.invalid").await.unwrap();

        store
            .apply_batch(account, "group", "batch-1", &[])
            .await
            .unwrap();

        assert_eq!(
            store.last_batch(account, "group").await.unwrap().as_deref(),
            Some("batch-1")
        );
    }

    #[tokio::test]
    async fn apply_batch_assigns_new_uids_in_received_order() {
        let store = SqliteStateStore::open_in_memory().await.unwrap();
        let account = store.upsert_account("owner@example.invalid").await.unwrap();
        let mailbox = store
            .upsert_mailbox(account, &folder("list", "Inbox", FolderKind::Inbox), 7)
            .await
            .unwrap();

        let mut newer = header("mail-list", "newer");
        newer.received_at_ms = 1_700_000_002_000;
        let mut older = header("mail-list", "older");
        older.received_at_ms = 1_700_000_001_000;

        store
            .apply_batch(
                account,
                "group",
                "batch-1",
                &[
                    StateChange::UpsertHeader {
                        mailbox_list_id: "list".into(),
                        header: newer,
                    },
                    StateChange::UpsertHeader {
                        mailbox_list_id: "list".into(),
                        header: older,
                    },
                ],
            )
            .await
            .unwrap();

        let messages = store.messages(mailbox).await.unwrap();
        assert_eq!(messages.len(), 2);
        let uid = |element_id: &str| {
            messages
                .iter()
                .find(|message| message.header.element_id == element_id)
                .map(|message| message.uid)
                .unwrap()
        };
        assert_eq!(uid("older"), 1);
        assert_eq!(uid("newer"), 2);
    }

    #[tokio::test]
    async fn apply_batch_removes_header_everywhere() {
        let store = SqliteStateStore::open_in_memory().await.unwrap();
        let (account, mailbox) = account_and_mailbox(&store).await;
        let other_account = store.upsert_account("other@example.invalid").await.unwrap();
        let other_mailbox = store
            .upsert_mailbox(
                other_account,
                &folder("entries", "Inbox", FolderKind::Inbox),
                200,
            )
            .await
            .unwrap();
        store
            .assign_uid(mailbox, &header("entries", "shared"))
            .await
            .unwrap();
        store
            .assign_uid(other_mailbox, &header("entries", "shared"))
            .await
            .unwrap();

        store
            .apply_batch(
                account,
                "group",
                "batch-1",
                &[StateChange::RemoveHeaderEverywhere {
                    element_id: "shared".into(),
                }],
            )
            .await
            .unwrap();

        assert!(store.messages(mailbox).await.unwrap().is_empty());
        // The same element in another account is untouched.
        assert_eq!(store.messages(other_mailbox).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn apply_batch_removes_other_placements() {
        let store = SqliteStateStore::open_in_memory().await.unwrap();
        let account = store.upsert_account("owner@example.invalid").await.unwrap();
        let first = store
            .upsert_mailbox(account, &folder("first", "First", FolderKind::Inbox), 1)
            .await
            .unwrap();
        let second = store
            .upsert_mailbox(account, &folder("second", "Second", FolderKind::Archive), 1)
            .await
            .unwrap();
        store
            .assign_uid(first, &header("first", "shared"))
            .await
            .unwrap();
        store
            .assign_uid(second, &header("second", "shared"))
            .await
            .unwrap();

        store
            .apply_batch(
                account,
                "group",
                "batch-1",
                &[StateChange::RemoveOtherPlacements {
                    element_id: "shared".into(),
                    keep_list_ids: vec!["first".into()],
                }],
            )
            .await
            .unwrap();

        assert_eq!(store.messages(first).await.unwrap().len(), 1);
        assert!(store.messages(second).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn apply_batch_reports_touched_mailboxes() {
        let store = SqliteStateStore::open_in_memory().await.unwrap();
        let account = store.upsert_account("owner@example.invalid").await.unwrap();
        let mailbox_a = store
            .upsert_mailbox(account, &folder("list-a", "Inbox", FolderKind::Inbox), 1)
            .await
            .unwrap();
        let mailbox_b = store
            .upsert_mailbox(account, &folder("list-b", "Second", FolderKind::Archive), 1)
            .await
            .unwrap();
        let mailbox_c = store
            .upsert_mailbox(account, &folder("list-c", "Third", FolderKind::Custom), 1)
            .await
            .unwrap();
        // A stale placement of "shared" lives in list-b.
        store
            .assign_uid(mailbox_b, &header("list-b", "shared"))
            .await
            .unwrap();

        // Two mailboxes; one is upserted into, one has a stale placement
        // removed, a third is untouched.
        let outcome = store
            .apply_batch(
                account,
                "group",
                "batch-1",
                &[
                    StateChange::UpsertHeader {
                        mailbox_list_id: "list-a".into(),
                        header: header("mail-list", "mail-1"),
                    },
                    StateChange::RemoveOtherPlacements {
                        element_id: "shared".into(),
                        keep_list_ids: vec!["list-a".into()],
                    },
                ],
            )
            .await
            .unwrap();

        // The outcome lists exactly the two changed ids, in the order
        // the batch first touched them.
        assert_eq!(outcome.touched, vec![mailbox_a, mailbox_b]);
        assert!(!outcome.touched.contains(&mailbox_c));
    }

    #[tokio::test]
    async fn apply_batch_touches_only_mailboxes_whose_rows_changed() {
        let store = SqliteStateStore::open_in_memory().await.unwrap();
        let account = store.upsert_account("owner@example.invalid").await.unwrap();
        let mailbox_a = store
            .upsert_mailbox(account, &folder("list-a", "Inbox", FolderKind::Inbox), 1)
            .await
            .unwrap();
        let mailbox_b = store
            .upsert_mailbox(account, &folder("list-b", "Second", FolderKind::Archive), 1)
            .await
            .unwrap();
        store
            .assign_uid(mailbox_a, &header("list-a", "e1"))
            .await
            .unwrap();

        // An upsert for an unknown mailbox writes no row; the removal
        // deletes a row only in list-a.
        let outcome = store
            .apply_batch(
                account,
                "group",
                "batch-1",
                &[
                    StateChange::UpsertHeader {
                        mailbox_list_id: "missing".into(),
                        header: header("mail-list", "e2"),
                    },
                    StateChange::RemoveHeaderEverywhere {
                        element_id: "e1".into(),
                    },
                ],
            )
            .await
            .unwrap();

        assert_eq!(outcome.touched, vec![mailbox_a]);
        assert!(!outcome.touched.contains(&mailbox_b));
    }

    #[tokio::test]
    async fn apply_batch_marks_upserted_mailboxes_as_touched() {
        let store = SqliteStateStore::open_in_memory().await.unwrap();
        let account = store.upsert_account("owner@example.invalid").await.unwrap();

        let changes = [StateChange::UpsertMailbox {
            folder: folder("list-a", "Inbox", FolderKind::Inbox),
            uidvalidity: 7,
        }];
        let outcome = store
            .apply_batch(account, "group", "batch-1", &changes)
            .await
            .unwrap();
        let mailbox = store.mailboxes(account).await.unwrap().remove(0);
        // Creating the row counts.
        assert_eq!(outcome.touched, vec![mailbox.id]);

        // Replaying the same upsert runs the DO UPDATE path, which also
        // counts as a change.
        let outcome = store
            .apply_batch(account, "group", "batch-2", &changes)
            .await
            .unwrap();
        assert_eq!(outcome.touched, vec![mailbox.id]);
    }

    #[tokio::test]
    async fn apply_batch_removes_a_mailbox_and_its_messages() {
        let store = SqliteStateStore::open_in_memory().await.unwrap();
        let account = store.upsert_account("owner@example.invalid").await.unwrap();
        let removed = store
            .upsert_mailbox(
                account,
                &folder("removed", "Removed", FolderKind::Archive),
                1,
            )
            .await
            .unwrap();
        let kept = store
            .upsert_mailbox(account, &folder("kept", "Kept", FolderKind::Inbox), 1)
            .await
            .unwrap();
        store
            .assign_uid(removed, &header("removed", "e1"))
            .await
            .unwrap();
        store.assign_uid(kept, &header("kept", "e2")).await.unwrap();

        store.remove_mailbox(account, removed).await.unwrap();

        let mailboxes = store.mailboxes(account).await.unwrap();
        assert_eq!(mailboxes.len(), 1);
        assert_eq!(mailboxes[0].id, kept);
        assert!(store.messages(removed).await.unwrap().is_empty());
        assert_eq!(store.messages(kept).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn apply_batch_skips_unknown_mailbox() {
        let store = SqliteStateStore::open_in_memory().await.unwrap();
        let account = store.upsert_account("owner@example.invalid").await.unwrap();

        store
            .apply_batch(
                account,
                "group",
                "batch-1",
                &[StateChange::UpsertHeader {
                    mailbox_list_id: "missing".into(),
                    header: header("mail-list", "e1"),
                }],
            )
            .await
            .unwrap();

        assert!(store.mailboxes(account).await.unwrap().is_empty());
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM messages")
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn apply_batch_resolves_the_mailbox_by_placement_list_id() {
        let store = SqliteStateStore::open_in_memory().await.unwrap();
        let account = store.upsert_account("owner@example.invalid").await.unwrap();
        let mailbox = store
            .upsert_mailbox(
                account,
                &folder("folder-list", "Inbox", FolderKind::Inbox),
                7,
            )
            .await
            .unwrap();
        let changes = [StateChange::UpsertHeader {
            mailbox_list_id: "folder-list".into(),
            header: header("mail-list", "mail-1"),
        }];

        store
            .apply_batch(account, "group", "batch-1", &changes)
            .await
            .unwrap();

        // The row lives in the mailbox resolved by `mailbox_list_id`...
        let messages = store.messages(mailbox).await.unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].uid, 1);
        // ...while the stored header keeps the Mail's own list id, never
        // the folder's entries list id.
        assert_eq!(messages[0].header.list_id, "mail-list");
        assert_eq!(messages[0].header.element_id, "mail-1");
        let tuta_list_id: String = sqlx::query_scalar("SELECT tuta_list_id FROM messages")
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(tuta_list_id, "mail-list");

        // Reapplying the same batch neither duplicates nor reassigns.
        store
            .apply_batch(account, "group", "batch-1", &changes)
            .await
            .unwrap();
        let messages = store.messages(mailbox).await.unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].uid, 1);
    }

    #[tokio::test]
    async fn uid_assignment_is_idempotent_and_monotonic() {
        let store = SqliteStateStore::open_in_memory().await.unwrap();
        let (account, mailbox) = account_and_mailbox(&store).await;
        let h1 = header("entries", "e1");
        let h2 = header("entries", "e2");
        assert_eq!(store.assign_uid(mailbox, &h1).await.unwrap(), 1);
        assert_eq!(store.assign_uid(mailbox, &h1).await.unwrap(), 1);
        assert_eq!(store.assign_uid(mailbox, &h2).await.unwrap(), 2);

        let boxes = store.mailboxes(account).await.unwrap();
        assert_eq!(boxes[0].next_uid, 3);
        assert_eq!(boxes[0].uidvalidity, 100);
    }

    #[tokio::test]
    async fn assign_uid_updates_metadata_without_changing_uid() {
        let store = SqliteStateStore::open_in_memory().await.unwrap();
        let (account, mailbox) = account_and_mailbox(&store).await;
        let first = header("entries", "e1");
        assert_eq!(store.assign_uid(mailbox, &first).await.unwrap(), 1);

        let mut changed = first.clone();
        changed.subject = "updated subject".into();
        changed.unread = false;
        changed.references = vec!["<r2@example.invalid>".into()];
        assert_eq!(store.assign_uid(mailbox, &changed).await.unwrap(), 1);

        let stored = store.messages(mailbox).await.unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].header.subject, "updated subject");
        assert!(!stored[0].header.unread);
        assert_eq!(stored[0].header.references, changed.references);
        assert_eq!(store.mailboxes(account).await.unwrap()[0].next_uid, 2);
    }

    #[tokio::test]
    async fn assign_uid_partial_header_preserves_enriched_envelope() {
        let store = SqliteStateStore::open_in_memory().await.unwrap();
        let (_, mailbox) = account_and_mailbox(&store).await;

        let mut complete = header("entries", "e1");
        complete.sent_at_ms = 1_699_999_999_000;
        complete.in_reply_to = Some("<parent@example.invalid>".into());
        assert!(complete.envelope_complete);
        assert_eq!(store.assign_uid(mailbox, &complete).await.unwrap(), 1);

        let mut partial = complete.clone();
        partial.received_at_ms = 1_700_000_001_000;
        partial.sent_at_ms = 0;
        partial.subject = "refreshed subject".into();
        partial.from.address = "new-sender@example.invalid".into();
        partial.to.clear();
        partial.cc.clear();
        partial.bcc.clear();
        partial.reply_to.clear();
        partial.message_id = None;
        partial.in_reply_to = None;
        partial.references.clear();
        partial.unread = false;
        partial.envelope_complete = false;

        assert_eq!(store.assign_uid(mailbox, &partial).await.unwrap(), 1);

        let stored = store.messages(mailbox).await.unwrap();
        assert_eq!(stored.len(), 1);
        let stored = &stored[0].header;
        // List-level fields follow the incoming partial header.
        assert_eq!(stored.received_at_ms, partial.received_at_ms);
        assert_eq!(stored.subject, "refreshed subject");
        assert_eq!(stored.from.address, "new-sender@example.invalid");
        assert!(!stored.unread);
        // Envelope fields stay enriched from the complete header.
        assert!(stored.envelope_complete);
        assert_eq!(stored.sent_at_ms, complete.sent_at_ms);
        assert_eq!(stored.to.len(), 1);
        assert_eq!(stored.message_id, complete.message_id);
        assert_eq!(stored.in_reply_to, complete.in_reply_to);
        assert_eq!(stored.references, complete.references);
    }

    #[tokio::test]
    async fn assign_uid_leaves_no_partial_state_on_failure() {
        let store = SqliteStateStore::open_in_memory().await.unwrap();
        let (account, mailbox) = account_and_mailbox(&store).await;
        sqlx::query(
            "CREATE TRIGGER fail_message_insert BEFORE INSERT ON messages
             BEGIN SELECT RAISE(ABORT, 'forced failure'); END",
        )
        .execute(store.pool())
        .await
        .unwrap();

        assert!(store
            .assign_uid(mailbox, &header("entries", "e1"))
            .await
            .is_err());
        assert_eq!(store.mailboxes(account).await.unwrap()[0].next_uid, 1);
        assert!(store.messages(mailbox).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn store_page_assigns_reconciles_and_reports_removals() {
        let store = SqliteStateStore::open_in_memory().await.unwrap();
        let (account, mailbox) = account_and_mailbox(&store).await;
        let first = [header("mail", "e1"), header("mail", "e2")];
        assert_eq!(
            store.store_page(mailbox, &first, &[], true).await.unwrap(),
            0
        );

        // e1 is gone from the next complete page and e3 is new: e2 keeps
        // its UID, e3 gets the next one, and e1's UID is not reused.
        let second = [header("mail", "e2"), header("mail", "e3")];
        assert_eq!(
            store.store_page(mailbox, &second, &[], true).await.unwrap(),
            1
        );
        let stored: Vec<(u32, String)> = store
            .messages(mailbox)
            .await
            .unwrap()
            .into_iter()
            .map(|message| (message.uid, message.header.element_id))
            .collect();
        assert_eq!(stored, vec![(2, "e2".to_string()), (3, "e3".to_string())]);

        // A mail the folder still lists but that could not be loaded is
        // kept as stored, while a genuinely absent one would be removed.
        let unreadable = [("mail".to_string(), "e2".to_string())];
        assert_eq!(
            store
                .store_page(mailbox, &second[1..], &unreadable, true)
                .await
                .unwrap(),
            0
        );
        assert_eq!(store.messages(mailbox).await.unwrap().len(), 2);

        // An incomplete page removes nothing.
        let partial = [header("mail", "e3")];
        assert_eq!(
            store
                .store_page(mailbox, &partial, &[], false)
                .await
                .unwrap(),
            0
        );
        assert_eq!(store.messages(mailbox).await.unwrap().len(), 2);
        assert_eq!(store.mailboxes(account).await.unwrap()[0].next_uid, 4);
    }

    #[tokio::test]
    async fn message_uids_lists_uid_and_unread_in_uid_order() {
        let store = SqliteStateStore::open_in_memory().await.unwrap();
        let (account, mailbox) = account_and_mailbox(&store).await;
        let other = store
            .upsert_mailbox(account, &folder("other", "Other", FolderKind::Custom), 100)
            .await
            .unwrap();
        let mut read = header("mail", "e2");
        read.unread = false;
        for stored in [header("mail", "e1"), read, header("mail", "e3")] {
            store.assign_uid(mailbox, &stored).await.unwrap();
        }
        store
            .assign_uid(other, &header("mail", "e9"))
            .await
            .unwrap();
        // A removed message leaves a gap, not a renumbering.
        store.remove_message(mailbox, 1).await.unwrap();

        assert_eq!(
            store.message_uids(mailbox).await.unwrap(),
            vec![(2, false), (3, true)]
        );
        assert_eq!(store.message_uids(other).await.unwrap(), vec![(1, true)]);
        assert!(store.message_uids(MailboxId(999)).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn store_page_is_all_or_nothing() {
        let store = SqliteStateStore::open_in_memory().await.unwrap();
        let (account, mailbox) = account_and_mailbox(&store).await;
        store
            .store_page(mailbox, &[header("mail", "e1")], &[], true)
            .await
            .unwrap();
        // The second new message of the page fails to insert.
        sqlx::query(
            "CREATE TRIGGER fail_one_insert BEFORE INSERT ON messages
             WHEN NEW.tuta_element_id = 'e3'
             BEGIN SELECT RAISE(ABORT, 'forced failure'); END",
        )
        .execute(store.pool())
        .await
        .unwrap();

        let page = [header("mail", "e2"), header("mail", "e3")];
        assert!(store.store_page(mailbox, &page, &[], true).await.is_err());

        // Neither the first insert nor the removal of e1 was kept.
        let stored = store.messages(mailbox).await.unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].header.element_id, "e1");
        assert_eq!(store.mailboxes(account).await.unwrap()[0].next_uid, 2);
    }

    #[tokio::test]
    async fn element_removals_use_the_element_index() {
        let store = SqliteStateStore::open_in_memory().await.unwrap();
        for sql in [DELETE_ELEMENT_HEADERS_SQL, SELECT_ELEMENT_MAILBOXES_SQL] {
            let plan: Vec<String> = sqlx::query(&format!("EXPLAIN QUERY PLAN {sql}"))
                .bind("e1")
                .bind(1_i64)
                .fetch_all(store.pool())
                .await
                .unwrap()
                .iter()
                .map(|row| row.get::<String, _>("detail"))
                .collect();
            assert!(
                plan.iter().any(|step| step.contains("messages_by_element")),
                "expected the element index in {plan:?}"
            );
        }
    }

    #[tokio::test]
    async fn messages_roundtrip_headers_without_content() {
        let store = SqliteStateStore::open_in_memory().await.unwrap();
        let (_, mailbox) = account_and_mailbox(&store).await;
        let header = header("entries", "e1");
        assert_eq!(store.assign_uid(mailbox, &header).await.unwrap(), 1);

        let stored = store.messages(mailbox).await.unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].uid, 1);
        assert_eq!(stored[0].header.list_id, "entries");
        assert_eq!(stored[0].header.element_id, "e1");
        assert_eq!(stored[0].header.subject, "subject");
        assert_eq!(stored[0].header.from.name.as_deref(), Some("Alice"));
        assert_eq!(stored[0].header.from.address, "alice@example.invalid");
        assert_eq!(stored[0].header.to.len(), 1);
        assert_eq!(stored[0].header.references, header.references);
        assert!(stored[0].header.unread);
        assert!(stored[0].header.envelope_complete);
        assert_eq!(stored[0].rfc822_size, None);

        let recipients_json: String =
            sqlx::query_scalar("SELECT recipients_json FROM messages WHERE uid = 1")
                .fetch_one(store.pool())
                .await
                .unwrap();
        let recipients: serde_json::Value = serde_json::from_str(&recipients_json).unwrap();
        for key in ["to", "cc", "bcc", "reply_to"] {
            assert!(recipients[key].is_array(), "missing {key} array");
        }

        let mut updated = header.clone();
        updated.subject = "updated".into();
        updated.unread = false;
        updated.references.clear();
        updated.to.push(Address {
            name: Some("Carol".into()),
            address: "carol@example.invalid".into(),
        });
        store
            .update_metadata(mailbox, 1, &updated, Some(4096))
            .await
            .unwrap();

        let stored = store.messages(mailbox).await.unwrap();
        assert_eq!(stored[0].header.subject, "updated");
        assert!(!stored[0].header.unread);
        assert_eq!(stored[0].header.to.len(), 2);
        assert!(stored[0].header.references.is_empty());
        assert_eq!(stored[0].rfc822_size, Some(4096));

        let references_json: String =
            sqlx::query_scalar("SELECT references_json FROM messages WHERE uid = 1")
                .fetch_one(store.pool())
                .await
                .unwrap();
        let references: Vec<String> = serde_json::from_str(&references_json).unwrap();
        assert!(references.is_empty());
    }

    #[tokio::test]
    async fn update_metadata_rejects_unknown_uid() {
        let store = SqliteStateStore::open_in_memory().await.unwrap();
        let (_, mailbox) = account_and_mailbox(&store).await;
        assert!(store
            .update_metadata(mailbox, 42, &header("entries", "missing"), Some(1))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn message_by_uid_returns_one_row_and_none_for_unknown_uids() {
        let store = SqliteStateStore::open_in_memory().await.unwrap();
        let (account, mailbox) = account_and_mailbox(&store).await;
        let other = store
            .upsert_mailbox(account, &folder("other", "Other", FolderKind::Archive), 1)
            .await
            .unwrap();
        assert_eq!(
            store
                .assign_uid(mailbox, &header("entries", "e1"))
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            store
                .assign_uid(other, &header("entries", "e2"))
                .await
                .unwrap(),
            1
        );

        // The lookup is scoped to one mailbox's UID namespace.
        let found = store
            .message_by_uid(mailbox, 1)
            .await
            .unwrap()
            .expect("uid 1 exists in the first mailbox");
        assert_eq!(found.uid, 1);
        assert_eq!(found.header.element_id, "e1");
        assert_eq!(found.mime_structure, None);
        let found = store
            .message_by_uid(other, 1)
            .await
            .unwrap()
            .expect("uid 1 exists in the second mailbox");
        assert_eq!(found.header.element_id, "e2");
        // Unknown uids answer None instead of an error.
        assert!(store.message_by_uid(mailbox, 42).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn set_mime_structure_round_trips_and_rejects_unknown_uids() {
        let store = SqliteStateStore::open_in_memory().await.unwrap();
        let (_, mailbox) = account_and_mailbox(&store).await;
        assert_eq!(
            store
                .assign_uid(mailbox, &header("entries", "e1"))
                .await
                .unwrap(),
            1
        );

        store
            .set_mime_structure(mailbox, 1, "(\"TEXT\" \"PLAIN\")")
            .await
            .unwrap();

        let by_uid = store
            .message_by_uid(mailbox, 1)
            .await
            .unwrap()
            .expect("uid 1 exists");
        assert_eq!(
            by_uid.mime_structure.as_deref(),
            Some("(\"TEXT\" \"PLAIN\")")
        );
        let listed = store.messages(mailbox).await.unwrap();
        assert_eq!(
            listed[0].mime_structure.as_deref(),
            Some("(\"TEXT\" \"PLAIN\")")
        );

        assert!(store.set_mime_structure(mailbox, 42, "x").await.is_err());
    }

    #[tokio::test]
    async fn migrates_an_existing_version_one_database() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.sqlite3");

        // A pre-migration (M4) database: the messages table predates the
        // mime_structure column and user_version is 1.
        {
            let options = SqliteConnectOptions::new()
                .filename(&path)
                .create_if_missing(true)
                .journal_mode(SqliteJournalMode::Wal);
            let pool = pool_options().connect_with(options).await.unwrap();
            for statement in [
                "CREATE TABLE accounts (
                    id INTEGER PRIMARY KEY,
                    mail_address TEXT NOT NULL UNIQUE
                )",
                "CREATE TABLE mailboxes (
                    id INTEGER PRIMARY KEY,
                    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                    list_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    parent_list_id TEXT,
                    uidvalidity INTEGER NOT NULL,
                    next_uid INTEGER NOT NULL,
                    UNIQUE (account_id, list_id)
                )",
                "CREATE TABLE messages (
                    mailbox_id INTEGER NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
                    uid INTEGER NOT NULL,
                    tuta_list_id TEXT NOT NULL,
                    tuta_element_id TEXT NOT NULL,
                    received_at_ms INTEGER NOT NULL,
                    sent_at_ms INTEGER NOT NULL DEFAULT 0,
                    subject TEXT NOT NULL,
                    from_name TEXT,
                    from_address TEXT NOT NULL,
                    recipients_json TEXT,
                    unread INTEGER NOT NULL,
                    message_id TEXT,
                    in_reply_to TEXT,
                    references_json TEXT NOT NULL,
                    rfc822_size INTEGER,
                    envelope_complete INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (mailbox_id, uid),
                    UNIQUE (mailbox_id, tuta_list_id, tuta_element_id)
                )",
                "INSERT INTO accounts (id, mail_address) VALUES (1, 'owner@example.invalid')",
                "INSERT INTO mailboxes (id, account_id, list_id, name, kind, uidvalidity, next_uid)
                 VALUES (1, 1, 'entries', 'Inbox', 'inbox', 100, 2)",
                "INSERT INTO messages (mailbox_id, uid, tuta_list_id, tuta_element_id,
                     received_at_ms, subject, from_address, unread, references_json)
                 VALUES (1, 1, 'mail-list', 'e1', 1700000000000, 'subject',
                     'sender@example.invalid', 1, '[]')",
                "PRAGMA user_version = 1",
            ] {
                sqlx::query(statement).execute(&pool).await.unwrap();
            }
            pool.close().await;
        }

        // Opening migrates: the column is added, the pre-migration row
        // survives with a NULL structure, and the version becomes 2.
        let store = SqliteStateStore::open(&path).await.unwrap();
        let version: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        let stored = store
            .message_by_uid(MailboxId(1), 1)
            .await
            .unwrap()
            .expect("the pre-migration row survived");
        assert_eq!(stored.header.element_id, "e1");
        assert_eq!(stored.header.subject, "subject");
        assert!(!stored.header.envelope_complete);
        assert_eq!(stored.mime_structure, None);

        // Enrichment persists on the migrated database and survives a
        // reopen, which is itself idempotent.
        store
            .set_mime_structure(MailboxId(1), 1, "(\"TEXT\" \"PLAIN\")")
            .await
            .unwrap();
        let store = SqliteStateStore::open(&path).await.unwrap();
        let stored = store
            .message_by_uid(MailboxId(1), 1)
            .await
            .unwrap()
            .expect("row present after reopen");
        assert_eq!(
            stored.mime_structure.as_deref(),
            Some("(\"TEXT\" \"PLAIN\")")
        );
        let version: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
    }

    /// Create a database exactly as the version 2 binary left it: two
    /// mailboxes sharing one UIDVALIDITY, two messages, and a batch
    /// marker.
    async fn version_two_database(path: &std::path::Path) {
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal);
        let pool = pool_options().connect_with(options).await.unwrap();
        for statement in SCHEMA_STATEMENTS {
            sqlx::query(statement).execute(&pool).await.unwrap();
        }
        for statement in [
            "INSERT INTO accounts (id, mail_address) VALUES (1, 'owner@example.invalid')",
            "INSERT INTO mailboxes (id, account_id, list_id, name, kind, uidvalidity, next_uid)
             VALUES (1, 1, 'entries-a', 'Inbox', 'inbox', 100, 8),
                    (2, 1, 'entries-b', 'Work', 'custom', 100, 4)",
            // e1 was enriched by the version 2 binary; e2 never was.
            "INSERT INTO messages (mailbox_id, uid, tuta_list_id, tuta_element_id,
                 received_at_ms, sent_at_ms, subject, from_address, unread, message_id,
                 references_json, rfc822_size, envelope_complete, mime_structure)
             VALUES (1, 7, 'mail-list', 'e1', 1700000000000, 1699999999000, 'first',
                     'sender@example.invalid', 1, '<m1@example.invalid>', '[]', 1234, 1,
                     'structure'),
                    (2, 3, 'mail-list', 'e2', 1700000000001, 0, 'second',
                     'sender@example.invalid', 0, NULL, '[]', NULL, 0, NULL)",
            "INSERT INTO sync_state (account_id, group_id, last_batch_id)
             VALUES (1, 'group1', 'batch-1')",
            "PRAGMA user_version = 2",
        ] {
            sqlx::query(statement).execute(&pool).await.unwrap();
        }
        pool.close().await;
    }

    #[tokio::test]
    async fn migrating_a_version_two_database_keeps_ids_uids_and_uidvalidity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.sqlite3");
        version_two_database(&path).await;

        let store = SqliteStateStore::open(&path).await.unwrap();
        let version: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);

        // Nothing a client can see moved: ids, UIDVALIDITY, UIDNEXT, UIDs.
        let mailboxes = store.mailboxes(1).await.unwrap();
        let seen: Vec<(i64, &str, u32, u32)> = mailboxes
            .iter()
            .map(|mailbox| {
                (
                    mailbox.id.0,
                    mailbox.name.as_str(),
                    mailbox.uidvalidity,
                    mailbox.next_uid,
                )
            })
            .collect();
        assert_eq!(seen, vec![(1, "Inbox", 100, 8), (2, "Work", 100, 4)]);
        let first = store
            .message_by_uid(MailboxId(1), 7)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first.header.element_id, "e1");
        // The enriched row lost exactly its enrichment state, so it is
        // enriched again on its next fetch; its header fields and flag
        // are as stored.
        assert!(!first.header.envelope_complete);
        assert_eq!(first.rfc822_size, None);
        assert_eq!(first.mime_structure, None);
        assert_eq!(first.header.subject, "first");
        assert!(first.header.unread);
        assert_eq!(first.header.sent_at_ms, 1_699_999_999_000);
        assert_eq!(
            first.header.message_id.as_deref(),
            Some("<m1@example.invalid>")
        );
        let second = store
            .message_by_uid(MailboxId(2), 3)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(second.header.element_id, "e2");
        assert_eq!(
            store.last_batch(1, "group1").await.unwrap().as_deref(),
            Some("batch-1")
        );

        // Foreign keys are back on and still point at the rebuilt table.
        let foreign_keys: i64 = sqlx::query_scalar("PRAGMA foreign_keys")
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(foreign_keys, 1);
        sqlx::query("DELETE FROM mailboxes WHERE id = 2")
            .execute(store.pool())
            .await
            .unwrap();
        assert!(store.messages(MailboxId(2)).await.unwrap().is_empty());
        assert_eq!(store.messages(MailboxId(1)).await.unwrap().len(), 1);

        // The deleted mailbox's id is not handed out again.
        let created = store
            .upsert_mailbox(1, &folder("entries-c", "New", FolderKind::Custom), 200)
            .await
            .unwrap();
        assert_eq!(created, MailboxId(3));
    }

    #[tokio::test]
    async fn write_transactions_hold_the_write_lock_from_the_start() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.sqlite3");
        let store = SqliteStateStore::open(&path).await.unwrap();
        let (_account, mailbox) = account_and_mailbox(&store).await;

        // A second connection, as another process would hold one; it
        // gives up at once instead of waiting.
        let options = SqliteConnectOptions::new()
            .filename(&path)
            .busy_timeout(Duration::ZERO);
        let other = pool_options().connect_with(options).await.unwrap();

        // The store's transaction has only read so far...
        let mut transaction = store.begin_write().await.unwrap();
        let next_uid: i64 = sqlx::query_scalar(SELECT_NEXT_UID_SQL)
            .bind(mailbox.0)
            .fetch_one(&mut *transaction)
            .await
            .unwrap();
        assert_eq!(next_uid, 1);

        // ...yet no other connection can commit a write behind its back,
        // which is what used to fail the transaction's own later write.
        let error = sqlx::query(INCREMENT_NEXT_UID_SQL)
            .bind(mailbox.0)
            .execute(&other)
            .await
            .unwrap_err();
        // The lock is reported with its own, transient message.
        match storage_error(error) {
            Error::Storage(message) => assert_eq!(message, STATE_BUSY_MESSAGE),
            _ => panic!("a busy database is a storage error"),
        }

        // The store's write then succeeds on the state it read.
        store
            .assign_uid_in(&mut transaction, mailbox, &header("entries", "e1"))
            .await
            .unwrap();
        transaction.commit().await.unwrap();
        assert_eq!(store.messages(mailbox).await.unwrap()[0].uid, 1);

        // Once it committed, the other connection gets through.
        sqlx::query(INCREMENT_NEXT_UID_SQL)
            .bind(mailbox.0)
            .execute(&other)
            .await
            .unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn exclusive_open_refuses_a_second_writer_until_the_first_is_gone() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.sqlite3");
        let first = SqliteStateStore::open_exclusive(&path).await.unwrap();
        first.upsert_account("owner@example.invalid").await.unwrap();

        // A second writer, as another process would be, is turned away
        // at once with a message that names the commands involved.
        let error = match SqliteStateStore::open_exclusive(&path).await {
            Ok(_) => panic!("a second writer must be refused"),
            Err(error) => error,
        };
        assert!(error.downcast_ref::<StateInUse>().is_some());
        assert!(error.to_string().contains("sync, resync, watch or serve"));

        // The lock file is private like the database itself.
        assert_private_file(&dir.path().join("state.sqlite3.lock"));

        // Dropping the first store releases the lock.
        drop(first);
        let second = SqliteStateStore::open_exclusive(&path).await.unwrap();
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM accounts")
            .fetch_one(second.pool())
            .await
            .unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn mailbox_ids_are_never_reused() {
        let store = SqliteStateStore::open_in_memory().await.unwrap();
        let (account, first) = account_and_mailbox(&store).await;
        let second = store
            .upsert_mailbox(account, &folder("other", "Other", FolderKind::Custom), 100)
            .await
            .unwrap();

        // Removing the newest mailbox must not free its id...
        store.remove_mailbox(account, second).await.unwrap();
        let third = store
            .upsert_mailbox(account, &folder("third", "Third", FolderKind::Custom), 100)
            .await
            .unwrap();
        assert!(third.0 > second.0);

        // ...and neither must a full account reset.
        store.reset_account(account).await.unwrap();
        let after_reset = store
            .upsert_mailbox(account, &folder("entries", "Inbox", FolderKind::Inbox), 100)
            .await
            .unwrap();
        assert!(after_reset.0 > third.0);
        assert_ne!(after_reset, first);
    }

    #[tokio::test]
    async fn reopens_after_an_older_binary_restamped_the_version() {
        // Binaries from before the version gate stamp user_version = 2 on
        // every open. One run of such a build over a migrated database
        // must not leave it unopenable here: every step replays cleanly.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.sqlite3");
        version_two_database(&path).await;
        let store = SqliteStateStore::open(&path).await.unwrap();
        let floor_before: i64 = sqlx::query_scalar("SELECT uidvalidity_floor FROM accounts")
            .fetch_one(store.pool())
            .await
            .unwrap();
        let created = store
            .upsert_mailbox(1, &folder("entries-c", "Later", FolderKind::Custom), 100)
            .await
            .unwrap();
        let created_uidvalidity = store
            .mailboxes(1)
            .await
            .unwrap()
            .into_iter()
            .find(|mailbox| mailbox.id == created)
            .unwrap()
            .uidvalidity;
        assert!(i64::from(created_uidvalidity) > floor_before);

        // The older build: it deletes the mailbox carrying the highest
        // UIDVALIDITY (a resync of its own would) and re-stamps 2.
        sqlx::query("DELETE FROM mailboxes WHERE id = ?")
            .bind(created.0)
            .execute(store.pool())
            .await
            .unwrap();
        sqlx::query("PRAGMA user_version = 2")
            .execute(store.pool())
            .await
            .unwrap();
        store.pool().close().await;
        drop(store);

        let store = SqliteStateStore::open(&path).await.unwrap();
        let version: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);

        // Ids, UIDVALIDITY and UIDs survived the replay, and the mark was
        // not lowered: the deleted mailbox's value is never handed out
        // again.
        let seen: Vec<(i64, u32, u32)> = store
            .mailboxes(1)
            .await
            .unwrap()
            .iter()
            .map(|mailbox| (mailbox.id.0, mailbox.uidvalidity, mailbox.next_uid))
            .collect();
        assert_eq!(seen, vec![(1, 100, 8), (2, 100, 4)]);
        let floor_after: i64 = sqlx::query_scalar("SELECT uidvalidity_floor FROM accounts")
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert!(floor_after >= i64::from(created_uidvalidity));
        let again = store
            .upsert_mailbox(1, &folder("entries-d", "Again", FolderKind::Custom), 100)
            .await
            .unwrap();
        let again_uidvalidity = store
            .mailboxes(1)
            .await
            .unwrap()
            .into_iter()
            .find(|mailbox| mailbox.id == again)
            .unwrap()
            .uidvalidity;
        assert!(again_uidvalidity > created_uidvalidity);
        assert!(again.0 > created.0, "row ids are not reused either");
    }

    #[tokio::test]
    async fn refuses_a_database_newer_than_the_binary() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.sqlite3");
        {
            let store = SqliteStateStore::open(&path).await.unwrap();
            store.upsert_account("owner@example.invalid").await.unwrap();
            sqlx::query(&format!("PRAGMA user_version = {}", SCHEMA_VERSION + 1))
                .execute(store.pool())
                .await
                .unwrap();
            store.pool().close().await;
        }

        // The newer database is refused with the typed error...
        let error = match SqliteStateStore::open(&path).await {
            Ok(_) => panic!("a newer schema must be refused"),
            Err(error) => error,
        };
        let too_new = error
            .downcast_ref::<SchemaTooNew>()
            .expect("the error names the schema versions");
        assert_eq!(too_new.found, SCHEMA_VERSION + 1);
        assert_eq!(too_new.supported, SCHEMA_VERSION);
        assert!(error.to_string().contains("upgrade tuta-bridge"));

        // ...and left untouched: the version is not stamped back down.
        let options = SqliteConnectOptions::new().filename(&path);
        let pool = pool_options().connect_with(options).await.unwrap();
        let version: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION + 1);
        let accounts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM accounts")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(accounts, 1);
    }

    #[tokio::test]
    async fn adopts_an_unversioned_database_without_losing_rows() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.sqlite3");
        // A database that predates version stamping: tables exist, but
        // `user_version` is still 0.
        version_two_database(&path).await;
        {
            let options = SqliteConnectOptions::new().filename(&path);
            let pool = pool_options().connect_with(options).await.unwrap();
            sqlx::query("PRAGMA user_version = 0")
                .execute(&pool)
                .await
                .unwrap();
            pool.close().await;
        }

        let store = SqliteStateStore::open(&path).await.unwrap();
        let version: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        let account = store.upsert_account("owner@example.invalid").await.unwrap();
        let mailboxes = store.mailboxes(account).await.unwrap();
        assert_eq!(mailboxes.len(), 2);
        assert_eq!(mailboxes[0].uidvalidity, 100);
        assert_eq!(mailboxes[0].next_uid, 8);
        assert_eq!(store.messages(mailboxes[0].id).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn messages_table_stores_only_metadata_columns() {
        let store = SqliteStateStore::open_in_memory().await.unwrap();
        let columns: Vec<String> =
            sqlx::query_scalar("SELECT name FROM pragma_table_info('messages') ORDER BY cid")
                .fetch_all(store.pool())
                .await
                .unwrap();
        // The exact v2 column set: header metadata, the size, and the
        // one enrichment column — nothing else.
        let expected: Vec<String> = [
            "mailbox_id",
            "uid",
            "tuta_list_id",
            "tuta_element_id",
            "received_at_ms",
            "sent_at_ms",
            "subject",
            "from_name",
            "from_address",
            "recipients_json",
            "unread",
            "message_id",
            "in_reply_to",
            "references_json",
            "rfc822_size",
            "envelope_complete",
            "mime_structure",
        ]
        .iter()
        .map(|column| column.to_string())
        .collect();
        assert_eq!(columns, expected);
        // The no-content guard: `mime_structure` is the explicit
        // metadata-only allowance, and no column may look like content.
        for column in &columns {
            let lower = column.to_ascii_lowercase();
            for marker in ["body", "attachment", "eml", "blob", "content"] {
                assert!(
                    !lower.contains(marker),
                    "messages.{column} looks like a content column"
                );
            }
        }
    }

    #[tokio::test]
    async fn remove_message_deletes_mapping_but_never_reuses_uid() {
        let store = SqliteStateStore::open_in_memory().await.unwrap();
        let (account, mailbox) = account_and_mailbox(&store).await;
        let h1 = header("entries", "e1");
        let h2 = header("entries", "e2");
        assert_eq!(store.assign_uid(mailbox, &h1).await.unwrap(), 1);
        assert_eq!(store.assign_uid(mailbox, &h2).await.unwrap(), 2);

        store.remove_message(mailbox, 1).await.unwrap();
        store.remove_message(mailbox, 99).await.unwrap();

        let stored = store.messages(mailbox).await.unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].uid, 2);
        assert_eq!(store.mailboxes(account).await.unwrap()[0].next_uid, 3);

        assert_eq!(store.assign_uid(mailbox, &h1).await.unwrap(), 3);
    }

    #[tokio::test]
    async fn mailboxes_roundtrip_explicit_kinds() {
        let store = SqliteStateStore::open_in_memory().await.unwrap();
        let account = store.upsert_account("a@b.c").await.unwrap();
        let inbox = store
            .upsert_mailbox(account, &folder("inbox", "Inbox", FolderKind::Inbox), 1)
            .await
            .unwrap();
        let custom = store
            .upsert_mailbox(
                account,
                &folder("custom", "Projects", FolderKind::Custom),
                2,
            )
            .await
            .unwrap();

        let boxes = store.mailboxes(account).await.unwrap();
        assert_eq!(boxes.len(), 2);
        assert_eq!(boxes[0].id, inbox);
        assert_eq!(boxes[0].kind, FolderKind::Inbox);
        assert_eq!(boxes[1].id, custom);
        assert_eq!(boxes[1].kind, FolderKind::Custom);
    }

    #[tokio::test]
    async fn last_batch_roundtrip_and_upsert() {
        let store = SqliteStateStore::open_in_memory().await.unwrap();
        let account = store.upsert_account("a@b.c").await.unwrap();
        assert_eq!(store.last_batch(account, "group-1").await.unwrap(), None);

        store
            .set_last_batch(account, "group-1", "batch-1")
            .await
            .unwrap();
        assert_eq!(
            store.last_batch(account, "group-1").await.unwrap(),
            Some("batch-1".into())
        );

        store
            .set_last_batch(account, "group-1", "batch-2")
            .await
            .unwrap();
        assert_eq!(
            store.last_batch(account, "group-1").await.unwrap(),
            Some("batch-2".into())
        );
        assert_eq!(store.last_batch(account, "group-2").await.unwrap(), None);
    }

    #[tokio::test]
    async fn reset_clears_mail_and_state_but_keeps_account() {
        let store = SqliteStateStore::open_in_memory().await.unwrap();
        let (account, mailbox) = account_and_mailbox(&store).await;
        store
            .assign_uid(mailbox, &header("entries", "e1"))
            .await
            .unwrap();
        store
            .set_last_batch(account, "group-1", "batch-1")
            .await
            .unwrap();

        let other_account = store.upsert_account("other@example.invalid").await.unwrap();
        let other_mailbox = store
            .upsert_mailbox(
                other_account,
                &folder("entries", "Inbox", FolderKind::Inbox),
                200,
            )
            .await
            .unwrap();
        store
            .assign_uid(other_mailbox, &header("entries", "e9"))
            .await
            .unwrap();

        store.reset_account(account).await.unwrap();

        assert!(store.mailboxes(account).await.unwrap().is_empty());
        assert!(store.messages(mailbox).await.unwrap().is_empty());
        assert_eq!(store.last_batch(account, "group-1").await.unwrap(), None);

        let accounts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM accounts WHERE id = ?")
            .bind(account)
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(accounts, 1);

        assert_eq!(store.mailboxes(other_account).await.unwrap().len(), 1);
        assert_eq!(store.messages(other_mailbox).await.unwrap().len(), 1);
    }

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
        // v2 adds the metadata-only mime_structure column.
        let version: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
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
        // The four schema tables plus SQLite's own `sqlite_sequence`.
        assert_eq!(tables.len(), 5);
        let version: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn wal_and_shm_sidecars_are_private() {
        use std::ffi::OsString;
        use std::path::PathBuf;

        // Regression test: a file-backed store must never leave readable
        // sidecars, including ones SQLite creates lazily after opening.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.sqlite3");
        let store = SqliteStateStore::open(&path).await.unwrap();
        // Force a write so WAL and SHM exist while the connection is open.
        store.upsert_account("owner@example.invalid").await.unwrap();

        for suffix in ["", "-wal", "-shm"] {
            let mut name = OsString::from(path.as_os_str());
            name.push(suffix);
            let candidate = PathBuf::from(name);
            assert!(candidate.exists(), "{} must exist", candidate.display());
            assert_private_file(&candidate);
        }
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
