use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context;
use serde::{Deserialize, Serialize};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteRow};
use sqlx::{Row, Sqlite, SqlitePool};

use crate::domain::{
    Address, Error, Folder, FolderKind, MailboxId, MessageHeader, Result, StoredMailbox,
    StoredMessage,
};
use crate::ports::StateStore;

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
        let store = Self { pool };
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

const UPSERT_ACCOUNT_SQL: &str = "\
INSERT INTO accounts (mail_address) VALUES (?)
ON CONFLICT(mail_address) DO NOTHING";

const SELECT_ACCOUNT_ID_SQL: &str = "SELECT id FROM accounts WHERE mail_address = ?";

const INSERT_MAILBOX_SQL: &str = "\
INSERT INTO mailboxes (account_id, list_id, name, kind, uidvalidity, next_uid)
VALUES (?, ?, ?, ?, ?, 1)
ON CONFLICT(account_id, list_id) DO NOTHING";

const SELECT_MAILBOX_SQL: &str = "\
SELECT id, account_id, list_id, name, kind, uidvalidity, next_uid
FROM mailboxes WHERE account_id = ? AND list_id = ?";

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
       references_json, rfc822_size, envelope_complete
FROM messages WHERE mailbox_id = ? ORDER BY uid";

const SELECT_LAST_BATCH_SQL: &str =
    "SELECT last_batch_id FROM sync_state WHERE account_id = ? AND group_id = ?";

const UPSERT_LAST_BATCH_SQL: &str = "\
INSERT INTO sync_state (account_id, group_id, last_batch_id) VALUES (?, ?, ?)
ON CONFLICT(account_id, group_id) DO UPDATE SET last_batch_id = excluded.last_batch_id";

const DELETE_ACCOUNT_MESSAGES_SQL: &str = "\
DELETE FROM messages WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE account_id = ?)";

const DELETE_ACCOUNT_MAILBOXES_SQL: &str = "DELETE FROM mailboxes WHERE account_id = ?";

const DELETE_ACCOUNT_SYNC_STATE_SQL: &str = "DELETE FROM sync_state WHERE account_id = ?";

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

fn storage_error(_error: sqlx::Error) -> Error {
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
        sqlx::query(INSERT_MAILBOX_SQL)
            .bind(account_id)
            .bind(&folder.list_id)
            .bind(&folder.name)
            .bind(folder.kind.as_db_str())
            .bind(i64::from(uidvalidity))
            .execute(&self.pool)
            .await
            .map_err(storage_error)?;

        let row = sqlx::query(SELECT_MAILBOX_SQL)
            .bind(account_id)
            .bind(&folder.list_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_error)?
            .ok_or_else(|| Error::Storage("mailbox missing after upsert".into()))?;
        Ok(stored_mailbox_from_row(&row)?.id)
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
        let mut transaction = self.pool.begin().await.map_err(storage_error)?;

        let existing: Option<i64> = sqlx::query_scalar(SELECT_UID_BY_ELEMENT_SQL)
            .bind(mailbox.0)
            .bind(&header.list_id)
            .bind(&header.element_id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(storage_error)?;

        let uid = match existing {
            Some(uid) => {
                let uid = u32_from_i64(uid)?;
                if header.envelope_complete {
                    write_message_metadata(&mut *transaction, mailbox, uid, header, None).await?;
                } else {
                    write_partial_metadata(&mut *transaction, mailbox, uid, header).await?;
                }
                uid
            }
            None => {
                let next_uid: Option<i64> = sqlx::query_scalar(SELECT_NEXT_UID_SQL)
                    .bind(mailbox.0)
                    .fetch_optional(&mut *transaction)
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
                    .execute(&mut *transaction)
                    .await
                    .map_err(storage_error)?;

                sqlx::query(INCREMENT_NEXT_UID_SQL)
                    .bind(mailbox.0)
                    .execute(&mut *transaction)
                    .await
                    .map_err(storage_error)?;

                uid
            }
        };

        transaction.commit().await.map_err(storage_error)?;
        Ok(uid)
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

    async fn remove_message(&self, mailbox: MailboxId, uid: u32) -> Result<()> {
        sqlx::query("DELETE FROM messages WHERE mailbox_id = ? AND uid = ?")
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

        rows.iter()
            .map(|row| {
                let recipients_json: Option<String> =
                    row.try_get("recipients_json").map_err(storage_error)?;
                let recipients = match recipients_json {
                    Some(json) => serde_json::from_str::<RecipientsJson>(&json)
                        .map_err(|_| metadata_error())?,
                    None => RecipientsJson::default(),
                };
                let references_json: String =
                    row.try_get("references_json").map_err(storage_error)?;
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
                })
            })
            .collect()
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
        let mut transaction = self.pool.begin().await.map_err(storage_error)?;
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
    async fn upsert_mailbox_preserves_existing_uid_state() {
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
                &folder("entries", "Renamed", FolderKind::Archive),
                999,
            )
            .await
            .unwrap();
        assert_eq!(again, mailbox);

        let boxes = store.mailboxes(account).await.unwrap();
        assert_eq!(boxes.len(), 1);
        assert_eq!(boxes[0].id, mailbox);
        assert_eq!(boxes[0].name, "Inbox");
        assert_eq!(boxes[0].kind, FolderKind::Inbox);
        assert_eq!(boxes[0].uidvalidity, 100);
        assert_eq!(boxes[0].next_uid, 2);
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
