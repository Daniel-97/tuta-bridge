use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::adapters::sqlite_state::{SchemaTooNew, SqliteStateStore};
use crate::app::sync::{SyncEngine, SyncReport};
use crate::config::{state_path, Config};
use crate::domain::{AccountId, Error, Result};
use crate::ports::credentials::CredentialStore;
use crate::ports::mail_source::MailSource;
use crate::ports::session::SessionFactory;
use crate::ports::state_store::StateStore;

/// Wires the active session, credentials, and SQLite state into a sync.
pub struct StateSyncUseCase {
    pub factory: Arc<dyn SessionFactory>,
    pub store: Arc<dyn CredentialStore>,
    pub config_path: PathBuf,
}

impl StateSyncUseCase {
    pub fn new(
        factory: Arc<dyn SessionFactory>,
        store: Arc<dyn CredentialStore>,
        config_path: PathBuf,
    ) -> Self {
        Self {
            factory,
            store,
            config_path,
        }
    }

    /// Sync new and updated headers, keeping existing UIDs.
    pub async fn sync(&self) -> Result<SyncReport> {
        self.run(false).await
    }

    /// Reset all local state for the account, then sync with a new UIDVALIDITY.
    pub async fn resync(&self) -> Result<SyncReport> {
        self.run(true).await
    }

    async fn run(&self, reset: bool) -> Result<SyncReport> {
        // 1. Load the active account and its credentials.
        let config = Config::load(&self.config_path).map_err(|e| Error::Config(e.to_string()))?;
        let account = config.active_account.ok_or(Error::NoActiveAccount)?;
        let credentials = match self.store.load(&AccountId(account))? {
            Some(credentials) => credentials,
            None => return Err(Error::MissingCredentials),
        };

        // 2. Resume the session. It is intentionally not closed here.
        let session = self.factory.resume(&credentials).await?;

        // 3. Open the state database and resolve the account row.
        let state = open_state_store().await?;
        let account_id = state.upsert_account(&credentials.login).await?;
        let uidvalidity = current_uidvalidity();

        // 4. Sync or reset-and-resync.
        if reset {
            resync_with(state, session.mail(), account_id, uidvalidity).await
        } else {
            sync_with(state, session.mail(), account_id, uidvalidity).await
        }
    }
}

/// Open the SQLite state store at the platform data path.
pub async fn open_state_store() -> Result<Arc<dyn StateStore>> {
    let path = state_path().map_err(|e| Error::Config(e.to_string()))?;
    let store = SqliteStateStore::open(&path).await.map_err(open_error)?;
    Ok(Arc::new(store))
}

/// Map a failed open to a fixed message.
///
/// A database written by a newer binary keeps its own explanation, which
/// carries schema version numbers only; every other failure stays opaque.
fn open_error(error: anyhow::Error) -> Error {
    match error.downcast_ref::<SchemaTooNew>() {
        Some(too_new) => Error::Storage(too_new.to_string()),
        None => Error::Storage("failed to open state database".into()),
    }
}

pub(crate) async fn sync_with(
    state: Arc<dyn StateStore>,
    source: &dyn MailSource,
    account_id: i64,
    uidvalidity: u32,
) -> Result<SyncReport> {
    SyncEngine::new(state)
        .sync(account_id, source, uidvalidity)
        .await
}

pub(crate) async fn resync_with(
    state: Arc<dyn StateStore>,
    source: &dyn MailSource,
    account_id: i64,
    now: u32,
) -> Result<SyncReport> {
    // A fresh UIDVALIDITY tells clients to discard their UID mappings. Use the
    // highest stored value so the new one differs from every existing mailbox.
    let previous = state
        .mailboxes(account_id)
        .await?
        .into_iter()
        .map(|mailbox| mailbox.uidvalidity)
        .max();
    let uidvalidity = next_uidvalidity(previous, now)?;

    state.reset_account(account_id).await?;
    SyncEngine::new(state)
        .sync(account_id, source, uidvalidity)
        .await
}

/// Pick a UIDVALIDITY guaranteed to differ from `previous`.
pub(crate) fn next_uidvalidity(previous: Option<u32>, now: u32) -> Result<u32> {
    match previous {
        None => Ok(now),
        Some(previous) if previous >= now => previous
            .checked_add(1)
            .ok_or_else(|| Error::Storage("UIDVALIDITY exhausted".into())),
        Some(_) => Ok(now),
    }
}

/// Seconds since the Unix epoch, clamped to the `u32` UIDVALIDITY range.
pub(crate) fn current_uidvalidity() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u32::try_from(elapsed.as_secs()).unwrap_or(u32::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{
        Address, Folder, FolderKind, MessageContent, MessageHeader, MessagePage, MessageSummary,
    };

    fn folder() -> Folder {
        Folder {
            list_id: "inbox-list".into(),
            name: "Inbox".into(),
            kind: FolderKind::Inbox,
        }
    }

    fn header(element_id: &str) -> MessageHeader {
        MessageHeader {
            list_id: "inbox-list".into(),
            element_id: element_id.into(),
            received_at_ms: 1_700_000_000_000,
            sent_at_ms: 0,
            subject: "subject".into(),
            from: Address {
                name: None,
                address: "sender@example.invalid".into(),
            },
            to: Vec::new(),
            cc: Vec::new(),
            bcc: Vec::new(),
            reply_to: Vec::new(),
            unread: true,
            message_id: None,
            in_reply_to: None,
            references: Vec::new(),
            envelope_complete: false,
        }
    }

    struct FakeSource {
        folders: Vec<Folder>,
        headers: Vec<MessageHeader>,
    }

    #[async_trait::async_trait]
    impl MailSource for FakeSource {
        async fn folders(&self) -> Result<Vec<Folder>> {
            Ok(self.folders.clone())
        }

        async fn messages(&self, _folder: &Folder, _limit: usize) -> Result<Vec<MessageSummary>> {
            Err(Error::Unsupported("not used in tests".into()))
        }

        async fn content(&self, _message: &MessageSummary) -> Result<MessageContent> {
            Err(Error::Unsupported("not used in tests".into()))
        }

        async fn headers_page(
            &self,
            _folder: &Folder,
            _start: Option<&str>,
            _limit: usize,
        ) -> Result<MessagePage> {
            Ok(MessagePage {
                headers: self.headers.clone(),
                next_start: None,
                skipped: 0,
            })
        }
    }

    fn source() -> FakeSource {
        FakeSource {
            folders: vec![folder()],
            headers: vec![header("e2"), header("e1")],
        }
    }

    async fn account(state: &dyn StateStore) -> i64 {
        state.upsert_account("owner@example.invalid").await.unwrap()
    }

    #[test]
    fn next_uidvalidity_uses_now_without_previous() {
        assert_eq!(
            next_uidvalidity(None, 1_700_000_000).unwrap(),
            1_700_000_000
        );
    }

    #[test]
    fn next_uidvalidity_increments_equal_or_greater_previous() {
        assert_eq!(next_uidvalidity(Some(100), 100).unwrap(), 101);
        assert_eq!(next_uidvalidity(Some(101), 100).unwrap(), 102);
    }

    #[test]
    fn next_uidvalidity_uses_a_newer_now() {
        assert_eq!(next_uidvalidity(Some(100), 200).unwrap(), 200);
    }

    #[test]
    fn next_uidvalidity_rejects_exhausted_range() {
        assert!(next_uidvalidity(Some(u32::MAX), u32::MAX).is_err());
    }

    #[tokio::test]
    async fn sync_preserves_existing_uidvalidity() {
        let state: Arc<dyn StateStore> =
            Arc::new(SqliteStateStore::open_in_memory().await.unwrap());
        let account_id = account(&*state).await;
        let source = source();

        let first = sync_with(Arc::clone(&state), &source, account_id, 100)
            .await
            .unwrap();
        assert_eq!(first.folders, 1);
        assert_eq!(first.messages, 2);

        let second = sync_with(Arc::clone(&state), &source, account_id, 200)
            .await
            .unwrap();
        assert_eq!(second, first);

        let mailboxes = state.mailboxes(account_id).await.unwrap();
        assert_eq!(mailboxes.len(), 1);
        assert_eq!(mailboxes[0].uidvalidity, 100);
        assert_eq!(mailboxes[0].next_uid, 3);
    }

    #[tokio::test]
    async fn resync_changes_uidvalidity_and_restarts_uids() {
        let state: Arc<dyn StateStore> =
            Arc::new(SqliteStateStore::open_in_memory().await.unwrap());
        let account_id = account(&*state).await;
        let source = source();

        sync_with(Arc::clone(&state), &source, account_id, 100)
            .await
            .unwrap();
        let report = resync_with(Arc::clone(&state), &source, account_id, 100)
            .await
            .unwrap();
        assert_eq!(report.folders, 1);
        assert_eq!(report.messages, 2);

        let mailboxes = state.mailboxes(account_id).await.unwrap();
        assert_eq!(mailboxes.len(), 1);
        assert_eq!(mailboxes[0].uidvalidity, 101);
        assert_eq!(mailboxes[0].next_uid, 3);

        let uids: Vec<u32> = state
            .messages(mailboxes[0].id)
            .await
            .unwrap()
            .into_iter()
            .map(|message| message.uid)
            .collect();
        assert_eq!(uids, vec![1, 2]);
    }
}
