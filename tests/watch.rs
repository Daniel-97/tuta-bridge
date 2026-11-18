//! Watch use-case tests against a scripted event session.
//!
//! The fake session replays one script per `events()` call and records the
//! batch markers it is handed; no network is involved and the credentials
//! are dummies. Every script ends with a fatal error so the watch loop
//! returns deterministically.

mod support;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tuta_bridge::adapters::tuta::generated_id::{timestamp_to_generated_id, BATCH_EXPIRY_MS};
use tuta_bridge::app::watch::{BackoffPolicy, WatchUseCase};
use tuta_bridge::config::Config;
use tuta_bridge::domain::{
    AccountInfo, Address, EntityEvent, EntityOperation, Error, EventBatch, EventFrame, Folder,
    FolderKind, MailPlacement, MailboxId, MessageHeader, Result, StoredCredentials,
    MAIL_SET_ENTRY_TYPE_ID, MAIL_TYPE_ID, TUTANOTA_APP,
};
use tuta_bridge::ports::clock::Clock;
use tuta_bridge::ports::mailbox_events::MailboxChanged;
use tuta_bridge::ports::session::{NewSession, Session, SessionFactory, SessionRequest};
use tuta_bridge::ports::state_store::StateStore;

use support::{
    FakeEventLookup, FakeEventSession, FakeEventSessionHandle, FakeMailSource, FakeStateStore,
    FakeStore,
};

const LOGIN: &str = "owner@example.invalid";
/// Fixed instant for expiry decisions and resume markers.
const NOW_MS: i64 = 2_000_000_000_000;

/// Resume marker the watch loop stamps for groups without a batch.
fn resume_id() -> String {
    timestamp_to_generated_id((NOW_MS - 5_000).max(0))
}

/// A clock pinned to [`NOW_MS`].
struct FakeClock(i64);

impl Clock for FakeClock {
    fn now_ms(&self) -> i64 {
        self.0
    }
}

/// Hands out handles to one shared scripted session on every resume.
struct FakeEventFactory {
    session: Arc<FakeEventSession>,
}

#[async_trait::async_trait]
impl SessionFactory for FakeEventFactory {
    async fn create(&self, _request: SessionRequest) -> Result<NewSession> {
        Err(Error::Unsupported("watch never creates a session".into()))
    }

    async fn resume(&self, _credentials: &StoredCredentials) -> Result<Box<dyn Session>> {
        Ok(Box::new(FakeEventSessionHandle(Arc::clone(&self.session))))
    }
}

/// Write a temp config with an active account and a loopback base URL.
fn temp_config() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    Config {
        active_account: Some(LOGIN.to_string()),
        base_url: "http://127.0.0.1:9".to_string(),
    }
    .save(&path)
    .unwrap();
    (dir, path)
}

/// Credentials store holding one dummy credential set.
fn fake_credentials() -> Arc<FakeStore> {
    let store = Arc::new(FakeStore::new());
    *store.load_result.lock().unwrap() = Some(StoredCredentials {
        login: LOGIN.to_string(),
        user_id: "u1".to_string(),
        access_token: "token".to_string(),
        encrypted_passphrase_key: vec![1],
    });
    store
}

fn account_info() -> AccountInfo {
    AccountInfo {
        mail_address: LOGIN.to_string(),
        user_id: "u1".to_string(),
    }
}

/// A scripted session subscribed to one group.
fn event_session() -> Arc<FakeEventSession> {
    Arc::new(FakeEventSession::new(
        account_info(),
        vec!["group1".to_string()],
    ))
}

/// Build the use case around a scripted session. The backoff is zero so
/// reconnects in tests are immediate.
fn use_case(
    session: &Arc<FakeEventSession>,
    credentials: Arc<FakeStore>,
    config_path: PathBuf,
    state: Arc<FakeStateStore>,
) -> WatchUseCase {
    WatchUseCase {
        factory: Arc::new(FakeEventFactory {
            session: Arc::clone(session),
        }) as Arc<dyn SessionFactory>,
        credentials: credentials as Arc<dyn tuta_bridge::ports::credentials::CredentialStore>,
        config_path,
        state: state as Arc<dyn StateStore>,
        clock: Arc::new(FakeClock(NOW_MS)),
        backoff: BackoffPolicy {
            first_ms: 0,
            second_ms: 0,
            max_ms: 0,
        },
        connect_timeout: Duration::from_secs(5),
        lookup_failure_threshold: 10,
        notifier: None,
    }
}

async fn account_id(store: &FakeStateStore) -> i64 {
    store.upsert_account(LOGIN).await.unwrap()
}

fn folder(list_id: &str) -> Folder {
    Folder {
        list_id: list_id.to_string(),
        name: list_id.to_string(),
        kind: FolderKind::Inbox,
    }
}

fn header(list_id: &str, element_id: &str) -> MessageHeader {
    MessageHeader {
        list_id: list_id.to_string(),
        element_id: element_id.to_string(),
        received_at_ms: 1_700_000_000_000,
        sent_at_ms: 0,
        subject: "subject".to_string(),
        from: Address {
            name: None,
            address: "sender@example.invalid".to_string(),
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

/// Build a placement: `mailbox_list_id` resolves the mailbox row, while the
/// header keeps the Mail's own list id.
fn placement(mailbox_list_id: &str, header_list_id: &str, element_id: &str) -> MailPlacement {
    MailPlacement {
        mailbox_list_id: mailbox_list_id.to_string(),
        header: header(header_list_id, element_id),
    }
}

/// One mail-set-entry creation inside `list-a`, owned by `group`.
fn entry_batch(batch_id: &str, group: &str, entry_id: &str) -> EventBatch {
    EventBatch {
        batch_id: batch_id.to_string(),
        owner_group_id: group.to_string(),
        application_types_hash: "types-hash".to_string(),
        events: vec![EntityEvent {
            application: TUTANOTA_APP.to_string(),
            type_id: MAIL_SET_ENTRY_TYPE_ID,
            list_id: "list-a".to_string(),
            element_id: entry_id.to_string(),
            operation: EntityOperation::Create,
        }],
    }
}

/// One mail update inside `mail-list`, owned by `group`.
fn mail_update_batch(batch_id: &str, group: &str) -> EventBatch {
    EventBatch {
        batch_id: batch_id.to_string(),
        owner_group_id: group.to_string(),
        application_types_hash: "types-hash".to_string(),
        events: vec![EntityEvent {
            application: TUTANOTA_APP.to_string(),
            type_id: MAIL_TYPE_ID,
            list_id: "mail-list".to_string(),
            element_id: "mail-1".to_string(),
            operation: EntityOperation::Update,
        }],
    }
}

/// A batch without events; applying it still advances the batch marker.
fn empty_batch(batch_id: &str, group: &str) -> EventBatch {
    EventBatch {
        batch_id: batch_id.to_string(),
        owner_group_id: group.to_string(),
        application_types_hash: "types-hash".to_string(),
        events: Vec::new(),
    }
}

/// Pre-store one mailbox and a current marker so no baseline sync runs.
async fn synced_account(state: &FakeStateStore) -> (i64, String) {
    let account = account_id(state).await;
    state
        .upsert_mailbox(account, &folder("list-a"), 100)
        .await
        .unwrap();
    let marker = timestamp_to_generated_id(NOW_MS);
    state
        .set_last_batch(account, "group1", &marker)
        .await
        .unwrap();
    (account, marker)
}

#[tokio::test]
async fn applies_batches_and_persists_the_batch_id() {
    let (_dir, config_path) = temp_config();
    let credentials = fake_credentials();
    let state = Arc::new(FakeStateStore::new());
    let (account, marker) = synced_account(&state).await;

    // The entry event resolves to one placement of mail-1 in list-a.
    let session = Arc::new(
        FakeEventSession::new(account_info(), vec!["group1".to_string()]).with_lookup(Arc::new(
            FakeEventLookup::new().with_entry_placement(
                "list-a",
                "entry-1",
                placement("list-a", "list-a", "mail-1"),
            ),
        )),
    );
    session.push_script(vec![
        Ok(EventFrame::Batch(entry_batch(
            "batch-2", "group1", "entry-1",
        ))),
        Ok(EventFrame::InitialSyncDone),
        Err(Error::Login("stop".into())),
    ]);

    let error = use_case(&session, credentials, config_path, state.clone())
        .run_until(std::future::pending())
        .await
        .unwrap_err();
    assert!(matches!(error, Error::Login(_)));

    // The stream resumed from the stored marker and no baseline sync ran.
    assert_eq!(session.markers_for_call(0).get("group1"), Some(&marker));
    assert!(session.mail.calls().is_empty());

    // The batch was applied and its id became the persisted marker.
    assert_eq!(
        state
            .last_batch(account, "group1")
            .await
            .unwrap()
            .as_deref(),
        Some("batch-2")
    );
    let mailbox = state.mailbox_id(account, "list-a");
    assert_eq!(state.uid_for(mailbox, "list-a", "mail-1"), Some(1));
}

#[tokio::test]
async fn reconnects_from_the_latest_batch() {
    let (_dir, config_path) = temp_config();
    let credentials = fake_credentials();
    let state = Arc::new(FakeStateStore::new());
    let (account, _marker) = synced_account(&state).await;

    // The first connection delivers a batch and drops; the second proves
    // the reconnect resumed from the batch just applied.
    let session = event_session();
    session.push_script(vec![
        Ok(EventFrame::Batch(empty_batch("batch-1", "group1"))),
        Err(Error::Network("drop".into())),
    ]);
    session.push_script(vec![
        Ok(EventFrame::Batch(empty_batch("batch-2", "group1"))),
        Err(Error::Login("stop".into())),
    ]);

    let error = use_case(&session, credentials, config_path, state.clone())
        .run_until(std::future::pending())
        .await
        .unwrap_err();
    assert!(matches!(error, Error::Login(_)));

    assert_eq!(session.events_calls(), 2);
    // The reconnect resumed from the latest applied batch.
    assert_eq!(
        session.markers_for_call(1).get("group1"),
        Some(&"batch-1".to_string())
    );
    // The batch after the reconnect was applied too.
    assert_eq!(
        state
            .last_batch(account, "group1")
            .await
            .unwrap()
            .as_deref(),
        Some("batch-2")
    );
}

#[tokio::test]
async fn expired_marker_triggers_resync_before_events() {
    let (_dir, config_path) = temp_config();
    let credentials = fake_credentials();
    let state = Arc::new(FakeStateStore::new());
    let account = account_id(&state).await;
    state
        .upsert_mailbox(account, &folder("list-a"), 100)
        .await
        .unwrap();
    let old = timestamp_to_generated_id(NOW_MS - BATCH_EXPIRY_MS - 1);
    state.set_last_batch(account, "group1", &old).await.unwrap();

    // The resync replays the mail source: one folder with one header.
    let mut mail = FakeMailSource::new();
    mail.folders = vec![folder("list-a")];
    let session = Arc::new(
        FakeEventSession::new(account_info(), vec!["group1".to_string()]).with_mail(Arc::new(mail)),
    );
    session
        .mail
        .set_headers("list-a", vec![header("list-a", "e1")]);
    session.push_script(vec![
        Ok(EventFrame::Batch(empty_batch("batch-9", "group1"))),
        Err(Error::Login("stop".into())),
    ]);

    let error = use_case(&session, credentials, config_path, state.clone())
        .run_until(std::future::pending())
        .await
        .unwrap_err();
    assert!(matches!(error, Error::Login(_)));

    // The account was reset and resynced exactly once.
    let calls = state.calls();
    assert!(calls.iter().any(|call| call == "reset_account"));
    assert_eq!(
        session
            .mail
            .calls()
            .iter()
            .filter(|call| *call == "headers_page")
            .count(),
        1,
        "the ordinary sync must not run after the resync"
    );

    // The resync assigned a new UIDVALIDITY and filed the source's header.
    let mailboxes = state.mailboxes(account).await.unwrap();
    assert_eq!(mailboxes.len(), 1);
    assert_ne!(mailboxes[0].uidvalidity, 100);
    assert_eq!(state.uid_for(mailboxes[0].id, "list-a", "e1"), Some(1));

    // The expired marker was replaced: the stream resumed from the
    // five-seconds-ago stamp, and the applied batch moved it again.
    assert_eq!(
        session.markers_for_call(0).get("group1"),
        Some(&resume_id())
    );
    assert_eq!(
        state
            .last_batch(account, "group1")
            .await
            .unwrap()
            .as_deref(),
        Some("batch-9")
    );
}

#[tokio::test]
async fn missing_marker_runs_a_baseline_sync() {
    let (_dir, config_path) = temp_config();
    let credentials = fake_credentials();
    let state = Arc::new(FakeStateStore::new());
    let account = account_id(&state).await;
    // A stored mailbox but no batch marker.
    state
        .upsert_mailbox(account, &folder("list-a"), 100)
        .await
        .unwrap();

    let mut mail = FakeMailSource::new();
    mail.folders = vec![folder("list-a")];
    let session = Arc::new(
        FakeEventSession::new(account_info(), vec!["group1".to_string()]).with_mail(Arc::new(mail)),
    );
    session
        .mail
        .set_headers("list-a", vec![header("list-a", "e1")]);
    session.push_script(vec![Err(Error::Login("stop".into()))]);

    let error = use_case(&session, credentials, config_path, state.clone())
        .run_until(std::future::pending())
        .await
        .unwrap_err();
    assert!(matches!(error, Error::Login(_)));

    // The ordinary sync ran (no reset) and filed the source's header; the
    // mailbox kept its UIDVALIDITY.
    let calls = state.calls();
    assert!(!calls.iter().any(|call| call == "reset_account"));
    assert!(session
        .mail
        .calls()
        .iter()
        .any(|call| call == "headers_page"));
    let mailboxes = state.mailboxes(account).await.unwrap();
    assert_eq!(mailboxes.len(), 1);
    assert_eq!(mailboxes[0].uidvalidity, 100);
    assert_eq!(state.uid_for(mailboxes[0].id, "list-a", "e1"), Some(1));

    // The group without a marker got the resume stamp, persisted and
    // passed to the stream.
    assert_eq!(
        state
            .last_batch(account, "group1")
            .await
            .unwrap()
            .as_deref(),
        Some(resume_id().as_str())
    );
    assert_eq!(
        session.markers_for_call(0).get("group1"),
        Some(&resume_id())
    );
}

#[tokio::test]
async fn connect_failure_is_retried_with_backoff() {
    let (_dir, config_path) = temp_config();
    let credentials = fake_credentials();
    let state = Arc::new(FakeStateStore::new());
    let (account, _marker) = synced_account(&state).await;

    // The first connect fails while the network is down; the second
    // connects, delivers one batch, and stops with a fatal error.
    let session = event_session();
    session.push_connect_error(Error::Network("event stream connect failed".into()));
    session.push_script(vec![
        Ok(EventFrame::Batch(empty_batch("batch-4", "group1"))),
        Err(Error::Login("stop".into())),
    ]);

    let error = use_case(&session, credentials, config_path, state.clone())
        .run_until(std::future::pending())
        .await
        .unwrap_err();

    // The failed connect was retried, not treated as fatal.
    assert_eq!(session.events_calls(), 2);
    assert!(matches!(error, Error::Login(_)));
    // The second connection's batch was applied.
    assert_eq!(
        state
            .last_batch(account, "group1")
            .await
            .unwrap()
            .as_deref(),
        Some("batch-4")
    );
}

#[tokio::test]
async fn stop_future_is_honored() {
    let (_dir, config_path) = temp_config();
    let credentials = fake_credentials();
    let state = Arc::new(FakeStateStore::new());
    let _ = synced_account(&state).await;

    // The connection stays silent forever; only the stop future can end
    // the watch loop.
    let session = event_session();
    session.push_pending();

    let result = use_case(&session, credentials, config_path, state.clone())
        .run_until(tokio::time::sleep(Duration::ZERO))
        .await;
    assert!(result.is_ok());

    // The stream was opened once and no batch was applied.
    assert_eq!(session.events_calls(), 1);
    assert!(!state.calls().iter().any(|call| call == "apply_batch"));
}

#[tokio::test]
async fn auth_failure_stops_without_retrying() {
    let (_dir, config_path) = temp_config();
    let credentials = fake_credentials();
    let state = Arc::new(FakeStateStore::new());
    let _ = synced_account(&state).await;

    let session = event_session();
    session.push_script(vec![Err(Error::Login("auth".into()))]);

    let error = use_case(&session, credentials, config_path, state.clone())
        .run_until(std::future::pending())
        .await
        .unwrap_err();
    assert!(matches!(error, Error::Login(_)));

    // Auth errors are fatal: the session is never reconnected.
    assert_eq!(session.events_calls(), 1);
}

#[tokio::test]
async fn consecutive_lookup_failures_resync_once_and_continue() {
    let (_dir, config_path) = temp_config();
    let credentials = fake_credentials();
    let state = Arc::new(FakeStateStore::new());
    let (account, _marker) = synced_account(&state).await;

    // The resync replays the mail source: one folder with one header.
    let mut mail = FakeMailSource::new();
    mail.folders = vec![folder("list-a")];
    let lookup = Arc::new(FakeEventLookup::new().fail_next(2).with_entry_placement(
        "list-a",
        "entry-9",
        placement("list-a", "mail-list", "mail-9"),
    ));
    let session = Arc::new(
        FakeEventSession::new(account_info(), vec!["group1".to_string()])
            .with_mail(Arc::new(mail))
            .with_lookup(lookup),
    );
    session
        .mail
        .set_headers("list-a", vec![header("list-a", "e1")]);
    // Two batches fail their only lookup; the third resolves one entry
    // and the stream ends on a fatal error.
    session.push_script(vec![
        Ok(EventFrame::Batch(mail_update_batch("batch-1", "group1"))),
        Ok(EventFrame::Batch(mail_update_batch("batch-2", "group1"))),
        Ok(EventFrame::Batch(entry_batch(
            "batch-3", "group1", "entry-9",
        ))),
        Err(Error::Login("stop".into())),
    ]);

    let mut watch = use_case(&session, credentials, config_path, state.clone());
    watch.lookup_failure_threshold = 2;

    let error = watch.run_until(std::future::pending()).await.unwrap_err();
    assert!(matches!(error, Error::Login(_)));

    // The valve fired exactly once and the stream was never
    // reconnected.
    let calls = state.calls();
    assert_eq!(
        calls.iter().filter(|call| *call == "reset_account").count(),
        1
    );
    assert_eq!(
        session
            .mail
            .calls()
            .iter()
            .filter(|call| *call == "headers_page")
            .count(),
        1,
        "only the valve resync may fetch headers"
    );
    assert_eq!(session.events_calls(), 1);

    // The resync filed the source's header under a fresh UIDVALIDITY...
    let mailboxes = state.mailboxes(account).await.unwrap();
    assert_eq!(mailboxes.len(), 1);
    assert_ne!(mailboxes[0].uidvalidity, 100);
    assert_eq!(state.uid_for(mailboxes[0].id, "list-a", "e1"), Some(1));

    // ...the good batch applied on top of it, and its id became the
    // persisted marker.
    assert_eq!(
        state.uid_for(mailboxes[0].id, "mail-list", "mail-9"),
        Some(2)
    );
    assert_eq!(
        state
            .last_batch(account, "group1")
            .await
            .unwrap()
            .as_deref(),
        Some("batch-3")
    );
}

#[tokio::test]
async fn connect_timeout_is_retried() {
    let (_dir, config_path) = temp_config();
    let credentials = fake_credentials();
    let state = Arc::new(FakeStateStore::new());
    let (account, marker) = synced_account(&state).await;

    // The first connect hangs forever; the tiny connect timeout must
    // abandon it, and the retry must deliver one batch before the
    // fatal end.
    let session = event_session();
    session.push_hung_connect();
    session.push_script(vec![
        Ok(EventFrame::Batch(empty_batch("batch-6", "group1"))),
        Err(Error::Login("stop".into())),
    ]);

    let mut watch = use_case(&session, credentials, config_path, state.clone());
    watch.connect_timeout = Duration::from_millis(50);

    let error = watch.run_until(std::future::pending()).await.unwrap_err();
    assert!(matches!(error, Error::Login(_)));

    // The hung call was recorded and abandoned; the retry connected and
    // resumed from the stored marker.
    assert_eq!(session.events_calls(), 2);
    assert_eq!(session.markers_for_call(1).get("group1"), Some(&marker));
    // The retried connection applied its batch.
    assert_eq!(
        state
            .last_batch(account, "group1")
            .await
            .unwrap()
            .as_deref(),
        Some("batch-6")
    );
}

#[tokio::test]
async fn batches_notify_every_touched_mailbox() {
    let (_dir, config_path) = temp_config();
    let credentials = fake_credentials();
    let state = Arc::new(FakeStateStore::new());
    let (account, _marker) = synced_account(&state).await;

    // The entry event resolves to one placement of mail-1 in list-a.
    let session = Arc::new(
        FakeEventSession::new(account_info(), vec!["group1".to_string()]).with_lookup(Arc::new(
            FakeEventLookup::new().with_entry_placement(
                "list-a",
                "entry-1",
                placement("list-a", "list-a", "mail-1"),
            ),
        )),
    );
    // One batch touches list-a; the empty batch after it touches nothing.
    session.push_script(vec![
        Ok(EventFrame::Batch(entry_batch(
            "batch-2", "group1", "entry-1",
        ))),
        Ok(EventFrame::Batch(empty_batch("batch-3", "group1"))),
        Ok(EventFrame::InitialSyncDone),
        Err(Error::Login("stop".into())),
    ]);

    let (sender, mut receiver) = tokio::sync::broadcast::channel(4);
    let error = use_case(&session, credentials, config_path, state.clone())
        .with_notifier(sender)
        .run_until(std::future::pending())
        .await
        .unwrap_err();
    assert!(matches!(error, Error::Login(_)));

    // Exactly one notification, for the mailbox the batch touched.
    let mailbox = state.mailbox_id(account, "list-a");
    assert_eq!(receiver.recv().await.unwrap(), MailboxChanged(mailbox));
    assert!(
        receiver.try_recv().is_err(),
        "the empty batch must not notify"
    );
}

#[tokio::test]
async fn closed_notifier_channel_is_ignored() {
    let (_dir, config_path) = temp_config();
    let credentials = fake_credentials();
    let state = Arc::new(FakeStateStore::new());
    let (account, _marker) = synced_account(&state).await;

    let session = Arc::new(
        FakeEventSession::new(account_info(), vec!["group1".to_string()]).with_lookup(Arc::new(
            FakeEventLookup::new().with_entry_placement(
                "list-a",
                "entry-1",
                placement("list-a", "list-a", "mail-1"),
            ),
        )),
    );
    session.push_script(vec![
        Ok(EventFrame::Batch(entry_batch(
            "batch-2", "group1", "entry-1",
        ))),
        Err(Error::Login("stop".into())),
    ]);

    // No receiver: every send fails, and the loop must keep running.
    let (sender, receiver) = tokio::sync::broadcast::channel(4);
    drop(receiver);

    let error = use_case(&session, credentials, config_path, state.clone())
        .with_notifier(sender)
        .run_until(std::future::pending())
        .await
        .unwrap_err();
    assert!(matches!(error, Error::Login(_)));

    // The batch was applied despite the failed notifications.
    let mailbox = state.mailbox_id(account, "list-a");
    assert_eq!(state.uid_for(mailbox, "list-a", "mail-1"), Some(1));
}

#[tokio::test]
async fn resync_notifies_every_current_mailbox() {
    let (_dir, config_path) = temp_config();
    let credentials = fake_credentials();
    let state = Arc::new(FakeStateStore::new());
    let account = account_id(&state).await;
    state
        .upsert_mailbox(account, &folder("list-a"), 100)
        .await
        .unwrap();
    let old = timestamp_to_generated_id(NOW_MS - BATCH_EXPIRY_MS - 1);
    state.set_last_batch(account, "group1", &old).await.unwrap();

    // The resync rebuilds two mailboxes; both must be announced.
    let mut mail = FakeMailSource::new();
    mail.folders = vec![folder("list-a"), folder("list-b")];
    let session = Arc::new(
        FakeEventSession::new(account_info(), vec!["group1".to_string()]).with_mail(Arc::new(mail)),
    );
    session
        .mail
        .set_headers("list-a", vec![header("list-a", "e1")]);
    session
        .mail
        .set_headers("list-b", vec![header("list-b", "e2")]);
    session.push_script(vec![
        Ok(EventFrame::Batch(empty_batch("batch-9", "group1"))),
        Err(Error::Login("stop".into())),
    ]);

    let (sender, mut receiver) = tokio::sync::broadcast::channel(8);
    let error = use_case(&session, credentials, config_path, state.clone())
        .with_notifier(sender)
        .run_until(std::future::pending())
        .await
        .unwrap_err();
    assert!(matches!(error, Error::Login(_)));

    // The rebuild announced every current mailbox, in id order; the
    // empty batch after it added nothing.
    let mut notified = Vec::new();
    while let Ok(changed) = receiver.try_recv() {
        notified.push(changed.0);
    }
    let current: Vec<MailboxId> = state
        .mailboxes(account)
        .await
        .unwrap()
        .into_iter()
        .map(|mailbox| mailbox.id)
        .collect();
    assert_eq!(notified, current);
}
