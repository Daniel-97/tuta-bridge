mod support;

use std::sync::Arc;

use tuta_bridge::app::sync::{SyncEngine, SyncReport};
use tuta_bridge::domain::{Address, Error, Folder, FolderKind, MessageHeader};
use tuta_bridge::ports::state_store::StateStore;

const ACCOUNT_ID: i64 = 7;
const UIDVALIDITY: u32 = 1_700_000_000;

fn folder(list_id: &str, name: &str, kind: FolderKind) -> Folder {
    Folder {
        list_id: list_id.to_string(),
        name: name.to_string(),
        kind,
    }
}

fn header(list_id: &str, element_id: &str) -> MessageHeader {
    header_at(list_id, element_id, 1_700_000_000_000)
}

fn header_at(list_id: &str, element_id: &str, received_at_ms: i64) -> MessageHeader {
    MessageHeader {
        list_id: list_id.to_string(),
        element_id: element_id.to_string(),
        received_at_ms,
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

fn uid(store: &support::FakeStateStore, folder: &Folder, element_id: &str) -> u32 {
    let mailbox = store.mailbox_id(ACCOUNT_ID, &folder.list_id);
    store
        .uid_for(mailbox, &folder.list_id, element_id)
        .unwrap_or_else(|| panic!("element {element_id} has no UID"))
}

fn report(folders: usize, messages: usize, removed: usize) -> SyncReport {
    SyncReport {
        folders,
        messages,
        removed,
        skipped_messages: 0,
        skipped_folders: 0,
    }
}

#[tokio::test]
async fn sync_is_idempotent() {
    let store = Arc::new(support::FakeStateStore::new());
    let engine = SyncEngine::new(store.clone());

    let inbox = folder("inbox-list", "Inbox", FolderKind::Inbox);
    let sent = folder("sent-list", "Sent", FolderKind::Sent);

    let mut source = support::FakeMailSource::new();
    source.folders = vec![inbox.clone(), sent.clone()];
    // Headers arrive newest-first. UIDs follow ascending arrival time.
    source.set_headers(
        &inbox.list_id,
        vec![
            header_at(&inbox.list_id, "e2", 1_700_000_002_000),
            header_at(&inbox.list_id, "e1", 1_700_000_001_000),
        ],
    );
    source.set_headers(&sent.list_id, vec![header(&sent.list_id, "s1")]);

    let first = engine.sync(ACCOUNT_ID, &source, UIDVALIDITY).await.unwrap();
    assert_eq!(first, report(2, 3, 0));
    assert_eq!(uid(&store, &inbox, "e1"), 1);
    assert_eq!(uid(&store, &inbox, "e2"), 2);
    // UIDs increase with received time even though the page was newest-first.
    assert!(uid(&store, &inbox, "e1") < uid(&store, &inbox, "e2"));
    assert_eq!(uid(&store, &sent, "s1"), 1);
    let mailboxes = store.mailboxes(ACCOUNT_ID).await.unwrap();
    assert_eq!(mailboxes.len(), 2);
    assert!(mailboxes
        .iter()
        .all(|mailbox| mailbox.uidvalidity == UIDVALIDITY));

    let second = engine.sync(ACCOUNT_ID, &source, UIDVALIDITY).await.unwrap();
    assert_eq!(second, first);
    assert_eq!(uid(&store, &inbox, "e1"), 1);
    assert_eq!(uid(&store, &inbox, "e2"), 2);
    assert_eq!(uid(&store, &sent, "s1"), 1);
}

#[tokio::test]
async fn sync_assigns_new_uid_to_new_mail() {
    let store = Arc::new(support::FakeStateStore::new());
    let engine = SyncEngine::new(store.clone());
    let inbox = folder("inbox-list", "Inbox", FolderKind::Inbox);

    let mut source = support::FakeMailSource::new();
    source.folders = vec![inbox.clone()];
    source.set_headers(
        &inbox.list_id,
        vec![
            header_at(&inbox.list_id, "e2", 1_700_000_002_000),
            header_at(&inbox.list_id, "e1", 1_700_000_001_000),
        ],
    );

    let first = engine.sync(ACCOUNT_ID, &source, UIDVALIDITY).await.unwrap();
    assert_eq!(first, report(1, 2, 0));
    assert_eq!(uid(&store, &inbox, "e1"), 1);
    assert_eq!(uid(&store, &inbox, "e2"), 2);

    // A new mail arrives at the top of the newest-first page.
    source.set_headers(
        &inbox.list_id,
        vec![
            header_at(&inbox.list_id, "e3", 1_700_000_003_000),
            header_at(&inbox.list_id, "e2", 1_700_000_002_000),
            header_at(&inbox.list_id, "e1", 1_700_000_001_000),
        ],
    );

    let second = engine.sync(ACCOUNT_ID, &source, UIDVALIDITY).await.unwrap();
    assert_eq!(second, report(1, 3, 0));
    assert_eq!(uid(&store, &inbox, "e1"), 1);
    assert_eq!(uid(&store, &inbox, "e2"), 2);
    assert_eq!(uid(&store, &inbox, "e3"), 3);
}

#[tokio::test]
async fn sync_orders_uids_by_received_time_then_element_id() {
    let store = Arc::new(support::FakeStateStore::new());
    let engine = SyncEngine::new(store.clone());
    let inbox = folder("inbox-list", "Inbox", FolderKind::Inbox);

    let mut source = support::FakeMailSource::new();
    source.folders = vec![inbox.clone()];
    source.set_headers(
        &inbox.list_id,
        vec![
            header_at(&inbox.list_id, "e3", 1_700_000_003_000),
            header_at(&inbox.list_id, "z", 1_700_000_002_000),
            header_at(&inbox.list_id, "e1", 1_700_000_001_000),
            header_at(&inbox.list_id, "a", 1_700_000_002_000),
        ],
    );

    engine.sync(ACCOUNT_ID, &source, UIDVALIDITY).await.unwrap();
    assert_eq!(uid(&store, &inbox, "e1"), 1);
    assert_eq!(uid(&store, &inbox, "a"), 2);
    assert_eq!(uid(&store, &inbox, "z"), 3);
    assert_eq!(uid(&store, &inbox, "e3"), 4);
}

#[tokio::test]
async fn sync_removes_deleted_mail() {
    let store = Arc::new(support::FakeStateStore::new());
    let engine = SyncEngine::new(store.clone());
    let inbox = folder("inbox-list", "Inbox", FolderKind::Inbox);

    let mut source = support::FakeMailSource::new();
    source.folders = vec![inbox.clone()];
    source.set_headers(
        &inbox.list_id,
        vec![
            header_at(&inbox.list_id, "e2", 1_700_000_002_000),
            header_at(&inbox.list_id, "e1", 1_700_000_001_000),
        ],
    );
    engine.sync(ACCOUNT_ID, &source, UIDVALIDITY).await.unwrap();

    source.set_headers(
        &inbox.list_id,
        vec![header_at(&inbox.list_id, "e1", 1_700_000_001_000)],
    );
    let second = engine.sync(ACCOUNT_ID, &source, UIDVALIDITY).await.unwrap();
    assert_eq!(second, report(1, 1, 1));

    let mailbox = store.mailbox_id(ACCOUNT_ID, &inbox.list_id);
    assert_eq!(store.uid_for(mailbox, &inbox.list_id, "e1"), Some(1));
    assert_eq!(store.uid_for(mailbox, &inbox.list_id, "e2"), None);
    // Removed UIDs are never reused.
    assert_eq!(store.mailboxes(ACCOUNT_ID).await.unwrap()[0].next_uid, 3);
}

#[tokio::test]
async fn sync_removes_mail_moved_out_of_folder() {
    let store = Arc::new(support::FakeStateStore::new());
    let engine = SyncEngine::new(store.clone());
    let inbox = folder("inbox-list", "Inbox", FolderKind::Inbox);
    let archive = folder("archive-list", "Archive", FolderKind::Archive);

    let mut source = support::FakeMailSource::new();
    source.folders = vec![inbox.clone(), archive.clone()];
    source.set_headers(
        &inbox.list_id,
        vec![
            header_at(&inbox.list_id, "e2", 1_700_000_002_000),
            header_at(&inbox.list_id, "e1", 1_700_000_001_000),
        ],
    );
    source.set_headers(&archive.list_id, Vec::new());
    engine.sync(ACCOUNT_ID, &source, UIDVALIDITY).await.unwrap();

    // e2 leaves the inbox and appears in the archive: source removal plus a
    // fresh UID in the destination folder.
    source.set_headers(
        &inbox.list_id,
        vec![header_at(&inbox.list_id, "e1", 1_700_000_001_000)],
    );
    source.set_headers(
        &archive.list_id,
        vec![header_at(&archive.list_id, "e2", 1_700_000_002_000)],
    );
    let second = engine.sync(ACCOUNT_ID, &source, UIDVALIDITY).await.unwrap();
    assert_eq!(second, report(2, 2, 1));

    let inbox_id = store.mailbox_id(ACCOUNT_ID, &inbox.list_id);
    let archive_id = store.mailbox_id(ACCOUNT_ID, &archive.list_id);
    assert_eq!(store.uid_for(inbox_id, &inbox.list_id, "e2"), None);
    assert_eq!(store.uid_for(archive_id, &archive.list_id, "e2"), Some(1));
}

#[tokio::test]
async fn sync_skips_failing_folder_and_continues() {
    let store = Arc::new(support::FakeStateStore::new());
    let engine = SyncEngine::new(store.clone());
    let inbox = folder("inbox-list", "Inbox", FolderKind::Inbox);
    let sent = folder("sent-list", "Sent", FolderKind::Sent);

    let mut source = support::FakeMailSource::new();
    source.folders = vec![inbox.clone(), sent.clone()];
    source.set_headers(&inbox.list_id, vec![header(&inbox.list_id, "e1")]);
    source.fail_headers_in(&sent.list_id);

    let result = engine.sync(ACCOUNT_ID, &source, UIDVALIDITY).await.unwrap();
    assert_eq!(
        result,
        SyncReport {
            folders: 1,
            messages: 1,
            removed: 0,
            skipped_messages: 0,
            skipped_folders: 1,
        }
    );
    assert_eq!(uid(&store, &inbox, "e1"), 1);
}

#[tokio::test]
async fn sync_reports_skipped_messages_without_removing_them() {
    let store = Arc::new(support::FakeStateStore::new());
    let engine = SyncEngine::new(store.clone());
    let inbox = folder("inbox-list", "Inbox", FolderKind::Inbox);

    let mut source = support::FakeMailSource::new();
    source.folders = vec![inbox.clone()];
    source.set_headers(
        &inbox.list_id,
        vec![
            header_at(&inbox.list_id, "e2", 1_700_000_002_000),
            header_at(&inbox.list_id, "e1", 1_700_000_001_000),
        ],
    );
    engine.sync(ACCOUNT_ID, &source, UIDVALIDITY).await.unwrap();

    // The page is incomplete because one mail was unreadable, so the absent
    // mail must not be treated as deleted.
    source.set_headers(
        &inbox.list_id,
        vec![header_at(&inbox.list_id, "e1", 1_700_000_001_000)],
    );
    source.set_skipped(&inbox.list_id, 1);
    let second = engine.sync(ACCOUNT_ID, &source, UIDVALIDITY).await.unwrap();
    assert_eq!(
        second,
        SyncReport {
            folders: 1,
            messages: 1,
            removed: 0,
            skipped_messages: 1,
            skipped_folders: 0,
        }
    );
    let mailbox = store.mailbox_id(ACCOUNT_ID, &inbox.list_id);
    assert_eq!(store.uid_for(mailbox, &inbox.list_id, "e2"), Some(2));
}

#[tokio::test]
async fn sync_fails_when_every_folder_fails() {
    let store = Arc::new(support::FakeStateStore::new());
    let engine = SyncEngine::new(store.clone());
    let inbox = folder("inbox-list", "Inbox", FolderKind::Inbox);

    let mut source = support::FakeMailSource::new();
    source.folders = vec![inbox.clone()];
    source.fail_headers_in(&inbox.list_id);

    match engine.sync(ACCOUNT_ID, &source, UIDVALIDITY).await {
        Err(Error::Network(message)) => assert_eq!(message, "sync failed for all folders"),
        other => panic!("expected fixed all-folders error, got {other:?}"),
    }
}

#[tokio::test]
async fn sync_fails_when_folder_listing_fails() {
    let store = Arc::new(support::FakeStateStore::new());
    let engine = SyncEngine::new(store.clone());

    let mut source = support::FakeMailSource::new();
    source.fail_folders = true;

    match engine.sync(ACCOUNT_ID, &source, UIDVALIDITY).await {
        Err(Error::Network(message)) => assert_eq!(message, "sync failed for all folders"),
        other => panic!("expected fixed all-folders error, got {other:?}"),
    }
}

#[tokio::test]
async fn sync_fetches_headers_only() {
    let store = Arc::new(support::FakeStateStore::new());
    let engine = SyncEngine::new(store.clone());

    let inbox = folder("inbox-list", "Inbox", FolderKind::Inbox);
    let sent = folder("sent-list", "Sent", FolderKind::Sent);

    let mut source = support::FakeMailSource::new();
    source.folders = vec![inbox.clone(), sent.clone()];
    source.set_headers(&inbox.list_id, vec![header(&inbox.list_id, "e1")]);
    source.set_headers(&sent.list_id, vec![header(&sent.list_id, "s1")]);

    engine.sync(ACCOUNT_ID, &source, UIDVALIDITY).await.unwrap();

    let calls = source.calls();
    assert_eq!(
        calls.iter().filter(|call| *call == "headers_page").count(),
        2
    );
    assert!(!calls.iter().any(|call| call == "messages"));
    assert!(!calls.iter().any(|call| call == "content"));
    assert!(source
        .header_limits
        .lock()
        .unwrap()
        .iter()
        .all(|limit| *limit == usize::MAX));
}

#[tokio::test]
async fn mailboxes_have_independent_uid_sequences() {
    let store = Arc::new(support::FakeStateStore::new());
    let engine = SyncEngine::new(store.clone());

    let inbox = folder("inbox-list", "Inbox", FolderKind::Inbox);
    let archive = folder("archive-list", "Archive", FolderKind::Archive);

    let mut source = support::FakeMailSource::new();
    source.folders = vec![inbox.clone(), archive.clone()];
    // The same Tuta element id appears in both mailboxes.
    source.set_headers(&inbox.list_id, vec![header(&inbox.list_id, "shared")]);
    source.set_headers(&archive.list_id, vec![header(&archive.list_id, "shared")]);

    engine.sync(ACCOUNT_ID, &source, UIDVALIDITY).await.unwrap();
    assert_eq!(uid(&store, &inbox, "shared"), 1);
    assert_eq!(uid(&store, &archive, "shared"), 1);

    source.set_headers(
        &inbox.list_id,
        vec![
            header_at(&inbox.list_id, "inbox-second", 1_700_000_002_000),
            header_at(&inbox.list_id, "shared", 1_700_000_001_000),
        ],
    );
    engine.sync(ACCOUNT_ID, &source, UIDVALIDITY).await.unwrap();

    assert_eq!(uid(&store, &inbox, "shared"), 1);
    assert_eq!(uid(&store, &inbox, "inbox-second"), 2);
    assert_eq!(uid(&store, &archive, "shared"), 1);
}
