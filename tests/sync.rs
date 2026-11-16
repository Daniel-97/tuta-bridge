mod support;

use std::sync::Arc;

use tuta_bridge::app::sync::{SyncEngine, SyncReport};
use tuta_bridge::domain::{Address, Folder, FolderKind, MessageHeader};
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

fn uid(store: &support::FakeStateStore, folder: &Folder, element_id: &str) -> u32 {
    let mailbox = store.mailbox_id(ACCOUNT_ID, &folder.list_id);
    store
        .uid_for(mailbox, &folder.list_id, element_id)
        .unwrap_or_else(|| panic!("element {element_id} has no UID"))
}

#[tokio::test]
async fn sync_is_idempotent() {
    let store = Arc::new(support::FakeStateStore::new());
    let engine = SyncEngine::new(store.clone());

    let inbox = folder("inbox-list", "Inbox", FolderKind::Inbox);
    let sent = folder("sent-list", "Sent", FolderKind::Sent);

    let mut source = support::FakeMailSource::new();
    source.folders = vec![inbox.clone(), sent.clone()];
    // Headers arrive newest-first. UIDs follow Tuta element ids, not position.
    source.set_headers(
        &inbox.list_id,
        vec![header(&inbox.list_id, "e2"), header(&inbox.list_id, "e1")],
    );
    source.set_headers(&sent.list_id, vec![header(&sent.list_id, "s1")]);

    let first = engine.sync(ACCOUNT_ID, &source, UIDVALIDITY).await.unwrap();
    assert_eq!(
        first,
        SyncReport {
            folders: 2,
            messages: 3,
        }
    );
    assert_eq!(uid(&store, &inbox, "e2"), 1);
    assert_eq!(uid(&store, &inbox, "e1"), 2);
    assert_eq!(uid(&store, &sent, "s1"), 1);
    let mailboxes = store.mailboxes(ACCOUNT_ID).await.unwrap();
    assert_eq!(mailboxes.len(), 2);
    assert!(mailboxes
        .iter()
        .all(|mailbox| mailbox.uidvalidity == UIDVALIDITY));

    let second = engine.sync(ACCOUNT_ID, &source, UIDVALIDITY).await.unwrap();
    assert_eq!(second, first);
    assert_eq!(uid(&store, &inbox, "e2"), 1);
    assert_eq!(uid(&store, &inbox, "e1"), 2);
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
        vec![header(&inbox.list_id, "e2"), header(&inbox.list_id, "e1")],
    );

    let first = engine.sync(ACCOUNT_ID, &source, UIDVALIDITY).await.unwrap();
    assert_eq!(first.messages, 2);
    assert_eq!(uid(&store, &inbox, "e2"), 1);
    assert_eq!(uid(&store, &inbox, "e1"), 2);

    // A new mail arrives at the top of the newest-first page.
    source.set_headers(
        &inbox.list_id,
        vec![
            header(&inbox.list_id, "e3"),
            header(&inbox.list_id, "e2"),
            header(&inbox.list_id, "e1"),
        ],
    );

    let second = engine.sync(ACCOUNT_ID, &source, UIDVALIDITY).await.unwrap();
    assert_eq!(second.messages, 3);
    assert_eq!(uid(&store, &inbox, "e2"), 1);
    assert_eq!(uid(&store, &inbox, "e1"), 2);
    assert_eq!(uid(&store, &inbox, "e3"), 3);
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
            header(&inbox.list_id, "inbox-second"),
            header(&inbox.list_id, "shared"),
        ],
    );
    engine.sync(ACCOUNT_ID, &source, UIDVALIDITY).await.unwrap();

    assert_eq!(uid(&store, &inbox, "shared"), 1);
    assert_eq!(uid(&store, &inbox, "inbox-second"), 2);
    assert_eq!(uid(&store, &archive, "shared"), 1);
}
