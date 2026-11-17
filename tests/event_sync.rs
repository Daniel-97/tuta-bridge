mod support;

use std::sync::Arc;

use tuta_bridge::app::event_sync::{EventProcessor, EventReport};
use tuta_bridge::domain::{
    Address, EntityEvent, EntityOperation, EventBatch, Folder, FolderKind, MailPlacement,
    MessageHeader, MAIL_SET_ENTRY_TYPE_ID, MAIL_SET_TYPE_ID, MAIL_TYPE_ID,
};
use tuta_bridge::ports::state_store::StateStore;

use support::{FakeEventLookup, FakeStateStore};

fn folder(list_id: &str) -> Folder {
    Folder {
        list_id: list_id.to_string(),
        name: list_id.to_string(),
        kind: FolderKind::Custom,
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

/// Build a placement: `mailbox_list_id` resolves the mailbox row (the
/// folder's entries list), while the header keeps the Mail's own list id.
fn placement(mailbox_list_id: &str, header_list_id: &str, element_id: &str) -> MailPlacement {
    MailPlacement {
        mailbox_list_id: mailbox_list_id.to_string(),
        header: header(header_list_id, element_id),
    }
}

fn event(
    application: &str,
    type_id: i64,
    list_id: &str,
    element_id: &str,
    operation: EntityOperation,
) -> EntityEvent {
    EntityEvent {
        application: application.to_string(),
        type_id,
        list_id: list_id.to_string(),
        element_id: element_id.to_string(),
        operation,
    }
}

fn batch(events: Vec<EntityEvent>) -> EventBatch {
    EventBatch {
        batch_id: "batch-1".to_string(),
        owner_group_id: "group-1".to_string(),
        application_types_hash: "types-hash".to_string(),
        events,
    }
}

/// Pre-store one placement of `element_id` (in the Mail's own list
/// `mail_list`) inside the folder named by `folder_list`.
async fn filed(
    store: &FakeStateStore,
    account: i64,
    folder_list: &str,
    mail_list: &str,
    element_id: &str,
) -> u32 {
    let mailbox = store
        .upsert_mailbox(account, &folder(folder_list), 7)
        .await
        .unwrap();
    store
        .assign_uid(mailbox, &header(mail_list, element_id))
        .await
        .unwrap()
}

async fn account(store: &FakeStateStore) -> i64 {
    store.upsert_account("owner@example.invalid").await.unwrap()
}

#[tokio::test]
async fn mail_set_entry_create_assigns_a_uid() {
    let store = Arc::new(FakeStateStore::new());
    let account = account(&store).await;
    store
        .upsert_mailbox(account, &folder("list-a"), 7)
        .await
        .unwrap();
    let lookup = FakeEventLookup::new().with_entry_placement(
        "list-a",
        "entry-1",
        placement("list-a", "mail-list", "mail-1"),
    );
    let batch = batch(vec![event(
        "tutanota",
        MAIL_SET_ENTRY_TYPE_ID,
        "list-a",
        "entry-1",
        EntityOperation::Create,
    )]);

    let report = EventProcessor::new(store.clone())
        .apply(account, &lookup, 7, &batch)
        .await
        .unwrap();

    assert_eq!(report.changes, 1);
    let mailbox = store.mailbox_id(account, "list-a");
    assert_eq!(store.uid_for(mailbox, "mail-list", "mail-1"), Some(1));
    assert_eq!(
        store
            .last_batches_for(account)
            .get("group-1")
            .map(String::as_str),
        Some("batch-1")
    );
}

#[tokio::test]
async fn mail_set_create_upserts_a_folder() {
    let store = Arc::new(FakeStateStore::new());
    let account = account(&store).await;
    let set_folder = Folder {
        list_id: "folder-list".to_string(),
        name: "Projects".to_string(),
        kind: FolderKind::Custom,
    };
    let lookup = FakeEventLookup::new().with_folder("sets", "set-1", set_folder);
    let batch = batch(vec![event(
        "tutanota",
        MAIL_SET_TYPE_ID,
        "sets",
        "set-1",
        EntityOperation::Create,
    )]);

    let report = EventProcessor::new(store.clone())
        .apply(account, &lookup, 7, &batch)
        .await
        .unwrap();

    assert_eq!(
        report,
        EventReport {
            changes: 1,
            skipped: 0
        }
    );
    let mailboxes = store.mailboxes(account).await.unwrap();
    assert_eq!(mailboxes.len(), 1);
    assert_eq!(mailboxes[0].list_id, "folder-list");
    assert_eq!(mailboxes[0].name, "Projects");
    assert_eq!(mailboxes[0].uidvalidity, 7);
    assert_eq!(
        store
            .last_batches_for(account)
            .get("group-1")
            .map(String::as_str),
        Some("batch-1")
    );
}

#[tokio::test]
async fn mail_update_adds_every_placement_and_removes_old_ones() {
    let store = Arc::new(FakeStateStore::new());
    let account = account(&store).await;
    // The mail is already filed in three folders.
    for folder_list in ["list-a", "list-b", "list-c"] {
        filed(&store, account, folder_list, "mail-list", "mail-1").await;
    }
    let lookup = FakeEventLookup::new().with_mail_placements(
        "mail-list",
        "mail-1",
        Some(vec![
            placement("list-a", "mail-list", "mail-1"),
            placement("list-b", "mail-list", "mail-1"),
        ]),
    );
    let batch = batch(vec![event(
        "tutanota",
        MAIL_TYPE_ID,
        "mail-list",
        "mail-1",
        EntityOperation::Update,
    )]);

    let report = EventProcessor::new(store.clone())
        .apply(account, &lookup, 7, &batch)
        .await
        .unwrap();

    assert_eq!(
        report,
        EventReport {
            changes: 1,
            skipped: 0
        }
    );
    let list_a = store.mailbox_id(account, "list-a");
    let list_b = store.mailbox_id(account, "list-b");
    let list_c = store.mailbox_id(account, "list-c");
    assert_eq!(store.uid_for(list_a, "mail-list", "mail-1"), Some(1));
    assert_eq!(store.uid_for(list_b, "mail-list", "mail-1"), Some(1));
    assert_eq!(store.uid_for(list_c, "mail-list", "mail-1"), None);
}

#[tokio::test]
async fn mail_update_with_no_placements_removes_the_mail() {
    let store = Arc::new(FakeStateStore::new());
    let account = account(&store).await;
    filed(&store, account, "list-a", "mail-list", "mail-1").await;
    filed(&store, account, "list-b", "mail-list", "mail-1").await;
    let lookup =
        FakeEventLookup::new().with_mail_placements("mail-list", "mail-1", Some(Vec::new()));
    let batch = batch(vec![event(
        "tutanota",
        MAIL_TYPE_ID,
        "mail-list",
        "mail-1",
        EntityOperation::Update,
    )]);

    let report = EventProcessor::new(store.clone())
        .apply(account, &lookup, 7, &batch)
        .await
        .unwrap();

    assert_eq!(
        report,
        EventReport {
            changes: 1,
            skipped: 0
        }
    );
    assert_eq!(
        store.uid_for(store.mailbox_id(account, "list-a"), "mail-list", "mail-1"),
        None
    );
    assert_eq!(
        store.uid_for(store.mailbox_id(account, "list-b"), "mail-list", "mail-1"),
        None
    );
}

#[tokio::test]
async fn unreadable_mail_is_skipped_and_keeps_the_existing_row() {
    let store = Arc::new(FakeStateStore::new());
    let account = account(&store).await;
    filed(&store, account, "list-a", "mail-list", "mail-1").await;
    // `None` marks the mail unreadable: its rows must be kept.
    let lookup = FakeEventLookup::new().with_mail_placements("mail-list", "mail-1", None);
    let batch = batch(vec![event(
        "tutanota",
        MAIL_TYPE_ID,
        "mail-list",
        "mail-1",
        EntityOperation::Update,
    )]);

    let report = EventProcessor::new(store.clone())
        .apply(account, &lookup, 7, &batch)
        .await
        .unwrap();

    assert_eq!(
        report,
        EventReport {
            changes: 0,
            skipped: 1
        }
    );
    assert_eq!(
        store.uid_for(store.mailbox_id(account, "list-a"), "mail-list", "mail-1"),
        Some(1)
    );
    // The batch is persisted even though nothing changed.
    assert_eq!(
        store
            .last_batches_for(account)
            .get("group-1")
            .map(String::as_str),
        Some("batch-1")
    );
}

#[tokio::test]
async fn mail_delete_removes_every_placement() {
    let store = Arc::new(FakeStateStore::new());
    let account = account(&store).await;
    filed(&store, account, "list-a", "mail-list", "mail-1").await;
    filed(&store, account, "list-b", "mail-list", "mail-1").await;
    let lookup = FakeEventLookup::new();
    let batch = batch(vec![event(
        "tutanota",
        MAIL_TYPE_ID,
        "mail-list",
        "mail-1",
        EntityOperation::Delete,
    )]);

    let report = EventProcessor::new(store.clone())
        .apply(account, &lookup, 7, &batch)
        .await
        .unwrap();

    assert_eq!(
        report,
        EventReport {
            changes: 1,
            skipped: 0
        }
    );
    assert_eq!(
        store.uid_for(store.mailbox_id(account, "list-a"), "mail-list", "mail-1"),
        None
    );
    assert_eq!(
        store.uid_for(store.mailbox_id(account, "list-b"), "mail-list", "mail-1"),
        None
    );
    assert_eq!(
        store
            .last_batches_for(account)
            .get("group-1")
            .map(String::as_str),
        Some("batch-1")
    );
}

#[tokio::test]
async fn lookup_failure_is_skipped_and_the_batch_is_still_persisted() {
    let store = Arc::new(FakeStateStore::new());
    let account = account(&store).await;
    filed(&store, account, "list-a", "mail-list", "mail-1").await;
    let lookup = FakeEventLookup::new().with_failure();
    let batch = batch(vec![event(
        "tutanota",
        MAIL_TYPE_ID,
        "mail-list",
        "mail-1",
        EntityOperation::Update,
    )]);

    let report = EventProcessor::new(store.clone())
        .apply(account, &lookup, 7, &batch)
        .await
        .unwrap();

    assert_eq!(
        report,
        EventReport {
            changes: 0,
            skipped: 1
        }
    );
    assert_eq!(
        store.uid_for(store.mailbox_id(account, "list-a"), "mail-list", "mail-1"),
        Some(1)
    );
    assert_eq!(
        store
            .last_batches_for(account)
            .get("group-1")
            .map(String::as_str),
        Some("batch-1")
    );
}

#[tokio::test]
async fn unknown_types_and_entry_deletes_are_skipped_but_persisted() {
    let store = Arc::new(FakeStateStore::new());
    let account = account(&store).await;
    let lookup = FakeEventLookup::new();
    let batch = batch(vec![
        // A type id the bridge does not handle...
        event("tutanota", 999, "list-a", "mail-1", EntityOperation::Create),
        // ...an event from another application...
        event(
            "calendar",
            MAIL_TYPE_ID,
            "list-a",
            "mail-1",
            EntityOperation::Create,
        ),
        // ...and an entry delete, which the accompanying Mail update or a
        // later sync reconciles.
        event(
            "tutanota",
            MAIL_SET_ENTRY_TYPE_ID,
            "list-a",
            "entry-1",
            EntityOperation::Delete,
        ),
    ]);

    let report = EventProcessor::new(store.clone())
        .apply(account, &lookup, 7, &batch)
        .await
        .unwrap();

    assert_eq!(
        report,
        EventReport {
            changes: 0,
            skipped: 3
        }
    );
    assert_eq!(store.mailboxes(account).await.unwrap().len(), 0);
    assert_eq!(
        store
            .last_batches_for(account)
            .get("group-1")
            .map(String::as_str),
        Some("batch-1")
    );
    // The empty change list was still applied exactly once.
    assert_eq!(
        store
            .calls()
            .iter()
            .filter(|call| *call == "apply_batch")
            .count(),
        1
    );
}

#[tokio::test]
async fn duplicate_entry_placement_counts_as_skipped() {
    let store = Arc::new(FakeStateStore::new());
    let account = account(&store).await;
    store
        .upsert_mailbox(account, &folder("list-a"), 7)
        .await
        .unwrap();
    let lookup = FakeEventLookup::new().with_entry_placement(
        "list-a",
        "entry-1",
        placement("list-a", "mail-list", "mail-1"),
    );
    // A create followed by an update for the same entry: both resolve
    // to the same placement, so the update adds nothing new.
    let batch = batch(vec![
        event(
            "tutanota",
            MAIL_SET_ENTRY_TYPE_ID,
            "list-a",
            "entry-1",
            EntityOperation::Create,
        ),
        event(
            "tutanota",
            MAIL_SET_ENTRY_TYPE_ID,
            "list-a",
            "entry-1",
            EntityOperation::Update,
        ),
    ]);

    let report = EventProcessor::new(store.clone())
        .apply(account, &lookup, 7, &batch)
        .await
        .unwrap();

    // Only the create added a placement; the duplicate counts as
    // skipped, so the two events still sum to the batch size.
    assert_eq!(report.changes, 1);
    assert_eq!(report.skipped, 1);
    let mailbox = store.mailbox_id(account, "list-a");
    assert_eq!(store.uid_for(mailbox, "mail-list", "mail-1"), Some(1));
}

#[tokio::test]
async fn reapplying_the_same_batch_does_not_change_uids() {
    let store = Arc::new(FakeStateStore::new());
    let account = account(&store).await;
    store
        .upsert_mailbox(account, &folder("list-a"), 7)
        .await
        .unwrap();
    let lookup = FakeEventLookup::new().with_entry_placement(
        "list-a",
        "entry-1",
        placement("list-a", "mail-list", "mail-1"),
    );
    let batch = batch(vec![event(
        "tutanota",
        MAIL_SET_ENTRY_TYPE_ID,
        "list-a",
        "entry-1",
        EntityOperation::Create,
    )]);
    let processor = EventProcessor::new(store.clone());

    let first = processor.apply(account, &lookup, 7, &batch).await.unwrap();
    let mailbox = store.mailbox_id(account, "list-a");
    assert_eq!(store.uid_for(mailbox, "mail-list", "mail-1"), Some(1));

    let second = processor.apply(account, &lookup, 7, &batch).await.unwrap();

    assert_eq!(second, first);
    assert_eq!(store.uid_for(mailbox, "mail-list", "mail-1"), Some(1));
    // The batch was applied twice; the second run kept the same UID.
    assert_eq!(
        store
            .calls()
            .iter()
            .filter(|call| *call == "apply_batch")
            .count(),
        2
    );
}
