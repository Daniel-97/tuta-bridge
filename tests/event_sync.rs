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

    let created = store.mailbox_id(account, "folder-list");
    assert_eq!(
        report,
        EventReport {
            changes: 1,
            skipped: 0,
            lookup_failures: 0,
            touched_mailboxes: vec![created],
            counts: report.counts,
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

    let list_a = store.mailbox_id(account, "list-a");
    let list_b = store.mailbox_id(account, "list-b");
    let list_c = store.mailbox_id(account, "list-c");
    assert_eq!(
        report,
        EventReport {
            changes: 1,
            skipped: 0,
            lookup_failures: 0,
            // The upserts touched list-a and list-b first; the removal
            // guard then dropped the stale row in list-c.
            touched_mailboxes: vec![list_a, list_b, list_c],
            counts: report.counts,
        }
    );
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
            skipped: 0,
            lookup_failures: 0,
            // Both mailboxes lost the mail's row.
            touched_mailboxes: vec![
                store.mailbox_id(account, "list-a"),
                store.mailbox_id(account, "list-b")
            ],
            counts: report.counts,
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
            skipped: 1,
            // An unreadable mail (Ok(None)) is not a lookup failure.
            lookup_failures: 0,
            touched_mailboxes: Vec::new(),
            counts: report.counts,
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
            skipped: 0,
            lookup_failures: 0,
            // Both mailboxes lost the mail's row.
            touched_mailboxes: vec![
                store.mailbox_id(account, "list-a"),
                store.mailbox_id(account, "list-b")
            ],
            counts: report.counts,
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
async fn one_failed_lookup_keeps_the_whole_batch_unapplied_until_it_succeeds() {
    let store = Arc::new(FakeStateStore::new());
    let account = account(&store).await;
    filed(&store, account, "list-a", "mail-list", "mail-1").await;
    // Only the first lookup fails; the entry itself is loadable.
    let lookup = FakeEventLookup::new()
        .with_entry_placement(
            "list-a",
            "entry-2",
            placement("list-a", "mail-list", "mail-2"),
        )
        .fail_next(1);
    // A new mail whose lookup fails, next to a delete that needs none.
    let batch = batch(vec![
        event(
            "tutanota",
            MAIL_SET_ENTRY_TYPE_ID,
            "list-a",
            "entry-2",
            EntityOperation::Create,
        ),
        event(
            "tutanota",
            MAIL_TYPE_ID,
            "mail-list",
            "mail-1",
            EntityOperation::Delete,
        ),
    ]);
    let processor = EventProcessor::new(store.clone());
    let mailbox = store.mailbox_id(account, "list-a");

    let failed = processor.apply(account, &lookup, 7, &batch).await.unwrap();
    assert_eq!(
        failed,
        EventReport {
            changes: 0,
            skipped: 2,
            lookup_failures: 1,
            touched_mailboxes: Vec::new(),
            counts: failed.counts,
        }
    );
    // Nothing was written — not even the delete that needed no lookup —
    // and the batch marker did not move past the unresolved event.
    assert!(!store.calls().iter().any(|call| call == "apply_batch"));
    assert_eq!(store.uid_for(mailbox, "mail-list", "mail-1"), Some(1));
    assert!(store.last_batches_for(account).is_empty());

    // The retry of the same batch applies all of it.
    let retried = processor.apply(account, &lookup, 7, &batch).await.unwrap();
    assert_eq!(retried.changes, 2);
    assert_eq!(retried.lookup_failures, 0);
    assert_eq!(store.uid_for(mailbox, "mail-list", "mail-1"), None);
    assert_eq!(store.uid_for(mailbox, "mail-list", "mail-2"), Some(2));
    assert_eq!(
        store
            .last_batches_for(account)
            .get("group-1")
            .map(String::as_str),
        Some("batch-1")
    );
}

#[tokio::test]
async fn every_failed_lookup_is_counted() {
    let store = Arc::new(FakeStateStore::new());
    let account = account(&store).await;
    filed(&store, account, "list-a", "mail-list", "mail-1").await;
    let lookup = FakeEventLookup::new().with_failure();
    // Every lookup-using event kind fails: a mail-set create, a mail
    // update, and an entry create.
    let batch = batch(vec![
        event(
            "tutanota",
            MAIL_SET_TYPE_ID,
            "sets",
            "set-1",
            EntityOperation::Create,
        ),
        event(
            "tutanota",
            MAIL_TYPE_ID,
            "mail-list",
            "mail-1",
            EntityOperation::Update,
        ),
        event(
            "tutanota",
            MAIL_SET_ENTRY_TYPE_ID,
            "list-a",
            "entry-1",
            EntityOperation::Create,
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
            skipped: 3,
            // Every skipped event was skipped because its lookup
            // failed.
            lookup_failures: 3,
            touched_mailboxes: Vec::new(),
            counts: report.counts,
        }
    );
    assert_eq!(
        store.uid_for(store.mailbox_id(account, "list-a"), "mail-list", "mail-1"),
        Some(1)
    );
    // The failed batch left no marker behind.
    assert!(store.last_batches_for(account).is_empty());
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
            skipped: 3,
            // Unknown types, foreign applications, and entry deletes
            // never reach a lookup, so none counts as a failure.
            lookup_failures: 0,
            touched_mailboxes: Vec::new(),
            counts: report.counts,
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
async fn delete_then_entry_create_in_one_batch_removes_the_mail() {
    let store = Arc::new(FakeStateStore::new());
    let account = account(&store).await;
    // The mail is already filed in two folders.
    filed(&store, account, "list-a", "mail-list", "mail-1").await;
    filed(&store, account, "list-b", "mail-list", "mail-1").await;
    let lookup = FakeEventLookup::new().with_entry_placement(
        "list-a",
        "entry-1",
        placement("list-a", "mail-list", "mail-1"),
    );
    // A Mail delete followed by a late MailSetEntry create that files
    // the same mail again: the delete must win.
    let batch = batch(vec![
        event(
            "tutanota",
            MAIL_TYPE_ID,
            "mail-list",
            "mail-1",
            EntityOperation::Delete,
        ),
        event(
            "tutanota",
            MAIL_SET_ENTRY_TYPE_ID,
            "list-a",
            "entry-1",
            EntityOperation::Create,
        ),
    ]);

    let report = EventProcessor::new(store.clone())
        .apply(account, &lookup, 7, &batch)
        .await
        .unwrap();

    // The delete and the entry create each produced an action.
    assert_eq!(report.changes, 2);
    assert_eq!(report.skipped, 0);
    // The mail has no UID left in any mailbox.
    for mailbox in store.mailboxes(account).await.unwrap() {
        assert_eq!(store.uid_for(mailbox.id, "mail-list", "mail-1"), None);
    }
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

    assert_eq!(second.changes, first.changes);
    assert_eq!(second.touched_mailboxes, first.touched_mailboxes);
    // The replay finds the row already there: an update, never a new mail.
    assert_eq!(first.counts.new_mails, 1);
    assert_eq!(second.counts.new_mails, 0);
    assert_eq!(second.counts.updated_mails, 1);
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

#[tokio::test]
async fn report_lists_every_touched_mailbox() {
    let store = Arc::new(FakeStateStore::new());
    let account = account(&store).await;
    store
        .upsert_mailbox(account, &folder("list-a"), 7)
        .await
        .unwrap();
    // The mail is already filed in list-b; the update below keeps only
    // list-a, so list-b's stale row is removed.
    filed(&store, account, "list-b", "mail-list", "mail-1").await;
    let lookup = FakeEventLookup::new().with_mail_placements(
        "mail-list",
        "mail-1",
        Some(vec![placement("list-a", "mail-list", "mail-1")]),
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

    // The upsert touched list-a first, the removal touched list-b.
    assert_eq!(
        report.touched_mailboxes,
        vec![
            store.mailbox_id(account, "list-a"),
            store.mailbox_id(account, "list-b")
        ]
    );
}
