mod support;

use std::sync::Arc;

use tuta_bridge::adapters::imap::render::bodystructure;
use tuta_bridge::app::enrich::EnvelopeEnricher;
use tuta_bridge::domain::{
    Address, Folder, FolderKind, MailboxId, MessageContent, MessageHeader, MessageSummary,
    StoredMessage,
};
use tuta_bridge::ports::state_store::StateStore;

/// A list-level (partial) header: no envelope fields, no message id.
fn partial_header(list_id: &str, element_id: &str) -> MessageHeader {
    MessageHeader {
        list_id: list_id.into(),
        element_id: element_id.into(),
        received_at_ms: 1_700_000_000_000,
        sent_at_ms: 0,
        subject: "list subject".into(),
        from: Address {
            name: None,
            address: "list@example.invalid".into(),
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

/// The summary the enricher must derive from a stored header.
fn stored_summary(header: &MessageHeader) -> MessageSummary {
    MessageSummary {
        list_id: header.list_id.clone(),
        element_id: header.element_id.clone(),
        received_at_ms: header.received_at_ms,
        subject: header.subject.clone(),
        unread: header.unread,
    }
}

/// Fully decrypted content: every envelope field is set.
fn full_content(summary: &MessageSummary) -> MessageContent {
    MessageContent {
        summary: summary.clone(),
        from: Address {
            name: Some("Alice".into()),
            address: "alice@x.y".into(),
        },
        to: vec![Address {
            name: Some("Bob".into()),
            address: "bob@x.y".into(),
        }],
        cc: vec![Address {
            name: None,
            address: "carol@x.y".into(),
        }],
        bcc: vec![Address {
            name: None,
            address: "bcc@x.y".into(),
        }],
        reply_to: vec![Address {
            name: None,
            address: "reply@x.y".into(),
        }],
        sent_at_ms: 1_700_000_000_000,
        subject: "full subject".into(),
        message_id: Some("<m1@x.y>".into()),
        in_reply_to: Some("<parent@x.y>".into()),
        references: vec!["<parent@x.y>".into()],
        body_html: Some("<p>Hello</p>".into()),
        body_text: Some("Hello".into()),
        attachments: Vec::new(),
    }
}

fn inbox() -> Folder {
    Folder {
        list_id: "entries".into(),
        name: "Inbox".into(),
        kind: FolderKind::Inbox,
    }
}

/// Seed one partial message and return its store, mailbox, and UID.
async fn seeded_mailbox() -> (Arc<support::FakeStateStore>, MailboxId, u32) {
    let store = Arc::new(support::FakeStateStore::new());
    let account = store.upsert_account("owner@example.invalid").await.unwrap();
    let mailbox = store.upsert_mailbox(account, &inbox(), 100).await.unwrap();
    let uid = store
        .assign_uid(mailbox, &partial_header("mail-list", "e1"))
        .await
        .unwrap();
    (store, mailbox, uid)
}

fn partial_stored(uid: u32) -> StoredMessage {
    StoredMessage {
        uid,
        header: partial_header("mail-list", "e1"),
        rfc822_size: None,
        mime_structure: None,
    }
}

/// An enricher over the fake store whose renderer emits ten bytes.
fn new_enricher(
    store: &Arc<support::FakeStateStore>,
) -> (EnvelopeEnricher, Arc<support::FakeRenderer>) {
    let renderer = Arc::new(support::FakeRenderer::new(b"0123456789".to_vec()));
    let store = Arc::clone(store);
    let renderer_handle = Arc::clone(&renderer);
    // The struct fields are the trait-object coercion sites.
    let enricher = EnvelopeEnricher {
        store,
        renderer: renderer_handle,
    };
    (enricher, renderer)
}

/// A fake source that serves `full_content` for the stored header.
fn content_source(header: &MessageHeader) -> support::FakeMailSource {
    let mut source = support::FakeMailSource::new();
    source.content = Some(full_content(&stored_summary(header)));
    source
}

#[tokio::test]
async fn enriches_partial_envelopes_once_persisting_only_metadata() {
    let (store, mailbox, uid) = seeded_mailbox().await;
    let stored = partial_stored(uid);
    let source = content_source(&stored.header);
    let (enricher, renderer) = new_enricher(&store);

    let enriched = enricher.enrich(mailbox, &stored, &source).await.unwrap();

    // The envelope is complete and comes from the content.
    assert!(enriched.header.envelope_complete);
    assert_eq!(enriched.header.subject, "full subject");
    assert_eq!(enriched.header.message_id.as_deref(), Some("<m1@x.y>"));
    assert_eq!(enriched.header.in_reply_to.as_deref(), Some("<parent@x.y>"));
    assert_eq!(enriched.header.references, vec!["<parent@x.y>".to_string()]);
    assert_eq!(enriched.header.from.address, "alice@x.y");
    assert_eq!(enriched.header.to.len(), 1);
    assert_eq!(enriched.header.cc.len(), 1);
    assert_eq!(enriched.header.bcc.len(), 1);
    assert_eq!(enriched.header.reply_to.len(), 1);
    assert_eq!(enriched.header.sent_at_ms, 1_700_000_000_000);
    // Placement and list-level fields stay from the stored header.
    assert_eq!(enriched.header.list_id, "mail-list");
    assert_eq!(enriched.header.element_id, "e1");
    assert_eq!(enriched.header.received_at_ms, stored.header.received_at_ms);
    assert!(enriched.header.unread);
    // The size is the rendered byte length.
    assert_eq!(enriched.rfc822_size, Some(10));
    // The structure mirrors the pure renderer for the same content.
    let expected_structure = bodystructure(source.content.as_ref().unwrap());
    assert!(
        enriched
            .mime_structure
            .as_deref()
            .is_some_and(|s| s.contains("TEXT")),
        "structure must describe the text parts"
    );
    assert_eq!(
        enriched.mime_structure.as_deref(),
        Some(expected_structure.as_str())
    );

    // Only metadata was persisted: the complete envelope, the size,
    // and the structure string.
    let persisted = store
        .message_by_uid(mailbox, uid)
        .await
        .unwrap()
        .expect("stored row exists");
    assert!(persisted.header.envelope_complete);
    assert_eq!(persisted.rfc822_size, Some(10));
    assert_eq!(persisted.mime_structure, enriched.mime_structure);

    // The second call must not hit the source or the renderer.
    let again = enricher.enrich(mailbox, &enriched, &source).await.unwrap();
    assert!(again.header.envelope_complete);
    assert_eq!(again.rfc822_size, Some(10));
    assert_eq!(again.mime_structure, enriched.mime_structure);
    assert_eq!(source.content_calls(), 1);
    assert_eq!(renderer.render_calls(), 1);
    // No second persistence round either.
    let update_calls = store
        .calls()
        .iter()
        .filter(|call| call.as_str() == "update_metadata")
        .count();
    assert_eq!(update_calls, 1);
}

#[tokio::test]
async fn skips_enrichment_for_already_complete_messages() {
    let (store, mailbox, uid) = seeded_mailbox().await;
    let mut stored = partial_stored(uid);
    stored.header.envelope_complete = true;
    stored.rfc822_size = Some(4096);
    stored.mime_structure = Some("(\"TEXT\" \"PLAIN\")".into());
    let source = content_source(&stored.header);
    let (enricher, renderer) = new_enricher(&store);

    let again = enricher.enrich(mailbox, &stored, &source).await.unwrap();

    // The input is returned unchanged.
    assert_eq!(again.uid, stored.uid);
    assert_eq!(again.header.subject, stored.header.subject);
    assert_eq!(again.rfc822_size, Some(4096));
    assert_eq!(again.mime_structure, stored.mime_structure);
    // Neither the source nor the store was touched.
    assert_eq!(source.content_calls(), 0);
    assert_eq!(renderer.render_calls(), 0);
    assert!(!store.calls().iter().any(|call| call == "update_metadata"));
    assert!(!store
        .calls()
        .iter()
        .any(|call| call == "set_mime_structure"));
}

#[tokio::test]
async fn re_enriches_when_only_the_structure_is_missing() {
    let (store, mailbox, uid) = seeded_mailbox().await;
    let mut stored = partial_stored(uid);
    stored.header.envelope_complete = true;
    stored.rfc822_size = Some(4096);
    let source = content_source(&stored.header);
    let (enricher, _renderer) = new_enricher(&store);

    let enriched = enricher.enrich(mailbox, &stored, &source).await.unwrap();

    assert_eq!(source.content_calls(), 1);
    assert!(enriched.mime_structure.is_some());
    // A size from an interrupted enrichment is recomputed, not kept.
    assert_eq!(enriched.rfc822_size, Some(10));
    assert_eq!(enriched.header.subject, "full subject");
}

#[tokio::test]
async fn content_failure_leaves_stored_state_untouched() {
    let (store, mailbox, uid) = seeded_mailbox().await;
    let stored = partial_stored(uid);
    let mut source = content_source(&stored.header);
    source.failing_elements = vec!["e1".into()];
    let (enricher, _renderer) = new_enricher(&store);

    assert!(enricher.enrich(mailbox, &stored, &source).await.is_err());

    let persisted = store
        .message_by_uid(mailbox, uid)
        .await
        .unwrap()
        .expect("stored row exists");
    assert!(!persisted.header.envelope_complete);
    assert_eq!(persisted.rfc822_size, None);
    assert_eq!(persisted.mime_structure, None);
    assert!(!store.calls().iter().any(|call| call == "update_metadata"));
}

#[tokio::test]
async fn message_by_uid_scans_one_row_and_set_mime_structure_round_trips() {
    let store = support::FakeStateStore::new();
    let account = store.upsert_account("owner@example.invalid").await.unwrap();
    let first = store.upsert_mailbox(account, &inbox(), 100).await.unwrap();
    let archive = Folder {
        list_id: "archive".into(),
        name: "Archive".into(),
        kind: FolderKind::Archive,
    };
    let second = store.upsert_mailbox(account, &archive, 100).await.unwrap();
    store
        .assign_uid(first, &partial_header("mail-list", "e1"))
        .await
        .unwrap();
    store
        .assign_uid(second, &partial_header("mail-list", "e2"))
        .await
        .unwrap();

    // UID namespaces are per mailbox; each lookup finds exactly one row.
    let found = store
        .message_by_uid(first, 1)
        .await
        .unwrap()
        .expect("uid 1 exists in the first mailbox");
    assert_eq!(found.header.element_id, "e1");
    let found = store
        .message_by_uid(second, 1)
        .await
        .unwrap()
        .expect("uid 1 exists in the second mailbox");
    assert_eq!(found.header.element_id, "e2");
    // Unknown uids answer None.
    assert!(store.message_by_uid(first, 99).await.unwrap().is_none());

    // The structure round-trips through the fake.
    store
        .set_mime_structure(first, 1, "(\"TEXT\" \"PLAIN\")")
        .await
        .unwrap();
    let found = store
        .message_by_uid(first, 1)
        .await
        .unwrap()
        .expect("row still exists");
    assert_eq!(
        found.mime_structure.as_deref(),
        Some("(\"TEXT\" \"PLAIN\")")
    );
    // Unknown uids are a storage error, not a silent no-op.
    assert!(store.set_mime_structure(first, 99, "x").await.is_err());
}
