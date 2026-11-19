//! Integration contract for the read-only IMAP backend.
//!
//! Every test drives `TutaImapBackend` through the `ImapBackend` port with
//! the in-memory fakes and the real `MimeRenderer`, pinning the network
//! discipline (which fetches may load content at all), the persistence
//! rules (metadata only, PEEK never persists), and the SEARCH key subset.

mod support;

use std::sync::Arc;
use std::sync::Mutex;

use secrecy::{ExposeSecret, SecretString};
use tuta_bridge::adapters::imap::backend::TutaImapBackend;
use tuta_bridge::adapters::imap::codec::{self, ImapArg};
use tuta_bridge::adapters::imap::render::bodystructure;
use tuta_bridge::adapters::imap::search::parse_search;
use tuta_bridge::adapters::mime::MimeRenderer;
use tuta_bridge::app::enrich::EnvelopeEnricher;
use tuta_bridge::domain::{
    Address, Error, Folder, FolderKind, MailboxId, MessageContent, MessageHeader, MessageSummary,
    Result,
};
use tuta_bridge::ports::imap_backend::ImapBackend;
use tuta_bridge::ports::local_password::LocalPasswordStore;
use tuta_bridge::ports::renderer::MessageRenderer;
use tuta_bridge::ports::state_store::StateStore;

// ---------------------------------------------------------------------------
// Fakes and fixtures
// ---------------------------------------------------------------------------

/// In-memory local password store: the bridge password in a mutex.
struct FakePasswordStore {
    stored: Mutex<Option<String>>,
}

impl FakePasswordStore {
    fn with(password: &str) -> Self {
        Self {
            stored: Mutex::new(Some(password.to_string())),
        }
    }

    fn empty() -> Self {
        Self {
            stored: Mutex::new(None),
        }
    }
}

#[async_trait::async_trait]
impl LocalPasswordStore for FakePasswordStore {
    async fn set(&self, password: &SecretString) -> Result<()> {
        *self.stored.lock().unwrap() = Some(password.expose_secret().to_string());
        Ok(())
    }

    async fn load(&self) -> Result<Option<SecretString>> {
        Ok(self
            .stored
            .lock()
            .unwrap()
            .clone()
            .map(|password| SecretString::new(password.into())))
    }
}

/// A list-level (partial) header as the sync stores it: no envelope fields.
fn partial_header(
    element_id: &str,
    subject: &str,
    received_at_ms: i64,
    unread: bool,
) -> MessageHeader {
    MessageHeader {
        list_id: "mail-list".into(),
        element_id: element_id.into(),
        received_at_ms,
        sent_at_ms: 0,
        subject: subject.into(),
        from: Address {
            name: None,
            address: "list@example.invalid".into(),
        },
        to: Vec::new(),
        cc: Vec::new(),
        bcc: Vec::new(),
        reply_to: Vec::new(),
        unread,
        message_id: None,
        in_reply_to: None,
        references: Vec::new(),
        envelope_complete: false,
    }
}

/// Fully decrypted content: every envelope field is set, so enrichment
/// completes partial headers and the renderer produces stable bytes.
fn full_content() -> MessageContent {
    MessageContent {
        summary: MessageSummary {
            list_id: "mail-list".into(),
            element_id: "e1".into(),
            received_at_ms: 1_700_000_000_000,
            subject: "full subject".into(),
            unread: true,
        },
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
        bcc: Vec::new(),
        reply_to: Vec::new(),
        sent_at_ms: 1_700_000_000_000,
        subject: "full subject".into(),
        message_id: Some("<m1@x.y>".into()),
        in_reply_to: None,
        references: Vec::new(),
        body_html: Some("<p>Hello</p>".into()),
        body_text: Some("Hello".into()),
        attachments: Vec::new(),
    }
}

fn inbox_folder() -> Folder {
    Folder {
        list_id: "entries".into(),
        name: "Inbox".into(),
        kind: FolderKind::Inbox,
    }
}

/// One fully wired backend over the fakes: the real `MimeRenderer` for
/// both the backend and the enricher, a fake source serving `full_content`
/// for every message, and the fake state store seeded with an Inbox.
struct TestWorld {
    backend: TutaImapBackend,
    store: Arc<support::FakeStateStore>,
    source: Arc<support::FakeMailSource>,
    account: i64,
    inbox: MailboxId,
}

async fn world_with(passwords: Arc<dyn LocalPasswordStore>) -> TestWorld {
    let store = Arc::new(support::FakeStateStore::new());
    let account = store.upsert_account("owner@example.invalid").await.unwrap();
    let inbox = store
        .upsert_mailbox(account, &inbox_folder(), 100)
        .await
        .unwrap();
    let mut fake_source = support::FakeMailSource::new();
    fake_source.content = Some(full_content());
    let source = Arc::new(fake_source);
    // Hoisted clones: without an expected type at the call site,
    // `Arc::clone` infers the concrete fake and the struct literal fields
    // coerce to the port objects.
    let backend_store = Arc::clone(&store);
    let enricher_store = Arc::clone(&store);
    let backend_source = Arc::clone(&source);
    let backend = TutaImapBackend {
        account_id: account,
        expected_user: "owner@example.invalid".into(),
        passwords,
        store: backend_store,
        enricher: Arc::new(EnvelopeEnricher {
            store: enricher_store,
            renderer: Arc::new(MimeRenderer),
        }),
        source: backend_source,
        renderer: Arc::new(MimeRenderer),
    };
    TestWorld {
        backend,
        store,
        source,
        account,
        inbox,
    }
}

async fn world() -> TestWorld {
    world_with(Arc::new(FakePasswordStore::with("bridge-password"))).await
}

/// Run `a SEARCH <raw>` over `backend`, tokenized like the session
/// tokenizes it, with every stored message in view.
async fn search_line(backend: &TutaImapBackend, mailbox: MailboxId, raw: &str) -> Vec<u32> {
    let request = codec::parse_line(&format!("a SEARCH {raw}"))
        .unwrap_or_else(|_| panic!("search line must tokenize"));
    let keys = parse_search(&request.args).unwrap_or_else(|_| panic!("criteria must parse"));
    let view: Vec<u32> = backend
        .store
        .message_uids(mailbox)
        .await
        .unwrap()
        .into_iter()
        .map(|(uid, _)| uid)
        .collect();
    backend.search(mailbox, &keys, &view).await.unwrap()
}

/// Run one SEARCH over `backend` with `&str` criteria for brevity.
/// The FETCH items of `raw`, parsed the way the session parses them:
/// tokenized as a command first.
fn parse_fetch_items(raw: &str) -> Result<Vec<codec::FetchItem>> {
    let request = codec::parse_line(&format!("a FETCH 1 {raw}"))?;
    codec::parse_fetch_items(&request.args[1..])
}

async fn search(backend: &TutaImapBackend, mailbox: MailboxId, criteria: &[&str]) -> Vec<u32> {
    let args: Vec<ImapArg> = criteria
        .iter()
        .map(|token| ImapArg::Atom(token.to_string()))
        .collect();
    let keys = parse_search(&args).unwrap_or_else(|_| panic!("criteria must parse"));
    // The session's view: every stored uid, in order.
    let view: Vec<u32> = backend
        .store
        .message_uids(mailbox)
        .await
        .unwrap()
        .into_iter()
        .map(|(uid, _)| uid)
        .collect();
    backend.search(mailbox, &keys, &view).await.unwrap()
}

// ---------------------------------------------------------------------------
// LOGIN
// ---------------------------------------------------------------------------

#[tokio::test]
async fn login_is_case_insensitive_inbox_and_constant_time() {
    let world = world().await;
    let good = SecretString::new("bridge-password".into());
    let wrong = SecretString::new("wrong-password".into());

    // Wrong user, wrong password, then the right pair.
    assert!(!world.backend.login("other@x.y", &good).await.unwrap());
    assert!(!world
        .backend
        .login("owner@example.invalid", &wrong)
        .await
        .unwrap());
    assert!(world
        .backend
        .login("owner@example.invalid", &good)
        .await
        .unwrap());

    // The user name compares ASCII-case-insensitively: a client that
    // types the address in different casing than the stored one still
    // logs in, while the password stays exact.
    assert!(world
        .backend
        .login("OWNER@Example.Invalid", &good)
        .await
        .unwrap());
    assert!(!world
        .backend
        .login(
            "owner@example.invalid",
            &SecretString::new("Bridge-Password".into())
        )
        .await
        .unwrap());

    // A missing stored password is a plain mismatch, never an error.
    let empty = world_with(Arc::new(FakePasswordStore::empty())).await;
    assert!(!empty
        .backend
        .login("owner@example.invalid", &good)
        .await
        .unwrap());

    // The lowercase INBOX alias resolves the Inbox mailbox.
    let selected = world
        .backend
        .select("inbox")
        .await
        .unwrap()
        .expect("inbox resolves case-insensitively");
    assert_eq!(selected.view.name, "Inbox");
}

// ---------------------------------------------------------------------------
// LIST / SELECT
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mailboxes_list_special_use() {
    let world = world().await;
    let sent = Folder {
        list_id: "sent".into(),
        name: "Sent".into(),
        kind: FolderKind::Sent,
    };
    let archive = Folder {
        list_id: "archive".into(),
        name: "Archive".into(),
        kind: FolderKind::Archive,
    };
    let custom = Folder {
        list_id: "projects".into(),
        name: "Projects".into(),
        kind: FolderKind::Custom,
    };
    world
        .store
        .upsert_mailbox(world.account, &sent, 200)
        .await
        .unwrap();
    world
        .store
        .upsert_mailbox(world.account, &archive, 300)
        .await
        .unwrap();
    world
        .store
        .upsert_mailbox(world.account, &custom, 400)
        .await
        .unwrap();

    // Kinds map to special-use flags; INBOX and custom carry none.
    let views = world.backend.mailboxes().await.unwrap();
    let by_name = |name: &str| {
        views
            .iter()
            .find(|view| view.name == name)
            .expect("every seeded mailbox is listed")
    };
    assert_eq!(by_name("Inbox").special_use, "");
    assert_eq!(by_name("Sent").special_use, "\\Sent");
    assert_eq!(by_name("Archive").special_use, "\\Archive");
    assert_eq!(by_name("Projects").special_use, "");

    // Two messages: one unread, one read.
    world
        .store
        .assign_uid(
            world.inbox,
            &partial_header("e1", "one", 1_700_000_000_000, true),
        )
        .await
        .unwrap();
    world
        .store
        .assign_uid(
            world.inbox,
            &partial_header("e2", "two", 1_700_000_000_000, false),
        )
        .await
        .unwrap();

    // `select("inbox")` (lowercase) resolves the Inbox with the counts
    // and identity straight from the store.
    let selected = world
        .backend
        .select("inbox")
        .await
        .unwrap()
        .expect("lowercase inbox resolves");
    assert_eq!(selected.view.id, world.inbox);
    assert_eq!(selected.messages.len(), 2);
    assert_eq!(selected.unseen(), 1);
    assert_eq!(selected.uidnext, 3);
    assert_eq!(selected.uidvalidity, 100);

    // Other names match exactly; casing only relaxes for INBOX.
    assert!(world.backend.select("INBOX").await.unwrap().is_some());
    assert!(world.backend.select("Projects").await.unwrap().is_some());
    assert!(world.backend.select("projects").await.unwrap().is_none());
    assert!(world.backend.select("Missing").await.unwrap().is_none());
}

// ---------------------------------------------------------------------------
// FETCH
// ---------------------------------------------------------------------------

#[tokio::test]
async fn fetch_serves_envelopes_from_the_index_and_enriches_structure_once() {
    let world = world().await;
    let uid_one = world
        .store
        .assign_uid(
            world.inbox,
            &partial_header("e1", "list subject", 1_700_000_000_000, true),
        )
        .await
        .unwrap();
    let uid_two = world
        .store
        .assign_uid(
            world.inbox,
            &partial_header("e2", "list subject", 1_700_000_000_000, true),
        )
        .await
        .unwrap();
    assert_eq!((uid_one, uid_two), (1, 2));

    let content = world.source.content.clone().unwrap();
    let expected_bytes = MimeRenderer.render(&content).unwrap();
    let expected_structure = bodystructure(&content, &expected_bytes);

    // ENVELOPE serves from the stored (partial) header: no source call,
    // unknown fields stay NIL until enrichment.
    let items = parse_fetch_items("(ENVELOPE UID FLAGS INTERNALDATE)").unwrap();
    let response = world
        .backend
        .fetch(world.inbox, uid_one, &items)
        .await
        .unwrap()
        .expect("row exists");
    assert_eq!(world.source.content_calls(), 0);
    assert_eq!(response.uid, uid_one);
    assert_eq!(response.flags, "");
    assert_eq!(response.internal_date, "\"14-Nov-2023 22:13:20 +0000\"");
    let envelope = response.envelope.expect("envelope requested");
    assert!(envelope.contains("\"list subject\""));
    // The partial header renders a NIL to/cc/bcc/in-reply-to/message-id
    // tail.
    assert!(envelope.ends_with(" NIL NIL NIL NIL NIL)"));
    assert_eq!(response.bodystructure, None);
    assert_eq!(response.rfc822_size, None);
    assert!(response.bodies.is_empty());

    // BODYSTRUCTURE enriches once: one content load, the persisted
    // structure is returned, and the row gains the complete envelope.
    let items = parse_fetch_items("(BODYSTRUCTURE)").unwrap();
    let response = world
        .backend
        .fetch(world.inbox, uid_one, &items)
        .await
        .unwrap()
        .expect("row exists");
    assert_eq!(world.source.content_calls(), 1);
    assert_eq!(
        response.bodystructure.as_deref(),
        Some(expected_structure.as_str())
    );
    let stored = world
        .store
        .message_by_uid(world.inbox, uid_one)
        .await
        .unwrap()
        .expect("row exists");
    assert!(stored.header.envelope_complete);
    assert_eq!(
        stored.mime_structure.as_deref(),
        Some(expected_structure.as_str())
    );
    assert_eq!(stored.rfc822_size, Some(expected_bytes.len() as u64));

    // A second identical BODYSTRUCTURE answers from the store.
    let response = world
        .backend
        .fetch(world.inbox, uid_one, &items)
        .await
        .unwrap()
        .expect("row exists");
    assert_eq!(world.source.content_calls(), 1);
    assert_eq!(
        response.bodystructure.as_deref(),
        Some(expected_structure.as_str())
    );

    // The enriched envelope is complete — still without another load.
    let items = parse_fetch_items("(ENVELOPE)").unwrap();
    let response = world
        .backend
        .fetch(world.inbox, uid_one, &items)
        .await
        .unwrap()
        .expect("row exists");
    assert_eq!(world.source.content_calls(), 1);
    let envelope = response.envelope.expect("envelope requested");
    assert!(envelope.contains("\"full subject\""));
    assert!(envelope.contains("((NIL NIL \"carol\" \"x.y\"))"));
    assert!(envelope.contains("\"<m1@x.y>\""));

    // BODY[] re-renders through the injected renderer and returns the
    // exact bytes, with the size riding along from the store.
    let items = parse_fetch_items("(BODY[] RFC822.SIZE)").unwrap();
    let response = world
        .backend
        .fetch(world.inbox, uid_one, &items)
        .await
        .unwrap()
        .expect("row exists");
    assert_eq!(world.source.content_calls(), 2);
    assert_eq!(
        response.bodies.first().map(Vec::as_slice),
        Some(expected_bytes.as_slice())
    );
    assert_eq!(response.rfc822_size, Some(expected_bytes.len() as u64));

    // A following RFC822.SIZE answers from the store, no new render.
    let items = parse_fetch_items("(RFC822.SIZE)").unwrap();
    let response = world
        .backend
        .fetch(world.inbox, uid_one, &items)
        .await
        .unwrap()
        .expect("row exists");
    assert_eq!(world.source.content_calls(), 2);
    assert_eq!(response.rfc822_size, Some(expected_bytes.len() as u64));

    // Bodies are always re-rendered on demand: no body cache by design.
    let items = parse_fetch_items("(BODY[])").unwrap();
    world
        .backend
        .fetch(world.inbox, uid_one, &items)
        .await
        .unwrap()
        .expect("row exists");
    assert_eq!(world.source.content_calls(), 3);

    // A non-peek body fetch on a still-partial message persists the size
    // directly (the update_metadata path, no enrichment round).
    let items = parse_fetch_items("(BODY[])").unwrap();
    let response = world
        .backend
        .fetch(world.inbox, uid_two, &items)
        .await
        .unwrap()
        .expect("row exists");
    assert_eq!(world.source.content_calls(), 4);
    assert_eq!(
        response.bodies.first().map(Vec::as_slice),
        Some(expected_bytes.as_slice())
    );
    let stored = world
        .store
        .message_by_uid(world.inbox, uid_two)
        .await
        .unwrap()
        .expect("row exists");
    assert_eq!(stored.rfc822_size, Some(expected_bytes.len() as u64));
    assert!(
        !stored.header.envelope_complete,
        "the body path persists only the size"
    );
    // The persisted size now answers without another load.
    let items = parse_fetch_items("(RFC822.SIZE)").unwrap();
    let response = world
        .backend
        .fetch(world.inbox, uid_two, &items)
        .await
        .unwrap()
        .expect("row exists");
    assert_eq!(world.source.content_calls(), 4);
    assert_eq!(response.rfc822_size, Some(expected_bytes.len() as u64));
}

#[tokio::test]
async fn body_peek_does_not_persist_anything() {
    let world = world().await;
    let uid = world
        .store
        .assign_uid(
            world.inbox,
            &partial_header("e1", "list subject", 1_700_000_000_000, true),
        )
        .await
        .unwrap();
    let content = world.source.content.clone().unwrap();
    let expected_bytes = MimeRenderer.render(&content).unwrap();

    // PEEK returns the rendered bytes without persisting anything.
    let items = parse_fetch_items("(BODY.PEEK[])").unwrap();
    let response = world
        .backend
        .fetch(world.inbox, uid, &items)
        .await
        .unwrap()
        .expect("row exists");
    assert_eq!(world.source.content_calls(), 1);
    assert_eq!(
        response.bodies.first().map(Vec::as_slice),
        Some(expected_bytes.as_slice())
    );
    let stored = world
        .store
        .message_by_uid(world.inbox, uid)
        .await
        .unwrap()
        .expect("row exists");
    assert_eq!(stored.rfc822_size, None, "peek must not persist the size");
    assert_eq!(stored.mime_structure, None);
    assert!(!stored.header.envelope_complete);
    assert!(!world
        .store
        .calls()
        .iter()
        .any(|call| call == "update_metadata"));
    assert!(!world
        .store
        .calls()
        .iter()
        .any(|call| call == "set_mime_structure"));

    // Quoted HEADER.FIELDS names keep their quotes in the codec, so the
    // match must strip them: "SUBJECT" selects the Subject: line of the
    // rendered bytes, terminated by the delimiting blank line.
    let items = parse_fetch_items("(BODY.PEEK[HEADER.FIELDS (\"SUBJECT\")])").unwrap();
    let response = world
        .backend
        .fetch(world.inbox, uid, &items)
        .await
        .unwrap()
        .expect("row exists");
    assert_eq!(
        response.bodies.first().map(Vec::as_slice),
        Some(b"Subject: full subject\r\n\r\n".as_slice())
    );
    let stored = world
        .store
        .message_by_uid(world.inbox, uid)
        .await
        .unwrap()
        .expect("row exists");
    assert_eq!(stored.rfc822_size, None);
    assert!(!stored.header.envelope_complete);
    assert!(!world
        .store
        .calls()
        .iter()
        .any(|call| call == "update_metadata"));

    // The size arrives only through enrichment, which PEEK never ran.
    let items = parse_fetch_items("(RFC822.SIZE)").unwrap();
    let response = world
        .backend
        .fetch(world.inbox, uid, &items)
        .await
        .unwrap()
        .expect("row exists");
    assert_eq!(response.rfc822_size, Some(expected_bytes.len() as u64));
}

#[tokio::test]
async fn body_sections_slice_and_parts_are_refused() {
    let world = world().await;
    let uid = world
        .store
        .assign_uid(
            world.inbox,
            &partial_header("e1", "list subject", 1_700_000_000_000, true),
        )
        .await
        .unwrap();
    let content = world.source.content.clone().unwrap();
    let expected_bytes = MimeRenderer.render(&content).unwrap();

    // HEADER carries the header block plus its delimiting blank line.
    let items = parse_fetch_items("(BODY[HEADER])").unwrap();
    let response = world
        .backend
        .fetch(world.inbox, uid, &items)
        .await
        .unwrap()
        .expect("row exists");
    let header = response
        .bodies
        .into_iter()
        .next()
        .expect("header section renders");
    let header_text = String::from_utf8_lossy(&header);
    assert!(header_text.contains("Subject: full subject\r\n"));
    assert!(header.ends_with(b"\r\n\r\n"));

    // TEXT is everything after the separator; HEADER + TEXT rebuild the
    // exact rendered bytes.
    let items = parse_fetch_items("(BODY[TEXT])").unwrap();
    let response = world
        .backend
        .fetch(world.inbox, uid, &items)
        .await
        .unwrap()
        .expect("row exists");
    let text = response
        .bodies
        .into_iter()
        .next()
        .expect("text section renders");
    assert!(!text.is_empty());
    assert_eq!(
        [header.as_slice(), text.as_slice()].concat(),
        expected_bytes.as_slice()
    );

    // RFC822.HEADER is the peek equivalent of BODY[HEADER] (RFC 3501
    // §6.4.5): same slice, no persistence — see the dedicated peek test.
    let items = parse_fetch_items("(RFC822.HEADER)").unwrap();
    let response = world
        .backend
        .fetch(world.inbox, uid, &items)
        .await
        .unwrap()
        .expect("row exists");
    assert_eq!(
        response.bodies.first().map(Vec::as_slice),
        Some(header.as_slice())
    );

    // Numeric part sections are refused with the fixed message, before
    // any content load. `FetchResponse` deliberately has no `Debug`
    // (bodies are personal data), so the error is taken via `.err()`.
    let before = world.source.content_calls();
    let items = parse_fetch_items("(BODY[1.2])").unwrap();
    let error = world
        .backend
        .fetch(world.inbox, uid, &items)
        .await
        .err()
        .expect("part sections are refused");
    assert!(
        matches!(error, Error::Unsupported(message) if message == "message part sections are not supported")
    );
    assert_eq!(world.source.content_calls(), before);
}

#[tokio::test]
async fn rfc822_header_is_peek_and_persists_nothing() {
    let world = world().await;
    let uid = world
        .store
        .assign_uid(
            world.inbox,
            &partial_header("e1", "list subject", 1_700_000_000_000, true),
        )
        .await
        .unwrap();
    let content = world.source.content.clone().unwrap();
    let expected_bytes = MimeRenderer.render(&content).unwrap();

    // RFC 3501 §6.4.5: "RFC822.HEADER — Functionally equivalent to
    // BODY.PEEK[HEADER]". A fresh message returns the header bytes and
    // the row keeps nothing: no size, no structure, no complete envelope.
    let items = parse_fetch_items("(RFC822.HEADER)").unwrap();
    let response = world
        .backend
        .fetch(world.inbox, uid, &items)
        .await
        .unwrap()
        .expect("row exists");
    let body = response
        .bodies
        .into_iter()
        .next()
        .expect("header section renders");
    assert!(String::from_utf8_lossy(&body).contains("Subject: full subject\r\n"));
    assert!(body.ends_with(b"\r\n\r\n"));
    assert!(
        body.len() < expected_bytes.len(),
        "the header slice, not the whole message"
    );
    assert_eq!(world.source.content_calls(), 1);
    let stored = world
        .store
        .message_by_uid(world.inbox, uid)
        .await
        .unwrap()
        .expect("row exists");
    assert_eq!(
        stored.rfc822_size, None,
        "rfc822.header must not persist the size"
    );
    assert_eq!(stored.mime_structure, None);
    assert!(!stored.header.envelope_complete);
    assert!(!world
        .store
        .calls()
        .iter()
        .any(|call| call == "update_metadata"));
    assert!(!world
        .store
        .calls()
        .iter()
        .any(|call| call == "set_mime_structure"));
}

#[tokio::test]
async fn fetch_unknown_uid_returns_none() {
    let world = world().await;
    world
        .store
        .assign_uid(
            world.inbox,
            &partial_header("e1", "list subject", 1_700_000_000_000, true),
        )
        .await
        .unwrap();

    let items = parse_fetch_items("(ENVELOPE UID FLAGS BODY[])").unwrap();
    assert!(world
        .backend
        .fetch(world.inbox, 99, &items)
        .await
        .unwrap()
        .is_none());
    // Nothing was loaded or persisted for the phantom row.
    assert_eq!(world.source.content_calls(), 0);
}

#[tokio::test]
async fn same_named_and_slashed_folders_stay_reachable_and_distinct() {
    let world = world().await;
    let folder = |list_id: &str, name: &str| Folder {
        list_id: list_id.into(),
        name: name.into(),
        kind: FolderKind::Custom,
    };
    let mut ids = Vec::new();
    for (list_id, name) in [
        ("work-a", "Work"),
        ("work-b", "Work"),
        ("slashed", "Clients/ACME"),
        ("shadow", "INBOX"),
    ] {
        ids.push(
            world
                .store
                .upsert_mailbox(world.account, &folder(list_id, name), 500)
                .await
                .unwrap(),
        );
    }

    // Every mailbox is listed once, under a name of its own, and no
    // name contains the hierarchy delimiter.
    let views = world.backend.mailboxes().await.unwrap();
    let mut names: Vec<&str> = views.iter().map(|view| view.name.as_str()).collect();
    names.sort_unstable();
    assert_eq!(
        names,
        [
            "Clients\u{2215}ACME",
            "INBOX (2)",
            "Inbox",
            "Work",
            "Work (2)"
        ]
    );

    // Each listed name selects the mailbox it was listed for.
    for view in &views {
        let selected = world
            .backend
            .select(&view.name)
            .await
            .unwrap()
            .expect("a listed name selects");
        assert_eq!(selected.view.id, view.id);
    }
    // The two namesakes are different mailboxes, the older one first.
    let select = |name: &'static str| {
        let backend = &world.backend;
        async move {
            backend
                .select(name)
                .await
                .unwrap()
                .map(|found| found.view.id)
        }
    };
    assert_eq!(select("Work").await, Some(ids[0]));
    assert_eq!(select("Work (2)").await, Some(ids[1]));
    // INBOX in any casing is the Inbox, never the custom namesake.
    assert_eq!(select("INBOX").await, Some(world.inbox));
    assert_eq!(select("inbox").await, Some(world.inbox));
    assert_eq!(select("INBOX (2)").await, Some(ids[3]));
    assert_eq!(select("Clients/ACME").await, None);

    // By id the snapshot never depends on the name.
    let snapshot = world
        .backend
        .snapshot(ids[1])
        .await
        .unwrap()
        .expect("the mailbox exists");
    assert_eq!(snapshot.view.name, "Work (2)");
    assert!(world
        .backend
        .snapshot(MailboxId(9_999))
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        world.backend.uidvalidity(MailboxId(9_999)).await.unwrap(),
        None
    );
}

// ---------------------------------------------------------------------------
// SEARCH
// ---------------------------------------------------------------------------

#[tokio::test]
async fn search_resolves_star_ranges_like_the_fetch_path() {
    let world = world().await;
    let backend = &world.backend;
    let inbox = world.inbox;

    // An empty mailbox selects nothing, star included.
    assert_eq!(search(backend, inbox, &["*"]).await, Vec::<u32>::new());
    assert_eq!(
        search(backend, inbox, &["UID", "*"]).await,
        Vec::<u32>::new()
    );

    // uids 1 and 3 (2 was removed): the gap proves UID-space
    // resolution against the highest uid, not the message count.
    for element in ["e1", "e2", "e3"] {
        world
            .store
            .assign_uid(
                inbox,
                &partial_header(element, "any subject", 1_700_000_000_000, true),
            )
            .await
            .unwrap();
    }
    world.store.remove_message(inbox, 2).await.unwrap();

    // A lone `*` selects exactly the LAST message — not every
    // message.
    assert_eq!(search(backend, inbox, &["*"]).await, vec![3]);
    // `3:*` with fewer than three messages still selects the last.
    assert_eq!(search(backend, inbox, &["3:*"]).await, vec![3]);
    // Finite sequence ranges keep their exact positions.
    assert_eq!(search(backend, inbox, &["1:2"]).await, vec![1, 3]);

    // UID keys resolve in uid space: `<max+1>:*` (mbsync's
    // newest-mail probe) includes the highest uid, and a lone `*`
    // selects it alone.
    assert_eq!(search(backend, inbox, &["UID", "4:*"]).await, vec![3]);
    assert_eq!(search(backend, inbox, &["UID", "*"]).await, vec![3]);
    // Finite UID ranges are unchanged.
    assert_eq!(search(backend, inbox, &["UID", "1:2"]).await, vec![1]);
}

#[tokio::test]
async fn search_covers_index_keys() {
    let world = world().await;
    // uid 1: Nov 14 22:13:20 UTC, unread, 1200 bytes.
    let one = partial_header("e1", "Quarterly report", 1_700_000_000_000, true);
    // uid 2: exactly the Nov 15 UTC day boundary, read, 300 bytes.
    let two = partial_header("e2", "Lunch on Friday", 1_700_006_400_000, false);
    // uid 3: Nov 13 01:00 UTC, unread, 5000 bytes.
    let three = partial_header("e3", "SPAM-can offer", 1_699_837_200_000, true);
    let uid_one = world.store.assign_uid(world.inbox, &one).await.unwrap();
    let uid_two = world.store.assign_uid(world.inbox, &two).await.unwrap();
    let uid_three = world.store.assign_uid(world.inbox, &three).await.unwrap();
    world
        .store
        .update_metadata(world.inbox, uid_one, &one, Some(1200))
        .await
        .unwrap();
    world
        .store
        .update_metadata(world.inbox, uid_two, &two, Some(300))
        .await
        .unwrap();
    world
        .store
        .update_metadata(world.inbox, uid_three, &three, Some(5000))
        .await
        .unwrap();

    let backend = &world.backend;
    let inbox = world.inbox;

    assert_eq!(search(backend, inbox, &["ALL"]).await, vec![1, 2, 3]);
    assert_eq!(search(backend, inbox, &["UNSEEN"]).await, vec![1, 3]);
    assert_eq!(search(backend, inbox, &["SEEN"]).await, vec![2]);
    assert_eq!(search(backend, inbox, &["UID", "1:2"]).await, vec![1, 2]);
    // A bare sequence set filters message numbers, results stay UIDs.
    assert_eq!(search(backend, inbox, &["2:3"]).await, vec![2, 3]);
    assert_eq!(
        search(backend, inbox, &["SINCE", "15-Nov-2023"]).await,
        vec![2]
    );
    // The month parses in any casing clients send.
    assert_eq!(
        search(backend, inbox, &["ON", "14-nov-2023"]).await,
        vec![1]
    );
    assert_eq!(
        search(backend, inbox, &["BEFORE", "14-Nov-2023"]).await,
        vec![3]
    );
    assert_eq!(
        search(backend, inbox, &["SUBJECT", "quarterly"]).await,
        vec![1]
    );
    assert_eq!(
        search(backend, inbox, &["FROM", "example"]).await,
        vec![1, 2, 3]
    );
    assert_eq!(
        search(backend, inbox, &["HEADER", "Subject", "offer"]).await,
        vec![3]
    );
    assert_eq!(
        search(backend, inbox, &["LARGER", "1000"]).await,
        vec![1, 3]
    );
    assert_eq!(search(backend, inbox, &["SMALLER", "1000"]).await, vec![2]);
    assert_eq!(search(backend, inbox, &["NOT", "SEEN"]).await, vec![1, 3]);
    assert_eq!(
        search(backend, inbox, &["OR", "SEEN", "SUBJECT", "offer"]).await,
        vec![2, 3]
    );

    // Groups, NOT, and OR keep their structure: NOT negates the whole
    // group, and OR takes the group as one of its two keys.
    assert_eq!(
        search_line(backend, inbox, "NOT (SEEN SUBJECT lunch)").await,
        vec![1, 3]
    );
    assert_eq!(
        search_line(backend, inbox, "OR (UNSEEN SUBJECT quarterly) SEEN").await,
        vec![1, 2]
    );
    assert_eq!(
        search_line(backend, inbox, "(UNSEEN (OR SUBJECT offer SUBJECT lunch))").await,
        vec![3]
    );
    // Negations of flags the bridge never sets match everything, so a
    // client's habitual UNDELETED prefix changes nothing.
    assert_eq!(
        search_line(backend, inbox, "UNDELETED UNANSWERED SUBJECT offer").await,
        vec![3]
    );
    assert_eq!(
        search_line(backend, inbox, "CHARSET UTF-8 SUBJECT \"quarterly\"").await,
        vec![1]
    );
    // SENT* keys compare the sent date, which is the received time
    // until a row is enriched; BCC reads the stored (empty) field.
    assert_eq!(
        search_line(backend, inbox, "SENTSINCE 15-Nov-2023").await,
        vec![2]
    );
    assert_eq!(
        search_line(backend, inbox, "SENTON 14-Nov-2023").await,
        vec![1]
    );
    assert_eq!(
        search_line(backend, inbox, "SENTBEFORE 14-Nov-2023").await,
        vec![3]
    );
    assert_eq!(
        search_line(backend, inbox, "BCC example").await,
        Vec::<u32>::new()
    );

    // Search never enriches: it reads only the stored index.
    assert_eq!(world.source.content_calls(), 0);

    // Only the searching session's view is searched, and numbers
    // resolve against it: with uid 1 not (yet) part of the view, `1`
    // is uid 2 and uid 1 never matches.
    let keys = parse_search(&[ImapArg::Atom("1".into())]).unwrap_or_else(|_| panic!());
    assert_eq!(
        backend.search(inbox, &keys, &[2, 3]).await.unwrap(),
        vec![2]
    );
    let keys = parse_search(&[ImapArg::Atom("ALL".into())]).unwrap_or_else(|_| panic!());
    assert_eq!(
        backend.search(inbox, &keys, &[2, 3]).await.unwrap(),
        vec![2, 3]
    );
}

/// Seed one row shaped like the M2-era zero-date population: marked
/// complete with size and structure stored, but a sent date that never
/// landed.
async fn seed_stale_row(
    store: &Arc<support::FakeStateStore>,
    inbox: MailboxId,
    element_id: &str,
) -> u32 {
    let mut header = partial_header(element_id, "list subject", 1_700_000_000_000, true);
    header.envelope_complete = true;
    header.sent_at_ms = 0;
    let uid = store.assign_uid(inbox, &header).await.unwrap();
    store
        .update_metadata(inbox, uid, &header, Some(4096))
        .await
        .unwrap();
    store
        .set_mime_structure(inbox, uid, "(\"TEXT\" \"PLAIN\")")
        .await
        .unwrap();
    uid
}

#[tokio::test]
async fn fetch_heals_rows_marked_complete_with_a_zero_sent_date() {
    let world = world().await;
    let uid_structure = seed_stale_row(&world.store, world.inbox, "e1").await;
    let uid_size = seed_stale_row(&world.store, world.inbox, "e2").await;
    let uid_body = seed_stale_row(&world.store, world.inbox, "e3").await;
    let content = world.source.content.clone().unwrap();
    let expected_bytes = MimeRenderer.render(&content).unwrap();
    let expected_structure = bodystructure(&content, &expected_bytes);

    // BODYSTRUCTURE heals through the enricher even though the
    // structure was stored: one content load, the sent date lands, and
    // the recomputed structure is served.
    let items = parse_fetch_items("(BODYSTRUCTURE)").unwrap();
    let response = world
        .backend
        .fetch(world.inbox, uid_structure, &items)
        .await
        .unwrap()
        .expect("row exists");
    assert_eq!(world.source.content_calls(), 1);
    assert_eq!(
        response.bodystructure.as_deref(),
        Some(expected_structure.as_str())
    );
    let stored = world
        .store
        .message_by_uid(world.inbox, uid_structure)
        .await
        .unwrap()
        .expect("row exists");
    assert_eq!(stored.header.sent_at_ms, 1_700_000_000_000);
    assert!(stored.header.envelope_complete);
    assert_eq!(stored.rfc822_size, Some(expected_bytes.len() as u64));

    // The healed row short-circuits: no new source call.
    let response = world
        .backend
        .fetch(world.inbox, uid_structure, &items)
        .await
        .unwrap()
        .expect("row exists");
    assert_eq!(world.source.content_calls(), 1);
    assert_eq!(
        response.bodystructure.as_deref(),
        Some(expected_structure.as_str())
    );

    // ENVELOPE now renders the real date — from the healed index alone.
    let items = parse_fetch_items("(ENVELOPE)").unwrap();
    let response = world
        .backend
        .fetch(world.inbox, uid_structure, &items)
        .await
        .unwrap()
        .expect("row exists");
    assert_eq!(world.source.content_calls(), 1);
    assert!(response
        .envelope
        .expect("envelope requested")
        .contains("14 Nov 2023 22:13:20 +0000"));

    // RFC822.SIZE heals the same way even though the size was stored.
    let items = parse_fetch_items("(RFC822.SIZE)").unwrap();
    let response = world
        .backend
        .fetch(world.inbox, uid_size, &items)
        .await
        .unwrap()
        .expect("row exists");
    assert_eq!(world.source.content_calls(), 2);
    assert_eq!(response.rfc822_size, Some(expected_bytes.len() as u64));
    let stored = world
        .store
        .message_by_uid(world.inbox, uid_size)
        .await
        .unwrap()
        .expect("row exists");
    assert_eq!(stored.header.sent_at_ms, 1_700_000_000_000);

    // BODY[] heals too, and the enrichment and the by-design render
    // share one content load; later fetches load once each.
    let items = parse_fetch_items("(BODY[])").unwrap();
    let response = world
        .backend
        .fetch(world.inbox, uid_body, &items)
        .await
        .unwrap()
        .expect("row exists");
    assert_eq!(world.source.content_calls(), 3);
    assert_eq!(
        response.bodies.first().map(Vec::as_slice),
        Some(expected_bytes.as_slice())
    );
    let stored = world
        .store
        .message_by_uid(world.inbox, uid_body)
        .await
        .unwrap()
        .expect("row exists");
    assert_eq!(stored.header.sent_at_ms, 1_700_000_000_000);
    assert!(stored.header.envelope_complete);

    let response = world
        .backend
        .fetch(world.inbox, uid_body, &items)
        .await
        .unwrap()
        .expect("row exists");
    assert_eq!(world.source.content_calls(), 4);
    assert_eq!(
        response.bodies.first().map(Vec::as_slice),
        Some(expected_bytes.as_slice())
    );
}

#[tokio::test]
async fn one_fetch_returns_every_body_item_from_a_single_content_load() {
    let world = world().await;
    let uid = world
        .store
        .assign_uid(
            world.inbox,
            &partial_header("e1", "list subject", 1_700_000_000_000, true),
        )
        .await
        .unwrap();
    let rendered = MimeRenderer.render(&full_content()).unwrap();

    // A still-partial row asked for its size, its structure, and two
    // sections at once: one download serves the enrichment and both
    // sections, and every body item gets its own answer, in order.
    let items = parse_fetch_items(
        "(RFC822.SIZE BODYSTRUCTURE BODY.PEEK[HEADER] BODY.PEEK[TEXT] RFC822.HEADER)",
    )
    .unwrap();
    let response = world
        .backend
        .fetch(world.inbox, uid, &items)
        .await
        .unwrap()
        .expect("row exists");
    assert_eq!(world.source.content_calls(), 1);
    assert_eq!(response.rfc822_size, Some(rendered.len() as u64));
    assert!(response.bodystructure.is_some());
    assert_eq!(response.bodies.len(), 3);
    let (header, text) = (&response.bodies[0], &response.bodies[1]);
    assert!(header.ends_with(b"\r\n\r\n"));
    assert!(!text.is_empty());
    assert_eq!([header.as_slice(), text.as_slice()].concat(), rendered);
    assert_eq!(&response.bodies[2], header);
}
