# Tuta Bridge M5 Implementation Plan — Read-Only IMAP Server

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Serve the local index to standard mail clients over a read-only IMAP4rev1 subset on TLS loopback, with on-demand MIME rendering, index-backed SEARCH, and IDLE fed by the M4 event loop.

**Architecture:** A hand-written IMAP server (no mature embeddable server crate exists in Rust) split into a pure codec, pure renderers, an `ImapBackend` port (login, mailboxes, fetch, search) implemented over the existing `StateStore` + `MailSource` + envelope enricher, and a session state machine behind a TLS accept loop. A new `serve` command hosts the M4 watch loop and the IMAP listener in one process; IDLE sessions subscribe to a mailbox-change broadcast published from `apply_batch`. Bodies are never stored: only envelope metadata and `rfc822_size` are persisted, everything else is rendered per request and streamed.

**Tech Stack:** Rust 2021, tokio, `tokio-rustls` 0.26 + `rustls` 0.23 (already in the tree), `rcgen` 0.13 + `rustls-pemfile` 2 for the local certificate, existing `sqlx` store, existing `MimeRenderer`, `keyring` (Secret Service), `time`, `clap`.

**Spec:** `docs/superpowers/specs/2026-11-17-tuta-bridge-m3-m5-design.md` (sections 8, 9, 11); parent `tuta-bridge-spec.md`.

## Global Constraints

- All code, identifiers, comments, and commit messages in English.
- Never write passwords, TOTP codes, access tokens, subjects, addresses, or bodies to logs or errors. IMAP session logs carry only command names, tags, and counts.
- TLS on loopback only: the listener binds `127.0.0.1` and nothing else; no plaintext listener, no STARTTLS.
- The bridge stores no message bodies, attachments, inline images, or `.eml`; on-demand rendering may persist only envelope metadata and `rfc822_size`.
- UID and UIDVALIDITY stay stable; only `resync` changes them. Sessions whose mailbox changed UIDVALIDITY must be reset.
- Read-only v1: `STORE`, `APPEND`, `COPY`, `MOVE`, `CREATE`, `DELETE`, `RENAME`, `SUBSCRIBE`, `UNSUBSCRIBE`, `EXPUNGE` answer a tagged `NO` (writes are M6).
- One backend: the `serve` command runs the M4 event loop and the IMAP listener in a single process sharing one `StateStore`.
- The Tuta SDK pin stays `rev = 5dba96493532804ebd5a541024aa217ca3b7874d`.
- No automated test contacts the real Tuta server; loopback TLS with an ephemeral self-signed certificate is allowed in tests.
- `cargo fmt` and `cargo clippy --all-targets -- -D warnings` must pass before every commit.
- Do not add a `LICENSE` file.

## Review Focus

These are the failure modes most likely to corrupt a client's view or leak data:

1. UIDVALIDITY changes under a connected session (resync valve or expired marker): the session must be reset with `* BYE`, never silently mix UIDs from two generations. Test in Task 7.
2. FETCH of a UID expunged mid-session: skip it in the response without failing the whole FETCH. Test in Task 6.
3. The on-demand content path persists only envelope metadata and `rfc822_size`; bodies never reach the store. Test in Task 4 (enrich) and Task 5 (fetch).
4. LOGIN with a wrong username or password: constant-time comparison, tagged `NO`, no timing oracle, no credential material in logs. Test in Task 5.
5. Real clients are picky about shapes: ENVELOPE/BODYSTRUCTURE/literal syntax must be byte-pinned, and non-ASCII strings must use literals. Test in Tasks 2 and 3.
6. Large bodies: stream literal bytes in chunks and hold at most one rendered message at a time. Test in Task 6.

---

## Findings From the Proton Bridge Study

We studied Proton Mail Bridge (GPL-3, `/tmp/opencode/proton-bridge`, concepts only — no code copied) before finalizing this plan. Adopted:

1. **Snapshot validity before every command** (their Gluon invalidates the session state and sends `* BYE`): a `Selected` session re-checks UIDVALIDITY in the store before every command, not only during IDLE.
2. **Precomputed BODYSTRUCTURE** (Gluon serves ENVELOPE/BODYSTRUCTURE from DB columns): the first content load persists `rfc822_size` and a new metadata-only `mime_structure` column, so structure requests never re-download bodies.
3. **`ID` (RFC 2971) supported**, `NOOP` flushes pending notifications (untagged EXISTS outside IDLE), IDLE flushes pending responses on entry and answers `BAD` to anything but `DONE`.
4. **Certificate SANs** cover `localhost`, `127.0.0.1`, `::1` (clients bind to a specific name).
5. **Confirmation of our own design**: markers are set *after* a rebuild (their "bookmark + rewind" property holds implicitly — events during a resync are replayed because they postdate the marker); UID problems are solved by reset-and-rebuild, never by in-band renumbering; a tiny backend trait mirrors their connector seam.

Ruling: `ENVELOPE` is served from the stored header only — it never triggers a network load. The partial M3 header already carries subject/from/date/first-recipient; cc/bcc/message-id appear after the first BODYSTRUCTURE/BODY fetch enriches the row. This deviates from a literal reading of design §8 ("se envelope_complete = 0 … carica i dettagli") to avoid a content download per message on folder listing; the design's convergence goal is unchanged. Cost if wrong: cc/bcc stay blank in a listing until the first body open.

Explicitly not copied from Proton Bridge: pre-downloading all bodies (violates the no-content-cache foundation), remote kill switches for core protocol behavior, read-write semantics with per-client patches. Their test with a Tuta-originated message carrying an RFC-invalid MIME boundary confirms our renderer's choice of regenerating boundaries instead of echoing originals.

---

## File Structure

Create:

- `src/adapters/imap/mod.rs` — module hub.
- `src/adapters/imap/codec.rs` — request parsing, sequence sets, fetch items, string encoding.
- `src/adapters/imap/render.rs` — ENVELOPE, BODYSTRUCTURE, INTERNALDATE, flags, SPECIAL-USE.
- `src/adapters/imap/backend.rs` — `TutaImapBackend` implementing the `ImapBackend` port.
- `src/adapters/imap/session.rs` — session state machine, command dispatch, IDLE.
- `src/adapters/imap/server.rs` — certificate load/generation, TLS acceptor, accept loop.
- `src/adapters/password_store.rs` — `KeyringPasswordStore` implementing `LocalPasswordStore`.
- `src/app/enrich.rs` — envelope enrichment use case.
- `src/ports/imap_backend.rs` — backend port and data types.
- `src/ports/local_password.rs` — bridge password port.
- `src/ports/mailbox_events.rs` — `MailboxChanged` broadcast types.
- `tests/imap_backend.rs`, `tests/imap_server.rs`, `tests/enrich.rs`.

Modify:

- `Cargo.toml` — `tokio-rustls`, `rustls`, `rcgen`, `rustls-pemfile`.
- `src/domain/state.rs`, `src/ports/state_store.rs`, `src/adapters/sqlite_state.rs`, `tests/support/mod.rs` — `BatchOutcome` and `message_by_uid`.
- `src/app/event_sync.rs` — `EventReport.touched_mailboxes`.
- `src/app/watch.rs` — optional notifier.
- `src/config.rs` — `imap_port`.
- `src/adapters/cli.rs`, `src/main.rs` — `serve` and `passwd` commands.
- `src/adapters/mod.rs`, `src/ports/mod.rs`, `src/app/mod.rs` — wiring.
- `README.md`, `NOTES.md` — usage and acceptance.

---

### Task 1: Batch outcome and mailbox-change notifier

**Files:**
- Modify: `src/domain/state.rs`, `src/ports/state_store.rs`, `src/adapters/sqlite_state.rs`, `tests/support/mod.rs`
- Create: `src/ports/mailbox_events.rs`, modify `src/ports/mod.rs`
- Modify: `src/app/event_sync.rs`, `src/app/watch.rs`
- Test: inline modules, `tests/watch.rs`

**Interfaces:**
- Consumes: `StateStore::apply_batch`, `MailboxId`.
- Produces:
  - `pub struct BatchOutcome { pub touched: Vec<MailboxId> }` (derive `Clone`, no `Debug`)
  - `StateStore::apply_batch(...) -> Result<BatchOutcome>` (same arguments)
  - `pub struct MailboxChanged(pub MailboxId);`
  - `pub type MailboxEventSender = tokio::sync::broadcast::Sender<MailboxChanged>;`
  - `EventReport` gains `pub touched_mailboxes: Vec<MailboxId>`
  - `WatchUseCase::with_notifier(self, sender: MailboxEventSender) -> Self` (default stays no-notifier; existing construction sites unchanged)

- [ ] **Step 1: Write the failing store test**

```rust
#[tokio::test]
async fn apply_batch_reports_touched_mailboxes() {
    // Two mailboxes; one is upserted into, one has a stale placement removed,
    // a third is untouched. The outcome lists exactly the two changed ids.
    let outcome = store.apply_batch(account, "group", "batch-1", &changes).await.unwrap();
    assert_eq!(outcome.touched, vec![mailbox_a, mailbox_b]);
}
```

Also assert an `UpsertHeader` for an unknown mailbox adds nothing to `touched`, and `RemoveHeaderEverywhere` lists only mailboxes where a row was actually deleted.

- [ ] **Step 2: Run to verify failure**

Run: `cargo test adapters::sqlite_state apply_batch_reports_touched`
Expected: FAIL (no `BatchOutcome`).

- [ ] **Step 3: Implement**

- In `apply_batch`, track per-mailbox `rows_affected > 0` for every insert/update/delete in the transaction (use `execute` return values), plus the mailbox id for each `UpsertMailbox`; return the deduplicated, insertion-ordered list. `remove_mailbox` stays `Result<()>`.
- Mirror in `FakeStateStore`.
- `EventProcessor::apply` copies the outcome's `touched` into `EventReport.touched_mailboxes`.
- `WatchUseCase` gains an `Option<MailboxEventSender>`; after each applied batch it sends one `MailboxChanged` per touched mailbox (send errors from a closed channel are ignored).

- [ ] **Step 4: Run tests and checks**

Run: `cargo test && cargo fmt --check && cargo clippy --all-targets -- -D warnings`
Expected: PASS with all existing watch/event tests green.

- [ ] **Step 5: Commit**

```bash
git add src/domain/state.rs src/ports/state_store.rs src/ports/mailbox_events.rs src/ports/mod.rs src/adapters/sqlite_state.rs src/app/event_sync.rs src/app/watch.rs tests/support/mod.rs tests/watch.rs
git commit -m "feat: report touched mailboxes from event batches"
```

---

### Task 2: IMAP codec

**Files:**
- Create: `src/adapters/imap/mod.rs`, `src/adapters/imap/codec.rs`
- Modify: `src/adapters/mod.rs`
- Test: inline module in `src/adapters/imap/codec.rs`

**Interfaces:**
- Produces:
  - `pub enum ImapArg { Atom(String), Quoted(String), Literal(Vec<u8>) }`
  - `pub struct Request { pub tag: String, pub command: String, pub args: Vec<ImapArg> }`
  - `pub fn parse_line(line: &str) -> Result<Request>` — atoms, quoted strings with `\\` and `\"` escapes; a trailing `{n}` is surfaced by `pub fn pending_literal(line: &str) -> Option<usize>` so the session can send `+` and read `n` bytes.
  - `pub struct SeqSet { ranges: Vec<(u32, Option<u32>)> }` with `parse_seq_set(&str) -> Result<SeqSet>`, `contains(u32) -> bool`, and `SeqSet::ALL` semantics for `*` (unbounded upper end).
  - `pub fn encode_string(value: &str) -> ImapString` where `pub enum ImapString { Quoted(String), Literal(Vec<u8>) }` — quoted only for non-empty ASCII-printable text without CR/LF/`"`/`\\`; otherwise literal (`{n}\r\n` framing is the writer's job).
  - `pub enum BodySection { Empty, Header, HeaderFields(Vec<String>), Text, Part(String) }`
  - `pub enum FetchItem { Body { peek: bool, section: BodySection }, BodyStructure, Envelope, Flags, InternalDate, Rfc822, Rfc822Header, Rfc822Size, Rfc822Text, Uid }`
  - `pub fn parse_fetch_items(raw: &str) -> Result<Vec<FetchItem>>` including the `ALL`, `FAST`, `FULL` macros.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn parses_login_list_select_and_uid_fetch() {
    let request = parse_line("a001 LOGIN \"user@example\" \"pass word\"").unwrap();
    assert_eq!(request.command, "LOGIN");
    assert_eq!(request.args[1], ImapArg::Quoted("pass word".into()));

    let request = parse_line("a002 UID FETCH 1:* (FLAGS BODY.PEEK[HEADER.FIELDS (SUBJECT FROM)] UID)").unwrap();
    assert_eq!(request.command, "UID");
    assert_eq!(request.args[0], ImapArg::Atom("FETCH".into()));
    let items = parse_fetch_items("(FLAGS BODY.PEEK[HEADER.FIELDS (SUBJECT FROM)] UID)").unwrap();
    assert_eq!(items[0], FetchItem::Flags);
    assert!(matches!(items[1], FetchItem::Body { peek: true, section: BodySection::HeaderFields(ref f) } if f == &["SUBJECT".into(), "FROM".into()]));
    assert_eq!(items[2], FetchItem::Uid);
}

#[test]
fn sequence_sets_cover_ranges_and_star() {
    let set = parse_seq_set("2,4:6,*").unwrap();
    assert!(!set.contains(1) && set.contains(2) && !set.contains(3) && set.contains(999_999));
    assert!(parse_seq_set("0").is_err());
    assert!(parse_seq_set("5:1").is_err());
}

#[test]
fn strings_quote_ascii_and_use_literals_otherwise() {
    assert!(matches!(encode_string("simple"), ImapString::Quoted(_)));
    assert!(matches!(encode_string("say \"hi\""), ImapString::Literal(_)));
    assert!(matches!(encode_string("Caffè"), ImapString::Literal(bytes) if bytes == "Caffè".as_bytes().to_vec()));
}
```

Add: literal detection `pending_literal("a003 LOGIN {5}") == Some(5)`; macro expansion (`FAST` → FLAGS INTERNALDATE RFC822.SIZE, `ALL` → + ENVELOPE, `FULL` → + BODY); a malformed fetch list is a fixed error.

- [ ] **Step 2: Run to verify failure**

Run: `cargo test adapters::imap::codec`
Expected: FAIL (module missing).

- [ ] **Step 3: Implement the codec as pure functions**

No I/O; the session owns reading. `*` in a range means "unbounded upper end". Reject sequence number `0` and reversed ranges with `Error::Unsupported("invalid sequence set".into())`.

- [ ] **Step 4: Run tests and checks**

Run: `cargo test adapters::imap::codec && cargo fmt --check && cargo clippy --all-targets -- -D warnings`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/adapters/imap src/adapters/mod.rs
git commit -m "feat: add imap request codec"
```

---

### Task 3: IMAP renderers

**Files:**
- Create: `src/adapters/imap/render.rs`
- Modify: `src/adapters/imap/mod.rs`
- Test: inline module in `src/adapters/imap/render.rs`

**Interfaces:**
- Consumes: `codec::encode_string`, `MessageHeader`, `MessageContent`, `FolderKind`.
- Produces:
  - `pub fn internal_date(ms: i64) -> String` → `"14-Nov-2023 22:13:20 +0000"` (UTC, dashes per RFC 3501, single-digit days SPACE-padded)
  - `pub fn flags(unread: bool) -> String` → `""` or `"\\Seen"`
  - `pub fn special_use(kind: &FolderKind) -> &'static str` (Sent/Drafts/Trash/Junk/Archive → `\\Sent`/`\\Drafts`/`\\Trash`/`\\Junk`/`\\Archive`; Inbox and Custom → `""` — INBOX is identified by name, not by an attribute)
  - `pub fn envelope(header: &MessageHeader) -> String`
  - `pub fn bodystructure(content: &MessageContent) -> String`

- [ ] **Step 1: Write the failing byte-exact tests**

```rust
#[test]
fn envelope_renders_nils_and_addresses() {
    let header = complete_header(); // fixture helper: from "Alice <alice@x.y>", to "Bob <bob@x.y>", subject "Hi", message_id "<m1@x.y>", sent_at_ms 1_700_000_000_000, empty cc/bcc, no in-reply-to
    let rendered = envelope(&header);
    // Pin the COMPLETE byte-exact string; empty cc/bcc and a missing
    // in-reply-to are bare NIL tokens (RFC 3501 env-cc/env-bcc = "(" 1*address
    // ")" / nil — never a parenthesized group of NILs), and sender/reply-to
    // default to the from value.
    assert_eq!(
        rendered,
        "(\"Tue, 14 Nov 2023 22:13:20 +0000\" \"Hi\" \
          ((\"Alice\" NIL \"alice\" \"x.y\")) \
          ((\"Alice\" NIL \"alice\" \"x.y\")) \
          ((\"Alice\" NIL \"alice\" \"x.y\")) \
          ((\"Bob\" NIL \"bob\" \"x.y\")) \
          NIL NIL NIL \"<m1@x.y>\")"
    );
}

#[test]
fn bodystructure_mirrors_the_mime_renderer_tree() {
    // read src/adapters/mime.rs first: the renderer ALWAYS writes
    // multipart/mixed( multipart/alternative( text/plain [multipart/related(
    // text/html + inline attachments)] ) + regular attachments ) with
    // deterministic boundaries. RFC 3501 body-type-mpart = 1*body SP
    // media-subtype SP body-fld-param: the PARTS come first, then the
    // subtype, then ("BOUNDARY" <boundary>).
    let rendered = bodystructure(&content_with_html_and_attachment_named("doc.pdf"));
    assert!(rendered.starts_with("((\"TEXT\" \"PLAIN\""));
    assert!(rendered.contains("\"ALTERNATIVE\" (\"BOUNDARY\""));
    assert!(rendered.contains("\"RELATED\" (\"BOUNDARY\""));
    assert!(rendered.contains("\"MIXED\" (\"BOUNDARY\""));
    assert!(rendered.contains("(\"APPLICATION\" \"PDF\" (\"NAME\" \"doc.pdf\")"));
}

#[test]
fn internal_date_and_flags_are_fixed_format() {
    assert_eq!(internal_date(1_700_000_000_000), "\"14-Nov-2023 22:13:20 +0000\"");
    // RFC 3501 date-day-fixed: single-digit days are SPACE-padded, not zero-padded.
    assert_eq!(internal_date(millis_of_day(4)), "\" 4-Nov-2023 00:00:00 +0000\"");
    assert_eq!(flags(true), "");
    assert_eq!(flags(false), "\\Seen");
    assert_eq!(special_use(&FolderKind::Inbox), "", "INBOX needs no special-use attribute");
    assert_eq!(special_use(&FolderKind::Archive), "\\Archive");
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test adapters::imap::render`
Expected: FAIL.

- [ ] **Step 3: Implement**

- `envelope` order per RFC 3501: `(date subject from sender reply-to to cc bcc in-reply-to message-id)`; `sender`/`reply-to` default to the from value when absent (standard practice); every address is `(name adl mailbox host)` with `NIL` adl and mailbox/host split at the last `@`. All strings go through `codec::encode_string`; a `sent_at_ms <= 0` renders a `NIL` date (pre-epoch dates are never fabricated — Proton sanitizes them for Apple Mail; we simply omit until enrichment).
- `bodystructure` mirrors what `MimeRenderer::render` actually writes — read `src/adapters/mime.rs` first and replicate its tree exactly: the root is **always** `multipart/mixed` containing `multipart/alternative( text/plain [multipart/related( text/html + inline attachments )] )` followed by root-level inline attachments (when there is no html) and regular attachments. Per RFC 3501 the parts come first, then the subtype, then `("BOUNDARY" <boundary>)`; boundaries come from `deterministic_boundary(seed, label)` with the same seed derivation as `build_message` (`message_id` or `list_id/element_id`). Media types come from `sanitize_media_type(attachment.mime_type)` (upper-cased major/subtype), falling back to `("APPLICATION" "OCTET-STREAM")` when invalid; attachment parts are `("NAME" <name>)` + `"BASE64" <decoded len> NIL NIL NIL NIL` (complete body-ext). Text parts are `("TEXT" "PLAIN"/"HTML" ("CHARSET" "UTF-8") NIL NIL "8BIT" <len> <lines>)`. Empty address lists in `envelope` are bare `NIL`; a `sent_at_ms <= 0` renders a `NIL` date.

- [ ] **Step 4: Run tests and checks**

Run: `cargo test adapters::imap::render && cargo fmt --check && cargo clippy --all-targets -- -D warnings`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/adapters/imap/render.rs
git commit -m "feat: render imap envelopes and bodystructure"
```

---

### Task 4: Envelope enrichment and `message_by_uid`

**Files:**
- Modify: `src/ports/state_store.rs`, `src/adapters/sqlite_state.rs`, `tests/support/mod.rs`, `src/domain/state.rs`
- Create: `src/app/enrich.rs`, modify `src/app/mod.rs`
- Test: inline modules, `tests/enrich.rs`

**Interfaces:**
- Consumes: `StateStore`, `MailSource::content(&MessageSummary) -> Result<MessageContent>`, `MessageRenderer::render`, `render::bodystructure`.
- Produces:
  - `StateStore::message_by_uid(&self, mailbox: MailboxId, uid: u32) -> Result<Option<StoredMessage>>`
  - `StateStore::set_mime_structure(&self, mailbox: MailboxId, uid: u32, structure: &str) -> Result<()>`
  - `StoredMessage` gains `pub mime_structure: Option<String>`
  - SQLite schema migration to `PRAGMA user_version = 2`: `ALTER TABLE messages ADD COLUMN mime_structure TEXT;` (metadata only; existing rows stay `NULL`)
  - `pub struct EnvelopeEnricher { pub store: Arc<dyn StateStore>, pub renderer: Arc<dyn MessageRenderer> }`
  - `EnvelopeEnricher::enrich(&self, mailbox: MailboxId, stored: &StoredMessage, source: &dyn MailSource) -> Result<StoredMessage>`

- [ ] **Step 1: Write the failing tests**

```rust
#[tokio::test]
async fn enriches_partial_envelopes_once_persisting_only_metadata() {
    // FakeMailSource returns a full MessageContent; the stored header is
    // partial (envelope_complete = false, rfc822_size = None).
    let enriched = enricher.enrich(mailbox, &stored, &source).await.unwrap();
    assert!(enriched.header.envelope_complete);
    assert_eq!(enriched.header.message_id.as_deref(), Some("<m1@x.y>"));
    assert!(enriched.rfc822_size.is_some(), "size computed from the rendered literal");
    assert!(enriched.mime_structure.as_deref().is_some_and(|s| s.contains("TEXT")));
    // Second call must not hit the source or the renderer.
    enricher.enrich(mailbox, &enriched, &source).await.unwrap();
    assert_eq!(source.content_calls(), 1);
    // The DB gained exactly the mime_structure column and no content column.
}
```

Add: `message_by_uid` returns exactly one row and `None` for unknown uids (SQLite + fake); the schema migration runs on an existing M4 database (open, set, reopen); the no-content guard still rejects any new column containing `body`, `attachment`, `eml`, `blob`, or `content` while allowing `mime_structure`; `set_mime_structure` round-trips.

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --test enrich && cargo test adapters::sqlite_state message_by_uid`
Expected: FAIL.

- [ ] **Step 3: Implement**

- `message_by_uid`: single-row SQL `SELECT` in the SQLite adapter; a scan in the fake.
- Schema migration: bump `user_version` to 2 and `ALTER TABLE messages ADD COLUMN mime_structure TEXT`; existing databases migrate on open.
- `enrich`: if `header.envelope_complete` and `rfc822_size`/`mime_structure` are present, return the input unchanged. Otherwise build `MessageSummary { list_id: header.list_id, element_id: header.element_id, received_at_ms: header.received_at_ms, subject: header.subject, unread: header.unread }`, call `source.content`, render once through the injected `MessageRenderer` for the byte length, map the content into a complete `MessageHeader` (keep `list_id`/`element_id`/`received_at_ms`/`unread` from the stored header; take subject/from/to/cc/bcc/reply_to/sent_at/message_id/in_reply_to/references from the content; `envelope_complete = true`), persist via `store.update_metadata(mailbox, uid, &complete, Some(len))` and `store.set_mime_structure(mailbox, uid, &render::bodystructure(&content))`, and return the enriched `StoredMessage`. The rendered bytes are dropped immediately — nothing but envelope metadata, the size, and the structure string is persisted.

- [ ] **Step 4: Run tests and checks**

Run: `cargo test && cargo fmt --check && cargo clippy --all-targets -- -D warnings`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/domain/state.rs src/ports/state_store.rs src/adapters/sqlite_state.rs src/app/enrich.rs src/app/mod.rs tests/support/mod.rs tests/enrich.rs
git commit -m "feat: enrich envelopes and mime structure on demand"
```

---

### Task 5: `ImapBackend` port, Tuta backend, and SEARCH

**Files:**
- Create: `src/ports/imap_backend.rs`, `src/ports/local_password.rs`, modify `src/ports/mod.rs`
- Create: `src/adapters/imap/backend.rs`, `src/adapters/password_store.rs`, modify `src/adapters/mod.rs`
- Modify: `src/config.rs` (`imap_port`), `src/adapters/cli.rs` (`Passwd` command, test-only wiring in Task 8)
- Test: `tests/imap_backend.rs`, inline module in `src/adapters/password_store.rs`

**Interfaces:**
- Consumes: `StateStore`, `MailSource`, `EnvelopeEnricher`, `MessageRenderer`, `render::*`, `codec::*`.
- Produces:
  - `pub struct MailboxView { pub id: MailboxId, pub name: String, pub special_use: &'static str }`
  - `pub struct SelectedMailbox { pub view: MailboxView, pub uidvalidity: u32, pub uidnext: u32, pub exists: usize, pub unseen: usize }`
  - `pub struct FetchResponse { pub uid: u32, pub flags: String, pub internal_date: String, pub envelope: Option<String>, pub bodystructure: Option<String>, pub rfc822_size: Option<u64>, pub body: Option<Vec<u8>> }`
  - `#[async_trait] pub trait ImapBackend: Send + Sync` with:
    - `async fn login(&self, user: &str, password: &SecretString) -> Result<bool>`
    - `async fn mailboxes(&self) -> Result<Vec<MailboxView>>`
    - `async fn select(&self, name: &str) -> Result<Option<SelectedMailbox>>` (`INBOX` matches case-insensitively; other names exact)
    - `async fn fetch(&self, mailbox: MailboxId, uid: u32, items: &[FetchItem]) -> Result<Option<FetchResponse>>`
    - `async fn search(&self, mailbox: MailboxId, criteria: &[String]) -> Result<Vec<u32>>`
  - `#[async_trait] pub trait LocalPasswordStore: Send + Sync` with `async fn set(&self, password: &SecretString) -> Result<()>` and `async fn load(&self) -> Result<Option<SecretString>>`
  - `KeyringPasswordStore` via `keyring::Entry::new("tuta-bridge", "imap-bridge")`
  - `pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool` in `src/adapters/imap/backend.rs`

- [ ] **Step 1: Write the failing backend tests**

```rust
#[tokio::test]
async fn login_is_case_insensitive_inbox_and_constant_time() {
    // wrong user, wrong password, right pair
    assert!(!backend.login("other@x.y", &good_password).await.unwrap());
    assert!(backend.login(account_login, &good_password).await.unwrap());
}
```

Add:
- `mailboxes_list_special_use`: kinds map to flags; `select("inbox")` (lowercase) finds the Inbox mailbox with `exists`, `unseen`, `uidnext`, `uidvalidity` from the store.
- `fetch_serves_envelopes_from_the_index_and_enriches_structure_once`: FETCH `(ENVELOPE UID FLAGS INTERNALDATE)` never calls the source (partial header renders with NIL cc/message-id); FETCH `(BODYSTRUCTURE)` calls the source once, returns the persisted structure, and a second identical fetch answers from the store; FETCH `(BODY[] RFC822.SIZE)` renders through `MimeRenderer`, returns the exact bytes, and persists `rfc822_size`; a following FETCH `(RFC822.SIZE)` answers from the store without another render (by design bodies are always re-rendered on demand — the second `BODY[]` fetch does call the source again).
- `body_peek_does_not_persist_anything`: `BODY.PEEK[]` returns bytes but writes no size (PEEK semantics).
- `search_covers_index_keys`: `ALL`, `UNSEEN`, `SEEN`, `UID 1:2`, `SINCE <date>`, `SUBJECT <text>`, `LARGER <n>`, `NOT SEEN`, `OR UNSEEN SUBJECT x`; `BODY foo` and `TEXT foo` return `Error::Unsupported`; unknown key likewise.
- `fetch_unknown_uid_returns_none`.

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --test imap_backend`
Expected: FAIL.

- [ ] **Step 3: Implement**

- `TutaImapBackend { account_id, expected_user: String, passwords: Arc<dyn LocalPasswordStore>, store: Arc<dyn StateStore>, enricher: Arc<EnvelopeEnricher>, source: Arc<dyn MailSource>, renderer: Arc<dyn MessageRenderer> }` — no session lives inside the backend; `serve` (Task 8) injects the owned `Arc<dyn MailSource>` obtained from the session.
- `login`: load the stored password, compare user and password with `constant_time_eq` (compare lengths first only via XOR-fold over `max(len)`; document why timing is uniform).
- `select`: `store.mailboxes(account_id)`, resolve the name (INBOX alias), then `store.messages(id)` for `exists`/`unseen` counts; `uidnext`/`uidvalidity` from the `StoredMailbox`.
- `fetch`: `message_by_uid`; build `FetchResponse` per item list:
  - `Envelope` renders from the stored header as-is (partial or complete) — **never a network load**; unknown fields are `NIL` until enrichment.
  - `BodyStructure` answers from the stored `mime_structure`; when missing it runs the enricher (one content load, persisted) and returns the stored structure.
  - `Body { peek: false }`/`Rfc822`/`Rfc822Text` always re-render through the injected `Arc<dyn MessageRenderer>` (no body cache by design) and persist `rfc822_size` via `update_metadata` when it was `None`; `Body { peek: true }` renders but never persists.
  - `BodySection::Header`/`HeaderFields` slice the rendered bytes between the blank-line separator; `BodySection::Part` returns `Error::Unsupported("message part sections are not supported".into())`.
  - `Rfc822Size` answers from the store; when `None` it enriches once and returns the persisted value without re-rendering.
- `search`: load `store.messages(mailbox)`, filter in memory; parse keys per the test list; dates compare `received_at_ms` against the parsed day boundaries (UTC); `SUBJECT`/`FROM`/`TO`/`CC`/`HEADER` are case-insensitive substring matches on the enriched-or-partial header fields; `BODY`/`TEXT`/`KEYWORD`/flag keys other than SEEN/UNSEEN → `Error::Unsupported`.
- `Passwd` command in `cli.rs` with parser test (implementation lands in Task 8's `main` wiring; the store itself is fully implemented here with an `#[ignore]`-style manual keyring test matching the existing pattern plus a serde/format unit test).

- [ ] **Step 4: Run tests and checks**

Run: `cargo test --test imap_backend && cargo test && cargo fmt --check && cargo clippy --all-targets -- -D warnings`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/ports/imap_backend.rs src/ports/local_password.rs src/ports/mod.rs src/adapters/imap/backend.rs src/adapters/password_store.rs src/adapters/mod.rs src/config.rs src/adapters/cli.rs tests/imap_backend.rs
git commit -m "feat: add the imap backend"
```

---

### Task 6: TLS server and IMAP session (without IDLE)

**Files:**
- Modify: `Cargo.toml` (`tokio-rustls = "0.26"`, `rustls = "0.23"`, `rcgen = "0.13"`, `rustls-pemfile = "2"`)
- Create: `src/adapters/imap/session.rs`, `src/adapters/imap/server.rs`
- Test: inline modules, `tests/imap_server.rs`

**Interfaces:**
- Consumes: `ImapBackend`, codec, renderers, `MailboxChanged` receiver.
- Produces:
  - `pub async fn run_session<S>(stream: S, backend: Arc<dyn ImapBackend>, watch: broadcast::Receiver<MailboxChanged>) -> Result<()> where S: AsyncRead + AsyncWrite + Unpin`
  - `pub fn ensure_certificate(dir: &Path) -> Result<(String, String)>` — generates and persists `imap-cert.pem`/`imap-key.pem` (`0600`, reuse existing) via `rcgen`, CN `localhost` with SANs `DNS:localhost`, `IP:127.0.0.1`, `IP:::1`
  - `pub fn tls_acceptor(cert_pem: &str, key_pem: &str) -> Result<TlsAcceptor>`
  - `pub async fn serve(listener: TcpListener, tls: TlsAcceptor, backend: Arc<dyn ImapBackend>, watch: MailboxEventSender) -> Result<()>` — subscribes one receiver per connection

- [ ] **Step 1: Write the failing session tests**

Use `tokio::io::duplex` and a scripted fake `ImapBackend` (add to `tests/support/mod.rs`); drive lines and assert bytes:

```rust
#[tokio::test]
async fn greets_authenticates_and_lists() {
    // "* OK [CAPABILITY IMAP4rev1] tuta-bridge ready"
    // "a1 LOGIN user@example.invalid hunter2" -> "a1 OK [CAPABILITY IMAP4rev1] LOGIN completed"
    // "a1 LOGIN user@example.invalid wrong"   -> "a1 NO authentication failed"
    // "a2 LIST \"\" \"*\"" -> '* LIST () "/" "Inbox"' for the Inbox (no special-use
    // attribute) and '* LIST (\\Archive) "/" "Archive"' etc. for the others + "a2 OK LIST completed"
}
```

Add:
- `select_reports_counts_and_read_only_flags`: `* <exists> EXISTS`, `* 0 RECENT`, `* OK [UNSEEN <n>]`, `* OK [UIDVALIDITY <v>]`, `* OK [UIDNEXT <n>]`, `* FLAGS (\\Seen)`, `* OK [PERMANENTFLAGS ()] Read-only mailbox`, `a3 OK [READ-WRITE] SELECT completed` (READ-WRITE because clients dislike read-only SELECT; STORE still answers NO).
- `fetch_streams_bodies_and_skips_expunged_uids`: UID FETCH `1,3 (FLAGS BODY[])` where uid 3 vanished: exactly one `* 1 FETCH ...` line whose body is a server-sent literal (`{n}\r\n` immediately followed by the raw bytes — no continuation round-trip), no entry for 3, then the tagged OK. Body literals are written in 64 KiB chunks (assert with a >128 KiB fake body).
- `status_reports_requested_items`; `close_and_check`; `logout_sends_bye`.
- `writes_are_refused`: `STORE`, `APPEND`, `EXPUNGE`, `CREATE`, `DELETE`, `RENAME`, `COPY`, `MOVE`, `SUBSCRIBE`, `UNSUBSCRIBE` each answer `NO not supported by this read-only bridge`; unknown commands answer `BAD`.
- `uidvalidity_drift_resets_sessions_before_every_command`: after the store's UIDVALIDITY changes under a `Selected` session (simulated resync), the *next* command — FETCH, NOOP, anything — answers `* BYE mailbox state was resynced; reconnect` and closes the stream, regardless of IDLE (Proton Bridge lesson: validate the snapshot before every command, not only during push).
- `id_command_answers_and_noop_flushes_notifications`: `ID ("name" "test")` → `* ID ("name" "tuta-bridge")` + tagged OK; with a pending `MailboxChanged` in the watch receiver, `NOOP` emits `* <n> EXISTS` even outside IDLE.
- `capability_advertises_the_subset`: greeting and LOGIN responses carry `CAPABILITY IMAP4rev1 IDLE ID`.
- `search_returns_uids`: `* SEARCH 2 5` shape for UID SEARCH.
- Log hygiene: the session uses `tracing::debug!` with only tag/command/count fields; no subjects, names, or bodies.

- [ ] **Step 2: Run to verify failure**

Run: `cargo test imap_session`
Expected: FAIL.

- [ ] **Step 3: Implement**

- Session state machine: `NotAuthenticated` → LOGIN (also accept a client literal via `pending_literal` + `+ `) → `Authenticated` → SELECT/EXAMINE → `Selected { view, exists, unseen, uidvalidity }`. CAPABILITY/NOOP/ID/LOGOUT valid in all states; state-inappropriate commands → `BAD`.
- Snapshot validity: in `Selected`, before dispatching any command, compare the session's `uidvalidity` with `backend.select(...)`'s current value; on mismatch send `* BYE mailbox state was resynced; reconnect` and close.
- `NOOP` in `Selected` drains pending `MailboxChanged` notifications (try_recv loop) and emits `* <n> EXISTS` when the count changed — clients that poll instead of idling still see updates.
- Response writing: one `BufWriter`, CRLF line endings, literal framing `{n}\r\n` followed by raw bytes for `encode_string` literals and bodies; flush after each command.
- LIST/LSUB: single wildcard match (`*`) returns every `MailboxView` as `* LIST (<flags>) "/" <name>`; mailbox names use `encode_string`.
- FETCH: resolve the sequence set against the selected mailbox's uid list (msn = 1-based index; `*` = last); ask the backend per uid; skip `None`.
- SELECT/EXAMINE/STATUS/CLOSE/CHECK per the test shapes; `EXAMINE` answers `[READ-ONLY]`.
- IDLE answers a tagged `NO not supported` in this task (the watch receiver is already a parameter; Task 7 activates it).

- [ ] **Step 4: TLS plumbing and integration**

- `ensure_certificate` + `tls_acceptor` + `serve` accept loop spawning `run_session` per connection.
- In `tests/imap_server.rs`: generate an ephemeral `rcgen` cert, start the acceptor on `127.0.0.1:0`, connect with a `tokio-rustls` client whose verifier is a test-only accept-all `ServerCertVerifier` (in-file, `#[cfg(test)]` semantics by living in the integration test), and run one LOGIN/LIST/SELECT/FETCH round over real TLS.

- [ ] **Step 5: Run tests and checks**

Run: `cargo test && cargo fmt --check && cargo clippy --all-targets -- -D warnings`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock src/adapters/imap/session.rs src/adapters/imap/server.rs tests/imap_server.rs tests/support/mod.rs
git commit -m "feat: serve imap over tls loopback"
```

---

### Task 7: IDLE with live notifications

**Files:**
- Modify: `src/adapters/imap/session.rs`
- Test: `tests/imap_server.rs`

**Interfaces:**
- Consumes: the `watch: broadcast::Receiver<MailboxChanged>` already passed to `run_session` (Task 6), `ImapBackend::select`.
- Produces: IDLE behavior only; no new public signatures.

- [ ] **Step 1: Write the failing tests**

```rust
#[tokio::test]
async fn idle_emits_exists_on_changes_and_done_ends_it() {
    // select, IDLE -> "+ idling", backend gains a message, notifier sends
    // MailboxChanged(mailbox) -> "* 3 EXISTS", then DONE -> tagged OK.
}

#[tokio::test]
async fn uidvalidity_change_resets_the_session_with_bye() {
    // notifier fires after a simulated resync changed UIDVALIDITY in the store
    // -> "* BYE mailbox state was resynced; reconnect" and the stream closes.
}
```

Add: changes to other mailboxes emit nothing; IDLE outside `Selected` answers `BAD`; pending notifications queued before IDLE are flushed on entry (`* <n> EXISTS` immediately after `+ idling`); any command other than `DONE` during IDLE answers `BAD` and ends the idling state.

- [ ] **Step 2: Run to verify failure**

Run: `cargo test idle`
Expected: FAIL.

- [ ] **Step 3: Implement**

- On `SELECT`, the session stores the mailbox id, `uidvalidity`, and current `exists`.
- IDLE answers `+ idling`, **flushes any notifications that queued while not idling** (Proton Bridge lesson: never lose an update at the IDLE boundary), then `tokio::select!` over: the command reader (`DONE` ends IDLE with the tagged OK; anything else answers `BAD` and leaves the idling loop; LOGOUT behaves normally), and the watcher receiver. On `MailboxChanged(id)` for the selected mailbox: re-run `backend.select`; if `uidvalidity` differs from the session's → `* BYE ...` and close; otherwise emit `* <exists> EXISTS` when the count changed.
- Expunges are not itemized (v1 documents EXISTS-only updates; clients re-sync).

- [ ] **Step 4: Run tests and checks**

Run: `cargo test && cargo fmt --check && cargo clippy --all-targets -- -D warnings`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/adapters/imap/session.rs tests/imap_server.rs
git commit -m "feat: push mailbox changes over idle"
```

---

### Task 8: `serve` and `passwd` commands

**Files:**
- Modify: `src/main.rs`, `src/adapters/cli.rs`, `src/config.rs`
- Modify: `src/ports/session.rs`, `src/adapters/tuta/session.rs`, `tests/support/mod.rs`
- Modify: `src/app/watch.rs` (expose the notifier channel from `serve`)
- Test: inline module in `src/adapters/cli.rs`, `tests/serve.rs`

**Interfaces:**
- Consumes: everything above; `open_state_store`, `WatchUseCase::with_notifier`, `TutaSessionFactory`.
- Produces:
  - `Session::shared_mail(&self) -> Arc<dyn MailSource>` (new required trait method; `TutaSession` wraps its mail source in an `Arc`, fakes return their shared `Arc<FakeMailSource>`; `mail()` stays for existing callers)
  - `Command::Serve` — help: `"Serve IMAP on TLS loopback while watching Tuta events."`
  - `Command::Passwd` — help: `"Set the local IMAP password."`
  - `Config { imap_port: Option<u16> }` (default `9930`; validated range 1..=65535)
  - `serve` binds `127.0.0.1:{port}` only; any other configured address is impossible (never configurable)

- [ ] **Step 1: Write the failing tests**

CLI parse tests for `serve`/`passwd`; `config_roundtrips_imap_port` (Some(10143), None → default).

Integration in `tests/serve.rs` with a fake factory/session (groups + quiet event script), a temp config, `FakeStateStore` seeded with one mailbox and one message, an ephemeral certificate, and the accept-all TLS client:

```rust
#[tokio::test]
async fn serve_logs_in_lists_and_fetches_end_to_end() {
    // start serve on a random loopback port with the bridge password set,
    // connect, LOGIN, LIST, SELECT INBOX, UID FETCH 1 (ENVELOPE), LOGOUT;
    // then trigger the stop channel and assert serve returns Ok(()).
}
```

Add: `serve_refuses_to_start_without_a_password` (`Error::Config` fixed message suggesting `tuta-bridge passwd`).

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --test serve && cargo test adapters::cli`
Expected: FAIL.

- [ ] **Step 3: Implement**

- `passwd`: read the password twice with `rpassword` (hidden), store via `KeyringPasswordStore::set`, print `local IMAP password stored` — never the password.
- Add `Session::shared_mail(&self) -> Arc<dyn MailSource>`; implement it in `TutaSession` (wrap `TutaMailSource` in an `Arc` at construction) and in the test fakes; keep the existing `mail()` method unchanged.
- `serve`:
  1. Load config; resolve `imap_port` (default `9930`).
  2. `open_state_store()`, resume the session, `upsert_account`.
  3. Load the bridge password; missing → `Error::Config("local IMAP password not set; run tuta-bridge passwd first".into())`.
  4. Build the `TutaImapBackend` (expected user = the account's mail address; `source = session.shared_mail()`; enricher; `Arc::new(MimeRenderer)` as the `Arc<dyn MessageRenderer>`).
  5. Create the `MailboxEventSender`, build `WatchUseCase ... .with_notifier(sender.clone())`, and run `run_until(stop)` as a spawned task. Fatal watch errors end `serve` with that error.
  6. `ensure_certificate(data_dir())`, `tls_acceptor`, bind `127.0.0.1:{port}`, print `serving IMAP on 127.0.0.1:{port}; press Ctrl-C to stop`, accept loop until Ctrl-C (`tokio::signal::ctrl_c`), then resolve the stop channel and wait for the watch task.
- Keep the Tuta session open for the process lifetime (no close).

- [ ] **Step 4: Run tests and checks**

Run: `cargo test && cargo fmt --check && cargo clippy --all-targets -- -D warnings`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/main.rs src/adapters/cli.rs src/config.rs src/ports/session.rs src/adapters/tuta/session.rs src/app/watch.rs tests/support/mod.rs tests/serve.rs
git commit -m "feat: serve imap alongside the event loop"
```

---

### Task 9: Documentation and M5 manual acceptance

**Files:**
- Modify: `README.md`, `NOTES.md`

**Interfaces:**
- Consumes: all previous tasks.
- Produces: documented `serve`/`passwd` usage and an acceptance record.

- [ ] **Step 1: Document**

README:
- `serve`/`passwd` commands; bind address and default port `9930`; `imap_port` config key; certificate files in the data directory (`0600`); `Ctrl-C` stops.
- Client setup: Thunderbird (manual account, IMAP `127.0.0.1:9930`, SSL/TLS, accept the certificate exception, username = Tuta address, password = bridge password) and an `mbsync` sample channel config.
- Limits of v1: read-only (writes answer NO, coming in M6); `SEARCH BODY`/`TEXT` unsupported; numeric `BODY[n]` part sections unsupported (whole-message `BODY[]`, `HEADER`, `TEXT`, `HEADER.FIELDS` only); EXISTS-only IDLE updates; no multi-account.

NOTES: the served subset, response shapes worth remembering (SELECT untagged block, PERMANENTFLAGS () with READ-WRITE, literal strategy), the IDLE reset rule, the password/certificate locations, and the Proton Bridge study conclusions that shaped the server: snapshot re-validation before every command, ENVELOPE served index-only, `mime_structure` persisted at first enrichment, and the confirmation that setting batch markers *after* a rebuild gives Proton's bookmark-and-rewind property (events during a resync postdate the marker and are replayed).

- [ ] **Step 2: Verify formatting and the full suite**

Run: `cargo test && cargo fmt --check && cargo clippy --all-targets -- -D warnings`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add README.md NOTES.md
git commit -m "docs: document the imap server"
```

- [ ] **Step 4: Manual acceptance (requires the real account)**

```bash
source "$HOME/.cargo/env"
cargo run -- passwd
cargo run -- serve
```

Checklist (record every result in NOTES under `## M5 manual acceptance`):
1. Terminal client: a short Python `imaplib` script (TLS, unverified cert) logs in, `LIST`, `SELECT INBOX`, `UID FETCH <newest> (ENVELOPE RFC822.SIZE FLAGS INTERNALDATE)`, and prints the subject found in the DB.
2. `mbsync`: full first sync downloads; a **second** sync reports no body re-downloads (UIDs stable).
3. Thunderbird: folders with SPECIAL-USE visible; subjects/senders/dates/flags shown; open a mail **with an attachment**; delete/move attempts show the read-only NO.
4. IDLE: with Thunderbird open, send a mail from another client — it appears without pressing "Get Messages"; then restart `serve` and confirm the account still loads.
5. `pragma table_info(messages)` still has no body/attachment/`.eml` column; `rfc822_size` populated for fetched mails only.
6. No subjects/addresses/bodies in `serve` logs; the bridge password never printed.

```bash
git add NOTES.md
git commit -m "docs: record M5 manual acceptance"
```

---

## Self-Review Notes

- **Spec coverage:** §8 LIST/LSUB (Task 6), SELECT/EXAMINE (Tasks 5/6), FETCH items incl. on-demand details and persisted `rfc822_SIZE` (Tasks 4/5), BODYSTRUCTURE/BODY[]/PEEK (Tasks 3/5/6), SEARCH limits (Task 5), IDLE watchers without new tables (Tasks 1/7), streaming literals (Task 6), TLS loopback + local password (Tasks 5/6/8). §9 constraints are in Global Constraints. §11 acceptance maps to Task 9.
- **Type consistency:** `BatchOutcome`, `MailboxChanged`, `ImapArg`, `SeqSet`, `FetchItem`, `MailboxView`, `SelectedMailbox`, `FetchResponse`, `ImapBackend`, `LocalPasswordStore`, `StoredMessage.mime_structure` are each defined once and consumed by the same names later.
- **Review Focus coverage:** UIDVALIDITY reset before every command (Task 6) and during IDLE push (Task 7), expunged-uid FETCH (Task 6), no body persistence (Tasks 4/5), constant-time login (Task 5), byte-pinned shapes (Tasks 2/3), chunked literals (Task 6).
- **Proton Bridge study folded in:** snapshot re-validation before every command (Task 6), `mime_structure` precomputed at first enrichment (Tasks 4/5), `ID` command and NOOP flush (Task 6), IDLE entry flush (Task 7), certificate SANs (Task 6), ENVELOPE index-only ruling recorded in the findings section.
- **Known v1 trade-offs recorded, not hidden:** per-message rendering buffers one body at a time; EXISTS-only IDLE; numeric part sections unsupported; READ-WRITE SELECT with NO-writing commands; `mime_structure` is the only new column and the no-content guard was updated accordingly.
