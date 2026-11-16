# Tuta Bridge M3 Implementation Plan — Minimal State and Sync

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Persist only the protocol state needed by IMAP (UIDs, UIDVALIDITY, last event batch) plus a lightweight header index, and synchronize Tuta folders/mail headers without caching bodies or attachments.

**Architecture:** A `StateStore` port backed by SQLite (`sqlx`, runtime queries). A `SyncEngine` upserts mailboxes and message headers, assigning stable UIDs in transactions. A `sync`/`resync` CLI drives the engine using the existing session/credential infrastructure. No message body, attachment, or `.eml` is stored.

**Tech Stack:** Rust 2021, `sqlx` 0.8 (SQLite, tokio runtime), existing `tuta-sdk`, `tokio`, `clap`, `tracing`.

**Spec:** `docs/superpowers/specs/2026-11-17-tuta-bridge-m3-m5-design.md`; parent `tuta-bridge-spec.md`.

## Global Constraints

- All code, identifiers, comments, and commit messages in English. Design docs in Italian.
- Never write passwords, TOTP codes, access tokens, decrypted keys, subjects, addresses, or bodies to logs or errors.
- SQLite stores protocol state and header metadata only. **Never store message bodies, attachments, inline images, or complete `.eml` files.**
- The state database path is `$XDG_DATA_HOME/tuta-bridge/state.sqlite3`; directory `0700`, database `0600` on Unix.
- UID and UIDVALIDITY must be stable across runs; only `resync` may change UIDVALIDITY.
- `sync` and `resync` must not require a new Tuta login: they use credentials from the Secret Service.
- No automated test contacts the real Tuta server.
- `cargo fmt` and `cargo clippy --all-targets -- -D warnings` must pass before every commit.

## Review Focus

These are the failure modes most likely to corrupt a client or leak content:

1. Re-running sync assigns different UIDs or changes UIDVALIDITY.
2. A mail moved/removed in Tuta leaves a stale UID or a duplicate row.
3. The state DB accidentally stores a body, attachment, or rendered message.
4. A failed transaction leaves `next_uid` advanced without a message row (or vice versa).
5. `resync` changes UIDVALIDITY but leaves old rows, so Thunderbird sees inconsistent data.

Each gets a test in the task that owns the code.

---

### Task 1: Add SQLite dependency, state path, and schema

**Files:**
- Modify: `Cargo.toml`
- Modify: `src/config.rs`
- Create: `src/adapters/sqlite_state.rs`
- Modify: `src/adapters/mod.rs`
- Test: `src/adapters/sqlite_state.rs` (unit tests)

**Interfaces:**
- Consumes: `crate::config::data_dir()`.
- Produces: `pub struct SqliteStateStore { pool: sqlx::SqlitePool }`; `SqliteStateStore::open(&Path)`, `SqliteStateStore::open_in_memory()`; `pub fn state_path() -> anyhow::Result<PathBuf>`.

- [ ] **Step 1: Write failing tests**

```rust
#[tokio::test]
async fn creates_schema_and_sets_user_version() {
    let store = SqliteStateStore::open_in_memory().await.unwrap();
    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name",
    )
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
```

- [ ] **Step 2: Run the test and verify failure**

Run: `cargo test adapters::sqlite_state`
Expected: FAIL because the module and dependency do not exist.

- [ ] **Step 3: Add dependency and implementation**

Add to `Cargo.toml`:

```toml
sqlx = { version = "0.8", default-features = false, features = ["runtime-tokio", "sqlite"] }
```

`src/config.rs`:

```rust
pub fn state_path() -> anyhow::Result<std::path::PathBuf> {
    Ok(data_dir()?.join("state.sqlite3"))
}
```

`src/adapters/sqlite_state.rs` opens the pool with:

```rust
let options = sqlx::sqlite::SqliteConnectOptions::new()
    .filename(path)
    .create_if_missing(true)
    .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
    .foreign_keys(true);
let pool = sqlx::sqlite::SqlitePoolOptions::new()
    .max_connections(1)
    .connect_with(options)
    .await?;
```

For `open_in_memory`, use `SqliteConnectOptions::new().in_memory(true)` with the same pool settings. After opening a file pool, set the file permissions to `0600` on Unix.

Execute the schema from the design in one `sqlx::query(...).execute` per statement, then `PRAGMA user_version = 1`. Expose `pub fn pool(&self) -> &sqlx::SqlitePool` for tests.

- [ ] **Step 4: Run tests and checks, then commit**

Run: `cargo test adapters::sqlite_state && cargo fmt --check && cargo clippy --all-targets -- -D warnings`

```bash
git add Cargo.toml Cargo.lock src/config.rs src/adapters/sqlite_state.rs src/adapters/mod.rs
git commit -m "feat: add minimal SQLite state schema"
```

---

### Task 2: State domain types and `StateStore` port

**Files:**
- Create: `src/domain/state.rs`
- Modify: `src/domain/mod.rs`
- Create: `src/ports/state_store.rs`
- Modify: `src/ports/mod.rs`
- Test: `src/domain/state.rs` (unit tests)

**Interfaces:**
- Consumes: `Address`, `FolderKind`.
- Produces:
  - `MailboxId(pub i64)`
  - `StoredMailbox { id, account_id, list_id, name, kind, uidvalidity: u32, next_uid: u32 }`
  - `MessageHeader { list_id, element_id, received_at_ms, sent_at_ms, subject, from: Address, to: Vec<Address>, cc: Vec<Address>, bcc: Vec<Address>, reply_to: Vec<Address>, unread: bool, message_id: Option<String>, in_reply_to: Option<String>, references: Vec<String>, envelope_complete: bool }`
  - `StoredMessage { uid: u32, header: MessageHeader, rfc822_size: Option<u64> }`
  - `MessagePage { headers: Vec<MessageHeader>, next_start: Option<String> }`
  - `StateStore` trait (async).

- [ ] **Step 1: Write failing tests**

```rust
#[test]
fn header_keeps_ids_and_optional_metadata() {
    let header = MessageHeader {
        list_id: "l".into(), element_id: "e".into(),
        received_at_ms: 5, sent_at_ms: 0, subject: "s".into(),
        from: Address { name: None, address: "a@b.c".into() },
        to: vec![], cc: vec![], bcc: vec![], reply_to: vec![],
        unread: true, message_id: None, in_reply_to: None,
        references: vec![], envelope_complete: false,
    };
    assert_eq!(header.list_id, "l");
    assert!(!header.envelope_complete);
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test domain::state`
Expected: FAIL because the module does not exist.

- [ ] **Step 3: Implement types and port**

```rust
#[async_trait::async_trait]
pub trait StateStore: Send + Sync {
    async fn upsert_account(&self, mail_address: &str) -> Result<i64>;
    async fn upsert_mailbox(&self, account_id: i64, folder: &Folder, uidvalidity: u32) -> Result<MailboxId>;
    async fn mailboxes(&self, account_id: i64) -> Result<Vec<StoredMailbox>>;
    async fn assign_uid(&self, mailbox: MailboxId, header: &MessageHeader) -> Result<u32>;
    async fn update_metadata(&self, mailbox: MailboxId, uid: u32, header: &MessageHeader, rfc822_size: Option<u64>) -> Result<()>;
    async fn remove_message(&self, mailbox: MailboxId, uid: u32) -> Result<()>;
    async fn messages(&self, mailbox: MailboxId) -> Result<Vec<StoredMessage>>;
    async fn last_batch(&self, account_id: i64, group_id: &str) -> Result<Option<String>>;
    async fn set_last_batch(&self, account_id: i64, group_id: &str, batch_id: &str) -> Result<()>;
    async fn reset_account(&self, account_id: i64) -> Result<()>;
}
```

Do not derive `Debug` on types containing subjects or addresses.

- [ ] **Step 4: Run tests and checks, then commit**

Run: `cargo test domain::state && cargo fmt --check && cargo clippy --all-targets -- -D warnings`

```bash
git add src/domain/state.rs src/domain/mod.rs src/ports/state_store.rs src/ports/mod.rs
git commit -m "feat: add state domain types and port"
```

---

### Task 3: SQLite state adapter with transactional UID assignment

**Files:**
- Modify: `src/adapters/sqlite_state.rs`
- Test: `src/adapters/sqlite_state.rs` (unit tests)

**Interfaces:**
- Consumes: `StateStore`, `StoredMailbox`, `MessageHeader`, `StoredMessage`.
- Produces: `impl StateStore for SqliteStateStore`.

- [ ] **Step 1: Write failing tests**

```rust
#[tokio::test]
async fn uid_assignment_is_idempotent_and_monotonic() {
    let store = SqliteStateStore::open_in_memory().await.unwrap();
    let account = store.upsert_account("a@b.c").await.unwrap();
    let folder = Folder { list_id: "entries".into(), name: "Inbox".into(), kind: FolderKind::Inbox };
    let mailbox = store.upsert_mailbox(account, &folder, 100).await.unwrap();
    let h1 = header("list", "e1");
    let h2 = header("list", "e2");
    assert_eq!(store.assign_uid(mailbox, &h1).await.unwrap(), 1);
    assert_eq!(store.assign_uid(mailbox, &h1).await.unwrap(), 1);
    assert_eq!(store.assign_uid(mailbox, &h2).await.unwrap(), 2);
    let boxes = store.mailboxes(account).await.unwrap();
    assert_eq!(boxes[0].next_uid, 3);
    assert_eq!(boxes[0].uidvalidity, 100);
}

#[tokio::test]
async fn reset_clears_mail_and_state_but_keeps_account() {
    // assert messages emptied, mailboxes emptied, account still present
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test adapters::sqlite_state::tests::uid_assignment`
Expected: FAIL because `impl StateStore` is missing.

- [ ] **Step 3: Implement**

`upsert_mailbox` uses `INSERT ... ON CONFLICT(account_id, list_id) DO NOTHING`, then `SELECT` the row. It never overwrites `uidvalidity` or `next_uid` for an existing mailbox.

`assign_uid` runs in a transaction:
1. `SELECT uid FROM messages WHERE mailbox_id=? AND tuta_list_id=? AND tuta_element_id=?`; return it if present (and update metadata using the same transaction).
2. Otherwise `SELECT next_uid FROM mailboxes WHERE id=?`; insert the message with that UID; `UPDATE mailboxes SET next_uid = next_uid + 1`.
3. Commit only after both statements succeed.

`reset_account` deletes `messages`, `mailboxes`, and `sync_state` for the account (foreign keys cascade handles messages), leaving `accounts`.

Serialize `recipients_json` as `{"to":[],"cc":[],"bcc":[],"reply_to":[]}` using `serde_json`; `references_json` as an array.

- [ ] **Step 4: Run tests and checks, then commit**

Run: `cargo test adapters::sqlite_state && cargo fmt --check && cargo clippy --all-targets -- -D warnings`

```bash
git add src/adapters/sqlite_state.rs
git commit -m "feat: implement SQLite state store with stable UIDs"
```

---

### Task 4: Tuta header page source

**Files:**
- Modify: `src/ports/mail_source.rs`
- Modify: `src/adapters/tuta/mail_source.rs`
- Test: `tests/header_source.rs`

**Interfaces:**
- Consumes: `MessageHeader`, `MessagePage`, `MailAddress`.
- Produces:
  - `MailSource::headers_page(&self, folder: &Folder, start: Option<&str>, limit: usize) -> Result<MessagePage>` with a default `Err(Error::Unsupported("headers not implemented"))` for existing fakes.
  - `pub fn header_from_parts(list_id: &str, element_id: &str, received_at_ms: i64, subject: &str, sender: &MailAddress, first_recipient: Option<&MailAddress>, unread: bool) -> MessageHeader`.

- [ ] **Step 1: Write failing tests**

```rust
#[test]
fn maps_only_fields_available_in_mail_list() {
    let sender = MailAddress { _id: None, name: "Sender".into(), address: "sender@example.com".into(), contact: None, _errors: Default::default() };
    let recipient = MailAddress { _id: None, name: String::new(), address: "recipient@example.com".into(), contact: None, _errors: Default::default() };
    let header = header_from_parts("list", "elem", 5, "subject", &sender, Some(&recipient), true);
    assert_eq!(header.list_id, "list");
    assert_eq!(header.element_id, "elem");
    assert_eq!(header.from.address, "sender@example.com");
    assert_eq!(header.to[0].address, "recipient@example.com");
    assert!(!header.envelope_complete);
    assert_eq!(header.sent_at_ms, 0);
    assert!(header.message_id.is_none());
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --test header_source`
Expected: FAIL because the function does not exist.

- [ ] **Step 3: Implement**

`TutaMailSource::headers_page` loads `MailSetEntry` values with `CryptoEntityClient::load_all` (DESC), then loads each referenced `Mail`; it maps them with `header_from_parts` using `mail._id`, `mail.receivedDate`, `mail.subject`, `&mail.sender`, `mail.firstRecipient.as_ref()`, and `mail.unread`. For M3 `next_start` is `None` (all entries loaded); pagination can be added in M5 without changing the state schema.

`headers_page` ignores `start` and `limit` for now, but must accept them and return all entries; document this in a comment.

`header_from_parts` returns `None` only if the element id is empty; `to` contains the first recipient when present; other recipients, `sent_at_ms`, `message_id`, `in_reply_to`, `references` remain empty/0/None; `envelope_complete = false`.

- [ ] **Step 4: Run tests and checks, then commit**

Run: `cargo test --test header_source && cargo fmt --check && cargo clippy --all-targets -- -D warnings`

```bash
git add src/ports/mail_source.rs src/adapters/tuta/mail_source.rs tests/header_source.rs
git commit -m "feat: expose mail header pages for sync"
```

---

### Task 5: Sync engine

**Files:**
- Create: `src/app/sync.rs`
- Modify: `src/app/mod.rs`
- Test: `tests/sync.rs`
- Test support: extend `tests/support/mod.rs` with `FakeStateStore` and `FakeHeaderSource`.

**Interfaces:**
- Consumes: `StateStore`, `MailSource`, `Folder`.
- Produces:
  - `SyncReport { folders: usize, messages: usize }`
  - `SyncEngine { store: Arc<dyn StateStore> }` with `async fn sync(&self, account_id: i64, source: &dyn MailSource, uidvalidity: u32) -> Result<SyncReport>`.

- [ ] **Step 1: Write failing tests**

```rust
#[tokio::test]
async fn sync_is_idempotent() {
    // fake source: two folders, three headers.
    // run sync twice with the same UIDVALIDITY.
    // assert 2 folders, 3 messages, UIDs unchanged on the second run.
}

#[tokio::test]
async fn sync_assigns_new_uid_to_new_mail() {
    // first run: two messages; second run: three.
    // assert third UID is 3 and earlier UIDs unchanged.
}

#[tokio::test]
async fn resync_changes_uidvalidity_and_resets_uids() {
    // reset_account, then sync with a new uidvalidity; UIDs restart at 1.
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --test sync`
Expected: FAIL because `SyncEngine` does not exist.

- [ ] **Step 3: Implement**

For each folder from `source.folders()`: `store.upsert_mailbox(account_id, folder, uidvalidity)`; then `source.headers_page(folder, None, usize::MAX)`; for each header call `store.assign_uid(mailbox, header)`. Count folders and headers. Do not fetch `content()`.

`resync` is a separate use case (Task 6) that calls `store.reset_account` before `sync` with a fresh `uidvalidity` (Unix seconds as `u32`, or an incrementing value if the previous is too recent).

- [ ] **Step 4: Run tests and checks, then commit**

Run: `cargo test --test sync && cargo fmt --check && cargo clippy --all-targets -- -D warnings`

```bash
git add src/app/sync.rs src/app/mod.rs tests/sync.rs tests/support/mod.rs
git commit -m "feat: add idempotent mail header sync engine"
```

---

### Task 6: `sync` and `resync` CLI commands

**Files:**
- Modify: `src/adapters/cli.rs`
- Modify: `src/main.rs`
- Create: `src/app/state_sync.rs` (wires session/credentials/state engine)
- Modify: `src/app/mod.rs`
- Test: `src/adapters/cli.rs` (unit tests)

**Interfaces:**
- Consumes: `Config`, `CredentialStore`, `SessionFactory`, `SqliteStateStore`, `state_path`, `SyncEngine`.
- Produces: `Command::Sync`, `Command::Resync`; `StateSyncUseCase { factory, store, config_path }` with `async fn sync(&self) -> Result<SyncReport>` and `async fn resync(&self) -> Result<SyncReport>`.

- [ ] **Step 1: Write failing parser tests**

```rust
#[test]
fn parses_sync_commands() {
    assert!(matches!(parse_from(["tuta-bridge", "sync"]).unwrap().command, Command::Sync));
    assert!(matches!(parse_from(["tuta-bridge", "resync"]).unwrap().command, Command::Resync));
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test adapters::cli::tests::parses_sync_commands`
Expected: FAIL because the variants do not exist.

- [ ] **Step 3: Implement**

`StateSyncUseCase::sync`:
1. Load config and active account; load credentials; `factory.resume`.
2. Upsert account with credentials.login.
3. Open `SqliteStateStore` at `state_path()`.
4. Call `SyncEngine::sync` with current Unix seconds as `uidvalidity`.
5. Return the report.

`resync`: same, but call `store.reset_account(account_id)` before syncing and use a fresh `uidvalidity` (increment the previous value or use Unix seconds; ensure it differs from the stored value).

`main` prints `synced {folders} folders, {messages} messages` and `resynced ...` respectively. Do not print subjects or addresses. `sync` does not close the session.

- [ ] **Step 4: Run tests and checks, then commit**

Run: `cargo test && cargo fmt --check && cargo clippy --all-targets -- -D warnings`

```bash
git add src/adapters/cli.rs src/main.rs src/app/state_sync.rs src/app/mod.rs
git commit -m "feat: add sync and resync commands"
```

---

### Task 7: M3 manual acceptance and documentation

**Files:**
- Modify: `NOTES.md`
- Modify: `README.md`

**Interfaces:**
- Consumes: the binary from Tasks 1–6.
- Produces: recorded M3 results.

- [ ] **Step 1: Run the sync twice**

```bash
cargo run -- sync
cargo run -- sync
```

Expected: the second run reports the same folder/message counts and no error.

- [ ] **Step 2: Inspect the state database without copying content**

Use `python3` with `sqlite3` to read only counts and UID values:

```bash
python3 - <<'PY'
import sqlite3, os
p = os.path.expanduser("~/.local/share/tuta-bridge/state.sqlite3")
db = sqlite3.connect(p)
print("mailboxes", db.execute("select count(*) from mailboxes").fetchone()[0])
print("messages", db.execute("select count(*) from messages").fetchone()[0])
print("uids", db.execute("select mailbox_id, min(uid), max(uid), count(*) from messages group by mailbox_id").fetchall())
print("uidvalidity", db.execute("select id, uidvalidity, next_uid from mailboxes").fetchall())
PY
```

Expected: counts stable between runs; `next_uid` equals max UID + 1.

- [ ] **Step 3: Verify resync invalidates UIDs**

```bash
cargo run -- resync
# run the inspection again
```

Expected: `uidvalidity` changes, UIDs restart at 1, counts match the mailbox.

- [ ] **Step 4: Verify no content is stored**

```bash
python3 - <<'PY'
import sqlite3, os
p = os.path.expanduser("~/.local/share/tuta-bridge/state.sqlite3")
db = sqlite3.connect(p)
cols = [r[1] for r in db.execute("pragma table_info(messages)")]
for forbidden in ["body", "html", "attachment", "eml"]:
    assert not any(forbidden in c.lower() for c in cols), cols
print("no content columns")
PY
```

- [ ] **Step 5: Record results and commit**

Update `NOTES.md` with folder/message counts, whether UIDs were stable, and the resync result. Do not record subjects, addresses, or bodies. Update `README.md` with `tuta-bridge sync` and `resync`.

```bash
git add NOTES.md README.md
git commit -m "docs: record M3 sync acceptance"
```

---

## Self-Review

**Spec coverage:** minimal SQLite state and no content cache → Tasks 1–3; header sync and UID stability → Tasks 4–5; CLI and acceptance → Tasks 6–7. Deliberately out of scope: event bus (M4), IMAP (M5), writes, SMTP.

**Type consistency:** `MailboxId`, `StoredMailbox`, `MessageHeader`, `StoredMessage`, `MessagePage`, `StateStore`, and `SyncReport` are defined once and reused. `headers_page` is added to `MailSource` with a default error so existing fakes keep compiling.

**Review Focus tests:** idempotency and UID stability → Task 5; stale/duplicate rows → Task 3; no content columns → Task 7; transaction atomicity → Task 3; resync UIDVALIDITY → Task 6/Task 7.

**Known limitations:** initial sync loads all headers per folder (no pagination) and lazy envelope enrichment for recipients/size is deferred to M5; `SEARCH BODY` remains unsupported.
