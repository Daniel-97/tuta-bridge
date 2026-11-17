# Tuta Bridge M4 Implementation Plan — Event Bus and Incremental Updates

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Keep the local header index current through a single Tuta websocket event bus, persist each event batch atomically with its batch id, reconnect with backoff, and resync when batches are too old.

**Architecture:** A `EventStream` port hides the websocket and yields parsed `EventFrame`s; a `EventLookup` port reloads the affected `Mail`/`MailSet` entities through the existing decryption path. `EventProcessor` turns entity events into `StateChange`s and `StateStore::apply_batch` writes them plus `last_batch` in one SQLite transaction. `WatchUseCase` owns the reconnect loop and baseline/resync policy. No message body or attachment is ever fetched or stored.

**Tech Stack:** Rust 2021, existing `tuta-sdk` (`CryptoEntityClient`), `tokio`, `tokio-tungstenite` 0.24 (rustls), `futures-util`, `urlencoding`, `sqlx` 0.8 SQLite, `clap`, `tracing`.

**Spec:** `docs/superpowers/specs/2026-11-17-tuta-bridge-m3-m5-design.md` (section 7); parent `tuta-bridge-spec.md`.

## Global Constraints

- All code, identifiers, comments, and commit messages in English. Plan documents stay in English like the M3 plan.
- Never write passwords, TOTP codes, access tokens, websocket URLs, decrypted keys, subjects, addresses, or bodies to logs or errors. The event URL contains the access token: never log or `Debug` it.
- SQLite stores protocol state and header metadata only. **Never store message bodies, attachments, inline images, or complete `.eml` files.**
- The state database path stays `$XDG_DATA_HOME/tuta-bridge/state.sqlite3`; directory `0700`, database/WAL/SHM `0600` on Unix.
- UID and UIDVALIDITY stay stable; only `resync` changes UIDVALIDITY.
- `watch` uses credentials from the Secret Service and never prompts for a new login.
- One websocket backend for all future IMAP connections.
- No automated test contacts the real Tuta server. Loopback websockets (`ws://127.0.0.1`) are allowed in tests only.
- The Tuta SDK pin stays `rev = 5dba96493532804ebd5a541024aa217ca3b7874d`.
- `cargo fmt` and `cargo clippy --all-targets -- -D warnings` must pass before every commit.
- Do not add a `LICENSE` file.

## Review Focus

These are the failure modes most likely to lose mail, corrupt UIDs, or leak data:

1. A stored batch marker is older than 45 days: `watch` must resync instead of silently missing events.
2. The server closes the socket with an auth/session code (4403/4440/4470/4472): `watch` must stop with a clear fixed message, not retry forever.
3. A batch is replayed after reconnect: applying it twice must not change UIDs or duplicate rows.
4. A batch fails halfway through: the transaction must roll back and `last_batch` must not advance.
5. An event points at a mail/folder that cannot be decrypted or was already deleted: skip it, keep watching, and still persist the batch.
6. A mail moves between folders: the old row must disappear and the destination must get its own UID.
7. A network drop reconnects: the next connection must start from the last persisted batch, not the original one.

Each line gets a test in the task that owns the code.

---

## File Structure

Create:

- `src/domain/event.rs` — event domain types and Tuta type-id constants.
- `src/ports/event_lookup.rs` — reload entities needed by an event.
- `src/ports/event_stream.rs` — websocket frame stream and handles.
- `src/ports/clock.rs` — injectable clock for expiry and markers.
- `src/adapters/tuta/event_wire.rs` — parse `type;json` websocket frames.
- `src/adapters/tuta/event_lookup.rs` — `TutaEventLookup`.
- `src/adapters/tuta/event_stream.rs` — URL builder, model versions, websocket client, close-code mapping.
- `src/adapters/tuta/generated_id.rs` — timestamp ⇄ generated id, batch expiry.
- `src/app/event_sync.rs` — `EventProcessor`.
- `src/app/watch.rs` — `WatchUseCase`, `BackoffPolicy`.
- `tests/event_sync.rs`, `tests/event_stream.rs`, `tests/watch.rs`.

Modify:

- `Cargo.toml` — `tokio-tungstenite`, `futures-util`, `urlencoding`, tokio `signal`/`net`.
- `src/domain/mod.rs`, `src/ports/mod.rs`, `src/adapters/tuta/mod.rs`, `src/app/mod.rs`.
- `src/domain/state.rs` — `StateChange`.
- `src/ports/state_store.rs` — `apply_batch`, `remove_mailbox`.
- `src/ports/session.rs` — `event_groups`, `events` defaults.
- `src/adapters/sqlite_state.rs` — batch transaction, mailbox rename/delete, transactional UID helper.
- `src/adapters/tuta/session.rs` — implement event group/stream hooks.
- `src/app/sync.rs` — reconcile deleted folders and propagate folder renames.
- `src/app/state_sync.rs` — expose shared state-store/sync helpers.
- `tests/support/mod.rs` — fake store batch behavior and fake event lookup/stream/session.
- `src/adapters/cli.rs`, `src/main.rs` — `watch` command and dispatch.
- `README.md`, `NOTES.md` — M4 usage and acceptance record.

---

### Task 1: Event domain types and websocket frame parser

**Files:**
- Create: `src/domain/event.rs`
- Modify: `src/domain/mod.rs`
- Create: `src/adapters/tuta/event_wire.rs`
- Modify: `src/adapters/tuta/mod.rs`
- Test: inline module in `src/adapters/tuta/event_wire.rs`

**Interfaces:**
- Consumes: `serde_json` and the numeric attribute ids of `WebsocketEntityData` (1484/1485/1486/2557/2558/1487) and `EntityUpdate` (463/464/466/467/624/2556/2617/2701/2618). Do **not** reuse the SDK structs: the Rust SDK models the `NumberString` wire fields as `i64`, but the server sends them as JSON strings (`"624":"0"`, `"2556":"97"`), which the SDK models cannot deserialize. Define a private raw struct instead.
- Produces:
  - `pub enum EntityOperation { Create, Update, Delete }` (derive `Debug, Clone, Copy, PartialEq, Eq`)
  - `pub struct EntityEvent { pub application: String, pub type_id: i64, pub list_id: String, pub element_id: String, pub operation: EntityOperation }` (derive `Clone, PartialEq, Eq`; no `Debug`)
  - `pub struct EventBatch { pub batch_id: String, pub owner_group_id: String, pub application_types_hash: String, pub events: Vec<EntityEvent> }` (derive `Clone, PartialEq, Eq`; no `Debug`)
  - `pub enum EventFrame { Batch(EventBatch), InitialSyncDone, Ignored }` (derive `Clone, PartialEq, Eq`; no `Debug`)
  - `pub const TUTANOTA_APP: &str = "tutanota";`
  - `pub const MAIL_TYPE_ID: i64 = 97;`
  - `pub const MAIL_SET_TYPE_ID: i64 = 429;`
  - `pub const MAIL_SET_ENTRY_TYPE_ID: i64 = 1450;`
  - `pub fn parse_frame(text: &str) -> Result<EventFrame>`

- [ ] **Step 1: Write the failing parser tests**

Use the real numeric attribute ids: `1485` batch id, `1486` owner, `1487` updates, `464` application, `466` list id, `467` element id, `624` operation, `2556` type id. A frame is `entityUpdate;<json>`.

```rust
#[test]
fn parses_entity_update_batch() {
    // Real wire shape: the server sends every NumberString field as a string.
    let json = r#"{"1484":"0","1485":"batch1","1486":"group1","2557":"7","2558":"hash","1487":[{"463":"u1","464":"tutanota","466":"list1","467":"mail1","624":"0","2556":"97","2617":null,"2701":null,"2618":null},{"463":"u2","464":"tutanota","466":"list1","467":"entry1","624":"2","2556":"1450","2617":null,"2701":null,"2618":null}]}"#;
    let frame = parse_frame(&format!("entityUpdate;{json}")).unwrap();
    let EventFrame::Batch(batch) = frame else { panic!("expected batch") };
    assert_eq!(batch.batch_id, "batch1");
    assert_eq!(batch.owner_group_id, "group1");
    assert_eq!(batch.events.len(), 2);
    assert_eq!(batch.events[0].operation, EntityOperation::Create);
    assert_eq!(batch.events[1].operation, EntityOperation::Delete);
    assert_eq!(batch.events[1].list_id, "list1");
    assert_eq!(batch.events[1].element_id, "entry1");
}

#[test]
fn accepts_the_same_batch_with_json_numbers() {
    let json = r#"{"1484":0,"1485":"batch1","1486":"group1","2557":7,"2558":"hash","1487":[{"463":null,"464":"tutanota","466":"list1","467":"mail1","624":0,"2556":97,"2617":null,"2701":null,"2618":null}]}"#;
    let EventFrame::Batch(batch) = parse_frame(&format!("entityUpdate;{json}")).unwrap() else { panic!() };
    assert_eq!(batch.events[0].type_id, 97);
    assert_eq!(batch.events[0].operation, EntityOperation::Create);
}

#[test]
fn ignores_other_message_types_and_bad_operations() {
    assert!(matches!(parse_frame("initialSyncDone;").unwrap(), EventFrame::InitialSyncDone));
    assert!(matches!(parse_frame("leaderStatus;{}").unwrap(), EventFrame::Ignored));
    let json = r#"{"1484":0,"1485":"b","1486":"g","2557":0,"2558":"h","1487":[{"463":null,"464":"tutanota","466":"l","467":"e","624":9,"2556":97,"2617":null,"2701":null,"2618":null}]}"#;
    let EventFrame::Batch(batch) = parse_frame(&format!("entityUpdate;{json}")).unwrap() else { panic!() };
    assert!(batch.events.is_empty());
}

#[test]
fn malformed_entity_update_is_a_fixed_error() {
    let error = parse_frame("entityUpdate;not-json").unwrap_err();
    assert_eq!(error.to_string(), "network error: invalid event message");
}
```

Also test the empty frame (`parse_frame("")` → `Ignored`) and `unreadCounterUpdate;{}` → `Ignored`.

- [ ] **Step 2: Run the tests to verify failure**

Run: `cargo test adapters::tuta::event_wire`
Expected: FAIL because the module does not exist.

- [ ] **Step 3: Implement the domain types and parser**

`parse_frame` splits once on the first `;`, trims nothing from the value, and:
- `entityUpdate` → deserialize a **private raw struct** (`serde_json`, unknown fields ignored) with the numeric attribute ids above. The number-like fields (`624` operation, `2556` type id) must go through a tolerant deserializer that accepts a JSON number **or** a numeric string, because the server sends them as strings. Map each update's `application`, `typeId`, `instanceListId`, `instanceId`; map `operation` 0/1/2 and silently drop other values; keep unknown apps/types so the processor decides. Never read or store `instance`/`blobInstance`/`patch`.
- `initialSyncDone` → `EventFrame::InitialSyncDone`.
- every other known or unknown type → `EventFrame::Ignored`.
- a malformed `entityUpdate` payload → `Error::Network("invalid event message".into())`; never include the raw payload.

Do not derive `Debug` on `EventBatch`/`EntityEvent` (they carry ids, and this keeps future PII out of logs).

- [ ] **Step 4: Run tests and checks**

Run: `cargo test adapters::tuta::event_wire && cargo fmt --check && cargo clippy --all-targets -- -D warnings`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/domain/event.rs src/domain/mod.rs src/adapters/tuta/event_wire.rs src/adapters/tuta/mod.rs
git commit -m "feat: parse websocket entity event batches"
```

---

### Task 2: Generated-id timestamps and batch expiry

**Files:**
- Create: `src/adapters/tuta/generated_id.rs`
- Modify: `src/adapters/tuta/mod.rs`
- Test: inline module in `src/adapters/tuta/generated_id.rs`

**Interfaces:**
- Produces:
  - `pub const BATCH_EXPIRY_MS: i64 = 45 * 24 * 60 * 60 * 1000;`
  - `pub fn timestamp_to_generated_id(timestamp_ms: i64) -> String`
  - `pub fn generated_id_timestamp(id: &str) -> Option<i64>`
  - `pub fn batch_is_expired(id: &str, now_ms: i64) -> bool`

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn timestamps_roundtrip_through_generated_ids() {
    for ts in [0_i64, 1, 1_700_000_000_000, 2_000_000_000_000] {
        let id = timestamp_to_generated_id(ts);
        assert_eq!(id.len(), 12, "generated ids are 12 base64ext chars");
        assert_eq!(generated_id_timestamp(&id), Some(ts));
    }
    assert_eq!(timestamp_to_generated_id(0), "------------");
    assert_eq!(timestamp_to_generated_id(1), "------0-----");
    assert_eq!(timestamp_to_generated_id(1_700_000_000_000), "NjEtLV------");
}

#[test]
fn decodes_real_server_batch_ids() {
    // Live batch id captured from the Tuta event bus (server bytes suffix is
    // ignored by the decoder). It must decode to its capture time.
    assert_eq!(generated_id_timestamp("P6f_Itx----9"), Some(1_794_953_789_053));
    // Markers produced by the earlier wrong-shift encoder decode to 1973 and
    // must be treated as expired so the next watch start resyncs.
    assert_eq!(generated_id_timestamp("0cTi85rc----"), Some(112_184_562_103));
    assert!(batch_is_expired("0cTi85rc----", 1_794_953_789_053));
}

#[test]
fn rejects_invalid_generated_ids() {
    assert_eq!(generated_id_timestamp(""), None);
    assert_eq!(generated_id_timestamp("not-an-id"), None);
    assert_eq!(generated_id_timestamp("............"), None);
}

#[test]
fn expiry_is_strictly_older_than_45_days() {
    let now = 2_000_000_000_000;
    let edge = timestamp_to_generated_id(now - BATCH_EXPIRY_MS);
    let old = timestamp_to_generated_id(now - BATCH_EXPIRY_MS - 1);
    assert!(!batch_is_expired(&edge, now));
    assert!(batch_is_expired(&old, now));
    assert!(batch_is_expired("garbage", now), "unparseable markers fail closed");
}
```

- [ ] **Step 2: Run the tests to verify failure**

Run: `cargo test adapters::tuta::generated_id`
Expected: FAIL because the module does not exist.

- [ ] **Step 3: Implement the base64ext codec**

Tuta's `timestampToHexGeneratedId` builds the id as `(timestamp_ms * 4)` in hex followed by **seven** hex suffix digits (five zeros plus the two server digits) padded to 18 — a 72-bit value of `(timestamp_ms * 4) << 28`, standard-base64 encoded, then mapped onto the sortable base64ext alphabet:

```text
std: ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
ext: -0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz
```

Encode: write `((timestamp_ms as u128) * 4) << 28` as nine big-endian bytes (server bytes zero; clamp negative timestamps to zero), standard-base64 encode, map the alphabet. Decode by reversing the alphabet, padding to a multiple of four, base64-decoding exactly nine bytes, then `n = first five bytes as a big-endian u40` and `timestamp = n * 4 + (byte5 >> 6)` — exactly the reference client's `generatedIdToTimestamp`. Ignore the trailing server bytes. `batch_is_expired` returns `true` when decoding fails.

- [ ] **Step 4: Run tests and checks**

Run: `cargo test adapters::tuta::generated_id && cargo fmt --check && cargo clippy --all-targets -- -D warnings`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/adapters/tuta/generated_id.rs src/adapters/tuta/mod.rs
git commit -m "feat: map event batch ids to timestamps"
```

---

### Task 3: Transactional batch application and folder reconciliation

**Files:**
- Modify: `src/domain/state.rs`
- Modify: `src/ports/state_store.rs`
- Modify: `src/adapters/sqlite_state.rs`
- Modify: `src/app/sync.rs`
- Modify: `tests/support/mod.rs`
- Test: inline modules and `tests/sync.rs`

**Interfaces:**
- Consumes: existing `StateStore`, `Folder`, `MessageHeader`, `MailboxId`.
- Produces:
  - `pub struct MailPlacement { pub mailbox_list_id: String, pub header: MessageHeader }` (no `Debug`)
  - `pub enum StateChange { UpsertMailbox { folder: Folder, uidvalidity: u32 }, UpsertHeader { mailbox_list_id: String, header: MessageHeader }, RemoveHeaderEverywhere { element_id: String }, RemoveOtherPlacements { element_id: String, keep_list_ids: Vec<String> } }`
  - `StateStore::apply_batch(&self, account_id: i64, group_id: &str, batch_id: &str, changes: &[StateChange]) -> Result<()>`
  - `StateStore::remove_mailbox(&self, account_id: i64, mailbox: MailboxId) -> Result<()>`
  - `SyncReport` keeps its fields; folder reconciliation is observable in the store.

- [ ] **Step 1: Write the failing SQLite tests**

Add tests in `src/adapters/sqlite_state.rs`:

```rust
#[tokio::test]
async fn apply_batch_writes_changes_and_last_batch_in_one_transaction() {
    let store = SqliteStateStore::open_in_memory().await.unwrap();
    let account = store.upsert_account("owner@example.invalid").await.unwrap();
    let folder = Folder { list_id: "list".into(), name: "Inbox".into(), kind: FolderKind::Inbox };
    let header = header("mail-list", "e1");
    store.apply_batch(account, "group", "batch-1", &[
        StateChange::UpsertMailbox { folder, uidvalidity: 7 },
        StateChange::UpsertHeader { mailbox_list_id: "list".into(), header },
    ]).await.unwrap();

    let mailbox = store.mailboxes(account).await.unwrap().remove(0);
    assert_eq!(mailbox.uidvalidity, 7);
    assert_eq!(store.messages(mailbox.id).await.unwrap()[0].uid, 1);
    assert_eq!(store.last_batch(account, "group").await.unwrap().as_deref(), Some("batch-1"));
}

#[tokio::test]
async fn apply_batch_rolls_back_updates_when_a_later_change_fails() {
    let store = SqliteStateStore::open_in_memory().await.unwrap();
    let account = store.upsert_account("owner@example.invalid").await.unwrap();
    sqlx::query("CREATE TRIGGER fail_insert BEFORE INSERT ON messages BEGIN SELECT RAISE(ABORT, 'forced'); END")
        .execute(store.pool()).await.unwrap();
    let folder = Folder { list_id: "list".into(), name: "Inbox".into(), kind: FolderKind::Inbox };
    let error = store.apply_batch(account, "group", "batch-1", &[
        StateChange::UpsertMailbox { folder, uidvalidity: 7 },
        StateChange::UpsertHeader { mailbox_list_id: "list".into(), header: header("mail-list", "e1") },
    ]).await.unwrap_err();
    assert!(matches!(error, Error::Storage(_)));
    assert!(store.mailboxes(account).await.unwrap().is_empty());
    assert_eq!(store.last_batch(account, "group").await.unwrap(), None);
}
```

Add:
- `apply_batch_persists_empty_batches` (empty changes still writes `last_batch`).
- `apply_batch_assigns_new_uids_in_received_order`: two new headers in reverse time order in one batch; the older header gets UID 1 and the newer UID 2.
- `apply_batch_removes_other_placements`: two mailboxes, same element id, `keep_list_ids` only the first; second row gone.
- `apply_batch_removes_a_mailbox_and_its_messages` via `remove_mailbox`.
- `apply_batch_skips_unknown_mailbox`: `UpsertHeader` whose `mailbox_list_id` is not stored does not error and writes no row.
- `upsert_mailbox_updates_name_and_kind_without_touching_uid_state`.
- `sync_removes_mailboxes_missing_from_source` in `tests/sync.rs`: pre-store two mailboxes/messages, source returns one folder, after `sync` the other mailbox and its messages are gone.

- [ ] **Step 2: Run the tests to verify failure**

Run: `cargo test adapters::sqlite_state && cargo test --test sync`
Expected: FAIL because `apply_batch`, `remove_mailbox`, and folder reconciliation do not exist.

- [ ] **Step 3: Implement the SQLite batch transaction**

- Extract the body of `assign_uid` into `async fn assign_uid_in<'e, E: Executor<'e, Database = Sqlite>>(&self, executor: E, mailbox: MailboxId, header: &MessageHeader) -> Result<u32>`; keep `assign_uid` as `begin` + helper + `commit`.
- `apply_batch` begins one transaction, applies changes, then calls the `last_batch` upsert with the same executor, then commits. Apply all `UpsertMailbox` changes first, then every other change in its original order, so a new folder and its mail can arrive in the same batch regardless of update order. Within the header pass, sort `UpsertHeader` changes by `(mailbox_list_id, header.received_at_ms, header.element_id)` so new UIDs follow arrival order; existing UIDs are untouched.
- `UpsertHeader` resolves the mailbox by `(account_id, mailbox_list_id)`. `header.list_id` is the Mail's own list id and is stored in `messages.tuta_list_id` for later `content()` reloads; it is never used to resolve the mailbox. If the mailbox is absent, skip silently. Existing header update keeps the established partial/complete envelope rules.
- `RemoveHeaderEverywhere` deletes `messages` for the account by `tuta_element_id`.
- `RemoveOtherPlacements` deletes rows for the element id whose mailbox `list_id` is not in `keep_list_ids`; build the `NOT IN` placeholders with runtime SQL.
- `RemoveMailbox`/`remove_mailbox` delete the mailbox's messages then the mailbox row, in one transaction.
- Change `upsert_mailbox` to `ON CONFLICT(account_id, list_id) DO UPDATE SET name = excluded.name, kind = excluded.kind`; never touch `uidvalidity`/`next_uid`.
- `SyncEngine::sync` after the folder loop removes stored mailboxes whose `list_id` is not in the source list. Do this only after `source.folders()` succeeded.

Mirror all of this in `FakeStateStore` so later tests observe the same semantics: `apply_batch` mutates its maps and records `last_batch`; `remove_mailbox` deletes the mailbox and its messages. Keep `calls` entries descriptive (`"apply_batch"`, `"remove_mailbox"`).

- [ ] **Step 4: Run tests and checks**

Run: `cargo test && cargo fmt --check && cargo clippy --all-targets -- -D warnings`
Expected: PASS, including the existing M3 tests.

- [ ] **Step 5: Commit**

```bash
git add src/domain/state.rs src/ports/state_store.rs src/adapters/sqlite_state.rs src/app/sync.rs tests/support/mod.rs tests/sync.rs
git commit -m "feat: apply event batches transactionally"
```

---

### Task 4: Event entity lookup

**Files:**
- Create: `src/ports/event_lookup.rs`
- Modify: `src/ports/mod.rs`
- Create: `src/adapters/tuta/event_lookup.rs`
- Modify: `src/adapters/tuta/mod.rs`
- Test: inline module in `src/adapters/tuta/event_lookup.rs`; fake in `tests/support/mod.rs`

**Interfaces:**
- Consumes: `LoggedInSdk::mail_facade().get_crypto_entity_client()`, `header_from_parts`, `folder_from_parts`, `mail_is_intact`.
- Produces:
  - `#[async_trait] pub trait EventLookup: Send + Sync` with:
    - `async fn headers_for_mail(&self, mail_list_id: &str, mail_element_id: &str) -> Result<Option<Vec<MailPlacement>>>`
    - `async fn header_for_entry(&self, entry_list_id: &str, entry_element_id: &str) -> Result<Option<MailPlacement>>`
    - `async fn folder(&self, set_list_id: &str, set_element_id: &str) -> Result<Option<Folder>>`
  - `pub struct TutaEventLookup { logged: Arc<LoggedInSdk> }` with `new`.

- [ ] **Step 1: Write the failing helper test**

Add a pure helper `fn dedupe_placements(placements: Vec<MailPlacement>) -> Vec<MailPlacement>` that keeps the first placement per `mailbox_list_id`, and test:

```rust
#[test]
fn deduplicates_placements_for_the_same_mailbox() {
    let placements = dedupe_placements(vec![
        placement("list-a", "mail-list", "m1"),
        placement("list-a", "mail-list", "m1"),
        placement("list-b", "mail-list", "m1"),
    ]);
    assert_eq!(placements.len(), 2);
    assert_eq!(placements[0].mailbox_list_id, "list-a");
    assert_eq!(placements[1].mailbox_list_id, "list-b");
}
```

- [ ] **Step 2: Run the test to verify failure**

Run: `cargo test adapters::tuta::event_lookup`
Expected: FAIL because the module does not exist.

- [ ] **Step 3: Implement `TutaEventLookup`**

- `headers_for_mail`: load `Mail` by `IdTupleGenerated::new(GeneratedId(mail_list_id), GeneratedId(mail_element_id))`. If `mail_is_intact` is false, return `Ok(None)` so the processor skips it and keeps the existing row. `Mail.sets` is a `ListElementAssociationGenerated` to **`MailSet` (type 429)**, not to `MailSetEntry` (confirmed by the pinned type model: field 1465, `refTypeId: 429`). For each `mail.sets` tuple, load the `MailSet`; its `entries` value is the folder's entries list id, which becomes `MailPlacement.mailbox_list_id`. Build the header with `header_from_parts(mail_id.list_id, mail_element_id, mail.receivedDate, mail.subject, mail.sender, mail.firstRecipient, mail.unread)`; `mail_id.list_id` is the Mail's own list id stored in `messages.tuta_list_id`, never the mailbox id. Skip sets whose `entries` list id is empty; run `dedupe_placements` and return `Ok(Some(placements))`, where an empty vector means the mail genuinely has no placements. If any placement set fails to load, return an error for the whole mail instead of returning a partial placement list, so the processor never removes a folder because one set could not be read.
- `header_for_entry`: load `MailSetEntry` by `IdTupleCustom::new(GeneratedId(entry_list_id), CustomId(entry_element_id))`, then its `Mail`. Return `None` when the mail is not intact or has no `_id`. Return `MailPlacement { mailbox_list_id: entry_list_id.to_string(), header }`, where the header's `list_id` is the Mail's own list id and its `element_id` is the Mail's element id (never the entry id).
- `folder`: load `MailSet` by `IdTupleGenerated::new(GeneratedId(set_list_id), GeneratedId(set_element_id))` and return `folder_from_parts(set.entries.as_str(), &set.name, set.folderType)`.
- Map every SDK failure to `Error::Network("event entity unavailable".into())`; no ids, addresses, or subjects in the error.

Add a `FakeEventLookup` to `tests/support/mod.rs` with maps keyed by the three tuple pairs plus an optional failure flag. Builders return `MailPlacement` and preserve the three-branch contract (`Ok(None)` default).

- [ ] **Step 4: Run tests and checks**

Run: `cargo test adapters::tuta::event_lookup && cargo fmt --check && cargo clippy --all-targets -- -D warnings`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/ports/event_lookup.rs src/ports/mod.rs src/adapters/tuta/event_lookup.rs src/adapters/tuta/mod.rs tests/support/mod.rs
git commit -m "feat: reload entities for event updates"
```

---

### Task 5: Event processor

**Files:**
- Create: `src/app/event_sync.rs`
- Modify: `src/app/mod.rs`
- Test: `tests/event_sync.rs`

**Interfaces:**
- Consumes: `EventBatch`, `EventLookup`, `MailPlacement`, `StateStore::apply_batch`, `StateChange`, `MAIL_TYPE_ID`, `MAIL_SET_TYPE_ID`, `MAIL_SET_ENTRY_TYPE_ID`.
- Produces:
  - `pub struct EventReport { pub changes: usize, pub skipped: usize }`
  - `pub struct EventProcessor { pub store: Arc<dyn StateStore> }` with `new` and
    `pub async fn apply(&self, account_id: i64, lookup: &dyn EventLookup, uidvalidity: u32, batch: &EventBatch) -> Result<EventReport>`.

- [ ] **Step 1: Write the failing processor tests**

In `tests/event_sync.rs`, pre-populate `FakeStateStore` and use `FakeEventLookup`:

```rust
#[tokio::test]
async fn mail_set_entry_create_assigns_a_uid() {
    let store = Arc::new(FakeStateStore::new());
    let account = store.upsert_account("owner@example.invalid").await.unwrap();
    store.upsert_mailbox(account, &folder("list-a"), 7).await.unwrap();
    let lookup = FakeEventLookup::new().with_entry_placement("list-a", "entry-1", placement("list-a", "mail-list", "mail-1"));
    let batch = batch(vec![event("tutanota", MAIL_SET_ENTRY_TYPE_ID, "list-a", "entry-1", EntityOperation::Create)]);

    let report = EventProcessor::new(store.clone()).apply(account, &lookup, 7, &batch).await.unwrap();

    assert_eq!(report.changes, 1);
    let mailbox = store.mailbox_id(account, "list-a");
    assert_eq!(store.uid_for(mailbox, "mail-list", "mail-1"), Some(1));
    assert_eq!(store.last_batches_for(account).get("group-1").map(String::as_str), Some("batch-1"));
}
```

Add tests:
- `mail_set_create_upserts_a_folder`.
- `mail_update_adds_every_placement_and_removes_old_ones`: lookup returns placements in mailboxes `list-a` and `list-b`; store already has `list-a`, `list-b`, `list-c` for the same element; after apply, `list-c` row is gone and `list-a`/`list-b` keep their UIDs.
- `mail_update_with_no_placements_removes_the_mail`.
- `unreadable_mail_is_skipped_and_keeps_the_existing_row`: lookup returns `Ok(None)`; the stored row survives, `skipped == 1`, and the batch is persisted.
- `mail_delete_removes_every_placement`.
- `lookup_failure_is_skipped_and_the_batch_is_still_persisted`: fake lookup errors; `skipped == 1`, `changes == 0`, `last_batch` advanced.
- `unknown_types_and_entry_deletes_are_skipped_but_persisted`.
- `reapplying_the_same_batch_does_not_change_uids` (apply twice; compare `uid_for`).

- [ ] **Step 2: Run the tests to verify failure**

Run: `cargo test --test event_sync`
Expected: FAIL because `EventProcessor` does not exist.

- [ ] **Step 3: Implement `EventProcessor::apply`**

Process events in order. First upsert folders immediately, then coalesce all mail events per `element_id` so one batch never emits both a removal and an upsert for the same element. Use a map `element_id -> MailAction`, where:

```text
enum MailAction {
    Placements(Vec<MailPlacement>), // authoritative placements for this element
    Delete,                         // the Mail itself was deleted
}
```

- `application == TUTANOTA_APP`, `type_id == MAIL_SET_TYPE_ID`, `Create|Update`: `lookup.folder(list_id, element_id)`; `Some(folder)` → `UpsertMailbox`; `None` or error → skip.
- `MAIL_SET_TYPE_ID`, `Delete`: skip (folder deletion is reconciled by `sync`).
- `MAIL_TYPE_ID`, `Create|Update`: `lookup.headers_for_mail(list_id, element_id)`. `Ok(Some(placements))` replaces the element's action with `Placements(placements)`. `Ok(None)` or `Err` → skip and keep the existing action/row.
- `MAIL_TYPE_ID`, `Delete`: set the element's action to `Delete`.
- `MAIL_SET_ENTRY_TYPE_ID`, `Create|Update`: `lookup.header_for_entry(list_id, element_id)`; `Some(placement)` adds that placement to the element's `Placements` (create the entry if absent; keep existing placements; dedupe by `mailbox_list_id`); `None` or error → skip.
- `MAIL_SET_ENTRY_TYPE_ID`, `Delete`: skip; the accompanying `Mail` update/sync reconciles placement.
- anything else: skip.

After the event loop, turn each `MailAction` into changes:
- `Delete` → `RemoveHeaderEverywhere { element_id }`.
- `Placements(empty)` → `RemoveHeaderEverywhere { element_id }`.
- `Placements(placements)` → one `UpsertHeader { mailbox_list_id, header }` per placement plus one `RemoveOtherPlacements { element_id, keep_list_ids }` with the placements' mailbox list ids.

Then call `store.apply_batch(account_id, &batch.owner_group_id, &batch.batch_id, &changes)` exactly once, even when `changes` is empty. Return `changes.len()` and the skipped count. Never log ids, subjects, or addresses.

- [ ] **Step 4: Run tests and checks**

Run: `cargo test --test event_sync && cargo test && cargo fmt --check && cargo clippy --all-targets -- -D warnings`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/app/event_sync.rs src/app/mod.rs tests/event_sync.rs tests/support/mod.rs
git commit -m "feat: apply entity events to the header index"
```

---

### Task 6: Websocket event stream and session hooks

**Files:**
- Modify: `Cargo.toml`
- Create: `src/ports/event_stream.rs`
- Modify: `src/ports/mod.rs`
- Modify: `src/ports/session.rs`
- Create: `src/adapters/tuta/event_stream.rs`
- Modify: `src/adapters/tuta/mod.rs`
- Modify: `src/adapters/tuta/session.rs`
- Test: inline module in `src/adapters/tuta/event_stream.rs`, `tests/event_stream.rs`

**Interfaces:**
- Produces:
  - `#[async_trait] pub trait EventStream: Send { async fn next_frame(&mut self) -> Result<EventFrame>; }`
  - `pub struct EventHandles { pub stream: Box<dyn EventStream>, pub lookup: Arc<dyn EventLookup> }`
  - `Session::event_groups(&self) -> Vec<String>` (default `Vec::new()`)
  - `Session::events(&self, last_batches: &HashMap<String, String>, now_ms: i64) -> Result<EventHandles>` as an `async fn` under the trait's existing `#[async_trait]` (default `Err(Error::Unsupported("events not implemented".into()))`)
  - `pub struct TutaEventStream` with `pub async fn connect(url: &str) -> Result<Self>`
  - `pub fn event_url(base_url: &str, user_id: &str, access_token: &str, groups: &[(String, String)], model_versions: &str, client_version: &str) -> Result<String>`
  - `pub fn model_versions(models: &ApplicationModels) -> Option<String>`
  - `pub fn close_error(code: Option<u16>) -> Error`
  - `pub fn is_event_group(group_type: Option<i64>) -> bool` (false only for `Some(2)`, the mailing-list group type)

- [ ] **Step 1: Add dependencies and write the failing URL/close tests**

`Cargo.toml`:

```toml
tokio = { version = "1", features = ["rt-multi-thread", "macros", "time", "signal", "net"] }
tokio-tungstenite = { version = "0.24", features = ["rustls-tls-webpki-roots"] }
futures-util = "0.3"
urlencoding = "2"
```

Tests:

```rust
#[test]
fn builds_authenticated_event_url() {
    let url = event_url(
        "https://app.tuta.com",
        "user1",
        "a+b/c=",
        &[("group1".into(), "batch1".into()), ("group2".into(), "batch2".into())],
        "158.118",
        "369.261113.0",
    ).unwrap();
    assert!(url.starts_with("wss://app.tuta.com/event?"));
    assert!(url.contains("modelVersions=158.118"));
    assert!(url.contains("clientVersion=369.261113.0"));
    assert!(url.contains("userId=user1"));
    assert!(url.contains("accessToken=a%2Bb%2Fc%3D"));
    assert!(url.contains("clientName=tuta-bridge"));
    assert!(url.contains("groupsToLastEventBatchIds=group1=batch1;group2=batch2;"));
}

#[test]
fn loopback_uses_plain_websocket_and_omits_empty_groups() {
    let url = event_url("http://127.0.0.1:9000", "u", "t", &[], "1.2", "3.4").unwrap();
    assert!(url.starts_with("ws://127.0.0.1:9000/event?"));
    assert!(!url.contains("groupsToLastEventBatchIds"));
}

#[test]
fn auth_and_session_close_codes_are_fatal() {
    assert!(matches!(close_error(Some(4403)), Error::Login(_)));
    assert!(matches!(close_error(Some(4440)), Error::Login(_)));
    assert!(matches!(close_error(Some(4470)), Error::Login(_)));
    assert!(matches!(close_error(None), Error::Network(_)));
}
```

Add a `model_versions` test with a constructed `ApplicationModels` containing `Sys` version `"158"` and `Tutanota` version `"118"` → `Some("158.118")`. Add `is_event_group_skips_only_mailing_lists` asserting `false` for `Some(2)` and `true` for `None`, `Some(0)`, and `Some(5)`.

- [ ] **Step 2: Run the tests to verify failure**

Run: `cargo test adapters::tuta::event_stream`
Expected: FAIL because the module and dependencies are missing.

- [ ] **Step 3: Implement URL, model versions, close mapping, and stream**

- `event_url`: replace `https://` with `wss://` and `http://` with `ws://`; reject any other prefix with `Error::Config("event URL requires http or https".into())`. Percent-encode every query value with `urlencoding::encode`. The fixed parameters are `modelVersions`, `clientVersion`, `userId`, `accessToken`, `clientName=tuta-bridge`, and the group map. Keep group order and skip duplicate group ids.
- `model_versions`: read `ApplicationModels.apps` for `AppName::Sys` and `AppName::Tutanota`; return `"{sys.version}.{tutanota.version}"`.
- `TutaEventStream::connect`: `tokio_tungstenite::connect_async(url)`; map failures to `Error::Network("event stream connect failed")`.
- `next_frame`: on `Text`, call `parse_frame`; on `Ping`, reply with `Pong` and continue; on `Close(frame)`, return `close_error(Some(frame.code.into()))`; on transport error → `Error::Network("event stream disconnected")`; binary/other frames are ignored.
- `close_error`: 4403/4440/4470/4471/4472 → `Error::Login("event stream not authorized; run login again")`; 4429 → `Error::Network("event stream rate limited")`; everything else → `Error::Network("event stream closed")`.
- `TutaEventStream` must not derive `Debug`.

- [ ] **Step 4: Implement session hooks**

In `TutaSession`:
- `event_groups`: `logged.get_user()` → `memberships` where `groupType != Some(2)` (mailing lists) plus `userGroup`, mapped to `membership.group.0`, deduplicated preserving order.
- `events`: for each group in `event_groups`, use `last_batches.get(group)` or `timestamp_to_generated_id((now_ms - 5_000).max(0))`. Compute `model_versions` from `logged.type_model_provider.client_app_models`. Build the URL with `self.base_url`, `self.info.user_id`, `self.access_token`, and `TUTA_CLIENT_VERSION`. Connect and return `EventHandles { stream, lookup: Arc::new(TutaEventLookup::new(Arc::clone(&self.logged))) }`.
- Add `pub const TUTA_CLIENT_VERSION: &str = "369.261113.0";` next to the URL builder, with a comment that it must match the pinned Tuta SDK revision.

- [ ] **Step 5: Write the loopback websocket integration test**

In `tests/event_stream.rs`, bind `TcpListener` on `127.0.0.1:0`, accept one connection with `tokio_tungstenite::accept_async`, send `entityUpdate;<json>`, then close. Assert `next_frame` returns the batch. Add a second server that sends `Close(CloseFrame { code: 4403, reason: "".into() })`; assert `next_frame` returns `Error::Login(_)`.

- [ ] **Step 6: Run tests and checks**

Run: `cargo test adapters::tuta::event_stream && cargo test --test event_stream && cargo fmt --check && cargo clippy --all-targets -- -D warnings`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml Cargo.lock src/ports/event_stream.rs src/ports/mod.rs src/ports/session.rs src/adapters/tuta/event_stream.rs src/adapters/tuta/mod.rs src/adapters/tuta/session.rs tests/event_stream.rs
git commit -m "feat: connect to the Tuta event bus"
```

---

### Task 7: Watch use case and CLI

**Files:**
- Create: `src/ports/clock.rs`
- Modify: `src/ports/mod.rs`
- Create: `src/app/watch.rs`
- Modify: `src/app/mod.rs`
- Modify: `src/app/state_sync.rs`
- Modify: `src/adapters/cli.rs`
- Modify: `src/main.rs`
- Modify: `tests/support/mod.rs`
- Test: `tests/watch.rs`, inline module in `src/adapters/cli.rs`

**Interfaces:**
- Produces:
  - `pub trait Clock: Send + Sync { fn now_ms(&self) -> i64; }`
  - `pub struct BackoffPolicy { pub first_ms: u64, pub second_ms: u64, pub max_ms: u64 }` with `production()` and `delay_ms(attempt: u32) -> u64`
  - `pub struct WatchUseCase { pub factory: Arc<dyn SessionFactory>, pub credentials: Arc<dyn CredentialStore>, pub config_path: PathBuf, pub state: Arc<dyn StateStore>, pub clock: Arc<dyn Clock>, pub backoff: BackoffPolicy }`
  - `WatchUseCase::run(&self) -> Result<()>` and `WatchUseCase::run_until<F: Future<Output = ()>>(&self, stop: F) -> Result<()>`
  - `pub fn is_fatal(error: &Error) -> bool`
  - `pub async fn open_state_store() -> Result<Arc<dyn StateStore>>` (moved from private in `state_sync.rs`)
  - `pub(crate) fn current_uidvalidity() -> u32`, `pub(crate) fn next_uidvalidity(...)`, `pub(crate) async fn sync_with(...)`, `pub(crate) async fn resync_with(...)`.
  - `Command::Watch` with help text `"Stream Tuta events and update the local index."`.

- [ ] **Step 1: Write the failing CLI and policy tests**

CLI parser:

```rust
#[test]
fn parses_watch_command() {
    assert!(matches!(parse_from(["tuta-bridge", "watch"]).unwrap().command, Command::Watch));
}
```

Policy:

```rust
#[test]
fn backoff_grows_and_caps() {
    let policy = BackoffPolicy { first_ms: 5_000, second_ms: 20_000, max_ms: 60_000 };
    assert_eq!(policy.delay_ms(1), 5_000);
    assert_eq!(policy.delay_ms(2), 20_000);
    assert_eq!(policy.delay_ms(3), 60_000);
    assert_eq!(policy.delay_ms(20), 60_000);
}

#[test]
fn only_network_errors_are_retried() {
    assert!(!is_fatal(&Error::Network("x".into())));
    assert!(is_fatal(&Error::Login("x".into())));
    assert!(is_fatal(&Error::Storage("x".into())));
    assert!(is_fatal(&Error::MissingCredentials));
}
```

- [ ] **Step 2: Run the tests to verify failure**

Run: `cargo test adapters::cli::tests::parses_watch_command && cargo test app::watch`
Expected: FAIL because the command and module do not exist.

- [ ] **Step 3: Implement `WatchUseCase::run_until`**

Sequence:

1. Load `Config`, active account, and `StoredCredentials`; resume the session. Never call `login` or the prompt.
2. `account_id = state.upsert_account(&credentials.login)`.
3. `groups = session.event_groups()`; empty → `Error::Network("no event groups".into())`.
4. Baseline:
   - Read `state.mailboxes(account_id)` and `state.last_batch(account_id, group)` for every group.
   - If any marker is `batch_is_expired(marker, clock.now_ms())`, call `resync_with(Arc::clone(&state), session.mail(), account_id, current_uidvalidity())`, clear the in-memory markers, and skip the ordinary sync because `resync_with` already reset and re-synced.
   - Else if there are no mailboxes or any group has no marker, call `sync_with(...)`.
   - After the sync/reset, for every group without a marker generate `timestamp_to_generated_id((now_ms - 5_000).max(0))`, persist with `set_last_batch`, and add it to the in-memory map.
5. `event_uidvalidity = next_uidvalidity(max stored uidvalidity, current_uidvalidity())?`.
6. Reconnect loop:
   - `handles = session.events(&batches, clock.now_ms()).await`; keep `lookup`. Fatal errors return; `Error::Network` (including a failed websocket *connect*) counts the attempt, sleeps the backoff with `tokio::select!` against `stop`, and continues, so an outage longer than one delay keeps `watch` alive instead of exiting.
   - Inner loop with `tokio::select!` between `stop` and `stream.next_frame()`.
   - `Batch(batch)` → `EventProcessor::apply(account_id, lookup.as_ref(), event_uidvalidity, &batch).await?`; update `batches` with the batch's owner group and batch id; print `applied {changes} changes` only when `changes > 0`.
   - `InitialSyncDone` → print `event stream caught up`.
   - `Ignored` → continue.
   - `Err(e)` where `is_fatal(&e)` → return `Err(e)`.
   - `Err(e)` → break the inner loop, print a fixed line with the attempt delay, and sleep with `tokio::select!` against `stop`.
   - Any successful frame resets the attempt counter to zero.
7. `run` calls `run_until` with `tokio::signal::ctrl_c()` and returns `Ok(())` on Ctrl-C. Print `watching for Tuta events; press Ctrl-C to stop` before the loop.

No URL, token, subject, address, or batch id in output.

- [ ] **Step 4: Write the watch tests**

Use a local `FakeEventSession` in `tests/support/mod.rs` with:
- fixed `event_groups`;
- a `Mutex<VecDeque<Vec<Result<EventFrame>>>>` of scripts, one per `events()` call;
- a `FakeEventLookup`;
- a `FakeMailSource` for the baseline sync.

Tests in `tests/watch.rs` with a temp `Config` file and `FakeStore` credentials:

```rust
#[tokio::test]
async fn applies_batches_and_persists_the_batch_id() {
    // pre-populate store with one mailbox and a current batch marker
    // script: Batch(entry create) -> InitialSyncDone -> Err(Error::Login("stop"))
    let error = use_case.run_until(std::future::pending()).await.unwrap_err();
    assert!(matches!(error, Error::Login(_)));
    assert_eq!(store.last_batch(account, "group1").await.unwrap().as_deref(), Some("batch-2"));
    assert_eq!(store.uid_for(mailbox, "list-a", "mail-1"), Some(1));
}
```

Add:
- `reconnects_from_the_latest_batch`: first script returns `Err(Error::Network(...))`, second returns a batch; `backoff.first_ms = 0`; assert `events()` was called twice and the second call saw `batch-1`.
- `connect_failure_is_retried_with_backoff`: the first `events()` call returns `Err(Error::Network(...))` before any frame (scripted connect failure); the second returns a batch and then a fatal error; assert two calls and one applied batch.
- `stop_future_is_honored`: a stream whose `next_frame` never resolves, with `run_until(tokio::time::sleep(Duration::ZERO))`, returns `Ok(())` promptly.
- `expired_marker_triggers_resync_before_events`: pre-store an old marker; fake mail source has a folder/header; assert `reset_account`/`apply_batch`/UIDVALIDITY changed and the marker is replaced.
- `missing_marker_runs_a_baseline_sync`: store has a mailbox but no marker; assert the fake mail source was synced and the marker persisted.
- `auth_failure_stops_without_retrying`: `Err(Error::Login)` on the first frame; assert one `events()` call.

- [ ] **Step 5: Wire the CLI and main**

- `Command::Watch` in `cli.rs`.
- `main`: in the `Watch` arm open the state store with `open_state_store().await?`, build `WatchUseCase` with `TutaSessionFactory`, `KeyringCredentialStore`, `config_path`, `Arc::new(SystemClock)`, and `BackoffPolicy::production()`, then `run().await`.
- Add `SystemClock` (already present in `main.rs` for the SDK) implementing `Clock` with `now_ms`.

- [ ] **Step 6: Run tests and checks**

Run: `cargo test && cargo fmt --check && cargo clippy --all-targets -- -D warnings`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/ports/clock.rs src/ports/mod.rs src/app/watch.rs src/app/mod.rs src/app/state_sync.rs src/adapters/cli.rs src/main.rs tests/support/mod.rs tests/watch.rs
git commit -m "feat: watch Tuta events and update the index"
```

---

### Task 8: Documentation and M4 manual acceptance

**Files:**
- Modify: `README.md`
- Modify: `NOTES.md`

**Interfaces:**
- Consumes: all previous tasks.
- Produces: documented `watch` behavior and an acceptance record.

- [ ] **Step 1: Document the command and protocol**

README:
- Add `watch` to the command list and describe the one-backend model.
- State that `watch` reconnects with backoff, uses persisted batch markers, runs a baseline sync when state or markers are missing, and resyncs when a marker is older than 45 days.
- State the limits: folder deletion is reconciled by the next `sync`; `MailSetEntry` deletes rely on the accompanying `Mail` update or the next sync; no body content is fetched or stored.
- Keep the existing permission and no-content guarantees.

NOTES:
- Record the websocket endpoint shape (`/event`, `groupsToLastEventBatchIds`, `clientName=tuta-bridge`), message types, the 45-day expiry, close-code mapping, and the numeric type ids used (`Mail 97`, `MailSet 429`, `MailSetEntry 1450`).
- Record that `clientVersion` must be bumped together with the SDK pin.
- Never write tokens or URLs with tokens into NOTES.

- [ ] **Step 2: Verify formatting and the full suite**

Run: `cargo test && cargo fmt --check && cargo clippy --all-targets -- -D warnings`
Expected: PASS.

- [ ] **Step 3: Commit documentation**

```bash
git add README.md NOTES.md
git commit -m "docs: document the event bus"
```

- [ ] **Step 4: Manual acceptance (requires a real account)**

Run from the repository root:

```bash
source "$HOME/.cargo/env"
cargo run -- sync        # baseline index and batch markers
cargo run -- watch       # leave running
```

While `watch` runs, send a mail to the account from another client. Expected within a few seconds: `applied N changes`, and these queries show the new header:

```bash
sqlite3 "$HOME/.local/share/tuta-bridge/state.sqlite3" \
  "select count(*), max(received_at_ms) from messages;"
sqlite3 "$HOME/.local/share/tuta-bridge/state.sqlite3" \
  "select group_id, batch_id from sync_state order by group_id;"
```

Then:
1. Stop `watch` with Ctrl-C, wait a minute, send another mail, restart `watch`; the mail must appear without duplicating UIDs.
2. Record a batch marker older than 45 days (for example `timestamp_to_generated_id(now - 46 days)` through a one-off `sqlite3` update), start `watch`; it must resync and change `uidvalidity`.
3. Confirm `pragma table_info(messages);` still has no body/attachment/`.eml` columns.
4. Confirm no token or subject appears in `watch` output.

Record the results in `NOTES.md` under `## M4 manual acceptance`, then commit:

```bash
git add NOTES.md
git commit -m "docs: record M4 manual acceptance"
```

---

## Self-Review Notes

- **Spec coverage:** Section 7 items map to Task 6 (one websocket), Task 3 (batch id in the same transaction), Task 2/Task 7 (45-day expiry → resync), Task 7 (backoff), Task 5/Task 6 (entity updates → index), Task 7 (single backend).
- **Type consistency:** `EventBatch`, `EntityEvent`, `EventFrame`, `StateChange`, `EventHandles`, `EventLookup`, `EventStream`, `Clock`, `BackoffPolicy`, `EventReport` are defined once and referenced by the same names later.
- **Review Focus coverage:** expiry (Task 2/7), auth close codes (Task 6), replay idempotency (Task 3/5), rollback (Task 3), unreadable entity (Task 5), move (Task 5), reconnect marker (Task 7).
- **No content path:** `EventLookup` loads only `Mail`, `MailSetEntry`, and `MailSet`; it never calls `load_details`, blob fetch, or attachment code.
