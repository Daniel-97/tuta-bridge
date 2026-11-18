# Tuta Bridge M6 Implementation Plan — IMAP Writes

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let standard mail clients mark mail read/unread, move it between folders, and delete it (to trash, or permanently from trash), with every change reflected in Tuta and in the local index without double-echo.

**Architecture:** A new `MailboxWriter` port wraps the SDK's write services (`UnreadMailStateService`, `SimpleMoveMailService`/`trash`/`archive`, `MoveMailService` for custom folders, `MailService DELETE`). The `ImapBackend` gains store/move/expunge operations that call the writer, then apply an optimistic local update through the existing `StateStore`; the M4 event bus later delivers the echo of our own change and is idempotent by construction (partial-header upserts preserve enriched fields, entry-deletes on already-removed rows are no-ops). The IMAP session emits real `* n FETCH (FLAGS)` responses for STORE and itemized `* n EXPUNGE` (descending MSNs) for MOVE/EXPUNGE, and SELECT now advertises `PERMANENTFLAGS (\Seen)`.

**Tech Stack:** Rust 2021, existing tokio/tokio-rustls stack, `tuta-sdk` mail facade + service executor, existing SQLite store.

**Spec:** `tuta-bridge-spec.md` (roadmap M6); findings below extend the approved M3–M5 design (sections 7–9). Design recon: `/tmp/opencode/tutanota/tuta-sdk/rust/sdk/src/mail_facade.rs` (set_unread_status_for_mails, simple_move_mail — Trash/Archive only —, trash_mails, archive_mails, MAX_MAIL_UPDATE_LIMIT 50), `MoveMailData { moveReason, targetFolder: IdTuple, mails, excludeMailSet }`, `DeleteMailData { mails, folder }`, and the web client offering **no copy operation** between folders.

## Design decisions (controller, from SDK recon — user review gates this plan)

1. **STORE supports only `\Seen`** (`+FLAGS`, `-FLAGS`, `FLAGS`, with or without `.SILENT`): mapped to `UnreadMailStateService`. Every other flag — including `\Deleted` — answers a fixed NO: Tuta has no star/flag and the delete flow is a move. Clients that delete via the classic `STORE \Deleted` + `EXPUNGE` pattern are documented as unsupported (Thunderbird's default is move-to-trash; mbsync with `Expunge None` never stores it).
2. **MOVE / UID MOVE** (RFC 6851) is native: target folder resolves to its `MailSet` id and one `MoveMailService` call moves the mails; the session answers itemized `* n EXPUNGE` (descending MSNs) plus the tagged OK. **COPY answers NO** — Tuta itself has no copy; its web client uses labels for multi-set membership. Documented v1 limit.
3. **EXPUNGE deletes**: in any folder except Trash it moves the mails to Trash (`simple_move_mail(Trash)`); in Trash it permanently deletes (`MailService DELETE` with the trash folder). The session answers itemized `* n EXPUNGE`.
4. **Optimistic local update after the remote call succeeds**: STORE updates `unread` in place; MOVE/EXPUNGE removes the rows (the message gets a fresh UID in the target folder when the echo event arrives, exactly like a server-side move). The echo is idempotent: the upsert preserves enriched fields and the delete of a removed row is a no-op. On remote failure nothing changes locally and the command answers NO.
5. **MailSet id resolution**: the store keeps `list_id` = the folder's `entries` list; moving needs the `MailSet` id, so `TutaMailboxWriter` loads the mailbox's mail sets once per write command (≤18 rows, one request) and matches `set.entries == folder.list_id`. No schema change.
6. **`PERMANENTFLAGS (\Seen)`** replaces `()` in SELECT/EXAMINE; `STORE` of an unsupported flag still answers NO. IDLE stays EXISTS-only in M6 (flag pushes land with the client's own NOOP/poll — documented limit; a `* n FETCH (FLAGS)` push is backlog with M9).
7. **No APPEND, no folder mutation commands** (CREATE/DELETE/RENAME stay NO; they belong with later milestones).

## Global Constraints

- All code, identifiers, comments, and commit messages in English.
- Never write passwords, tokens, subjects, addresses, or bodies to logs or errors; session logs carry only tags/commands/counts.
- The store remains metadata-only; writes never persist bodies or attachments.
- UID discipline: a moved mail gets a new UID in the target (server-driven via events); UIDs in the source are never reused.
- No automated test contacts the real Tuta server; loopback only.
- The Tuta SDK pin stays `rev = 5dba96493532804ebd5a541024aa217ca3b7874d`.
- `cargo fmt` and `cargo clippy --all-targets -- -D warnings` must pass before every commit.
- Do not add a `LICENSE` file.

## Review Focus

1. A MOVE whose echo event arrives while the session is mid-response: EXPUNGE MSNs must be computed from the pre-move snapshot and stay consistent (no renumbering gaps). Test in Task 4.
2. STORE on an expunged/moved uid must answer nothing for it (like FETCH does) without failing the batch. Test in Task 3.
3. The optimistic update and the echo event must not double-apply (unread toggles, row removals, fresh-UID assignment in the target). Test in Task 2.
4. Trash semantics must not destroy mail: EXPUNGE outside Trash only ever moves; permanent delete happens only in Trash. Test in Task 2.
5. PERMANENTFLAGS must advertise exactly `(\Seen)`; unsupported STORE flags must not be silently ignored. Test in Task 3.
6. A failed remote write must leave the store and the wire untouched (NO, no local change). Test in Task 2.

---

## File Structure

Create:

- `src/ports/mailbox_writer.rs` — the write port.
- `src/adapters/tuta/mailbox_writer.rs` — SDK implementation (unread, simple move, custom move, permanent delete, mail-set resolution).
- `tests/imap_writes.rs` — backend-level write tests against fakes.

Modify:

- `src/ports/mod.rs`, `src/adapters/tuta/mod.rs`, `src/adapters/mod.rs` — wiring.
- `src/ports/imap_backend.rs`, `src/adapters/imap/backend.rs` — store/move/expunge operations on the backend.
- `src/adapters/imap/session.rs` — STORE/UID STORE, MOVE/UID MOVE, EXPUNGE dispatch, PERMANENTFLAGS, refusal updates.
- `src/ports/session.rs`, `src/adapters/tuta/session.rs` — expose the writer from the session (`shared_mail`-style).
- `src/main.rs` — wire the writer into `serve`.
- `README.md`, `NOTES.md` — writable semantics + limits.

---

### Task 1: `MailboxWriter` port and Tuta implementation

**Files:**
- Create: `src/ports/mailbox_writer.rs`, modify `src/ports/mod.rs`
- Create: `src/adapters/tuta/mailbox_writer.rs`, modify `src/adapters/tuta/mod.rs`
- Test: inline module in `src/adapters/tuta/mailbox_writer.rs`

**Interfaces:**
- Consumes: `LoggedInSdk` (mail facade + service executor), `MailSet`/`MailBox` entities.
- Produces:
  - `#[async_trait] pub trait MailboxWriter: Send + Sync` with:
    - `async fn set_unread(&self, mails: &[IdTupleGenerated], unread: bool) -> Result<()>`
    - `async fn move_to_folder(&self, target_folder_entries: &str, mails: &[IdTupleGenerated]) -> Result<()>`
    - `async fn move_to_trash(&self, mails: &[IdTupleGenerated]) -> Result<()>`
    - `async fn delete_permanently(&self, folder_entries: &str, mails: &[IdTupleGenerated]) -> Result<()>`
  - `pub struct TutaMailboxWriter { logged: Arc<LoggedInSdk> }` with `new`.
  - A pure, tested helper `pub fn mail_set_for_entries(sets: &[MailSet], entries: &str) -> Option<&MailSet>` (match on `entries`, empty-entries sets skipped).

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn resolves_the_mail_set_by_entries_list() {
    // three sets with distinct `entries` values; one match, one empty-entries skip, one miss
    assert!(mail_set_for_entries(&sets, "entries-b").is_some_and(|s| s.entries.as_str() == "entries-b"));
    assert!(mail_set_for_entries(&sets, "").is_none());
    assert!(mail_set_for_entries(&sets, "nope").is_none());
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test adapters::tuta::mailbox_writer`
Expected: FAIL (module missing).

- [ ] **Step 3: Implement**

- `set_unread`: `mail_facade().set_unread_status_for_mails(mails.to_vec(), unread)`.
- `move_to_trash`: `mail_facade().trash_mails(mails.to_vec())`.
- `move_to_folder`: load the mailbox (`load_user_mailbox`) and its mail sets (`load_range` on `mailbox.mailSets.mailSets`, ascending, 100 — same pattern as `folders()`), resolve the target set by `entries`, then POST `MoveMailService` with `MoveMailData { _format: 0, moveReason: None, targetFolder: <set _id clone>, mails: mails.to_vec(), excludeMailSet: None }` through `get_service_executor()`, batching in chunks of 50 (the SDK's own limit).
- `delete_permanently`: resolve the set by `entries` (the mails' current folder), then `MailService` DELETE with `DeleteMailData { _format: 0, mails: mails.to_vec(), folder: Some(set_id) }`.
- Map every SDK failure to a fixed `Error::Network("mailbox write failed")`; never include ids or addresses.

- [ ] **Step 4: Run tests and checks**

Run: `cargo test adapters::tuta::mailbox_writer && cargo fmt --check && cargo clippy --all-targets -- -D warnings`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/ports/mailbox_writer.rs src/ports/mod.rs src/adapters/tuta/mailbox_writer.rs src/adapters/tuta/mod.rs
git commit -m "feat: add the mailbox writer port"
```

---

### Task 2: Backend write operations with optimistic local updates

**Files:**
- Modify: `src/ports/imap_backend.rs`, `src/adapters/imap/backend.rs`
- Test: `tests/imap_writes.rs`, `tests/support/mod.rs` (fake `MailboxWriter`)

**Interfaces:**
- Consumes: `MailboxWriter`, `StateStore::{update_metadata, remove_message, message_by_uid, messages}`, `StoredMailbox`.
- Produces on `ImapBackend`:
  - `async fn store_seen(&self, mailbox: MailboxId, uids: &[u32], seen: bool) -> Result<Vec<(u32, bool)>>` — returns the (uid, unread) pairs actually applied
  - `async fn move_mails(&self, mailbox: MailboxId, uids: &[u32], target_list_id: &str) -> Result<()>`
  - `async fn expunge_mails(&self, mailbox: MailboxId, uids: &[u32]) -> Result<()>`

- [ ] **Step 1: Write the failing tests**

```rust
#[tokio::test]
async fn store_seen_updates_remotely_then_locally() {
    // fresh unread=1 mail; STORE +FLAGS \Seen -> writer.set_unread(mails, false) called once;
    // the store row now has unread=0; the returned pair is (uid, unread=false).
}

#[tokio::test]
async fn move_removes_rows_and_never_touches_target_uids() {
    // move one uid to another folder: writer.move_to_folder called with the target's
    // entries list and the mail id tuple; the source row is gone; the target folder
    // has NO new row (the echo event assigns it later).
}

#[tokio::test]
async fn expunge_moves_to_trash_outside_trash_and_deletes_inside_trash() {
    // in Inbox: writer.move_to_trash called; row removed.
    // in Trash: writer.delete_permanently called; row removed; no other mailbox touched.
}

#[tokio::test]
async fn a_failed_remote_write_changes_nothing() {
    // fake writer returns Error::Network: backend answers Err, store untouched (calls recorded).
}

#[tokio::test]
async fn the_echo_event_after_our_own_write_is_idempotent() {
    // after store_seen(true) applied locally, replay the corresponding event batch
    // (Mail update with unread=0): the row keeps its UID and unread; no duplicate.
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --test imap_writes`
Expected: FAIL.

- [ ] **Step 3: Implement**

- Resolve uids to `(mail_id_tuple, row)` via `message_by_uid`; skip missing uids (expunged — same contract as FETCH); a fully-empty result answers `Ok(vec![])`.
- `store_seen`: remote first; then per row call `update_metadata(mailbox, uid, &header_with_new_unread, None)` — build the header by cloning the stored one and flipping `unread`. Return only the applied pairs (this is what the session renders as `* n FETCH (FLAGS)`).
- `move_mails`: remote `move_to_folder(target_entries, mails)`; then `remove_message` per uid in the source. Never write to the target (the event does that, assigning the new UID).
- `expunge_mails`: if the mailbox kind is `Trash` → `delete_permanently(mailbox_entries, mails)`; else → `move_to_trash(mails)`; then `remove_message` per uid.
- Fixed error strings; no ids in errors.

- [ ] **Step 4: Run tests and checks**

Run: `cargo test && cargo fmt --check && cargo clippy --all-targets -- -D warnings`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/ports/imap_backend.rs src/adapters/imap/backend.rs tests/imap_writes.rs tests/support/mod.rs
git commit -m "feat: apply imap writes through the mailbox writer"
```

---

### Task 3: STORE in the session with PERMANENTFLAGS

**Files:**
- Modify: `src/adapters/imap/session.rs`, `src/adapters/imap/backend.rs` (if the writer is reached through the backend only, no session change to the backend signature)
- Test: `tests/imap_server.rs`

**Interfaces:**
- Consumes: `ImapBackend::store_seen`, the codec's `ImapArg`/`SeqSet` (parse `+FLAGS (\Seen)` / `-FLAGS` / `FLAGS`, optional `.SILENT`).
- Produces: STORE/UID STORE dispatch; SELECT/EXAMINE now advertise `* OK [PERMANENTFLAGS (\Seen)] Flags permitted`.

- [ ] **Step 1: Write the failing tests**

```rust
#[tokio::test]
async fn store_seen_answers_fetch_flags_and_permanentflags_lists_seen() {
    // SELECT -> "* OK [PERMANENTFLAGS (\\Seen)] Flags permitted"
    // "a1 UID STORE 3 +FLAGS (\\Seen)" -> "* 3 FETCH (FLAGS (\\Seen) UID 3)" then tagged OK
    // ".SILENT" answers only the tagged OK (no untagged line)
    // "-FLAGS (\\Seen)" -> "* 3 FETCH (FLAGS ())"
    // "a1 UID STORE 3,4 +FLAGS (\\Deleted)" -> "a1 NO not supported by this read-only bridge" stays a NO
    // a uid that vanished -> no line for it, batch still OK
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test imap_session`
Expected: FAIL.

- [ ] **Step 3: Implement**

- Parse the flag list through the codec: accept exactly `+FLAGS`/`-FLAGS`/`FLAGS` with an optional `.SILENT` and the single flag `\Seen`; anything else answers the existing fixed NO.
- Resolve the sequence set against the selected mailbox (star rules identical to FETCH), call `backend.store_seen`, and emit `* <msn> FETCH (FLAGS (<flags>) UID <uid>)` per applied pair (msn from the pre-command snapshot), skipping `.SILENT`.
- Update the session's `unseen` count from the result so the next NOOP/SELECT reports consistently.

- [ ] **Step 4: Run tests and checks**

Run: `cargo test && cargo fmt --check && cargo clippy --all-targets -- -D warnings`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/adapters/imap/session.rs tests/imap_server.rs
git commit -m "feat: store the seen flag over imap"
```

---

### Task 4: MOVE and EXPUNGE with itemized untagged responses

**Files:**
- Modify: `src/adapters/imap/session.rs`
- Test: `tests/imap_server.rs`

**Interfaces:**
- Consumes: `ImapBackend::{move_mails, expunge_mails}`, the mailbox name→list-id resolution from SELECT (`MailboxView`) and `ImapBackend::mailboxes` for the target name.
- Produces: MOVE/UID MOVE and EXPUNGE dispatch; `COPY` answers the fixed NO.

- [ ] **Step 1: Write the failing tests**

```rust
#[tokio::test]
async fn move_answers_itemized_expunges_in_descending_msn() {
    // mailbox with 5 messages; UID MOVE 2,4 "Archive" -> "* 4 EXPUNGE" then "* 2 EXPUNGE"
    // (descending, snapshot-based numbering), then tagged OK; EXISTS drops 5 -> 3.
}

#[tokio::test]
async fn expunge_moves_to_trash_and_answers_expunges() {
    // EXPUNGE in a non-trash mailbox -> writer.move_to_trash called; itemized EXPUNGE; tagged OK.
}

#[tokio::test]
async fn copy_is_refused_with_a_fixed_no() {
    // "a1 UID COPY 1 Archive" -> "a1 NO not supported by this read-only bridge"
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test imap_session`
Expected: FAIL.

- [ ] **Step 3: Implement**

- MOVE: parse the sequence set and the target mailbox name (Raw arg); resolve the target's `list_id` via the backend's mailboxes; call `move_mails`; emit `* <msn> EXPUNGE` per removed uid in **descending** msn order from the pre-command snapshot; adjust the session's `exists`.
- EXPUNGE (and `UID EXPUNGE` remains BAD — UIDPLUS is not advertised): expunge the currently selected mailbox's full set? No — v1: EXPUNGE without arguments is a no-op OK (we never track `\Deleted`); moving happens through MOVE. Document in NOTES.
- COPY/UID COPY: fixed NO.
- Unknown-target MOVE: `NO mailbox not found`.

- [ ] **Step 4: Run tests and checks**

Run: `cargo test && cargo fmt --check && cargo clippy --all-targets -- -D warnings`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/adapters/imap/session.rs tests/imap_server.rs
git commit -m "feat: move and expunge mail over imap"
```

---

### Task 5: wiring the writer through session and serve

**Files:**
- Modify: `src/ports/session.rs`, `src/adapters/tuta/session.rs`, `src/main.rs`, `tests/support/mod.rs`
- Test: `tests/serve.rs`

**Interfaces:**
- Consumes: everything above.
- Produces: `Session::shared_writer(&self) -> Arc<dyn MailboxWriter>` (required trait method; `TutaSession` wraps a `TutaMailboxWriter`; fakes return their shared fake); `serve` builds the backend with the writer; `watch` untouched.

- [ ] **Step 1: Write the failing tests**

Extend the e2e serve test: after LOGIN/SELECT, `UID STORE 1 +FLAGS (\Seen)` returns a FETCH line and the fake store's row flips unread; `UID MOVE 1 Archive` returns an EXPUNGE line and the row is gone from the Inbox.

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --test serve`
Expected: FAIL.

- [ ] **Step 3: Implement** the trait method, the Arc in `TutaSession` (built from the same `logged`), the backend constructor field, and the `serve` wiring; update every fake.

- [ ] **Step 4: Run tests and checks**

Run: `cargo test && cargo fmt --check && cargo clippy --all-targets -- -D warnings`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/ports/session.rs src/adapters/tuta/session.rs src/main.rs tests/support/mod.rs tests/serve.rs
git commit -m "feat: wire the mailbox writer into serve"
```

---

### Task 6: Documentation and M6 manual acceptance

**Files:**
- Modify: `README.md`, `NOTES.md`

- [ ] **Step 1: Document**

README: writable operations (`STORE \Seen`, `MOVE`, `EXPUNGE→Trash`, permanent delete in Trash); `PERMANENTFLAGS (\Seen)`; limits — no `\Deleted` flow (delete is a move; clients configured with classic delete will see mail return), no COPY, no APPEND, no folder mutation; IDLE stays EXISTS-only (flag pushes land on the client's own poll).

NOTES: the write path (SDK services used), the optimistic-update + idempotent-echo contract, the fresh-UID-in-target rule for moves, and the accepted client-flow limits.

- [ ] **Step 2: Verify the full suite**

Run: `cargo test && cargo fmt --check && cargo clippy --all-targets -- -D warnings`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add README.md NOTES.md
git commit -m "docs: document imap writes"
```

- [ ] **Step 4: Manual acceptance (requires the real account and Thunderbird)**

1. Start `serve`; in Thunderbird mark a mail read and one unread → the Tuta web client shows the same states; the web client's own counter agrees.
2. In the Tuta web client mark a different mail read → within seconds Thunderbird's poll/NOOP shows it read (EXISTS/flag refresh; documented v1 limit if it needs a manual "Get Messages").
3. Drag a mail from Inbox to a custom folder in Thunderbird → it disappears from Inbox, appears in the target with a new UID, and the web client shows the move; drag back works.
4. Delete a mail in Thunderbird (move to trash path) → it lands in Tuta's Trash; deleting from Trash removes it permanently (verify in the web client's trash).
5. Confirm the local DB stayed metadata-only and no UIDs were reused in the source folder.
6. Record results in NOTES under `## M6 manual acceptance`, commit `docs: record M6 manual acceptance`.

---

## Self-Review Notes

- **Spec coverage:** roadmap M6 — `STORE` flag (`\Seen`) via Task 3, `MOVE`/`COPY` (move native, copy refused+documented) via Task 4, `EXPUNGE` → trash/permanent via Task 2/4, websocket-echo coherence via the idempotence tests in Task 2.
- **Type consistency:** `MailboxWriter`, `store_seen/move_mails/expunge_mails`, `Session::shared_writer` are defined once and consumed with the same names.
- **Review Focus coverage:** mid-response echo (Task 4 snapshot numbering), expunged-uid STORE (Task 3), double-apply (Task 2), trash-only destruction (Task 2), PERMANENTFLAGS (Task 3), failed remote write (Task 2).
- **Known v1 trade-offs recorded, not hidden:** classic `STORE \Deleted`+`EXPUNGE` unsupported (Thunderbird defaults to move), no COPY (Tuta has none), no APPEND, EXISTS-only IDLE, no UIDPLUS.
