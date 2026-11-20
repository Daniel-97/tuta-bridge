# Implementation notes

## Pinned SDK

- Repository: `https://github.com/tutao/tutanota.git`
- Revision: `5dba96493532804ebd5a541024aa217ca3b7874d`
- Crate versions resolved at this revision: `tuta-sdk v369.261113.0`, `crypto-primitives v369.261113.0`
- Feature: `net` on `tuta-sdk`. Do not upgrade the pin without a dedicated task.

## Build check

- `cargo test`, `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings` are the baseline checks.
- Unused-dependency warnings are expected until the later tasks that consume them land.

## Server type model

- The server type model is fetched at runtime from `ApplicationTypesService`. It is not vendored or hardcoded.

## Credential store

- `keyring` 3.x has no default features. Without a platform feature it falls back to the in-memory `mock` store, which does not persist.
- The crate enables `async-secret-service`, `async-io` and `crypto-rust` so that on Linux it uses the Secret Service via zbus, with an encrypted DH session and without a system libdbus dependency.
- `apple-native` and `windows-native` are enabled too, so macOS uses the Keychain and Windows the Credential Manager instead of the mock store. The features only pull platform-gated dependencies, so the Linux build is unchanged. Only the Linux backend has been exercised against a real account.
- Service `tuta-bridge` in production, username = mail address. Credentials are stored as JSON in the password field.
- Ignored test `keyring_store::tests::keyring_roundtrip`: run manually with `cargo test --lib adapters::keyring_store -- --ignored`. Result on 2026-11-15 (GNOME keyring, login collection unlocked): passed.

## Pagination

- Mail listing uses `load_range` with `CustomId(GeneratedId::max_id().to_string())` as the start id and `DESC` ordering.

## SDK limitations

- The SDK's `create_session` does not support 2FA.
- It hardcodes Argon2id for the password KDF. Do not assume other KDF parameters.

## Wire encoding

- Tuta JSON encodes numbers as strings.
- Byte fields are encoded as base64.

## Mail content model

- `MailDetailsBlob` is a **BLOB_ELEMENT_TYPE**, not a regular list entity. It is fetched from the blob server with an archive read token (`BlobAccessTokenService`, storage `v=13`, `read` as an array and `write` as `[]`) and `v=118` for the blob-element GET.
- The blob-element response is server-model JSON; fields are decrypted with the mail's session key.
- Attachments are `TutanotaFile` instances, each referencing blobs that are decrypted separately.
- BlobService GET uses the plural form (`193` with one `BlobId` per blob) and returns a framed multi-blob response: 4-byte count, then per blob 9-byte id, 6-byte padding, 4-byte size, ciphertext. `v=13`, `accessToken` and `cv` are query parameters.
- `TutanotaFile.size` is the encrypted blob size, not the decrypted length.
- Inside a `MailDetailsBlob` only the values the type model flags `encrypted` are ciphertext: `Body.text`/`compressedText`, `Header.headers`/`compressedHeaders`, `MailAddress.name`, and both `EncryptedMailAddress` fields. `MailAddress.address` (id 95) and `MailDetails.sentDate` (id 1284) are plaintext. The decoder follows that flag; treating them as ciphertext dropped every To/Cc/Bcc recipient and read every `sentDate` as 0.

## M3 state and sync

- SQLite (`sqlx`) stores only protocol state and header metadata: accounts, mailboxes (`uidvalidity`, `next_uid`), messages (`uid`, Tuta ids, subject/from/first recipient/date/flags), and `sync_state`.
- Bodies, attachments, inline images, and `.eml` files are never stored.
- `assign_uid` is transactional: known mail keeps its UID, new mail gets `next_uid`, and `next_uid` increments atomically.
- `sync` sorts headers by `received_at_ms` ascending before assigning UIDs and reconciles deletions/moves; it skips unreadable mails/folders and reports counts. A mail the folder still lists but that cannot be loaded keeps its stored row and no longer blocks the reconciliation of the rest of its folder; only a listing that is itself incomplete disables it. Each folder page is stored and reconciled in one transaction (`store_page`).
- `resync` clears the account state and chooses a strictly different `UIDVALIDITY`, restarting UIDs at 1. It loads the folder list and every page before the reset and aborts, index untouched, when the listing or every folder fails.
- State DB permissions: directory `0700`, database and WAL/SHM `0600`; pool recycling is disabled and the process umask is restricted.
- Schema versioning: `user_version` is read on open; an older database is migrated forward in one `BEGIN IMMEDIATE` transaction and a newer one is refused. Version 3 rebuilds `mailboxes` with an `AUTOINCREMENT` id (ids are never reused), 4 adds `accounts.uidvalidity_floor`, 5 adds the `messages_by_element` index, 6 clears stored enrichment. No migration changes a UID, a `UIDVALIDITY`, or a mailbox id. Every step is idempotent: builds from before the gate stamp `user_version = 2` on every open, so one run of an older binary makes the next open here replay steps 3–6 over a schema that already has them (step 3 skips a table that is already `AUTOINCREMENT`, step 4 never lowers the mark, step 6 re-enriches what the older build may have enriched with its broken decoder).
- UIDVALIDITY is unique per mailbox: the `uidvalidity` passed to the store is a lower bound, and a new or renamed mailbox takes `max(bound, floor + 1)`, where the per-account floor survives deleted mailboxes and `reset_account`. Mailboxes that shared one value before version 4 keep it; a rename gives the mailbox a fresh value and keeps its UIDs.
- The version 6 step resets `envelope_complete`, `rfc822_size` and `mime_structure` on every message, because rows enriched before the mail-details decoder fix lack To/Cc/Bcc and were measured without them. Each message is re-enriched on its next body-class fetch, so the `RFC822.SIZE` of an already-cached message can change once; clients re-fetch on the mismatch.
- Write transactions use `BEGIN IMMEDIATE`: every one reads before it writes, and a deferred transaction fails its write immediately (ignoring the busy timeout) when another connection commits in between.
- `sync`, `resync`, `watch` and `serve` take an exclusive `flock` on `state.sqlite3.lock` for the lifetime of the store. A sync beside a running watch is not safe — it reconciles a snapshot taken over many requests against rows the watcher keeps changing — so the second process fails instead. Non-Unix builds run without the lock.
- Manual acceptance (2026-11-17): `sync` indexed 18 folders and 1,617 messages; later runs saw new mail arrive (1,620). A repeat sync compared 1,620 existing mappings with **0 UID changes**; `next_uid = max(uid)+1` held for every mailbox. `resync` changed `uidvalidity` for every mailbox and restarted UIDs at 1. The DB has no body/attachment/`.eml` columns; directory is `0700`, database/WAL/SHM `0600`. 1–2 individual messages could not be loaded and were skipped; reconciliation is disabled for incomplete pages so they are not deleted.

## M4 event bus

- `watch` opens one websocket at `/event` with the query parameters
  `modelVersions` (the client model versions of `sys` and `tutanota`,
  joined by a `.`), `clientVersion`, `userId`, `accessToken`,
  `clientName=tuta-bridge`, and `groupsToLastEventBatchIds` as
  `<group>=<batch>;` pairs. The URL embeds the access token, so it is
  never logged or echoed: the stream type has no `Debug` impl and every
  failure maps to a fixed error message.
- Websocket text frames are `type;payload`. `entityUpdate` (a
  `WebsocketEntityData` JSON carrying one event batch) and
  `initialSyncDone` are handled; every other message type is ignored.
- Only `tutanota` events with these type ids are applied: `Mail` `97`,
  `MailSet` `429`, `MailSetEntry` `1450`; all other events are skipped and
  counted. Subscribed groups are the user's memberships plus the user
  group; the mailing-list group type (`2`) is not subscribed.
- The server replays batches only for a limited window: a stored marker
  older than 45 days, a missing marker, or an empty index triggers the
  ordinary non-destructive `sync` (never a reset), after which every
  group resumes from `timestamp_to_generated_id(now - 5000)` with `now`
  taken before the sync, a stamp that is persisted so a restart does not
  replay from the beginning.
- Markers only advance when a batch of their group is applied, so on
  `initialSyncDone` every marker older than five seconds before the
  connect is re-stamped to that instant; otherwise a group without
  events would age out of the replay window. This assumes the server
  sends `initialSyncDone` only after replaying everything the connect's
  markers were missing — not verified against a live account. If the
  frame never arrives the only cost is a `sync` at a later start.
- A batch with a failed entity lookup is not persisted and its marker
  does not move. It is retried in place with the backoff; after
  `lookup_failure_threshold` (10) attempts the loop runs the same `sync`
  and reconnects from the fresh stamps. A busy state database retries
  the batch the same way but ends `watch` if it stays busy.
- An `entityUpdate` frame that does not parse ends the stream; the server
  replays it on reconnect. Three connections in a row ending that way
  trigger the `sync`, which moves the markers past the frame.
- A `MailSet` delete event cannot be resolved to a stored folder (the
  index keys folders by their entries list), so it triggers a reload of
  the folder list and the removal of mailboxes that are gone.
- Close-code mapping: `4403`, `4440`, `4470`, `4471`, `4472` are fatal for
  the session (the user must run `login` again); `4429` is rate limited;
  every other close is a reconnectable network error. Network errors retry
  with a 5 s / 20 s / 60 s-capped backoff; all other errors end `watch`.
- Liveness: after 60 s without any frame the stream sends a websocket
  ping, and a second silent 60 s (no pong either) ends it as a
  reconnectable network error, so a half-open connection is noticed
  within two minutes. This relies on the server answering pings, which
  RFC 6455 requires but was not checked against the live event bus.
- REST calls have no timeout in the SDK client; `TimeoutRestClient` bounds
  each exchange at 60 s, and blob-service downloads (a whole attachment
  per response) at 10 minutes. A timeout surfaces as a network error.
- `clientVersion` is `369.261113.0` and must be bumped together with the
  SDK pin, otherwise the server rejects the connection as an outdated
  client.
- Placement model: `Mail.sets` (type-model field 1465) references
  `MailSet` (`refTypeId: 429`), not `MailSetEntry`; the folder is resolved
  through `MailSet.entries` (the folder's entries list id), while
  `messages.tuta_list_id` stays the Mail's own list id so content reloads
  can still find the mail.

## M5 IMAP server

- Served subset: `CAPABILITY`, `NOOP`, `ID`, `LOGIN`, `SELECT`,
  `EXAMINE`, `LIST`, `LSUB`, `STATUS`, `FETCH`, `UID FETCH`, `SEARCH`,
  `UID SEARCH`, `CHECK`, `CLOSE`, `IDLE`, `LOGOUT`. Writes — `STORE`,
  `APPEND`, `COPY`, `MOVE`, `EXPUNGE`, `CREATE`, `DELETE`, `RENAME`,
  `SUBSCRIBE`, `UNSUBSCRIBE`, `UID STORE`, `UID COPY` — are understood
  and always refused with the fixed `NO not supported by this
  read-only bridge`; unknown commands answer `BAD unknown command`.
  The greeting, `CAPABILITY`, and `LOGIN` responses advertise
  `IMAP4rev1 IDLE ID`.
- Response shapes worth remembering:
  - The `SELECT` untagged block ships in Dovecot order, FLAGS first:
    `* FLAGS (\Seen)`, `* <n> EXISTS`, `* 0 RECENT`, `* OK [UNSEEN
    <n>]` (omitted when nothing is unseen), `* OK [PERMANENTFLAGS ()] Read-only
    mailbox`, `* OK [UIDVALIDITY <v>]`, `* OK [UIDNEXT <n>]`, then
    `<tag> OK [READ-WRITE] SELECT completed`. RFC 3501 mandates
    presence, not order; `[READ-WRITE]` with `PERMANENTFLAGS ()` keeps
    clients working while every write answers NO.
  - `* OK [UNSEEN <n>]` carries the message number of the first
    unseen message, as RFC 3501 §7.1 defines it (earlier versions sent
    the unseen count); `STATUS (UNSEEN)` is the count.
  - Server-sent literals are inline `{n}\r\n<bytes>` — no continuation
    round-trip; bodies stream in 64 KiB chunks with at most one
    rendered message in memory. Client literals get a `+ ` continuation
    and are capped per command, all literals of the command together:
    4 KiB before login, 16 MiB after (an announcement that would cross
    the cap answers NO before any continuation and ends the
    connection); command lines are capped at 64 KiB, and a
    longer line is answered BAD and discarded while being read, never
    buffered whole.
  - `ID` is answered with `* ID ("name" "tuta-bridge")` without
    interpreting the client payload.
  - A FETCH for an expunged uid answers nothing and the rest of the
    FETCH continues; a message whose details cannot be loaded is
    skipped in the FETCH response exactly like an expunged one, and
    its row disappears on the next sync or event.
- Session snapshot: a `Selected` session owns its view of the mailbox
  — the mailbox id, the UIDVALIDITY, and the `(uid, unread)` list whose
  positions are the message numbers the client knows. It addresses the
  mailbox by id from `SELECT` on and never resolves the name again.
  `FETCH` and `SEARCH` answer from that view: a uid the store no longer
  has answers nothing, and one the client was not told about has no
  number yet.
- Reset rules: the session re-validates the UIDVALIDITY (one mailbox
  row, no message read) before every command except `SELECT`/`EXAMINE`
  (which replace the view) and `CLOSE`/`LOGOUT` (which drop or end it).
  A drift — resync, or a renamed folder — or a mailbox whose id no
  longer exists sends the fixed `* BYE mailbox state was resynced;
  reconnect` and closes the session.
- Sync points: the view changes only at `NOOP`, `CHECK`, `IDLE` entry,
  and each `MailboxChanged` (or lagged receiver) during `IDLE` — never
  during `FETCH`/`STORE`/`SEARCH` (RFC 3501 §7.4.1). The session reads
  `StateStore::message_uids` and sends `* n EXPUNGE` per removed mail
  (highest number first), then `* n EXISTS` if any arrived, then
  `* n FETCH (FLAGS (...))` per read-state change. `EXAMINE` versus
  `SELECT` is recorded in the session state for the write milestone.
- Mailbox names: on the wire every name is modified UTF-7 (RFC 3501
  §5.1.3) in both directions; an argument that is not valid modified
  UTF-7 is taken as written, so a client sending the raw name still
  reaches its mailbox. The store is flat while `"/"` stays the
  advertised delimiter, so a `/` inside a folder name is listed as
  U+2215 DIVISION SLASH instead of inventing a hierarchy. Tuta lets
  folder names repeat (and nests folders, which the index flattens):
  of several mailboxes with one name the first keeps it — system
  folders before custom ones, then lowest mailbox id — and the others
  are listed as `Name (2)`, `Name (3)`, …; if the first is deleted the
  next takes over the plain name. Only the Inbox-kind folder answers
  to `INBOX` (any casing); a custom folder called `inbox` is a
  namesake and gets a suffix.
- BODYSTRUCTURE: the tree mirrors `build_message`, but each leaf's
  transfer encoding, octet count, and line count are measured from the
  rendered bytes (parsed back with `mail-parser`), because the renderer
  picks 7bit, quoted-printable, or base64 per part from its content.
  `text/*` attachments carry the line count a `body-type-text` needs.
  `message/rfc822` and `multipart/*` attachments are reported as
  `APPLICATION/OCTET-STREAM`: the real forms would need the attached
  message's own envelope and structure, and the bridge treats
  attachments as opaque bytes (the part header in the rendered message
  keeps the original type). A bare `BODY` item is answered as `BODY`
  with the extension data stripped from the stored string.
- Connection bounds (`ServeLimits` / `SessionLimits`, all injectable):
  the accept loop lives in `adapters::imap::server::serve` — the one
  implementation `serve` and the tests share — and never ends on a
  failed `accept` (warn, pause 1 s, retry: `EMFILE` and
  `ECONNABORTED` are transient). A semaphore caps live connections at
  64, handshake included; at the cap the listener is not polled and
  clients wait in the kernel backlog. The TLS handshake has 10 s. The
  whole unauthenticated phase shares one 60 s deadline (commands do
  not extend it); an authenticated session may wait 30 minutes for a
  command (RFC 3501 §5.4's minimum) and one `IDLE` may run 30 minutes
  (RFC 2177 clients re-issue it every 29) — both end with `* BYE idle
  for too long; closing connection`. Writes go through a stall guard:
  60 s without progress fails the write and ends the session, and a
  failed connection is never answered again.
- Login throttling: a failed `LOGIN` logs `imap login failed` at warn
  level with the per-connection attempt count and no client text,
  waits `login_failure_delay` (3 s) holding a mutex shared by every
  session of the listener — so failures are answered one at a time
  whatever the number of connections, about one guess per 3 s in
  total — then answers `NO`; the third failure adds `* BYE too many
  failed logins` and closes. A correct login never touches the mutex.
- IDLE literal edge: a tagged BAD during IDLE never answers a literal
  continuation, and RFC 3501 obliges the client not to send the octets
  its `{n}` token announced — the session reads none of them, and
  octets a misbehaving client sends anyway surface as rejected command
  lines.
- Password and certificate locations and modes: the bridge password is
  stored verbatim (no JSON, nothing to version) in the Secret Service
  under service `tuta-bridge`, account `imap-bridge` — readable with
  `secret-tool lookup service tuta-bridge username imap-bridge` — and
  never printed or written to a file. The certificate pair lives in
  the data directory: `imap-cert.pem` / `imap-key.pem`, both 0600, CN
  `localhost`, SANs `DNS:localhost`, `IP:127.0.0.1`, `IP:::1`; when
  both files are non-empty they are reused verbatim, a missing or empty
  one regenerates the pair.
- Proton Bridge study conclusions that shaped the server (concepts
  only, no code):
  - Snapshot re-validation before every command: a stale view gets the
    fixed BYE, never a silently wrong answer.
  - `mime_structure` (the precomputed BODYSTRUCTURE string) and
    `rfc822_size` are persisted at first enrichment, so structure and
    size requests never re-download content; `BODY[]` always re-renders
    — no body is ever stored. The one exception lives in memory: a
    session downloading a message in `BODY[]<offset.count>` chunks
    keeps that message's rendered sections between chunks (one message,
    at most 16 MiB, at most 5 minutes, dropped on `SELECT`/`CLOSE` and
    with the session), because each chunk would otherwise download and
    render the whole mail again. Whole-body fetches never use it.
  - `ENVELOPE` is served index-only, from the stored header; it never
    triggers a network load. cc/bcc/message-id stay blank in a
    listing until the first body open enriches the row.
  - Batch markers written *after* a rebuild give Proton's
    bookmark-and-rewind property: events that arrive during the resync
    postdate the marker and are replayed. UID problems are solved by
    reset-and-rebuild, never by in-band renumbering.
  - Tuta can emit RFC-invalid MIME boundaries; the renderer regenerates
    boundaries from a deterministic seed instead of echoing the
    originals.
- System folder display names (`Inbox`, `Sent`, `Drafts`, `Trash`,
  `Junk`, `Archive`) are derived from the folder kind because Tuta
  stores the `name` of system MailSets empty on the server; custom
  MailSets carry real names and an unnamed custom set is skipped.
- Sent dates are taken from the parsed `Date:` header first, then Tuta's
  `MailDetails.sentDate`. The M2-era decoder read `sentDate` as 0 for
  every mail (it tried to decrypt the plaintext field; this was first
  misread as "0 for external mail"), which left every enriched row with
  `sent_at_ms = 0`, so ENVELOPE dates rendered NIL and Thunderbird showed
  01/01/1970. Whether the server really stores 0 for external mail is
  unverified, so the header keeps precedence. Mail without a
  parseable `Date:` falls back to `sentDate`, then to the received time
  (mirroring the web client's display), so undated mail never renders
  as epoch. Rows already in a database heal on their next
  BODYSTRUCTURE/RFC822.SIZE/BODY request: the enricher treats a row as
  complete only when its sent date landed, so a row marked complete
  with a zero date re-enriches once (one content load) and comes back
  with the header's date (or the received time when the mail is
  undated) — no migration. Only mail with no Date header, no sent date,
  and no received time keeps re-loading per body request, the same
  accepted posture as permanently-unavailable content.

## M1/M2 manual acceptance (2026-11-16)

- Login with password + TOTP against `https://app.tuta.com` succeeded; credentials were persisted in the Secret Service and `status` showed the account.
- KDF was Argon2id (`kdfVersion = 1`); no bcrypt migration.
- `dump --folder inbox --limit 3 --out ./out` wrote 3 `.eml` files. The message with a PDF attachment produced a valid 3-page PDF, and the MIME parts included `text/plain` and `text/html`.
- A second dump over the same folder produced identical filenames and SHA-256 hashes.
- TOTP input is echoed on the terminal by request; the password remains hidden.

## M4 manual acceptance (2026-11-17)

- Baseline: `watch` ran a full sync when no batch markers existed, then subscribed one websocket for 13 groups. A mail sent from another client while `watch` was running appeared in the index **4.6 seconds** after sending (`applied 2 changes`).
- Restart after a pause: `watch` was stopped for about a minute while another mail arrived. On restart it replayed from the persisted batch markers and indexed the mail; comparing 1,623 existing mappings showed **0 changed UIDs**, 0 duplicates, and exactly 1 new row.
- Expired-marker self-healing, observed live: markers written by an earlier build with the wrong timestamp layout decoded to 1973, so `watch` resynced on startup (`uidvalidity` 1794940997 → 1794954354) and rewrote the markers in the correct format.
- The event path never fetched or stored bodies: `messages` still has no body/attachment/`.eml` column; `watch` output is fixed strings and counts only.
- Two live-only defects were found and fixed during this acceptance, each with a regression test: the server sends `NumberString` fields as JSON strings (the SDK models them as `i64`, so every `entityUpdate` failed to parse), and marker ids encoded the timestamp with a 24-bit instead of 28-bit suffix (the server read them as ancient and replayed the whole retained backlog).

## M5 manual acceptance (2026-11-18)

- Terminal client (Python `imaplib` over TLS loopback, unverified cert): `LOGIN`, `LIST` shows 18 named mailboxes with the right SPECIAL-USE attributes (INBOX carries none), `SELECT INBOX` reports EXISTS 255 / RECENT 0 / UIDVALIDITY / UIDNEXT / UNSEEN / `FLAGS (\Seen)` / `PERMANENTFLAGS ()`, `STATUS` matches, and `UID FETCH` returns an ENVELOPE whose subject matches the index. `BODY.PEEK[]` serves bytes without any store write; `BODY[]` persists `rfc822_size`; `BODY[HEADER.FIELDS (…)]` works.
- `mbsync` (isync 1.5.1) with the bridge certificate as `CertificateFile`: first sync pulled 255 messages; an immediate second sync reported **+0** — no body re-downloads, stable UIDs; no warnings after the folder-name fix.
- Thunderbird (manual account, IMAP `127.0.0.1:9930`, SSL/TLS, certificate exception): folders and headers visible with correct dates and flags; a mail **with an attachment opens correctly**; new mail arrived via **IDLE without any user action** (serve log: event applied → `* n EXISTS` → Thunderbird `UID FETCH`); write commands answer the read-only NO.
- Acceptance found and fixed three live defects, each with a regression test and a scoped re-review: (a) Tuta system MailSets carry an **empty name** — display names are now derived from the folder kind, custom folders keep theirs; (b) `sent_at` came from `MailDetails.sentDate`, which is **0 for external mail** (M2-era root cause) — it is now parsed from the real `Date:` header, falling back to `sentDate` and then the received time; (c) four genuinely undated mails now show the received time, mirroring the web client. After a `resync` and a client re-download every date displays correctly.
- The state database is still metadata-only (17 columns); `rfc822_size` and `mime_structure` are populated only for fetched mails; `serve` logs carry only fixed strings and counts.
- A `resync` run during acceptance changed UIDVALIDITY as designed and Thunderbird rebuilt its cache without errors (the session-reset path exercised in production).

