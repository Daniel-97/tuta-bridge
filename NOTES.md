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

## M3 state and sync

- SQLite (`sqlx`) stores only protocol state and header metadata: accounts, mailboxes (`uidvalidity`, `next_uid`), messages (`uid`, Tuta ids, subject/from/first recipient/date/flags), and `sync_state`.
- Bodies, attachments, inline images, and `.eml` files are never stored.
- `assign_uid` is transactional: known mail keeps its UID, new mail gets `next_uid`, and `next_uid` increments atomically.
- `sync` sorts headers by `received_at_ms` ascending before assigning UIDs and reconciles deletions/moves; it skips unreadable mails/folders and reports counts.
- `resync` clears the account state and chooses a strictly different `UIDVALIDITY`, restarting UIDs at 1.
- State DB permissions: directory `0700`, database and WAL/SHM `0600`; pool recycling is disabled and the process umask is restricted.
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
  older than 45 days triggers a resync, and a group without a marker
  resumes from `timestamp_to_generated_id(now - 5000)`, a stamp that is
  persisted so a restart does not replay from the beginning.
- Close-code mapping: `4403`, `4440`, `4470`, `4471`, `4472` are fatal for
  the session (the user must run `login` again); `4429` is rate limited;
  every other close is a reconnectable network error. Network errors retry
  with a 5 s / 20 s / 60 s-capped backoff; all other errors end `watch`.
- `clientVersion` is `369.261113.0` and must be bumped together with the
  SDK pin, otherwise the server rejects the connection as an outdated
  client.
- Placement model: `Mail.sets` (type-model field 1465) references
  `MailSet` (`refTypeId: 429`), not `MailSetEntry`; the folder is resolved
  through `MailSet.entries` (the folder's entries list id), while
  `messages.tuta_list_id` stays the Mail's own list id so content reloads
  can still find the mail.

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

