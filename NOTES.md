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
- Manual acceptance against a real account is pending; record the twice-sync/resync/no-content results here when run.

## M1/M2 manual acceptance (2026-11-16)

- Login with password + TOTP against `https://app.tuta.com` succeeded; credentials were persisted in the Secret Service and `status` showed the account.
- KDF was Argon2id (`kdfVersion = 1`); no bcrypt migration.
- `dump --folder inbox --limit 3 --out ./out` wrote 3 `.eml` files. The message with a PDF attachment produced a valid 3-page PDF, and the MIME parts included `text/plain` and `text/html`.
- A second dump over the same folder produced identical filenames and SHA-256 hashes.
- TOTP input is echoed on the terminal by request; the password remains hidden.

