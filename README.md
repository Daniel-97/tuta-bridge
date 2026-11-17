# tuta-bridge

Local command-line bridge for Tuta Mail. It logs in to a Tuta account, reads mail through the official Tuta Rust SDK, and exposes the decrypted data to local tooling.

Status: M0–M4 complete for a single account (login, status/logout, dump, minimal state, sync, and live event watching). IMAP/SMTP are not implemented yet.

## Credentials

- Credentials are stored only in the system Secret Service (service name `tuta-bridge`, username = mail address). There is no file fallback.
- The password and TOTP code are never accepted from command-line arguments or environment variables.

## State and sync

The bridge keeps only the protocol state needed by IMAP: stable UIDs,
`UIDVALIDITY`, the last event batch, and a lightweight header index. It never
stores message bodies, attachments, or complete `.eml` files; those remain in
Thunderbird's own cache.

```sh
# Index folders and mail headers; safe to run repeatedly
tuta-bridge sync

# Invalidate all UIDs/UIDVALIDITY and rebuild the index
tuta-bridge resync

# Keep the index current by streaming live Tuta events
tuta-bridge watch
```

- `sync` is idempotent: known mail keeps its UID; new mail gets the next one.
- Mail deleted or moved in Tuta is removed from the index on the next sync.
- `resync` deliberately changes `UIDVALIDITY`, so IMAP clients redownload
  headers. Use it only when the state is suspect.
- The state database is `$XDG_DATA_HOME/tuta-bridge/state.sqlite3`
  (`0600`), inside a `0700` directory.

### Watch

`tuta-bridge watch` keeps the index current: it opens a single websocket to
the Tuta event bus and applies incoming events to the header index
incrementally, with no polling and no second backend. It resumes the stored
session (run `login` first) and runs until Ctrl-C.

- On startup it runs a baseline `sync` when the index is empty or an event
  group has no stored batch marker, and a full `resync` when a stored batch
  marker is older than 45 days, because the server can no longer replay
  batches that old.
- Each batch is applied in the same transaction that stores its batch
  marker, so a restart or a replayed batch neither duplicates nor skips
  changes.
- A dropped connection reconnects with a capped backoff (5 s, 20 s, then
  60 s) and resumes from the stored batch markers.
- Authentication and session closes are fatal: `watch` stops and tells the
  user to run `login` again. A rate-limited close reconnects like any
  other network error.
- The output is fixed text and counters only; ids, tokens, subjects, and
  addresses never appear in it.

Limits:

- A folder deleted in Tuta is removed from the index by the next `sync`;
  `watch` does not act on folder-deletion events.
- A `MailSetEntry` deletion is reconciled by the accompanying `Mail` update
  in the same batch, or by the next `sync`.
- `watch` never fetches or stores message bodies, attachments, or `.eml`
  files; event lookups reload header metadata only.

## Dump

Write messages from a mailbox folder to one `.eml` file per message:

```sh
tuta-bridge dump --folder inbox --limit 100 --out ~/tuta-inbox
tuta-bridge dump --folder "My Projects" --limit 50 --out ~/tuta-projects
```

- `--folder` matches a system folder alias (`inbox`, `sent`, `drafts`, `trash`, `junk`, `archive`) or a custom folder name, case-insensitively.
- `--limit` caps how many messages are read; it must be a positive integer.
- `--out` is created with mode `0700` if it does not exist. Re-running over the same folder overwrites the same filenames with the same bytes.
- Each message that fails to decrypt or render is skipped and reported in the summary; a partial dump exits with code `7`.

> **Warning:** the `.eml` files are the **decrypted plaintext** of your mail — including subjects, addresses, and bodies. They are written with mode `0600`, and the output directory with `0700`. Store them somewhere private and delete them when you are done.

## Manual acceptance

These commands exercise the full stack against a real account and must be run
by a human; they are not run by the automated test suite.

```sh
# Interactive login (prompts for mail address, password, and TOTP)
tuta-bridge login

# Show the currently active account (no network call)
tuta-bridge status

# Dump a folder to a private directory
tuta-bridge dump --folder inbox --limit 10 --out ~/tuta-inbox

# Watch live events and keep the index current (Ctrl-C to stop)
tuta-bridge watch

# Remove stored credentials and clear the active account
tuta-bridge logout
```

## Debugging HTTP errors

Errors are printed to stderr. To also print the HTTP phase, path, status, and
a sanitized server error body (sensitive JSON fields are redacted), add the
global `--debug` flag:

```bash
cargo run -- --debug login
```

The diagnostic line may include a server-provided error message; review it
before sharing.

## Development

```sh
source "$HOME/.cargo/env"
cargo test
cargo fmt --check
cargo clippy --all-targets -- -D warnings
```

See `NOTES.md` for SDK pinning and protocol notes.
