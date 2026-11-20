# tuta-bridge

Local command-line bridge for Tuta Mail. It logs in to a Tuta account, reads mail through the official Tuta Rust SDK, and exposes the decrypted data to local tooling.

Status: M0–M6 implemented for a single account (login, status/logout, dump, minimal state, sync, live event watching, an IMAP server with read/unread, move and delete, an optional read-only POP3 server, and optional SMTP submission). Sending is **not end-to-end encrypted** — see "SMTP submission" below.

## Credentials

- Credentials are stored only in the system keyring — the Secret Service on Linux, the Keychain on macOS, the Credential Manager on Windows (service name `tuta-bridge`, username = mail address). There is no file fallback.
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
  headers. Use it only when the state is suspect. It loads the folders and
  headers before it deletes anything, so a `resync` that cannot reach Tuta
  fails and leaves the index as it was.
- Every mailbox has its own `UIDVALIDITY`, and a folder renamed in Tuta gets
  a new one (its UIDs are kept): a mailbox name and `UIDVALIDITY` never
  refer to two different folders.
- Only one of `sync`, `resync`, `watch`, and `serve` can run at a time. They
  share a lock file (`state.sqlite3.lock`); starting a second one fails
  immediately (exit code 2) with `error: storage error: the state database
  is in use by another tuta-bridge process (sync, resync, watch or serve);
  stop it first`. Stop
  `watch`/`serve` before running `sync` or `resync`. The lock is released
  when the process ends, however it ends. (On non-Unix platforms there is
  no lock.)
- The state database is `$XDG_DATA_HOME/tuta-bridge/state.sqlite3`
  (`0600`), inside a `0700` directory. It is upgraded in place when a newer
  `tuta-bridge` opens it; an older `tuta-bridge` refuses a database written
  by a newer one instead of modifying it.

### Watch

`tuta-bridge watch` keeps the index current: it opens a single websocket to
the Tuta event bus and applies incoming events to the header index
incrementally, with no polling and no second backend. It resumes the stored
session (run `login` first) and runs until Ctrl-C.

- On startup it runs the same non-destructive `sync` when the index is
  empty, an event group has no stored batch marker, or a stored marker is
  older than 45 days (the server can no longer replay batches that old).
  It prints that sync's counters. `watch` never resets the index: UIDs and
  `UIDVALIDITY` survive every recovery, and only the explicit `resync`
  command changes them.
- Each batch is applied in the same transaction that stores its batch
  marker, so a restart or a replayed batch neither duplicates nor skips
  changes.
- A batch whose lookups fail is not applied and its marker does not move;
  it is retried with the backoff. After ten failed attempts `watch` falls
  back to the non-destructive `sync` and resumes the stream from just
  before that sync started. The same sync takes over when the server keeps
  replaying an event message that cannot be parsed (three reconnects in a
  row).
- A dropped connection, and a sync that cannot reach Tuta, retry with a
  capped backoff (5 s, 20 s, then 60 s); the stream resumes from the
  stored batch markers.
- A folder deleted in Tuta is removed from the index when its deletion
  event arrives: `watch` reloads the folder list and drops the mailboxes
  that are gone. If the list cannot be loaded, it tries again after the
  next batch or reconnect. No separate `sync` is needed (and none can run
  while `watch`/`serve` holds the lock).
- Authentication and session closes are fatal: `watch` stops and tells the
  user to run `login` again. A rate-limited close reconnects like any
  other network error.
- Ctrl-C takes effect at once, also during a sync or while a batch is
  being applied or retried.
- The output is fixed text and counters only; ids, tokens, subjects, and
  addresses never appear in it.

Limits:

- A `MailSetEntry` deletion is reconciled by the accompanying `Mail` update
  in the same batch, or by the next `sync`.
- A folder deletion that happened while `watch` was not running is
  reconciled by the next `sync` (run it before starting `watch`/`serve`
  again), or by the next folder-deletion event.
- `watch` never fetches or stores message bodies, attachments, or `.eml`
  files; event lookups reload header metadata only.

## IMAP server

`tuta-bridge serve` runs one process with two loops: the `watch` event
loop keeping the index current, and a TLS-only IMAP listener that
answers from it. Ctrl-C stops the process.

```sh
# Set the password IMAP clients must use (prompted twice, hidden input)
tuta-bridge passwd

# Serve IMAP while watching Tuta events (Ctrl-C to stop)
tuta-bridge serve
```

- The listener binds `127.0.0.1` only — the address is not configurable.
  The port defaults to `9930` and can be changed with the `imap_port`
  key in the config file; it is validated to be within 1..=65535, so a
  reserved port fails the command instead of silently binding an
  ephemeral one.
- On first start a self-signed certificate is generated into the data
  directory: `imap-cert.pem` and `imap-key.pem`, both mode `0600`, CN
  `localhost`, with SANs `DNS:localhost`, `IP:127.0.0.1`, and `IP:::1`.
  Existing non-empty files are reused; if either file is missing a
  fresh pair is generated.
- The bridge password — the one IMAP clients send — is stored in the
  system Secret Service (service `tuta-bridge`, account `imap-bridge`),
  never in a file and never printed. `passwd` prompts twice with hidden
  input, refuses empty or mismatched entries without storing anything,
  and overwrites the previous password. `serve` refuses to start until
  the password exists.
- Connections are bounded: at most 64 at once, 10 seconds for the TLS
  handshake, 60 seconds to log in, and 30 minutes of inactivity (or of
  one `IDLE`) once logged in. A client that stops reading is dropped
  after 60 seconds. A client cut off this way gets `* BYE` and simply
  reconnects.
- A FETCH that has to download at least 25 messages from Tuta — the
  first mass FETCH of a folder whose sizes and structures were never
  loaded, or any FETCH of that many bodies — is announced first with an
  untagged `* OK [ALERT] loading N messages from Tuta; this may take a
  while`, so the client can show why it is waiting instead of a mute
  indicator. RFC 3501 §7.1 requires clients to show ALERT text to the
  user. It is sent at most once per mailbox and connection, never for a
  FETCH the index can answer by itself (flags, envelopes, sizes and
  structures already loaded), and carries only that fixed text and the
  count. The progress bar a client draws is its own estimate from the
  `EXISTS`/`STATUS` totals; IMAP has no progress channel.
- A wrong password is answered after 3 seconds, logged as a warning
  (without the user name), and the connection is closed after the
  third failure. Failed attempts wait in a single queue, so opening
  more connections does not allow more guesses.
- Ctrl-C stops `serve`. A Ctrl-C pressed during the initial baseline
  sync takes effect only after that sync finishes; once the event
  stream is running the stop is immediate.
- `serve` resumes the stored session exactly like `watch`, so run
  `login` first; fatal authentication errors end it with the same
  message.

### Thunderbird

Use manual account configuration (not the automatic account dialog):

- Incoming, IMAP: hostname `127.0.0.1`, port `9930`, connection
  security SSL/TLS, authentication "Normal password".
- Username: the Tuta address of the logged-in account. Password: the
  bridge password set by `passwd`.
- Accept the certificate exception on first connect — the certificate
  is self-signed.
- Outgoing (SMTP), once `smtp_port` is set (see below): hostname
  `127.0.0.1`, the configured port, connection security SSL/TLS,
  authentication "Normal password", same username and password.

Marking mail read/unread, moving it between folders (drag and drop)
and deleting it (Thunderbird's default "move to Trash") are applied to
Tuta. Starring a mail (`\Flagged`) and copying a mail are refused with
`NO`: Tuta has neither.

After a send, Thunderbird uploads its own copy to Sent ("Place a copy
in Sent"). The bridge accepts that upload and discards it, because Tuta
already filed the sent copy itself (it appears through the event
stream); turning the option off saves the upload.

### mbsync

```ini
IMAPAccount tuta-bridge
Host 127.0.0.1
Port 9930
User <the Tuta address>
TLSType IMAPS
CertificateFile ~/.local/share/tuta-bridge/imap-cert.pem
# Read the password from the Secret Service instead of storing it
# (on macOS: "security find-generic-password -s tuta-bridge -a imap-bridge -w"):
PassCmd "secret-tool lookup service tuta-bridge username imap-bridge"

IMAPStore tuta-bridge-remote
Account tuta-bridge

MaildirStore tuta-bridge-local
Path ~/mail/tuta-bridge/
Inbox ~/mail/tuta-bridge/INBOX

Channel tuta-bridge
Far :tuta-bridge-remote:
Near :tuta-bridge-local:
Patterns *
Create Near
Expunge None
Sync PullNew PullFlags PushFlags
SyncState *
```

`CertificateFile` points at the bridge certificate
(`$XDG_DATA_HOME/tuta-bridge/imap-cert.pem`), so mbsync verifies TLS
without a per-host exception. `Sync PullNew PullFlags PushFlags` pulls new mail
and flag changes and pushes read/unread changes back; only `\Seen` is
kept by Tuta, so other pushed flags are refused. The `Far`/`Near` names require mbsync ≥ 1.3
(older releases spell them `Master`/`Slave`).

### Limits of v1

- **Writes.** `STORE` accepts `\Seen` (applied to Tuta) and
  `\Deleted` (kept by the session until `EXPUNGE`/`CLOSE`); every other
  flag answers `NO`, and `PERMANENTFLAGS` is `(\Seen)`. `MOVE`/`UID MOVE`
  (RFC 6851) move mail to another folder; the moved mail gets a new UID
  in the target when the Tuta event arrives. `EXPUNGE` moves `\Deleted`
  mail to Trash, and deletes it for good only when it already is in
  Trash. `COPY` answers `NO` (Tuta has no copy; `[TRYCREATE]` when the
  target does not exist). `APPEND` to Sent is accepted and discarded
  (see Thunderbird above); any other `APPEND` answers `NO`, as do folder
  mutations (`CREATE`, `DELETE`, `RENAME`, `SUBSCRIBE`,
  `UNSUBSCRIBE`). `SEARCH DELETED` stays unsupported even though
  `\Deleted` is kept per session. `EXAMINE`d mailboxes refuse every write. `UIDPLUS` is
  not advertised, so `UID EXPUNGE` is unknown.
- IDLE pushes new mail (`EXISTS`) and removals; read-state changes made
  elsewhere reach the client at its next `NOOP`/poll or during IDLE.
- `SEARCH BODY` and `SEARCH TEXT` are unsupported — bodies are never
  stored. `NEW`/`OLD` are unsupported too (`RECENT` is always zero), as
  are `ANSWERED`, `DELETED`, `DRAFT`, `FLAGGED`, and keyword keys: the
  bridge stores none of those flags, so their `UN…` forms match every
  mail. Unsupported keys answer `NO`. `SEARCH CHARSET` accepts `UTF-8`
  and `US-ASCII` only.
- Mail bodies are never written to disk. While a client downloads one
  mail in chunks (`BODY[]<offset.count>`), its session keeps that
  mail's bytes in memory — one mail, 16 MiB at most, for five minutes
  at most — so each chunk does not download the whole mail again.
- Numeric `BODY[n]` part sections are unsupported; only whole-message
  `BODY[]`, `HEADER`, `TEXT`, and `HEADER.FIELDS` sections are served.
- Mailbox changes are announced at `NOOP`, `CHECK`, and during `IDLE`
  only: removed mails as `EXPUNGE`, new ones as `EXISTS`, read-state
  changes as `FETCH (FLAGS ...)`. Between those points a session keeps
  the message numbers it last announced, so a mail that arrived since
  is not visible to `FETCH` or `SEARCH` until the next one.
- Folders are listed flat. A `/` in a folder name is shown as `∕`
  (U+2215), and folders that share a name are listed as `Name`,
  `Name (2)`, … so each stays reachable.
- One account at a time.

## POP3 server (optional)

`serve` can also answer POP3 over implicit TLS (POP3S) for clients that
only download the Inbox. It is off unless the config file names a port:

```toml
pop3_port = 9950
```

- Same listener rules as IMAP: `127.0.0.1` only, the same self-signed
  certificate, the same bridge password, the same failed-login delay.
- The maildrop is the Inbox as it was at login. `UIDL` answers
  `<uidvalidity>.<uid>`, stable across sessions, so a client that keeps
  mail on the server never downloads a message twice. Mail that leaves
  the Inbox during a session disappears from `LIST`, `STAT` and `UIDL`
  alike; a `resync` during a session ends it (`-ERR [SYS/TEMP]`) rather
  than renumbering. `CAPA` advertises `EXPIRE NEVER`.
- Connections are bounded like IMAP's: 60 seconds to log in, 10 minutes
  of inactivity, 60 seconds for a stalled write, at most 16 at once.
- Supported: `CAPA`, `USER`/`PASS`, `STAT`, `LIST`, `UIDL`, `RETR`,
  `TOP`, `NOOP`, `RSET`, `QUIT`. Messages render on demand like IMAP
  `BODY[]`.
- `DELE` answers `-ERR`: mail always stays on the server. Configure the
  client to leave messages on the server (Thunderbird's default;
  `fetchmail --keep`). POP3 has no folders, flags, push, or server-side
  search; use IMAP for those.

## SMTP submission (optional)

`serve` can accept mail to send over SMTP submission with implicit TLS.
It is off unless the config file names a port:

```toml
smtp_port = 9925
```

> **Not end-to-end encrypted.** The bridge sends every mail the way the
> Tuta web client sends a *non-confidential* mail: the mail's key is
> handed to the Tuta server, which delivers it — in plain text to
> external recipients, and readable by Tuta's servers in transit even
> for Tuta recipients. The web client encrypts Tuta-to-Tuta mail end to
> end; the bridge cannot yet, because the Tuta SDK pinned here does not
> expose the public-key operations that needs, and the bridge never
> reimplements cryptography. Use the web or desktop client for mail that
> must stay end-to-end encrypted. Password-protected mail to external
> recipients is not available either.

- Same listener rules as IMAP: `127.0.0.1` only, the same self-signed
  certificate, `AUTH PLAIN`/`AUTH LOGIN` with the account address and
  the bridge password, the same failed-login delay. Mail is accepted
  only after authentication.
- The sender must be one of the account's enabled addresses or aliases
  (compared case-insensitively). `MAIL FROM` is checked right away and
  refused with `553`; if the check cannot reach Tuta the answer is a
  temporary `451`. Envelope and header addresses must be plain
  `local@domain`.
- Connections are bounded: 60 seconds to log in, 5 minutes of
  inactivity, 10 minutes for one whole `DATA`, 60 seconds for a stalled
  write, at most 16 at once. IMAP, POP3 and SMTP share one
  failed-login delay queue.
- Recipients come from the SMTP envelope: envelope recipients that are
  not in `To:`/`Cc:` are sent as Bcc. Attachments and inline parts are
  uploaded. HTML bodies are sent as they are; plain-text bodies are
  escaped into HTML. Messages are limited to 25 MiB and bodies to 1 MiB
  (Tuta's limit).
- Tuta files the sent copy in Sent itself; it reaches IMAP clients
  through the event stream like any other new mail.
- A `250` reply means Tuta accepted the mail. If Tuta cannot be reached
  the reply is a temporary `451`, so the client keeps the mail and
  retries.
- Not carried over from the submitted message: custom headers,
  `In-Reply-To`/`References` (Tuta builds its own threading headers),
  and the `Date:` (Tuta stamps the send time).

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

# Set the local IMAP password (prompted twice, hidden)
tuta-bridge passwd

# Serve read-only IMAP on 127.0.0.1:9930 (Ctrl-C to stop)
tuta-bridge serve

# Remove stored credentials and clear the active account
tuta-bridge logout
```

## Debugging HTTP errors

Errors are printed to stderr. To also print one line per login HTTP request —
the phase, method, URL path, status code, and response body size — add the
global `--debug` flag:

```bash
cargo run -- --debug login
```

The line never contains a request or response body, the URL query, or any
header, so it carries no credentials; it does show the server host and path.

## Development

```sh
source "$HOME/.cargo/env"
cargo test
cargo fmt --check
cargo clippy --all-targets -- -D warnings
```

See `NOTES.md` for SDK pinning and protocol notes.

## License

GPL-3.0-only — see [LICENSE](LICENSE). The bridge links the GPL-3.0
`tuta-sdk`, so it carries the same terms.
