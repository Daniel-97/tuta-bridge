# tuta-bridge: detailed reference

Everything the README summarizes: per-protocol behavior and limits, client setup details, field mappings, URL layouts, the service section with its exit-code contract, and the acceptance command list. Moved here when the README was simplified; the content is unchanged.

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
  immediately (exit code 10) with `error: already in use: the state database
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
- Ctrl-C or SIGTERM stops `serve` cleanly (exit code 0). A stop requested during the initial baseline
  sync takes effect only after that sync finishes; once the event
  stream is running the stop is immediate.
- `serve` resumes the stored session exactly like `watch`, so run
  `login` first; fatal authentication errors end it with the same
  message. A resume that fails because the network is not up yet is
  retried with the same backoff as a dropped event stream.
- To run it in the background at login, see "Running as a service".

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

## CardDAV server (optional)

`serve` can serve your Tuta address book over CardDAV, to read and
write it from Thunderbird's address book and its address auto-complete.
It is off unless the config file names a port:

```toml
carddav_port = 9932
```

`serve` prints `serving CardDAV on 127.0.0.1:9932` — the
`(read-only)` suffix appears only when the session hands out no DAV
writer, and a logged-in session always hands one out.

- Same listener rules as IMAP: `127.0.0.1` only (implicit TLS, the same
  self-signed certificate), HTTP Basic with the account address and the
  bridge password, the failed-login delay shared with IMAP/POP3/SMTP, at
  most 16 connections.
- The address book is loaded in the background when `serve` starts and
  kept fresh by the event stream: a contact changed in the Tuta web
  client is updated on the client's next refresh. Every load also
  records the account's contact-list id, which a create needs. Only
  metadata (ids and ETags) is cached in the state database; vCards are
  decrypted and rendered on demand.

### Thunderbird

1. Address Book → *New Address Book* → *Add CardDAV Address Book*.
2. Username: your Tuta address. Location: `https://127.0.0.1:9932/`
   (Thunderbird finds the address book through `/.well-known/carddav`).
3. Thunderbird first asks to accept the bridge's self-signed
   certificate: confirm the security exception for `127.0.0.1:9932`
   (if the dialog does not appear, open *Settings → Privacy & Security →
   Certificates → Manage Certificates → Servers → Add Exception* and
   enter `https://127.0.0.1:9932`). Then enter the bridge password.
4. Pick *Tuta contacts*. The book is writable in Thunderbird: edits,
   new contacts and deletions go to Tuta.

### URL layout

| URL                                    | Resource                         |
|----------------------------------------|----------------------------------|
| `/`, `/.well-known/carddav`            | entry points (→ the principal)   |
| `/principal/`                          | current-user-principal           |
| `/addressbooks/`                       | addressbook-home-set             |
| `/addressbooks/contacts/`              | the address book                 |
| `/addressbooks/contacts/<id>.vcf`      | one contact                      |

### Field mapping (vCard 4.0)

| Tuta                                   | vCard                                       |
|----------------------------------------|---------------------------------------------|
| contact id                             | `UID` (`tuta-contact-<id>`)                 |
| title, first, middle, last name, suffix| `N` (and composed into `FN`)                |
| nickname                               | `NICKNAME`                                  |
| email addresses                        | `EMAIL;TYPE=home/work`                      |
| phone numbers                          | `TEL;TYPE=home/work/cell/fax`               |
| postal addresses (free text)           | `ADR;TYPE=home/work`, as the street part    |
| company, department                    | `ORG`                                       |
| job title (role)                       | `TITLE`                                     |
| birthday                               | `BDAY` (`--MMDD` without a year)            |
| first anniversary                      | `ANNIVERSARY`                               |
| websites                               | `URL;TYPE=home/work`                        |
| relationships                          | `RELATED;VALUE=text` with a `TYPE`          |
| comment                                | `NOTE`                                      |

`FN` falls back to the nickname, company, first email or first phone
number when a contact has no name. "Other" and custom-labelled values
carry no `TYPE`; the custom label text is not exported.

Dropped (no clean vCard equivalent or not loaded): the photo, social
network ids, messenger handles, pronouns, phonetic names, custom dates
other than the first anniversary, custom type labels, and the
preshared password.

### Writes (PUT and DELETE)

- `PUT` and `DELETE` are served: the session always hands the handler a
  writer. The book's `current-user-privilege-set` advertises read and
  write, so clients stop marking it read-only; every other write method
  keeps the fixed `403`.
- Preconditions run against the stored row, never the rendered body:
  `If-Match` must match the stored ETag strongly, `If-None-Match: *` on
  an existing card answers `412`, and so does a stale `If-Match`; an
  unchanged reload can never answer `412`.
- Create: a `PUT` to any unused `.vcf` href writes to Tuta first and
  answers `201` with `Location: /addressbooks/contacts/<id>.vcf` naming
  the server-generated id, plus the new `ETag`. The id in the client's
  made-up href is never stored — the client re-lists or follows
  `Location`.
- Update: `204` with the new `ETag`.
- The remote write holds before the cache is touched: a remote failure
  answers the fixed `503` (with `Retry-After`) and leaves the cache and
  its ETag untouched, so the client retries. Bodies are parsed in
  memory only; the cache stays metadata-only.
- The contact-list id is resolved structurally, not from the first
  loaded card: the `RootInstance` at (user group id, `ContactList` root
  id) → the `ContactList` entity → its `contacts` field, the same chain
  the Tuta client walks, whatever the number of contacts
  (`src/adapters/tuta/contact_source.rs::contact_list_id`). Every book
  load records it, so an empty address book can create its first
  contact; the `409` "the address book's contact list is not known yet"
  only ever fires before a load has resolved the list id — the
  resolution is retried on every load.
- Import (`src/adapters/carddav/import.rs`): vCard 4.0, the first card
  of the body, a complete `BEGIN:VCARD`…`END:VCARD` required. Folding
  is undone and CRLF or LF is accepted; vCard 3.0 grouping (`item1.TEL`)
  and bare or quoted `TYPE` parameters are accepted. `FN` fills the
  first name only when the card carries no `N`. Dropped silently, like
  Tuta's own importer: `VERSION`, `PRODID`, `REV`, `UID` (the href owns
  the identity), `PHOTO`, `CATEGORIES`, `GEO`, `TZ`, every `X-`
  property and every unrecognized name. A `BDAY`/`ANNIVERSARY` not in
  the basic form the bridge serves (`19900115`, `--0412`) refuses the
  whole card (`400`, fixed body) — it is never imported as a silently
  changed date.
- Other and Custom: the renderer writes no `TYPE` for either, so an
  exported Other field re-imports as Custom, and only an explicit
  `TYPE=other` reaches Other. The exporter serves one anniversary at
  most; the importer accepts every `ANNIVERSARY`.
- `DELETE`: a card that never existed answers `404` (no tombstone for a
  nonexistent row) and `If-Match` is enforced. The remote delete runs
  first (already-gone counts as success), then the row is tombstoned so
  `sync-collection` reports it as a `404`; the answer is `204`.
- Echo idempotence: the write upserts the new ETag and the store skips
  a row whose ETag is unchanged, so the event-bus echo of the same
  change does not count twice (`src/app/contacts.rs::apply_written`).

### Limits of v1

- `PUT` and `DELETE` are served (see "Writes"); `PROPPATCH`, `MKCOL`
  (contact groups are not creatable) and the other write methods still
  answer the fixed `403`.
- One address book: the user's own contacts. Shared contact lists and
  contact groups are not served.
- `PROPFIND` serves depth 0 and 1; `Depth: infinity` (or no `Depth`) is
  answered as depth 1.
- Reports: `addressbook-multiget`, `addressbook-query` and
  `sync-collection`. Query filters support `prop-filter` on `FN`, `N`,
  `NICKNAME`, `EMAIL`, `TEL`, `ORG` and `NOTE` with `text-match`
  (equals/contains/starts-with/ends-with, negation; collations
  `i;unicode-casemap` (default), `i;ascii-casemap` and `i;octet`) or
  `is-not-defined`, matched against the values as rendered (`FN` with
  its fallbacks and suffix). Another collation answers `403` with
  `supported-collation`; anything else (`param-filter`, other
  properties) `403` with `supported-filter`.
- Only vCard 4.0 is produced: an `address-data` asking explicitly for
  another version or type answers `403` with `supported-address-data`.
- `addressbook-query` honours `limit` by truncating (marked with a `507`
  response). `sync-collection` does not truncate: if a `DAV:limit` is
  smaller than the changes due, it answers `507`
  (`number-of-matches-within-limits`) and the client syncs without one.
- A contact that exists but fails to decrypt keeps its last cached
  entry (it is not reported deleted) but is not served until it
  decrypts again; it is counted as skipped in the console output.
- Filtered queries and multigets of more than a few cards load the
  whole address book from Tuta.

## CalDAV server (optional)

`serve` can also publish your Tuta calendars over CalDAV (HTTPS) and
accept edits, so Thunderbird and other calendar clients can show and
change them. Creating events is refused (upstream-blocked): create them
in the Tuta client, then edit them here. It is off unless the config
file names a port:

```toml
caldav_port = 9933
```

`serve` then prints `serving CalDAV on https://127.0.0.1:9933/` — a
session without a DAV writer would keep the `(read-only)` suffix, and a
logged-in session always hands one out. Same listener rules as IMAP:
`127.0.0.1` only, the same self-signed certificate, the same bridge
password (HTTP Basic over TLS), the same failed-login delay shared with
IMAP/POP3/SMTP. A port another process holds stops `serve` with exit
code 10.

### Thunderbird

1. Accept the self-signed certificate once. The calendar dialog cannot
   show the exception prompt, so add it by hand: *Settings → Privacy &
   Security → Certificates → Manage Certificates → Servers → Add
   Exception…*, enter `https://127.0.0.1:9933/`, *Get Certificate*,
   *Confirm Security Exception* (keep "Permanently store" checked).
2. *New Calendar → On the Network*. Username: the Tuta address of the
   logged-in account. Location: `https://127.0.0.1:9933/`. Leave "This
   location doesn't require credentials" unchecked.
3. *Find Calendars*, enter the bridge password when asked, and
   subscribe to the calendars you want. Each Tuta calendar is its own
   collection, with its Tuta name and colour. Each calendar advertises
   read and write; edits and deletions go to Tuta, while creating events
   is refused — create them in the Tuta app, then edit them here.

### URL layout

| URL | What |
|---|---|
| `/`, `/caldav/` | entry points; name the principal and the home set |
| `/.well-known/caldav` | redirects to the principal |
| `/caldav/principal/` | the account's principal |
| `/caldav/calendars/` | the calendar home set |
| `/caldav/calendars/<calendar>/` | one Tuta calendar |
| `/caldav/calendars/<calendar>/<event>.ics` | one event (with its moved occurrences) |

`<calendar>` is the Tuta calendar id, `<event>` a hash of the event's
UID. A series split in Tuta with "edit this and all future events"
(two series sharing one UID) is served as two `.ics`: the original
half keeps its URL and UID, the later half gets its own URL and a UID
ending in `-split-<hash>`. Tuta's birthday calendar is not served: Tuta builds it in the
client from your contacts, it is not a calendar on the server.

### How events are mapped

- `SUMMARY`, `DESCRIPTION`, `LOCATION`, `ORGANIZER`, `ATTENDEE` (with
  `PARTSTAT`: accepted, declined, tentative, needs action) and the UID
  come from the Tuta event. Tuta descriptions are HTML: `DESCRIPTION`
  carries a plain-text version, `X-ALT-DESC` the original.
- Reminders: your own Tuta alarms become `VALARM`s (display alarms,
  minutes to weeks before the start), so Thunderbird rings them.
  Other attendees' alarms are not visible to you and are not served.
- Time zones: a single event is written in UTC — Tuta stores UTC
  instants, so this is exact and every client shows it in its own
  zone. All-day events are dates (`VALUE=DATE`, exclusive end). A
  repeating event is written in the time zone its Tuta repeat rule
  uses (`DTSTART;TZID=Europe/Berlin` plus a `VTIMEZONE`), so it keeps
  its wall-clock time across daylight-saving changes exactly as in
  Tuta.
- Repeating events become an `RRULE` (daily/weekly/monthly/yearly,
  interval, end after a count or on a date, the advanced "by
  weekday/month day/…" options), removed occurrences `EXDATE`s, and
  occurrences moved in Tuta are served in the same `.ics` as the
  series (`RECURRENCE-ID`). Where Tuta and RFC 5545 disagree, the rule
  is rewritten to match what Tuta shows: a monthly event on the 29th–31st
  falls on the last day of shorter months, a yearly one on Feb 29 on
  Feb 28. "Ends after N occurrences" counts removed occurrences too,
  as in the Tuta app.
- **Degradation.** A repeat rule that cannot be expressed in iCalendar
  (an unknown repeat type, or a combination RFC 5545 forbids) is never
  approximated: the event is served as its first occurrence only, its
  description starts with *"[tuta-bridge: this event repeats in Tuta,
  but its repeat rule cannot be expressed in iCalendar …]"*, and it
  carries `X-TUTA-BRIDGE-RECURRENCE:UNSUPPORTED`.

### Writes (PUT and DELETE)

- `PUT` is an update only: the href must name a cached event row that
  is a series' own master. An unknown calendar, an href without a row,
  or a non-master (an altered occurrence) answers the fixed `403`
  `creating events is not supported: create them in the Tuta client,
  then edit them here`: creating events is upstream-blocked, since the
  pinned SDK cannot create Tuta's custom-id events (NOTES.md records
  why).
- Preconditions run against the stored resource ETag: a matching
  `If-None-Match` answers `412`, `If-Match` must match strongly, and an
  unchanged reload never answers `412`.
- The body must be exactly one `VEVENT` in a `VCALENDAR` (a
  `VTIMEZONE` is accepted and ignored). Times come in the three forms
  the renderer writes: UTC (`…Z`), a `TZID`-qualified local time naming
  a zone the bundled data knows on both bounds, or `VALUE=DATE` on both
  bounds with an exclusive end. Anything else — mixed bounds, an
  explicit UTC offset, a floating time, a missing `DTEND` — answers
  `400` with the importer's fixed message.
- The repeat rule must be one of the shapes the exporter emits
  (`src/adapters/caldav/import.rs`): `FREQ`, `INTERVAL`, `COUNT`,
  `UNTIL` (the UTC second form on a timed event, the date form on an
  all-day one), weekly `BYDAY`, and the month-end
  `BYMONTHDAY=28…31;BYSETPOS=-1` pattern of a start on the 29th–31st,
  which maps back onto Tuta's clamp to each month's last day. Anything
  else — `BYMONTH`, an ordinal `BYDAY`, a second `RRULE` — refuses the
  whole event with `400`: a rule that cannot be mapped is never
  accepted and then mangled. The renderer itself emits three shapes the
  importer refuses with the same `400`: advanced rule parts, the yearly
  Feb-29 clamp (it carries a `BYMONTH`), and the degraded
  single-occurrence form, which carries no `RRULE` at all — a `PUT` of
  it parses as a non-recurring event and would clear the repetition in
  Tuta. Such events are read-only in practice; edit them in the Tuta
  client.
- `EXDATE`, `RDATE` or `RECURRENCE-ID` refuses the event
  (occurrence-level editing is out of scope); the refusal outranks the
  one-event rule, so the body a client writes back after editing one
  occurrence fails with the occurrence message. An `ATTENDEE` other
  than the organizer (case-insensitive) refuses the event — invitations
  are out of scope and are never dropped silently. A `VALARM` is
  accepted and ignored: reminders set by clients are not carried to
  Tuta.
- `ORGANIZER` maps to its address only (the `CN` parameter is accepted
  and dropped; an unusable value is treated as no organizer, a personal
  event). The address must be one of the account's, and only the
  primary address is known without a network call, so aliases answer
  the fixed `403` `the organizer is not an address of this account`.
- The update goes remote first: the writer reloads the stored event,
  applies the parsed fields and `update_instance`s it back (uid,
  sequence, recurrence, alarms and attendees stay as the Tuta client
  keeps them). The row is then rebuilt from the reloaded event — the
  same row, fingerprint and all, that the reader derives — and
  upserted, so the `204`'s `ETag` is the one the next read serves and
  the event-bus echo of the same change counts once
  (`src/app/calendar_sync.rs::apply_written`). The two-year loading
  window is deliberately not applied to a written row: an event moved
  beyond the window keeps its row until the echo removes it, exactly as
  an edit made in the Tuta client does, so the client sees the write it
  just made.
- Two honest degenerates: a legacy event whose missing uid a write
  repaired moves to another href — `204` without an `ETag`; a state
  that cannot be read back after a held write answers the fixed `503`
  (`Retry-After`) and keeps the row as it was.
- `DELETE` removes the whole resource: every event of the series is
  deleted remotely first (already-gone counts as done), then the rows
  are removed the way a delete event removes them. The calendar cache
  keeps no tombstones and there is no `sync-collection`, so a href that
  never existed answers `404`; `If-Match` is enforced; the answer is
  `204`.

### Freshness

On start `serve` loads every calendar and the events from two years
back to two years ahead (every repeating event that has not ended
yet, whatever its start), and keeps them current from the Tuta event
stream: an event created or changed in the Tuta app is visible on
Thunderbird's next refresh. Unchanged events keep their ETags and the
calendar its `getctag`, so a refresh with no change transfers nothing.
Event bodies are not stored: they are decrypted and rendered on demand.

### Limits of v1

- `PUT` and `DELETE` are served (see "Writes"); `PROPPATCH`,
  `MKCALENDAR` and the other write methods still answer the fixed
  `403`, and creating events is refused — create them in the Tuta app
  and edit them here.
- Events starting more than two years in the past or in the future
  are not served (repeating events excepted).
- Reports: `calendar-query` (the first `time-range` of the filter is
  applied; `expand` is ignored, clients expand rules themselves) and
  `calendar-multiget`. No `sync-collection` (WebDAV sync): clients
  use `getctag`/`getetag`. `Depth: infinity` is answered as `Depth: 1`.
- No scheduling (iTIP): invitations are answered in the Tuta app.
- No tasks (`VTODO`) — Tuta has none.

## Running as a service

On Linux `serve` can run as a `systemd --user` service: it starts at login
with no terminal, comes back after a crash or a kill, and logs to the
journal. The unit is `contrib/systemd/tuta-bridge.service`; it expects the
binary at `~/.cargo/bin/tuta-bridge` (edit `ExecStart` otherwise).

```sh
cargo install --path .
tuta-bridge login     # once, interactively
tuta-bridge passwd    # once, interactively

install -Dm644 contrib/systemd/tuta-bridge.service \
    ~/.config/systemd/user/tuta-bridge.service
systemctl --user daemon-reload
systemctl --user enable --now tuta-bridge

systemctl --user status tuta-bridge     # state and last log lines
journalctl --user -u tuta-bridge -f     # follow the log
systemctl --user stop tuta-bridge       # stop until the next login
systemctl --user disable --now tuta-bridge
```

The log holds what `serve` prints in a terminal: listen addresses,
counters, and fixed error strings — never subjects, addresses, or ids.
Colours are turned off when stderr is not a terminal.

### Restart policy and exit codes

`serve` separates failures a restart can fix from failures that need you.
Its exit code carries that distinction, and the unit restarts only on the
first kind (`Restart=always`, `RestartSec=10`,
`RestartPreventExitStatus=1 3 4 5 8 9 10`). A unit stopped with
`systemctl --user stop` is never restarted. Five starts within two minutes
stop the restarts as well; the unit then stays failed until
`systemctl --user reset-failed tuta-bridge`.

| Exit | Meaning | Restarted | What to do |
| ---- | ------- | --------- | ---------- |
| 0 | stopped by Ctrl-C or SIGTERM | only after a kill | — |
| 1 | configuration error, local password missing | no | fix the config, run `tuta-bridge passwd` |
| 2 | storage error (state database) | yes | if it repeats, check the data directory |
| 3 | no active account or stored credentials | no | `tuta-bridge login` |
| 4 | session expired or revoked, second factor required | no | `tuta-bridge login` again |
| 5 | folder not found | no | — |
| 6 | network error | yes | — |
| 8 | system keyring unavailable or locked | no | unlock the keyring, then `systemctl --user start tuta-bridge` |
| 9 | unsupported: server model or client version changed, state database from a newer build | no | update tuta-bridge |
| 10 | already in use: another bridge holds the state lock, or a port is taken | no | stop the other process |

A network that is down when the service starts (at boot or before Wi-Fi
connects) does not end `serve`: the session resume is retried in-process
with backoff, like a dropped event stream.

### Troubleshooting

- **Keyring locked or unavailable** (`error: system keyring unavailable:
  the Secret Service is not running or the keyring is locked`, exit 8).
  `serve` reads the Tuta session and the local IMAP password from the
  Secret Service, which works only when your keyring is unlocked in the
  session — normally at a graphical login with the keyring password equal
  to the login password. Do not enable lingering (`loginctl
  enable-linger`) for this unit: without a login nothing unlocks the
  keyring. If the keyring is locked, the desktop may show an unlock
  prompt when the unit starts; dismissing it ends the unit with exit 8.
  Check that a Secret Service is running (`busctl --user list | grep
  org.freedesktop.secrets`) and that the login keyring is unlocked (for
  example in Seahorse), then start the unit again.
- **Port already in use** (`error: already in use: imap port 9930 is
  already in use`, exit 10). Another program, or a bridge started by
  hand, holds the port: `ss -ltnp 'sport = :9930'`. Stop it, or change
  `imap_port` (and `pop3_port`/`smtp_port`) in the config.
- **Lock held by another instance** (`error: already in use: the state
  database is in use by another tuta-bridge process`, exit 10). A `serve`,
  `watch`, `sync`, or `resync` is running elsewhere, for example in a
  terminal: stop it, then start the unit.
- **Session expired** (`error: login failed: ... run login again`, exit 4).
  The unit stops once and stays stopped: run `tuta-bridge login`, then
  `systemctl --user start tuta-bridge`.

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

# Run serve as a systemd --user service (Linux, see "Running as a service")
systemctl --user enable --now tuta-bridge

# Remove stored credentials and clear the active account
tuta-bridge logout
```

