# tuta-bridge

Use a Tuta Mail account with any standard mail, address-book and calendar
client. The bridge runs on your machine, talks to Tuta through the official
Rust SDK, decrypts locally, and serves everything over standard protocols on
`127.0.0.1` — the same idea as the Proton bridge, for Tuta.

## Features

| Protocol | Port | Enabled by | What you get |
|---|---|---|---|
| **IMAP** (TLS) | `9930` | always on | folders, mail, attachments, read/unread, **move**, **delete**, search, IDLE push |
| **POP3S** | `9950` | `pop3_port` | read-only Inbox download; mail always stays on the server |
| **SMTP submission** | `9925` | `smtp_port` | send mail: attachments, Bcc, aliases — see the warning below |
| **CardDAV** | `9932` | `carddav_port` | read-only contacts (vCard 4.0), address auto-complete |
| **CalDAV** | `9933` | `caldav_port` | read-only calendars: recurring events, time zones, reminders |

All listeners share the same design: `127.0.0.1` only, one self-signed
certificate, one bridge password, bounded connections, and live updates
through Tuta's event stream — a mail moved in the web client is moved in
your client within seconds. Credentials live only in the system keyring
(Secret Service / Keychain / Credential Manager). The local index is
metadata-only: no message bodies, contacts or events are ever written to
disk — data is decrypted on demand.

## Quick start

```sh
cargo build --release
./target/release/tuta-bridge login    # interactive: address, password, TOTP
./target/release/tuta-bridge passwd   # sets the bridge password clients use
./target/release/tuta-bridge serve    # IMAP on 127.0.0.1:9930 (Ctrl-C to stop)
```

Enable the optional protocols in `~/.config/tuta-bridge/config.toml`:

```toml
pop3_port = 9950
smtp_port = 9925
carddav_port = 9932
caldav_port = 9933
```

Run it as a `systemd --user` service instead of a terminal (Linux):

```sh
cargo install --path .
install -Dm644 contrib/systemd/tuta-bridge.service \
    ~/.config/systemd/user/tuta-bridge.service
systemctl --user daemon-reload && systemctl --user enable --now tuta-bridge
journalctl --user -u tuta-bridge -f
```

## Client setup (Thunderbird)

Username is always your Tuta address; password is the bridge password;
accept the self-signed certificate on first connect (CalDAV needs the
exception added by hand in *Settings → Privacy & Security → Certificates*,
because the calendar dialog cannot show the prompt).

| Service | Type | Host / URL | Security |
|---|---|---|---|
| Incoming mail | IMAP | `127.0.0.1:9930` | SSL/TLS |
| Outgoing mail | SMTP | `127.0.0.1:9925` | SSL/TLS |
| Inbox-only download | POP3 | `127.0.0.1:9950` | SSL/TLS |
| Address book | CardDAV | `https://127.0.0.1:9932/` | via dialog |
| Calendars | CalDAV | `https://127.0.0.1:9933/` | via dialog |

Use the manual account dialog for mail (not the automatic one). mbsync and
other standard clients work too — see the detailed reference.

## Commands

| Command | What it does |
|---|---|
| `login` / `logout` | interactive login / remove credentials and the active account |
| `status` | show the active account (no network call) |
| `passwd` | set or change the bridge password (prompted twice, hidden) |
| `sync` | index folders and headers; safe to run repeatedly |
| `resync` | rebuild the index (changes `UIDVALIDITY`; clients redownload) |
| `watch` | keep the index current from the live event stream, no server |
| `serve` | run the protocol servers next to the watch loop |
| `dump` | write one folder's mail as decrypted `.eml` files |

## Warnings

- **SMTP is not end-to-end encrypted.** Mail sent through the bridge is a
  *non-confidential* Tuta mail: readable by Tuta's servers in transit, even
  for Tuta recipients. Use the web client for mail that must stay
  end-to-end encrypted. (Blocked upstream: the SDK exposes no public-key
  operations yet.)
- **`dump` writes plaintext.** The `.eml` files are your decrypted mail;
  put them somewhere private and delete them when done.
- **CardDAV and CalDAV are read-only**: edits in your client are refused
  (`403`), the same way IMAP writes once were. POP3 never deletes from the
  server.

One account at a time. Exit codes, per-protocol limits, field mappings and
troubleshooting live in the
[detailed reference](docs/client-and-protocol-details.md); design notes in
[NOTES.md](NOTES.md).

## Development

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

## License

GPL-3.0-only — see [LICENSE](LICENSE). The bridge links the GPL-3.0
`tuta-sdk`, so it carries the same terms.
