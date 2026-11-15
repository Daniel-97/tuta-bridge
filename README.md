# tuta-bridge

Local command-line bridge for Tuta Mail. It logs in to a Tuta account, reads mail through the official Tuta Rust SDK, and exposes the decrypted data to local tooling.

Status: M0–M2 in progress

## Credentials

- Credentials are stored only in the system Secret Service (service name `tuta-bridge`, username = mail address). There is no file fallback.
- The password and TOTP code are never accepted from command-line arguments or environment variables.

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

# Remove stored credentials and clear the active account
tuta-bridge logout
```

## Development

```sh
source "$HOME/.cargo/env"
cargo test
cargo fmt --check
cargo clippy --all-targets -- -D warnings
```

See `NOTES.md` for SDK pinning and protocol notes.
