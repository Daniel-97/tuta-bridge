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
tuta-bridge dump --folder "My Projects" --limit 0 --out ~/tuta-projects
```

- `--folder` matches a system folder alias (`inbox`, `sent`, `drafts`, `trash`, `junk`, `archive`) or a custom folder name, case-insensitively.
- `--limit` caps how many messages are read; `0` means no cap.
- `--out` is created with mode `0700` if it does not exist. Re-running over the same folder overwrites the same filenames with the same bytes.
- Each message that fails to decrypt or render is skipped and reported in the summary; a partial dump exits with code `7`.

> **Warning:** the `.eml` files are the **decrypted plaintext** of your mail — including subjects, addresses, and bodies. Store them somewhere private and delete them when you are done.

## Development

```sh
source "$HOME/.cargo/env"
cargo test
cargo fmt --check
cargo clippy --all-targets -- -D warnings
```

See `NOTES.md` for SDK pinning and protocol notes.
