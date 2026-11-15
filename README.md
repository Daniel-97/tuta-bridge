# tuta-bridge

Local command-line bridge for Tuta Mail. It logs in to a Tuta account, reads mail through the official Tuta Rust SDK, and exposes the decrypted data to local tooling.

Status: M0–M2 in progress

## Credentials

- Credentials are stored only in the system Secret Service (service name `tuta-bridge`, username = mail address). There is no file fallback.
- The password and TOTP code are never accepted from command-line arguments or environment variables.

## Development

```sh
source "$HOME/.cargo/env"
cargo test
cargo fmt --check
cargo clippy --all-targets -- -D warnings
```

See `NOTES.md` for SDK pinning and protocol notes.
