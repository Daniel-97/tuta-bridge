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

## Pagination

- Mail listing uses `load_range` with `CustomId(GeneratedId::max_id().to_string())` as the start id and `DESC` ordering.

## SDK limitations

- The SDK's `create_session` does not support 2FA.
- It hardcodes Argon2id for the password KDF. Do not assume other KDF parameters.

## Wire encoding

- Tuta JSON encodes numbers as strings.
- Byte fields are encoded as base64.

## Mail content model

- `MailDetailsBlob` is encrypted with the mail's session key.
- Attachments are `TutanotaFile` instances, each referencing blobs that are decrypted separately.
