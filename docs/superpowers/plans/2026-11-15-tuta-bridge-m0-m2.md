# Tuta Bridge M0–M2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Rust CLI that logs in to a Tuta account with password + TOTP, stores the session in the system Secret Service, and dumps messages with body and attachments as `.eml` files.

**Architecture:** A single crate with a library and a thin binary. Domain types and use cases depend only on small ports; all Tuta SDK and I/O code lives in adapters. The first block stops before IMAP, SMTP, SQLite, and the event bus.

**Tech Stack:** Rust 2021, `tuta-sdk` pinned to Tuta commit `5dba96493532804ebd5a541024aa217ca3b7874d`, `tokio`, `clap`, `keyring` 3, `rpassword`, `secrecy`, `serde`, `toml`, `mail-builder` 2, `mail-parser` 1, `tracing`, `wiremock` (dev).

**Spec:** `docs/superpowers/specs/2026-11-15-tuta-bridge-m0-m2-design.md`; parent `tuta-bridge-spec.md`.

## Global Constraints

- All code, identifiers, comments, and commit messages in English. Design docs in Italian.
- Never write passwords, TOTP codes, access tokens, decrypted keys, subjects, addresses, or bodies to logs, errors, fixtures, or commits.
- Credentials are stored only in the Secret Service, service name `tuta-bridge`, username = mail address. No file fallback.
- The password and TOTP code are never accepted from argv or environment variables.
- `clientIdentifier` sent to Tuta is exactly `tuta-bridge`.
- Tuta SDK pinned to `rev = 5dba96493532804ebd5a541024aa217ca3b7874d` with `features = ["net"]`. Do not upgrade it in this plan.
- No automated test contacts the real Tuta server. Real-account commands are run manually by the user.
- Listen on nothing; this block opens only outbound HTTPS.
- License is undecided: do not add a `LICENSE` file.
- `cargo fmt` and `cargo clippy --all-targets -- -D warnings` must pass before every commit.

## Review Focus

These are the conditions most likely to break a person using this software. Each gets a test in the task that owns the code.

1. A message whose body is HTML-only with an inline `cid:` image: the `.eml` must show the image and still have a plain-text alternative.
2. A subject or filename containing non-ASCII text or `\r\n` (header injection): headers must be encoded, never split into new headers.
3. A message with missing `MailDetails` or an attachment that fails to decrypt: `dump` must continue, report it, and exit non-zero.
4. An account using bcrypt KDF or a non-TOTP second factor: login must stop with an explicit message, never hang or silently migrate.
5. Running `dump` twice on the same folder: filenames and bytes must be identical.

---

### Task 1: Project skeleton and CLI parser

**Files:**
- Create: `Cargo.toml`
- Create: `.gitignore`
- Create: `src/lib.rs`
- Create: `src/main.rs`
- Create: `src/adapters/mod.rs`
- Create: `src/adapters/cli.rs`
- Create: `NOTES.md`
- Create: `README.md`

**Interfaces:**
- Consumes: nothing.
- Produces: `tuta_bridge::adapters::cli::{Cli, Command, parse_from}`; `Cli.base_url: Option<String>`; `Command::{Login { email: Option<String> }, Logout, Status, Dump { folder: String, limit: usize, out: PathBuf }}`.

- [ ] **Step 1: Write the failing CLI parser test**

In `src/adapters/cli.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_status() {
        let cli = parse_from(["tuta-bridge", "status"]).unwrap();
        assert!(matches!(cli.command, Command::Status));
        assert_eq!(cli.base_url, None);
    }

    #[test]
    fn parses_login_email_and_dump() {
        let cli = parse_from(["tuta-bridge", "login", "--email", "a@b.c"]).unwrap();
        assert!(matches!(cli.command, Command::Login { email: Some(ref e) } if e == "a@b.c"));

        let cli = parse_from([
            "tuta-bridge", "--base-url", "http://127.0.0.1:9", "dump",
            "--folder", "inbox", "--limit", "10", "--out", "/tmp/x",
        ])
        .unwrap();
        assert_eq!(cli.base_url.as_deref(), Some("http://127.0.0.1:9"));
        assert!(matches!(cli.command, Command::Dump { ref folder, limit: 10, ref out }
            if folder == "inbox" && out == std::path::Path::new("/tmp/x")));
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `source "$HOME/.cargo/env" && cargo test adapters::cli -- --nocapture`
Expected: FAIL because `Cargo.toml` or the types do not exist.

- [ ] **Step 3: Create the manifest and parser**

`Cargo.toml`:

```toml
[package]
name = "tuta-bridge"
version = "0.1.0"
edition = "2021"
rust-version = "1.84"

[dependencies]
tuta-sdk = { git = "https://github.com/tutao/tutanota.git", rev = "5dba96493532804ebd5a541024aa217ca3b7874d", features = ["net"] }
crypto-primitives = { git = "https://github.com/tutao/tutanota.git", rev = "5dba96493532804ebd5a541024aa217ca3b7874d", package = "crypto-primitives", default-features = false }
tokio = { version = "1", features = ["rt-multi-thread", "macros", "time"] }
clap = { version = "4", features = ["derive"] }
async-trait = "0.1"
rpassword = "7"
keyring = "3"
secrecy = "0.10"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
toml = "0.8"
thiserror = "2"
anyhow = "1"
base64 = "0.22"
rand_core = { version = "0.6", features = ["getrandom"] }
time = { version = "0.3", features = ["formatting", "parsing", "macros"] }
mail-builder = "2"
mail-parser = "1"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }

[dev-dependencies]
tempfile = "3"
wiremock = "0.6"
```

`.gitignore`:

```text
/target
*.eml
/out
```

In `src/adapters/cli.rs`, define:

```rust
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "tuta-bridge", version, about = "Local CLI bridge for Tuta Mail")]
pub struct Cli {
    #[arg(long, global = true)]
    pub base_url: Option<String>,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Login { #[arg(long)] email: Option<String> },
    Logout,
    Status,
    Dump {
        #[arg(long)] folder: String,
        #[arg(long)] limit: usize,
        #[arg(long)] out: PathBuf,
    },
}

pub fn parse_from<I, T>(args: I) -> Result<Cli, clap::Error>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    Cli::try_parse_from(args)
}
```

`src/lib.rs`:

```rust
pub mod adapters;
```

`src/adapters/mod.rs`:

```rust
pub mod cli;
```

`src/main.rs`:

```rust
fn main() -> anyhow::Result<()> {
    let _ = tuta_bridge::adapters::cli::parse_from(std::env::args_os())?;
    Ok(())
}
```

`NOTES.md` must record, in English: the pinned commit and version; the build check; that the server type model is fetched at runtime from `ApplicationTypesService`; that pagination uses `load_range` with `CustomId(GeneratedId::max_id().to_string())` and `DESC`; that the SDK's `create_session` lacks 2FA and hardcodes Argon2id; that Tuta JSON encodes numbers as strings and bytes as base64; and that `MailDetailsBlob` uses the mail's session key while attachments are `TutanotaFile` with blobs. `README.md` starts with the project description and a "Status: M0–M2 in progress" line.

- [ ] **Step 4: Run tests and checks**

Run: `source "$HOME/.cargo/env" && cargo test && cargo fmt --check && cargo clippy --all-targets -- -D warnings`
Expected: all tests pass, formatting clean, clippy exits 0. Cargo may warn that later-task dependencies are not used yet; those warnings disappear as tasks land.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock .gitignore src NOTES.md README.md
git commit -m "chore: bootstrap tuta-bridge crate and CLI parser"
```

---

### Task 2: Configuration file and base URL precedence

**Files:**
- Create: `src/config.rs`
- Modify: `src/lib.rs`
- Test: `src/config.rs` (unit tests)

**Interfaces:**
- Consumes: nothing.
- Produces: `Config { active_account: Option<String>, base_url: String }`; `Config::load(&Path)`, `Config::save(&Path)`, `resolve_base_url(cli: Option<&str>, env: Option<&str>, config: &Config) -> String`, `config_path() -> anyhow::Result<PathBuf>`, `data_dir() -> anyhow::Result<PathBuf>`.

- [ ] **Step 1: Write failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_file_returns_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = Config::load(&dir.path().join("config.toml")).unwrap();
        assert_eq!(cfg.active_account, None);
        assert_eq!(cfg.base_url, "https://app.tuta.com");
    }

    #[test]
    fn roundtrips_and_resolves_precedence() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let cfg = Config { active_account: Some("a@b.c".into()), base_url: "https://cfg.example".into() };
        cfg.save(&path).unwrap();
        assert_eq!(Config::load(&path).unwrap(), cfg);
        assert_eq!(resolve_base_url(Some("https://cli.example"), Some("https://env.example"), &cfg), "https://cli.example");
        assert_eq!(resolve_base_url(None, Some("https://env.example"), &cfg), "https://env.example");
        assert_eq!(resolve_base_url(None, None, &cfg), "https://cfg.example");
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test config::tests`
Expected: FAIL with `cannot find struct Config`.

- [ ] **Step 3: Implement**

Use `serde::{Serialize, Deserialize}` and `toml`. `Config::load` returns defaults when the file is absent; parse errors become `anyhow` errors with the path but no file content. `Config::save` creates the parent directory with mode `0700` on Unix. `config_path` uses `$XDG_CONFIG_HOME/tuta-bridge/config.toml`, falling back to `$HOME/.config/tuta-bridge/config.toml`; `data_dir` uses `$XDG_DATA_HOME/tuta-bridge`, falling back to `$HOME/.local/share/tuta-bridge`, creates it with mode `0700`, and returns it.

- [ ] **Step 4: Run tests and checks, then commit**

Run: `cargo test config::tests && cargo fmt --check && cargo clippy --all-targets -- -D warnings`

```bash
git add src/config.rs src/lib.rs
git commit -m "feat: add XDG config with active account and base URL"
```

---

### Task 3: Domain types, errors, and ports

**Files:**
- Create: `src/domain/mod.rs`
- Create: `src/domain/account.rs`
- Create: `src/domain/mail.rs`
- Create: `src/domain/error.rs`
- Create: `src/ports/mod.rs`
- Create: `src/ports/credentials.rs`
- Create: `src/ports/prompt.rs`
- Create: `src/ports/session.rs`
- Create: `src/ports/mail_source.rs`
- Create: `src/ports/renderer.rs`
- Modify: `src/lib.rs`
- Test: `src/domain/mail.rs`, `src/domain/error.rs` (unit tests)

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `AccountId(pub String)` with `Display`.
  - `StoredCredentials { login: String, user_id: String, access_token: String, encrypted_passphrase_key: Vec<u8> }` with `Serialize`, `Deserialize`, `Clone`.
  - `AccountInfo { mail_address: String, user_id: String }`, `Clone`.
  - `FolderKind { Inbox, Sent, Drafts, Trash, Junk, Archive, Custom }` with `FolderKind::from_alias(&str) -> Option<Self>`.
  - `Folder { list_id: String, name: String, kind: FolderKind }`.
  - `MessageSummary { list_id: String, element_id: String, received_at_ms: i64, subject: String, unread: bool }` with `file_stem()`.
  - `Address { name: Option<String>, address: String }`.
  - `Attachment { name: String, mime_type: String, data: Vec<u8>, cid: Option<String> }`.
  - `MessageContent { summary: MessageSummary, from: Address, to: Vec<Address>, cc: Vec<Address>, bcc: Vec<Address>, reply_to: Vec<Address>, sent_at_ms: i64, subject: String, message_id: Option<String>, in_reply_to: Option<String>, references: Vec<String>, body_html: Option<String>, body_text: Option<String>, attachments: Vec<Attachment> }`.
  - `Error` (thiserror) with variants `NoActiveAccount`, `MissingCredentials(String)`, `Login(String)`, `SecondFactor(String)`, `BcryptUnsupported`, `FolderNotFound(String)`, `Network(String)`, `Storage(String)`, `Config(String)`, `Message(String)`, `Unsupported(String)`, `PartialDump { failed: usize }`; `Error::exit_code(&self) -> u8`; `type Result<T> = std::result::Result<T, Error>`.
  - Ports: `CredentialStore`, `LoginPrompt`, `SessionFactory`, `Session`, `MailSource`, `MessageRenderer`.

- [ ] **Step 1: Write failing tests**

In `src/domain/mail.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aliases_are_case_insensitive() {
        assert_eq!(FolderKind::from_alias("Inbox"), Some(FolderKind::Inbox));
        assert_eq!(FolderKind::from_alias("TRASH"), Some(FolderKind::Trash));
        assert_eq!(FolderKind::from_alias("custom-folder"), None);
    }

    #[test]
    fn file_stem_is_stable_and_safe() {
        let s = MessageSummary {
            list_id: "list".into(), element_id: "abc-_123".into(),
            received_at_ms: 1_700_000_000_000, subject: "ignored".into(), unread: false,
        };
        assert_eq!(s.file_stem(), "20231114-221320-abc-_123");
    }
}
```

In `src/domain/error.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_are_distinct() {
        assert_eq!(Error::NoActiveAccount.exit_code(), 3);
        assert_eq!(Error::MissingCredentials("x".into()).exit_code(), 3);
        assert_eq!(Error::Login("x".into()).exit_code(), 4);
        assert_eq!(Error::SecondFactor("x".into()).exit_code(), 4);
        assert_eq!(Error::BcryptUnsupported.exit_code(), 4);
        assert_eq!(Error::FolderNotFound("x".into()).exit_code(), 5);
        assert_eq!(Error::Network("x".into()).exit_code(), 6);
        assert_eq!(Error::PartialDump { failed: 2 }.exit_code(), 7);
        assert_eq!(Error::Config("x".into()).exit_code(), 1);
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test domain::`
Expected: FAIL because the modules do not exist.

- [ ] **Step 3: Implement the types and ports**

`file_stem` uses `time::OffsetDateTime::from_unix_timestamp_nanos(received_at_ms as i128 * 1_000_000)` and the format description `[year][month][day]-[hour][minute][second]`, then appends `-{element_id}` with every character outside `[A-Za-z0-9_-]` replaced by `_`. If the timestamp is out of range, use `19700101-000000`.

Port signatures:

```rust
pub trait CredentialStore: Send + Sync {
    fn save(&self, account: &AccountId, credentials: &StoredCredentials) -> Result<()>;
    fn load(&self, account: &AccountId) -> Result<Option<StoredCredentials>>;
    fn delete(&self, account: &AccountId) -> Result<()>;
}

pub trait LoginPrompt: Send + Sync {
    fn mail_address(&self) -> Result<String>;
    fn password(&self) -> Result<SecretString>;
    fn totp_code(&self) -> Result<String>;
}

pub struct SessionRequest {
    pub mail_address: String,
    pub password: SecretString,
    pub totp: std::sync::Arc<dyn Fn() -> Result<String> + Send + Sync>,
    pub on_device_approval: std::sync::Arc<dyn Fn() + Send + Sync>,
}

pub struct NewSession {
    pub user_id: String,
    pub access_token: String,
    pub encrypted_passphrase_key: Vec<u8>,
}

#[async_trait::async_trait]
pub trait SessionFactory: Send + Sync {
    async fn create(&self, request: SessionRequest) -> Result<NewSession>;
    async fn resume(&self, credentials: &StoredCredentials) -> Result<Box<dyn Session>>;
}

#[async_trait::async_trait]
pub trait Session: Send + Sync {
    fn account(&self) -> AccountInfo;
    fn mail(&self) -> &dyn MailSource;
    async fn close(&self) -> Result<()>;
}

#[async_trait::async_trait]
pub trait MailSource: Send + Sync {
    async fn folders(&self) -> Result<Vec<Folder>>;
    async fn messages(&self, folder: &Folder, limit: usize) -> Result<Vec<MessageSummary>>;
    async fn content(&self, message: &MessageSummary) -> Result<MessageContent>;
}

pub trait MessageRenderer: Send + Sync {
    fn render(&self, content: &MessageContent) -> Result<Vec<u8>>;
}
```

- [ ] **Step 4: Run tests and checks, then commit**

Run: `cargo test domain:: && cargo fmt --check && cargo clippy --all-targets -- -D warnings`

```bash
git add src/domain src/ports src/lib.rs
git commit -m "feat: add domain model, error taxonomy, and ports"
```

---

### Task 4: Tuta protocol JSON codec

**Files:**
- Create: `src/adapters/tuta/mod.rs`
- Create: `src/adapters/tuta/json.rs`
- Modify: `src/adapters/mod.rs`
- Test: `src/adapters/tuta/json.rs` (unit tests)

**Interfaces:**
- Consumes: `domain::Error`.
- Produces:
  - `SaltResponse { salt: [u8; 16], kdf_version: i64 }`
  - `SessionResponse { access_token: String, user_id: String, challenges: Vec<ChallengeType> }`
  - `ChallengeType { Totp, Other(i64) }`
  - `SessionId { list_id: String, element_id: String }`
  - `salt_query`, `create_session_body`, `parse_salt_response`, `parse_session_response`, `session_id_from_access_token`, `second_factor_body`, `second_factor_query`, `parse_pending`.

- [ ] **Step 1: Write failing codec tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    const SALT: &str = r#"{"421":"0","422":"AAECAwQFBgcICQoLDA0ODw==","2133":"1"}"#;
    const SESSION: &str = r#"{"1220":"0","1221":"tok_abc","1222":[{"1188":"0","1189":"1","1247":{"1239":"x"}}],"1223":"userid"}"#;

    #[test]
    fn parses_salt_and_session() {
        let salt = parse_salt_response(SALT.as_bytes()).unwrap();
        assert_eq!(salt.kdf_version, 1);
        assert_eq!(salt.salt[0], 0);
        let s = parse_session_response(SESSION.as_bytes()).unwrap();
        assert_eq!(s.access_token, "tok_abc");
        assert_eq!(s.challenges, vec![ChallengeType::Totp]);
    }

    #[test]
    fn request_bodies_use_string_numbers_and_base64() {
        let v: serde_json::Value = serde_json::from_slice(&salt_query("A@B.C")).unwrap();
        assert_eq!(v["418"], "0");
        assert_eq!(v["419"], "A@B.C");

        let v: serde_json::Value = serde_json::from_slice(&create_session_body(
            "a@b.c", "verifier", "AAECAw==", "tuta-bridge",
        )).unwrap();
        assert_eq!(v["1212"], "0");
        assert_eq!(v["1214"], "verifier");
        assert_eq!(v["1215"], "tuta-bridge");
        assert_eq!(v["1216"], "AAECAw==");
        assert!(v["1217"].is_null());

        let v: serde_json::Value = serde_json::from_slice(&second_factor_body(
            &SessionId { list_id: "L".into(), element_id: "E".into() }, "123456",
        )).unwrap();
        assert_eq!(v["1230"], "1");
        assert_eq!(v["1243"], "123456");
        assert_eq!(v["1232"], serde_json::json!(["L", "E"]));
    }

    #[test]
    fn session_id_is_derived_like_the_clients() {
        let token = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let id = session_id_from_access_token(token).unwrap();
        assert!(!id.list_id.is_empty());
        assert!(!id.element_id.is_empty());
    }

    #[test]
    fn parses_pending() {
        assert!(parse_pending(br#"{"1237":"0","1238":"1"}"#).unwrap());
        assert!(!parse_pending(br#"{"1237":"0","1238":"0"}"#).unwrap());
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test adapters::tuta::json`
Expected: FAIL because the module does not exist.

- [ ] **Step 3: Implement the codec**

Use `serde_json::json!` for requests. All numeric values are JSON strings. `accessKey` is base64 **standard**; `authVerifier` is base64url without padding, produced by the caller. For the session ID, decode the access token with `base64::engine::general_purpose::URL_SAFE_NO_PAD`, split at 9 bytes, encode the first 9 bytes with `tutasdk::util::BASE64_EXT`, and encode `tutasdk::crypto::sha256(&bytes[9..])` with URL-safe no-pad base64. Import `BASE64_EXT` and `sha256` from `tuta-sdk`. Parse responses by reading the numeric string keys and converting; a wrong salt length or missing key is `Error::Login("invalid salt response")` without echoing the payload.

`second_factor_body` uses key `"542"` for `_format`, `"1230"` for type (`"1"`), `"1243"` for the code, `"1231"` and `"1905"` null, and `"1232"` for the session tuple.

- [ ] **Step 4: Run tests and checks, then commit**

Run: `cargo test adapters::tuta::json && cargo fmt --check && cargo clippy --all-targets -- -D warnings`

```bash
git add src/adapters/tuta src/adapters/mod.rs
git commit -m "feat: add Tuta session JSON codec"
```

---

### Task 5: Pre-session HTTP adapter with TOTP

**Files:**
- Create: `src/adapters/tuta/pre_session.rs`
- Modify: `src/adapters/tuta/mod.rs`
- Create: `tests/pre_session.rs`

**Interfaces:**
- Consumes: `json` codec, `domain::{Error, Result}`, `ports::session::{SessionRequest, NewSession}`, `tutasdk::bindings::rest_client::{RestClient, RestClientOptions, HttpMethod}`.
- Produces: `TutaPreSession { rest: Arc<dyn RestClient>, base_url: String }` with `new(rest, base_url)` and `async fn create(&self, request: SessionRequest) -> Result<NewSession>`.

- [ ] **Step 1: Write failing wiremock tests**

`tests/pre_session.rs` must cover:

```rust
#[tokio::test]
async fn creates_session_with_totp() {
    // GET /rest/sys/saltservice -> SALT JSON
    // POST /rest/sys/sessionservice -> SESSION JSON with challenge type "1"
    // POST /rest/sys/secondfactorauthservice -> empty 200
    // GET /rest/sys/secondfactorauthservice -> {"1237":"0","1238":"0"}
    // assert NewSession.user_id == "userid", access_token == "tok_abc",
    // encrypted_passphrase_key.len() == 81 (1 version + 16 IV + 32 key + 32 MAC),
    // TOTP callback called once.
}

#[tokio::test]
async fn rejects_bcrypt() {
    // SALT with kdfVersion "0"
    // assert matches Error::BcryptUnsupported and no POST /sessionservice happened.
}

#[tokio::test]
async fn device_approval_polls_without_totp_prompt() {
    // SESSION with challenge type "0"
    // GET 2FA returns pending "1" once, then "0"
    // assert TOTP callback was not called, approval callback was called.
}
```

Use `wiremock::MockServer::start().await`, `NativeRestClient::try_new()`, and `base_url = server.uri()`. Set body matchers with `body_partial_json` where useful.

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --test pre_session`
Expected: FAIL because `TutaPreSession` does not exist.

- [ ] **Step 3: Implement `TutaPreSession::create`**

The flow, in order:

1. `GET {base_url}/rest/sys/saltservice?_body=<url-encoded salt_query>` with no auth.
2. Parse salt; if `kdf_version != 1`, return `Error::BcryptUnsupported`.
3. `let key = tutasdk::crypto::generate_key_from_passphrase(password.expose_secret(), salt)`.
4. `let verifier = tutasdk::crypto::crypto_facade::create_auth_verifier(key.clone())`.
5. Generate 32 random bytes with `rand_core::{RngCore, OsRng}`; base64-standard them for the body; construct `Aes256Key::from_bytes`.
6. `POST {base_url}/rest/sys/sessionservice` with `create_session_body(...)`; headers `cv` = `tutasdk::CLIENT_VERSION`, `v` = `"158"`, `Content-Type: application/json`.
7. Parse response. For each challenge: `Totp` → prompt via `request.totp`, then `POST /rest/sys/secondfactorauthservice` with `second_factor_body`; `Other` → call `request.on_device_approval` once and poll without posting; after posting TOTP, poll too.
8. Poll `GET /rest/sys/secondfactorauthservice?_body=<url-encoded second_factor_query>` every 2 seconds, up to 120 attempts; stop when `parse_pending` is false. A timeout is `Error::SecondFactor("timed out waiting for approval")`.
9. Build `encrypted_passphrase_key` with `GenericAesKey::Aes256(access_key).encrypt_key(&GenericAesKey::Aes256(key), InitializationVector::from_arr(random_iv))`, where `random_iv` is 16 random bytes.
10. Return `NewSession`.

Build query strings with `tutasdk::bindings::rest_client::encode_query_params`; set `RestClientOptions { headers, body, suspension_behavior: Some(SuspensionBehavior::Suspend) }`. Do not log bodies or tokens. Use a private helper `async fn request_json(&self, method, path, body, headers) -> Result<Vec<u8>>` that maps non-2xx to `Error::Network` with status only.

- [ ] **Step 4: Run tests and checks, then commit**

Run: `cargo test --test pre_session && cargo fmt --check && cargo clippy --all-targets -- -D warnings`

```bash
git add src/adapters/tuta/pre_session.rs src/adapters/tuta/mod.rs tests/pre_session.rs
git commit -m "feat: implement Tuta pre-session login with TOTP"
```

---

### Task 6: Secret Service credential store

**Files:**
- Create: `src/adapters/keyring_store.rs`
- Modify: `src/adapters/mod.rs`
- Test: `src/adapters/keyring_store.rs` (unit tests + one ignored integration test)

**Interfaces:**
- Consumes: `domain::{AccountId, StoredCredentials, Error, Result}`, `ports::credentials::CredentialStore`.
- Produces: `KeyringCredentialStore { service: String }` with `new(service: impl Into<String>)` and `CredentialStore`.

- [ ] **Step 1: Write failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_credentials_json_roundtrip() {
        let c = StoredCredentials {
            login: "a@b.c".into(), user_id: "u".into(), access_token: "t".into(),
            encrypted_passphrase_key: vec![1, 2, 3],
        };
        let json = serde_json::to_string(&c).unwrap();
        assert_eq!(serde_json::from_str::<StoredCredentials>(&json).unwrap().login, "a@b.c");
    }

    #[test]
    #[ignore = "requires a running Secret Service; run manually"]
    fn keyring_roundtrip() {
        let store = KeyringCredentialStore::new("tuta-bridge-test");
        let account = AccountId("test@example.invalid".into());
        let c = StoredCredentials { login: "test@example.invalid".into(), user_id: "u".into(), access_token: "t".into(), encrypted_passphrase_key: vec![9] };
        store.save(&account, &c).unwrap();
        assert_eq!(store.load(&account).unwrap().unwrap().user_id, "u");
        store.delete(&account).unwrap();
        assert!(store.load(&account).unwrap().is_none());
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test adapters::keyring_store`
Expected: FAIL because the adapter does not exist.

- [ ] **Step 3: Implement**

Use `keyring::Entry::new(&self.service, account.0.as_str())`. Save serializes to JSON and calls `set_password`. Load maps `keyring::Error::NoEntry` to `Ok(None)` and any other error to `Error::Storage("keyring read failed")`. Delete maps `NoEntry` to `Ok(())`. Never include the serialized JSON in an error or log. Run the ignored test manually once and note the result in `NOTES.md`.

- [ ] **Step 4: Run tests and checks, then commit**

Run: `cargo test adapters::keyring_store && cargo fmt --check && cargo clippy --all-targets -- -D warnings`

```bash
git add src/adapters/keyring_store.rs src/adapters/mod.rs NOTES.md
git commit -m "feat: store session credentials in Secret Service"
```

---

### Task 7: Login use case

**Files:**
- Create: `src/app/mod.rs`
- Create: `src/app/login.rs`
- Modify: `src/lib.rs`
- Create: `tests/support/mod.rs`
- Create: `tests/login.rs`

**Interfaces:**
- Consumes: `Config`, ports, `domain::{AccountId, AccountInfo, StoredCredentials, Error, Result}`.
- Produces: `LoginUseCase { factory: Arc<dyn SessionFactory>, store: Arc<dyn CredentialStore>, prompt: Arc<dyn LoginPrompt>, config_path: PathBuf }` with `new(...)` and `async fn execute(&self, email: Option<String>) -> Result<AccountInfo>`.

- [ ] **Step 1: Write failing use-case tests**

`tests/support/mod.rs` provides `FakeFactory`, `FakeStore`, `FakePrompt`, `FakeSession`, `FakeMailSource`, `FakeRenderer`. Each fake records calls behind `Mutex<Vec<String>>` and has settable results.

`tests/login.rs`:

```rust
#[tokio::test]
async fn login_saves_credentials_and_active_account() {
    // FakePrompt returns a@b.c, pw, 123456.
    // FakeFactory.create returns NewSession { user_id: "u", access_token: "t", encrypted_passphrase_key: vec![7] }.
    // FakeFactory.resume returns a session whose account is a@b.c / u.
    // execute(None) -> AccountInfo { a@b.c, u }.
    // assert store contains credentials and config.active_account == Some("a@b.c").
}

#[tokio::test]
async fn bcrypt_error_is_propagated_without_storing() {
    // FakeFactory.create returns Err(Error::BcryptUnsupported).
    // assert execute(None) is Err(BcryptUnsupported) and store is empty.
}

#[tokio::test]
async fn email_argument_skips_the_email_prompt() {
    // execute(Some("given@example.com")) must not call FakePrompt::mail_address.
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --test login`
Expected: FAIL because `LoginUseCase` does not exist.

- [ ] **Step 3: Implement**

The use case:

1. `let mail = match email { Some(e) => e, None => prompt.mail_address()? };` then `let mail = mail.trim().to_lowercase();`
2. `let password = prompt.password()?;`
3. Build `SessionRequest` with `totp = Arc::new(move || prompt_for_totp.totp_code())` and `on_device_approval = Arc::new(|| eprintln!("Approve the login from another Tuta client."))`.
4. `let new = factory.create(request).await?;`
5. `let credentials = StoredCredentials { login: mail.clone(), user_id: new.user_id, access_token: new.access_token, encrypted_passphrase_key: new.encrypted_passphrase_key };`
6. `let session = factory.resume(&credentials).await?;` then `let info = session.account();`
7. `store.save(&AccountId(mail), &credentials)?;`
8. Load config, set `active_account`, save.
9. Return `info`.

Do not clone the password; move it into the request. The `StoredCredentials` and `NewSession` values are not logged.

- [ ] **Step 4: Run tests and checks, then commit**

Run: `cargo test --test login && cargo fmt --check && cargo clippy --all-targets -- -D warnings`

```bash
git add src/app src/lib.rs tests/support tests/login.rs
git commit -m "feat: add login use case with credential persistence"
```

---

### Task 8: Status and logout use cases

**Files:**
- Create: `src/app/status.rs`
- Create: `src/app/logout.rs`
- Modify: `src/app/mod.rs`
- Create: `tests/account_lifecycle.rs`

**Interfaces:**
- Consumes: Task 7 fakes and ports.
- Produces:
  - `StatusUseCase { store: Arc<dyn CredentialStore>, config_path: PathBuf }` with `async fn execute(&self) -> Result<Option<AccountInfo>>`.
  - `LogoutUseCase { factory: Arc<dyn SessionFactory>, store: Arc<dyn CredentialStore>, config_path: PathBuf }` with `async fn execute(&self) -> Result<()>`.

- [ ] **Step 1: Write failing tests**

```rust
#[tokio::test]
async fn status_reports_none_without_active_account() { /* execute -> Ok(None) */ }

#[tokio::test]
async fn status_reads_stored_account_without_network() {
    // config has a@b.c, store has credentials; FakeFactory must record zero calls.
    // execute -> Some(AccountInfo { "a@b.c", "u" })
}

#[tokio::test]
async fn logout_deletes_even_when_close_fails() {
    // FakeSession::close returns Err(Error::Network("x")).
    // execute -> Ok(()), store empty, config.active_account == None.
}

#[tokio::test]
async fn logout_without_credentials_clears_config() {
    // store empty, config active; execute -> Ok(()), active_account None.
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --test account_lifecycle`
Expected: FAIL because the use cases do not exist.

- [ ] **Step 3: Implement**

`StatusUseCase`: load config; if no active account return `Ok(None)`; load credentials; if absent return `Err(Error::MissingCredentials(account))`; return `AccountInfo` from the credentials. No SDK call.

`LogoutUseCase`: load config; if no active account return `Ok(())`; load credentials; if present, `factory.resume(&credentials).await`; on success call `session.close().await`; on any close/resume error emit `tracing::warn!("server session close failed")` without the error payload, and continue. Delete the keyring entry, clear `active_account`, save config. Always `Ok(())` except storage/config failures.

- [ ] **Step 4: Run tests and checks, then commit**

Run: `cargo test --test account_lifecycle && cargo fmt --check && cargo clippy --all-targets -- -D warnings`

```bash
git add src/app/status.rs src/app/logout.rs src/app/mod.rs tests/account_lifecycle.rs
git commit -m "feat: add status and best-effort logout use cases"
```

---

### Task 9: Wire auth commands into the binary

**Files:**
- Modify: `src/main.rs`
- Modify: `src/adapters/cli.rs`
- Modify: `src/adapters/mod.rs`

**Interfaces:**
- Consumes: `Config`, `KeyringCredentialStore`, `TerminalPrompt`, `TutaSessionFactory`, use cases.
- Produces: working `tuta-bridge login|logout|status`; `TerminalPrompt` in `adapters::terminal_prompt`; `TutaSessionFactory` in `adapters::tuta::session`.

- [ ] **Step 1: Write the failing smoke test**

Add to `src/main.rs`:

```rust
#[cfg(test)]
mod tests {
    #[test]
    fn error_exit_codes_are_used() {
        assert_eq!(tuta_bridge::domain::Error::NoActiveAccount.exit_code(), 3);
    }
}
```

This pins the binary's error contract. Run `cargo test --bin tuta-bridge` and expect FAIL only if `domain::Error` is not re-exported.

- [ ] **Step 2: Implement the composition root**

`main.rs` initializes `tracing_subscriber` with `EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into())`, parses `Cli`, resolves the base URL (cli > `TUTA_BRIDGE_BASE_URL` > config), creates `NativeRestClient` and `NativeFileClient::try_new(data_dir)`, wraps the rest client in `SuspendableRestClient::new(raw.clone(), Arc::new(SystemClock))`, creates `Sdk::new(base_url, raw.clone(), file_client)`, then `KeyringCredentialStore::new("tuta-bridge")`, `TerminalPrompt`, and `TutaSessionFactory::new(sdk, suspendable, base_url)`. `SystemClock` is a local zero-sized type implementing `tutasdk::date::DateProvider` with `DateTime::from_system_time(std::time::SystemTime::now())`. The suspendable wrapper is used for pre-session and blob requests; the SDK gets the raw client and applies its own suspension handling. On error print `error: {error}` to stderr and exit with `error.exit_code()`. `status` prints `not logged in` when `None`, otherwise `{mail_address} ({user_id})`. `logout` prints `logged out`. Do not print tokens or keys.

`TerminalPrompt` uses `rpassword::prompt_password("Password: ")` and `rpassword::prompt_password("TOTP code: ")`; the mail address uses `std::io::stdin`.

- [ ] **Step 3: Manual smoke test**

Run: `cargo run -- status`
Expected: `not logged in`, exit code 0. Then `cargo run -- logout`; expected `logged out`, exit 0.

- [ ] **Step 4: Run checks and commit**

Run: `cargo test && cargo fmt --check && cargo clippy --all-targets -- -D warnings`

```bash
git add src/main.rs src/adapters
git commit -m "feat: wire login, logout, and status commands"
```

---

### Task 10: Deterministic MIME renderer

**Files:**
- Create: `src/adapters/mime.rs`
- Modify: `src/adapters/mod.rs`
- Test: `tests/mime.rs`

**Interfaces:**
- Consumes: `domain::{MessageContent, Attachment, Address}`, `ports::renderer::MessageRenderer`.
- Produces: `MimeRenderer` implementing `MessageRenderer`; `pub fn deterministic_boundary(seed: &str, label: &str) -> String`.

- [ ] **Step 1: Write failing renderer tests**

```rust
fn fixture() -> MessageContent { /* fixed summary, from, to, cc: vec![], bcc: vec![], reply_to: vec![],
    sent_at_ms: 1_700_000_000_000, subject: "Ciao — ünïcode",
    message_id: Some("<id@example>"), in_reply_to: None, references: vec![],
    body_html: Some("<p>Hello <img src=\"cid:img1\"></p>".into()), body_text: None,
    attachments: vec![Attachment { name: "report.pdf".into(), mime_type: "application/pdf".into(), data: b"%PDF".to_vec(), cid: None },
                      Attachment { name: "logo.png".into(), mime_type: "image/png".into(), data: b"PNG".to_vec(), cid: Some("img1".into()) }] */ }

#[test]
fn renders_twice_identically() {
    let r = MimeRenderer;
    let a = r.render(&fixture()).unwrap();
    let b = r.render(&fixture()).unwrap();
    assert_eq!(a, b);
    assert!(String::from_utf8_lossy(&a).contains("multipart/alternative"));
}

#[test]
fn html_only_body_gets_plain_alternative_and_inline_image() {
    let bytes = MimeRenderer.render(&fixture()).unwrap();
    let parsed = mail_parser::MessageParser::default().parse(&bytes).unwrap();
    assert!(parsed.body_text(0).is_some());
    assert!(parsed.body_html(0).unwrap().contains("cid:img1"));
    // attachment metadata and Content-ID must be present
    let raw = String::from_utf8_lossy(&bytes);
    assert!(raw.contains("Content-ID: <img1>"));
    assert!(raw.contains("filename=\"report.pdf\""));
}

#[test]
fn header_injection_is_impossible() {
    let mut c = fixture();
    c.subject = "hello\r\nBcc: evil@example.com".into();
    let bytes = MimeRenderer.render(&c).unwrap();
    let parsed = mail_parser::MessageParser::default().parse(&bytes).unwrap();
    assert!(parsed.bcc().is_none());
    assert!(!String::from_utf8_lossy(&bytes).contains("\r\nBcc: evil@example.com"));
    assert!(parsed.subject().unwrap().contains("hello"));
}

#[test]
fn date_comes_from_sent_at_not_clock() {
    let parsed = mail_parser::MessageParser::default().parse(&MimeRenderer.render(&fixture()).unwrap()).unwrap();
    assert_eq!(parsed.date().unwrap().to_timestamp(), 1_700_000_000);
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --test mime`
Expected: FAIL because `MimeRenderer` does not exist.

- [ ] **Step 3: Implement the renderer**

Build a `mail_builder::MessageBuilder` with explicit headers and a `MimePart` tree:

- Boundaries: `format!("=_tuta_bridge_{}_{}", label, BASE64_URL_SAFE_NO_PAD.encode(&tutasdk::crypto::sha256(seed)[..9]))`; labels `mixed`, `alt`, `related`. Seed is the `message_id` when present, else `format!("{}/{}", list_id, element_id)`. Build each multipart part with `ContentType::new("multipart/mixed").attribute("boundary", boundary)`; do not pass the boundary inside the type string, because `mail-builder` appends a random one. Sanitize `subject` by replacing `\r` and `\n` with a space before passing it to mail-builder.
- Root `multipart/mixed`; first child `multipart/alternative`; inside it a `text/plain` part (use `body_text`, or `mail_parser::html_to_text(body_html)`); if HTML exists, a `multipart/related` containing `text/html` plus inline attachments (those with `cid`) as `BodyPart::Binary(data.into())` with `.inline().cid(...)`; then non-inline attachments as `BodyPart::Binary(data.into())` with `.attachment(filename)`.
- If no HTML, put `text/plain` directly in the alternative; if no text either, use an empty string.
- Top-level headers: `From`, `To`, `Cc`, `Bcc` only when non-empty, `Reply-To`, `Subject`, `Date` (RFC 2822 from `sent_at_ms`), `Message-ID` (given or `<tuta-{list}-{element}@tuta-bridge.invalid>`), `In-Reply-To`, `References`, `MIME-Version: 1.0`. Set raw header values with `mail_builder::headers::raw::Raw::new(...)`; do not use builder methods that auto-generate Date/Message-ID.
- Use `.body(root_part)` and `write_to_vec()`.

Keep bodies out of logs. A rendering error is `Error::Message("failed to render message")`.

- [ ] **Step 4: Run tests and checks, then commit**

Run: `cargo test --test mime && cargo fmt --check && cargo clippy --all-targets -- -D warnings`

```bash
git add src/adapters/mime.rs src/adapters/mod.rs tests/mime.rs
git commit -m "feat: render deterministic RFC 5322 MIME with inline images"
```

---

### Task 11: Tuta session resume and folder/message listing

**Files:**
- Create: `src/adapters/tuta/session.rs`
- Create: `src/adapters/tuta/mail_source.rs`
- Modify: `src/adapters/tuta/mod.rs`
- Test: `tests/mail_mapping.rs`

**Interfaces:**
- Consumes: `tuta-sdk` (`Sdk`, `LoggedInSdk`, `Credentials`, `CredentialType`), ports, `domain`.
- Produces:
  - `TutaSessionFactory { pre: TutaPreSession, sdk: tutasdk::Sdk, rest: Arc<dyn RestClient>, base_url: String }` with `new(...)`; implements `SessionFactory` (`create` delegates to `pre.create`, `resume` uses the SDK).
  - `TutaSession { logged: Arc<LoggedInSdk>, rest: Arc<dyn RestClient>, info: AccountInfo, mail: TutaMailSource }`; implements `Session`.
  - `TutaMailSource { logged: Arc<LoggedInSdk>, rest: Arc<dyn RestClient> }`; implements `MailSource`.
  - `pub fn folder_kind(folder_type: i64) -> Option<FolderKind>`
  - `pub fn folder_from_parts(list_id: &str, name: &str, folder_type: i64) -> Option<Folder>`
  - `pub fn summary_from_parts(list_id: &str, element_id: &str, received_at_ms: i64, subject: &str, unread: bool) -> MessageSummary`

- [ ] **Step 1: Write failing mapping tests**

```rust
#[test]
fn maps_system_folder_types() {
    assert_eq!(folder_kind(1), Some(FolderKind::Inbox));
    assert_eq!(folder_kind(2), Some(FolderKind::Sent));
    assert_eq!(folder_kind(3), Some(FolderKind::Trash));
    assert_eq!(folder_kind(4), Some(FolderKind::Archive));
    assert_eq!(folder_kind(5), Some(FolderKind::Junk));
    assert_eq!(folder_kind(6), Some(FolderKind::Drafts));
    assert_eq!(folder_kind(0), Some(FolderKind::Custom));
    assert_eq!(folder_kind(7), None); // "All" is skipped
}

#[test]
fn resolves_folder_aliases_and_custom_names() {
    let folders = vec![
        folder_from_parts("i", "Inbox", 1).unwrap(),
        folder_from_parts("c", "Projects", 0).unwrap(),
    ];
    assert_eq!(resolve_folder(&folders, "INBOX").unwrap().list_id, "i");
    assert_eq!(resolve_folder(&folders, "projects").unwrap().list_id, "c");
    assert!(matches!(resolve_folder(&folders, "missing"), Err(Error::FolderNotFound(_))));
}

#[test]
fn summary_keeps_ids_and_time() {
    let s = summary_from_parts("l", "e", 5, "subject", true);
    assert_eq!(s.list_id, "l");
    assert_eq!(s.element_id, "e");
    assert!(s.unread);
}
```

Add `pub fn resolve_folder(folders: &[Folder], requested: &str) -> Result<&Folder>` to `mail_source.rs`.

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --test mail_mapping`
Expected: FAIL because the functions do not exist.

- [ ] **Step 3: Implement**

`TutaSessionFactory::resume` builds `tutasdk::login::Credentials { login, user_id: GeneratedId(...), access_token, encrypted_passphrase_key, credential_type: CredentialType::Internal }` and calls `self.sdk.login(creds).await`, mapping `LoginError` to `Error::Login("session resume failed")` without payload. It returns a `TutaSession` whose `account()` is built from credentials.

`TutaMailSource::folders`: `logged.mail_facade().load_user_mailbox().await`, then `logged.get_crypto_entity_client().load_range::<MailSet>(&mailbox.mailSets.mailSets, &GeneratedId::min_id(), 100, ASC)`. Map each `MailSet` with `folder_from_parts(set.entries.as_str(), &set.name, set.folderType)`; skip `None`.

`TutaMailSource::messages`: `load_range::<Mail>(&GeneratedId(folder.list_id.clone()), &CustomId(GeneratedId::max_id().to_string()), limit, DESC)`. For each mail, take `_id` (skip if absent) and call `summary_from_parts(mail._id.list_id.as_str(), mail._id.element_id.as_str(), mail.receivedDate.as_millis(), &mail.subject, mail.unread)`.

`resolve_folder` matches aliases and custom names case-insensitively, using `folder.kind` first and then `folder.name`; trim whitespace.

`Session::close` posts `CloseSessionService` with `CloseSessionServicePost { _format: 0, accessToken, sessionId: <session id from access token> }` through `logged.get_service_executor().post(...)`. Reuse `json::session_id_from_access_token` and convert to `IdTupleCustom`. Store the credentials' access token in `TutaSession`.

- [ ] **Step 4: Run tests and checks, then commit**

Run: `cargo test --test mail_mapping && cargo fmt --check && cargo clippy --all-targets -- -D warnings`

```bash
git add src/adapters/tuta/session.rs src/adapters/tuta/mail_source.rs src/adapters/tuta/mod.rs tests/mail_mapping.rs
git commit -m "feat: resume Tuta sessions and list folders and messages"
```

---

### Task 12: Mail details, body, and header mapping

**Files:**
- Create: `src/adapters/tuta/content.rs`
- Modify: `src/adapters/tuta/mail_source.rs`
- Test: `tests/content_mapping.rs`

**Interfaces:**
- Consumes: `tuta-sdk` entities `Mail`, `MailDetails`, `MailDetailsBlob`, `MailDetailsDraft`, `Body`, `MailAddress`, `EncryptedMailAddress`; `EntityFacadeImpl`; `CryptoFacade`.
- Produces:
  - `pub fn select_body(body: &Body) -> (Option<String>, Option<String>)`
  - `pub fn looks_like_html(text: &str) -> bool`
  - `pub fn parse_headers(raw: &str) -> std::collections::HashMap<String, Vec<String>>`
  - `pub fn threading_headers(headers: &HashMap<String, Vec<String>>) -> (Option<String>, Option<String>, Vec<String>)`
  - `pub fn address_from_mail_address(a: &MailAddress) -> Address`
  - `pub fn address_from_encrypted(a: &EncryptedMailAddress) -> Address`

- [ ] **Step 1: Write failing mapping tests**

```rust
#[test]
fn prefers_compressed_text_and_detects_html() {
    let body = Body { _id: None, text: Some("plain".into()), compressedText: Some("<p>html</p>".into()), _errors: Default::default() };
    let (html, text) = select_body(&body);
    assert_eq!(html, Some("<p>html</p>".into()));
    assert_eq!(text, None);
    assert!(looks_like_html("<div>x</div>"));
    assert!(!looks_like_html("just text"));
}

#[test]
fn parses_folded_and_repeated_headers() {
    let raw = "Message-ID: <a@b>\r\nReferences: <x@y>\r\n <z@w>\r\nReceived: one\r\nReceived: two\r\n";
    let h = parse_headers(raw);
    assert_eq!(h["message-id"], vec!["<a@b>"]);
    assert_eq!(h["references"], vec!["<x@y> <z@w>"]);
    assert_eq!(h["received"].len(), 2);
}

#[test]
fn extracts_threading_headers() {
    let h = HashMap::from([
        ("message-id".into(), vec!["<m@x>".into()]),
        ("in-reply-to".into(), vec!["<r@x>".into()]),
        ("references".into(), vec!["<a@x> <b@x>".into()]),
    ]);
    let (id, reply, refs) = threading_headers(&h);
    assert_eq!(id.as_deref(), Some("<m@x>"));
    assert_eq!(reply.as_deref(), Some("<r@x>"));
    assert_eq!(refs, vec!["<a@x>", "<b@x>"]);
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --test content_mapping`
Expected: FAIL because the module does not exist.

- [ ] **Step 3: Implement**

`select_body`: if `compressedText` is present and non-empty, treat it as the body and classify with `looks_like_html`; otherwise use `text`. `looks_like_html` checks case-insensitively for `<html`, `<body`, `<div`, `<p`, `<br`, `<table`, `<a `.

`parse_headers`: split on `\r\n` or `\n`; lines starting with space or tab continue the previous value with a single space; split each header at the first `:`; lowercase the name; trim the value; preserve order within a name.

`threading_headers`: read `message-id`, `in-reply-to`, `references` (case-insensitive); split `references` on whitespace.

In `TutaMailSource::content`:
- If `mail.mailDetailsDraft` is present, load `MailDetailsDraft` with `CryptoEntityClient::load` and use `.details`.
- Else if `mail.mailDetails` is present, resolve the mail's session key: `let parsed = logged.instance_mapper.serialize_entity(mail.clone())?;` `let model = logged.type_model_provider.resolve_server_type_ref(&Mail::type_ref())?;` `let key = logged.get_crypto_entity_client().get_crypto_facade().resolve_session_key(&parsed, &model).await?;`
- Load the raw blob with `logged.get_entity_client().load(&MailDetailsBlob::type_ref(), id)`, decrypt with `EntityFacadeImpl::new(logged.type_model_provider.clone(), RandomizerFacade::from_core(rand_core::OsRng))` and `decrypt_and_map`, then `logged.instance_mapper.parse_entity::<MailDetailsBlob>(...)`.
- If `resolve_session_key` returns `None` or errors, fall back to `logged.get_crypto_entity_client().load::<MailDetailsBlob>(id)`. If both fail, `Error::Message("mail details unavailable")`.
- Else `Error::Message("message has no details")`.

Map sender with `differentEnvelopeSender` used as the address only when non-empty, keeping `sender.name`. Map recipients from `details.recipients.{toRecipients, ccRecipients, bccRecipients}` and `replyTos`. `sent_at_ms = details.sentDate.as_millis()`. Headers from `details.headers` choosing `compressedHeaders` before `headers`. Message-ID fallback is left to the renderer.

Attachments are loaded by Task 13; until then `content()` returns an empty `attachments` vector and Task 13 fills it.

- [ ] **Step 4: Run tests and checks, then commit**

Run: `cargo test --test content_mapping && cargo fmt --check && cargo clippy --all-targets -- -D warnings`

```bash
git add src/adapters/tuta/content.rs src/adapters/tuta/mail_source.rs tests/content_mapping.rs
git commit -m "feat: load mail details, body, and threading headers"
```

---

### Task 13: Attachment download and decryption

**Files:**
- Create: `src/adapters/tuta/blob.rs`
- Modify: `src/adapters/tuta/mail_source.rs`
- Modify: `src/adapters/tuta/content.rs`
- Test: `tests/blob.rs`

**Interfaces:**
- Consumes: `tuta-sdk` entities `TutanotaFile`, `Blob`, `BlobAccessTokenPostIn`, `BlobReadData`, `InstanceId`, `BlobGetIn`, `BlobId`; services `BlobAccessTokenService`; `RestClient`.
- Produces:
  - `pub fn blob_get_body(archive_id: &str, blob_ids: &[String]) -> Result<Vec<u8>>`
  - `pub fn blob_url(server: &str, token: &str, body: &[u8]) -> String`
  - `pub async fn fetch_blob(rest: &dyn RestClient, url: &str, access_token: &str) -> Result<Vec<u8>>`
  - `pub fn decrypt_chunks(key: &GenericAesKey, chunks: &[Vec<u8>]) -> Result<Vec<u8>>`
  - `pub async fn load_attachment(logged: &LoggedInSdk, rest: &dyn RestClient, id: &IdTupleGenerated) -> Result<Attachment>`

- [ ] **Step 1: Write failing tests**

```rust
#[test]
fn builds_blob_get_json_and_url() {
    let body = blob_get_body("arch", &["b1".into(), "b2".into()]).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["52"], "arch");
    assert_eq!(v["193"][0]["146"], "b1");
    assert!(v["110"].is_null());
    let url = blob_url("https://blob.example", "tok", b"{\"a\":1}");
    assert!(url.starts_with("https://blob.example/rest/storage/blobservice?"));
    assert!(url.contains("blobAccessToken=tok"));
    assert!(url.contains("v=16"));
}

#[test]
fn decrypts_concatenated_chunks() {
    let key = GenericAesKey::from_bytes(&[7u8; 32]).unwrap();
    let iv = InitializationVector::from_arr([1u8; 16]);
    let c1 = key.encrypt_data(b"hello ", iv.clone()).unwrap();
    let c2 = key.encrypt_data(b"world", iv).unwrap();
    assert_eq!(decrypt_chunks(&key, &[c1, c2]).unwrap(), b"hello world");
}

#[tokio::test]
async fn fetches_binary_blob_with_access_token() {
    // wiremock GET returns b"cipher"; assert fetch_blob returns it and the
    // request carried header accessToken: tok.
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --test blob`
Expected: FAIL because the module does not exist.

- [ ] **Step 3: Implement**

`blob_get_body` uses `json!({"51":"0","52":archive_id,"110":null,"193":[{"145":"0","146":blob_id}, ...]})`.

`blob_url` builds the query with `tutasdk::bindings::rest_client::encode_query_params([("blobAccessToken", token), ("v", "16"), ("_body", body_str)])` and returns `{server}/rest/storage/blobservice{query}`.

`fetch_blob` calls `rest.request_binary(url, HttpMethod::GET, RestClientOptions { headers: HashMap::from([("accessToken", token.to_owned()), ("cv", tutasdk::CLIENT_VERSION.to_owned())]), body: None, suspension_behavior: Some(Suspend) })`; non-2xx is `Error::Network("blob download failed")`.

`load_attachment`:
1. `logged.get_crypto_entity_client().load::<TutanotaFile>(id)`.
2. If `blobs` is empty, return `Attachment` with empty data.
3. Group blobs by `archiveId`. For each group, `logged.get_service_executor().post::<BlobAccessTokenService>(BlobAccessTokenPostIn { _format: 0, archiveDataType: Some(1), write: None, read: Some(BlobReadData { _id: None, archiveId, instanceListId: Some(id.list_id.clone()), instanceIds: vec![InstanceId { _id: None, instanceId: Some(id.element_id.clone()) }] }) }, ExtraServiceParams::default())`.
4. Pick the first `servers` URL; fetch each blob with `fetch_blob`; decrypt with the file's resolved session key. Resolve the key like Task 12: serialize `TutanotaFile`, resolve type model, `resolve_session_key`, else `Error::Message("attachment key unavailable")`.
5. Concatenate decrypted chunks; if the total differs from `file.size as usize`, return `Error::Message("attachment size mismatch")`.
6. Build `Attachment { name: file.name, mime_type: file.mimeType.unwrap_or_else(|| "application/octet-stream".into()), data, cid: file.cid }`.

In `TutaMailSource::content`, for each id in `mail.attachments`, call `load_attachment(...).await`; a single failure returns `Error::Message("attachment load failed")` for that message, which the dump use case handles.

- [ ] **Step 4: Run tests and checks, then commit**

Run: `cargo test --test blob && cargo fmt --check && cargo clippy --all-targets -- -D warnings`

```bash
git add src/adapters/tuta/blob.rs src/adapters/tuta/mail_source.rs src/adapters/tuta/content.rs tests/blob.rs
git commit -m "feat: download and decrypt Tuta attachments"
```

---

### Task 14: Dump use case and CLI

**Files:**
- Create: `src/app/dump.rs`
- Modify: `src/app/mod.rs`
- Modify: `src/main.rs`
- Modify: `src/adapters/cli.rs`
- Create: `tests/dump.rs`
- Modify: `README.md`

**Interfaces:**
- Consumes: all ports and `Config`.
- Produces:
  - `DumpArgs { folder: String, limit: usize, out: PathBuf }`
  - `DumpReport { written: usize, failed: Vec<String> }`
  - `DumpUseCase { factory: Arc<dyn SessionFactory>, store: Arc<dyn CredentialStore>, renderer: Arc<dyn MessageRenderer>, config_path: PathBuf }` with `async fn execute(&self, args: DumpArgs) -> Result<DumpReport>`.

- [ ] **Step 1: Write failing dump tests**

```rust
#[tokio::test]
async fn writes_one_file_per_message_and_reports_partial_failure() {
    // FakeMailSource: folders -> inbox; messages -> two summaries; content fails for "e2".
    // FakeRenderer writes "rendered". execute -> Err(PartialDump { failed: 1 }).
    // assert out/e1.eml exists with "rendered"; e2 missing.
}

#[tokio::test]
async fn second_run_overwrites_same_names() {
    // execute twice; assert exactly one file per message and same bytes.
}

#[tokio::test]
async fn missing_folder_is_an_error() {
    // execute with "nope" -> FolderNotFound and no files.
}
```

Also assert `limit` is passed unchanged to `messages`, and a custom folder name resolves case-insensitively.

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --test dump`
Expected: FAIL because `DumpUseCase` does not exist.

- [ ] **Step 3: Implement**

Flow: load config; require active account (`Error::NoActiveAccount`); load credentials (`MissingCredentials`); `factory.resume`; `let source = session.mail();`; `let folders = source.folders().await?;`; `let folder = resolve_folder(&folders, &args.folder)?;`; `let messages = source.messages(folder, args.limit).await?`; create `out` with mode `0700` if missing; for each message, call `source.content`, `renderer.render`, write `out/{summary.file_stem()}.eml` with `std::fs::write`; on error push `format!("{}/{}", list_id, element_id)` to `failed` and continue. Do not log subjects. If `failed` is non-empty return `Err(Error::PartialDump { failed: failed.len() })` after all writes. `DumpReport` is returned for the success path.

The CLI prints `wrote N messages to <dir>`; on `PartialDump` prints `error: N messages failed` and exits 7. Never close the session.

Update `README.md` with the exact manual acceptance commands and a warning that `.eml` files are decrypted plaintext.

- [ ] **Step 4: Run tests and checks, then commit**

Run: `cargo test --test dump && cargo fmt --check && cargo clippy --all-targets -- -D warnings`

```bash
git add src/app/dump.rs src/app/mod.rs src/main.rs src/adapters/cli.rs tests/dump.rs README.md
git commit -m "feat: dump messages to deterministic eml files"
```

---

### Task 15: Manual acceptance run and documentation

**Files:**
- Modify: `NOTES.md`
- Modify: `README.md`

**Interfaces:**
- Consumes: the binary built in Tasks 1–14.
- Produces: recorded results and answers to the remaining verification questions.

- [ ] **Step 1: Prepare the build**

Run: `source "$HOME/.cargo/env" && cargo build`
Expected: build succeeds with no warnings.

- [ ] **Step 2: Run the manual login (user only)**

Tell the user to run, in their own terminal:

```bash
cargo run -- login
```

They enter their mail address, password, and TOTP code themselves. The agent must not ask for or accept those values. Expected: `logged in as <address>`; `cargo run -- status` prints the address and user id.

- [ ] **Step 3: Run the manual dump**

```bash
cargo run -- dump --folder inbox --limit 10 --out ./out
```

Expected: ten `.eml` files; open them in Thunderbird and check sender, recipients, subject, date, body, attachments, and inline images. Run the same command again; compare file names and `sha256sum` output; they must be identical.

- [ ] **Step 4: Verify logout**

```bash
cargo run -- logout
cargo run -- status
```

Expected: `logged out`, then `not logged in`.

- [ ] **Step 5: Record findings**

Update `NOTES.md` with: the real API base URL that worked; whether `kdfVersion` was 1; whether `compressedText` or `text` held the body; whether `MailDetailsBlob` had its own `_ownerEncSessionKey`; any error messages from the server; and any deviation from this plan. Update the verification table in `tuta-bridge-spec.md` if the user asks.

- [ ] **Step 6: Commit**

```bash
git add NOTES.md README.md
git commit -m "docs: record M1-M2 manual acceptance results"
```

---

## Self-Review

**Spec coverage:** M0 verification → Task 1 + Task 15; login with Argon2id, TOTP, bcrypt rejection, keyring, logout, status → Tasks 4–9; mailbox/folder listing, pagination, MailDetails, body, attachments, MIME → Tasks 10–13; dump acceptance → Tasks 14–15. Deliberately out of scope: IMAP, SMTP, SQLite, event bus, multiple accounts, license.

**Type consistency:** `MessageSummary`, `MessageContent`, `Attachment`, `SessionRequest`, `NewSession`, `DumpArgs`, `DumpReport`, and all port signatures are defined once in Task 3 and used with the same names and fields afterwards. `resolve_folder` is introduced in Task 11 and used by Task 14. `file_stem` is defined in Task 3 and used in Task 14. `deterministic_boundary` is defined and used only in Task 10.

**Review Focus tests:** inline image + plain alternative and header injection → Task 10; partial dump → Task 14; bcrypt/non-TOTP → Tasks 5 and 7; deterministic rerun → Tasks 10 and 14.

**Known manual gaps:** real server responses, Secret Service behavior, and the exact body/attachment shapes can only be confirmed by the user-run acceptance in Task 15; `NOTES.md` is the place where those findings land.
