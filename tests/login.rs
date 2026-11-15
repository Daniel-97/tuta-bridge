mod support;

use std::sync::atomic::Ordering;
use std::sync::Arc;

use tuta_bridge::app::login::LoginUseCase;
use tuta_bridge::config::Config;
use tuta_bridge::domain::{AccountInfo, Error};
use tuta_bridge::ports::session::NewSession;

#[tokio::test]
async fn login_saves_credentials_and_active_account() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.toml");

    let prompt = Arc::new(support::FakePrompt::new("a@b.c", "pw", "123456"));
    let factory = Arc::new(support::FakeFactory::new(
        Ok(NewSession {
            user_id: "u".into(),
            access_token: "t".into(),
            encrypted_passphrase_key: vec![7],
        }),
        AccountInfo {
            mail_address: "a@b.c".into(),
            user_id: "u".into(),
        },
    ));
    let store = Arc::new(support::FakeStore::new());

    let uc = LoginUseCase::new(factory, store.clone(), prompt, config_path.clone());
    let info = uc.execute(None).await.unwrap();

    assert_eq!(info.mail_address, "a@b.c");
    assert_eq!(info.user_id, "u");

    // Assert store contains credentials (no Debug on StoredCredentials; assert fields).
    let saved = store.saved.lock().unwrap();
    assert_eq!(saved.len(), 1);
    assert_eq!(saved[0].0 .0, "a@b.c");
    assert_eq!(saved[0].1.login, "a@b.c");
    assert_eq!(saved[0].1.user_id, "u");
    assert_eq!(saved[0].1.access_token, "t");
    assert_eq!(saved[0].1.encrypted_passphrase_key, vec![7]);

    // Assert config active_account was persisted.
    let cfg = Config::load(&config_path).unwrap();
    assert_eq!(cfg.active_account, Some("a@b.c".into()));
}

#[tokio::test]
async fn bcrypt_error_is_propagated_without_storing() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.toml");

    let prompt = Arc::new(support::FakePrompt::new("a@b.c", "pw", "123456"));
    let factory = Arc::new(support::FakeFactory::new(
        Err(tuta_bridge::domain::Error::BcryptUnsupported),
        AccountInfo {
            mail_address: "a@b.c".into(),
            user_id: "u".into(),
        },
    ));
    let store = Arc::new(support::FakeStore::new());

    let uc = LoginUseCase::new(factory, store.clone(), prompt, config_path);
    let result = uc.execute(None).await;
    let err = match result {
        Err(e) => e,
        Ok(info) => panic!("expected error, got Ok({:?})", info.mail_address),
    };

    assert!(matches!(err, tuta_bridge::domain::Error::BcryptUnsupported));
    assert!(store.is_empty());
}

#[tokio::test]
async fn email_argument_skips_the_email_prompt() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.toml");

    let prompt = Arc::new(support::FakePrompt::new(
        "should-not-be-called@example.com",
        "pw",
        "123456",
    ));
    let factory = Arc::new(support::FakeFactory::new(
        Ok(NewSession {
            user_id: "u".into(),
            access_token: "t".into(),
            encrypted_passphrase_key: vec![7],
        }),
        AccountInfo {
            mail_address: "given@example.com".into(),
            user_id: "u".into(),
        },
    ));
    let store = Arc::new(support::FakeStore::new());

    let prompt_clone = prompt.clone();
    let uc = LoginUseCase::new(factory, store, prompt, config_path);
    uc.execute(Some("given@example.com".into())).await.unwrap();

    let calls = prompt_clone.calls.lock().unwrap();
    assert!(
        !calls.contains(&"mail_address".to_string()),
        "mail_address prompt must not be called when email is supplied as argument; calls: {calls:?}"
    );
}

#[tokio::test]
async fn storage_failure_closes_session_and_returns_error() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.toml");

    let prompt = Arc::new(support::FakePrompt::new("a@b.c", "pw", "123456"));
    let factory = Arc::new(support::FakeFactory::new(
        Ok(NewSession {
            user_id: "u".into(),
            access_token: "t".into(),
            encrypted_passphrase_key: vec![7],
        }),
        AccountInfo {
            mail_address: "a@b.c".into(),
            user_id: "u".into(),
        },
    ));
    let store = Arc::new(support::FakeStore::new());
    *store.save_result.lock().unwrap() = Some(Err(Error::Storage("save failed".into())));

    let uc = LoginUseCase::new(factory.clone(), store.clone(), prompt, config_path.clone());
    let result = uc.execute(None).await;

    assert!(matches!(result, Err(Error::Storage(_))));
    // The session was closed best-effort before returning.
    assert_eq!(factory.close_calls.load(Ordering::SeqCst), 1);
    // No active account was persisted.
    let cfg = Config::load(&config_path).unwrap();
    assert_eq!(cfg.active_account, None);
}

#[tokio::test]
async fn config_save_failure_cleans_up_credentials_and_session() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let cfg_dir = dir.path().join("cfg");
    std::fs::create_dir(&cfg_dir).unwrap();
    // Read-only parent: Config::load falls back to defaults (NotFound), but
    // Config::save cannot create the file.
    std::fs::set_permissions(&cfg_dir, std::fs::Permissions::from_mode(0o500)).unwrap();
    let config_path = cfg_dir.join("config.toml");

    let prompt = Arc::new(support::FakePrompt::new("a@b.c", "pw", "123456"));
    let factory = Arc::new(support::FakeFactory::new(
        Ok(NewSession {
            user_id: "u".into(),
            access_token: "t".into(),
            encrypted_passphrase_key: vec![7],
        }),
        AccountInfo {
            mail_address: "a@b.c".into(),
            user_id: "u".into(),
        },
    ));
    let store = Arc::new(support::FakeStore::new());

    let uc = LoginUseCase::new(factory.clone(), store.clone(), prompt, config_path);
    let result = uc.execute(None).await;

    // Restore writability so the tempdir can be cleaned up.
    std::fs::set_permissions(&cfg_dir, std::fs::Permissions::from_mode(0o700)).unwrap();

    assert!(matches!(result, Err(Error::Config(_))));
    // Credentials were removed and the session closed best-effort.
    let calls = store.calls.lock().unwrap();
    assert!(
        calls.contains(&"delete".to_string()),
        "expected store.delete to be called, got: {calls:?}"
    );
    assert_eq!(factory.close_calls.load(Ordering::SeqCst), 1);
}
