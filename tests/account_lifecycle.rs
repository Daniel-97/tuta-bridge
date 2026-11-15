mod support;

use std::sync::Arc;

use tuta_bridge::app::logout::LogoutUseCase;
use tuta_bridge::app::status::StatusUseCase;
use tuta_bridge::config::Config;
use tuta_bridge::domain::{AccountInfo, StoredCredentials};
use tuta_bridge::ports::session::NewSession;

#[tokio::test]
async fn status_reports_none_without_active_account() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.toml");

    let store = Arc::new(support::FakeStore::new());
    let uc = StatusUseCase { store, config_path };

    let result = uc.execute().await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn status_reads_stored_account_without_network() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.toml");

    // Config has an active account.
    let cfg = Config {
        active_account: Some("a@b.c".into()),
        ..Default::default()
    };
    cfg.save(&config_path).unwrap();

    // Store has credentials for that account.
    let store = Arc::new(support::FakeStore::new());
    *store.load_result.lock().unwrap() = Some(StoredCredentials {
        login: "a@b.c".into(),
        user_id: "u".into(),
        access_token: "t".into(),
        encrypted_passphrase_key: vec![7],
    });

    // Factory exists in the test scope but StatusUseCase must not call it.
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

    let uc = StatusUseCase { store, config_path };

    let result = uc.execute().await.unwrap();
    let info = result.expect("expected Some(AccountInfo)");
    assert_eq!(info.mail_address, "a@b.c");
    assert_eq!(info.user_id, "u");

    // FakeFactory must record zero calls — status is offline.
    let calls = factory.calls.lock().unwrap();
    assert!(
        calls.is_empty(),
        "expected no factory calls, got: {calls:?}"
    );
}

#[tokio::test]
async fn logout_deletes_even_when_close_fails() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.toml");

    // Config has an active account.
    let cfg = Config {
        active_account: Some("a@b.c".into()),
        ..Default::default()
    };
    cfg.save(&config_path).unwrap();

    // Store has credentials.
    let store = Arc::new(support::FakeStore::new());
    *store.load_result.lock().unwrap() = Some(StoredCredentials {
        login: "a@b.c".into(),
        user_id: "u".into(),
        access_token: "t".into(),
        encrypted_passphrase_key: vec![7],
    });

    let mut factory = support::FakeFactory::new(
        Ok(NewSession {
            user_id: "u".into(),
            access_token: "t".into(),
            encrypted_passphrase_key: vec![7],
        }),
        AccountInfo {
            mail_address: "a@b.c".into(),
            user_id: "u".into(),
        },
    );
    // FakeSession::close returns Err(Error::Network("x")).
    factory.close_should_fail = true;
    let factory = Arc::new(factory);

    let uc = LogoutUseCase {
        factory,
        store: store.clone(),
        config_path: config_path.clone(),
    };

    let result = uc.execute().await;
    assert!(result.is_ok(), "expected Ok(()), got {result:?}");

    // Store must be empty (delete was called, nothing was ever saved).
    assert!(store.is_empty());

    // Config active_account must be cleared.
    let cfg = Config::load(&config_path).unwrap();
    assert_eq!(cfg.active_account, None);
}

#[tokio::test]
async fn logout_without_credentials_clears_config() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.toml");

    // Config has an active account.
    let cfg = Config {
        active_account: Some("a@b.c".into()),
        ..Default::default()
    };
    cfg.save(&config_path).unwrap();

    // Store is empty — no credentials.
    let store = Arc::new(support::FakeStore::new());

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

    let uc = LogoutUseCase {
        factory,
        store: store.clone(),
        config_path: config_path.clone(),
    };

    let result = uc.execute().await;
    assert!(result.is_ok());

    let cfg = Config::load(&config_path).unwrap();
    assert_eq!(cfg.active_account, None);
}
