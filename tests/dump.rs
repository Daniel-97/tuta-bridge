mod support;

use std::path::Path;
use std::sync::Arc;

use tuta_bridge::app::dump::{DumpArgs, DumpUseCase};
use tuta_bridge::config::Config;
use tuta_bridge::domain::{
    AccountInfo, Address, Error, Folder, FolderKind, MessageContent, MessageSummary,
    StoredCredentials,
};
use tuta_bridge::ports::renderer::MessageRenderer;
use tuta_bridge::ports::session::NewSession;

fn summary(list_id: &str, element_id: &str) -> MessageSummary {
    MessageSummary {
        list_id: list_id.to_string(),
        element_id: element_id.to_string(),
        received_at_ms: 1_700_000_000_000,
        subject: String::new(),
        unread: false,
    }
}

fn content(summary: &MessageSummary) -> MessageContent {
    MessageContent {
        summary: summary.clone(),
        from: Address {
            name: None,
            address: "a@b.c".into(),
        },
        to: Vec::new(),
        cc: Vec::new(),
        bcc: Vec::new(),
        reply_to: Vec::new(),
        sent_at_ms: summary.received_at_ms,
        subject: summary.subject.clone(),
        message_id: None,
        in_reply_to: None,
        references: Vec::new(),
        body_html: None,
        body_text: None,
        attachments: Vec::new(),
    }
}

fn inbox_folder() -> Folder {
    Folder {
        list_id: "inbox-list".to_string(),
        name: "Inbox".to_string(),
        kind: FolderKind::Inbox,
    }
}

fn custom_folder() -> Folder {
    Folder {
        list_id: "projects-list".to_string(),
        name: "Projects".to_string(),
        kind: FolderKind::Custom,
    }
}

fn write_config(path: &Path) {
    let cfg = Config {
        active_account: Some("a@b.c".into()),
        ..Default::default()
    };
    cfg.save(path).unwrap();
}

fn store_with_credentials() -> Arc<support::FakeStore> {
    let store = Arc::new(support::FakeStore::new());
    *store.load_result.lock().unwrap() = Some(StoredCredentials {
        login: "a@b.c".into(),
        user_id: "u".into(),
        access_token: "t".into(),
        encrypted_passphrase_key: vec![7],
    });
    store
}

fn factory_with_mail(
    mail: support::FakeMailSource,
) -> (Arc<support::FakeFactory>, Arc<support::FakeMailSource>) {
    let mail = Arc::new(mail);
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
    factory.mail = Arc::clone(&mail);
    (Arc::new(factory), mail)
}

fn renderer() -> Arc<dyn MessageRenderer> {
    Arc::new(support::FakeRenderer::new(b"rendered".to_vec()))
}

#[tokio::test]
async fn writes_one_file_per_message_and_reports_partial_failure() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.toml");
    let out = dir.path().join("out");
    write_config(&config_path);

    let store = store_with_credentials();

    let e1 = summary("inbox-list", "e1");
    let e2 = summary("inbox-list", "e2");

    let mut mail = support::FakeMailSource::new();
    mail.folders = vec![inbox_folder()];
    mail.messages = vec![e1.clone(), e2.clone()];
    mail.content = Some(content(&e1));
    mail.failing_elements = vec!["e2".to_string()];

    let (factory, _mail) = factory_with_mail(mail);

    let uc = DumpUseCase::new(factory, store, renderer(), config_path);

    let result = uc
        .execute(DumpArgs {
            folder: "inbox".into(),
            limit: 10,
            out: out.clone(),
        })
        .await;

    match result {
        Ok(r) => panic!("expected PartialDump, got {r:?}"),
        Err(Error::PartialDump { failed }) => assert_eq!(failed, 1),
        Err(other) => panic!("expected PartialDump, got {other:?}"),
    }

    let e1_path = out.join(format!("{}.eml", e1.file_stem()));
    let e2_path = out.join(format!("{}.eml", e2.file_stem()));
    assert_eq!(std::fs::read_to_string(&e1_path).unwrap(), "rendered");
    assert!(!e2_path.exists(), "failed message must not leave a file");
}

#[tokio::test]
async fn second_run_overwrites_same_names() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.toml");
    let out = dir.path().join("out");
    write_config(&config_path);

    let store = store_with_credentials();

    let e1 = summary("inbox-list", "e1");

    let mut mail = support::FakeMailSource::new();
    mail.folders = vec![inbox_folder()];
    mail.messages = vec![e1.clone()];
    mail.content = Some(content(&e1));

    let (factory, _mail) = factory_with_mail(mail);

    let uc = DumpUseCase::new(factory, store, renderer(), config_path);

    let args = DumpArgs {
        folder: "inbox".into(),
        limit: 10,
        out: out.clone(),
    };
    let first = uc.execute(args.clone()).await.unwrap();
    assert_eq!(first.written, 1);
    let second = uc.execute(args.clone()).await.unwrap();
    assert_eq!(second.written, 1);

    let entries: Vec<_> = std::fs::read_dir(&out).unwrap().collect();
    assert_eq!(entries.len(), 1, "expected exactly one file per message");

    let path = out.join(format!("{}.eml", e1.file_stem()));
    assert_eq!(std::fs::read(&path).unwrap(), b"rendered");
}

#[tokio::test]
async fn missing_folder_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.toml");
    let out = dir.path().join("out");
    write_config(&config_path);

    let store = store_with_credentials();

    let mut mail = support::FakeMailSource::new();
    mail.folders = vec![inbox_folder()];

    let (factory, _mail) = factory_with_mail(mail);

    let uc = DumpUseCase::new(factory, store, renderer(), config_path);

    let result = uc
        .execute(DumpArgs {
            folder: "nope".into(),
            limit: 10,
            out: out.clone(),
        })
        .await;

    assert!(matches!(result, Err(Error::FolderNotFound(_))));
    assert!(!out.exists(), "a missing folder must write no files");
}

#[tokio::test]
async fn passes_limit_unchanged_to_messages() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.toml");
    let out = dir.path().join("out");
    write_config(&config_path);

    let store = store_with_credentials();

    let e1 = summary("projects-list", "e1");

    let mut mail = support::FakeMailSource::new();
    mail.folders = vec![custom_folder()];
    mail.messages = vec![e1.clone()];
    mail.content = Some(content(&e1));

    let (factory, mail) = factory_with_mail(mail);

    let uc = DumpUseCase::new(factory, store, renderer(), config_path);

    uc.execute(DumpArgs {
        folder: "Projects".into(),
        limit: 7,
        out,
    })
    .await
    .unwrap();

    assert_eq!(*mail.message_limits.lock().unwrap(), vec![7]);
}

#[tokio::test]
async fn resolves_custom_folder_case_insensitively() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.toml");
    let out = dir.path().join("out");
    write_config(&config_path);

    let store = store_with_credentials();

    let e1 = summary("projects-list", "e1");

    let mut mail = support::FakeMailSource::new();
    mail.folders = vec![custom_folder()];
    mail.messages = vec![e1.clone()];
    mail.content = Some(content(&e1));

    let (factory, mail) = factory_with_mail(mail);

    let uc = DumpUseCase::new(factory, store, renderer(), config_path);

    let report = uc
        .execute(DumpArgs {
            folder: "projects".into(),
            limit: 10,
            out,
        })
        .await
        .unwrap();

    assert_eq!(report.written, 1);
    let folders = mail.message_folders.lock().unwrap();
    assert_eq!(folders.len(), 1);
    assert_eq!(folders[0].list_id, "projects-list");
}

#[tokio::test]
async fn rejects_zero_limit() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.toml");
    let out = dir.path().join("out");
    write_config(&config_path);

    let store = store_with_credentials();
    let (factory, _mail) = factory_with_mail(support::FakeMailSource::new());

    let uc = DumpUseCase::new(factory, store, renderer(), config_path);

    let result = uc
        .execute(DumpArgs {
            folder: "inbox".into(),
            limit: 0,
            out,
        })
        .await;

    assert!(matches!(result, Err(Error::Config(_))));
}

#[cfg(unix)]
#[tokio::test]
async fn dump_file_is_private() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.toml");
    let out = dir.path().join("out");
    write_config(&config_path);

    let store = store_with_credentials();

    let e1 = summary("inbox-list", "e1");

    let mut mail = support::FakeMailSource::new();
    mail.folders = vec![inbox_folder()];
    mail.messages = vec![e1.clone()];
    mail.content = Some(content(&e1));

    let (factory, _mail) = factory_with_mail(mail);

    let uc = DumpUseCase::new(factory, store, renderer(), config_path);

    uc.execute(DumpArgs {
        folder: "inbox".into(),
        limit: 10,
        out: out.clone(),
    })
    .await
    .unwrap();

    let path = out.join(format!("{}.eml", e1.file_stem()));
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
}
