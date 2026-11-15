#![allow(dead_code)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use secrecy::SecretString;
use tuta_bridge::domain::{
    AccountId, AccountInfo, Error, Folder, MessageContent, MessageSummary, Result,
    StoredCredentials,
};
use tuta_bridge::ports::credentials::CredentialStore;
use tuta_bridge::ports::mail_source::MailSource;
use tuta_bridge::ports::prompt::LoginPrompt;
use tuta_bridge::ports::renderer::MessageRenderer;
use tuta_bridge::ports::session::{NewSession, Session, SessionFactory, SessionRequest};

// ---------------------------------------------------------------------------
// FakePrompt
// ---------------------------------------------------------------------------

pub struct FakePrompt {
    pub email: String,
    pub password: String,
    pub totp: String,
    pub calls: Mutex<Vec<String>>,
}

impl FakePrompt {
    pub fn new(email: &str, password: &str, totp: &str) -> Self {
        Self {
            email: email.to_string(),
            password: password.to_string(),
            totp: totp.to_string(),
            calls: Mutex::new(Vec::new()),
        }
    }
}

impl LoginPrompt for FakePrompt {
    fn mail_address(&self) -> Result<String> {
        self.calls.lock().unwrap().push("mail_address".to_string());
        Ok(self.email.clone())
    }

    fn password(&self) -> Result<SecretString> {
        self.calls.lock().unwrap().push("password".to_string());
        Ok(SecretString::from(self.password.clone()))
    }

    fn totp_code(&self) -> Result<String> {
        self.calls.lock().unwrap().push("totp_code".to_string());
        Ok(self.totp.clone())
    }
}

// ---------------------------------------------------------------------------
// FakeStore
// ---------------------------------------------------------------------------

pub struct FakeStore {
    pub calls: Mutex<Vec<String>>,
    pub saved: Mutex<Vec<(AccountId, StoredCredentials)>>,
    pub load_result: Mutex<Option<StoredCredentials>>,
    pub save_result: Mutex<Option<Result<()>>>,
}

impl FakeStore {
    pub fn new() -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            saved: Mutex::new(Vec::new()),
            load_result: Mutex::new(None),
            save_result: Mutex::new(None),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.saved.lock().unwrap().is_empty()
    }
}

impl CredentialStore for FakeStore {
    fn save(&self, account: &AccountId, credentials: &StoredCredentials) -> Result<()> {
        self.calls.lock().unwrap().push("save".to_string());
        if let Some(result) = self.save_result.lock().unwrap().take() {
            return result;
        }
        self.saved
            .lock()
            .unwrap()
            .push((account.clone(), credentials.clone()));
        Ok(())
    }

    fn load(&self, _account: &AccountId) -> Result<Option<StoredCredentials>> {
        self.calls.lock().unwrap().push("load".to_string());
        Ok(self.load_result.lock().unwrap().clone())
    }

    fn delete(&self, _account: &AccountId) -> Result<()> {
        self.calls.lock().unwrap().push("delete".to_string());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// FakeFactory
// ---------------------------------------------------------------------------

pub struct FakeFactory {
    pub create_result: Mutex<Option<Result<NewSession>>>,
    pub resume_account: AccountInfo,
    pub close_should_fail: bool,
    pub mail: Arc<FakeMailSource>,
    pub calls: Mutex<Vec<String>>,
    pub close_calls: Arc<AtomicUsize>,
}

impl FakeFactory {
    pub fn new(create_result: Result<NewSession>, resume_account: AccountInfo) -> Self {
        Self {
            create_result: Mutex::new(Some(create_result)),
            resume_account,
            close_should_fail: false,
            mail: Arc::new(FakeMailSource::new()),
            calls: Mutex::new(Vec::new()),
            close_calls: Arc::new(AtomicUsize::new(0)),
        }
    }
}

#[async_trait::async_trait]
impl SessionFactory for FakeFactory {
    async fn create(&self, _request: SessionRequest) -> Result<NewSession> {
        self.calls.lock().unwrap().push("create".to_string());
        self.create_result
            .lock()
            .unwrap()
            .take()
            .expect("FakeFactory::create called more than once")
    }

    async fn resume(&self, _credentials: &StoredCredentials) -> Result<Box<dyn Session>> {
        self.calls.lock().unwrap().push("resume".to_string());
        Ok(Box::new(FakeSession {
            account: self.resume_account.clone(),
            mail: Arc::clone(&self.mail),
            close_should_fail: self.close_should_fail,
            close_calls: Arc::clone(&self.close_calls),
        }))
    }
}

// ---------------------------------------------------------------------------
// FakeSession
// ---------------------------------------------------------------------------

pub struct FakeSession {
    pub account: AccountInfo,
    pub mail: Arc<FakeMailSource>,
    pub close_should_fail: bool,
    pub close_calls: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl Session for FakeSession {
    fn account(&self) -> AccountInfo {
        self.account.clone()
    }

    fn mail(&self) -> &dyn MailSource {
        self.mail.as_ref()
    }

    async fn close(&self) -> Result<()> {
        self.close_calls.fetch_add(1, Ordering::SeqCst);
        if self.close_should_fail {
            Err(Error::Network("close failed".into()))
        } else {
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// FakeMailSource
// ---------------------------------------------------------------------------

pub struct FakeMailSource {
    pub folders: Vec<Folder>,
    pub messages: Vec<MessageSummary>,
    pub content: Option<MessageContent>,
    pub failing_elements: Vec<String>,
    pub message_limits: Mutex<Vec<usize>>,
    pub message_folders: Mutex<Vec<Folder>>,
    pub calls: Mutex<Vec<String>>,
}

impl FakeMailSource {
    pub fn new() -> Self {
        Self {
            folders: Vec::new(),
            messages: Vec::new(),
            content: None,
            failing_elements: Vec::new(),
            message_limits: Mutex::new(Vec::new()),
            message_folders: Mutex::new(Vec::new()),
            calls: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait::async_trait]
impl MailSource for FakeMailSource {
    async fn folders(&self) -> Result<Vec<Folder>> {
        self.calls.lock().unwrap().push("folders".to_string());
        Ok(self.folders.clone())
    }

    async fn messages(&self, folder: &Folder, limit: usize) -> Result<Vec<MessageSummary>> {
        self.calls.lock().unwrap().push("messages".to_string());
        self.message_limits.lock().unwrap().push(limit);
        self.message_folders.lock().unwrap().push(folder.clone());
        Ok(self.messages.clone())
    }

    async fn content(&self, message: &MessageSummary) -> Result<MessageContent> {
        self.calls.lock().unwrap().push("content".to_string());
        if self.failing_elements.contains(&message.element_id) {
            return Err(Error::Message("content failed".into()));
        }
        self.content
            .clone()
            .ok_or_else(|| Error::Message("no content configured".into()))
    }
}

// ---------------------------------------------------------------------------
// FakeRenderer
// ---------------------------------------------------------------------------

pub struct FakeRenderer {
    pub output: Vec<u8>,
}

impl FakeRenderer {
    pub fn new(output: Vec<u8>) -> Self {
        Self { output }
    }
}

impl MessageRenderer for FakeRenderer {
    fn render(&self, _content: &MessageContent) -> Result<Vec<u8>> {
        Ok(self.output.clone())
    }
}
