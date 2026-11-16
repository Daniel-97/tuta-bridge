#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use secrecy::SecretString;
use tuta_bridge::domain::{
    AccountId, AccountInfo, Error, Folder, MailboxId, MessageContent, MessageHeader, MessagePage,
    MessageSummary, Result, StoredCredentials, StoredMailbox, StoredMessage,
};
use tuta_bridge::ports::credentials::CredentialStore;
use tuta_bridge::ports::mail_source::MailSource;
use tuta_bridge::ports::prompt::LoginPrompt;
use tuta_bridge::ports::renderer::MessageRenderer;
use tuta_bridge::ports::session::{NewSession, Session, SessionFactory, SessionRequest};
use tuta_bridge::ports::state_store::StateStore;

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
// FakeStateStore
// ---------------------------------------------------------------------------

/// In-memory [`StateStore`] mirroring the observable semantics of the SQLite
/// adapter: mailboxes are keyed by `(account_id, list_id)`, a repeated upsert
/// preserves the existing mailbox and its UID sequence, and UIDs are assigned
/// per mailbox by Tuta element id rather than by header position.
pub struct FakeStateStore {
    pub calls: Mutex<Vec<String>>,
    pub accounts: Mutex<HashMap<String, i64>>,
    pub mailboxes: Mutex<HashMap<(i64, String), StoredMailbox>>,
    pub messages: Mutex<HashMap<(MailboxId, String, String), StoredMessage>>,
    pub last_batches: Mutex<HashMap<(i64, String), String>>,
    next_account_id: Mutex<i64>,
    next_mailbox_id: Mutex<i64>,
}

impl FakeStateStore {
    pub fn new() -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            accounts: Mutex::new(HashMap::new()),
            mailboxes: Mutex::new(HashMap::new()),
            messages: Mutex::new(HashMap::new()),
            last_batches: Mutex::new(HashMap::new()),
            next_account_id: Mutex::new(1),
            next_mailbox_id: Mutex::new(1),
        }
    }

    pub fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }

    pub fn mailbox_id(&self, account_id: i64, list_id: &str) -> MailboxId {
        self.mailboxes
            .lock()
            .unwrap()
            .get(&(account_id, list_id.to_string()))
            .map(|mailbox| mailbox.id)
            .unwrap_or_else(|| panic!("mailbox {list_id} not found"))
    }

    pub fn uid_for(&self, mailbox: MailboxId, list_id: &str, element_id: &str) -> Option<u32> {
        self.messages
            .lock()
            .unwrap()
            .get(&(mailbox, list_id.to_string(), element_id.to_string()))
            .map(|message| message.uid)
    }
}

impl Default for FakeStateStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl StateStore for FakeStateStore {
    async fn upsert_account(&self, mail_address: &str) -> Result<i64> {
        self.calls.lock().unwrap().push("upsert_account".into());
        let mut accounts = self.accounts.lock().unwrap();
        if let Some(id) = accounts.get(mail_address) {
            return Ok(*id);
        }
        let mut next_account_id = self.next_account_id.lock().unwrap();
        let id = *next_account_id;
        *next_account_id += 1;
        accounts.insert(mail_address.to_string(), id);
        Ok(id)
    }

    async fn upsert_mailbox(
        &self,
        account_id: i64,
        folder: &Folder,
        uidvalidity: u32,
    ) -> Result<MailboxId> {
        self.calls.lock().unwrap().push("upsert_mailbox".into());
        let key = (account_id, folder.list_id.clone());
        let mut mailboxes = self.mailboxes.lock().unwrap();
        if let Some(mailbox) = mailboxes.get(&key) {
            return Ok(mailbox.id);
        }
        let mut next_mailbox_id = self.next_mailbox_id.lock().unwrap();
        let mailbox = StoredMailbox {
            id: MailboxId(*next_mailbox_id),
            account_id,
            list_id: folder.list_id.clone(),
            name: folder.name.clone(),
            kind: folder.kind.clone(),
            uidvalidity,
            next_uid: 1,
        };
        *next_mailbox_id += 1;
        let id = mailbox.id;
        mailboxes.insert(key, mailbox);
        Ok(id)
    }

    async fn mailboxes(&self, account_id: i64) -> Result<Vec<StoredMailbox>> {
        self.calls.lock().unwrap().push("mailboxes".into());
        let mut mailboxes: Vec<_> = self
            .mailboxes
            .lock()
            .unwrap()
            .values()
            .filter(|mailbox| mailbox.account_id == account_id)
            .cloned()
            .collect();
        mailboxes.sort_by_key(|mailbox| mailbox.id.0);
        Ok(mailboxes)
    }

    async fn assign_uid(&self, mailbox: MailboxId, header: &MessageHeader) -> Result<u32> {
        self.calls.lock().unwrap().push("assign_uid".into());
        let key = (mailbox, header.list_id.clone(), header.element_id.clone());
        let mut messages = self.messages.lock().unwrap();
        if let Some(message) = messages.get_mut(&key) {
            message.header = header.clone();
            return Ok(message.uid);
        }

        let uid = {
            let mut mailboxes = self.mailboxes.lock().unwrap();
            let stored = mailboxes
                .values_mut()
                .find(|stored| stored.id == mailbox)
                .ok_or_else(|| Error::Storage("mailbox not found".into()))?;
            let uid = stored.next_uid;
            stored.next_uid += 1;
            uid
        };
        messages.insert(
            key,
            StoredMessage {
                uid,
                header: header.clone(),
                rfc822_size: None,
            },
        );
        Ok(uid)
    }

    async fn update_metadata(
        &self,
        mailbox: MailboxId,
        uid: u32,
        header: &MessageHeader,
        rfc822_size: Option<u64>,
    ) -> Result<()> {
        self.calls.lock().unwrap().push("update_metadata".into());
        let mut messages = self.messages.lock().unwrap();
        let message = messages
            .iter_mut()
            .find(|((stored_mailbox, _, _), message)| {
                *stored_mailbox == mailbox && message.uid == uid
            })
            .map(|(_, message)| message)
            .ok_or_else(|| Error::Storage("message not found".into()))?;
        message.header = header.clone();
        if rfc822_size.is_some() {
            message.rfc822_size = rfc822_size;
        }
        Ok(())
    }

    async fn remove_message(&self, mailbox: MailboxId, uid: u32) -> Result<()> {
        self.calls.lock().unwrap().push("remove_message".into());
        self.messages
            .lock()
            .unwrap()
            .retain(|(stored_mailbox, _, _), message| {
                !(*stored_mailbox == mailbox && message.uid == uid)
            });
        Ok(())
    }

    async fn messages(&self, mailbox: MailboxId) -> Result<Vec<StoredMessage>> {
        self.calls.lock().unwrap().push("messages".into());
        let mut messages: Vec<_> = self
            .messages
            .lock()
            .unwrap()
            .iter()
            .filter(|((stored_mailbox, _, _), _)| *stored_mailbox == mailbox)
            .map(|(_, message)| message.clone())
            .collect();
        messages.sort_by_key(|message| message.uid);
        Ok(messages)
    }

    async fn last_batch(&self, account_id: i64, group_id: &str) -> Result<Option<String>> {
        self.calls.lock().unwrap().push("last_batch".into());
        Ok(self
            .last_batches
            .lock()
            .unwrap()
            .get(&(account_id, group_id.to_string()))
            .cloned())
    }

    async fn set_last_batch(&self, account_id: i64, group_id: &str, batch_id: &str) -> Result<()> {
        self.calls.lock().unwrap().push("set_last_batch".into());
        self.last_batches
            .lock()
            .unwrap()
            .insert((account_id, group_id.to_string()), batch_id.to_string());
        Ok(())
    }

    async fn reset_account(&self, account_id: i64) -> Result<()> {
        self.calls.lock().unwrap().push("reset_account".into());
        let removed: Vec<MailboxId> = {
            let mailboxes = self.mailboxes.lock().unwrap();
            mailboxes
                .values()
                .filter(|mailbox| mailbox.account_id == account_id)
                .map(|mailbox| mailbox.id)
                .collect()
        };
        self.mailboxes
            .lock()
            .unwrap()
            .retain(|(stored_account_id, _), _| *stored_account_id != account_id);
        self.messages
            .lock()
            .unwrap()
            .retain(|(mailbox, _, _), _| !removed.contains(mailbox));
        self.last_batches
            .lock()
            .unwrap()
            .retain(|(stored_account_id, _), _| *stored_account_id != account_id);
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
    pub headers_by_folder: Mutex<HashMap<String, Vec<MessageHeader>>>,
    pub message_limits: Mutex<Vec<usize>>,
    pub message_folders: Mutex<Vec<Folder>>,
    pub header_limits: Mutex<Vec<usize>>,
    pub header_folders: Mutex<Vec<Folder>>,
    pub calls: Mutex<Vec<String>>,
}

impl FakeMailSource {
    pub fn new() -> Self {
        Self {
            folders: Vec::new(),
            messages: Vec::new(),
            content: None,
            failing_elements: Vec::new(),
            headers_by_folder: Mutex::new(HashMap::new()),
            message_limits: Mutex::new(Vec::new()),
            message_folders: Mutex::new(Vec::new()),
            header_limits: Mutex::new(Vec::new()),
            header_folders: Mutex::new(Vec::new()),
            calls: Mutex::new(Vec::new()),
        }
    }

    /// Replace the headers returned for `list_id`.
    pub fn set_headers(&self, list_id: &str, headers: Vec<MessageHeader>) {
        self.headers_by_folder
            .lock()
            .unwrap()
            .insert(list_id.to_string(), headers);
    }

    pub fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}

impl Default for FakeMailSource {
    fn default() -> Self {
        Self::new()
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

    async fn headers_page(
        &self,
        folder: &Folder,
        _start: Option<&str>,
        limit: usize,
    ) -> Result<MessagePage> {
        self.calls.lock().unwrap().push("headers_page".to_string());
        self.header_limits.lock().unwrap().push(limit);
        self.header_folders.lock().unwrap().push(folder.clone());
        let headers = self
            .headers_by_folder
            .lock()
            .unwrap()
            .get(&folder.list_id)
            .cloned()
            .unwrap_or_default();
        Ok(MessagePage {
            headers,
            next_start: None,
        })
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
