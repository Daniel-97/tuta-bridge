#![allow(dead_code)]

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use secrecy::{ExposeSecret, SecretString};
use tuta_bridge::adapters::imap::codec::{BodySection, FetchItem, ImapArg};
use tuta_bridge::adapters::imap::search::{parse_search, SearchKey};
use tuta_bridge::domain::{
    AccountId, AccountInfo, BatchCounts, BatchOutcome, Error, EventFrame, Folder, MailPlacement,
    MailboxId, MessageContent, MessageHeader, MessagePage, MessageSummary, Result, StateChange,
    StoredCredentials, StoredMailbox, StoredMessage,
};
use tuta_bridge::domain::{CalendarEvent, CalendarInfo};
use tuta_bridge::ports::calendar::{CalendarSource, CalendarStore};
use tuta_bridge::ports::credentials::CredentialStore;
use tuta_bridge::ports::event_lookup::EventLookup;
use tuta_bridge::ports::event_stream::{EventHandles, EventStream};
use tuta_bridge::ports::imap_backend::{FetchResponse, ImapBackend, MailboxView, SelectedMailbox};
use tuta_bridge::ports::mail_source::MailSource;
use tuta_bridge::ports::mailbox_writer::{MailRef, MailboxWriter};
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
    /// Highest UIDVALIDITY ever handed out per account.
    uidvalidity_floors: Mutex<HashMap<i64, u32>>,
    /// When nonzero, the next this many `apply_batch` calls fail like a
    /// locked database, writing nothing.
    busy_apply_batches: Mutex<usize>,
    /// The calendar cache `calendar_store` hands out (CalDAV tests).
    pub calendar_cache: Mutex<Option<Arc<dyn CalendarStore>>>,
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
            uidvalidity_floors: Mutex::new(HashMap::new()),
            busy_apply_batches: Mutex::new(0),
            calendar_cache: Mutex::new(None),
        }
    }

    /// Make the next `count` `apply_batch` calls fail with the busy
    /// storage error.
    pub fn fail_next_apply_batches_busy(&self, count: usize) {
        *self.busy_apply_batches.lock().unwrap() = count;
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

    /// Group id to the batch id last persisted for one account.
    pub fn last_batches_for(&self, account_id: i64) -> HashMap<String, String> {
        self.last_batches
            .lock()
            .unwrap()
            .iter()
            .filter(|((stored_account_id, _), _)| *stored_account_id == account_id)
            .map(|((_, group_id), batch_id)| (group_id.clone(), batch_id.clone()))
            .collect()
    }

    /// Reserve a UIDVALIDITY the account never used: `at_least` or the
    /// account's high-water mark plus one, whichever is greater. The mark
    /// survives removed mailboxes and `reset_account`.
    fn allocate_uidvalidity(&self, account_id: i64, at_least: u32) -> u32 {
        let mut floors = self.uidvalidity_floors.lock().unwrap();
        let floor = floors.entry(account_id).or_insert(0);
        *floor = at_least.max(*floor + 1);
        *floor
    }

    /// Upsert without recording a call, shared by `upsert_mailbox` and
    /// `apply_batch`.
    fn upsert_mailbox_entry(
        &self,
        account_id: i64,
        folder: &Folder,
        uidvalidity: u32,
    ) -> MailboxId {
        let key = (account_id, folder.list_id.clone());
        let mut mailboxes = self.mailboxes.lock().unwrap();
        if let Some(mailbox) = mailboxes.get_mut(&key) {
            // A rename gets a fresh UIDVALIDITY, like the SQLite adapter.
            if mailbox.name != folder.name && !mailbox.name.is_empty() {
                mailbox.uidvalidity = self.allocate_uidvalidity(account_id, uidvalidity);
            }
            mailbox.name = folder.name.clone();
            mailbox.kind = folder.kind.clone();
            return mailbox.id;
        }
        let uidvalidity = self.allocate_uidvalidity(account_id, uidvalidity);
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
        id
    }

    /// Assign or refresh a header without recording a call.
    fn assign_uid_entry(&self, mailbox: MailboxId, header: &MessageHeader) -> Result<u32> {
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
                mime_structure: None,
            },
        );
        Ok(uid)
    }

    fn remove_mailbox_entry(&self, account_id: i64, mailbox: MailboxId) {
        self.mailboxes
            .lock()
            .unwrap()
            .retain(|(stored_account_id, _), stored| {
                !(*stored_account_id == account_id && stored.id == mailbox)
            });
        self.messages
            .lock()
            .unwrap()
            .retain(|(stored_mailbox, _, _), _| *stored_mailbox != mailbox);
    }

    /// Remove the element's rows in the account and return the mailboxes
    /// that lost a row, in ascending id order like the SQLite adapter.
    fn remove_element_headers(&self, account_id: i64, element_id: &str) -> Vec<MailboxId> {
        let account_mailboxes: HashSet<MailboxId> = self
            .mailboxes
            .lock()
            .unwrap()
            .values()
            .filter(|mailbox| mailbox.account_id == account_id)
            .map(|mailbox| mailbox.id)
            .collect();
        let mut removed: HashSet<MailboxId> = HashSet::new();
        self.messages
            .lock()
            .unwrap()
            .retain(|(mailbox, _, element), _| {
                if account_mailboxes.contains(mailbox) && element == element_id {
                    removed.insert(*mailbox);
                    false
                } else {
                    true
                }
            });
        sorted_mailbox_ids(removed)
    }

    /// Remove the element's rows outside `keep_list_ids` and return the
    /// mailboxes that lost a row, in ascending id order like the SQLite
    /// adapter.
    fn remove_other_placements(
        &self,
        account_id: i64,
        element_id: &str,
        keep_list_ids: &[String],
    ) -> Vec<MailboxId> {
        let (account_mailboxes, kept): (HashSet<MailboxId>, HashSet<MailboxId>) = {
            let mailboxes = self.mailboxes.lock().unwrap();
            let account_mailboxes = mailboxes
                .values()
                .filter(|mailbox| mailbox.account_id == account_id)
                .map(|mailbox| mailbox.id)
                .collect();
            let kept = mailboxes
                .values()
                .filter(|mailbox| {
                    mailbox.account_id == account_id && keep_list_ids.contains(&mailbox.list_id)
                })
                .map(|mailbox| mailbox.id)
                .collect();
            (account_mailboxes, kept)
        };
        let mut removed: HashSet<MailboxId> = HashSet::new();
        self.messages
            .lock()
            .unwrap()
            .retain(|(mailbox, _, element), _| {
                if account_mailboxes.contains(mailbox)
                    && !kept.contains(mailbox)
                    && element == element_id
                {
                    removed.insert(*mailbox);
                    false
                } else {
                    true
                }
            });
        sorted_mailbox_ids(removed)
    }
}

/// Mailbox ids in ascending id order, mirroring the SQLite adapter's
/// `ORDER BY id` when a removal attributes its deleted rows.
fn sorted_mailbox_ids(ids: HashSet<MailboxId>) -> Vec<MailboxId> {
    let mut ids: Vec<i64> = ids.into_iter().map(|id| id.0).collect();
    ids.sort_unstable();
    ids.into_iter().map(MailboxId).collect()
}

/// Record `mailbox` in `touched` unless it is already listed.
fn touch_mailbox(touched: &mut Vec<MailboxId>, mailbox: MailboxId) {
    if !touched.contains(&mailbox) {
        touched.push(mailbox);
    }
}

impl Default for FakeStateStore {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// FakeEventLookup
// ---------------------------------------------------------------------------

/// Placements per mail keyed by the mail's `(list_id, element_id)`;
/// `None` marks the mail unreadable so the caller keeps its rows.
type MailPlacementMap = Mutex<HashMap<(String, String), Option<Vec<MailPlacement>>>>;
/// Placement per mail-set entry keyed by the entry's `(list_id, element_id)`;
/// `None` means no readable placement.
type EntryPlacementMap = Mutex<HashMap<(String, String), Option<MailPlacement>>>;
/// Folder per mail set keyed by the set's `(list_id, element_id)`.
type FolderMap = Mutex<HashMap<(String, String), Option<Folder>>>;

/// In-memory [`EventLookup`] for processor tests.
///
/// Placements, entry placements, and folders are keyed by their
/// `(list_id, element_id)` pairs. A missing key answers `Ok(None)` so an
/// unconfigured entity never causes a deletion, and a `None` value
/// reproduces the unreadable/absent case. `with_failure` makes every lookup
/// fail with the fixed network error.
pub struct FakeEventLookup {
    pub mail_placements: MailPlacementMap,
    pub entry_placements: EntryPlacementMap,
    pub folders: FolderMap,
    /// When set, every lookup fails with a network error.
    pub fail: Mutex<bool>,
    /// When nonzero, the next this many lookups fail with a network
    /// error; consumed before the `fail` flag is consulted.
    pub failing_calls: Mutex<usize>,
    /// When set, every mail lookup hangs forever.
    pub hang: Mutex<bool>,
    pub calls: Mutex<Vec<String>>,
}

impl FakeEventLookup {
    pub fn new() -> Self {
        Self {
            mail_placements: Mutex::new(HashMap::new()),
            entry_placements: Mutex::new(HashMap::new()),
            folders: Mutex::new(HashMap::new()),
            fail: Mutex::new(false),
            failing_calls: Mutex::new(0),
            hang: Mutex::new(false),
            calls: Mutex::new(Vec::new()),
        }
    }

    /// Make every mail lookup hang forever; only a stop future can end
    /// a batch that needs one.
    pub fn with_hang(self) -> Self {
        *self.hang.lock().unwrap() = true;
        self
    }

    /// Configure the placements of one mail; `None` marks the mail
    /// unreadable so the caller keeps its existing rows.
    pub fn with_mail_placements(
        self,
        mail_list_id: &str,
        mail_element_id: &str,
        placements: Option<Vec<MailPlacement>>,
    ) -> Self {
        self.mail_placements.lock().unwrap().insert(
            (mail_list_id.to_string(), mail_element_id.to_string()),
            placements,
        );
        self
    }

    /// Configure the placement of one mail-set entry.
    pub fn with_entry_placement(
        self,
        entry_list_id: &str,
        entry_element_id: &str,
        placement: MailPlacement,
    ) -> Self {
        self.entry_placements.lock().unwrap().insert(
            (entry_list_id.to_string(), entry_element_id.to_string()),
            Some(placement),
        );
        self
    }

    /// Configure the folder of one mail set.
    pub fn with_folder(self, set_list_id: &str, set_element_id: &str, folder: Folder) -> Self {
        self.folders.lock().unwrap().insert(
            (set_list_id.to_string(), set_element_id.to_string()),
            Some(folder),
        );
        self
    }

    /// Make every lookup fail with a network error.
    pub fn with_failure(self) -> Self {
        *self.fail.lock().unwrap() = true;
        self
    }

    /// Make the next `count` lookups fail with a network error.
    pub fn fail_next(self, count: usize) -> Self {
        *self.failing_calls.lock().unwrap() = count;
        self
    }

    /// Consume one scripted failing call, if any are left.
    fn consume_failing_call(&self) -> bool {
        let mut failing_calls = self.failing_calls.lock().unwrap();
        if *failing_calls == 0 {
            return false;
        }
        *failing_calls -= 1;
        true
    }

    pub fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}

impl Default for FakeEventLookup {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl EventLookup for FakeEventLookup {
    async fn headers_for_mail(
        &self,
        mail_list_id: &str,
        mail_element_id: &str,
    ) -> Result<Option<Vec<MailPlacement>>> {
        self.calls.lock().unwrap().push("headers_for_mail".into());
        if *self.hang.lock().unwrap() {
            // A hung lookup never resolves on its own.
            return std::future::pending().await;
        }
        if *self.fail.lock().unwrap() || self.consume_failing_call() {
            return Err(Error::Network("event entity unavailable".into()));
        }
        Ok(self
            .mail_placements
            .lock()
            .unwrap()
            .get(&(mail_list_id.to_string(), mail_element_id.to_string()))
            .cloned()
            .unwrap_or(None))
    }

    async fn header_for_entry(
        &self,
        entry_list_id: &str,
        entry_element_id: &str,
    ) -> Result<Option<MailPlacement>> {
        self.calls.lock().unwrap().push("header_for_entry".into());
        if *self.fail.lock().unwrap() || self.consume_failing_call() {
            return Err(Error::Network("event entity unavailable".into()));
        }
        Ok(self
            .entry_placements
            .lock()
            .unwrap()
            .get(&(entry_list_id.to_string(), entry_element_id.to_string()))
            .cloned()
            .unwrap_or(None))
    }

    async fn folder(&self, set_list_id: &str, set_element_id: &str) -> Result<Option<Folder>> {
        self.calls.lock().unwrap().push("folder".into());
        if *self.fail.lock().unwrap() || self.consume_failing_call() {
            return Err(Error::Network("event entity unavailable".into()));
        }
        Ok(self
            .folders
            .lock()
            .unwrap()
            .get(&(set_list_id.to_string(), set_element_id.to_string()))
            .cloned()
            .unwrap_or(None))
    }
}

#[async_trait::async_trait]
impl StateStore for FakeStateStore {
    fn calendar_store(self: Arc<Self>) -> Option<Arc<dyn CalendarStore>> {
        self.calendar_cache.lock().unwrap().clone()
    }

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
        Ok(self.upsert_mailbox_entry(account_id, folder, uidvalidity))
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
        self.assign_uid_entry(mailbox, header)
    }

    async fn apply_batch(
        &self,
        account_id: i64,
        group_id: &str,
        batch_id: &str,
        changes: &[StateChange],
    ) -> Result<BatchOutcome> {
        self.calls.lock().unwrap().push("apply_batch".into());
        {
            let mut busy = self.busy_apply_batches.lock().unwrap();
            if *busy > 0 {
                *busy -= 1;
                // The SQLite adapter's message for a locked database.
                return Err(Error::Storage("state database is busy".into()));
            }
        }
        // Mailboxes whose rows this batch changes, deduplicated and in
        // first-touch order.
        let mut touched: Vec<MailboxId> = Vec::new();
        let mut counts = BatchCounts::default();

        for change in changes {
            if let StateChange::UpsertMailbox {
                folder,
                uidvalidity,
            } = change
            {
                // Creating the row and running the update path both
                // count as a change.
                let mailbox = self.upsert_mailbox_entry(account_id, folder, *uidvalidity);
                touch_mailbox(&mut touched, mailbox);
                counts.folders_upserted += 1;
            }
        }

        let mut headers: Vec<(&str, &MessageHeader)> = changes
            .iter()
            .filter_map(|change| match change {
                StateChange::UpsertHeader {
                    mailbox_list_id,
                    header,
                } => Some((mailbox_list_id.as_str(), header)),
                _ => None,
            })
            .collect();
        headers.sort_by(|(mailbox_a, header_a), (mailbox_b, header_b)| {
            mailbox_a
                .cmp(mailbox_b)
                .then_with(|| header_a.received_at_ms.cmp(&header_b.received_at_ms))
                .then_with(|| header_a.element_id.cmp(&header_b.element_id))
        });
        for (mailbox_list_id, header) in headers {
            // The mailbox is resolved by the placement's `mailbox_list_id`;
            // `header.list_id` is the Mail's own list id and only keys the
            // stored message row.
            let mailbox = self
                .mailboxes
                .lock()
                .unwrap()
                .get(&(account_id, mailbox_list_id.to_string()))
                .map(|mailbox| mailbox.id);
            if let Some(mailbox) = mailbox {
                let previous = self
                    .messages
                    .lock()
                    .unwrap()
                    .get(&(mailbox, header.list_id.clone(), header.element_id.clone()))
                    .map(|message| message.header.unread);
                match previous {
                    None => counts.new_mails += 1,
                    Some(unread) if unread != header.unread => counts.read_state_changes += 1,
                    Some(_) => counts.updated_mails += 1,
                }
                // A successful write always inserts or updates a row.
                self.assign_uid_entry(mailbox, header)?;
                touch_mailbox(&mut touched, mailbox);
            }
        }

        for change in changes {
            match change {
                StateChange::RemoveHeaderEverywhere { element_id } => {
                    let removed = self.remove_element_headers(account_id, element_id);
                    counts.deleted += removed.len();
                    for mailbox in removed {
                        touch_mailbox(&mut touched, mailbox);
                    }
                }
                StateChange::RemoveOtherPlacements {
                    element_id,
                    keep_list_ids,
                } => {
                    let removed =
                        self.remove_other_placements(account_id, element_id, keep_list_ids);
                    counts.moved_out += removed.len();
                    for mailbox in removed {
                        touch_mailbox(&mut touched, mailbox);
                    }
                }
                StateChange::UpsertMailbox { .. } | StateChange::UpsertHeader { .. } => {}
            }
        }

        self.last_batches
            .lock()
            .unwrap()
            .insert((account_id, group_id.to_string()), batch_id.to_string());
        Ok(BatchOutcome { touched, counts })
    }

    async fn remove_mailbox(&self, account_id: i64, mailbox: MailboxId) -> Result<()> {
        self.calls.lock().unwrap().push("remove_mailbox".into());
        self.remove_mailbox_entry(account_id, mailbox);
        Ok(())
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

    async fn set_mime_structure(
        &self,
        mailbox: MailboxId,
        uid: u32,
        structure: &str,
    ) -> Result<()> {
        self.calls.lock().unwrap().push("set_mime_structure".into());
        let mut messages = self.messages.lock().unwrap();
        let message = messages
            .iter_mut()
            .find(|((stored_mailbox, _, _), message)| {
                *stored_mailbox == mailbox && message.uid == uid
            })
            .map(|(_, message)| message)
            .ok_or_else(|| Error::Storage("message not found".into()))?;
        message.mime_structure = Some(structure.to_string());
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

    async fn message_by_uid(&self, mailbox: MailboxId, uid: u32) -> Result<Option<StoredMessage>> {
        self.calls.lock().unwrap().push("message_by_uid".into());
        Ok(self
            .messages
            .lock()
            .unwrap()
            .iter()
            .find(|((stored_mailbox, _, _), message)| {
                *stored_mailbox == mailbox && message.uid == uid
            })
            .map(|(_, message)| message.clone()))
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

    fn shared_mail(&self) -> Arc<dyn MailSource> {
        Arc::clone(&self.mail) as Arc<dyn MailSource>
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
    pub fail_folders: bool,
    /// When nonzero, the next this many `folders()` calls fail.
    pub failing_folder_calls: Mutex<usize>,
    /// When set, `folders()` hangs forever.
    pub hang_folders: Mutex<bool>,
    pub headers_by_folder: Mutex<HashMap<String, Vec<MessageHeader>>>,
    pub failing_header_folders: Mutex<Vec<String>>,
    pub skipped_by_folder: Mutex<HashMap<String, usize>>,
    /// Skipped mails the folder still lists, by folder list id.
    pub unreadable_by_folder: Mutex<HashMap<String, Vec<(String, String)>>>,
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
            fail_folders: false,
            failing_folder_calls: Mutex::new(0),
            hang_folders: Mutex::new(false),
            headers_by_folder: Mutex::new(HashMap::new()),
            failing_header_folders: Mutex::new(Vec::new()),
            skipped_by_folder: Mutex::new(HashMap::new()),
            unreadable_by_folder: Mutex::new(HashMap::new()),
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

    /// Make the next `count` `folders()` calls fail with a network error.
    pub fn fail_next_folders(&self, count: usize) {
        *self.failing_folder_calls.lock().unwrap() = count;
    }

    /// Make `folders()` hang forever; only a stop future can end a sync.
    pub fn hang_folders(&self) {
        *self.hang_folders.lock().unwrap() = true;
    }

    /// Make `headers_page` fail for `list_id`.
    pub fn fail_headers_in(&self, list_id: &str) {
        self.failing_header_folders
            .lock()
            .unwrap()
            .push(list_id.to_string());
    }

    /// Report `count` unreadable mails for `list_id`'s header page.
    /// Mark mails as listed by the folder but impossible to load.
    pub fn set_unreadable(&self, list_id: &str, mails: Vec<(String, String)>) {
        self.unreadable_by_folder
            .lock()
            .unwrap()
            .insert(list_id.to_owned(), mails);
    }

    pub fn set_skipped(&self, list_id: &str, count: usize) {
        self.skipped_by_folder
            .lock()
            .unwrap()
            .insert(list_id.to_string(), count);
    }

    pub fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }

    /// Number of `content` calls served so far.
    pub fn content_calls(&self) -> usize {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|call| call.as_str() == "content")
            .count()
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
        if *self.hang_folders.lock().unwrap() {
            // A hung listing never resolves on its own.
            return std::future::pending().await;
        }
        let scripted_failure = {
            let mut failing = self.failing_folder_calls.lock().unwrap();
            let fail = *failing > 0;
            *failing = failing.saturating_sub(1);
            fail
        };
        if self.fail_folders || scripted_failure {
            return Err(Error::Network("folders failed".into()));
        }
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
        if self
            .failing_header_folders
            .lock()
            .unwrap()
            .contains(&folder.list_id)
        {
            return Err(Error::Network("headers failed".into()));
        }
        let headers = self
            .headers_by_folder
            .lock()
            .unwrap()
            .get(&folder.list_id)
            .cloned()
            .unwrap_or_default();
        let skipped = self
            .skipped_by_folder
            .lock()
            .unwrap()
            .get(&folder.list_id)
            .copied()
            .unwrap_or(0);
        let unreadable = self
            .unreadable_by_folder
            .lock()
            .unwrap()
            .get(&folder.list_id)
            .cloned()
            .unwrap_or_default();
        Ok(MessagePage {
            headers,
            next_start: None,
            skipped: skipped + unreadable.len(),
            unreadable,
        })
    }
}

// ---------------------------------------------------------------------------
// FakeEventSession
// ---------------------------------------------------------------------------

/// Scripted event-bus session for watch tests.
///
/// Every `events()` call consumes the next queued script and replays its
/// frames in order. A call without a queued script, or a script that runs
/// out of frames, panics so a broken test fails loudly instead of hanging.
/// The batch markers handed to each call are recorded for assertions.
///
/// `SessionFactory::resume` must return an owned `Box<dyn Session>`, so
/// tests share one session through an [`Arc`] and hand out
/// [`FakeEventSessionHandle`]s that keep it alive.
pub struct FakeEventSession {
    pub account: AccountInfo,
    /// Groups reported by `event_groups`.
    pub groups: Vec<String>,
    /// One script per `events()` call, consumed in order.
    pub scripts: Mutex<VecDeque<Vec<Result<EventFrame>>>>,
    /// Errors the next `events()` calls return before replaying a script.
    pub connect_errors: Mutex<VecDeque<Error>>,
    /// Calls whose `events()` future never resolves, consumed before
    /// scripts and after connect errors.
    pub hung_connects: Mutex<VecDeque<()>>,
    /// Calls whose stream never resolves, consumed before scripts.
    pub pending_calls: Mutex<VecDeque<()>>,
    /// Lookup handed out with every stream.
    pub lookup: Arc<FakeEventLookup>,
    /// Mail source used for baseline syncs.
    pub mail: Arc<FakeMailSource>,
    /// Batch markers passed to each `events()` call.
    pub marker_calls: Mutex<Vec<HashMap<String, String>>>,
    /// The write seam handed to `serve` through `shared_writer`.
    pub writer: Arc<FakeMailboxWriter>,
    /// The address book handed to `serve` through `shared_contacts`.
    pub contacts: Arc<FakeContactSource>,
    /// The calendar seam handed to `serve` through `shared_calendar`.
    pub calendar: Option<Arc<FakeCalendarSource>>,
}

impl FakeEventSession {
    pub fn new(account: AccountInfo, groups: Vec<String>) -> Self {
        Self {
            account,
            groups,
            scripts: Mutex::new(VecDeque::new()),
            connect_errors: Mutex::new(VecDeque::new()),
            hung_connects: Mutex::new(VecDeque::new()),
            pending_calls: Mutex::new(VecDeque::new()),
            lookup: Arc::new(FakeEventLookup::new()),
            mail: Arc::new(FakeMailSource::new()),
            marker_calls: Mutex::new(Vec::new()),
            writer: Arc::new(FakeMailboxWriter::new()),
            contacts: Arc::new(FakeContactSource::new(Vec::new())),
            calendar: None,
        }
    }

    /// Hand out `calendar` through `shared_calendar`.
    pub fn with_calendar(mut self, calendar: Arc<FakeCalendarSource>) -> Self {
        self.calendar = Some(calendar);
        self
    }

    /// Queue the frames the next `events()` call will replay.
    pub fn push_script(&self, frames: Vec<Result<EventFrame>>) {
        self.scripts.lock().unwrap().push_back(frames);
    }

    /// Make the next `events()` call fail with `error` before any frames
    /// are replayed; scripts queued for that call stay untouched.
    pub fn push_connect_error(&self, error: Error) {
        self.connect_errors.lock().unwrap().push_back(error);
    }

    /// Make the next `events()` call hang forever; only the watch's
    /// connect timeout can end it.
    pub fn push_hung_connect(&self) {
        self.hung_connects.lock().unwrap().push_back(());
    }

    /// Make the next `events()` call hand out a stream that never
    /// resolves; only a stop future can end such a watch loop.
    pub fn push_pending(&self) {
        self.pending_calls.lock().unwrap().push_back(());
    }

    /// Replace the lookup handed out by `events()`.
    pub fn with_lookup(mut self, lookup: Arc<FakeEventLookup>) -> Self {
        self.lookup = lookup;
        self
    }

    /// Replace the mail source used for baseline syncs.
    pub fn with_mail(mut self, mail: Arc<FakeMailSource>) -> Self {
        self.mail = mail;
        self
    }

    /// Number of `events()` calls so far.
    pub fn events_calls(&self) -> usize {
        self.marker_calls.lock().unwrap().len()
    }

    /// Batch markers passed to the `events()` call at `index`.
    pub fn markers_for_call(&self, index: usize) -> HashMap<String, String> {
        self.marker_calls.lock().unwrap()[index].clone()
    }
}

/// Owned [`Session`] handle over a shared [`FakeEventSession`].
pub struct FakeEventSessionHandle(pub Arc<FakeEventSession>);

#[async_trait::async_trait]
impl Session for FakeEventSessionHandle {
    fn account(&self) -> AccountInfo {
        self.0.account.clone()
    }

    fn mail(&self) -> &dyn MailSource {
        self.0.mail.as_ref()
    }

    fn shared_mail(&self) -> Arc<dyn MailSource> {
        Arc::clone(&self.0.mail) as Arc<dyn MailSource>
    }

    fn shared_writer(&self) -> Arc<dyn MailboxWriter> {
        Arc::clone(&self.0.writer) as Arc<dyn MailboxWriter>
    }

    fn shared_contacts(&self) -> Arc<dyn tuta_bridge::ports::contact_source::ContactSource> {
        Arc::clone(&self.0.contacts) as Arc<dyn tuta_bridge::ports::contact_source::ContactSource>
    }

    fn event_groups(&self) -> Vec<String> {
        self.0.groups.clone()
    }

    fn shared_calendar(&self) -> Option<Arc<dyn CalendarSource>> {
        self.0
            .calendar
            .as_ref()
            .map(|calendar| Arc::clone(calendar) as Arc<dyn CalendarSource>)
    }

    async fn events(
        &self,
        last_batches: &HashMap<String, String>,
        _now_ms: i64,
    ) -> Result<EventHandles> {
        self.0
            .marker_calls
            .lock()
            .unwrap()
            .push(last_batches.clone());
        if let Some(error) = self.0.connect_errors.lock().unwrap().pop_front() {
            return Err(error);
        }
        if self.0.hung_connects.lock().unwrap().pop_front().is_some() {
            // A hung connect never resolves on its own.
            return std::future::pending().await;
        }
        if self.0.pending_calls.lock().unwrap().pop_front().is_some() {
            return Ok(EventHandles {
                stream: Box::new(PendingEventStream),
                lookup: Arc::clone(&self.0.lookup) as Arc<dyn EventLookup>,
            });
        }
        let frames = self
            .0
            .scripts
            .lock()
            .unwrap()
            .pop_front()
            .expect("events() was called more times than scripted");
        Ok(EventHandles {
            stream: Box::new(ScriptedEventStream {
                frames: frames.into(),
            }),
            lookup: Arc::clone(&self.0.lookup) as Arc<dyn EventLookup>,
        })
    }

    async fn close(&self) -> Result<()> {
        Ok(())
    }
}

/// Replays one script; an exhausted script panics so tests fail loudly.
struct ScriptedEventStream {
    frames: VecDeque<Result<EventFrame>>,
}

#[async_trait::async_trait]
impl EventStream for ScriptedEventStream {
    async fn next_frame(&mut self) -> Result<EventFrame> {
        self.frames
            .pop_front()
            .expect("script ran out of frames; end every script with an error")
    }
}

/// A stream that never yields a frame; only a stop future can end it.
struct PendingEventStream;

#[async_trait::async_trait]
impl EventStream for PendingEventStream {
    async fn next_frame(&mut self) -> Result<EventFrame> {
        std::future::pending().await
    }
}

// ---------------------------------------------------------------------------
// FakeRenderer
// ---------------------------------------------------------------------------

pub struct FakeRenderer {
    pub output: Vec<u8>,
    render_calls: AtomicUsize,
}

impl FakeRenderer {
    pub fn new(output: Vec<u8>) -> Self {
        Self {
            output,
            render_calls: AtomicUsize::new(0),
        }
    }

    /// Number of `render` calls served so far.
    pub fn render_calls(&self) -> usize {
        self.render_calls.load(Ordering::SeqCst)
    }
}

impl MessageRenderer for FakeRenderer {
    fn render(&self, _content: &MessageContent) -> Result<Vec<u8>> {
        self.render_calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.output.clone())
    }
}

// ---------------------------------------------------------------------------
// FakeImapBackend
// ---------------------------------------------------------------------------

/// One scripted mailbox state. The uid list doubles as the message
/// count, so a new stored message is one pushed uid — exactly how the
/// real store reports a growing mailbox. `new` marks the last `unseen`
/// uids unread.
#[derive(Clone)]
pub struct FakeSelected {
    pub uidvalidity: u32,
    pub uidnext: u32,
    pub uids: Vec<u32>,
    pub unread: Vec<u32>,
}

impl FakeSelected {
    pub fn new(uidvalidity: u32, uidnext: u32, unseen: usize, uids: Vec<u32>) -> Self {
        let unread = uids[uids.len().saturating_sub(unseen)..].to_vec();
        Self {
            uidvalidity,
            uidnext,
            uids,
            unread,
        }
    }
}

/// One scripted `FETCH` answer; the session renders whichever of these
/// fields the request asked for.
#[derive(Clone)]
pub struct FakeFetched {
    pub flags: String,
    pub internal_date: String,
    pub envelope: Option<String>,
    pub bodystructure: Option<String>,
    pub rfc822_size: Option<u64>,
    pub body: Vec<u8>,
}

/// In-memory [`ImapBackend`] for session tests.
///
/// Logins compare against the expected pair. `select` matches names
/// exactly plus the `INBOX` alias for a mailbox named Inbox. `search`
/// answers the snapshot's uid list for the `["ALL"]` criteria the
/// session uses to enumerate the mailbox, a scripted result for exact
/// criteria, and the default scripted list otherwise. `fetch` answers
/// only the scripted uids and `None` for anything else, so an unscripted
/// uid behaves exactly like an expunged message.
pub struct FakeImapBackend {
    pub expected_user: String,
    pub expected_password: String,
    pub views: Vec<MailboxView>,
    pub snapshots: Mutex<HashMap<String, FakeSelected>>,
    pub fetches: Mutex<HashMap<u32, FakeFetched>>,
    /// Uids whose FETCH answers a fixed error: the row exists but its
    /// details cannot be loaded.
    pub failing_fetches: Mutex<Vec<u32>>,
    /// Non-ALL search answers, keyed by the exact parsed keys.
    pub search_scripts: Mutex<Vec<(Vec<SearchKey>, Vec<u32>)>>,
    /// The fallback non-ALL search answer.
    pub search_uids: Mutex<Vec<u32>>,
    /// While set, reading a mailbox by id fails like a store error.
    pub store_failing: Mutex<bool>,
    /// How many FETCH calls asked for at least one body.
    pub body_fetches: AtomicUsize,
    /// Every write the session asked for, as `verb mailbox uids [target]`.
    pub writes: Mutex<Vec<String>>,
    /// While set, every write fails like a refused remote call.
    pub writes_failing: Mutex<bool>,
    /// What `pending_loads` answers, whatever the request.
    pub pending_loads: Mutex<usize>,
    /// The uid lists `pending_loads` was asked about, in call order.
    pub pending_calls: Mutex<Vec<Vec<u32>>>,
}

impl FakeImapBackend {
    pub fn new(user: &str, password: &str) -> Self {
        Self {
            expected_user: user.into(),
            expected_password: password.into(),
            views: Vec::new(),
            snapshots: Mutex::new(HashMap::new()),
            fetches: Mutex::new(HashMap::new()),
            failing_fetches: Mutex::new(Vec::new()),
            search_scripts: Mutex::new(Vec::new()),
            search_uids: Mutex::new(Vec::new()),
            store_failing: Mutex::new(false),
            body_fetches: AtomicUsize::new(0),
            writes: Mutex::new(Vec::new()),
            writes_failing: Mutex::new(false),
            pending_loads: Mutex::new(0),
            pending_calls: Mutex::new(Vec::new()),
        }
    }

    /// Make `pending_loads` answer `count` for every request.
    pub fn with_pending_loads(self, count: usize) -> Self {
        *self.pending_loads.lock().unwrap() = count;
        self
    }

    /// Register one mailbox: its LIST view plus its `SELECT` snapshot.
    pub fn with_mailbox(
        mut self,
        id: MailboxId,
        name: &str,
        special_use: &'static str,
        snapshot: FakeSelected,
    ) -> Self {
        self.views.push(MailboxView {
            id,
            name: name.into(),
            special_use,
        });
        self.snapshots.lock().unwrap().insert(name.into(), snapshot);
        self
    }

    /// Script one uid's FETCH answer.
    pub fn with_fetch(self, uid: u32, fetched: FakeFetched) -> Self {
        self.fetches.lock().unwrap().insert(uid, fetched);
        self
    }

    /// Make `fetch` fail for `uid` with a fixed error: the row exists
    /// but its details cannot be loaded.
    pub fn with_failing_fetch(self, uid: u32) -> Self {
        self.failing_fetches.lock().unwrap().push(uid);
        self
    }

    /// Script the exact `SEARCH` result for one criteria list.
    pub fn with_search_result(self, criteria: &[&str], uids: Vec<u32>) -> Self {
        let args: Vec<ImapArg> = criteria
            .iter()
            .map(|token| ImapArg::Atom(token.to_string()))
            .collect();
        let keys = parse_search(&args).unwrap_or_else(|_| panic!("criteria must parse"));
        self.search_scripts.lock().unwrap().push((keys, uids));
        self
    }

    /// Script the fallback `SEARCH` result for unknown criteria.
    pub fn with_search(self, uids: Vec<u32>) -> Self {
        *self.search_uids.lock().unwrap() = uids;
        self
    }

    /// Simulate a resync: change the mailbox's UIDVALIDITY under a live
    /// session.
    pub fn resync(&self, name: &str, uidvalidity: u32) {
        self.snapshots
            .lock()
            .unwrap()
            .get_mut(name)
            .unwrap_or_else(|| panic!("mailbox {name} is not scripted"))
            .uidvalidity = uidvalidity;
    }

    /// Simulate one new stored message: append a uid (read).
    pub fn add_message(&self, name: &str, uid: u32) {
        self.script(name, |snapshot| snapshot.uids.push(uid));
    }

    /// Simulate a message leaving the mailbox.
    pub fn remove_message(&self, name: &str, uid: u32) {
        self.script(name, |snapshot| {
            snapshot.uids.retain(|known| *known != uid);
            snapshot.unread.retain(|known| *known != uid);
        });
    }

    /// Simulate a read-state change on one stored message.
    pub fn set_unread(&self, name: &str, uid: u32, unread: bool) {
        self.script(name, |snapshot| {
            snapshot.unread.retain(|known| *known != uid);
            if unread {
                snapshot.unread.push(uid);
            }
        });
    }

    /// Simulate the state store failing (or recovering) under a live
    /// session.
    pub fn set_store_failing(&self, failing: bool) {
        *self.store_failing.lock().unwrap() = failing;
    }

    /// Simulate the folder being deleted: its id stops resolving.
    pub fn remove_mailbox(&self, name: &str) {
        self.snapshots.lock().unwrap().remove(name);
    }

    fn script(&self, name: &str, change: impl FnOnce(&mut FakeSelected)) {
        change(
            self.snapshots
                .lock()
                .unwrap()
                .get_mut(name)
                .unwrap_or_else(|| panic!("mailbox {name} is not scripted")),
        );
    }

    fn name_of(&self, id: MailboxId) -> Option<String> {
        self.views
            .iter()
            .find(|view| view.id == id)
            .map(|view| view.name.clone())
    }

    pub fn writes(&self) -> Vec<String> {
        self.writes.lock().unwrap().clone()
    }

    /// Record one write; fail it when writes are scripted to fail.
    fn record_write(&self, line: String) -> Result<()> {
        self.writes.lock().unwrap().push(line);
        if *self.writes_failing.lock().unwrap() {
            return Err(Error::Network("mailbox write failed".into()));
        }
        Ok(())
    }

    /// Drop `uids` from the named mailbox and return the ones it had.
    fn remove_uids(&self, name: &str, uids: &[u32]) -> Vec<u32> {
        let mut removed = Vec::new();
        self.script(name, |snapshot| {
            snapshot.uids.retain(|uid| {
                if uids.contains(uid) {
                    removed.push(*uid);
                    false
                } else {
                    true
                }
            });
            snapshot.unread.retain(|uid| !uids.contains(uid));
        });
        removed
    }

    fn opened(&self, view: &MailboxView) -> Option<SelectedMailbox> {
        let snapshot = self.snapshots.lock().unwrap().get(&view.name).cloned()?;
        Some(SelectedMailbox {
            view: MailboxView {
                id: view.id,
                name: view.name.clone(),
                special_use: view.special_use,
            },
            uidvalidity: snapshot.uidvalidity,
            uidnext: snapshot.uidnext,
            messages: snapshot
                .uids
                .iter()
                .map(|uid| (*uid, snapshot.unread.contains(uid)))
                .collect(),
        })
    }
}

#[async_trait::async_trait]
impl ImapBackend for FakeImapBackend {
    async fn store_seen(
        &self,
        mailbox: MailboxId,
        uids: &[u32],
        seen: bool,
    ) -> Result<Vec<(u32, bool)>> {
        let name = self.name_of(mailbox).expect("scripted mailbox");
        self.record_write(format!("seen {name} {uids:?} {seen}"))?;
        let mut applied = Vec::new();
        self.script(&name, |snapshot| {
            for uid in uids {
                if !snapshot.uids.contains(uid) {
                    continue;
                }
                snapshot.unread.retain(|known| known != uid);
                if !seen {
                    snapshot.unread.push(*uid);
                }
                applied.push((*uid, !seen));
            }
        });
        Ok(applied)
    }

    async fn move_mails(
        &self,
        mailbox: MailboxId,
        uids: &[u32],
        target: MailboxId,
    ) -> Result<Vec<u32>> {
        let name = self.name_of(mailbox).expect("scripted mailbox");
        let target = self.name_of(target).expect("scripted mailbox");
        self.record_write(format!("move {name} {uids:?} {target}"))?;
        Ok(self.remove_uids(&name, uids))
    }

    async fn expunge_mails(&self, mailbox: MailboxId, uids: &[u32]) -> Result<Vec<u32>> {
        let name = self.name_of(mailbox).expect("scripted mailbox");
        self.record_write(format!("expunge {name} {uids:?}"))?;
        Ok(self.remove_uids(&name, uids))
    }

    async fn login(&self, user: &str, password: &SecretString) -> Result<bool> {
        Ok(user == self.expected_user && password.expose_secret() == self.expected_password)
    }

    async fn mailboxes(&self) -> Result<Vec<MailboxView>> {
        Ok(self
            .views
            .iter()
            .map(|view| MailboxView {
                id: view.id,
                name: view.name.clone(),
                special_use: view.special_use,
            })
            .collect())
    }

    async fn select(&self, name: &str) -> Result<Option<SelectedMailbox>> {
        let found = self
            .views
            .iter()
            .find(|view| view.name == name)
            .or_else(|| {
                name.eq_ignore_ascii_case("INBOX")
                    .then(|| {
                        self.views
                            .iter()
                            .find(|view| view.name.eq_ignore_ascii_case("Inbox"))
                    })
                    .flatten()
            });
        Ok(found.and_then(|view| self.opened(view)))
    }

    async fn snapshot(&self, mailbox: MailboxId) -> Result<Option<SelectedMailbox>> {
        if *self.store_failing.lock().unwrap() {
            return Err(Error::Storage("state unavailable".into()));
        }
        Ok(self
            .views
            .iter()
            .find(|view| view.id == mailbox)
            .and_then(|view| self.opened(view)))
    }

    async fn pending_loads(
        &self,
        _mailbox: MailboxId,
        uids: &[u32],
        _items: &[FetchItem],
    ) -> Result<usize> {
        self.pending_calls.lock().unwrap().push(uids.to_vec());
        Ok(*self.pending_loads.lock().unwrap())
    }

    async fn fetch(
        &self,
        _mailbox: MailboxId,
        uid: u32,
        items: &[FetchItem],
    ) -> Result<Option<FetchResponse>> {
        // The row exists but its details cannot be loaded.
        if self.failing_fetches.lock().unwrap().contains(&uid) {
            return Err(Error::Network("fetch failed".into()));
        }
        // Numeric part sections are refused like the real backend
        // refuses them: a protocol verdict about the request, not
        // about one row.
        if items.iter().any(|item| {
            matches!(
                item,
                FetchItem::Body {
                    section: BodySection::Part(_),
                    ..
                }
            )
        }) {
            return Err(Error::Unsupported(
                "message part sections are not supported".into(),
            ));
        }
        let fetches = self.fetches.lock().unwrap();
        let Some(fetched) = fetches.get(&uid) else {
            return Ok(None);
        };
        if items.iter().any(|item| item.is_body()) {
            self.body_fetches.fetch_add(1, Ordering::SeqCst);
        }
        Ok(Some(FetchResponse {
            uid,
            flags: fetched.flags.clone(),
            internal_date: fetched.internal_date.clone(),
            envelope: fetched.envelope.clone(),
            bodystructure: fetched.bodystructure.clone(),
            rfc822_size: fetched.rfc822_size,
            bodies: items
                .iter()
                .filter(|item| item.is_body())
                .map(|_| fetched.body.clone())
                .collect(),
        }))
    }

    async fn search(
        &self,
        _mailbox: MailboxId,
        keys: &[SearchKey],
        view: &[u32],
    ) -> Result<Vec<u32>> {
        // ALL is every message of the searching session's view.
        if keys == [SearchKey::All] {
            return Ok(view.to_vec());
        }
        if let Some((_, scripted)) = self
            .search_scripts
            .lock()
            .unwrap()
            .iter()
            .find(|(scripted, _)| scripted == keys)
        {
            return Ok(scripted.clone());
        }
        Ok(self.search_uids.lock().unwrap().clone())
    }
}

/// One recorded [`MailboxWriter`] call, with element ids only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WriterCall {
    SetUnread(Vec<String>, bool),
    MoveToFolder(String, Vec<String>),
    MoveToTrash(Vec<String>),
    DeletePermanently(String, Vec<String>),
}

/// A [`MailboxWriter`] that records every call and can be made to fail.
#[derive(Default)]
pub struct FakeMailboxWriter {
    pub calls: Mutex<Vec<WriterCall>>,
    pub failing: Mutex<bool>,
}

impl FakeMailboxWriter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn calls(&self) -> Vec<WriterCall> {
        self.calls.lock().unwrap().clone()
    }

    fn record(&self, call: WriterCall) -> Result<()> {
        self.calls.lock().unwrap().push(call);
        if *self.failing.lock().unwrap() {
            return Err(Error::Network("mailbox write failed".into()));
        }
        Ok(())
    }
}

fn element_ids(mails: &[MailRef]) -> Vec<String> {
    mails.iter().map(|mail| mail.element_id.clone()).collect()
}

#[async_trait::async_trait]
impl MailboxWriter for FakeMailboxWriter {
    async fn set_unread(&self, mails: &[MailRef], unread: bool) -> Result<()> {
        self.record(WriterCall::SetUnread(element_ids(mails), unread))
    }

    async fn move_to_folder(&self, target: &str, mails: &[MailRef]) -> Result<()> {
        self.record(WriterCall::MoveToFolder(target.into(), element_ids(mails)))
    }

    async fn move_to_trash(&self, mails: &[MailRef]) -> Result<()> {
        self.record(WriterCall::MoveToTrash(element_ids(mails)))
    }

    async fn delete_permanently(&self, folder: &str, mails: &[MailRef]) -> Result<()> {
        self.record(WriterCall::DeletePermanently(
            folder.into(),
            element_ids(mails),
        ))
    }
}

// ---------------------------------------------------------------------------
// FakeContactSource (CardDAV)
// ---------------------------------------------------------------------------

/// An in-memory address book. Contacts are keyed by element id; every
/// load is counted, and loads can be made to fail with a network error.
pub struct FakeContactSource {
    pub cards: Mutex<Vec<tuta_bridge::domain::ContactCard>>,
    pub fail: std::sync::atomic::AtomicBool,
    pub full_loads: AtomicUsize,
    pub single_loads: AtomicUsize,
}

impl FakeContactSource {
    pub fn new(cards: Vec<tuta_bridge::domain::ContactCard>) -> Self {
        Self {
            cards: Mutex::new(cards),
            fail: std::sync::atomic::AtomicBool::new(false),
            full_loads: AtomicUsize::new(0),
            single_loads: AtomicUsize::new(0),
        }
    }

    /// Replace or add one contact.
    pub fn put(&self, card: tuta_bridge::domain::ContactCard) {
        let mut cards = self.cards.lock().unwrap();
        cards.retain(|existing| existing.element_id != card.element_id);
        cards.push(card);
    }

    pub fn remove(&self, element_id: &str) {
        self.cards
            .lock()
            .unwrap()
            .retain(|card| card.element_id != element_id);
    }

    pub fn set_failing(&self, failing: bool) {
        self.fail.store(failing, Ordering::SeqCst);
    }

    pub fn full_loads(&self) -> usize {
        self.full_loads.load(Ordering::SeqCst)
    }

    pub fn single_loads(&self) -> usize {
        self.single_loads.load(Ordering::SeqCst)
    }
}

// ---------------------------------------------------------------------------
// FakeCalendarSource
// ---------------------------------------------------------------------------

/// In-memory [`CalendarSource`]: calendars, events keyed by
/// `(list, element)`, alarm triggers keyed by alarm id, and a count of
/// calls to fail with a network error.
#[derive(Default)]
pub struct FakeCalendarSource {
    pub calendars: Mutex<Vec<CalendarInfo>>,
    pub events: Mutex<Vec<CalendarEvent>>,
    pub alarms: Mutex<HashMap<(String, String), String>>,
    /// The next this many calls fail with `Error::Network`.
    pub failures: Mutex<usize>,
    pub calls: Mutex<Vec<String>>,
}

impl FakeCalendarSource {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_calendar(&self, calendar: CalendarInfo) {
        self.calendars.lock().unwrap().push(calendar);
    }

    /// Insert or replace an event (by list and element id).
    pub fn put_event(&self, event: CalendarEvent) {
        let mut events = self.events.lock().unwrap();
        events.retain(|e| !(e.list_id == event.list_id && e.element_id == event.element_id));
        events.push(event);
    }

    pub fn remove_event(&self, list_id: &str, element_id: &str) {
        self.events
            .lock()
            .unwrap()
            .retain(|e| !(e.list_id == list_id && e.element_id == element_id));
    }

    pub fn put_alarm(&self, list_id: &str, element_id: &str, trigger: &str) {
        self.alarms
            .lock()
            .unwrap()
            .insert((list_id.into(), element_id.into()), trigger.into());
    }

    pub fn fail_next(&self, count: usize) {
        *self.failures.lock().unwrap() = count;
    }

    pub fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }

    fn record(&self, call: &str) -> Result<()> {
        self.calls.lock().unwrap().push(call.to_string());
        let mut failures = self.failures.lock().unwrap();
        if *failures > 0 {
            *failures -= 1;
            return Err(Error::Network("calendar data unavailable".into()));
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl tuta_bridge::ports::contact_source::ContactSource for FakeContactSource {
    async fn contacts(&self) -> Result<tuta_bridge::ports::contact_source::ContactListing> {
        self.full_loads.fetch_add(1, Ordering::SeqCst);
        if self.fail.load(Ordering::SeqCst) {
            return Err(Error::Network("contacts unavailable".into()));
        }
        Ok(tuta_bridge::ports::contact_source::ContactListing {
            cards: self.cards.lock().unwrap().clone(),
            skipped: 0,
        })
    }

    async fn contact(
        &self,
        list_id: &str,
        element_id: &str,
    ) -> Result<Option<tuta_bridge::domain::ContactCard>> {
        self.single_loads.fetch_add(1, Ordering::SeqCst);
        if self.fail.load(Ordering::SeqCst) {
            return Err(Error::Network("contacts unavailable".into()));
        }
        Ok(self
            .cards
            .lock()
            .unwrap()
            .iter()
            .find(|card| card.list_id == list_id && card.element_id == element_id)
            .cloned())
    }
}

#[async_trait::async_trait]
impl CalendarSource for FakeCalendarSource {
    async fn calendars(&self) -> Result<Vec<CalendarInfo>> {
        self.record("calendars")?;
        Ok(self.calendars.lock().unwrap().clone())
    }

    async fn events(
        &self,
        calendar: &CalendarInfo,
        from_ms: i64,
        to_ms: i64,
    ) -> Result<Vec<CalendarEvent>> {
        self.record("events")?;
        Ok(self
            .events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.list_id == calendar.short_list_id || e.list_id == calendar.long_list_id)
            .filter(|e| e.may_overlap(from_ms, to_ms))
            .cloned()
            .collect())
    }

    async fn event(&self, list_id: &str, element_id: &str) -> Result<Option<CalendarEvent>> {
        self.record("event")?;
        Ok(self
            .events
            .lock()
            .unwrap()
            .iter()
            .find(|e| e.list_id == list_id && e.element_id == element_id)
            .cloned())
    }

    async fn alarm_triggers(&self, alarm_ids: &[(String, String)]) -> Result<Vec<String>> {
        self.record("alarm_triggers")?;
        let alarms = self.alarms.lock().unwrap();
        let mut triggers: Vec<String> = alarm_ids
            .iter()
            .filter_map(|id| alarms.get(id).cloned())
            .collect();
        triggers.sort();
        Ok(triggers)
    }
}
