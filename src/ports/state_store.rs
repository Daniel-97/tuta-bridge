use crate::domain::{
    BatchOutcome, Folder, MailboxId, MessageHeader, Result, StateChange, StoredMailbox,
    StoredMessage,
};

#[async_trait::async_trait]
pub trait StateStore: Send + Sync {
    async fn upsert_account(&self, mail_address: &str) -> Result<i64>;
    /// Create or refresh the mailbox of `folder`.
    ///
    /// `uidvalidity` is a lower bound, not the stored value: a new
    /// mailbox, and one whose name changed, gets a UIDVALIDITY greater
    /// than any the account ever used and at least `uidvalidity`; an
    /// unchanged mailbox keeps its value and its UIDs. A name and
    /// UIDVALIDITY pair therefore never denotes two different mailboxes.
    async fn upsert_mailbox(
        &self,
        account_id: i64,
        folder: &Folder,
        uidvalidity: u32,
    ) -> Result<MailboxId>;
    async fn mailboxes(&self, account_id: i64) -> Result<Vec<StoredMailbox>>;
    async fn assign_uid(&self, mailbox: MailboxId, header: &MessageHeader) -> Result<u32>;
    /// Apply every change and record `batch_id` in one transaction.
    ///
    /// The outcome lists every mailbox whose rows the transaction
    /// actually inserted, updated, or deleted.
    async fn apply_batch(
        &self,
        account_id: i64,
        group_id: &str,
        batch_id: &str,
        changes: &[StateChange],
    ) -> Result<BatchOutcome>;
    async fn remove_mailbox(&self, account_id: i64, mailbox: MailboxId) -> Result<()>;
    async fn update_metadata(
        &self,
        mailbox: MailboxId,
        uid: u32,
        header: &MessageHeader,
        rfc822_size: Option<u64>,
    ) -> Result<()>;
    /// Persist the precomputed BODYSTRUCTURE string for one message.
    ///
    /// The structure is metadata only; the rendered bytes it describes
    /// are never stored. Fails when the `(mailbox, uid)` row is missing.
    async fn set_mime_structure(&self, mailbox: MailboxId, uid: u32, structure: &str)
        -> Result<()>;
    async fn remove_message(&self, mailbox: MailboxId, uid: u32) -> Result<()>;
    async fn messages(&self, mailbox: MailboxId) -> Result<Vec<StoredMessage>>;
    /// Load one stored message by UID, or `None` when the mailbox has no
    /// such UID. Like every store read this is metadata only.
    async fn message_by_uid(&self, mailbox: MailboxId, uid: u32) -> Result<Option<StoredMessage>>;
    async fn last_batch(&self, account_id: i64, group_id: &str) -> Result<Option<String>>;
    async fn set_last_batch(&self, account_id: i64, group_id: &str, batch_id: &str) -> Result<()>;
    async fn reset_account(&self, account_id: i64) -> Result<()>;
}
