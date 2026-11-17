use crate::domain::{
    Folder, MailboxId, MessageHeader, Result, StateChange, StoredMailbox, StoredMessage,
};

#[async_trait::async_trait]
pub trait StateStore: Send + Sync {
    async fn upsert_account(&self, mail_address: &str) -> Result<i64>;
    async fn upsert_mailbox(
        &self,
        account_id: i64,
        folder: &Folder,
        uidvalidity: u32,
    ) -> Result<MailboxId>;
    async fn mailboxes(&self, account_id: i64) -> Result<Vec<StoredMailbox>>;
    async fn assign_uid(&self, mailbox: MailboxId, header: &MessageHeader) -> Result<u32>;
    /// Apply every change and record `batch_id` in one transaction.
    async fn apply_batch(
        &self,
        account_id: i64,
        group_id: &str,
        batch_id: &str,
        changes: &[StateChange],
    ) -> Result<()>;
    async fn remove_mailbox(&self, account_id: i64, mailbox: MailboxId) -> Result<()>;
    async fn update_metadata(
        &self,
        mailbox: MailboxId,
        uid: u32,
        header: &MessageHeader,
        rfc822_size: Option<u64>,
    ) -> Result<()>;
    async fn remove_message(&self, mailbox: MailboxId, uid: u32) -> Result<()>;
    async fn messages(&self, mailbox: MailboxId) -> Result<Vec<StoredMessage>>;
    async fn last_batch(&self, account_id: i64, group_id: &str) -> Result<Option<String>>;
    async fn set_last_batch(&self, account_id: i64, group_id: &str, batch_id: &str) -> Result<()>;
    async fn reset_account(&self, account_id: i64) -> Result<()>;
}
