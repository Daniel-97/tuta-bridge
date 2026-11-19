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
    /// Store one folder's header page as a unit and return how many
    /// stored messages it removed.
    ///
    /// Every header keeps its UID or is assigned the next one, in the
    /// order given. With `reconcile`, stored messages of the mailbox that
    /// are absent from both `headers` and `keep` are removed; pass it
    /// only for a complete listing. `keep` names, as `(list id, element
    /// id)`, mails the folder still lists but whose header could not be
    /// loaded: their rows stay exactly as stored. Adapters with
    /// transactions run the whole page in one, so a failure leaves the
    /// mailbox as it was; this default applies the same steps one call
    /// at a time.
    async fn store_page(
        &self,
        mailbox: MailboxId,
        headers: &[MessageHeader],
        keep: &[(String, String)],
        reconcile: bool,
    ) -> Result<usize> {
        for header in headers {
            self.assign_uid(mailbox, header).await?;
        }
        if !reconcile {
            return Ok(0);
        }
        let mut removed = 0;
        for stored in self.messages(mailbox).await? {
            let fetched = headers.iter().any(|header| {
                header.list_id == stored.header.list_id
                    && header.element_id == stored.header.element_id
            }) || keep.iter().any(|(list_id, element_id)| {
                *list_id == stored.header.list_id && *element_id == stored.header.element_id
            });
            if !fetched {
                self.remove_message(mailbox, stored.uid).await?;
                removed += 1;
            }
        }
        Ok(removed)
    }
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
    /// The `(uid, unread)` pair of every message in the mailbox, in
    /// ascending UID order.
    ///
    /// This is the cheap read for keeping a message-number snapshot
    /// current: adapters answer it without loading or decoding headers.
    /// The default derives it from [`Self::messages`].
    async fn message_uids(&self, mailbox: MailboxId) -> Result<Vec<(u32, bool)>> {
        Ok(self
            .messages(mailbox)
            .await?
            .into_iter()
            .map(|message| (message.uid, message.header.unread))
            .collect())
    }
    /// Load one stored message by UID, or `None` when the mailbox has no
    /// such UID. Like every store read this is metadata only.
    async fn message_by_uid(&self, mailbox: MailboxId, uid: u32) -> Result<Option<StoredMessage>>;
    async fn last_batch(&self, account_id: i64, group_id: &str) -> Result<Option<String>>;
    async fn set_last_batch(&self, account_id: i64, group_id: &str, batch_id: &str) -> Result<()>;
    async fn reset_account(&self, account_id: i64) -> Result<()>;
}
