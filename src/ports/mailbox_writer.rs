use crate::domain::Result;

/// One mail as the write services address it: the `(list id, element id)`
/// pair of the `Mail` entity, exactly as the store keeps it.
#[derive(Clone, PartialEq, Eq)]
pub struct MailRef {
    pub list_id: String,
    pub element_id: String,
}

/// The write seam towards Tuta.
///
/// Every call either applies the whole change remotely or fails; callers
/// update the local index only after a call succeeded. The event bus later
/// delivers the echo of the same change, which the store applies
/// idempotently. Errors carry fixed messages only: never ids, names or
/// addresses.
#[async_trait::async_trait]
pub trait MailboxWriter: Send + Sync {
    /// Mark mails read (`unread == false`) or unread.
    async fn set_unread(&self, mails: &[MailRef], unread: bool) -> Result<()>;
    /// Move mails into the folder whose `entries` list id is
    /// `target_folder_entries` (the id the store keeps per mailbox).
    async fn move_to_folder(&self, target_folder_entries: &str, mails: &[MailRef]) -> Result<()>;
    /// Move mails into their mailbox's Trash folder.
    async fn move_to_trash(&self, mails: &[MailRef]) -> Result<()>;
    /// Delete mails for good from the folder whose `entries` list id is
    /// `folder_entries`. Only ever called for mails in Trash.
    async fn delete_permanently(&self, folder_entries: &str, mails: &[MailRef]) -> Result<()>;
}
