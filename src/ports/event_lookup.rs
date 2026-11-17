use crate::domain::{Folder, MessageHeader, Result};

/// Reload the Tuta entities referenced by a websocket event.
///
/// Event frames only carry ids and operations; the processor needs the
/// current metadata behind them. Implementations load through the SDK
/// decryption path and return metadata only: never `MailDetails`, blobs,
/// attachments, or bodies.
#[async_trait::async_trait]
pub trait EventLookup: Send + Sync {
    /// Reload every stored placement of one mail.
    ///
    /// `Ok(None)` means the mail is unreadable (its intactness check failed)
    /// and the caller must keep the existing rows. `Ok(Some(vec![]))` means
    /// the mail genuinely has no placements. `Err` means the mail could not
    /// be loaded completely; the caller must skip it rather than treat the
    /// placement list as empty.
    async fn headers_for_mail(
        &self,
        mail_list_id: &str,
        mail_element_id: &str,
    ) -> Result<Option<Vec<MessageHeader>>>;

    /// Reload the header of one mail-set entry, or `Ok(None)` when the
    /// entry's mail is unreadable or cannot be referenced.
    async fn header_for_entry(
        &self,
        entry_list_id: &str,
        entry_element_id: &str,
    ) -> Result<Option<MessageHeader>>;

    /// Reload one mail set as a folder, or `Ok(None)` when the set is not a
    /// folder the bridge stores (for example the virtual "All" set).
    async fn folder(&self, set_list_id: &str, set_element_id: &str) -> Result<Option<Folder>>;
}
