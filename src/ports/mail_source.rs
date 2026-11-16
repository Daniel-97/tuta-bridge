use crate::domain::{Error, Folder, MessageContent, MessagePage, MessageSummary, Result};

#[async_trait::async_trait]
pub trait MailSource: Send + Sync {
    async fn folders(&self) -> Result<Vec<Folder>>;
    async fn messages(&self, folder: &Folder, limit: usize) -> Result<Vec<MessageSummary>>;
    async fn content(&self, message: &MessageSummary) -> Result<MessageContent>;

    /// Load a page of metadata-only headers for a folder.
    ///
    /// `start` is a pagination cursor and `limit` a maximum page size. Sources
    /// that cannot paginate may ignore both and return every header. The
    /// default keeps lightweight fakes source-compatible.
    async fn headers_page(
        &self,
        _folder: &Folder,
        _start: Option<&str>,
        _limit: usize,
    ) -> Result<MessagePage> {
        Err(Error::Unsupported("headers not implemented".into()))
    }
}
