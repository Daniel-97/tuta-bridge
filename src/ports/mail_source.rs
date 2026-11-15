use crate::domain::{Folder, MessageContent, MessageSummary, Result};

#[async_trait::async_trait]
pub trait MailSource: Send + Sync {
    async fn folders(&self) -> Result<Vec<Folder>>;
    async fn messages(&self, folder: &Folder, limit: usize) -> Result<Vec<MessageSummary>>;
    async fn content(&self, message: &MessageSummary) -> Result<MessageContent>;
}
