use crate::domain::{MessageContent, Result};

pub trait MessageRenderer: Send + Sync {
    fn render(&self, content: &MessageContent) -> Result<Vec<u8>>;
}
