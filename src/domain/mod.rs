pub mod account;
pub mod error;
pub mod mail;

pub use account::{AccountId, AccountInfo, StoredCredentials};
pub use error::{Error, Result};
pub use mail::{Address, Attachment, Folder, FolderKind, MessageContent, MessageSummary};
