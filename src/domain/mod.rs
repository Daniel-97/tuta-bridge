pub mod account;
pub mod error;
pub mod mail;
pub mod state;

pub use account::{AccountId, AccountInfo, StoredCredentials};
pub use error::{Error, Result};
pub use mail::{Address, Attachment, Folder, FolderKind, MessageContent, MessageSummary};
pub use state::{MailboxId, MessageHeader, MessagePage, StoredMailbox, StoredMessage};
