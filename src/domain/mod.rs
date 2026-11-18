pub mod account;
pub mod error;
pub mod event;
pub mod mail;
pub mod state;

pub use account::{AccountId, AccountInfo, StoredCredentials};
pub use error::{Error, Result};
pub use event::{
    EntityEvent, EntityOperation, EventBatch, EventFrame, MAIL_SET_ENTRY_TYPE_ID, MAIL_SET_TYPE_ID,
    MAIL_TYPE_ID, TUTANOTA_APP,
};
pub use mail::{Address, Attachment, Folder, FolderKind, MessageContent, MessageSummary};
pub use state::{
    BatchOutcome, MailPlacement, MailboxId, MessageHeader, MessagePage, StateChange, StoredMailbox,
    StoredMessage,
};
