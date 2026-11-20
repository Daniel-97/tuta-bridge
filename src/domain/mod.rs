pub mod account;
pub mod contact;
pub mod error;
pub mod event;
pub mod mail;
pub mod state;

pub use account::{AccountId, AccountInfo, StoredCredentials};
pub use contact::{
    ContactCard, ContactField, ContactFieldKind, ContactRelation, ContactRelationKind,
};
pub use error::{Error, Result};
pub use event::CONTACT_TYPE_ID;
pub use event::{
    EntityEvent, EntityOperation, EventBatch, EventFrame, MAIL_SET_ENTRY_TYPE_ID, MAIL_SET_TYPE_ID,
    MAIL_TYPE_ID, TUTANOTA_APP,
};
pub use mail::{Address, Attachment, Folder, FolderKind, MessageContent, MessageSummary};
pub use state::{
    BatchCounts, BatchOutcome, MailPlacement, MailboxId, MessageHeader, MessagePage, StateChange,
    StoredMailbox, StoredMessage,
};
