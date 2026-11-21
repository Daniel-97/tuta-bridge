//! Domain types for Tuta websocket events.
//!
//! These types deliberately omit `Debug`: they only carry ids today, and a
//! future event may carry personal data that must not end up in logs.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntityOperation {
    Create,
    Update,
    Delete,
}

#[derive(Clone, PartialEq, Eq)]
pub struct EntityEvent {
    pub application: String,
    pub type_id: i64,
    pub list_id: String,
    pub element_id: String,
    pub operation: EntityOperation,
}

#[derive(Clone, PartialEq, Eq)]
pub struct EventBatch {
    pub batch_id: String,
    pub owner_group_id: String,
    pub application_types_hash: String,
    pub events: Vec<EntityEvent>,
}

#[derive(Clone, PartialEq, Eq)]
pub enum EventFrame {
    Batch(EventBatch),
    InitialSyncDone,
    Ignored,
}

/// Application name of every mail event handled by the bridge.
pub const TUTANOTA_APP: &str = "tutanota";
/// Type id of a `Mail`.
pub const MAIL_TYPE_ID: i64 = 97;
/// Type id of a `MailSet`.
pub const MAIL_SET_TYPE_ID: i64 = 429;
/// Type id of a `MailSetEntry`.
pub const MAIL_SET_ENTRY_TYPE_ID: i64 = 1450;
/// Type id of a `Contact` (CardDAV).
pub const CONTACT_TYPE_ID: i64 = 64;
