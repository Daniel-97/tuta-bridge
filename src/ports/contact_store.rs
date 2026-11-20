//! The CardDAV contact cache: metadata only.
//!
//! One row per contact with its ETag and the revision at which it last
//! changed; deleted contacts stay as tombstones so a `sync-collection`
//! report can name them. vCard bodies are never stored: they are
//! rendered from the SDK on demand.

use crate::domain::Result;

/// The address book of one account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactBookState {
    /// Random, fixed for the life of the book; a sync token from another
    /// epoch (another database) is refused.
    pub epoch: String,
    /// Bumped by every change to a contact row; the ctag and sync token.
    pub revision: i64,
    /// Whether a full load has filled the cache at least once.
    pub loaded: bool,
    /// The Tuta contact list the book was last loaded from, if known.
    pub list_id: Option<String>,
}

/// One cached contact (or tombstone).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredContact {
    pub list_id: String,
    pub element_id: String,
    /// The full quoted strong ETag (`"…"`).
    pub etag: String,
    /// The book revision at which the row last changed.
    pub revision: i64,
    pub deleted: bool,
}

/// A contact's current ETag, to store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactEntry {
    pub list_id: String,
    pub element_id: String,
    pub etag: String,
}

/// What one write changed. Unchanged rows count nowhere.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ContactCounts {
    pub added: usize,
    pub updated: usize,
    pub removed: usize,
}

impl ContactCounts {
    pub fn is_empty(&self) -> bool {
        self.added == 0 && self.updated == 0 && self.removed == 0
    }
}

/// The cache behind the CardDAV listener.
#[async_trait::async_trait]
pub trait ContactStore: Send + Sync {
    /// The book of `account_id`, created (empty, not loaded) when missing.
    async fn contact_book(&self, account_id: i64) -> Result<ContactBookState>;

    /// Replace the cache with a complete listing: new and changed rows
    /// get a new revision, rows absent from `entries` become tombstones,
    /// unchanged rows keep their revision. Marks the book loaded and
    /// records `list_id`.
    async fn replace_contacts(
        &self,
        account_id: i64,
        list_id: Option<&str>,
        entries: &[ContactEntry],
    ) -> Result<ContactCounts>;

    /// Apply individual changes: upserts first, then removals by element
    /// id. Rows whose ETag did not change keep their revision.
    async fn update_contacts(
        &self,
        account_id: i64,
        upserts: &[ContactEntry],
        removals: &[String],
    ) -> Result<ContactCounts>;

    /// Every live (non-deleted) contact, ordered by element id.
    async fn contacts(&self, account_id: i64) -> Result<Vec<StoredContact>>;

    /// One live contact by element id.
    async fn contact(&self, account_id: i64, element_id: &str) -> Result<Option<StoredContact>>;

    /// The current revision and every row (tombstones included) changed
    /// after `revision`, read together.
    async fn contact_changes_since(
        &self,
        account_id: i64,
        revision: i64,
    ) -> Result<(i64, Vec<StoredContact>)>;
}
