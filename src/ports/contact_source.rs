//! The read seam of the CardDAV listener: decrypted contacts.

use crate::domain::{ContactCard, Error, Result};

/// Every readable contact of the user's own address book.
pub struct ContactListing {
    pub cards: Vec<ContactCard>,
    /// Contacts that failed to decrypt and were left out.
    pub skipped: usize,
}

/// Loads contacts through the SDK's decryption path.
///
/// Errors carry fixed text only: never a name, an address or an id.
#[async_trait::async_trait]
pub trait ContactSource: Send + Sync {
    /// The whole address book.
    async fn contacts(&self) -> Result<ContactListing>;

    /// One contact, or `Ok(None)` when it no longer exists or does not
    /// decrypt.
    async fn contact(&self, list_id: &str, element_id: &str) -> Result<Option<ContactCard>>;
}

/// A [`ContactSource`] for sessions without contacts support.
pub struct NoContacts;

#[async_trait::async_trait]
impl ContactSource for NoContacts {
    async fn contacts(&self) -> Result<ContactListing> {
        Err(Error::Unsupported(
            "contacts are not supported by this session".into(),
        ))
    }

    async fn contact(&self, _list_id: &str, _element_id: &str) -> Result<Option<ContactCard>> {
        Err(Error::Unsupported(
            "contacts are not supported by this session".into(),
        ))
    }
}
