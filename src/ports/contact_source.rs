//! The read seam of the CardDAV listener: decrypted contacts.

use crate::domain::{ContactCard, Error, Result};

/// Every readable contact of the user's own address book.
pub struct ContactListing {
    pub cards: Vec<ContactCard>,
    /// Contacts that failed to decrypt and were left out.
    pub skipped: usize,
    /// The element ids of the skipped contacts that do exist (all of
    /// them but those without an id): the cache keeps their rows rather
    /// than reporting them deleted. Never logged.
    pub undecryptable: Vec<String>,
}

/// One contact looked up by id.
pub enum ContactLookup {
    Found(Box<ContactCard>),
    /// The contact no longer exists.
    Gone,
    /// The contact exists but did not decrypt: it is neither served nor
    /// removed from the cache.
    Undecryptable,
}

/// Loads contacts through the SDK's decryption path.
///
/// Errors carry fixed text only: never a name, an address or an id.
#[async_trait::async_trait]
pub trait ContactSource: Send + Sync {
    /// The whole address book.
    async fn contacts(&self) -> Result<ContactListing>;

    /// The id of the account's own contact list, resolved
    /// structurally — never learned from a rendered card, so an
    /// empty address book knows its list too.
    ///
    /// `Ok(None)` when the source cannot resolve it (the book falls
    /// back to the id of the first card); an error means the
    /// resolution was attempted and failed, and never fails the
    /// load that asked for it.
    async fn contact_list_id(&self) -> Result<Option<String>>;

    /// One contact: found, gone, or present but undecryptable.
    async fn contact(&self, list_id: &str, element_id: &str) -> Result<ContactLookup>;
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

    async fn contact_list_id(&self) -> Result<Option<String>> {
        Err(Error::Unsupported(
            "contacts are not supported by this session".into(),
        ))
    }

    async fn contact(&self, _list_id: &str, _element_id: &str) -> Result<ContactLookup> {
        Err(Error::Unsupported(
            "contacts are not supported by this session".into(),
        ))
    }
}
