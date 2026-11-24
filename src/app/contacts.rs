//! The CardDAV address book: the contact cache kept fresh from the
//! SDK, and vCards rendered on demand.
//!
//! The cache (see [`ContactStore`]) holds one ETag per contact, so
//! listings, `getctag` and `sync-token` never touch the network. It is
//! filled by a full load at `serve` start (and again whenever it is
//! stale or was never loaded), refreshed per contact by the event bus,
//! and healed whenever a rendering finds a different ETag than the one
//! stored. Every write runs under one lock, so a slow full load and an
//! event refresh never interleave.
//!
//! A contact that exists but does not decrypt is never turned into a
//! tombstone: a full load keeps its cached row (and counts it as
//! skipped), an event refresh leaves the row alone. It is not served
//! until it decrypts again (a fetch answers `404`).
//!
//! The DAV write path applies an accepted remote write the same way an
//! event refresh does.
//!
//! Output and errors carry fixed text and counters only.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::sync::Mutex;

use crate::adapters::carddav::vcard::{render_vcard, vcard_etag};
use crate::app::event_sync::{contact_events, ContactEventAction};
use crate::domain::{ContactCard, Error, EventBatch, Result};
use crate::ports::contact_source::{ContactLookup, ContactSource};
use crate::ports::contact_store::{
    ContactBookState, ContactCounts, ContactEntry, ContactStore, StoredContact,
};
use crate::ports::state_store::StateStore;

/// Up to this many cards are loaded one by one; more load the whole
/// book in one listing.
const SINGLE_LOAD_LIMIT: usize = 4;

/// A contact rendered as vCard, with its ETag.
#[derive(Clone)]
pub struct RenderedCard {
    pub card: ContactCard,
    pub vcard: String,
    pub etag: String,
}

impl RenderedCard {
    pub fn new(card: ContactCard) -> Self {
        let vcard = render_vcard(&card);
        let etag = vcard_etag(&vcard);
        Self { card, vcard, etag }
    }

    fn entry(&self) -> ContactEntry {
        ContactEntry {
            list_id: self.card.list_id.clone(),
            element_id: self.card.element_id.clone(),
            etag: self.etag.clone(),
        }
    }
}

/// What one full load did to the cache.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ContactReloadReport {
    pub counts: ContactCounts,
    /// Contacts that did not decrypt; the cached rows of those that
    /// exist are kept.
    pub skipped: usize,
}

/// What one event batch did to the cache.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ContactEventReport {
    /// Contact events in the batch (after coalescing).
    pub events: usize,
    pub counts: ContactCounts,
    /// Refreshed contacts that did not decrypt; their rows are kept.
    pub skipped: usize,
    /// A reload failed: the cache is marked stale and the next CardDAV
    /// request reloads the whole book.
    pub failed: bool,
}

/// The address book of one account.
pub struct ContactBook {
    account_id: i64,
    state: Arc<dyn StateStore>,
    source: Arc<dyn ContactSource>,
    /// Set when the cache may have missed a change (a failed event
    /// refresh, an index recovery after missed events).
    stale: AtomicBool,
    write: Mutex<()>,
}

impl ContactBook {
    /// A book over the contact cache of `state`; [`Error::Config`] when
    /// the store keeps none.
    pub fn new(
        account_id: i64,
        state: Arc<dyn StateStore>,
        source: Arc<dyn ContactSource>,
    ) -> Result<Self> {
        if state.contact_store().is_none() {
            return Err(Error::Config(
                "the state store has no contact cache for CardDAV".into(),
            ));
        }
        Ok(Self {
            account_id,
            state,
            source,
            stale: AtomicBool::new(false),
            write: Mutex::new(()),
        })
    }

    fn store(&self) -> &dyn ContactStore {
        self.state
            .contact_store()
            .expect("checked in ContactBook::new")
    }

    /// Ask for a full reload before the next listing is served.
    pub fn mark_stale(&self) {
        self.stale.store(true, Ordering::SeqCst);
    }

    pub fn is_stale(&self) -> bool {
        self.stale.load(Ordering::SeqCst)
    }

    /// Load the whole book and replace the cache. Unchanged contacts
    /// keep their ETag and revision; undecryptable ones keep their row.
    pub async fn reload(&self) -> Result<ContactReloadReport> {
        let _guard = self.write.lock().await;
        self.reload_locked().await.map(|(report, _)| report)
    }

    async fn reload_locked(&self) -> Result<(ContactReloadReport, Vec<RenderedCard>)> {
        // Cleared first: a change reported while the load runs sets it
        // again and is picked up by the next request.
        self.stale.store(false, Ordering::SeqCst);
        let listing = match self.source.contacts().await {
            Ok(listing) => listing,
            Err(error) => {
                self.stale.store(true, Ordering::SeqCst);
                return Err(error);
            }
        };
        let rendered: Vec<RenderedCard> =
            listing.cards.into_iter().map(RenderedCard::new).collect();
        let mut entries: Vec<ContactEntry> = rendered.iter().map(RenderedCard::entry).collect();
        // Undecryptable contacts are not gone: their cached rows stay
        // as they are.
        for element_id in &listing.undecryptable {
            let kept = self
                .store()
                .contact(self.account_id, element_id)
                .await
                .inspect_err(|_| self.stale.store(true, Ordering::SeqCst))?;
            if let Some(stored) = kept {
                entries.push(ContactEntry {
                    list_id: stored.list_id,
                    element_id: stored.element_id,
                    etag: stored.etag,
                });
            }
        }
        let list_id = rendered.first().map(|card| card.card.list_id.as_str());
        let counts = self
            .store()
            .replace_contacts(self.account_id, list_id, &entries)
            .await
            .inspect_err(|_| self.stale.store(true, Ordering::SeqCst))?;
        let report = ContactReloadReport {
            counts,
            skipped: listing.skipped,
        };
        Ok((report, rendered))
    }

    /// Make sure the cache can answer a listing: a book that was never
    /// loaded is loaded now (a failure is returned); a stale one is
    /// reloaded, but on failure the stale cache is served.
    pub async fn ensure_fresh(&self) -> Result<ContactBookState> {
        let book = self.store().contact_book(self.account_id).await?;
        if book.loaded && !self.is_stale() {
            return Ok(book);
        }
        let _guard = self.write.lock().await;
        // Another request may have reloaded while this one waited.
        let book = self.store().contact_book(self.account_id).await?;
        if book.loaded && !self.is_stale() {
            return Ok(book);
        }
        match self.reload_locked().await {
            Ok(_) => {}
            Err(error) if !book.loaded => return Err(error),
            Err(_) => {}
        }
        self.store().contact_book(self.account_id).await
    }

    /// The book's revision, epoch and load state, without reloading.
    pub async fn state(&self) -> Result<ContactBookState> {
        self.store().contact_book(self.account_id).await
    }

    /// Every cached contact.
    pub async fn listing(&self) -> Result<Vec<StoredContact>> {
        self.store().contacts(self.account_id).await
    }

    /// One cached contact by element id.
    pub async fn lookup(&self, element_id: &str) -> Result<Option<StoredContact>> {
        self.store().contact(self.account_id, element_id).await
    }

    /// The current revision and every row changed after `revision`.
    pub async fn changes_since(&self, revision: i64) -> Result<(i64, Vec<StoredContact>)> {
        self.store()
            .contact_changes_since(self.account_id, revision)
            .await
    }

    /// Apply one contact write the remote side has already accepted: the
    /// same upsert a refresh applies, which keeps an unchanged ETag (and
    /// the revision with it) as it is — the echo of the same change
    /// counts once. A store failure marks the book stale so the next
    /// request reloads and heals the row.
    pub async fn apply_written(&self, entry: &ContactEntry) -> Result<()> {
        let _guard = self.write.lock().await;
        self.store()
            .update_contacts(self.account_id, std::slice::from_ref(entry), &[])
            .await
            .inspect_err(|_| self.mark_stale())
            .map(|_| ())
    }

    /// Apply one contact deletion the remote side has already confirmed:
    /// the row becomes a tombstone the sync reports. A store failure
    /// marks the book stale so the next request reloads and heals it.
    pub async fn apply_deleted(&self, element_id: &str) -> Result<()> {
        let _guard = self.write.lock().await;
        self.store()
            .update_contacts(
                self.account_id,
                &[],
                std::slice::from_ref(&element_id.to_string()),
            )
            .await
            .inspect_err(|_| self.mark_stale())
            .map(|_| ())
    }

    /// Render one cached contact from the SDK. `None` when it is gone
    /// (the cache is healed) or does not decrypt (the cache is left as
    /// it is); a changed ETag is healed too.
    pub async fn render(&self, stored: &StoredContact) -> Result<Option<RenderedCard>> {
        let loaded = self
            .source
            .contact(&stored.list_id, &stored.element_id)
            .await?;
        let _guard = self.write.lock().await;
        match loaded {
            ContactLookup::Found(card) => {
                let card = RenderedCard::new(*card);
                if card.etag != stored.etag {
                    self.store()
                        .update_contacts(self.account_id, &[card.entry()], &[])
                        .await?;
                }
                Ok(Some(card))
            }
            ContactLookup::Undecryptable => Ok(None),
            ContactLookup::Gone => {
                self.store()
                    .update_contacts(
                        self.account_id,
                        &[],
                        std::slice::from_ref(&stored.element_id),
                    )
                    .await?;
                Ok(None)
            }
        }
    }

    /// Render several cached contacts, keyed by element id; contacts that
    /// are gone are missing from the map. A few load one by one, more
    /// load the whole book (which also refreshes the cache).
    pub async fn render_many(
        &self,
        stored: &[StoredContact],
    ) -> Result<HashMap<String, RenderedCard>> {
        if stored.len() <= SINGLE_LOAD_LIMIT {
            let mut rendered = HashMap::new();
            for contact in stored {
                if let Some(card) = self.render(contact).await? {
                    rendered.insert(contact.element_id.clone(), card);
                }
            }
            return Ok(rendered);
        }
        let all = self.render_all().await?;
        Ok(all
            .into_iter()
            .map(|card| (card.card.element_id.clone(), card))
            .collect())
    }

    /// Load and render the whole book, refreshing the cache with it.
    pub async fn render_all(&self) -> Result<Vec<RenderedCard>> {
        let _guard = self.write.lock().await;
        self.reload_locked().await.map(|(_, rendered)| rendered)
    }

    /// Apply the `Contact` events of one event batch: reload created and
    /// updated contacts, drop deleted ones. Events of another contact
    /// list than the loaded book's are ignored. A contact that does not
    /// decrypt keeps its row and counts as skipped. A failed reload
    /// marks the book stale instead of failing the batch.
    pub async fn apply_batch(&self, batch: &EventBatch) -> ContactEventReport {
        let actions = contact_events(batch);
        let mut report = ContactEventReport {
            events: actions.len(),
            ..ContactEventReport::default()
        };
        if actions.is_empty() {
            return report;
        }
        let _guard = self.write.lock().await;
        let list_id = match self.store().contact_book(self.account_id).await {
            Ok(book) => book.list_id,
            Err(_) => {
                self.mark_stale();
                report.failed = true;
                return report;
            }
        };
        let mut upserts = Vec::new();
        let mut removals = Vec::new();
        for (list, element, action) in actions {
            if list_id.as_deref().is_some_and(|known| known != list) {
                continue;
            }
            match action {
                ContactEventAction::Remove => removals.push(element),
                ContactEventAction::Refresh => match self.source.contact(&list, &element).await {
                    Ok(ContactLookup::Found(card)) => {
                        upserts.push(RenderedCard::new(*card).entry())
                    }
                    Ok(ContactLookup::Gone) => removals.push(element),
                    // Still there, just not readable now: keep the row.
                    Ok(ContactLookup::Undecryptable) => report.skipped += 1,
                    Err(_) => {
                        self.mark_stale();
                        report.failed = true;
                        return report;
                    }
                },
            }
        }
        match self
            .store()
            .update_contacts(self.account_id, &upserts, &removals)
            .await
        {
            Ok(counts) => report.counts = counts,
            Err(_) => {
                self.mark_stale();
                report.failed = true;
            }
        }
        report
    }
}
