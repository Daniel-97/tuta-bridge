use std::collections::HashSet;
use std::sync::Arc;

use crate::domain::{Error, Result};
use crate::ports::mail_source::MailSource;
use crate::ports::state_store::StateStore;

/// Outcome of a metadata-only sync.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncReport {
    /// Folders that synced successfully.
    pub folders: usize,
    /// Headers assigned a UID during this run.
    pub messages: usize,
    /// Stored messages removed because they are gone from their folder.
    pub removed: usize,
    /// Individual headers the source reported as unreadable.
    pub skipped_messages: usize,
    /// Folders skipped because their header page could not be loaded.
    pub skipped_folders: usize,
}

/// Assigns stable UIDs to mail headers without fetching message bodies.
pub struct SyncEngine {
    pub store: Arc<dyn StateStore>,
}

impl SyncEngine {
    pub fn new(store: Arc<dyn StateStore>) -> Self {
        Self { store }
    }

    /// Sync every folder exposed by `source`.
    ///
    /// Mailboxes are upserted first, then all headers are requested in one
    /// page per folder and each header is mapped to a UID by its Tuta element
    /// id. Headers are processed oldest-first so new UIDs grow with arrival
    /// time. Stored messages missing from a complete page are removed, which
    /// reconciles deletions and moves out of the folder. Repeating a sync with
    /// the same `uidvalidity` keeps existing UIDs.
    ///
    /// A folder whose headers cannot be loaded is skipped and counted. If
    /// every folder is skipped the sync fails instead of reporting success.
    pub async fn sync(
        &self,
        account_id: i64,
        source: &dyn MailSource,
        uidvalidity: u32,
    ) -> Result<SyncReport> {
        let folders = source
            .folders()
            .await
            .map_err(|_| Error::Network("sync failed for all folders".into()))?;
        let mut messages = 0;
        let mut removed = 0;
        let mut skipped_messages = 0;
        let mut skipped_folders = 0;

        for folder in &folders {
            let mailbox = self
                .store
                .upsert_mailbox(account_id, folder, uidvalidity)
                .await?;
            let page = match source.headers_page(folder, None, usize::MAX).await {
                Ok(page) => page,
                Err(_) => {
                    skipped_folders += 1;
                    continue;
                }
            };
            skipped_messages += page.skipped;

            let mut headers = page.headers;
            // Tuta returns mails newest-first. UIDs must instead be handed out
            // in ascending arrival order, with the element id as a stable
            // tie-break for mails sharing a timestamp.
            headers.sort_by(|a, b| {
                a.received_at_ms
                    .cmp(&b.received_at_ms)
                    .then_with(|| a.element_id.cmp(&b.element_id))
            });

            let mut fetched = HashSet::with_capacity(headers.len());
            for header in &headers {
                self.store.assign_uid(mailbox, header).await?;
                messages += 1;
                fetched.insert((header.list_id.clone(), header.element_id.clone()));
            }

            // A page with skipped mails or a follow-up page is incomplete: its
            // absence is not evidence that a stored mail was deleted.
            if page.skipped == 0 && page.next_start.is_none() {
                for stored in self.store.messages(mailbox).await? {
                    let key = (stored.header.list_id, stored.header.element_id);
                    if !fetched.contains(&key) {
                        self.store.remove_message(mailbox, stored.uid).await?;
                        removed += 1;
                    }
                }
            }
        }

        if !folders.is_empty() && skipped_folders == folders.len() {
            return Err(Error::Network("sync failed for all folders".into()));
        }

        Ok(SyncReport {
            folders: folders.len() - skipped_folders,
            messages,
            removed,
            skipped_messages,
            skipped_folders,
        })
    }
}
