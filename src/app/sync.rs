use std::sync::Arc;

use crate::domain::Result;
use crate::ports::mail_source::MailSource;
use crate::ports::state_store::StateStore;

/// Outcome of a metadata-only sync.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncReport {
    pub folders: usize,
    pub messages: usize,
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
    /// id. Repeating a sync with the same `uidvalidity` keeps existing UIDs.
    pub async fn sync(
        &self,
        account_id: i64,
        source: &dyn MailSource,
        uidvalidity: u32,
    ) -> Result<SyncReport> {
        let folders = source.folders().await?;
        let mut messages = 0;

        for folder in &folders {
            let mailbox = self
                .store
                .upsert_mailbox(account_id, folder, uidvalidity)
                .await?;
            let page = source.headers_page(folder, None, usize::MAX).await?;
            for header in &page.headers {
                self.store.assign_uid(mailbox, header).await?;
                messages += 1;
            }
        }

        Ok(SyncReport {
            folders: folders.len(),
            messages,
        })
    }
}
