use std::collections::HashSet;
use std::sync::Arc;

use crate::domain::{Error, Folder, MailboxId, MessagePage, Result};
use crate::ports::mail_source::MailSource;
use crate::ports::state_store::StateStore;

/// Outcome of a metadata-only sync.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
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
    /// reconciles deletions and moves out of the folder. Repeating a sync
    /// keeps existing UIDs and UIDVALIDITY. After the folder loop, stored
    /// mailboxes missing from the source are removed together with their
    /// headers.
    ///
    /// A folder whose headers cannot be loaded is skipped and counted. If
    /// every folder is skipped the sync fails instead of reporting success.
    pub async fn sync(
        &self,
        account_id: i64,
        source: &dyn MailSource,
        uidvalidity: u32,
    ) -> Result<SyncReport> {
        let folders = load_folders(source).await?;
        let mut report = SyncReport::default();

        for folder in &folders {
            let mailbox = self
                .store
                .upsert_mailbox(account_id, folder, uidvalidity)
                .await?;
            match source.headers_page(folder, None, usize::MAX).await {
                Ok(page) => self.store_folder(mailbox, page, &mut report).await?,
                Err(_) => report.skipped_folders += 1,
            }
        }

        // Folders absent from a successful source listing were deleted on the
        // server, so their headers are dropped too. A failed `folders()` call
        // returns earlier and never reconciles.
        self.remove_missing_mailboxes(account_id, &folders).await?;

        if !folders.is_empty() && report.skipped_folders == folders.len() {
            return Err(all_folders_failed());
        }
        Ok(report)
    }

    /// Discard the account's index and rebuild it from `source`.
    ///
    /// The folder list and every folder's headers are loaded before
    /// anything is deleted: when the listing fails, or no folder at all
    /// can be loaded, the call fails with the stored index untouched
    /// instead of leaving it empty. Only then is the account reset and
    /// the loaded pages written, which restarts every UID sequence under
    /// a fresh UIDVALIDITY. A folder whose page could not be loaded is
    /// created empty and counted, exactly as in [`Self::sync`].
    pub async fn resync(
        &self,
        account_id: i64,
        source: &dyn MailSource,
        uidvalidity: u32,
    ) -> Result<SyncReport> {
        let folders = load_folders(source).await?;
        let mut pages = Vec::with_capacity(folders.len());
        for folder in &folders {
            pages.push(source.headers_page(folder, None, usize::MAX).await.ok());
        }
        if !folders.is_empty() && pages.iter().all(Option::is_none) {
            return Err(all_folders_failed());
        }

        self.store.reset_account(account_id).await?;
        let mut report = SyncReport::default();
        for (folder, page) in folders.iter().zip(pages) {
            let mailbox = self
                .store
                .upsert_mailbox(account_id, folder, uidvalidity)
                .await?;
            match page {
                Some(page) => self.store_folder(mailbox, page, &mut report).await?,
                None => report.skipped_folders += 1,
            }
        }
        Ok(report)
    }

    /// Store one loaded folder page and add its counts to `report`.
    async fn store_folder(
        &self,
        mailbox: MailboxId,
        page: MessagePage,
        report: &mut SyncReport,
    ) -> Result<()> {
        let mut headers = page.headers;
        // Tuta returns mails newest-first. UIDs must instead be handed out
        // in ascending arrival order, with the element id as a stable
        // tie-break for mails sharing a timestamp.
        headers.sort_by(|a, b| {
            a.received_at_ms
                .cmp(&b.received_at_ms)
                .then_with(|| a.element_id.cmp(&b.element_id))
        });

        // A page with skipped mails or a follow-up page is incomplete: its
        // absence is not evidence that a stored mail was deleted.
        let complete = page.skipped == 0 && page.next_start.is_none();
        // The whole page is stored as one unit, so a folder costs one
        // transaction rather than one per message.
        report.removed += self.store.store_page(mailbox, &headers, complete).await?;
        report.messages += headers.len();
        report.skipped_messages += page.skipped;
        report.folders += 1;
        Ok(())
    }

    /// Remove stored mailboxes that `folders` no longer lists and return
    /// their ids.
    async fn remove_missing_mailboxes(
        &self,
        account_id: i64,
        folders: &[Folder],
    ) -> Result<Vec<MailboxId>> {
        let source_lists: HashSet<&str> = folders
            .iter()
            .map(|folder| folder.list_id.as_str())
            .collect();
        let mut removed = Vec::new();
        for mailbox in self.store.mailboxes(account_id).await? {
            if !source_lists.contains(mailbox.list_id.as_str()) {
                self.store.remove_mailbox(account_id, mailbox.id).await?;
                removed.push(mailbox.id);
            }
        }
        Ok(removed)
    }
}

/// The source's folder list; a failed listing fails the whole run.
async fn load_folders(source: &dyn MailSource) -> Result<Vec<Folder>> {
    source.folders().await.map_err(|_| all_folders_failed())
}

fn all_folders_failed() -> Error {
    Error::Network("sync failed for all folders".into())
}
