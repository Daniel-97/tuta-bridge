use std::sync::Arc;

use tutasdk::bindings::rest_client::RestClient;
use tutasdk::entities::generated::tutanota::{Mail, MailSet};
use tutasdk::{CustomId, GeneratedId, ListLoadDirection, LoggedInSdk};

use crate::domain::{Error, Folder, FolderKind, MessageContent, MessageSummary, Result};
use crate::ports::mail_source::MailSource;

/// Map a Tuta folder-type code to our [`FolderKind`]. Type 7 ("All") is skipped.
pub fn folder_kind(folder_type: i64) -> Option<FolderKind> {
    match folder_type {
        0 => Some(FolderKind::Custom),
        1 => Some(FolderKind::Inbox),
        2 => Some(FolderKind::Sent),
        3 => Some(FolderKind::Trash),
        4 => Some(FolderKind::Archive),
        5 => Some(FolderKind::Junk),
        6 => Some(FolderKind::Drafts),
        _ => None,
    }
}

/// Build a [`Folder`] from raw Tuta mail-set parts, skipping the "All" set.
pub fn folder_from_parts(list_id: &str, name: &str, folder_type: i64) -> Option<Folder> {
    let kind = folder_kind(folder_type)?;
    Some(Folder {
        list_id: list_id.to_string(),
        name: name.to_string(),
        kind,
    })
}

/// Build a [`MessageSummary`] from raw Tuta mail parts.
pub fn summary_from_parts(
    list_id: &str,
    element_id: &str,
    received_at_ms: i64,
    subject: &str,
    unread: bool,
) -> MessageSummary {
    MessageSummary {
        list_id: list_id.to_string(),
        element_id: element_id.to_string(),
        received_at_ms,
        subject: subject.to_string(),
        unread,
    }
}

/// Resolve a requested folder name (alias or custom name) case-insensitively.
pub fn resolve_folder<'a>(folders: &'a [Folder], requested: &str) -> Result<&'a Folder> {
    let requested = requested.trim();
    if let Some(kind) = FolderKind::from_alias(requested) {
        if let Some(folder) = folders.iter().find(|f| f.kind == kind) {
            return Ok(folder);
        }
    }
    if let Some(folder) = folders
        .iter()
        .find(|f| f.name.trim().eq_ignore_ascii_case(requested))
    {
        return Ok(folder);
    }
    Err(Error::FolderNotFound(requested.to_string()))
}

/// Tuta implementation of the mail source: lists folders and message summaries.
pub struct TutaMailSource {
    logged: Arc<LoggedInSdk>,
    // Used by Task 12/13 for content and attachments.
    #[allow(dead_code)]
    rest: Arc<dyn RestClient>,
}

impl TutaMailSource {
    pub fn new(logged: Arc<LoggedInSdk>, rest: Arc<dyn RestClient>) -> Self {
        Self { logged, rest }
    }
}

#[async_trait::async_trait]
impl MailSource for TutaMailSource {
    async fn folders(&self) -> Result<Vec<Folder>> {
        let mail_facade = self.logged.mail_facade();
        let mailbox = mail_facade
            .load_user_mailbox()
            .await
            .map_err(|_| Error::Network("failed to load mailbox".into()))?;
        let sets: Vec<MailSet> = mail_facade
            .get_crypto_entity_client()
            .load_range(
                &mailbox.mailSets.mailSets,
                &GeneratedId::min_id(),
                100,
                ListLoadDirection::ASC,
            )
            .await
            .map_err(|_| Error::Network("failed to load folders".into()))?;

        Ok(sets
            .iter()
            .filter_map(|set| folder_from_parts(set.entries.as_str(), &set.name, set.folderType))
            .collect())
    }

    async fn messages(&self, folder: &Folder, limit: usize) -> Result<Vec<MessageSummary>> {
        let mails: Vec<Mail> = self
            .logged
            .mail_facade()
            .get_crypto_entity_client()
            .load_range(
                &GeneratedId(folder.list_id.clone()),
                &CustomId(GeneratedId::max_id().to_string()),
                limit,
                ListLoadDirection::DESC,
            )
            .await
            .map_err(|_| Error::Network("failed to load messages".into()))?;

        Ok(mails
            .iter()
            .filter_map(|mail| {
                let id = mail._id.as_ref()?;
                Some(summary_from_parts(
                    id.list_id.as_str(),
                    id.element_id.as_str(),
                    mail.receivedDate.as_millis() as i64,
                    &mail.subject,
                    mail.unread,
                ))
            })
            .collect())
    }

    async fn content(&self, _message: &MessageSummary) -> Result<MessageContent> {
        Err(Error::Unsupported("message content not implemented".into()))
    }
}
