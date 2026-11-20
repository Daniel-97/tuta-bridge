use std::sync::Arc;

use tutasdk::entities::generated::tutanota::{DeleteMailData, MailSet, MoveMailData};
use tutasdk::services::generated::tutanota::{MailService, MoveMailService};
use tutasdk::services::ExtraServiceParams;
use tutasdk::{GeneratedId, IdTupleGenerated, ListLoadDirection, LoggedInSdk};

use crate::domain::{Error, Result};
use crate::ports::mailbox_writer::{MailRef, MailboxWriter};

/// The SDK's own per-request limit for mail updates
/// (`MAX_MAIL_UPDATE_LIMIT` in `mail_facade.rs`): larger requests answer
/// HTTP 400.
const MAIL_UPDATE_LIMIT: usize = 50;

fn write_failed() -> Error {
    Error::Network("mailbox write failed".into())
}

fn id_tuples(mails: &[MailRef]) -> Vec<IdTupleGenerated> {
    let mut seen = std::collections::HashSet::new();
    mails
        .iter()
        .filter(|mail| seen.insert((mail.list_id.as_str(), mail.element_id.as_str())))
        .map(|mail| {
            IdTupleGenerated::new(
                GeneratedId(mail.list_id.clone()),
                GeneratedId(mail.element_id.clone()),
            )
        })
        .collect()
}

/// Resolve a folder's `MailSet` id from its `entries` list id.
///
/// The store addresses a folder by its `entries` list (where its
/// `MailSetEntry` rows live); the move and delete services want the
/// `MailSet` element itself. Sets with an empty `entries` value or no id
/// never match.
pub fn mail_set_for_entries<'a, I>(sets: I, entries: &str) -> Option<IdTupleGenerated>
where
    I: IntoIterator<Item = (&'a str, Option<&'a IdTupleGenerated>)>,
{
    if entries.is_empty() {
        return None;
    }
    sets.into_iter()
        .find(|(set_entries, id)| {
            !set_entries.is_empty() && *set_entries == entries && id.is_some()
        })
        .and_then(|(_, id)| id.cloned())
}

/// [`MailboxWriter`] over the logged-in Tuta SDK.
pub struct TutaMailboxWriter {
    logged: Arc<LoggedInSdk>,
}

impl TutaMailboxWriter {
    pub fn new(logged: Arc<LoggedInSdk>) -> Self {
        Self { logged }
    }

    /// Load the mailbox's mail sets (folders and labels, a handful of
    /// rows) and resolve the one owning `entries`.
    async fn mail_set(&self, entries: &str) -> Result<IdTupleGenerated> {
        let mail_facade = self.logged.mail_facade();
        let mailbox = mail_facade
            .load_user_mailbox()
            .await
            .map_err(|_| write_failed())?;
        let sets: Vec<MailSet> = mail_facade
            .get_crypto_entity_client()
            .load_all(&mailbox.mailSets.mailSets, ListLoadDirection::ASC)
            .await
            .map_err(|_| write_failed())?;
        mail_set_for_entries(
            sets.iter()
                .map(|set| (set.entries.as_str(), set._id.as_ref())),
            entries,
        )
        .ok_or_else(|| Error::Network("mailbox write failed: folder not found".into()))
    }
}

#[async_trait::async_trait]
impl MailboxWriter for TutaMailboxWriter {
    async fn set_unread(&self, mails: &[MailRef], unread: bool) -> Result<()> {
        if mails.is_empty() {
            return Ok(());
        }
        self.logged
            .mail_facade()
            .set_unread_status_for_mails(id_tuples(mails), unread)
            .await
            .map_err(|_| write_failed())
    }

    async fn move_to_folder(&self, target_folder_entries: &str, mails: &[MailRef]) -> Result<()> {
        if mails.is_empty() {
            return Ok(());
        }
        let target = self.mail_set(target_folder_entries).await?;
        let executor = self.logged.get_service_executor();
        for chunk in id_tuples(mails).chunks(MAIL_UPDATE_LIMIT) {
            executor
                .post::<MoveMailService>(
                    MoveMailData {
                        _format: 0,
                        moveReason: None,
                        targetFolder: target.clone(),
                        mails: chunk.to_vec(),
                        excludeMailSet: None,
                    },
                    ExtraServiceParams::default(),
                )
                .await
                .map_err(|_| write_failed())?;
        }
        Ok(())
    }

    async fn move_to_trash(&self, mails: &[MailRef]) -> Result<()> {
        if mails.is_empty() {
            return Ok(());
        }
        self.logged
            .mail_facade()
            .trash_mails(id_tuples(mails))
            .await
            .map_err(|_| write_failed())
    }

    async fn delete_permanently(&self, folder_entries: &str, mails: &[MailRef]) -> Result<()> {
        if mails.is_empty() {
            return Ok(());
        }
        let folder = self.mail_set(folder_entries).await?;
        let executor = self.logged.get_service_executor();
        for chunk in id_tuples(mails).chunks(MAIL_UPDATE_LIMIT) {
            executor
                .delete::<MailService>(
                    DeleteMailData {
                        _format: 0,
                        mails: chunk.to_vec(),
                        folder: Some(folder.clone()),
                    },
                    ExtraServiceParams::default(),
                )
                .await
                .map_err(|_| write_failed())?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(list: &str, element: &str) -> IdTupleGenerated {
        IdTupleGenerated::new(GeneratedId(list.into()), GeneratedId(element.into()))
    }

    #[test]
    fn resolves_the_mail_set_by_entries_list() {
        let a = id("sets", "a");
        let b = id("sets", "b");
        let empty = id("sets", "e");
        let sets = vec![
            ("entries-a", Some(&a)),
            ("", Some(&empty)),
            ("entries-b", Some(&b)),
            ("entries-c", None),
        ];
        assert!(mail_set_for_entries(sets.clone(), "entries-b") == Some(b.clone()));
        assert!(mail_set_for_entries(sets.clone(), "").is_none());
        assert!(mail_set_for_entries(sets.clone(), "entries-c").is_none());
        assert!(mail_set_for_entries(sets, "nope").is_none());
    }

    #[test]
    fn duplicate_mails_are_sent_once() {
        let mail = MailRef {
            list_id: "l".into(),
            element_id: "e".into(),
        };
        assert_eq!(id_tuples(&[mail.clone(), mail]).len(), 1);
    }
}
