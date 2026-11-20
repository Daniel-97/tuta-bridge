//! Reload Tuta entities referenced by websocket events.
//!
//! Event frames only carry ids and operations; the processor needs the
//! current metadata behind them. This adapter reloads the affected `Mail`,
//! the `MailSet`s the mail belongs to (for its placements), the
//! `MailSetEntry` and its `Mail`, and `MailSet` folders through the SDK's
//! decryption path and maps them to domain placements and folders. It is
//! metadata-only: `MailDetails`, blobs, attachments, and bodies are never
//! loaded.
//!
//! Every SDK failure maps to one fixed [`Error::Network`] message: ids,
//! subjects, and addresses never appear in errors or logs.

use std::collections::HashSet;
use std::sync::Arc;

use tutasdk::entities::generated::tutanota::{Mail, MailSet, MailSetEntry};
use tutasdk::rest_error::HttpError;
use tutasdk::{ApiCallError, CustomId, GeneratedId, IdTupleCustom, IdTupleGenerated, LoggedInSdk};

use super::content::mail_is_intact;
use super::mail_source::{folder_from_parts, header_from_parts};
use crate::domain::{Error, Folder, MailPlacement, Result};
use crate::ports::event_lookup::EventLookup;

/// Keep the first placement per `mailbox_list_id`.
///
/// Tuta can report the same mailbox placement twice when the mail is
/// associated with several sets resolving to one folder; the processor
/// treats each `mailbox_list_id` as one placement.
fn dedupe_placements(placements: Vec<MailPlacement>) -> Vec<MailPlacement> {
    let mut seen: HashSet<String> = HashSet::with_capacity(placements.len());
    let mut deduped = Vec::with_capacity(placements.len());
    for placement in placements {
        if seen.insert(placement.mailbox_list_id.clone()) {
            deduped.push(placement);
        }
    }
    deduped
}

/// The fixed error for every SDK load failure; carries no entity data.
fn entity_unavailable() -> Error {
    Error::Network("event entity unavailable".into())
}

/// Classify one SDK load: `Ok(None)` when the server answers that the
/// entity does not exist, the fixed network error for every other failure.
///
/// A replayed batch (after downtime, or within one busy batch) routinely
/// references mails, entries, and sets that were deleted afterwards. That
/// is a definitive answer, not a lookup failure: counting it as one makes
/// the processor believe the index desynced and triggers a full resync.
/// The caller reports such an entity as absent, which keeps the existing
/// rows; the entity's own delete event removes them.
fn found<T>(loaded: std::result::Result<T, ApiCallError>) -> Result<Option<T>> {
    match loaded {
        Ok(entity) => Ok(Some(entity)),
        Err(ApiCallError::ServerResponseError {
            source: HttpError::NotFoundError,
        }) => Ok(None),
        Err(_) => Err(entity_unavailable()),
    }
}

/// Tuta implementation of [`EventLookup`].
pub struct TutaEventLookup {
    logged: Arc<LoggedInSdk>,
}

impl TutaEventLookup {
    pub fn new(logged: Arc<LoggedInSdk>) -> Self {
        Self { logged }
    }
}

#[async_trait::async_trait]
impl EventLookup for TutaEventLookup {
    async fn headers_for_mail(
        &self,
        mail_list_id: &str,
        mail_element_id: &str,
    ) -> Result<Option<Vec<MailPlacement>>> {
        let crypto_client = self.logged.mail_facade().get_crypto_entity_client();
        let mail_id = IdTupleGenerated::new(
            GeneratedId(mail_list_id.to_string()),
            GeneratedId(mail_element_id.to_string()),
        );
        let Some(mail) = found::<Mail>(crypto_client.load(&mail_id).await)? else {
            return Ok(None);
        };

        // An unreadable mail must keep its existing rows: report it as
        // unreadable instead of as "no placements". Without its own id the
        // header could not be keyed for later content reloads either.
        if !mail_is_intact(&mail) {
            return Ok(None);
        }
        let Some(mail_id) = mail._id.as_ref() else {
            return Ok(None);
        };

        // One failed placement set fails the whole mail: a partial list
        // could make the caller delete a placement that still exists.
        //
        // `Mail.sets` (field 1465) is a `ListElementAssociationGenerated`
        // to `MailSet` (refTypeId 429), NOT to `MailSetEntry`: each tuple
        // addresses a MailSet, whose `entries` value is the folder's
        // entries list id that resolves the mailbox row.
        let mut placements = Vec::with_capacity(mail.sets.len());
        for set_id in &mail.sets {
            // A set that vanished between the event and this lookup means
            // the mail is being moved: report the mail as absent (rows
            // kept) rather than guess a partial placement list.
            let Some(set) = found::<MailSet>(crypto_client.load(set_id).await)? else {
                return Ok(None);
            };
            let mailbox_list_id = set.entries.as_str();
            if mailbox_list_id.is_empty() {
                continue;
            }
            if let Some(header) = header_from_parts(
                mail_id.list_id.as_str(),
                mail_element_id,
                mail.receivedDate.as_millis() as i64,
                &mail.subject,
                &mail.sender,
                mail.firstRecipient.as_ref(),
                mail.unread,
            ) {
                placements.push(MailPlacement {
                    mailbox_list_id: mailbox_list_id.to_string(),
                    header,
                });
            }
        }

        // An empty result means the mail genuinely has no placements.
        Ok(Some(dedupe_placements(placements)))
    }

    async fn header_for_entry(
        &self,
        entry_list_id: &str,
        entry_element_id: &str,
    ) -> Result<Option<MailPlacement>> {
        let crypto_client = self.logged.mail_facade().get_crypto_entity_client();
        let entry_id = IdTupleCustom::new(
            GeneratedId(entry_list_id.to_string()),
            CustomId(entry_element_id.to_string()),
        );
        let Some(entry) = found::<MailSetEntry>(crypto_client.load(&entry_id).await)? else {
            return Ok(None);
        };

        let Some(mail) = found::<Mail>(crypto_client.load(&entry.mail).await)? else {
            return Ok(None);
        };
        if !mail_is_intact(&mail) {
            return Ok(None);
        }
        let Some(mail_id) = mail._id.as_ref() else {
            return Ok(None);
        };

        // The mailbox is the entry's list (the folder.entries list); the
        // header's ids are the Mail's own ids, never the entry's, so later
        // content reloads can find the mail by `messages.tuta_list_id`.
        Ok(header_from_parts(
            mail_id.list_id.as_str(),
            mail_id.element_id.as_str(),
            mail.receivedDate.as_millis() as i64,
            &mail.subject,
            &mail.sender,
            mail.firstRecipient.as_ref(),
            mail.unread,
        )
        .map(|header| MailPlacement {
            mailbox_list_id: entry_list_id.to_string(),
            header,
        }))
    }

    async fn folder(&self, set_list_id: &str, set_element_id: &str) -> Result<Option<Folder>> {
        let crypto_client = self.logged.mail_facade().get_crypto_entity_client();
        let set_id = IdTupleGenerated::new(
            GeneratedId(set_list_id.to_string()),
            GeneratedId(set_element_id.to_string()),
        );
        let Some(set) = found::<MailSet>(crypto_client.load(&set_id).await)? else {
            return Ok(None);
        };
        Ok(folder_from_parts(
            set.entries.as_str(),
            &set.name,
            set.folderType,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{Address, MessageHeader};

    fn header(list_id: &str, element_id: &str) -> MessageHeader {
        MessageHeader {
            list_id: list_id.to_string(),
            element_id: element_id.to_string(),
            received_at_ms: 0,
            sent_at_ms: 0,
            subject: String::new(),
            from: Address {
                name: None,
                address: String::new(),
            },
            to: Vec::new(),
            cc: Vec::new(),
            bcc: Vec::new(),
            reply_to: Vec::new(),
            unread: false,
            message_id: None,
            in_reply_to: None,
            references: Vec::new(),
            envelope_complete: false,
        }
    }

    /// Build a placement: `mailbox_list_id` resolves the mailbox (the
    /// folder's entries list), while the header keeps the Mail's own ids.
    fn placement(mailbox_list_id: &str, mail_list_id: &str, element_id: &str) -> MailPlacement {
        MailPlacement {
            mailbox_list_id: mailbox_list_id.to_string(),
            header: header(mail_list_id, element_id),
        }
    }

    #[test]
    fn a_deleted_entity_is_absent_not_a_lookup_failure() {
        let gone: std::result::Result<u8, ApiCallError> = Err(ApiCallError::ServerResponseError {
            source: HttpError::NotFoundError,
        });
        assert!(matches!(found(gone), Ok(None)));
        assert!(matches!(found(Ok::<u8, ApiCallError>(7)), Ok(Some(7))));
    }

    #[test]
    fn every_other_load_failure_stays_a_network_error() {
        for error in [
            ApiCallError::ServerResponseError {
                source: HttpError::NotAuthorizedError,
            },
            ApiCallError::ServerResponseError {
                source: HttpError::InternalServerError,
            },
            ApiCallError::InternalSdkError {
                error_message: "SECRET".into(),
            },
        ] {
            let Err(mapped) = found::<u8>(Err(error)) else {
                panic!("expected an error")
            };
            assert_eq!(
                mapped.to_string(),
                "network error: event entity unavailable"
            );
        }
    }

    #[test]
    fn deduplicates_placements_for_the_same_mailbox() {
        let placements = dedupe_placements(vec![
            placement("list-a", "mail-list", "m1"),
            placement("list-a", "mail-list", "m1"),
            placement("list-b", "mail-list", "m1"),
        ]);
        assert_eq!(placements.len(), 2);
        assert_eq!(placements[0].mailbox_list_id, "list-a");
        assert_eq!(placements[1].mailbox_list_id, "list-b");
    }

    #[test]
    fn dedupe_keeps_the_first_placement_of_each_mailbox() {
        let placements = dedupe_placements(vec![
            placement("list-a", "mail-list", "first"),
            placement("list-a", "mail-list", "second"),
        ]);
        assert_eq!(placements.len(), 1);
        assert_eq!(placements[0].header.element_id, "first");
    }

    #[test]
    fn empty_placement_list_stays_empty() {
        assert!(dedupe_placements(Vec::new()).is_empty());
    }
}
