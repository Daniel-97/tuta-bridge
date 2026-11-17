//! Reload Tuta entities referenced by websocket events.
//!
//! Event frames only carry ids and operations; the processor needs the
//! current metadata behind them. This adapter reloads the affected `Mail`,
//! `MailSetEntry`, and `MailSet` through the SDK's decryption path and maps
//! them to domain headers and folders. It is metadata-only: `MailDetails`,
//! blobs, attachments, and bodies are never loaded.
//!
//! Every SDK failure maps to one fixed [`Error::Network`] message: ids,
//! subjects, and addresses never appear in errors or logs.

use std::collections::HashSet;
use std::sync::Arc;

use tutasdk::entities::generated::tutanota::{Mail, MailSet, MailSetEntry};
use tutasdk::{CustomId, GeneratedId, IdTupleCustom, IdTupleGenerated, LoggedInSdk};

use super::content::mail_is_intact;
use super::mail_source::{folder_from_parts, header_from_parts};
use crate::domain::{Error, Folder, MessageHeader, Result};
use crate::ports::event_lookup::EventLookup;

/// Keep the first header per `list_id`.
///
/// Tuta can report the same mailbox placement twice when several
/// `MailSetEntry` rows resolve to one folder; the processor treats each
/// `list_id` as one placement.
fn dedupe_placements(headers: Vec<MessageHeader>) -> Vec<MessageHeader> {
    let mut seen: HashSet<String> = HashSet::with_capacity(headers.len());
    let mut deduped = Vec::with_capacity(headers.len());
    for header in headers {
        if seen.insert(header.list_id.clone()) {
            deduped.push(header);
        }
    }
    deduped
}

/// The fixed error for every SDK load failure; carries no entity data.
fn entity_unavailable() -> Error {
    Error::Network("event entity unavailable".into())
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
    ) -> Result<Option<Vec<MessageHeader>>> {
        let crypto_client = self.logged.mail_facade().get_crypto_entity_client();
        let mail_id = IdTupleGenerated::new(
            GeneratedId(mail_list_id.to_string()),
            GeneratedId(mail_element_id.to_string()),
        );
        let mail: Mail = crypto_client
            .load(&mail_id)
            .await
            .map_err(|_| entity_unavailable())?;

        // An unreadable mail must keep its existing rows: report it as
        // unreadable instead of as "no placements".
        if !mail_is_intact(&mail) {
            return Ok(None);
        }

        // One failed placement entry fails the whole mail: a partial list
        // could make the caller delete a placement that still exists.
        let mut headers = Vec::with_capacity(mail.sets.len());
        for entry_id in &mail.sets {
            let entry: MailSetEntry = crypto_client
                .load(entry_id)
                .await
                .map_err(|_| entity_unavailable())?;
            let Some(entry_id) = entry._id.as_ref() else {
                continue;
            };
            if let Some(header) = header_from_parts(
                entry_id.list_id.as_str(),
                mail_element_id,
                mail.receivedDate.as_millis() as i64,
                &mail.subject,
                &mail.sender,
                mail.firstRecipient.as_ref(),
                mail.unread,
            ) {
                headers.push(header);
            }
        }

        // An empty result means the mail genuinely has no placements.
        Ok(Some(dedupe_placements(headers)))
    }

    async fn header_for_entry(
        &self,
        entry_list_id: &str,
        entry_element_id: &str,
    ) -> Result<Option<MessageHeader>> {
        let crypto_client = self.logged.mail_facade().get_crypto_entity_client();
        let entry_id = IdTupleCustom::new(
            GeneratedId(entry_list_id.to_string()),
            CustomId(entry_element_id.to_string()),
        );
        let entry: MailSetEntry = crypto_client
            .load(&entry_id)
            .await
            .map_err(|_| entity_unavailable())?;

        let mail: Mail = crypto_client
            .load(&entry.mail)
            .await
            .map_err(|_| entity_unavailable())?;
        if !mail_is_intact(&mail) {
            return Ok(None);
        }
        let Some(mail_id) = mail._id.as_ref() else {
            return Ok(None);
        };

        // The entry's list id is the mailbox (folder.entries list), not the
        // mail's own list id.
        Ok(header_from_parts(
            entry_list_id,
            mail_id.element_id.as_str(),
            mail.receivedDate.as_millis() as i64,
            &mail.subject,
            &mail.sender,
            mail.firstRecipient.as_ref(),
            mail.unread,
        ))
    }

    async fn folder(&self, set_list_id: &str, set_element_id: &str) -> Result<Option<Folder>> {
        let crypto_client = self.logged.mail_facade().get_crypto_entity_client();
        let set_id = IdTupleGenerated::new(
            GeneratedId(set_list_id.to_string()),
            GeneratedId(set_element_id.to_string()),
        );
        let set: MailSet = crypto_client
            .load(&set_id)
            .await
            .map_err(|_| entity_unavailable())?;
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
    use crate::domain::Address;

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

    #[test]
    fn deduplicates_headers_for_the_same_mailbox() {
        let headers = dedupe_placements(vec![
            header("list-a", "m1"),
            header("list-a", "m1"),
            header("list-b", "m1"),
        ]);
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0].list_id, "list-a");
        assert_eq!(headers[1].list_id, "list-b");
    }

    #[test]
    fn dedupe_keeps_the_first_header_of_each_mailbox() {
        let headers =
            dedupe_placements(vec![header("list-a", "first"), header("list-a", "second")]);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].element_id, "first");
    }

    #[test]
    fn empty_placement_list_stays_empty() {
        assert!(dedupe_placements(Vec::new()).is_empty());
    }
}
