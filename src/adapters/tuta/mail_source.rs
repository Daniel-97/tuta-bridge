use std::sync::Arc;

use serde_json::Value;
use tutasdk::bindings::rest_client::RestClient;
use tutasdk::crypto::crypto_facade::ResolvedSessionKey;
use tutasdk::entities::generated::tutanota::{
    Mail, MailAddress, MailDetails, MailDetailsDraft, MailSet, MailSetEntry,
};
use tutasdk::entities::Entity;
use tutasdk::{CustomId, GeneratedId, IdTupleGenerated, ListLoadDirection, LoggedInSdk};

use super::blob::{fetch_blob_element, load_attachment, request_archive_read_token};
use super::content::{
    address_from_encrypted, address_from_mail_address, draft_details_are_intact, from_address,
    mail_is_intact, parse_headers, select_body, sent_at_from, threading_headers,
};
use super::wire::decrypt_mail_details;
use crate::domain::{
    Error, Folder, FolderKind, MessageContent, MessageHeader, MessagePage, MessageSummary, Result,
};
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
///
/// System MailSets carry an empty `name` on the server, so the kind's default
/// display name is used instead. A custom set with an empty name cannot be
/// addressed and is skipped.
pub fn folder_from_parts(list_id: &str, name: &str, folder_type: i64) -> Option<Folder> {
    let kind = folder_kind(folder_type)?;
    let name = if name.trim().is_empty() {
        if kind == FolderKind::Custom {
            return None;
        }
        kind.default_name()
    } else {
        name
    };
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

/// Build a [`MessageHeader`] from raw Tuta mail-list parts.
///
/// Only metadata available on the `Mail` list entity is mapped. Details that
/// require decrypting the mail body (`sent` date, threading headers, cc/bcc,
/// reply-to) stay empty and `envelope_complete` is `false`. Returns `None`
/// when the mail has no element id and therefore cannot be referenced.
pub fn header_from_parts(
    list_id: &str,
    element_id: &str,
    received_at_ms: i64,
    subject: &str,
    sender: &MailAddress,
    first_recipient: Option<&MailAddress>,
    unread: bool,
) -> Option<MessageHeader> {
    if element_id.is_empty() {
        return None;
    }

    Some(MessageHeader {
        list_id: list_id.to_string(),
        element_id: element_id.to_string(),
        received_at_ms,
        sent_at_ms: 0,
        subject: subject.to_string(),
        from: address_from_mail_address(sender),
        to: first_recipient
            .map(address_from_mail_address)
            .into_iter()
            .collect(),
        cc: Vec::new(),
        bcc: Vec::new(),
        reply_to: Vec::new(),
        unread,
        message_id: None,
        in_reply_to: None,
        references: Vec::new(),
        envelope_complete: false,
    })
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
    rest: Arc<dyn RestClient>,
    access_token: String,
    base_url: String,
}

impl TutaMailSource {
    pub fn new(
        logged: Arc<LoggedInSdk>,
        rest: Arc<dyn RestClient>,
        access_token: String,
        base_url: String,
    ) -> Self {
        Self {
            logged,
            rest,
            access_token,
            base_url,
        }
    }

    /// Resolve the session key for a mail's owner-group encryption.
    async fn resolve_mail_session_key(&self, mail: &Mail) -> Result<ResolvedSessionKey> {
        let parsed = self
            .logged
            .instance_mapper
            .serialize_entity(mail.clone())
            .map_err(|_| Error::Message("mail details unavailable".into()))?;
        let model = self
            .logged
            .type_model_provider
            .resolve_server_type_ref(&Mail::type_ref())
            .ok_or_else(|| Error::Message("mail details unavailable".into()))?;
        self.logged
            .mail_facade()
            .get_crypto_entity_client()
            .get_crypto_facade()
            .resolve_session_key(&parsed, &model)
            .await
            .map_err(|_| Error::Message("mail details unavailable".into()))?
            .ok_or_else(|| Error::Message("mail details unavailable".into()))
    }

    /// Fetch and parse a `MailDetailsBlob` wire object from the blob server.
    async fn load_blob_element(&self, details_id: &IdTupleGenerated) -> Result<Value> {
        let access = request_archive_read_token(
            self.rest.as_ref(),
            &self.base_url,
            &self.access_token,
            details_id.list_id.as_str(),
        )
        .await?;
        let server = access
            .servers
            .first()
            .cloned()
            .ok_or_else(|| Error::Message("mail details server unavailable".into()))?;
        let bytes = fetch_blob_element(
            self.rest.as_ref(),
            &server,
            details_id.list_id.as_str(),
            details_id.element_id.as_str(),
            &access.blob_access_token,
            &self.access_token,
        )
        .await?;
        serde_json::from_slice(&bytes)
            .map_err(|_| Error::Message("mail details parse failed".into()))
    }

    /// Load the [`MailDetails`] for a mail, preferring the draft details and
    /// decrypting a blob element with the mail's session key otherwise.
    async fn load_details(&self, mail: &Mail) -> Result<MailDetails> {
        let crypto_client = self.logged.mail_facade().get_crypto_entity_client();

        if let Some(draft_id) = &mail.mailDetailsDraft {
            let draft: MailDetailsDraft = crypto_client
                .load(draft_id)
                .await
                .map_err(|_| Error::Message("draft details load failed".into()))?;
            if !draft_details_are_intact(&draft) {
                return Err(Error::Message("draft details corrupted".into()));
            }
            return Ok(draft.details);
        }

        let Some(details_id) = &mail.mailDetails else {
            return Err(Error::Message("message has no details".into()));
        };

        let raw = self.load_blob_element(details_id).await?;
        let blob = raw
            .as_array()
            .and_then(|items| items.first())
            .unwrap_or(&raw);
        let key = self
            .resolve_mail_session_key(mail)
            .await
            .map_err(|_| Error::Message("mail details key unavailable".into()))?;
        decrypt_mail_details(blob, &key.session_key)
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
        let crypto_client = self.logged.mail_facade().get_crypto_entity_client();
        // A mail set's `entries` list contains MailSetEntry elements, each of
        // which references the actual Mail. Loading Mail directly from that
        // list returns an empty page.
        let entries: Vec<MailSetEntry> = crypto_client
            .load_range(
                &GeneratedId(folder.list_id.clone()),
                &CustomId(GeneratedId::max_id().to_string()),
                limit,
                ListLoadDirection::DESC,
            )
            .await
            .map_err(|_| Error::Network("failed to load message entries".into()))?;

        let mut mails = Vec::with_capacity(entries.len());
        for entry in entries {
            let mail: Mail = crypto_client
                .load(&entry.mail)
                .await
                .map_err(|_| Error::Network("failed to load message".into()))?;
            mails.push(mail);
        }

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

    async fn headers_page(
        &self,
        folder: &Folder,
        _start: Option<&str>,
        _limit: usize,
    ) -> Result<MessagePage> {
        let crypto_client = self.logged.mail_facade().get_crypto_entity_client();
        // M3 loads every entry in the folder. `start` and `limit` are accepted
        // for a later paginated implementation and intentionally ignored.
        let entries: Vec<MailSetEntry> = crypto_client
            .load_all(
                &GeneratedId(folder.list_id.clone()),
                ListLoadDirection::DESC,
            )
            .await
            .map_err(|_| Error::Network("failed to load message entries".into()))?;

        let mut headers = Vec::with_capacity(entries.len());
        let mut skipped = 0;
        for entry in entries {
            // One unreadable mail must not fail the whole folder: count it and
            // keep loading the remaining headers.
            let mail: Mail = match crypto_client.load(&entry.mail).await {
                Ok(mail) => mail,
                Err(_) => {
                    skipped += 1;
                    continue;
                }
            };
            let Some(id) = mail._id.as_ref() else {
                continue;
            };
            if let Some(header) = header_from_parts(
                id.list_id.as_str(),
                id.element_id.as_str(),
                mail.receivedDate.as_millis() as i64,
                &mail.subject,
                &mail.sender,
                mail.firstRecipient.as_ref(),
                mail.unread,
            ) {
                headers.push(header);
            }
        }

        Ok(MessagePage {
            headers,
            next_start: None,
            skipped,
        })
    }

    async fn content(&self, message: &MessageSummary) -> Result<MessageContent> {
        let crypto_client = self.logged.mail_facade().get_crypto_entity_client();
        let mail_id = IdTupleGenerated::new(
            GeneratedId(message.list_id.clone()),
            GeneratedId(message.element_id.clone()),
        );
        let mail: Mail = crypto_client
            .load(&mail_id)
            .await
            .map_err(|_| Error::Message("mail details unavailable".into()))?;

        if !mail_is_intact(&mail) {
            return Err(Error::Message("mail content unavailable".into()));
        }

        let details = self.load_details(&mail).await?;

        let (body_html, body_text) = select_body(&details.body);

        let headers = details
            .headers
            .as_ref()
            .and_then(|header| {
                header
                    .compressedHeaders
                    .as_deref()
                    .filter(|raw| !raw.is_empty())
                    .or_else(|| header.headers.as_deref().filter(|raw| !raw.is_empty()))
            })
            .map(parse_headers)
            .unwrap_or_default();
        let (message_id, in_reply_to, references) = threading_headers(&headers);

        let from = from_address(&mail);

        let mut attachments = Vec::new();
        for attachment_id in &mail.attachments {
            match load_attachment(
                &self.logged,
                self.rest.as_ref(),
                &self.access_token,
                &self.base_url,
                attachment_id,
            )
            .await
            {
                Ok(attachment) => attachments.push(attachment),
                Err(e) => return Err(e),
            }
        }

        Ok(MessageContent {
            summary: message.clone(),
            from,
            to: details
                .recipients
                .toRecipients
                .iter()
                .map(address_from_mail_address)
                .collect(),
            cc: details
                .recipients
                .ccRecipients
                .iter()
                .map(address_from_mail_address)
                .collect(),
            bcc: details
                .recipients
                .bccRecipients
                .iter()
                .map(address_from_mail_address)
                .collect(),
            reply_to: details
                .replyTos
                .iter()
                .map(address_from_encrypted)
                .collect(),
            sent_at_ms: sent_at_from(
                &headers,
                details.sentDate.as_millis() as i64,
                message.received_at_ms,
            ),
            subject: mail.subject,
            message_id,
            in_reply_to,
            references,
            body_html,
            body_text,
            attachments,
        })
    }
}
