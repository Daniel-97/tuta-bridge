//! Pure mapping helpers for Tuta mail details: body selection, HTML detection,
//! header parsing, and address conversion.
//!
//! These functions are deliberately free of I/O so they can be unit-tested
//! without a live session or server.

use std::collections::HashMap;

use tutasdk::entities::generated::tutanota::{
    Body, EncryptedMailAddress, Mail, MailAddress, MailDetails, MailDetailsBlob, MailDetailsDraft,
    TutanotaFile,
};

use crate::domain::Address;

/// Choose the body text from a Tuta [`Body`], returning `(html, text)`.
///
/// The compressed variant is preferred when present and non-empty; the SDK
/// already decompresses it during mapping. The chosen string is classified as
/// HTML or plain text via [`looks_like_html`].
pub fn select_body(body: &Body) -> (Option<String>, Option<String>) {
    let source = body
        .compressedText
        .as_deref()
        .filter(|text| !text.is_empty())
        .or_else(|| body.text.as_deref().filter(|text| !text.is_empty()));

    let Some(source) = source else {
        return (None, None);
    };

    if looks_like_html(source) {
        (Some(source.to_string()), None)
    } else {
        (None, Some(source.to_string()))
    }
}

/// Heuristically decide whether `text` looks like an HTML document or fragment.
pub fn looks_like_html(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    ["<html", "<body", "<div", "<p", "<br", "<table", "<a "]
        .iter()
        .any(|needle| lower.contains(needle))
}

/// Parse a raw RFC 5322 header block into lower-cased header names and their
/// values. Folded continuation lines are joined to the previous value with a
/// single space, and repeated headers keep their order within each name.
pub fn parse_headers(raw: &str) -> HashMap<String, Vec<String>> {
    let mut headers: HashMap<String, Vec<String>> = HashMap::new();
    let mut last_name: Option<String> = None;

    for line in raw.lines() {
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some(name) = &last_name {
                if let Some(values) = headers.get_mut(name) {
                    if let Some(last) = values.last_mut() {
                        last.push(' ');
                        last.push_str(line.trim());
                    }
                }
            }
            continue;
        }

        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim().to_ascii_lowercase();
            headers
                .entry(name.clone())
                .or_default()
                .push(value.trim().to_string());
            last_name = Some(name);
        }
    }

    headers
}

/// Extract threading headers from a parsed header map as
/// `(message_id, in_reply_to, references)`. References are split on whitespace.
pub fn threading_headers(
    headers: &HashMap<String, Vec<String>>,
) -> (Option<String>, Option<String>, Vec<String>) {
    let first = |name: &str| headers.get(name).and_then(|values| values.first().cloned());

    let message_id = first("message-id");
    let in_reply_to = first("in-reply-to");
    let references = headers
        .get("references")
        .map(|values| {
            values
                .iter()
                .flat_map(|value| value.split_whitespace().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();

    (message_id, in_reply_to, references)
}

/// Convert a Tuta [`MailAddress`] into our [`Address`], dropping empty names.
pub fn address_from_mail_address(address: &MailAddress) -> Address {
    Address {
        name: (!address.name.is_empty()).then(|| address.name.clone()),
        address: address.address.clone(),
    }
}

/// Convert a Tuta [`EncryptedMailAddress`] into our [`Address`], dropping empty names.
pub fn address_from_encrypted(address: &EncryptedMailAddress) -> Address {
    Address {
        name: (!address.name.is_empty()).then(|| address.name.clone()),
        address: address.address.clone(),
    }
}

/// Extract the sent timestamp, in milliseconds since the Unix epoch, from
/// the `Date` header of a parsed header map.
///
/// The header name is matched case-insensitively: [`parse_headers`] already
/// lower-cases every name it stores, and this lookup folds ASCII case the
/// same way. All values stored for the name are joined with a space —
/// repeated `Date:` headers and the folded continuations [`parse_headers`]
/// has already collapsed — and the joined value is parsed as an RFC 5322
/// date with [`mail_parser::DateTime::parse_rfc822`], whose
/// `to_timestamp` applies the zone offset; the seconds are scaled to
/// milliseconds (RFC 5322 dates carry no sub-second precision). A missing
/// or malformed `Date` falls back to `sent_date_ms` when it is positive,
/// then to `received_ms` when it is positive, and yields 0 otherwise, so a
/// zeroed Tuta `sentDate` can never masquerade as a real date while mail
/// that arrives without a `Date:` header still gets the received time the
/// web client displays: Tuta stores external mail's real send time only in
/// the headers, with `MailDetails.sentDate` at 0.
pub fn sent_at_from(
    headers: &HashMap<String, Vec<String>>,
    sent_date_ms: i64,
    received_ms: i64,
) -> i64 {
    let joined = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("date"))
        .map(|(_, values)| values.join(" "))
        .unwrap_or_default();

    match mail_parser::DateTime::parse_rfc822(&joined) {
        Some(date) => date.to_timestamp() * 1000,
        None => {
            if sent_date_ms > 0 {
                sent_date_ms
            } else if received_ms > 0 {
                received_ms
            } else {
                0
            }
        }
    }
}

/// Decide whether a decrypted [`MailDetailsBlob`] is intact.
///
/// The SDK's `EntityFacadeImpl::decrypt_and_map_inner` does not return `Err`
/// when an encrypted value fails to decrypt: it records the failure in the
/// entity's `_errors` map and returns `Ok` with default (empty) values for the
/// affected fields. `parse_entity` then still succeeds, so a successful `load`
/// does not guarantee readable content. Every `_errors` map — top-level and
/// nested — must therefore be empty before the blob can be trusted.
pub fn details_are_intact(blob: &MailDetailsBlob) -> bool {
    blob._errors.is_empty() && mail_details_are_intact(&blob.details)
}

/// Decide whether a decrypted [`MailDetailsDraft`] is intact. Drafts own their
/// session key but carry `_errors` exactly like blobs do.
pub(crate) fn draft_details_are_intact(draft: &MailDetailsDraft) -> bool {
    draft._errors.is_empty() && mail_details_are_intact(&draft.details)
}

/// Check every nested `_errors` map inside [`MailDetails`] that can be
/// populated when a decryption fails.
fn mail_details_are_intact(details: &MailDetails) -> bool {
    if !details.body._errors.is_empty() {
        return false;
    }
    if details
        .headers
        .as_ref()
        .is_some_and(|header| !header._errors.is_empty())
    {
        return false;
    }
    let recipients = &details.recipients;
    if recipients
        .toRecipients
        .iter()
        .any(|a| !a._errors.is_empty())
        || recipients
            .ccRecipients
            .iter()
            .any(|a| !a._errors.is_empty())
        || recipients
            .bccRecipients
            .iter()
            .any(|a| !a._errors.is_empty())
    {
        return false;
    }
    details.replyTos.iter().all(|a| a._errors.is_empty())
}

/// Decide whether a decrypted [`TutanotaFile`] is intact.
///
/// The SDK reports per-field decryption failures in the entity's `_errors` map
/// and still returns `Ok` with default (empty) values, so a successful `load`
/// alone is not proof of intactness. A file is intact only when its `_errors`
/// map is empty and, whenever it declares a non-zero size, it carries at least
/// one blob. A non-zero size with no blobs means the blob list failed to
/// decrypt and defaulted to empty.
pub fn file_is_intact(file: &TutanotaFile) -> bool {
    file._errors.is_empty() && (file.size == 0 || !file.blobs.is_empty())
}

/// Decide whether a decrypted [`Mail`] entity is intact.
///
/// Like the details blob, the mail itself and its sender can carry `_errors`
/// when a field fails to decrypt while still deserializing successfully. Both
/// must be empty before the mail's content can be trusted.
pub fn mail_is_intact(mail: &Mail) -> bool {
    mail._errors.is_empty() && mail.sender._errors.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tutasdk::entities::generated::sys::Blob;
    use tutasdk::entities::generated::tutanota::{Header, Recipients};
    use tutasdk::entities::DateTime;
    use tutasdk::{GeneratedId, IdTupleGenerated};

    fn intact_body() -> Body {
        Body {
            _id: None,
            text: None,
            compressedText: None,
            _errors: Default::default(),
        }
    }

    fn intact_header() -> Header {
        Header {
            _id: None,
            headers: None,
            compressedHeaders: None,
            _errors: Default::default(),
        }
    }

    fn intact_recipients() -> Recipients {
        Recipients {
            _id: None,
            toRecipients: Vec::new(),
            ccRecipients: Vec::new(),
            bccRecipients: Vec::new(),
        }
    }

    fn intact_details() -> MailDetails {
        MailDetails {
            _id: None,
            sentDate: DateTime::from_millis(0),
            authStatus: 0,
            replyTos: Vec::new(),
            recipients: intact_recipients(),
            headers: None,
            body: intact_body(),
        }
    }

    fn intact_blob() -> MailDetailsBlob {
        MailDetailsBlob {
            _id: Some(IdTupleGenerated::new(
                GeneratedId("list".into()),
                GeneratedId("element".into()),
            )),
            _permissions: GeneratedId("permissions".into()),
            _format: 0,
            _ownerGroup: None,
            _ownerEncSessionKey: None,
            _ownerKeyVersion: None,
            _kdfNonce: None,
            details: intact_details(),
            _errors: Default::default(),
        }
    }

    /// Build a non-empty `Errors` map by deserializing a synthetic decryption
    /// error. `ElementValue` is not publicly nameable, so JSON round-trips the
    /// map through the public `Errors` alias.
    fn error_map() -> tutasdk::entities::Errors {
        serde_json::from_str(r#"{"body":{"String":"decryption failed"}}"#).unwrap()
    }

    fn intact_file() -> TutanotaFile {
        TutanotaFile {
            _id: Some(IdTupleGenerated::new(
                GeneratedId("list".into()),
                GeneratedId("element".into()),
            )),
            _permissions: GeneratedId("permissions".into()),
            _format: 0,
            _ownerEncSessionKey: None,
            name: "file.bin".into(),
            size: 5,
            mimeType: None,
            _ownerGroup: None,
            cid: None,
            _ownerKeyVersion: None,
            _kdfNonce: None,
            parent: None,
            subFiles: None,
            blobs: vec![Blob {
                _id: None,
                archiveId: GeneratedId("arch".into()),
                size: 5,
                blobId: GeneratedId("blob".into()),
            }],
            _errors: Default::default(),
        }
    }

    fn intact_mail() -> Mail {
        Mail {
            _id: Some(IdTupleGenerated::new(
                GeneratedId("list".into()),
                GeneratedId("element".into()),
            )),
            _permissions: GeneratedId("permissions".into()),
            _format: 0,
            _ownerEncSessionKey: None,
            subject: String::new(),
            receivedDate: DateTime::from_millis(0),
            state: 0,
            unread: false,
            confidential: false,
            replyType: 0,
            _ownerGroup: None,
            differentEnvelopeSender: None,
            listUnsubscribe: false,
            movedTime: None,
            phishingStatus: 0,
            authStatus: None,
            method: 0,
            recipientCount: 0,
            encryptionAuthStatus: None,
            _ownerKeyVersion: None,
            processingState: 0,
            processNeeded: false,
            sendAt: None,
            serverClassificationData: None,
            _kdfNonce: None,
            sender: MailAddress {
                _id: None,
                name: String::new(),
                address: "a@b".into(),
                contact: None,
                _errors: Default::default(),
            },
            attachments: Vec::new(),
            conversationEntry: IdTupleGenerated::new(
                GeneratedId("list".into()),
                GeneratedId("element".into()),
            ),
            firstRecipient: None,
            mailDetails: None,
            mailDetailsDraft: None,
            bucketKey: None,
            sets: Vec::new(),
            clientSpamClassifierResult: None,
            _errors: Default::default(),
        }
    }

    #[test]
    fn intact_blob_is_accepted() {
        assert!(details_are_intact(&intact_blob()));
    }

    #[test]
    fn blob_with_top_level_errors_is_rejected() {
        let mut blob = intact_blob();
        blob._errors = error_map();
        assert!(!details_are_intact(&blob));
    }

    #[test]
    fn blob_with_body_errors_is_rejected() {
        let mut blob = intact_blob();
        blob.details.body._errors = error_map();
        assert!(!details_are_intact(&blob));
    }

    #[test]
    fn blob_with_header_errors_is_rejected() {
        let mut blob = intact_blob();
        let mut header = intact_header();
        header._errors = error_map();
        blob.details.headers = Some(header);
        assert!(!details_are_intact(&blob));
    }

    #[test]
    fn blob_with_recipient_errors_is_rejected() {
        let mut blob = intact_blob();
        let mut recipient = MailAddress {
            _id: None,
            name: String::new(),
            address: "a@b".into(),
            contact: None,
            _errors: Default::default(),
        };
        recipient._errors = error_map();
        blob.details.recipients.toRecipients = vec![recipient];
        assert!(!details_are_intact(&blob));
    }

    #[test]
    fn blob_with_reply_to_errors_is_rejected() {
        let mut blob = intact_blob();
        let mut reply_to = EncryptedMailAddress {
            _id: None,
            name: String::new(),
            address: "e@f".into(),
            _errors: Default::default(),
        };
        reply_to._errors = error_map();
        blob.details.replyTos = vec![reply_to];
        assert!(!details_are_intact(&blob));
    }

    #[test]
    fn intact_file_is_accepted() {
        assert!(file_is_intact(&intact_file()));
    }

    #[test]
    fn file_with_errors_is_rejected() {
        let mut file = intact_file();
        file._errors = error_map();
        assert!(!file_is_intact(&file));
    }

    #[test]
    fn zero_sized_file_without_blobs_is_accepted() {
        let mut file = intact_file();
        file.size = 0;
        file.blobs = Vec::new();
        assert!(file_is_intact(&file));
    }

    #[test]
    fn non_zero_file_without_blobs_is_rejected() {
        let mut file = intact_file();
        file.blobs = Vec::new();
        assert!(!file_is_intact(&file));
    }

    #[test]
    fn intact_mail_is_accepted() {
        assert!(mail_is_intact(&intact_mail()));
    }

    #[test]
    fn mail_with_top_level_errors_is_rejected() {
        let mut mail = intact_mail();
        mail._errors = error_map();
        assert!(!mail_is_intact(&mail));
    }

    #[test]
    fn mail_with_sender_errors_is_rejected() {
        let mut mail = intact_mail();
        mail.sender._errors = error_map();
        assert!(!mail_is_intact(&mail));
    }
}
