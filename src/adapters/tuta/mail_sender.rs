//! Send mail through Tuta: create a draft, then send it.
//!
//! This ports the web client's `MailFacade.createDraft` + `sendDraft`
//! (`src/applications/common/api/worker/facades/lazy/MailFacade.ts` at
//! the pinned rev) onto SDK primitives, in the **non-confidential** mode
//! only: the mail session key travels to the Tuta server in the send
//! request, as the web client does for a mail with external recipients
//! and "confidential" off. Tuta-to-Tuta mail sent this way is therefore
//! not end-to-end encrypted. The confidential path needs the SDK's
//! asymmetric facade, which `LoggedInSdk` does not expose at this rev,
//! and the project does not reimplement cryptography.
//!
//! The SDK encrypts a whole service request under one session key, while
//! the web client uses one key per attachment. Attachments therefore
//! reuse the mail's session key: the blob, the file's name and MIME type,
//! and the key handed to the server in `AttachmentKeyData` all agree.
//!
//! Errors are fixed strings: no address, subject or body ever reaches
//! one.

use std::sync::Arc;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL, Engine as _};
use crypto_primitives::aes::{Aes256Key, InitializationVector};
use crypto_primitives::key::GenericAesKey;
use crypto_primitives::randomizer_facade::RandomizerFacade;
use rand_core::OsRng;
use tutasdk::entities::generated::tutanota::{
    AttachmentKeyData, BodyTransferAggregatedType, DraftAttachment, DraftCreateData, DraftData,
    EncryptedMailAddressTransferAggregatedType, FileTransferAggregatedType, Mail,
    MailAddressTransferAggregatedType, MailDetailsBlobTransferAggregatedType,
    MailDetailsTransferAggregatedType, MailTransferAggregatedType, NewDraftAttachment,
    RecipientsTransferAggregatedType, SendDraftData, SendDraftParameters,
};
use tutasdk::rest_error::HttpError;
use tutasdk::services::generated::tutanota::{DraftService, SendDraftService};
use tutasdk::services::ExtraServiceParams;
use tutasdk::tutanota_constants::ArchiveDataType;
use tutasdk::{ApiCallError, CustomId, GeneratedId, IdTupleGenerated, LoggedInSdk};

use crate::domain::{Error, Result};
use crate::ports::mail_sender::{MailSender, OutgoingAddress, OutgoingMail};

/// `ConversationType.NEW` in the web client.
const CONVERSATION_NEW: i64 = 0;
/// `MailMethod.NONE`: a plain mail, not a calendar invitation.
const MAIL_METHOD_NONE: i64 = 0;
/// The language of server-generated notification texts.
const LANGUAGE: &str = "en";

fn send_failed() -> Error {
    Error::Network("tuta send failed".into())
}

/// A fresh aggregate id, in the SDK's own format (4 random bytes,
/// base64url): the SDK generates these for encrypted requests only, so
/// the plain `SendDraftData` aggregates get theirs here.
fn aggregate_id(random: &RandomizerFacade) -> Option<CustomId> {
    Some(CustomId(
        BASE64_URL.encode(random.generate_random_array::<4>()),
    ))
}

fn transfer_address(address: &OutgoingAddress) -> MailAddressTransferAggregatedType {
    MailAddressTransferAggregatedType {
        _id: None,
        name: address.name.clone(),
        address: address.address.clone(),
        contact: None,
        _errors: Default::default(),
    }
}

/// The draft request for `mail`: every field the web client sets, the
/// deprecated ones left empty exactly like it leaves them.
pub fn draft_request(
    mail: &OutgoingMail,
    owner_enc_session_key: &[u8],
    owner_key_version: i64,
    attachments: Vec<DraftAttachment>,
) -> DraftCreateData {
    let first_recipient = mail.recipients().next().map(transfer_address);
    DraftCreateData {
        _format: 0,
        previousMessageId: None,
        conversationType: CONVERSATION_NEW,
        ownerEncSessionKey: None,
        ownerKeyVersion: None,
        draftData: DraftData {
            _id: None,
            subject: None,
            bodyText: None,
            senderMailAddress: None,
            senderName: None,
            confidential: None,
            method: None,
            compressedBodyText: None,
            toRecipients: Vec::new(),
            ccRecipients: Vec::new(),
            bccRecipients: Vec::new(),
            addedAttachments: attachments,
            removedAttachments: Vec::new(),
            replyTos: Vec::new(),
            mail: Some(MailTransferAggregatedType {
                _id: None,
                _ownerEncSessionKey: Some(owner_enc_session_key.to_vec()),
                _ownerKeyVersion: Some(owner_key_version),
                _kdfNonce: None,
                subject: mail.subject.clone(),
                confidential: false,
                method: MAIL_METHOD_NONE,
                sender: transfer_address(&mail.from),
                firstRecipient: first_recipient,
                _errors: Default::default(),
            }),
            mailDetailsBlob: Some(MailDetailsBlobTransferAggregatedType {
                _id: None,
                _ownerEncSessionKey: Some(owner_enc_session_key.to_vec()),
                _ownerKeyVersion: Some(owner_key_version),
                _kdfNonce: None,
                details: MailDetailsTransferAggregatedType {
                    _id: None,
                    replyTos: mail
                        .reply_to
                        .iter()
                        .map(|address| EncryptedMailAddressTransferAggregatedType {
                            _id: None,
                            name: address.name.clone(),
                            address: address.address.clone(),
                            _errors: Default::default(),
                        })
                        .collect(),
                    recipients: RecipientsTransferAggregatedType {
                        _id: None,
                        toRecipients: mail.to.iter().map(transfer_address).collect(),
                        ccRecipients: mail.cc.iter().map(transfer_address).collect(),
                        bccRecipients: mail.bcc.iter().map(transfer_address).collect(),
                    },
                    body: BodyTransferAggregatedType {
                        _id: None,
                        text: Some(String::new()),
                        compressedText: Some(mail.html_body.clone()),
                        _errors: Default::default(),
                    },
                },
            }),
            _errors: Default::default(),
        },
        _errors: Default::default(),
    }
}

/// The non-confidential send request: the raw mail session key, and the
/// same key for every attachment.
pub fn send_request(
    random: &RandomizerFacade,
    draft: IdTupleGenerated,
    session_key: &[u8],
    attachments: &[IdTupleGenerated],
) -> SendDraftData {
    let attachment_keys = |random: &RandomizerFacade| -> Vec<AttachmentKeyData> {
        attachments
            .iter()
            .map(|file| AttachmentKeyData {
                _id: aggregate_id(random),
                bucketEncFileSessionKey: None,
                fileSessionKey: Some(session_key.to_vec()),
                file: file.clone(),
            })
            .collect()
    };
    SendDraftData {
        _format: 0,
        language: LANGUAGE.to_string(),
        mailSessionKey: Some(session_key.to_vec()),
        bucketEncMailSessionKey: None,
        senderNameUnencrypted: None,
        plaintext: false,
        calendarMethod: false,
        sessionEncEncryptionAuthStatus: None,
        sendAt: None,
        allowUndo: false,
        internalRecipientKeyData: Vec::new(),
        secureExternalRecipientKeyData: Vec::new(),
        attachmentKeyData: attachment_keys(random),
        mail: draft.clone(),
        symEncInternalRecipientKeyData: Vec::new(),
        parameters: Some(SendDraftParameters {
            _id: aggregate_id(random),
            language: LANGUAGE.to_string(),
            mailSessionKey: Some(session_key.to_vec()),
            bucketEncMailSessionKey: None,
            senderNameUnencrypted: None,
            plaintext: false,
            calendarMethod: false,
            sessionEncEncryptionAuthStatus: None,
            mail: draft,
            internalRecipientKeyData: Vec::new(),
            secureExternalRecipientKeyData: Vec::new(),
            symEncInternalRecipientKeyData: Vec::new(),
            attachmentKeyData: attachment_keys(random),
        }),
    }
}

/// The canonical form of a sender address for the lookup: Tuta keeps
/// account addresses and aliases in lower case, so `Me@Tuta.example`
/// must match `me@tuta.example` (SMTP practice is case-insensitive).
pub fn canonical_sender(address: &str) -> String {
    address.trim().to_lowercase()
}

/// Classify the outcome of the SDK's sender lookup: the group when the
/// address is the account's, `None` when the SDK says it is not (it
/// answers `NotFound` after checking every mail group), and a transient
/// network error for anything else — a failed request must make the
/// client retry, never bounce the mail as "not your address".
pub fn classify_sender_lookup(
    outcome: std::result::Result<GeneratedId, ApiCallError>,
) -> Result<Option<GeneratedId>> {
    match outcome {
        Ok(group) => Ok(Some(group)),
        Err(ApiCallError::ServerResponseError {
            source: HttpError::NotFoundError,
        }) => Ok(None),
        Err(_) => Err(Error::Network("sender lookup failed".into())),
    }
}

/// [`MailSender`] over the logged-in Tuta SDK.
pub struct TutaMailSender {
    logged: Arc<LoggedInSdk>,
}

impl TutaMailSender {
    pub fn new(logged: Arc<LoggedInSdk>) -> Self {
        Self { logged }
    }

    async fn sender_group(&self, address: &str) -> Result<Option<GeneratedId>> {
        classify_sender_lookup(
            self.logged
                .mail_facade()
                .get_group_id_for_mail_address(&canonical_sender(address))
                .await,
        )
    }
}

#[async_trait::async_trait]
impl MailSender for TutaMailSender {
    async fn send(&self, mail: &OutgoingMail) -> Result<()> {
        let mail_facade = self.logged.mail_facade();
        // The sender must be one of the account's enabled addresses or
        // aliases; its mail group owns the draft.
        let group = self
            .sender_group(&mail.from.address)
            .await?
            .ok_or_else(|| {
                Error::Unsupported("sender address is not an address of this account".into())
            })?;
        // The draft carries the address as the account spells it.
        let mut mail = mail.clone();
        mail.from.address = canonical_sender(&mail.from.address);
        let mail = &mail;
        let group_key = self
            .logged
            .get_current_sym_group_key(&group)
            .await
            .map_err(|_| send_failed())?;

        let random = RandomizerFacade::from_core(OsRng);
        let session_key: GenericAesKey = Aes256Key::generate(&random).into();
        let owner_enc_session_key = group_key
            .object
            .encrypt_key(&session_key, InitializationVector::generate(&random));
        let owner_key_version = i64::try_from(group_key.version).map_err(|_| send_failed())?;

        // Attachments first: the draft references their blobs.
        let blob_facade = self.logged.blob_facade();
        let mut added = Vec::with_capacity(mail.attachments.len());
        for attachment in &mail.attachments {
            // The SDK's upload future is not `Send` (it holds a boxed
            // iterator), so it is built and driven on a blocking thread
            // through the runtime handle instead of on this task.
            let handle = tokio::runtime::Handle::current();
            let (blob_facade, group, key, data) = (
                Arc::clone(&blob_facade),
                group.clone(),
                session_key.clone(),
                attachment.data.clone(),
            );
            let tokens = tokio::task::spawn_blocking(move || {
                handle.block_on(blob_facade.encrypt_and_upload_single_legacy(
                    ArchiveDataType::Attachments,
                    &group,
                    &key,
                    &data,
                ))
            })
            .await
            .map_err(|_| Error::Network("attachment upload failed".into()))?
            .map_err(|_| Error::Network("attachment upload failed".into()))?;
            added.push(DraftAttachment {
                _id: None,
                ownerEncFileSessionKey: None,
                ownerKeyVersion: None,
                existingFile: None,
                newFile: Some(NewDraftAttachment {
                    _id: None,
                    encFileName: None,
                    encMimeType: None,
                    encCid: None,
                    referenceTokens: tokens,
                    file: Some(FileTransferAggregatedType {
                        _id: None,
                        _ownerEncSessionKey: Some(owner_enc_session_key.clone()),
                        _ownerKeyVersion: Some(owner_key_version),
                        _kdfNonce: None,
                        name: attachment.name.clone(),
                        mimeType: Some(attachment.mime_type.clone()),
                        cid: attachment.cid.clone(),
                        _errors: Default::default(),
                    }),
                }),
            });
        }
        let has_attachments = !added.is_empty();

        let executor = self.logged.get_service_executor();
        let created = executor
            .post::<DraftService>(
                draft_request(mail, &owner_enc_session_key, owner_key_version, added),
                ExtraServiceParams {
                    session_key: Some(session_key.clone()),
                    ..ExtraServiceParams::default()
                },
            )
            .await
            .map_err(|_| Error::Network("draft creation failed".into()))?;

        // The server created one File per attachment; sending needs
        // their ids, which only the stored draft lists.
        let attachment_ids = if has_attachments {
            let draft: Mail = mail_facade
                .get_crypto_entity_client()
                .load(&created.draft)
                .await
                .map_err(|_| Error::Network("draft reload failed".into()))?;
            draft.attachments
        } else {
            Vec::new()
        };

        executor
            .post::<SendDraftService>(
                send_request(
                    &random,
                    created.draft,
                    session_key.as_bytes(),
                    &attachment_ids,
                ),
                ExtraServiceParams::default(),
            )
            .await
            .map_err(|_| send_failed())?;
        Ok(())
    }

    async fn accepts_sender(&self, address: &str) -> Result<bool> {
        Ok(self.sender_group(address).await?.is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tutasdk::GeneratedId;

    fn address(name: &str, address: &str) -> OutgoingAddress {
        OutgoingAddress {
            name: name.into(),
            address: address.into(),
        }
    }

    fn mail() -> OutgoingMail {
        OutgoingMail {
            from: address("Me", "me@tuta.example"),
            to: vec![address("Ann", "ann@x.example")],
            cc: vec![address("", "bob@y.example")],
            bcc: vec![address("", "hidden@z.example")],
            reply_to: vec![],
            subject: "s".into(),
            html_body: "<p>hi</p>".into(),
            attachments: vec![],
        }
    }

    #[test]
    fn sender_lookup_failures_are_transient_unless_the_address_is_foreign() {
        let group = GeneratedId("group".into());
        assert!(matches!(
            classify_sender_lookup(Ok(group.clone())),
            Ok(Some(found)) if found == group
        ));
        assert!(matches!(
            classify_sender_lookup(Err(ApiCallError::ServerResponseError {
                source: HttpError::NotFoundError
            })),
            Ok(None)
        ));
        for error in [
            ApiCallError::ServerResponseError {
                source: HttpError::ConnectionError,
            },
            ApiCallError::RestClient {
                source: tutasdk::bindings::rest_client::RestClientError::NetworkError,
            },
            ApiCallError::InternalSdkError {
                error_message: "x".into(),
            },
        ] {
            assert!(matches!(
                classify_sender_lookup(Err(error)),
                Err(Error::Network(_))
            ));
        }
    }

    #[test]
    fn sender_addresses_compare_case_insensitively() {
        assert_eq!(canonical_sender(" Me@Tuta.Example "), "me@tuta.example");
    }

    #[test]
    fn the_draft_is_non_confidential_and_keeps_bcc_in_the_details() {
        let request = draft_request(&mail(), b"owner-key", 3, Vec::new());
        let transfer = request.draftData.mail.unwrap();
        assert!(!transfer.confidential);
        assert_eq!(transfer._ownerKeyVersion, Some(3));
        assert_eq!(transfer.firstRecipient.unwrap().address, "ann@x.example");
        let details = request.draftData.mailDetailsBlob.unwrap().details;
        assert_eq!(
            details.recipients.bccRecipients[0].address,
            "hidden@z.example"
        );
        assert_eq!(details.body.compressedText.as_deref(), Some("<p>hi</p>"));
        // The deprecated top-level fields stay empty, like the web client.
        assert!(request.ownerEncSessionKey.is_none());
        assert!(request.draftData.toRecipients.is_empty());
    }

    #[test]
    fn the_send_request_carries_the_session_key_for_mail_and_files() {
        let random = RandomizerFacade::from_core(OsRng);
        let id = |e: &str| IdTupleGenerated::new(GeneratedId("l".into()), GeneratedId(e.into()));
        let request = send_request(&random, id("draft"), b"key", &[id("f1"), id("f2")]);
        assert_eq!(request.mailSessionKey.as_deref(), Some(&b"key"[..]));
        assert!(request.bucketEncMailSessionKey.is_none());
        assert!(request.internalRecipientKeyData.is_empty());
        assert_eq!(request.attachmentKeyData.len(), 2);
        assert!(request
            .attachmentKeyData
            .iter()
            .all(|data| data.fileSessionKey.as_deref() == Some(&b"key"[..]) && data._id.is_some()));
        let parameters = request.parameters.unwrap();
        assert_eq!(parameters.attachmentKeyData.len(), 2);
        assert_eq!(parameters.mailSessionKey.as_deref(), Some(&b"key"[..]));
    }
}
