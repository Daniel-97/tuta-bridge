//! Load the user's contacts through the SDK's decryption path.
//!
//! The whole book comes from `ContactFacade::load_all_user_contacts`,
//! one contact from the crypto entity client (for event refreshes).
//! Contacts whose fields failed to decrypt are skipped. Every SDK
//! failure maps to one fixed [`Error::Network`] message: names,
//! addresses and ids never appear in errors or logs.

use std::sync::Arc;

use tutasdk::entities::generated::tutanota::Contact;
use tutasdk::rest_error::HttpError;
use tutasdk::{ApiCallError, GeneratedId, IdTupleGenerated, LoggedInSdk};

use crate::domain::{
    ContactCard, ContactField, ContactFieldKind, ContactRelation, ContactRelationKind, Error,
    Result,
};
use crate::ports::contact_source::{ContactListing, ContactSource};

/// Tuta implementation of [`ContactSource`].
pub struct TutaContactSource {
    logged: Arc<LoggedInSdk>,
}

impl TutaContactSource {
    pub fn new(logged: Arc<LoggedInSdk>) -> Self {
        Self { logged }
    }
}

fn contacts_unavailable() -> Error {
    Error::Network("contacts unavailable".into())
}

#[async_trait::async_trait]
impl ContactSource for TutaContactSource {
    async fn contacts(&self) -> Result<ContactListing> {
        let contacts = self
            .logged
            .contact_facade
            .load_all_user_contacts()
            .await
            .map_err(|_| contacts_unavailable())?;
        let total = contacts.len();
        let cards: Vec<ContactCard> = contacts.iter().filter_map(contact_card).collect();
        Ok(ContactListing {
            skipped: total - cards.len(),
            cards,
        })
    }

    async fn contact(&self, list_id: &str, element_id: &str) -> Result<Option<ContactCard>> {
        let id = IdTupleGenerated::new(
            GeneratedId(list_id.to_string()),
            GeneratedId(element_id.to_string()),
        );
        let loaded = self
            .logged
            .mail_facade()
            .get_crypto_entity_client()
            .load::<Contact, IdTupleGenerated>(&id)
            .await;
        match loaded {
            Ok(contact) => Ok(contact_card(&contact)),
            Err(ApiCallError::ServerResponseError {
                source: HttpError::NotFoundError,
            }) => Ok(None),
            Err(_) => Err(contacts_unavailable()),
        }
    }
}

/// Map a decrypted contact; `None` when it did not decrypt cleanly or
/// has no id.
pub fn contact_card(contact: &Contact) -> Option<ContactCard> {
    if !contact._errors.is_empty() {
        return None;
    }
    let id = contact._id.as_ref()?;
    let text = |value: &Option<String>| value.clone().unwrap_or_default();
    let birthday = contact
        .birthdayIso
        .clone()
        .filter(|iso| !iso.trim().is_empty())
        .or_else(|| {
            contact
                .oldBirthdayAggregate
                .as_ref()
                .map(|old| match old.year {
                    Some(year) => format!("{year:04}-{:02}-{:02}", old.month, old.day),
                    None => format!("--{:02}-{:02}", old.month, old.day),
                })
        });
    Some(ContactCard {
        list_id: id.list_id.as_str().to_string(),
        element_id: id.element_id.as_str().to_string(),
        title: text(&contact.title),
        first_name: contact.firstName.clone(),
        middle_name: text(&contact.middleName),
        last_name: contact.lastName.clone(),
        name_suffix: text(&contact.nameSuffix),
        nickname: text(&contact.nickname),
        company: contact.company.clone(),
        department: text(&contact.department),
        role: contact.role.clone(),
        birthday,
        anniversaries: contact
            .customDate
            .iter()
            // ContactCustomDateType.ANNIVERSARY = "0".
            .filter(|date| date.r#type == 0 && !date.dateIso.trim().is_empty())
            .map(|date| date.dateIso.clone())
            .collect(),
        comment: contact.comment.clone(),
        emails: contact
            .mailAddresses
            .iter()
            .map(|mail| field(address_kind(mail.r#type), &mail.address))
            .collect(),
        phones: contact
            .phoneNumbers
            .iter()
            .map(|phone| field(phone_kind(phone.r#type), &phone.number))
            .collect(),
        addresses: contact
            .addresses
            .iter()
            .map(|address| field(address_kind(address.r#type), &address.address))
            .collect(),
        websites: contact
            .websites
            .iter()
            .map(|site| field(address_kind(site.r#type), &site.url))
            .collect(),
        relations: contact
            .relationships
            .iter()
            .map(|relation| ContactRelation {
                kind: relation_kind(relation.r#type),
                person: relation.person.clone(),
            })
            .collect(),
    })
}

fn field(kind: ContactFieldKind, value: &str) -> ContactField {
    ContactField {
        kind,
        value: value.to_string(),
    }
}

/// `ContactAddressType` / `ContactWebsiteType`: PRIVATE 0, WORK 1,
/// OTHER 2, CUSTOM 3.
fn address_kind(code: i64) -> ContactFieldKind {
    match code {
        0 => ContactFieldKind::Home,
        1 => ContactFieldKind::Work,
        3 => ContactFieldKind::Custom,
        _ => ContactFieldKind::Other,
    }
}

/// `ContactPhoneNumberType`: PRIVATE 0, WORK 1, MOBILE 2, FAX 3,
/// OTHER 4, CUSTOM 5.
fn phone_kind(code: i64) -> ContactFieldKind {
    match code {
        0 => ContactFieldKind::Home,
        1 => ContactFieldKind::Work,
        2 => ContactFieldKind::Mobile,
        3 => ContactFieldKind::Fax,
        5 => ContactFieldKind::Custom,
        _ => ContactFieldKind::Other,
    }
}

/// `ContactRelationshipType`: PARENT 0, BROTHER 1, SISTER 2, CHILD 3,
/// FRIEND 4, RELATIVE 5, SPOUSE 6, PARTNER 7, ASSISTANT 8, MANAGER 9,
/// OTHER 10, CUSTOM 11.
fn relation_kind(code: i64) -> ContactRelationKind {
    match code {
        0 => ContactRelationKind::Parent,
        1 | 2 => ContactRelationKind::Sibling,
        3 => ContactRelationKind::Child,
        4 => ContactRelationKind::Friend,
        5 => ContactRelationKind::Relative,
        6 => ContactRelationKind::Spouse,
        7 => ContactRelationKind::Partner,
        8 => ContactRelationKind::Assistant,
        9 => ContactRelationKind::Manager,
        _ => ContactRelationKind::Other,
    }
}
