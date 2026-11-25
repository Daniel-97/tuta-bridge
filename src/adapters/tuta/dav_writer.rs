//! Write contacts through the SDK's generic encrypted-entity path,
//! update calendar events in place, and delete both the way the web
//! client does.
//!
//! Contacts are created through `CryptoEntityClient::create_instance`:
//! the session key is generated here, owner-encrypted with the owner
//! group's current key the same way [`super::mail_sender`] encrypts a
//! draft's session key, and handed to the SDK alongside the entity.
//! The SDK encrypts the payload and posts it; the server fills in the
//! element id. Contact updates, and calendar-event updates, load the
//! stored instance (the SDK resolves the session key from its
//! `_ownerEncSessionKey`), apply the fields in place and
//! `update_instance` it back.
//!
//! Calendar events are never created here: the handler refuses an
//! event creation before the writer is called, and the writer's create
//! branch answers `Unsupported` as well.
//!
//! Deletions cannot use the SDK's `erase_list_element`: at the pinned
//! rev it is a `todo!()`. The web client's `entityClient.erase` is a
//! plain authenticated `DELETE` on the entity REST endpoint, so the
//! writer issues the same request through the session's `RestClient`
//! with `cv`, `v` (type model version 118 for both types) and the
//! access token; a 404 answers `Gone`, auth rejections map to the
//! session error, everything else to the fixed write failure.
//!
//! Updates merge into the loaded contact, like the web client's edit:
//! every rewritten aggregate row is matched against the loaded rows
//! by value and by the kind the reader maps its Tuta type to (the
//! Other/Custom collapse included), and a match keeps the loaded row
//! byte for byte - id, Tuta type and custom label. A field without a
//! match becomes a new row whose id the server assigns, as on create
//! (the bridge never stamps aggregate ids); a loaded row without a
//! counterpart is removed. Custom dates that are not anniversaries are
//! kept untouched (the exporter never serves them, so no imported
//! field can name them), and the legacy birthday aggregate is cleared
//! so a removed birthday cannot return through the reader's fallback.
//!
//! An update honours the request's `If-Match` against the freshly
//! loaded entity, after the load and before anything is written: the
//! reader's own ETag derivation for a contact, the reader's own
//! fingerprint for an event. A mismatch answers the fixed
//! precondition refusal, so a write can never overwrite a remote edit
//! the event bus has not delivered yet; a contact that cannot be
//! rendered at all fails closed with the same refusal.
//!
//! Error mapping is honest about what the server said: an expired
//! session is the session error (the handlers let the session layer
//! answer it), a permanent rejection - 403, or a 400 the server will
//! answer again - is the fixed remote refusal the handlers answer
//! with `403`, and everything else is the retryable write failure.
//! Errors are fixed strings: no id, name, address or title ever
//! appears in one.

use std::collections::HashMap;
use std::sync::Arc;

use crypto_primitives::aes::{Aes256Key, InitializationVector};
use crypto_primitives::key::GenericAesKey;
use crypto_primitives::randomizer_facade::RandomizerFacade;
use crypto_primitives::sha::sha256;
use rand_core::OsRng;
use tutasdk::bindings::rest_client::{HttpMethod, RestClient, RestClientOptions};
use tutasdk::bindings::suspendable_rest_client::SuspensionBehavior;
use tutasdk::date::calendar_facade::DAYS_SHIFTED_MS;
use tutasdk::date::DateTime;
use tutasdk::entities::generated::sys::{DateWrapper, GroupMembership};
use tutasdk::entities::generated::tutanota::{
    AdvancedRepeatRule, CalendarEvent, CalendarRepeatRule, Contact, ContactAddress,
    ContactCustomDate, ContactMailAddress, ContactPhoneNumber, ContactRelationship, ContactWebsite,
    EncryptedMailAddress,
};
use tutasdk::rest_error::HttpError;
use tutasdk::{
    ApiCallError, CustomId, GeneratedId, IdTupleCustom, IdTupleGenerated, LoggedInSdk,
    CLIENT_VERSION,
};

use super::calendar_source::event_from_tuta;
use super::contact_source::{address_kind, contact_card, phone_kind, relation_kind};
use crate::adapters::caldav::ical::html_to_text;
use crate::adapters::carddav::vcard::{render_vcard, vcard_etag};
use crate::adapters::dav::strong_etag_matches;
use crate::adapters::smtp::outgoing::text_to_html;
use crate::domain::{ContactFieldKind, ContactRelationKind, Error, RepeatRule, Result};
use crate::ports::dav_writer::{
    CalendarRef, CalendarWriter, ContactFields, ContactRef, ContactWriter, DeleteOutcome,
    EventFields, EventRef, IfMatch, WriteRefusal,
};

/// REST path segment of the `Contact` type.
const CONTACT_PATH: &str = "contact";
/// REST path segment of the `CalendarEvent` type.
const EVENT_PATH: &str = "calendarevent";
/// Type model version of `Contact` and `CalendarEvent`: the `v` header
/// a raw request must carry.
const TYPE_MODEL_VERSION: &str = "118";
/// `GroupType.Contact`: the membership whose group owns the account's
/// contacts.
const CONTACT_GROUP_TYPE: Option<i64> = Some(6);

fn write_failed() -> Error {
    Error::Network("dav write failed".into())
}

/// The session error a rejected raw request answers with: the same
/// fixed text the session resume uses.
fn session_invalid() -> Error {
    Error::Login("session is no longer valid; run login again".into())
}

/// Map one SDK failure of the write path: an expired session is the
/// session error, a permanent rejection (403, or a 400 the server
/// will answer again) is the fixed remote refusal, and everything
/// else is the retryable write failure.
fn sdk_failure(error: ApiCallError) -> Error {
    match error {
        ApiCallError::ServerResponseError { source } => match source {
            HttpError::NotAuthenticatedError
            | HttpError::SessionExpiredError
            | HttpError::AccessDeactivatedError
            | HttpError::AccessExpiredError
            | HttpError::AccessBlockedError => session_invalid(),
            HttpError::NotAuthorizedError
            | HttpError::BadRequestError
            | HttpError::InvalidDataError => WriteRefusal::RemoteRefused.error(),
            _ => write_failed(),
        },
        _ => write_failed(),
    }
}

/// The strong ETag the reader derives from a loaded contact, or `None`
/// when the card does not map (the reader would not serve it).
fn loaded_contact_etag(
    contact: &tutasdk::entities::generated::tutanota::Contact,
) -> Option<String> {
    contact_card(contact).map(|card| vcard_etag(&render_vcard(&card)))
}

/// The content fingerprint the reader derives from a loaded event, or
/// `None` when the event does not map.
fn loaded_event_fingerprint(
    event: &tutasdk::entities::generated::tutanota::CalendarEvent,
) -> Option<String> {
    event_from_tuta(event).map(|mapped| mapped.fingerprint())
}

/// Refuse an update whose precondition does not name the freshly
/// loaded contact's current version. The handler has already verified
/// the header against its cached row; this is the authority. A
/// contact that cannot be rendered cannot be verified either: fail
/// closed with the same refusal, never with a silent overwrite.
fn check_contact_precondition(
    contact: &tutasdk::entities::generated::tutanota::Contact,
    if_match: IfMatch<'_>,
) -> Result<()> {
    let Some(condition) = if_match else {
        return Ok(());
    };
    if loaded_contact_etag(contact).is_some_and(|etag| strong_etag_matches(condition, &etag)) {
        return Ok(());
    }
    Err(WriteRefusal::StoredVersionChanged.error())
}

/// Refuse an update whose precondition does not name the freshly
/// loaded event's current content. The handler passes the stored
/// master row's fingerprint (the served resource ETag embeds the
/// row's first-seen stamp, which no freshly loaded event can
/// reproduce); the loaded event's fingerprint is the reader's own
/// derivation, so agreement means the event is still the version the
/// client read. An event that does not map fails closed the same way.
fn check_event_precondition(
    event: &tutasdk::entities::generated::tutanota::CalendarEvent,
    if_match: IfMatch<'_>,
) -> Result<()> {
    let Some(condition) = if_match else {
        return Ok(());
    };
    if loaded_event_fingerprint(event).is_some_and(|fingerprint| fingerprint == condition) {
        return Ok(());
    }
    Err(WriteRefusal::StoredVersionChanged.error())
}

/// The owner-encrypted session key of a new entity: what the server
/// stores so the owner group can read the entity. The raw session key
/// travels beside it into `create_instance`, not into the entity.
pub struct SessionKeyMaterial {
    pub owner_enc_session_key: Vec<u8>,
    pub owner_key_version: i64,
}

/// A Tuta `DateTime`, clamped to the epoch like the reader clamps on
/// the way out (times before 1970 cannot be stored).
fn date_time(ms: i64) -> DateTime {
    DateTime::from_millis(u64::try_from(ms).unwrap_or(0))
}

/// The contact owner group: the group of the account's Contact-group
/// membership, `None` for an account without one.
pub fn contact_owner_group<'a, I>(memberships: I) -> Option<String>
where
    I: IntoIterator<Item = &'a GroupMembership>,
{
    memberships
        .into_iter()
        .find(|membership| membership.groupType == CONTACT_GROUP_TYPE)
        .map(|membership| membership.group.0.clone())
}

/// A text field Tuta keeps nullable: `None` when unset, the way the
/// web client leaves it.
fn opt_text(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_string())
}

/// `ContactAddressType` / `ContactWebsiteType`: PRIVATE 0, WORK 1,
/// OTHER 2, CUSTOM 3 — the inverse of the reader's mapping.
fn address_code(kind: ContactFieldKind) -> i64 {
    match kind {
        ContactFieldKind::Home => 0,
        ContactFieldKind::Work => 1,
        ContactFieldKind::Custom => 3,
        ContactFieldKind::Mobile | ContactFieldKind::Fax | ContactFieldKind::Other => 2,
    }
}

/// `ContactPhoneNumberType`: PRIVATE 0, WORK 1, MOBILE 2, FAX 3,
/// OTHER 4, CUSTOM 5.
fn phone_code(kind: ContactFieldKind) -> i64 {
    match kind {
        ContactFieldKind::Home => 0,
        ContactFieldKind::Work => 1,
        ContactFieldKind::Mobile => 2,
        ContactFieldKind::Fax => 3,
        ContactFieldKind::Custom => 5,
        ContactFieldKind::Other => 4,
    }
}

/// `ContactRelationshipType`: PARENT 0, BROTHER 1, SISTER 2, CHILD 3,
/// FRIEND 4, RELATIVE 5, SPOUSE 6, PARTNER 7, ASSISTANT 8, MANAGER 9,
/// OTHER 10, CUSTOM 11. The reader folds BROTHER and SISTER into one
/// kind; the writer picks the first of the pair.
fn relation_code(kind: ContactRelationKind) -> i64 {
    match kind {
        ContactRelationKind::Parent => 0,
        ContactRelationKind::Sibling => 1,
        ContactRelationKind::Child => 3,
        ContactRelationKind::Friend => 4,
        ContactRelationKind::Relative => 5,
        ContactRelationKind::Spouse => 6,
        ContactRelationKind::Partner => 7,
        ContactRelationKind::Assistant => 8,
        ContactRelationKind::Manager => 9,
        ContactRelationKind::Other => 10,
    }
}

/// The `anniversary` kind of Tuta's custom dates (the reader's filter).
const ANNIVERSARY_TYPE: i64 = 0;

fn mail_address(field: &crate::domain::ContactField) -> ContactMailAddress {
    ContactMailAddress {
        _id: None,
        r#type: address_code(field.kind),
        address: field.value.clone(),
        customTypeName: String::new(),
        _errors: Default::default(),
    }
}

fn phone_number(field: &crate::domain::ContactField) -> ContactPhoneNumber {
    ContactPhoneNumber {
        _id: None,
        r#type: phone_code(field.kind),
        number: field.value.clone(),
        customTypeName: String::new(),
        _errors: Default::default(),
    }
}

fn postal_address(field: &crate::domain::ContactField) -> ContactAddress {
    ContactAddress {
        _id: None,
        r#type: address_code(field.kind),
        address: field.value.clone(),
        customTypeName: String::new(),
        _errors: Default::default(),
    }
}

fn website(field: &crate::domain::ContactField) -> ContactWebsite {
    ContactWebsite {
        _id: None,
        r#type: address_code(field.kind),
        customTypeName: String::new(),
        url: field.value.clone(),
        _errors: Default::default(),
    }
}

fn relationship(relation: &crate::domain::ContactRelation) -> ContactRelationship {
    ContactRelationship {
        _id: None,
        r#type: relation_code(relation.kind),
        customTypeName: String::new(),
        person: relation.person.clone(),
        _errors: Default::default(),
    }
}

fn anniversary(date_iso: &str) -> ContactCustomDate {
    ContactCustomDate {
        _id: None,
        r#type: ANNIVERSARY_TYPE,
        customTypeName: String::new(),
        dateIso: date_iso.to_string(),
        _errors: Default::default(),
    }
}

/// A new `Contact` in the web client's `createNewContact` shape: the
/// writable fields applied, the rest at their documented defaults
/// (empty strings, nulls, empty lists), the owner-encrypted session
/// key and owner group set, and the id prepared for the server to
/// fill. Aggregate rows carry no ids: the server assigns them, on
/// create and for a new row of an update alike, exactly as it does for
/// the web client's null-id rows.
pub fn contact_entity(
    fields: &ContactFields,
    list_id: &str,
    owner_group: &str,
    key: &SessionKeyMaterial,
) -> Contact {
    Contact {
        _id: Some(IdTupleGenerated {
            list_id: GeneratedId(list_id.to_string()),
            element_id: Default::default(),
        }),
        _permissions: Default::default(),
        _format: 0,
        _ownerEncSessionKey: Some(key.owner_enc_session_key.clone()),
        _ownerGroup: Some(GeneratedId(owner_group.to_string())),
        _ownerKeyVersion: Some(key.owner_key_version),
        _kdfNonce: None,
        firstName: fields.first_name.clone(),
        lastName: fields.last_name.clone(),
        company: fields.company.clone(),
        role: fields.role.clone(),
        oldBirthdayDate: None,
        comment: fields.comment.clone(),
        presharedPassword: None,
        nickname: opt_text(&fields.nickname),
        title: opt_text(&fields.title),
        birthdayIso: fields.birthday.clone(),
        middleName: opt_text(&fields.middle_name),
        nameSuffix: opt_text(&fields.name_suffix),
        phoneticFirst: None,
        phoneticMiddle: None,
        phoneticLast: None,
        department: opt_text(&fields.department),
        mailAddresses: fields.emails.iter().map(mail_address).collect(),
        phoneNumbers: fields.phones.iter().map(phone_number).collect(),
        addresses: fields.addresses.iter().map(postal_address).collect(),
        socialIds: Vec::new(),
        oldBirthdayAggregate: None,
        photo: None,
        customDate: fields
            .anniversaries
            .iter()
            .map(|iso| anniversary(iso))
            .collect(),
        websites: fields.websites.iter().map(website).collect(),
        relationships: fields.relations.iter().map(relationship).collect(),
        messengerHandles: Vec::new(),
        pronouns: Vec::new(),
        _errors: Default::default(),
    }
}

/// Whether a loaded row's kind and the incoming kind may name the same
/// row. Equal kinds always agree; Other and Custom agree with each
/// other because the renderer writes no `TYPE` for either and the
/// importer maps a TYPE-less property to Custom, so an echoed Other
/// row arrives as Custom (pinned by
/// `the_render_never_distinguishes_other_from_custom`). The loaded
/// row's type and label still win.
fn field_kinds_agree(loaded: ContactFieldKind, incoming: ContactFieldKind) -> bool {
    loaded == incoming
        || (matches!(loaded, ContactFieldKind::Other | ContactFieldKind::Custom)
            && matches!(incoming, ContactFieldKind::Other | ContactFieldKind::Custom))
}

/// Whether a loaded field row and an incoming field are the same
/// property: equal after trim, with a compatible reader-mapped kind.
fn same_field(
    row_value: &str,
    row_kind: ContactFieldKind,
    field: &crate::domain::ContactField,
) -> bool {
    row_value.trim() == field.value.trim() && field_kinds_agree(row_kind, field.kind)
}

/// Merge one aggregate list: each incoming field takes the first
/// not-yet-consumed loaded row the predicate accepts and emits that
/// row untouched, else becomes a new row. Loaded rows no field names
/// are dropped.
fn merge_rows<Row, Field>(
    mut loaded: Vec<Row>,
    fields: &[Field],
    matches: impl Fn(&Row, &Field) -> bool,
    new_row: impl Fn(&Field) -> Row,
) -> Vec<Row> {
    let mut merged = Vec::with_capacity(fields.len());
    for field in fields {
        match loaded.iter().position(|row| matches(row, field)) {
            Some(index) => merged.push(loaded.remove(index)),
            None => merged.push(new_row(field)),
        }
    }
    merged
}

/// Apply the writable fields onto a loaded contact (the update path).
/// Scalars replace their stored value. Aggregate rows merge instead:
/// an incoming field takes the first loaded row with the same trimmed
/// value and a compatible reader-mapped kind and keeps it byte for
/// byte (id, Tuta type and custom label survive), an unmatched field
/// becomes a new row with no id, and a loaded row no field names is
/// removed. Custom dates of other kinds are kept untouched, and the
/// legacy birthday aggregate is always cleared (see the module doc).
pub fn apply_contact_fields(contact: &mut Contact, fields: &ContactFields) {
    contact.firstName = fields.first_name.clone();
    contact.lastName = fields.last_name.clone();
    contact.company = fields.company.clone();
    contact.role = fields.role.clone();
    contact.comment = fields.comment.clone();
    contact.title = opt_text(&fields.title);
    contact.nickname = opt_text(&fields.nickname);
    contact.middleName = opt_text(&fields.middle_name);
    contact.nameSuffix = opt_text(&fields.name_suffix);
    contact.department = opt_text(&fields.department);
    contact.birthdayIso = fields.birthday.clone();
    // The reader falls back to the legacy birthday aggregate whenever
    // `birthdayIso` is empty, so a stale aggregate would resurrect a
    // removed birthday with a changed ETag. The web client clears it
    // when it migrates such contacts; every update clears it too.
    contact.oldBirthdayAggregate = None;
    contact.mailAddresses = merge_rows(
        std::mem::take(&mut contact.mailAddresses),
        &fields.emails,
        |row, field| same_field(&row.address, address_kind(row.r#type), field),
        mail_address,
    );
    contact.phoneNumbers = merge_rows(
        std::mem::take(&mut contact.phoneNumbers),
        &fields.phones,
        |row, field| same_field(&row.number, phone_kind(row.r#type), field),
        phone_number,
    );
    contact.addresses = merge_rows(
        std::mem::take(&mut contact.addresses),
        &fields.addresses,
        |row, field| same_field(&row.address, address_kind(row.r#type), field),
        postal_address,
    );
    contact.websites = merge_rows(
        std::mem::take(&mut contact.websites),
        &fields.websites,
        |row, field| same_field(&row.url, address_kind(row.r#type), field),
        website,
    );
    contact.relationships = merge_rows(
        std::mem::take(&mut contact.relationships),
        &fields.relations,
        |row, relation| {
            row.person.trim() == relation.person.trim()
                && relation_kind(row.r#type) == relation.kind
        },
        relationship,
    );
    // Anniversaries match only the anniversary-kind rows the reader
    // serves; every other custom date (a name day) is kept untouched,
    // since the exporter never serves it and no imported field can
    // name it.
    let loaded_dates = std::mem::take(&mut contact.customDate);
    let mut anniversaries = Vec::new();
    let mut other_dates = Vec::new();
    for date in loaded_dates {
        if date.r#type == ANNIVERSARY_TYPE {
            anniversaries.push(date);
        } else {
            other_dates.push(date);
        }
    }
    let mut merged = Vec::with_capacity(fields.anniversaries.len() + other_dates.len());
    for iso in &fields.anniversaries {
        let wanted = iso.trim();
        match anniversaries
            .iter()
            .position(|date| date.dateIso.trim() == wanted)
        {
            Some(index) => merged.push(anniversaries.remove(index)),
            None => merged.push(anniversary(iso)),
        }
    }
    merged.extend(other_dates);
    contact.customDate = merged;
}

/// The time zones a write stores on an event: none for an all-day one
/// (its bounds sit on UTC midnight), the fields' zone for a timed one,
/// and `None` when a timed body carried no `TZID` — a UTC-form body
/// names no zone, so the loaded zones stay untouched.
fn event_zones(fields: &EventFields) -> Option<(Option<String>, Option<String>)> {
    if fields.all_day {
        Some((None, None))
    } else {
        fields
            .time_zone
            .as_ref()
            .map(|zone| (Some(zone.clone()), Some(zone.clone())))
    }
}

/// A Tuta repeat rule from the domain one. The id is kept on updates
/// (the web client updates the progenitor's rule instead of replacing
/// it) and left to the server on creates.
fn repeat_rule(rule: &RepeatRule, id: Option<CustomId>) -> CalendarRepeatRule {
    CalendarRepeatRule {
        _id: id,
        frequency: rule.frequency,
        endType: rule.end_type,
        endValue: rule.end_value,
        interval: rule.interval,
        timeZone: rule.time_zone.clone(),
        excludedDates: rule
            .excluded_ms
            .iter()
            .map(|ms| DateWrapper {
                _id: None,
                date: date_time(*ms),
                _errors: Default::default(),
            })
            .collect(),
        advancedRules: rule
            .advanced
            .iter()
            .map(|(kind, value)| AdvancedRepeatRule {
                _id: None,
                ruleType: *kind,
                interval: value.clone(),
                _errors: Default::default(),
            })
            .collect(),
        _errors: Default::default(),
    }
}

fn event_organizer(person: &crate::domain::EventPerson) -> EncryptedMailAddress {
    EncryptedMailAddress {
        _id: None,
        name: person.name.clone(),
        address: person.address.clone(),
        _errors: Default::default(),
    }
}

/// Whether the loaded event carries an attendee other than its
/// organizer. The served body carries the attendees, and the importer
/// refuses any attendee other than the organizer, so an accepted body
/// never carries them — refusing updates to events that have stored
/// guests guarantees a client can never silently drop or desync them.
fn attendee_gate(event: &CalendarEvent) -> Result<()> {
    let organizer = event
        .organizer
        .as_ref()
        .map(|person| person.address.as_str());
    let foreign = event.attendees.iter().any(|attendee| {
        organizer.is_none_or(|address| !attendee.address.address.eq_ignore_ascii_case(address))
    });
    if foreign {
        return Err(Error::Unsupported(
            "events with attendees cannot be edited through the bridge".into(),
        ));
    }
    Ok(())
}

/// Apply the writable fields onto a loaded event (the update path).
/// The ids, owner encryption, permissions, alarms and attendees stay
/// as loaded; the stored uid is identity (the web client never edits
/// it), save that a legacy event without one takes the fields', the
/// way the web client repairs such events. The sequence bumps on
/// every edit, like the web client's `incrementSequence`, and the
/// repeat rule keeps its id when the loaded event had one.
pub fn apply_event_fields(event: &mut CalendarEvent, fields: &EventFields) {
    event.summary = fields.summary.clone();
    // `DESCRIPTION` is the plain rendering of the stored HTML, so a
    // description echoed back means the client did not touch it: keep
    // the stored HTML. A different description is regenerated from
    // its plain text, the way the web client's editor writes it.
    if html_to_text(&event.description) != fields.description {
        event.description = text_to_html(&fields.description);
    }
    event.location = fields.location.clone();
    event.startTime = date_time(fields.start_ms);
    event.endTime = date_time(fields.end_ms);
    // A timed body without a `TZID` (the UTC form) names no zone: the
    // stored zones stay. An all-day event stores none.
    if let Some((start_zone, end_zone)) = event_zones(fields) {
        event.startTimeZone = start_zone;
        event.endTimeZone = end_zone;
    }
    // The importer only ever maps the organizer's address. Keep a
    // stored display name when the same address stays the organizer.
    let preserved_name = fields.organizer.as_ref().and_then(|person| {
        event
            .organizer
            .as_ref()
            .filter(|stored| {
                !stored.name.is_empty() && stored.address.eq_ignore_ascii_case(&person.address)
            })
            .map(|stored| stored.name.clone())
    });
    event.organizer = fields.organizer.as_ref().map(|person| {
        let mut organizer = event_organizer(person);
        if let Some(name) = &preserved_name {
            organizer.name = name.clone();
        }
        organizer
    });
    if event.uid.is_none() {
        event.uid = fields.uid.clone();
        // Web-client parity (`CalendarFacade.hashUid`): the hash is the
        // SHA-256 of the uid's UTF-8 bytes, stored as the raw 32
        // bytes. A repaired legacy event gets both, so a later edit in
        // the Tuta client matches it.
        if let Some(uid) = &event.uid {
            event.hashedUid = Some(sha256(uid.as_bytes()));
        }
    }
    // The progenitor's rule is updated, not replaced: keep its id. A
    // UTC-form body carries no `TZID`, so a body echoing absolute
    // instants must not flip the series' wall-clock anchor: a timed
    // rule keeps the loaded rule's zone. Without a stored zone the
    // incoming zone stays (one is never invented).
    let rule_id = event.repeatRule.as_ref().and_then(|rule| rule._id.clone());
    let loaded_rule_zone = event
        .repeatRule
        .as_ref()
        .map(|rule| rule.timeZone.clone())
        .filter(|zone| !zone.is_empty());
    event.repeatRule = fields.repeat.as_ref().map(|rule| {
        let mut mapped = repeat_rule(rule, rule_id);
        if !fields.all_day && fields.time_zone.is_none() {
            if let Some(zone) = &loaded_rule_zone {
                mapped.timeZone = zone.clone();
            }
        }
        mapped
    });
    event.sequence = event.sequence.saturating_add(1);
}

/// Which event list a write goes to, the web client's `isLongEvent`:
/// the long list for any repeating event (a rule bounded by `UNTIL` or
/// `COUNT` included) and for a one-off longer than the event-id
/// randomization range, the short list for everything else.
pub fn choose_event_list<'a>(calendar: &'a CalendarRef, fields: &EventFields) -> &'a str {
    let duration_ms = i128::from(fields.end_ms) - i128::from(fields.start_ms);
    if fields.repeat.is_some() || duration_ms > i128::from(DAYS_SHIFTED_MS) {
        &calendar.long_list_id
    } else {
        &calendar.short_list_id
    }
}

/// The event a `put_event` updates: a create is refused with the same
/// fixed sentence the handler answers a creation `PUT` with. Creating
/// events is upstream-blocked, since the pinned SDK cannot create
/// Tuta's custom-id events.
fn update_target(existing: Option<&EventRef>) -> Result<&EventRef> {
    existing.ok_or_else(|| WriteRefusal::CreateRefused.error())
}

/// The URL of the raw entity DELETE the web client's
/// `entityClient.erase` issues.
pub fn entity_delete_url(
    base_url: &str,
    type_path: &str,
    list_id: &str,
    element_id: &str,
) -> String {
    format!("{base_url}/rest/tutanota/{type_path}/{list_id}/{element_id}")
}

/// Map a raw delete response: a 404 means the entity had already
/// vanished remotely, a rejected session is the session error, a 403
/// or 400 is a permanent refusal the server will answer again (a
/// read-only share, a rejected id), and every other status is the
/// fixed write failure.
fn delete_outcome(status: u32) -> Result<DeleteOutcome> {
    match status {
        200..=299 => Ok(DeleteOutcome::Deleted),
        404 => Ok(DeleteOutcome::Gone),
        401 => Err(session_invalid()),
        403 | 400 => Err(WriteRefusal::RemoteRefused.error()),
        _ => Err(write_failed()),
    }
}

/// [`ContactWriter`] and [`CalendarWriter`] over the logged-in Tuta
/// SDK. The rest client, base url and access token are constructor
/// arguments so the tests can substitute them; the SDK carries the
/// create and update cryptography.
pub struct TutaDavWriter {
    logged: Arc<LoggedInSdk>,
    rest: Arc<dyn RestClient>,
    base_url: String,
    access_token: String,
}

impl TutaDavWriter {
    pub fn new(
        logged: Arc<LoggedInSdk>,
        rest: Arc<dyn RestClient>,
        base_url: String,
        access_token: String,
    ) -> Self {
        Self {
            logged,
            rest,
            base_url,
            access_token,
        }
    }

    /// A fresh session key and the material that grants the owner
    /// group access to it: the same owner-encryption the draft path
    /// applies, keyed with the group's current symmetric key.
    async fn owner_key_material(
        &self,
        group_id: &str,
    ) -> Result<(SessionKeyMaterial, GenericAesKey)> {
        let group = GeneratedId(group_id.to_string());
        let group_key = self
            .logged
            .get_current_sym_group_key(&group)
            .await
            .map_err(|_| write_failed())?;
        let random = RandomizerFacade::from_core(OsRng);
        let session_key: GenericAesKey = Aes256Key::generate(&random).into();
        let owner_enc_session_key = group_key
            .object
            .encrypt_key(&session_key, InitializationVector::generate(&random));
        let owner_key_version = i64::try_from(group_key.version).map_err(|_| write_failed())?;
        Ok((
            SessionKeyMaterial {
                owner_enc_session_key,
                owner_key_version,
            },
            session_key,
        ))
    }

    /// The raw entity DELETE (decision 8): authenticated with the
    /// access token, `cv` and the type model version, like every
    /// other entity request the clients send.
    async fn delete_entity(
        &self,
        type_path: &str,
        list_id: &str,
        element_id: &str,
    ) -> Result<DeleteOutcome> {
        let url = entity_delete_url(&self.base_url, type_path, list_id, element_id);
        let mut headers = HashMap::new();
        headers.insert("cv".to_string(), CLIENT_VERSION.to_string());
        headers.insert("v".to_string(), TYPE_MODEL_VERSION.to_string());
        headers.insert("accessToken".to_string(), self.access_token.clone());
        let options = RestClientOptions {
            headers,
            body: None,
            suspension_behavior: Some(SuspensionBehavior::Suspend),
        };
        let response = self
            .rest
            .request_binary(url, HttpMethod::DELETE, options)
            .await
            .map_err(|_| write_failed())?;
        delete_outcome(response.status)
    }
}

#[async_trait::async_trait]
impl ContactWriter for TutaDavWriter {
    async fn put_contact(
        &self,
        list_id: &str,
        fields: &ContactFields,
        existing: Option<&ContactRef>,
        if_match: IfMatch<'_>,
    ) -> Result<ContactRef> {
        let crypto_client = self.logged.mail_facade().get_crypto_entity_client();
        if let Some(existing) = existing {
            let id = IdTupleGenerated::new(
                GeneratedId(existing.list_id.clone()),
                GeneratedId(existing.element_id.clone()),
            );
            let mut contact: Contact = crypto_client.load(&id).await.map_err(sdk_failure)?;
            // The precondition runs against the freshly loaded entity,
            // after the load and before anything is written: the
            // authority behind the handler's cached fast fail.
            check_contact_precondition(&contact, if_match)?;
            apply_contact_fields(&mut contact, fields);
            crypto_client
                .update_instance(contact)
                .await
                .map_err(sdk_failure)?;
            Ok(ContactRef {
                list_id: existing.list_id.clone(),
                element_id: existing.element_id.clone(),
            })
        } else {
            let owner_group = contact_owner_group(self.logged.get_user().memberships.iter())
                .ok_or_else(|| WriteRefusal::NoContactGroup.error())?;
            let (key, session_key) = self.owner_key_material(&owner_group).await?;
            let contact = contact_entity(fields, list_id, &owner_group, &key);
            let created = crypto_client
                .create_instance(contact, Some(session_key))
                .await
                .map_err(sdk_failure)?;
            let element_id = created.generatedId.ok_or_else(write_failed)?.0;
            Ok(ContactRef {
                list_id: list_id.to_string(),
                element_id,
            })
        }
    }

    async fn delete_contact(&self, id: &ContactRef) -> Result<DeleteOutcome> {
        self.delete_entity(CONTACT_PATH, &id.list_id, &id.element_id)
            .await
    }
}

#[async_trait::async_trait]
impl CalendarWriter for TutaDavWriter {
    async fn put_event(
        &self,
        _calendar: &CalendarRef,
        fields: &EventFields,
        existing: Option<&EventRef>,
        if_match: IfMatch<'_>,
    ) -> Result<EventRef> {
        let existing = update_target(existing)?;
        let crypto_client = self.logged.mail_facade().get_crypto_entity_client();
        let id = IdTupleCustom::new(
            GeneratedId(existing.list_id.clone()),
            CustomId(existing.element_id.clone()),
        );
        let mut event: CalendarEvent = crypto_client.load(&id).await.map_err(sdk_failure)?;
        // The attendee gate outranks the precondition: an event with
        // guests is never editable, so telling the client to reload and
        // retry would only lead it into the same refusal.
        attendee_gate(&event)?;
        // The precondition runs against the freshly loaded entity,
        // after the load and before anything is written.
        check_event_precondition(&event, if_match)?;
        apply_event_fields(&mut event, fields);
        crypto_client
            .update_instance(event)
            .await
            .map_err(sdk_failure)?;
        Ok(EventRef {
            list_id: existing.list_id.clone(),
            element_id: existing.element_id.clone(),
        })
    }

    async fn delete_event(&self, _calendar: &CalendarRef, id: &EventRef) -> Result<DeleteOutcome> {
        self.delete_entity(EVENT_PATH, &id.list_id, &id.element_id)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::carddav::import::parse_vcard;
    use crate::adapters::carddav::vcard::render_vcard;
    use crate::adapters::tuta::contact_source::contact_card;
    use crate::domain::{ContactField, ContactRelation, EventPerson};
    use tutasdk::entities::generated::tutanota::{Birthday, CalendarEventAttendee};

    fn key() -> SessionKeyMaterial {
        SessionKeyMaterial {
            owner_enc_session_key: b"owner-enc".to_vec(),
            owner_key_version: 7,
        }
    }

    fn membership(group_type: Option<i64>, group: &str) -> GroupMembership {
        GroupMembership {
            _id: None,
            symEncGKey: Vec::new(),
            admin: false,
            groupType: group_type,
            capability: None,
            groupKeyVersion: 0,
            symKeyVersion: 0,
            group: GeneratedId(group.into()),
            groupInfo: IdTupleGenerated::new(GeneratedId("i".into()), GeneratedId("e".into())),
            groupMember: IdTupleGenerated::new(GeneratedId("i".into()), GeneratedId("e".into())),
        }
    }

    fn fields() -> ContactFields {
        ContactFields {
            title: "Dr.".into(),
            first_name: "First".into(),
            middle_name: "Middle".into(),
            last_name: "Last".into(),
            name_suffix: "Jr.".into(),
            nickname: "Nick".into(),
            company: "Company".into(),
            department: "Dept".into(),
            role: "Role".into(),
            birthday: Some("2000-01-02".into()),
            anniversaries: vec!["2001-02-03".into()],
            comment: "Comment".into(),
            emails: vec![ContactField {
                kind: ContactFieldKind::Work,
                value: "a@b.example".into(),
            }],
            phones: vec![ContactField {
                kind: ContactFieldKind::Mobile,
                value: "123".into(),
            }],
            addresses: vec![ContactField {
                kind: ContactFieldKind::Home,
                value: "Street 1".into(),
            }],
            websites: vec![ContactField {
                kind: ContactFieldKind::Other,
                value: "https://x.example".into(),
            }],
            relations: vec![ContactRelation {
                kind: ContactRelationKind::Spouse,
                person: "P".into(),
            }],
        }
    }

    #[test]
    fn the_contact_owner_group_is_the_contact_membership_group() {
        let memberships = [
            membership(Some(2), "mail-group"),
            membership(Some(6), "contact-group"),
        ];
        assert_eq!(
            contact_owner_group(memberships.iter()),
            Some("contact-group".into())
        );
        let without = [membership(Some(2), "mail-group")];
        assert_eq!(contact_owner_group(without.iter()), None);
    }

    #[test]
    fn a_new_contact_maps_every_field_one_by_one() {
        let contact = contact_entity(&fields(), "list", "group", &key());
        assert_eq!(
            contact._id,
            Some(IdTupleGenerated {
                list_id: GeneratedId("list".into()),
                element_id: GeneratedId(String::new()),
            })
        );
        assert_eq!(contact._ownerGroup, Some(GeneratedId("group".into())));
        assert_eq!(
            contact._ownerEncSessionKey.as_deref(),
            Some(&b"owner-enc"[..])
        );
        assert_eq!(contact._ownerKeyVersion, Some(7));
        assert_eq!(contact._format, 0);
        assert_eq!(contact.firstName, "First");
        assert_eq!(contact.lastName, "Last");
        assert_eq!(contact.company, "Company");
        assert_eq!(contact.role, "Role");
        assert_eq!(contact.comment, "Comment");
        assert_eq!(contact.title.as_deref(), Some("Dr."));
        assert_eq!(contact.nickname.as_deref(), Some("Nick"));
        assert_eq!(contact.middleName.as_deref(), Some("Middle"));
        assert_eq!(contact.nameSuffix.as_deref(), Some("Jr."));
        assert_eq!(contact.department.as_deref(), Some("Dept"));
        assert_eq!(contact.birthdayIso.as_deref(), Some("2000-01-02"));
        assert_eq!(contact.mailAddresses.len(), 1);
        assert_eq!(contact.mailAddresses[0].r#type, 1);
        assert_eq!(contact.mailAddresses[0].address, "a@b.example");
        assert_eq!(contact.phoneNumbers[0].r#type, 2);
        assert_eq!(contact.phoneNumbers[0].number, "123");
        assert_eq!(contact.addresses[0].r#type, 0);
        assert_eq!(contact.addresses[0].address, "Street 1");
        assert_eq!(contact.websites[0].r#type, 2);
        assert_eq!(contact.websites[0].url, "https://x.example");
        assert_eq!(contact.relationships[0].r#type, 6);
        assert_eq!(contact.relationships[0].person, "P");
        assert_eq!(contact.customDate[0].r#type, 0);
        assert_eq!(contact.customDate[0].dateIso, "2001-02-03");
    }

    #[test]
    fn a_new_contact_keeps_the_web_client_defaults() {
        let contact = contact_entity(&ContactFields::default(), "list", "group", &key());
        assert_eq!(contact.firstName, "");
        assert_eq!(contact.lastName, "");
        assert_eq!(contact.company, "");
        assert_eq!(contact.role, "");
        assert_eq!(contact.comment, "");
        for value in [
            contact.title.as_deref(),
            contact.nickname.as_deref(),
            contact.middleName.as_deref(),
            contact.nameSuffix.as_deref(),
            contact.department.as_deref(),
        ] {
            assert_eq!(value, None);
        }
        assert_eq!(contact.birthdayIso, None);
        assert_eq!(contact.oldBirthdayDate, None);
        assert!(contact.oldBirthdayAggregate.is_none());
        assert_eq!(contact.presharedPassword, None);
        assert_eq!(contact.phoneticFirst, None);
        assert_eq!(contact.photo, None);
        assert!(contact.socialIds.is_empty());
        assert!(contact.messengerHandles.is_empty());
        assert!(contact.pronouns.is_empty());
        assert!(contact.mailAddresses.is_empty());
        // The aggregate rows carry no ids: the server assigns them on
        // create.
        assert!(contact._errors.is_empty());
    }

    /// The update the review's Thunderbird case describes: an edit of
    /// one property must not rewrite the rows the exporter cannot
    /// serve, and every rewritten row the exporter does serve must
    /// come back byte for byte.
    #[test]
    fn a_note_only_edit_keeps_every_unserved_field() {
        let mut contact = contact_entity(&fields(), "list", "group", &key());
        contact.mailAddresses = vec![ContactMailAddress {
            _id: Some(CustomId("mail-1".into())),
            r#type: 3,
            address: "gym@x.example".into(),
            customTypeName: "Gym".into(),
            _errors: Default::default(),
        }];
        contact.phoneNumbers = vec![ContactPhoneNumber {
            _id: Some(CustomId("tel-1".into())),
            r#type: 5,
            number: "555-0100".into(),
            customTypeName: "Signal".into(),
            _errors: Default::default(),
        }];
        contact.customDate = vec![
            ContactCustomDate {
                _id: Some(CustomId("date-1".into())),
                r#type: 0,
                customTypeName: String::new(),
                dateIso: "2001-02-03".into(),
                _errors: Default::default(),
            },
            ContactCustomDate {
                _id: Some(CustomId("date-2".into())),
                r#type: 1,
                customTypeName: "Name day".into(),
                dateIso: "--05-09".into(),
                _errors: Default::default(),
            },
        ];
        contact.relationships = vec![ContactRelationship {
            _id: Some(CustomId("rel-1".into())),
            r#type: 2,
            customTypeName: String::new(),
            person: "Sis".into(),
            _errors: Default::default(),
        }];
        // The labels on the Home address and the Other website are
        // synthetic: only a row emitted as loaded keeps them, which is
        // what these two lists now pin.
        contact.addresses = vec![ContactAddress {
            _id: Some(CustomId("addr-1".into())),
            r#type: 0,
            address: "Street 1".into(),
            customTypeName: "Address label".into(),
            _errors: Default::default(),
        }];
        contact.websites = vec![ContactWebsite {
            _id: Some(CustomId("site-1".into())),
            r#type: 2,
            customTypeName: "Site label".into(),
            url: "https://x.example".into(),
            _errors: Default::default(),
        }];
        let mut put = parse_vcard(&render_vcard(&contact_card(&contact).unwrap())).unwrap();
        put.comment = "Edited note".into();
        apply_contact_fields(&mut contact, &put);
        assert_eq!(contact.comment, "Edited note");
        assert_eq!(contact.mailAddresses.len(), 1);
        let mail = &contact.mailAddresses[0];
        assert!(mail._id.as_ref().is_some_and(|id| id.0 == "mail-1"));
        assert_eq!(mail.r#type, 3);
        assert_eq!(mail.customTypeName, "Gym");
        assert_eq!(mail.address, "gym@x.example");
        assert_eq!(contact.phoneNumbers.len(), 1);
        let phone = &contact.phoneNumbers[0];
        assert!(phone._id.as_ref().is_some_and(|id| id.0 == "tel-1"));
        assert_eq!(phone.r#type, 5);
        assert_eq!(phone.customTypeName, "Signal");
        assert_eq!(phone.number, "555-0100");
        assert_eq!(contact.customDate.len(), 2);
        let anniversary = &contact.customDate[0];
        assert!(anniversary._id.as_ref().is_some_and(|id| id.0 == "date-1"));
        assert_eq!(anniversary.r#type, 0);
        assert_eq!(anniversary.customTypeName, "");
        assert_eq!(anniversary.dateIso, "2001-02-03");
        let name_day = &contact.customDate[1];
        assert!(name_day._id.as_ref().is_some_and(|id| id.0 == "date-2"));
        assert_eq!(name_day.r#type, 1);
        assert_eq!(name_day.customTypeName, "Name day");
        assert_eq!(name_day.dateIso, "--05-09");
        assert_eq!(contact.relationships.len(), 1);
        let relation = &contact.relationships[0];
        assert!(relation._id.as_ref().is_some_and(|id| id.0 == "rel-1"));
        assert_eq!(relation.r#type, 2);
        assert_eq!(relation.person, "Sis");
        assert_eq!(contact.addresses.len(), 1);
        let address = &contact.addresses[0];
        assert!(address._id.as_ref().is_some_and(|id| id.0 == "addr-1"));
        assert_eq!(address.r#type, 0);
        assert_eq!(address.customTypeName, "Address label");
        assert_eq!(address.address, "Street 1");
        assert_eq!(contact.websites.len(), 1);
        let site = &contact.websites[0];
        assert!(site._id.as_ref().is_some_and(|id| id.0 == "site-1"));
        assert_eq!(site.r#type, 2, "the Other type survives the Custom echo");
        assert_eq!(site.customTypeName, "Site label");
        assert_eq!(site.url, "https://x.example");
    }

    #[test]
    fn every_relationship_type_round_trips() {
        let mut contact = contact_entity(&ContactFields::default(), "list", "group", &key());
        let mut rows: Vec<ContactRelationship> = (0..=11_i64)
            .map(|code| ContactRelationship {
                _id: Some(CustomId(format!("rel-{code}"))),
                r#type: code,
                customTypeName: format!("label{code}"),
                person: format!("p{code}"),
                _errors: Default::default(),
            })
            .collect();
        // The renderer skips a person-less relation, so the round trip
        // can never name this row: it must be dropped. That is what
        // makes a no-op merge fail.
        rows.push(ContactRelationship {
            _id: Some(CustomId("rel-empty".into())),
            r#type: 0,
            customTypeName: String::new(),
            person: String::new(),
            _errors: Default::default(),
        });
        contact.relationships = rows;
        let mut put = parse_vcard(&render_vcard(&contact_card(&contact).unwrap())).unwrap();
        assert_eq!(put.relations.len(), 12);
        // A person none of the loaded rows has: a new row, not a match.
        put.relations.push(ContactRelation {
            kind: ContactRelationKind::Parent,
            person: "new".into(),
        });
        apply_contact_fields(&mut contact, &put);
        assert_eq!(contact.relationships.len(), 13);
        for code in 0..=11_i64 {
            let row = &contact.relationships[code as usize];
            assert_eq!(row.r#type, code, "the loaded type {code} survives");
            assert!(row
                ._id
                .as_ref()
                .is_some_and(|id| id.0 == format!("rel-{code}")));
            assert_eq!(row.customTypeName, format!("label{code}"));
            assert_eq!(row.person, format!("p{code}"));
        }
        assert!(contact
            .relationships
            .iter()
            .all(|row| !row._id.as_ref().is_some_and(|id| id.0 == "rel-empty")));
        let new = &contact.relationships[12];
        assert_eq!(new.r#type, relation_code(ContactRelationKind::Parent));
        assert!(new._id.is_none());
        assert_eq!(new.customTypeName, "");
        assert_eq!(new.person, "new");
    }

    #[test]
    fn every_field_kind_round_trips_with_the_other_custom_collapse() {
        let mut contact = contact_entity(&ContactFields::default(), "list", "group", &key());
        contact.mailAddresses = (0..=3_i64)
            .map(|code| ContactMailAddress {
                _id: Some(CustomId(format!("mail-{code}"))),
                r#type: code,
                address: format!("mail-{code}@x.example"),
                customTypeName: format!("label{code}"),
                _errors: Default::default(),
            })
            .collect();
        // The renderer skips an empty address, so the round trip can
        // never name this row: it must be dropped.
        contact.mailAddresses.push(ContactMailAddress {
            _id: Some(CustomId("mail-empty".into())),
            r#type: 0,
            address: String::new(),
            customTypeName: String::new(),
            _errors: Default::default(),
        });
        contact.phoneNumbers = (0..=5_i64)
            .map(|code| ContactPhoneNumber {
                _id: Some(CustomId(format!("tel-{code}"))),
                r#type: code,
                number: format!("555-{code:04}"),
                customTypeName: format!("label{code}"),
                _errors: Default::default(),
            })
            .collect();
        contact.addresses = (0..=3_i64)
            .map(|code| ContactAddress {
                _id: Some(CustomId(format!("addr-{code}"))),
                r#type: code,
                address: format!("Street {code}"),
                customTypeName: format!("label{code}"),
                _errors: Default::default(),
            })
            .collect();
        contact.websites = (0..=3_i64)
            .map(|code| ContactWebsite {
                _id: Some(CustomId(format!("site-{code}"))),
                r#type: code,
                customTypeName: format!("label{code}"),
                url: format!("https://x.invalid/w{code}"),
                _errors: Default::default(),
            })
            .collect();
        let put = parse_vcard(&render_vcard(&contact_card(&contact).unwrap())).unwrap();
        apply_contact_fields(&mut contact, &put);
        assert_eq!(contact.mailAddresses.len(), 4);
        for code in 0..=3_i64 {
            let row = &contact.mailAddresses[code as usize];
            assert_eq!(row.r#type, code, "the loaded mail type {code} wins");
            assert!(row
                ._id
                .as_ref()
                .is_some_and(|id| id.0 == format!("mail-{code}")));
            assert_eq!(row.customTypeName, format!("label{code}"));
            assert_eq!(row.address, format!("mail-{code}@x.example"));
        }
        assert!(contact
            .mailAddresses
            .iter()
            .all(|row| !row._id.as_ref().is_some_and(|id| id.0 == "mail-empty")));
        assert_eq!(contact.phoneNumbers.len(), 6);
        for code in 0..=5_i64 {
            let row = &contact.phoneNumbers[code as usize];
            assert_eq!(row.r#type, code, "the loaded phone type {code} wins");
            assert!(row
                ._id
                .as_ref()
                .is_some_and(|id| id.0 == format!("tel-{code}")));
            assert_eq!(row.customTypeName, format!("label{code}"));
            assert_eq!(row.number, format!("555-{code:04}"));
        }
        assert_eq!(contact.addresses.len(), 4);
        for code in 0..=3_i64 {
            let row = &contact.addresses[code as usize];
            assert_eq!(row.r#type, code, "the loaded address type {code} wins");
            assert!(row
                ._id
                .as_ref()
                .is_some_and(|id| id.0 == format!("addr-{code}")));
            assert_eq!(row.customTypeName, format!("label{code}"));
            assert_eq!(row.address, format!("Street {code}"));
        }
        assert_eq!(contact.websites.len(), 4);
        for code in 0..=3_i64 {
            let row = &contact.websites[code as usize];
            assert_eq!(row.r#type, code, "the loaded website type {code} wins");
            assert!(row
                ._id
                .as_ref()
                .is_some_and(|id| id.0 == format!("site-{code}")));
            assert_eq!(row.customTypeName, format!("label{code}"));
            assert_eq!(row.url, format!("https://x.invalid/w{code}"));
        }
    }

    #[test]
    fn unmatched_rows_are_replaced_and_new_rows_carry_no_id() {
        let mut contact = contact_entity(&ContactFields::default(), "list", "group", &key());
        contact.mailAddresses = vec![
            ContactMailAddress {
                _id: Some(CustomId("mail-old-1".into())),
                r#type: 1,
                address: "old-one@x.example".into(),
                customTypeName: String::new(),
                _errors: Default::default(),
            },
            ContactMailAddress {
                _id: Some(CustomId("mail-old-2".into())),
                r#type: 1,
                address: "old-two@x.example".into(),
                customTypeName: String::new(),
                _errors: Default::default(),
            },
        ];
        contact.phoneNumbers = vec![ContactPhoneNumber {
            _id: Some(CustomId("tel-old".into())),
            r#type: 2,
            number: "111".into(),
            customTypeName: String::new(),
            _errors: Default::default(),
        }];
        contact.relationships = vec![ContactRelationship {
            _id: Some(CustomId("rel-old".into())),
            r#type: 1,
            customTypeName: String::new(),
            person: "Old".into(),
            _errors: Default::default(),
        }];
        contact.customDate = vec![ContactCustomDate {
            _id: Some(CustomId("date-old".into())),
            r#type: 0,
            customTypeName: String::new(),
            dateIso: "1999-01-01".into(),
            _errors: Default::default(),
        }];
        let next = ContactFields {
            // An unset nullable text clears the stored value.
            title: "New".into(),
            emails: vec![ContactField {
                kind: ContactFieldKind::Work,
                value: "new@x.example".into(),
            }],
            phones: vec![ContactField {
                kind: ContactFieldKind::Mobile,
                value: "222".into(),
            }],
            relations: vec![ContactRelation {
                kind: ContactRelationKind::Sibling,
                person: "New".into(),
            }],
            anniversaries: vec!["2001-02-03".into()],
            ..ContactFields::default()
        };
        apply_contact_fields(&mut contact, &next);
        assert_eq!(contact.title.as_deref(), Some("New"));
        assert_eq!(contact.nickname, None);
        assert_eq!(contact.mailAddresses.len(), 1);
        let mail = &contact.mailAddresses[0];
        assert!(mail._id.is_none());
        assert_eq!(mail.customTypeName, "");
        assert_eq!(mail.address, "new@x.example");
        assert!(contact.mailAddresses.iter().all(|row| !row
            ._id
            .as_ref()
            .is_some_and(|id| id.0 == "mail-old-1" || id.0 == "mail-old-2")));
        assert_eq!(contact.phoneNumbers.len(), 1);
        assert!(contact.phoneNumbers[0]._id.is_none());
        assert_eq!(contact.phoneNumbers[0].customTypeName, "");
        assert_eq!(contact.relationships.len(), 1);
        assert!(contact.relationships[0]._id.is_none());
        assert_eq!(contact.relationships[0].customTypeName, "");
        assert_eq!(contact.customDate.len(), 1);
        assert!(contact.customDate[0]._id.is_none());
        assert_eq!(contact.customDate[0].customTypeName, "");
        assert_eq!(contact.customDate[0].dateIso, "2001-02-03");
        // The Other/Custom tolerance is not a free pass: a loaded Home
        // row and an incoming Custom field with the SAME value differ
        // in kind and must not match.
        let mut contact = contact_entity(&ContactFields::default(), "list", "group", &key());
        contact.mailAddresses = vec![ContactMailAddress {
            _id: Some(CustomId("mail-home".into())),
            r#type: address_code(ContactFieldKind::Home),
            address: "same@x.example".into(),
            customTypeName: String::new(),
            _errors: Default::default(),
        }];
        let next = ContactFields {
            emails: vec![ContactField {
                kind: ContactFieldKind::Custom,
                value: "same@x.example".into(),
            }],
            ..ContactFields::default()
        };
        apply_contact_fields(&mut contact, &next);
        assert_eq!(contact.mailAddresses.len(), 1);
        let mail = &contact.mailAddresses[0];
        assert!(mail._id.is_none());
        assert_eq!(mail.r#type, address_code(ContactFieldKind::Custom));
        // Same once more, with an incoming Other field.
        let mut contact = contact_entity(&ContactFields::default(), "list", "group", &key());
        contact.mailAddresses = vec![ContactMailAddress {
            _id: Some(CustomId("mail-home-2".into())),
            r#type: address_code(ContactFieldKind::Home),
            address: "same@x.example".into(),
            customTypeName: String::new(),
            _errors: Default::default(),
        }];
        let next = ContactFields {
            emails: vec![ContactField {
                kind: ContactFieldKind::Other,
                value: "same@x.example".into(),
            }],
            ..ContactFields::default()
        };
        apply_contact_fields(&mut contact, &next);
        assert_eq!(contact.mailAddresses.len(), 1);
        let mail = &contact.mailAddresses[0];
        assert!(mail._id.is_none());
        assert_eq!(mail.r#type, address_code(ContactFieldKind::Other));
    }

    #[test]
    fn applying_fields_clears_the_legacy_birthday_aggregate() {
        let mut contact = contact_entity(&fields(), "list", "group", &key());
        // A legacy contact keeps the birthday only in the aggregate.
        contact.birthdayIso = None;
        contact.oldBirthdayAggregate = Some(Birthday {
            _id: None,
            day: 2,
            month: 9,
            year: Some(2000),
        });
        // The fallback really supplies the birthday before the update.
        assert_eq!(
            contact_card(&contact).unwrap().birthday,
            Some("2000-09-02".into())
        );
        let loaded_id = contact._id.clone();
        apply_contact_fields(&mut contact, &ContactFields::default());
        assert!(contact.oldBirthdayAggregate.is_none());
        // The update keeps the identity and owner encryption it loaded.
        assert_eq!(contact._id, loaded_id);
        assert_eq!(
            contact._ownerEncSessionKey.as_deref(),
            Some(&b"owner-enc"[..])
        );
        assert_eq!(contact._ownerKeyVersion, Some(7));
        // The reader falls back to the aggregate when `birthdayIso` is
        // empty: clearing it is what keeps a removed `BDAY` removed.
        assert_eq!(contact_card(&contact).unwrap().birthday, None);
        contact.oldBirthdayAggregate = Some(Birthday {
            _id: None,
            day: 2,
            month: 9,
            year: Some(2000),
        });
        let next = ContactFields {
            birthday: Some("2000-01-02".into()),
            ..ContactFields::default()
        };
        apply_contact_fields(&mut contact, &next);
        assert!(contact.oldBirthdayAggregate.is_none());
    }

    fn event_fields() -> EventFields {
        EventFields {
            summary: "Summary".into(),
            description: "Description".into(),
            location: "Location".into(),
            start_ms: 1_700_000_000_000,
            end_ms: 1_700_003_600_000,
            all_day: false,
            time_zone: Some("Europe/Rome".into()),
            repeat: Some(RepeatRule {
                frequency: 1,
                interval: 2,
                end_type: 1,
                end_value: Some(5),
                time_zone: "Europe/Rome".into(),
                excluded_ms: vec![1_700_000_000_000],
                advanced: vec![(2, "MO".into())],
            }),
            uid: Some("uid-1".into()),
            organizer: Some(EventPerson {
                name: "Me".into(),
                address: "me@tuta.example".into(),
            }),
        }
    }

    /// A loaded event fixture shaped like the update path sees one: the
    /// fields of `event_fields()` as stored, with `uid` as the stored
    /// identity.
    fn stored_event(uid: &str) -> CalendarEvent {
        let fields = event_fields();
        let (start_zone, end_zone) = event_zones(&fields).unwrap_or_default();
        CalendarEvent {
            _id: Some(IdTupleCustom {
                list_id: GeneratedId("list".into()),
                element_id: CustomId("element".into()),
            }),
            _permissions: Default::default(),
            _format: 0,
            _ownerGroup: Some(GeneratedId("group".into())),
            _ownerEncSessionKey: Some(b"owner-enc".to_vec()),
            _ownerKeyVersion: Some(7),
            _kdfNonce: None,
            summary: "Stored summary".into(),
            description: "Stored description".into(),
            startTime: date_time(fields.start_ms),
            endTime: date_time(fields.end_ms),
            location: "Stored location".into(),
            uid: Some(uid.to_string()),
            hashedUid: None,
            sequence: 0,
            invitedConfidentially: Some(false),
            recurrenceId: None,
            sender: None,
            pendingInvitation: Some(false),
            startTimeZone: start_zone,
            endTimeZone: end_zone,
            repeatRule: fields.repeat.as_ref().map(|rule| repeat_rule(rule, None)),
            alarmInfos: Vec::new(),
            attendees: Vec::new(),
            organizer: fields.organizer.as_ref().map(event_organizer),
            _errors: Default::default(),
        }
    }

    fn attendee(address: &str) -> CalendarEventAttendee {
        CalendarEventAttendee {
            _id: None,
            status: 1,
            address: EncryptedMailAddress {
                _id: None,
                name: "Guest".into(),
                address: address.into(),
                _errors: Default::default(),
            },
            _errors: Default::default(),
        }
    }

    #[test]
    fn an_event_create_is_refused_with_the_creation_sentence() {
        let error = update_target(None).err().unwrap();
        assert_eq!(
            error.to_string(),
            "unsupported: creating events is not supported: create them in the Tuta client, \
then edit them here"
        );
        let existing = EventRef {
            list_id: "list".into(),
            element_id: "element".into(),
        };
        assert_eq!(
            update_target(Some(&existing)).unwrap().element_id,
            "element"
        );
    }

    #[test]
    fn a_loaded_event_with_a_foreign_attendee_is_refused() {
        let mut event = stored_event("uid-1");
        // Without an organizer every attendee counts.
        event.organizer = None;
        event.attendees = vec![attendee("guest@x.example")];
        let error = attendee_gate(&event).err().unwrap();
        assert_eq!(
            error.to_string(),
            "unsupported: events with attendees cannot be edited through the bridge"
        );

        // The organizer itself, only letter case differing, is not
        // foreign.
        event.organizer = Some(EncryptedMailAddress {
            _id: None,
            name: String::new(),
            address: "me@tuta.example".into(),
            _errors: Default::default(),
        });
        event.attendees = vec![attendee("ME@TUTA.EXAMPLE")];
        assert!(attendee_gate(&event).is_ok());

        // Any other address is foreign, even beside the organizer.
        event.attendees.push(attendee("guest@x.example"));
        assert!(matches!(attendee_gate(&event), Err(Error::Unsupported(_))));

        // No attendees at all: the ordinary update path.
        event.attendees.clear();
        assert!(attendee_gate(&event).is_ok());
    }

    #[test]
    fn an_echoed_description_keeps_the_stored_html() {
        let mut event = stored_event("stored-uid");
        event.description = "<p>Description</p>".into();
        let mut fields = event_fields();
        fields.summary = "Edited title".into();
        // A title-only edit leaves the stored HTML untouched.
        apply_event_fields(&mut event, &fields);
        assert_eq!(event.description, "<p>Description</p>");

        // A changed description is regenerated as HTML.
        fields.description = "one\ntwo".into();
        apply_event_fields(&mut event, &fields);
        assert_eq!(event.description, text_to_html("one\ntwo"));
        assert!(event.description.contains("<br>"));

        // An empty stored description takes the incoming text.
        event.description = String::new();
        apply_event_fields(&mut event, &fields);
        assert_eq!(event.description, text_to_html("one\ntwo"));
    }

    #[test]
    fn a_utc_form_body_keeps_the_stored_zones() {
        let mut event = stored_event("stored-uid");
        event.startTimeZone = Some("Europe/Berlin".into());
        event.endTimeZone = Some("Europe/Berlin".into());
        let mut fields = event_fields();
        fields.time_zone = None;
        apply_event_fields(&mut event, &fields);
        assert_eq!(event.startTimeZone.as_deref(), Some("Europe/Berlin"));
        assert_eq!(event.endTimeZone.as_deref(), Some("Europe/Berlin"));

        fields.time_zone = Some("Europe/Rome".into());
        apply_event_fields(&mut event, &fields);
        assert_eq!(event.startTimeZone.as_deref(), Some("Europe/Rome"));
        assert_eq!(event.endTimeZone.as_deref(), Some("Europe/Rome"));
    }

    #[test]
    fn a_utc_form_body_keeps_the_loaded_rule_zone() {
        let mut event = stored_event("stored-uid");
        event.repeatRule.as_mut().unwrap().timeZone = "Europe/Berlin".into();
        let mut fields = event_fields();
        // The UTC form names no zone: the applied rule keeps the
        // series' wall-clock anchor.
        fields.time_zone = None;
        apply_event_fields(&mut event, &fields);
        assert_eq!(event.repeatRule.as_ref().unwrap().timeZone, "Europe/Berlin");

        // An explicit TZID uses the fields' zone as before.
        fields.time_zone = Some("Europe/Rome".into());
        apply_event_fields(&mut event, &fields);
        assert_eq!(event.repeatRule.as_ref().unwrap().timeZone, "Europe/Rome");
    }

    #[test]
    fn a_same_address_organizer_keeps_the_stored_name() {
        let mut event = stored_event("stored-uid");
        event.organizer = Some(EncryptedMailAddress {
            _id: None,
            name: "Stored Name".into(),
            address: "me@tuta.example".into(),
            _errors: Default::default(),
        });
        let mut fields = event_fields();
        fields.organizer = Some(EventPerson {
            name: String::new(),
            address: "ME@TUTA.EXAMPLE".into(),
        });
        apply_event_fields(&mut event, &fields);
        assert_eq!(event.organizer.as_ref().unwrap().name, "Stored Name");
        assert_eq!(event.organizer.as_ref().unwrap().address, "ME@TUTA.EXAMPLE");

        // A different address keeps the fields' (empty) name.
        fields.organizer = Some(EventPerson {
            name: String::new(),
            address: "other@tuta.example".into(),
        });
        apply_event_fields(&mut event, &fields);
        assert_eq!(event.organizer.as_ref().unwrap().name, "");
        assert_eq!(
            event.organizer.as_ref().unwrap().address,
            "other@tuta.example"
        );
    }

    #[test]
    fn a_legacy_uid_repair_hashes_the_uid_like_the_web_client() {
        let mut event = stored_event("filled-later");
        event.uid = None;
        event.hashedUid = None;
        let mut fields = event_fields();
        fields.uid = Some("client-uid".into());
        apply_event_fields(&mut event, &fields);
        assert_eq!(event.uid.as_deref(), Some("client-uid"));
        assert_eq!(event.hashedUid, Some(sha256(b"client-uid")));

        // A stored uid is identity: neither it nor its hash changes.
        let mut stored = stored_event("stored-uid");
        stored.hashedUid = Some(vec![1, 2, 3]);
        apply_event_fields(&mut stored, &fields);
        assert_eq!(stored.uid.as_deref(), Some("stored-uid"));
        assert_eq!(stored.hashedUid, Some(vec![1, 2, 3]));
    }

    #[test]
    fn an_all_day_edit_clears_the_zones_and_times_clamp_to_the_epoch() {
        let mut event = stored_event("stored-uid");
        let mut fields = event_fields();
        fields.all_day = true;
        fields.time_zone = Some("Europe/Rome".into());
        fields.start_ms = -1;
        apply_event_fields(&mut event, &fields);
        assert_eq!(event.startTimeZone, None);
        assert_eq!(event.endTimeZone, None);
        assert_eq!(event.startTime.as_millis(), 0);
    }

    #[test]
    fn applying_event_fields_keeps_identity_and_bumps_the_sequence() {
        let mut event = stored_event("stored-uid");
        event.sequence = 3;
        event.alarmInfos = vec![IdTupleGenerated::new(
            GeneratedId("alarms".into()),
            GeneratedId("alarm".into()),
        )];
        event.attendees = vec![attendee("guest@x.example")];
        event.repeatRule.as_mut().unwrap()._id = Some(CustomId("rule-id".into()));

        let mut fields = event_fields();
        fields.summary = "Edited".into();
        fields.uid = Some("client-uid".into());
        fields.repeat = Some(RepeatRule {
            frequency: 1,
            interval: 1,
            end_type: 0,
            end_value: None,
            time_zone: "Europe/Rome".into(),
            excluded_ms: Vec::new(),
            advanced: Vec::new(),
        });
        apply_event_fields(&mut event, &fields);
        assert_eq!(event.summary, "Edited");
        // The stored uid is identity: the client's uid does not replace it.
        assert_eq!(event.uid.as_deref(), Some("stored-uid"));
        // Every edit bumps the sequence, like the web client's editor.
        assert_eq!(event.sequence, 4);
        // The progenitor's rule keeps its id.
        assert!(event
            .repeatRule
            .as_ref()
            .unwrap()
            ._id
            .as_ref()
            .is_some_and(|id| id.0 == "rule-id"));
        assert_eq!(event.repeatRule.as_ref().unwrap().endType, 0);
        // Alarms and attendees are never touched by a write.
        assert_eq!(event.alarmInfos.len(), 1);
        assert_eq!(event.attendees.len(), 1);
        // No repeat left: the rule is cleared.
        let mut cleared = event_fields();
        cleared.repeat = None;
        apply_event_fields(&mut event, &cleared);
        assert!(event.repeatRule.is_none());
        assert_eq!(event.sequence, 5);
    }

    #[test]
    fn the_event_list_follows_the_repeat_rule() {
        let calendar = CalendarRef {
            group_id: "group".into(),
            short_list_id: "short".into(),
            long_list_id: "long".into(),
        };
        let mut fields = event_fields();
        fields.repeat = None;
        fields.start_ms = 1_700_000_000_000;
        fields.end_ms = fields.start_ms + 3_600_000;
        assert_eq!(choose_event_list(&calendar, &fields), "short");
        // The web client's `isLongEvent` boundary is strict: exactly
        // 15 days still fits the event-id randomization range.
        let days_shifted = i64::try_from(DAYS_SHIFTED_MS).unwrap();
        fields.end_ms = fields.start_ms + days_shifted;
        assert_eq!(choose_event_list(&calendar, &fields), "short");
        fields.end_ms += 1;
        assert_eq!(choose_event_list(&calendar, &fields), "long");
        fields.end_ms = fields.start_ms + 3_600_000;
        // Any repeat rule files the event into the long list, a
        // COUNT- or UNTIL-bounded one included.
        let unbounded = RepeatRule {
            frequency: 1,
            interval: 1,
            end_type: 0,
            end_value: None,
            time_zone: "UTC".into(),
            excluded_ms: Vec::new(),
            advanced: Vec::new(),
        };
        fields.repeat = Some(unbounded.clone());
        assert_eq!(choose_event_list(&calendar, &fields), "long");
        let mut bounded = unbounded.clone();
        bounded.end_type = 1;
        bounded.end_value = Some(10);
        fields.repeat = Some(bounded);
        assert_eq!(choose_event_list(&calendar, &fields), "long");
        let mut until = unbounded;
        until.end_type = 2;
        until.end_value = Some(1_700_000_000_000);
        fields.repeat = Some(until);
        assert_eq!(choose_event_list(&calendar, &fields), "long");
    }

    #[test]
    fn the_delete_url_is_the_entity_rest_path() {
        assert_eq!(
            entity_delete_url("https://tuta.example", "contact", "list", "element"),
            "https://tuta.example/rest/tutanota/contact/list/element"
        );
        assert_eq!(
            entity_delete_url("https://tuta.example", "calendarevent", "l", "e"),
            "https://tuta.example/rest/tutanota/calendarevent/l/e"
        );
    }

    #[test]
    fn delete_responses_map_to_outcomes_and_fixed_errors() {
        assert!(matches!(delete_outcome(200), Ok(DeleteOutcome::Deleted)));
        assert!(matches!(delete_outcome(204), Ok(DeleteOutcome::Deleted)));
        assert!(matches!(delete_outcome(404), Ok(DeleteOutcome::Gone)));
        assert_eq!(
            delete_outcome(401).unwrap_err().to_string(),
            "login failed: session is no longer valid; run login again"
        );
        // A 403 (NotAuthorized, for example a read-only share) and a
        // 400 are permanent: the fixed refusal the handler answers
        // with `403`, never a session error and never the retry.
        assert_eq!(
            delete_outcome(403).unwrap_err().to_string(),
            "unsupported: the remote server refused the write"
        );
        assert_eq!(
            delete_outcome(400).unwrap_err().to_string(),
            "unsupported: the remote server refused the write"
        );
        assert_eq!(
            delete_outcome(500).unwrap_err().to_string(),
            "network error: dav write failed"
        );
    }

    /// The reader's own chain names the loaded contact's version, so a
    /// matching `If-Match` passes, a stale one refuses before anything
    /// is written, and a card that cannot be rendered fails closed.
    #[test]
    fn a_contact_precondition_matches_the_readers_own_etag() {
        let contact = contact_entity(&fields(), "list", "group", &key());
        let etag = loaded_contact_etag(&contact).unwrap();
        assert_eq!(
            etag,
            vcard_etag(&render_vcard(&contact_card(&contact).unwrap()))
        );
        assert!(check_contact_precondition(&contact, Some(&etag)).is_ok());
        // A list of candidates, `*`, quoting: the strong comparison
        // of the DAV layer, not plain equality.
        assert!(check_contact_precondition(&contact, Some(&format!("\"other\", {etag}"))).is_ok());
        assert!(check_contact_precondition(&contact, Some("*")).is_ok());
        assert!(check_contact_precondition(&contact, None).is_ok());
        let error = check_contact_precondition(&contact, Some("\"stale\""))
            .err()
            .unwrap();
        assert_eq!(
            error.to_string(),
            "unsupported: the stored version changed since the client read it"
        );
        // A different content answers a different etag, so the stale
        // check catches the web client's edit.
        let mut edited = contact_entity(&fields(), "list", "group", &key());
        edited.comment = "Edited comment".into();
        assert_ne!(loaded_contact_etag(&edited).unwrap(), etag);
        // A contact the reader cannot serve cannot be verified: fail
        // closed, never with a silent overwrite.
        let mut broken = contact_entity(&fields(), "list", "group", &key());
        broken._id = None;
        assert_eq!(loaded_contact_etag(&broken), None);
        let error = check_contact_precondition(&broken, Some(&etag))
            .err()
            .unwrap();
        assert_eq!(
            error.to_string(),
            "unsupported: the stored version changed since the client read it"
        );
    }

    /// The reader's own fingerprint names the loaded event's content,
    /// which is the token the handler passes for the stored row.
    #[test]
    fn an_event_precondition_matches_the_readers_own_fingerprint() {
        let event = stored_event("uid-1");
        let fingerprint = loaded_event_fingerprint(&event).unwrap();
        assert!(check_event_precondition(&event, Some(&fingerprint)).is_ok());
        assert!(check_event_precondition(&event, None).is_ok());
        let error = check_event_precondition(&event, Some("stale"))
            .err()
            .unwrap();
        assert_eq!(
            error.to_string(),
            "unsupported: the stored version changed since the client read it"
        );
        // An edit made in the web client changes the fingerprint, so
        // the client's stale token no longer names the content.
        let mut edited = stored_event("uid-1");
        edited.summary = "Edited summary".into();
        assert_ne!(loaded_event_fingerprint(&edited).unwrap(), fingerprint);
        // An event the reader cannot serve fails closed.
        let mut broken = stored_event("uid-1");
        broken._id = None;
        assert_eq!(loaded_event_fingerprint(&broken), None);
        assert!(matches!(
            check_event_precondition(&broken, Some(&fingerprint)),
            Err(Error::Unsupported(_))
        ));
    }
}
