//! The write seams of the CardDAV and CalDAV servers: contacts and
//! calendar events.
//!
//! Every call either applies the whole change remotely or fails; the
//! caller updates its cache only after a call succeeded. The event bus
//! later delivers the echo of the same change, which the caches apply
//! idempotently. Errors carry fixed messages only: never ids, names,
//! addresses or titles.
//!
//! An update takes the request's precondition in `if_match`, already
//! verified by the handler against its cached row (the fast fail). The
//! writer re-checks it against the freshly loaded entity and answers
//! [`WriteRefusal::StoredVersionChanged`] when they disagree — the
//! authority is the loaded entity, never the cache — so a write cannot
//! overwrite a remote edit the event bus has not delivered yet. The
//! handlers answer that refusal with the same fixed `412` every
//! precondition failure answers, every other [`WriteRefusal`] with a
//! `403` carrying its fixed message, and let everything else (a session
//! error, a transport failure) reach the session layer.
//!
//! Like every data-carrying port type, these types do not implement
//! `Debug`: they hold personal data.

use std::sync::Arc;

use crate::domain::{ContactField, ContactRelation, EventPerson, RepeatRule, Result};

/// The `(list id, element id)` of a `Contact`, exactly as the store
/// keeps it.
#[derive(Clone, PartialEq, Eq)]
pub struct ContactRef {
    pub list_id: String,
    pub element_id: String,
}

/// A Tuta calendar as the writer addresses it: the group that owns the
/// events and its two event lists.
#[derive(Clone, PartialEq, Eq)]
pub struct CalendarRef {
    /// The calendar group id; the owner group of the calendar's
    /// events.
    pub group_id: String,
    /// The list of short events (non-repeating or bounded).
    pub short_list_id: String,
    /// The list of long and repeating events.
    pub long_list_id: String,
}

/// The `(list id, element id)` of a `CalendarEvent`.
#[derive(Clone, PartialEq, Eq)]
pub struct EventRef {
    pub list_id: String,
    pub element_id: String,
}

/// The writable fields of one contact: what the vCard importer maps,
/// the same set the reader serves.
///
/// Empty strings mean "not set", like the domain card.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct ContactFields {
    pub title: String,
    pub first_name: String,
    pub middle_name: String,
    pub last_name: String,
    pub name_suffix: String,
    pub nickname: String,
    pub company: String,
    pub department: String,
    pub role: String,
    /// Tuta's ISO form (`YYYY-MM-DD`, or `--MM-DD` without a year).
    pub birthday: Option<String>,
    /// Anniversaries (Tuta's custom dates of the anniversary kind).
    pub anniversaries: Vec<String>,
    pub comment: String,
    pub emails: Vec<ContactField>,
    pub phones: Vec<ContactField>,
    pub addresses: Vec<ContactField>,
    pub websites: Vec<ContactField>,
    pub relations: Vec<ContactRelation>,
}

/// The writable fields of one event: what the iCalendar importer maps,
/// the same set the reader serves.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct EventFields {
    pub summary: String,
    pub description: String,
    pub location: String,
    /// UTC start, in milliseconds. All-day events start at UTC
    /// midnight.
    pub start_ms: i64,
    /// UTC end (exclusive), in milliseconds.
    pub end_ms: i64,
    /// Whether the event is all-day: both bounds sit on UTC midnight
    /// and no time zone is stored.
    pub all_day: bool,
    /// The IANA zone of a timed event; `None` keeps floating times.
    /// Ignored on an all-day event.
    pub time_zone: Option<String>,
    pub repeat: Option<RepeatRule>,
    /// The event's `UID`: applied when the event is created (the
    /// identifier the clients and the cache key on); an update keeps
    /// the stored uid, which the web client treats as identity.
    /// `None` on create generates one the way the web client does.
    pub uid: Option<String>,
    pub organizer: Option<EventPerson>,
}

/// The precondition of one write: the version the client read, as the
/// handler already verified it against its cached row with the
/// request's `If-Match` (the fast fail). A contact write re-checks the
/// raw header against the strong ETag it derives from the freshly
/// loaded card — the same ETag the reader serves, so the check needs
/// nothing the handler knows. An event write cannot recompute the
/// served resource ETag (it embeds the row's first-seen stamp, which no
/// freshly loaded entity carries), so the handler passes the stored
/// row's content fingerprint instead: for an update, the master row's
/// (the version of the very event the update writes); for a delete,
/// each row's own (the resource is every row of the series). `None`
/// (no header) lets the write through without a check.
///
/// `Some("*")` pins existence only: a conditional write freshly loads
/// the entity and refuses with [`WriteRefusal::StoredVersionChanged`]
/// when the load finds it gone, never comparing `*` to a version. An
/// unconditional delete issues the raw delete without a load and
/// answers [`DeleteOutcome::Gone`] for a vanished entity.
pub type IfMatch<'a> = Option<&'a str>;

/// A fixed refusal of a write, carried as an
/// [`Error::Unsupported`](crate::domain::Error::Unsupported) with a
/// fixed message. The messages are a closed set the handlers
/// recognize and answer: [`WriteRefusal::StoredVersionChanged`] with
/// the fixed `412` every precondition failure answers, every other
/// refusal with `403` and its own message — a permanent refusal a
/// client must not retry. Everything else a writer answers (a session
/// error, a transport failure) propagates untouched.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WriteRefusal {
    /// The freshly loaded entity no longer matches the version the
    /// client's `If-Match` named; the write did not happen. The
    /// handler answers `412`, so the client reloads and retries.
    StoredVersionChanged,
    /// The remote server refused the write for good (403/400: a
    /// read-only share, a rejected payload). The handler answers
    /// `403`, never the retry `503`.
    RemoteRefused,
    /// The stored event carries attendees the bridge cannot keep in
    /// step, so it never edits such an event.
    AttendeesRefused,
    /// The stored contact cannot be edited through the bridge: its
    /// decryption errors leave fields the bridge cannot render and
    /// merge safely. The handler answers `403`, never a silent
    /// partial write.
    ContactDecryptionFailed,
    /// Creating events is upstream-blocked: the pinned SDK cannot
    /// create Tuta's custom-id events.
    CreateRefused,
    /// The account has no contact group to create a contact in.
    NoContactGroup,
}

impl WriteRefusal {
    /// The fixed message of this refusal.
    pub fn message(self) -> &'static str {
        match self {
            Self::StoredVersionChanged => "the stored version changed since the client read it",
            Self::RemoteRefused => "the remote server refused the write",
            Self::AttendeesRefused => "events with attendees cannot be edited through the bridge",
            Self::ContactDecryptionFailed => {
                "contacts with decryption errors cannot be edited through the bridge"
            }
            Self::CreateRefused => {
                "creating events is not supported: create them in the Tuta client, then edit them here"
            }
            Self::NoContactGroup => "this account has no contact group",
        }
    }

    /// This refusal as a writer error.
    pub fn error(self) -> crate::domain::Error {
        crate::domain::Error::Unsupported(self.message().into())
    }

    /// The refusal this writer error carries, when it carries one.
    /// Recognition is by the fixed message, so a foreign `Unsupported`
    /// text is never mistaken for one of these.
    pub fn of(error: &crate::domain::Error) -> Option<Self> {
        let crate::domain::Error::Unsupported(message) = error else {
            return None;
        };
        const ALL: [WriteRefusal; 6] = [
            WriteRefusal::StoredVersionChanged,
            WriteRefusal::RemoteRefused,
            WriteRefusal::AttendeesRefused,
            WriteRefusal::ContactDecryptionFailed,
            WriteRefusal::CreateRefused,
            WriteRefusal::NoContactGroup,
        ];
        ALL.into_iter()
            .find(|refusal| refusal.message() == message.as_str())
    }
}

/// The outcome of a delete: the caller answers a vanished entity with
/// its own "not found" instead of a tombstone.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DeleteOutcome {
    /// The entity was deleted by this call.
    Deleted,
    /// The entity no longer existed remotely.
    Gone,
}

/// The contact write seam towards Tuta.
///
/// `put_contact` creates a contact when `existing` is `None` and
/// updates the referenced one in place otherwise, answering with the
/// id the change landed on. On an update, `if_match` (the request's
/// `If-Match` header) is re-checked against the freshly loaded card's
/// strong ETag — the reader's own derivation — and a mismatch refuses
/// with [`WriteRefusal::StoredVersionChanged`] before anything is
/// written. Errors carry fixed text only.
#[async_trait::async_trait]
pub trait ContactWriter: Send + Sync {
    async fn put_contact(
        &self,
        list_id: &str,
        fields: &ContactFields,
        existing: Option<&ContactRef>,
        if_match: IfMatch<'_>,
    ) -> Result<ContactRef>;

    /// Delete one contact; [`DeleteOutcome::Gone`] when it had already
    /// vanished remotely. A condition (the request's `If-Match`, already
    /// verified against the cached row by the handler) is re-checked
    /// against the freshly loaded card — `*` pins existence — and a
    /// vanished or mismatching entity refuses with
    /// [`WriteRefusal::StoredVersionChanged`] before anything is
    /// deleted. `None` deletes unconditionally.
    async fn delete_contact(&self, id: &ContactRef, if_match: IfMatch<'_>)
        -> Result<DeleteOutcome>;
}

/// The calendar write seam towards Tuta.
///
/// `put_event` creates an event when `existing` is `None` — filed
/// into the calendar's short or long event list by its repeat rule —
/// and updates the referenced one otherwise, answering with the id
/// the change landed on. On an update, `if_match` (the content
/// fingerprint of the stored master row the handler verified against
/// the request's `If-Match`) is re-checked against the freshly loaded
/// event's fingerprint — the reader's own derivation — and a mismatch
/// refuses with [`WriteRefusal::StoredVersionChanged`] before anything
/// is written. Errors carry fixed text only.
#[async_trait::async_trait]
pub trait CalendarWriter: Send + Sync {
    async fn put_event(
        &self,
        calendar: &CalendarRef,
        fields: &EventFields,
        existing: Option<&EventRef>,
        if_match: IfMatch<'_>,
    ) -> Result<EventRef>;

    /// Delete one event; [`DeleteOutcome::Gone`] when it had already
    /// vanished remotely. A condition (the handler's per-row token:
    /// that row's cached content fingerprint, or `*` for existence) is
    /// re-checked against the freshly loaded event — a vanished or
    /// mismatching event refuses with
    /// [`WriteRefusal::StoredVersionChanged`] before anything is
    /// deleted. `None` deletes unconditionally.
    async fn delete_event(
        &self,
        calendar: &CalendarRef,
        id: &EventRef,
        if_match: IfMatch<'_>,
    ) -> Result<DeleteOutcome>;
}

/// The DAV write seams of one session, handed to `serve` together:
/// one writer per listener, both backed by the same logged-in state.
///
/// Like every data-carrying port type, this one does not implement
/// `Debug`: it hands out personal data.
pub struct DavWriters {
    pub contacts: Arc<dyn ContactWriter>,
    pub calendar: Arc<dyn CalendarWriter>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Error;

    #[test]
    fn every_refusal_round_trips_through_its_error() {
        for refusal in [
            WriteRefusal::StoredVersionChanged,
            WriteRefusal::RemoteRefused,
            WriteRefusal::AttendeesRefused,
            WriteRefusal::ContactDecryptionFailed,
            WriteRefusal::CreateRefused,
            WriteRefusal::NoContactGroup,
        ] {
            assert_eq!(WriteRefusal::of(&refusal.error()), Some(refusal));
            assert_eq!(
                refusal.error().to_string(),
                format!("unsupported: {}", refusal.message())
            );
        }
        // Recognition is exact: a foreign unsupported message is not
        // one of these, and neither is any other error.
        assert_eq!(WriteRefusal::of(&Error::Unsupported("other".into())), None);
        assert_eq!(
            WriteRefusal::of(&Error::Login("session is no longer valid".into())),
            None
        );
    }
}
