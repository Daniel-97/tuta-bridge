//! The write seams of the CardDAV and CalDAV servers: contacts and
//! calendar events.
//!
//! Every call either applies the whole change remotely or fails; the
//! caller updates its cache only after a call succeeded. The event bus
//! later delivers the echo of the same change, which the caches apply
//! idempotently. Errors carry fixed messages only: never ids, names,
//! addresses or titles.
//!
//! Like every data-carrying port type, these types do not implement
//! `Debug`: they hold personal data.

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
/// id the change landed on. Errors carry fixed text only.
#[async_trait::async_trait]
pub trait ContactWriter: Send + Sync {
    async fn put_contact(
        &self,
        list_id: &str,
        fields: &ContactFields,
        existing: Option<&ContactRef>,
    ) -> Result<ContactRef>;

    /// Delete one contact; [`DeleteOutcome::Gone`] when it had already
    /// vanished remotely.
    async fn delete_contact(&self, id: &ContactRef) -> Result<DeleteOutcome>;
}

/// The calendar write seam towards Tuta.
///
/// `put_event` creates an event when `existing` is `None` — filed
/// into the calendar's short or long event list by its repeat rule —
/// and updates the referenced one otherwise, answering with the id
/// the change landed on. Errors carry fixed text only.
#[async_trait::async_trait]
pub trait CalendarWriter: Send + Sync {
    async fn put_event(
        &self,
        calendar: &CalendarRef,
        fields: &EventFields,
        existing: Option<&EventRef>,
    ) -> Result<EventRef>;

    /// Delete one event; [`DeleteOutcome::Gone`] when it had already
    /// vanished remotely.
    async fn delete_event(&self, calendar: &CalendarRef, id: &EventRef) -> Result<DeleteOutcome>;
}
