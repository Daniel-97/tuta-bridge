//! Domain types for the read-only CalDAV server.
//!
//! [`CalendarEvent`] is a decrypted Tuta event, held only while one
//! response is rendered: it is never stored. The cache keeps
//! [`CalendarRow`]s instead — ids, times, a recurrence flag and a
//! content fingerprint — which is all listings, time-range filters,
//! ETags and collection tags need.
//!
//! None of these types derive `Debug`: they carry titles, addresses and
//! ids that must never reach a log line.

use std::collections::BTreeMap;

use crypto_primitives::sha::sha256;

/// Type id of a `CalendarEvent` (application `tutanota`).
pub const CALENDAR_EVENT_TYPE_ID: i64 = 933;
/// Type id of a `CalendarGroupRoot` (application `tutanota`).
pub const CALENDAR_GROUP_ROOT_TYPE_ID: i64 = 947;
/// Type id of the `UserSettingsGroupRoot` that holds calendar names and
/// colours (application `tutanota`).
pub const USER_SETTINGS_GROUP_ROOT_TYPE_ID: i64 = 972;
/// Application name of the `sys` model.
pub const SYS_APP: &str = "sys";
/// Type id of a `User` (application `sys`): its memberships list the
/// calendars.
pub const USER_TYPE_ID: i64 = 84;
/// Type id of a `GroupInfo` (application `sys`): the default name of a
/// shared calendar.
pub const GROUP_INFO_TYPE_ID: i64 = 14;

/// One millisecond-precise day.
pub const DAY_MS: i64 = 24 * 60 * 60 * 1000;

/// One Tuta calendar (a calendar group).
#[derive(Clone, PartialEq, Eq)]
pub struct CalendarInfo {
    /// The calendar group id; also the collection's path segment.
    pub calendar_id: String,
    /// The display name; may be empty (the default calendar has none,
    /// its label is translated by the Tuta clients).
    pub name: String,
    /// The colour as Tuta stores it: six hex digits without `#`.
    pub color: String,
    /// The list of short (non-repeating, shorter than 15 days) events.
    pub short_list_id: String,
    /// The list of long and repeating events.
    pub long_list_id: String,
}

/// An organizer or attendee.
#[derive(Clone, PartialEq, Eq)]
pub struct EventPerson {
    pub name: String,
    pub address: String,
}

/// An attendee with its Tuta participation status
/// (`0` added, `1` needs action, `2` accepted, `3` declined,
/// `4` tentative).
#[derive(Clone, PartialEq, Eq)]
pub struct EventAttendee {
    pub person: EventPerson,
    pub status: i64,
}

/// A Tuta repeat rule, as stored.
#[derive(Clone, PartialEq, Eq)]
pub struct RepeatRule {
    /// `0` daily, `1` weekly, `2` monthly, `3` annually.
    pub frequency: i64,
    pub interval: i64,
    /// `0` never, `1` after `end_value` occurrences, `2` before the
    /// instant `end_value` (exclusive).
    pub end_type: i64,
    pub end_value: Option<i64>,
    /// IANA name of the zone the rule repeats in.
    pub time_zone: String,
    /// Start instants of the removed occurrences.
    pub excluded_ms: Vec<i64>,
    /// Advanced `BYxxx` parts: `(rule type, value)`, rule types `0`
    /// BYMINUTE, `1` BYHOUR, `2` BYDAY, `3` BYMONTHDAY, `4` BYYEARDAY,
    /// `5` BYWEEKNO, `6` BYMONTH, `7` BYSETPOS, `8` WKST.
    pub advanced: Vec<(i64, String)>,
}

/// A decrypted Tuta calendar event. Rendered on demand, never stored.
#[derive(Clone, PartialEq, Eq)]
pub struct CalendarEvent {
    pub list_id: String,
    pub element_id: String,
    pub uid: Option<String>,
    pub summary: String,
    pub description: String,
    pub location: String,
    /// UTC start, in milliseconds. All-day events start and end at UTC
    /// midnight.
    pub start_ms: i64,
    /// UTC end (exclusive), in milliseconds.
    pub end_ms: i64,
    pub sequence: i64,
    /// Set on an altered occurrence of a repeating event: the original
    /// start of the occurrence it replaces.
    pub recurrence_id_ms: Option<i64>,
    pub repeat: Option<RepeatRule>,
    /// `UserAlarmInfo` ids `(list, element)`; only the user's own load.
    pub alarm_ids: Vec<(String, String)>,
    pub organizer: Option<EventPerson>,
    pub attendees: Vec<EventAttendee>,
}

impl CalendarEvent {
    /// Whether both bounds sit on UTC midnight, the way Tuta stores an
    /// all-day event.
    pub fn is_all_day(&self) -> bool {
        is_all_day(self.start_ms, self.end_ms)
    }

    /// The series this event belongs to: the CalDAV resource, unless
    /// the UID holds more than one master (see [`group_resources`]).
    ///
    /// A repeating event and its altered occurrences share one UID and
    /// must share one resource (RFC 4791 §4.1), so the name derives
    /// from the UID; an event without one gets a name of its own. The
    /// name is a hash: neither the UID nor an id appears in the path.
    pub fn resource_name(&self) -> String {
        let key = match &self.uid {
            Some(uid) if !uid.is_empty() => format!("uid\0{uid}"),
            _ => format!("id\0{}\0{}", self.list_id, self.element_id),
        };
        hex(&sha256(key.as_bytes())[..16])
    }

    /// A fingerprint of everything the rendered iCalendar depends on.
    ///
    /// Equal content gives an equal fingerprint on every load, so a
    /// reload does not change ETags; any edit (alarms included: Tuta
    /// replaces the alarm entities when they change) changes it.
    pub fn fingerprint(&self) -> String {
        let mut canonical = Vec::new();
        let mut field = |bytes: &[u8]| {
            canonical.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
            canonical.extend_from_slice(bytes);
        };
        field(self.list_id.as_bytes());
        field(self.element_id.as_bytes());
        field(self.uid.as_deref().unwrap_or("\u{0}none").as_bytes());
        field(self.summary.as_bytes());
        field(self.description.as_bytes());
        field(self.location.as_bytes());
        field(&self.start_ms.to_be_bytes());
        field(&self.end_ms.to_be_bytes());
        field(&self.sequence.to_be_bytes());
        field(&self.recurrence_id_ms.unwrap_or(i64::MIN).to_be_bytes());
        match &self.repeat {
            None => field(b"no-repeat"),
            Some(rule) => {
                field(&rule.frequency.to_be_bytes());
                field(&rule.interval.to_be_bytes());
                field(&rule.end_type.to_be_bytes());
                field(&rule.end_value.unwrap_or(i64::MIN).to_be_bytes());
                field(rule.time_zone.as_bytes());
                field(&(rule.excluded_ms.len() as u64).to_be_bytes());
                for excluded in &rule.excluded_ms {
                    field(&excluded.to_be_bytes());
                }
                field(&(rule.advanced.len() as u64).to_be_bytes());
                for (kind, value) in &rule.advanced {
                    field(&kind.to_be_bytes());
                    field(value.as_bytes());
                }
            }
        }
        field(&(self.alarm_ids.len() as u64).to_be_bytes());
        for (list, element) in &self.alarm_ids {
            field(list.as_bytes());
            field(element.as_bytes());
        }
        match &self.organizer {
            None => field(b"no-organizer"),
            Some(person) => {
                field(person.name.as_bytes());
                field(person.address.as_bytes());
            }
        }
        field(&(self.attendees.len() as u64).to_be_bytes());
        for attendee in &self.attendees {
            field(attendee.person.name.as_bytes());
            field(attendee.person.address.as_bytes());
            field(&attendee.status.to_be_bytes());
        }
        hex(&sha256(&canonical)[..16])
    }

    /// The end of the last occurrence when it is known from the data
    /// alone: the event's own end, or for a rule ending at an instant
    /// that instant plus the event's duration. `None` for open rules
    /// and rules counting occurrences.
    pub fn series_end_ms(&self) -> Option<i64> {
        match &self.repeat {
            None => Some(self.end_ms),
            Some(rule) if rule.end_type == 2 => rule
                .end_value
                .map(|until| until.saturating_add(self.end_ms - self.start_ms)),
            Some(_) => None,
        }
    }

    /// Whether any occurrence may overlap `[from_ms, to_ms)`. Generous
    /// for all-day events (their dates are floating, so ±14 h) and for
    /// rules without a known end.
    pub fn may_overlap(&self, from_ms: i64, to_ms: i64) -> bool {
        overlaps(
            self.start_ms,
            self.series_end_ms(),
            self.is_all_day(),
            from_ms,
            to_ms,
        )
    }

    /// The cache row of this event in `calendar_id`. `modified_ms` is
    /// the time the bridge first saw this content; the store keeps the
    /// stored value when the fingerprint did not change.
    pub fn row(&self, calendar_id: &str, modified_ms: i64) -> CalendarRow {
        CalendarRow {
            calendar_id: calendar_id.to_string(),
            list_id: self.list_id.clone(),
            element_id: self.element_id.clone(),
            resource: self.resource_name(),
            recurrence_id_ms: self.recurrence_id_ms,
            start_ms: self.start_ms,
            end_ms: self.end_ms,
            recurring: self.repeat.is_some(),
            series_end_ms: self.series_end_ms(),
            fingerprint: self.fingerprint(),
            modified_ms,
        }
    }
}

/// The cached metadata of one event: no title, text or address.
#[derive(Clone, PartialEq, Eq)]
pub struct CalendarRow {
    pub calendar_id: String,
    pub list_id: String,
    pub element_id: String,
    /// The series name (see [`CalendarEvent::resource_name`]), shared
    /// by every event with the same UID. It is the resource name
    /// (without `.ics`) unless the UID holds more than one master.
    pub resource: String,
    /// See [`CalendarEvent::recurrence_id_ms`]: set on an altered
    /// occurrence.
    pub recurrence_id_ms: Option<i64>,
    pub start_ms: i64,
    pub end_ms: i64,
    pub recurring: bool,
    /// See [`CalendarEvent::series_end_ms`].
    pub series_end_ms: Option<i64>,
    pub fingerprint: String,
    /// When the bridge first saw this fingerprint; the `DTSTAMP`.
    pub modified_ms: i64,
}

impl CalendarRow {
    /// See [`CalendarEvent::may_overlap`].
    pub fn may_overlap(&self, from_ms: i64, to_ms: i64) -> bool {
        overlaps(
            self.start_ms,
            if self.recurring {
                self.series_end_ms
            } else {
                Some(self.end_ms)
            },
            is_all_day(self.start_ms, self.end_ms),
            from_ms,
            to_ms,
        )
    }
}

/// One CalDAV resource: its rows and, when it holds a later master of
/// a split series, that master's ids (they derive its UID).
#[derive(Clone)]
pub struct Resource {
    pub rows: Vec<CalendarRow>,
    /// `(list_id, element_id)` of the master whose series this resource
    /// serves under a derived UID; `None` for the UID's own resource.
    pub split_master: Option<(String, String)>,
}

/// Group the cached rows of one calendar into CalDAV resources, keyed
/// by resource name.
///
/// Normally a UID is one resource: its master (the event without a
/// recurrence id) and its altered occurrences. Tuta's "edit this and
/// all future events" ends the series and starts a second master with
/// the same UID; two masters cannot share a `VCALENDAR` (clients key
/// components by UID and `RECURRENCE-ID`, so one would replace the
/// other) nor a UID across resources (RFC 4791 §4.1). So a UID with
/// several masters is split:
///
/// - Masters are ordered by start (then ids). The first keeps the UID
///   and the UID's resource name, so an unsplit series and the original
///   half of a split one keep their href.
/// - Every later master gets a resource of its own, named from the
///   series name and its ids ([`split_resource_name`]), served under a
///   UID derived the same way ([`split_uid`]): both are stable while
///   that master exists, whatever happens to the others.
/// - An altered occurrence joins the master whose series its recurrence
///   id falls in: the latest master starting at or before it whose
///   known end is after it; else the latest starting at or before it;
///   else the first. Split series follow each other in time, so this
///   is the series that generated the occurrence.
pub fn group_resources(rows: Vec<CalendarRow>) -> BTreeMap<String, Resource> {
    let mut series: BTreeMap<String, Vec<CalendarRow>> = BTreeMap::new();
    for row in rows {
        series.entry(row.resource.clone()).or_default().push(row);
    }
    let mut resources = BTreeMap::new();
    for (name, rows) in series {
        // (start, list id, element id, known end) of every master.
        let mut masters: Vec<(i64, String, String, Option<i64>)> = rows
            .iter()
            .filter(|row| row.recurrence_id_ms.is_none())
            .map(|row| {
                (
                    row.start_ms,
                    row.list_id.clone(),
                    row.element_id.clone(),
                    row.series_end_ms,
                )
            })
            .collect();
        if masters.len() < 2 {
            resources.insert(
                name,
                Resource {
                    rows,
                    split_master: None,
                },
            );
            continue;
        }
        masters.sort();
        let spans: Vec<(i64, Option<i64>)> = masters
            .iter()
            .map(|(start, _, _, end)| (*start, *end))
            .collect();
        let mut split: Vec<Vec<CalendarRow>> = vec![Vec::new(); masters.len()];
        for row in rows {
            let index = match row.recurrence_id_ms {
                None => masters
                    .iter()
                    .position(|(_, list, element, _)| {
                        *list == row.list_id && *element == row.element_id
                    })
                    .unwrap_or(0),
                Some(recurrence_id) => owning_master(&spans, recurrence_id),
            };
            split[index].push(row);
        }
        let keys = masters
            .into_iter()
            .enumerate()
            .map(|(index, (_, list, element, _))| {
                if index == 0 {
                    (name.clone(), None)
                } else {
                    (
                        split_resource_name(&name, &list, &element),
                        Some((list, element)),
                    )
                }
            });
        for ((key, split_master), rows) in keys.zip(split) {
            resources.insert(key, Resource { rows, split_master });
        }
    }
    resources
}

/// The master (index into `masters`, ordered by start) an altered
/// occurrence with `recurrence_id` belongs to; see [`group_resources`].
fn owning_master(masters: &[(i64, Option<i64>)], recurrence_id: i64) -> usize {
    let started = |index: &usize| masters[*index].0 <= recurrence_id;
    let running = (0..masters.len())
        .rev()
        .filter(started)
        .find(|index| masters[*index].1.is_none_or(|end| recurrence_id < end));
    running
        .or_else(|| (0..masters.len()).rev().find(started))
        .unwrap_or(0)
}

/// The resource name of a later master of a split series.
pub fn split_resource_name(series: &str, list_id: &str, element_id: &str) -> String {
    let key = format!("split\0{series}\0{list_id}\0{element_id}");
    hex(&sha256(key.as_bytes())[..16])
}

/// The UID a later master of a split series (and its altered
/// occurrences) is served under: the Tuta UID plus a hash of the
/// master's ids, so no id appears in it.
pub fn split_uid(uid: &str, list_id: &str, element_id: &str) -> String {
    let key = format!("{list_id}\0{element_id}");
    format!("{uid}-split-{}", hex(&sha256(key.as_bytes())[..8]))
}

/// Bump this when the iCalendar output changes for unchanged data, so
/// every ETag changes with it and clients fetch the new rendering.
pub const RENDER_VERSION: &str = "caldav-ics-2";

/// The strong ETag of a resource made of `rows` (quoted).
pub fn resource_etag<'a>(rows: impl IntoIterator<Item = &'a CalendarRow>) -> String {
    let mut parts: Vec<String> = rows
        .into_iter()
        .map(|row| {
            format!(
                "{}\0{}\0{}\0{}",
                row.list_id, row.element_id, row.fingerprint, row.modified_ms
            )
        })
        .collect();
    parts.sort();
    let mut canonical = String::from(RENDER_VERSION);
    for part in parts {
        canonical.push('\n');
        canonical.push_str(&part);
    }
    format!("\"{}\"", hex(&sha256(canonical.as_bytes())[..16]))
}

/// A collection tag over `(resource, etag)` pairs: equal content gives
/// an equal tag across reloads and restarts.
pub fn collection_tag(resources: &[(String, String)]) -> String {
    let mut parts: Vec<String> = resources
        .iter()
        .map(|(resource, etag)| format!("{resource}\0{etag}"))
        .collect();
    parts.sort();
    let mut canonical = String::from(RENDER_VERSION);
    for part in parts {
        canonical.push('\n');
        canonical.push_str(&part);
    }
    hex(&sha256(canonical.as_bytes())[..16])
}

/// Whether both bounds sit on UTC midnight and the event is not empty.
pub fn is_all_day(start_ms: i64, end_ms: i64) -> bool {
    start_ms.rem_euclid(DAY_MS) == 0 && end_ms.rem_euclid(DAY_MS) == 0 && end_ms > start_ms
}

/// Overlap test shared by events and rows (RFC 4791 §9.10, generous).
fn overlaps(start_ms: i64, end_ms: Option<i64>, all_day: bool, from_ms: i64, to_ms: i64) -> bool {
    // Floating dates can fall on either side of UTC midnight.
    let slack = if all_day { 14 * 60 * 60 * 1000 } else { 0 };
    let start = start_ms.saturating_sub(slack);
    let end = end_ms.map(|end| end.saturating_add(slack));
    if start >= to_ms {
        return false;
    }
    match end {
        None => true,
        // A zero-length event overlaps when it starts inside the range.
        Some(end) if end <= start => start >= from_ms,
        Some(end) => end > from_ms,
    }
}

/// Lowercase hex.
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[usize::from(byte >> 4)] as char);
        out.push(DIGITS[usize::from(byte & 0xf)] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event() -> CalendarEvent {
        CalendarEvent {
            list_id: "list".into(),
            element_id: "element".into(),
            uid: Some("uid-1".into()),
            summary: "Summary".into(),
            description: String::new(),
            location: String::new(),
            start_ms: 1_700_000_000_000,
            end_ms: 1_700_003_600_000,
            sequence: 0,
            recurrence_id_ms: None,
            repeat: None,
            alarm_ids: Vec::new(),
            organizer: None,
            attendees: Vec::new(),
        }
    }

    #[test]
    fn the_fingerprint_is_stable_and_tracks_content() {
        let a = event();
        assert_eq!(a.fingerprint(), event().fingerprint());
        let mut b = event();
        b.summary.push('!');
        assert_ne!(a.fingerprint(), b.fingerprint());
        let mut c = event();
        c.alarm_ids.push(("l".into(), "e".into()));
        assert_ne!(a.fingerprint(), c.fingerprint());
    }

    #[test]
    fn resources_follow_the_uid() {
        let master = event();
        let mut altered = event();
        altered.element_id = "other".into();
        altered.recurrence_id_ms = Some(1);
        assert_eq!(master.resource_name(), altered.resource_name());
        let mut no_uid = event();
        no_uid.uid = None;
        assert_ne!(no_uid.resource_name(), master.resource_name());
        assert_eq!(master.resource_name().len(), 32);
    }

    #[test]
    fn etags_ignore_row_order_and_track_fingerprints() {
        let a = event().row("cal", 5);
        let mut other = event();
        other.element_id = "x".into();
        let b = other.row("cal", 5);
        assert_eq!(
            resource_etag([&a, &b]),
            resource_etag([&b, &a]),
            "order does not matter"
        );
        let mut changed = b.clone();
        changed.fingerprint = "f".into();
        assert_ne!(resource_etag([&a, &b]), resource_etag([&a, &changed]));
        assert!(resource_etag([&a]).starts_with('"'));
    }

    fn weekly(end: Option<i64>) -> RepeatRule {
        RepeatRule {
            frequency: 1,
            interval: 1,
            end_type: if end.is_some() { 2 } else { 0 },
            end_value: end,
            time_zone: "UTC".into(),
            excluded_ms: Vec::new(),
            advanced: Vec::new(),
        }
    }

    const WEEK: i64 = 7 * DAY_MS;

    #[test]
    fn one_master_per_uid_keeps_the_uid_resource() {
        let mut master = event();
        master.repeat = Some(weekly(None));
        let mut altered = event();
        altered.element_id = "moved".into();
        altered.recurrence_id_ms = Some(master.start_ms + WEEK);
        let resources = group_resources(vec![master.row("cal", 0), altered.row("cal", 0)]);
        assert_eq!(resources.len(), 1);
        let (name, resource) = resources.iter().next().unwrap();
        assert_eq!(name, &master.resource_name());
        assert_eq!(resource.rows.len(), 2);
        assert!(resource.split_master.is_none());
    }

    #[test]
    fn a_split_series_becomes_one_resource_per_master() {
        // "Edit this and all future events": the original ends before
        // week 4, a second master with the same UID starts there.
        let start = 1_700_000_000_000;
        let split_at = start + 4 * WEEK;
        let mut original = event();
        original.element_id = "original".into();
        original.start_ms = start;
        original.end_ms = start + 3_600_000;
        original.repeat = Some(weekly(Some(split_at)));
        let mut future = original.clone();
        future.element_id = "future".into();
        future.start_ms = split_at + 3_600_000; // moved one hour later
        future.end_ms = future.start_ms + 3_600_000;
        future.repeat = Some(weekly(None));
        let mut early = event();
        early.element_id = "early".into();
        early.recurrence_id_ms = Some(start + WEEK);
        let mut late = event();
        late.element_id = "late".into();
        late.recurrence_id_ms = Some(future.start_ms + 2 * WEEK);
        // Moved before the second series' start, but generated by it.
        late.start_ms = split_at - DAY_MS;
        let rows = vec![
            late.row("cal", 0),
            future.row("cal", 0),
            early.row("cal", 0),
            original.row("cal", 0),
        ];
        let resources = group_resources(rows.clone());
        assert_eq!(resources.len(), 2);
        let first = &resources[&original.resource_name()];
        assert!(
            first.split_master.is_none(),
            "the first master keeps the UID"
        );
        let mut ids: Vec<&str> = first.rows.iter().map(|r| r.element_id.as_str()).collect();
        ids.sort_unstable();
        assert_eq!(ids, ["early", "original"]);
        let name = split_resource_name(&original.resource_name(), "list", "future");
        let second = &resources[&name];
        assert_eq!(
            second.split_master,
            Some(("list".to_string(), "future".to_string()))
        );
        let mut ids: Vec<&str> = second.rows.iter().map(|r| r.element_id.as_str()).collect();
        ids.sort_unstable();
        assert_eq!(ids, ["future", "late"]);
        // Deterministic whatever the row order.
        let mut reversed = rows;
        reversed.reverse();
        assert_eq!(
            group_resources(reversed).keys().collect::<Vec<_>>(),
            resources.keys().collect::<Vec<_>>()
        );
        assert_eq!(name.len(), 32);
        assert_ne!(
            split_uid("uid-1", "list", "future"),
            split_uid("uid-1", "list", "other")
        );
        assert!(split_uid("uid-1", "list", "future").starts_with("uid-1-split-"));
        assert!(!split_uid("uid-1", "list", "future").contains("future"));
    }

    #[test]
    fn an_occurrence_before_every_master_joins_the_first() {
        assert_eq!(owning_master(&[(10, Some(20)), (20, None)], 5), 0);
        assert_eq!(owning_master(&[(10, Some(20)), (20, None)], 15), 0);
        assert_eq!(owning_master(&[(10, Some(20)), (20, None)], 20), 1);
        // A master whose known end is past: the next running one wins,
        // else the latest started.
        assert_eq!(owning_master(&[(10, None), (20, Some(25))], 30), 0);
        assert_eq!(owning_master(&[(10, Some(12)), (20, Some(25))], 30), 1);
    }

    #[test]
    fn a_rule_ending_exactly_at_the_window_start_is_out() {
        // Tuta's end is exclusive: a rule ending at `from` has its last
        // occurrence before it; only its duration can reach into it.
        let mut repeating = event();
        let duration = repeating.end_ms - repeating.start_ms;
        let until = repeating.start_ms + 3 * WEEK;
        repeating.repeat = Some(weekly(Some(until)));
        let row = repeating.row("cal", 0);
        assert_eq!(row.series_end_ms, Some(until + duration));
        assert!(row.may_overlap(until + duration - 1, i64::MAX));
        assert!(!row.may_overlap(until + duration, i64::MAX));
    }

    #[test]
    fn overlap_is_half_open_and_generous_for_all_day() {
        let row = event().row("cal", 0);
        assert!(row.may_overlap(row.start_ms, row.start_ms + 1));
        assert!(!row.may_overlap(row.end_ms, row.end_ms + 1));
        assert!(!row.may_overlap(0, row.start_ms));
        let mut all_day = event();
        all_day.start_ms = 19_000 * DAY_MS;
        all_day.end_ms = 19_001 * DAY_MS;
        assert!(all_day.is_all_day());
        assert!(all_day.may_overlap(all_day.end_ms, all_day.end_ms + 1));
        let mut repeating = event();
        repeating.repeat = Some(RepeatRule {
            frequency: 1,
            interval: 1,
            end_type: 0,
            end_value: None,
            time_zone: "UTC".into(),
            excluded_ms: Vec::new(),
            advanced: Vec::new(),
        });
        assert!(repeating.may_overlap(i64::MAX - 10, i64::MAX));
        assert!(repeating.row("cal", 0).may_overlap(i64::MAX - 10, i64::MAX));
    }
}
