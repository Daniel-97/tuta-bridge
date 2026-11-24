//! Import the iCalendar `VEVENT` body of a CalDAV `PUT` into the
//! writable event fields: the inverse of [`super::ical`]'s render,
//! the field mapping of the plan's decision 1 and the refusals of
//! decision 3.
//!
//! - Folding is undone first: a line that starts with a space or a
//!   tab continues the previous one, and both CRLF and LF bodies are
//!   accepted (the RFC demands CRLF; real clients send both).
//! - One `PUT` is one event: the body must hold exactly one complete
//!   `BEGIN:VEVENT`…`END:VEVENT` inside a `VCALENDAR`. A `VTIMEZONE`
//!   the calendar carries is accepted and ignored — the `TZID` the
//!   times name is what counts, and it must name a zone the bundled
//!   data knows (the same lookup the reader resolves zones by): an
//!   unknown zone refuses the event, never a silent shift. The UTC
//!   form is the `Z` suffix, so a `TZID=UTC` parameter is refused
//!   the same way.
//! - Times come in the three forms the renderer writes: UTC
//!   (`…Z`), a `TZID`-qualified local time (the same zone name on
//!   both bounds), or `VALUE=DATE` on both bounds with the end
//!   exclusive. Every other shape — mixed bounds, an explicit UTC
//!   offset, a floating time, a missing `DTEND` — refuses the event,
//!   fail closed. The pair is stored as-is: the domain carries any
//!   two bounds, and the renderer is the one that clamps an empty
//!   event when it serves one.
//! - The repeat rule accepts exactly the part set the renderer
//!   emits (the part order is free, as in every RFC 5545 reader):
//!   `FREQ`, `INTERVAL`, `COUNT`, `UNTIL` — the UTC second form on a
//!   timed event, the date form on an all-day one, and Tuta's
//!   exclusive end is the whole unit after it, which is exact for
//!   the whole-unit ends Tuta stores — weekly `BYDAY`, and the
//!   month-end `BYMONTHDAY=28…;BYSETPOS=-1` pattern of a start on
//!   the 29th-31st, which maps back onto the plain monthly rule
//!   Tuta clamps to each month's last day. Anything else — `BYMONTH`,
//!   an ordinal `BYDAY`, a second `RRULE` — refuses the whole event:
//!   a rule that cannot be mapped is never accepted and then
//!   mangled. An event the reader serves with `EXDATE`s (or an
//!   altered occurrence) is refused the same way.
//! - An `EXDATE`, `RDATE` or `RECURRENCE-ID` refuses the event:
//!   occurrence-level editing is out of scope, and the refusal
//!   outranks the one-event rule, so the body a client writes back
//!   for an edited occurrence (master and override together) fails
//!   with the message about occurrence editing. An `ATTENDEE` other
//!   than the organizer refuses the event too — invitation mails are
//!   out of scope, and an invitation is never dropped silently; an
//!   attendee that is the organizer (case-insensitive) is a personal
//!   event and drops. A `VALARM` is accepted and ignored: refusing
//!   an event over a reminder would be hostile, and reminders are
//!   not carried to Tuta either way.
//! - The `ORGANIZER` value maps to its address only; the `CN`
//!   parameter is accepted and dropped, and an unusable value is
//!   treated as no organizer, the way the renderer drops such a
//!   person when it serves one. Everything the renderer never
//!   serves — `PRODID`, `VERSION`, `CALSCALE`, `METHOD`, `SEQUENCE`,
//!   `CREATED`, `LAST-MODIFIED`, `DTSTAMP`, `STATUS`, `TRANSP`,
//!   `CLASS`, `PRIORITY`, every `X-` property and every unrecognized
//!   name — is dropped silently, and an unknown property never fails
//!   the import.
//! - [`ImportError`] carries fixed messages only — no title, zone
//!   name, address or rule ever reaches an error — and this module
//!   never logs. The body is parsed in memory and never written
//!   anywhere.

use std::fmt;

use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time};

use super::timezone::Zone;
use crate::domain::calendar::DAY_MS;
use crate::domain::{EventPerson, RepeatRule};
use crate::ports::dav_writer::EventFields;

/// Why a body could not be imported. The messages are fixed: no
/// title, zone, address or rule ever appears in one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportError {
    /// The body holds no complete `BEGIN:VEVENT`…`END:VEVENT` inside
    /// a `VCALENDAR`.
    NoVevent,
    /// A `PUT` is one event; the body holds more than one.
    TooManyVevents,
    /// `DTSTART`/`DTEND` are missing or not in a form the bridge
    /// serves.
    BadTimes,
    /// A `TZID` does not name a zone the bundled data knows.
    UnknownZone,
    /// The `RRULE` is not one of the shapes the renderer emits.
    BadRule,
    /// An attendee other than the organizer: invitations are out of
    /// scope and never dropped silently.
    OtherAttendees,
    /// `EXDATE`, `RDATE` or `RECURRENCE-ID`: occurrence-level editing
    /// is out of scope.
    PerOccurrence,
}

impl ImportError {
    /// The fixed message of the failure.
    pub fn message(&self) -> &'static str {
        match self {
            ImportError::NoVevent => "the request body holds no complete vevent",
            ImportError::TooManyVevents => "the request body holds more than one vevent",
            ImportError::BadTimes => "the event's start or end is not in a form the bridge serves",
            ImportError::UnknownZone => "the event's time zone is not known to the bridge",
            ImportError::BadRule => "the event's repeat rule is not in a form the bridge serves",
            ImportError::OtherAttendees => {
                "the event carries attendees other than the organizer, which the bridge \
cannot send invitations for"
            }
            ImportError::PerOccurrence => {
                "the event edits or lists single occurrences of a series, which the \
bridge does not support"
            }
        }
    }
}

impl fmt::Display for ImportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

/// Import the `VEVENT` of `body` (a client sends one event per
/// `PUT`). An unrecognized property is dropped silently; a time,
/// zone, rule or attendee that cannot be mapped refuses the whole
/// import.
pub fn parse_event(body: &str) -> Result<EventFields, ImportError> {
    let scanned = scan(body);
    let Some(block) = scanned.blocks.first() else {
        return Err(ImportError::NoVevent);
    };
    // The occurrence-level refusal outranks the one-event rule: the
    // body a client writes back after editing one occurrence carries
    // the master beside it, and the message that matters is the one
    // about occurrence editing.
    for block in &scanned.blocks {
        for line in block {
            if let Some(property) = Property::parse(line) {
                if matches!(property.name.as_str(), "EXDATE" | "RECURRENCE-ID" | "RDATE") {
                    return Err(ImportError::PerOccurrence);
                }
            }
        }
    }
    if scanned.opens > 1 {
        return Err(ImportError::TooManyVevents);
    }

    let mut parts = Parts::default();
    for line in block {
        if let Some(property) = Property::parse(line) {
            apply(&mut parts, &property)?;
        }
    }

    // Both bounds in the same form, or not at all.
    let (start_ms, end_ms, all_day, zone, start_day) = match (parts.start, parts.end) {
        (Some(TimeForm::Date { ms, day }), Some(TimeForm::Date { ms: end_ms, .. })) => {
            (ms, end_ms, true, None, day)
        }
        (Some(TimeForm::Utc { ms, day }), Some(TimeForm::Utc { ms: end_ms, .. })) => {
            (ms, end_ms, false, Some("UTC".to_string()), day)
        }
        (
            Some(TimeForm::Zoned { ms, day, name }),
            Some(TimeForm::Zoned {
                ms: end_ms,
                name: end_name,
                ..
            }),
        ) if name == end_name => (ms, end_ms, false, Some(name), day),
        _ => return Err(ImportError::BadTimes),
    };

    // An attendee is the organizer's own address or the event is
    // refused: no invitation is ever lost silently.
    match parts.organizer.as_deref() {
        Some(organizer) => {
            if parts
                .attendees
                .iter()
                .any(|attendee| !attendee.eq_ignore_ascii_case(organizer))
            {
                return Err(ImportError::OtherAttendees);
            }
        }
        None if !parts.attendees.is_empty() => return Err(ImportError::OtherAttendees),
        None => {}
    }

    let rule_zone = match (&zone, all_day) {
        // An all-day rule repeats in no zone the body could name; the
        // importer files UTC, the zone the renderer ignores there.
        (_, true) => "UTC".to_string(),
        (Some(name), false) => name.clone(),
        (None, false) => "UTC".to_string(),
    };
    let mut fields = EventFields {
        summary: parts.summary.unwrap_or_default(),
        description: parts.description.unwrap_or_default(),
        location: parts.location.unwrap_or_default(),
        start_ms,
        end_ms,
        all_day,
        time_zone: zone,
        repeat: None,
        uid: parts.uid,
        organizer: parts.organizer.map(|address| EventPerson {
            name: String::new(),
            address,
        }),
    };
    if let Some(rule) = &parts.rrule {
        fields.repeat = Some(map_rule(rule, all_day, start_day, &rule_zone)?);
    }
    Ok(fields)
}

/// The scan of a body: every complete event's property lines, and how
/// many events were opened at all (an unterminated one never lands in
/// `blocks` but still counts against the one-event rule).
#[derive(Default)]
struct Scan {
    /// The open components, innermost last, upper-case.
    stack: Vec<String>,
    blocks: Vec<Vec<String>>,
    current: Option<Vec<String>>,
    opens: usize,
}

/// Split `body` into `VEVENT` blocks: the property lines of every
/// complete `BEGIN:VEVENT`…`END:VEVENT` directly inside a
/// `VCALENDAR`, with nested components (`VALARM`, `VTIMEZONE`,
/// anything else) skipped line by line.
fn scan(body: &str) -> Scan {
    let mut scanned = Scan::default();
    for line in unfold(body) {
        let Some(property) = Property::parse(&line) else {
            continue;
        };
        let component = property.value.trim().to_ascii_uppercase();
        if property.name == "BEGIN" {
            if scanned.stack.is_empty() {
                // Junk before the calendar is none of the importer's
                // business, and so is a component outside one.
                if component == "VCALENDAR" {
                    scanned.stack.push(component);
                }
            } else if component == "VEVENT"
                && scanned.stack.last().map(String::as_str) == Some("VCALENDAR")
            {
                scanned.opens += 1;
                scanned.current = Some(Vec::new());
                scanned.stack.push(component);
            } else {
                scanned.stack.push(component);
            }
            continue;
        }
        if property.name == "END" {
            if scanned.stack.last().map(String::as_str) == Some(component.as_str()) {
                let closing_event =
                    component == "VEVENT" && scanned.stack.len() == 2 && scanned.current.is_some();
                scanned.stack.pop();
                if closing_event {
                    if let Some(current) = scanned.current.take() {
                        scanned.blocks.push(current);
                    }
                }
            }
            continue;
        }
        if scanned.stack.len() == 2 && scanned.stack[1] == "VEVENT" {
            if let Some(current) = scanned.current.as_mut() {
                current.push(line);
            }
        }
    }
    scanned
}

/// The collected event before the cross-property checks.
#[derive(Default)]
struct Parts {
    start: Option<TimeForm>,
    end: Option<TimeForm>,
    summary: Option<String>,
    description: Option<String>,
    location: Option<String>,
    uid: Option<String>,
    uid_seen: bool,
    organizer: Option<String>,
    organizer_seen: bool,
    attendees: Vec<String>,
    rrule: Option<String>,
}

/// Apply one event property; the first occurrence of a
/// single-valued one wins, the way the renderer emits exactly one.
/// The fall-through arm is the importer's contract: what the
/// renderer never emits was never supported.
fn apply(parts: &mut Parts, property: &Property) -> Result<(), ImportError> {
    match property.name.as_str() {
        "DTSTART" => {
            let bound = parse_bound(property)?;
            if parts.start.is_none() {
                parts.start = Some(bound);
            }
        }
        "DTEND" => {
            let bound = parse_bound(property)?;
            if parts.end.is_none() {
                parts.end = Some(bound);
            }
        }
        "SUMMARY" => {
            if parts.summary.is_none() {
                parts.summary = Some(unescape(&property.value));
            }
        }
        "DESCRIPTION" => {
            if parts.description.is_none() {
                parts.description = Some(unescape(&property.value));
            }
        }
        "LOCATION" => {
            if parts.location.is_none() {
                parts.location = Some(unescape(&property.value));
            }
        }
        "UID" => {
            if !parts.uid_seen {
                parts.uid_seen = true;
                let uid = unescape(&property.value).trim().to_string();
                if !uid.is_empty() {
                    parts.uid = Some(uid);
                }
            }
        }
        "ORGANIZER" => {
            if !parts.organizer_seen {
                parts.organizer_seen = true;
                parts.organizer = mail_address(&property.value);
            }
        }
        // One unusable attendee can never be the organizer: refuse
        // here rather than lose an invitation silently.
        "ATTENDEE" => match mail_address(&property.value) {
            Some(address) => parts.attendees.push(address),
            None => return Err(ImportError::OtherAttendees),
        },
        "RRULE" => {
            if parts.rrule.is_some() {
                return Err(ImportError::BadRule);
            }
            parts.rrule = Some(property.value.trim().to_string());
        }
        // Occurrence-level data never reaches the mapping: the
        // pre-scan refuses it for every block, this arm keeps the
        // refusal true if only the first block is mapped.
        "EXDATE" | "RECURRENCE-ID" | "RDATE" => return Err(ImportError::PerOccurrence),
        _ => {}
    }
    Ok(())
}

/// One parsed time bound. The form decides the pair check; the local
/// day of the month carries into the month-end rule check.
enum TimeForm {
    /// `…Z`: a UTC instant.
    Utc { ms: i64, day: u8 },
    /// A `TZID`-qualified local time, resolved through the zone.
    Zoned { ms: i64, day: u8, name: String },
    /// `VALUE=DATE`: a UTC-midnight day, an all-day bound.
    Date { ms: i64, day: u8 },
}

/// Parse one time bound in one of the three served forms; every
/// other shape or parameter refuses the event.
fn parse_bound(property: &Property) -> Result<TimeForm, ImportError> {
    let mut tzid: Option<String> = None;
    let mut date_only = false;
    let mut value_param = false;
    for (name, raw) in &property.params {
        match name.as_str() {
            "TZID" if tzid.is_none() => {
                let name = unquote(raw);
                if name.is_empty() {
                    return Err(ImportError::BadTimes);
                }
                tzid = Some(name);
            }
            "TZID" => return Err(ImportError::BadTimes),
            "VALUE" if !value_param => {
                value_param = true;
                if raw.trim().eq_ignore_ascii_case("DATE") {
                    date_only = true;
                } else {
                    return Err(ImportError::BadTimes);
                }
            }
            "VALUE" => return Err(ImportError::BadTimes),
            _ => return Err(ImportError::BadTimes),
        }
    }
    let value = property.value.trim();
    if date_only {
        // An all-day bound takes no zone: its dates are floating.
        if tzid.is_some() {
            return Err(ImportError::BadTimes);
        }
        let date = parse_date(value).ok_or(ImportError::BadTimes)?;
        return Ok(TimeForm::Date {
            ms: day_ms(date),
            day: date.day(),
        });
    }
    match tzid {
        None => {
            let (date, time) = parse_utc(value).ok_or(ImportError::BadTimes)?;
            Ok(TimeForm::Utc {
                ms: utc_ms(date, time),
                day: date.day(),
            })
        }
        Some(name) => {
            // The same lookup the reader resolves zones by; a zone it
            // does not know refuses the event, never a silent shift.
            let zone = Zone::by_name(&name).ok_or(ImportError::UnknownZone)?;
            let (date, time) = parse_local(value).ok_or(ImportError::BadTimes)?;
            let ms = to_ms(zone.instant(PrimitiveDateTime::new(date, time)));
            Ok(TimeForm::Zoned {
                ms,
                day: date.day(),
                name,
            })
        }
    }
}

/// A parameter value without its optional quotes.
fn unquote(value: &str) -> String {
    value.trim().trim_matches('"').to_string()
}

/// A date in the renderer's basic form `YYYYMMDD`.
fn parse_date(text: &str) -> Option<Date> {
    if text.len() != 8 || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let year = text[..4].parse().ok()?;
    let month = Month::try_from(text[4..6].parse::<u8>().ok()?).ok()?;
    let day = text[6..8].parse::<u8>().ok()?;
    Date::from_calendar_date(year, month, day).ok()
}

/// A local date-time in the renderer's form `YYYYMMDDTHHMMSS`.
fn parse_local(text: &str) -> Option<(Date, Time)> {
    let bytes = text.as_bytes();
    if text.len() != 15
        || bytes[8] != b'T'
        || !bytes[..8].iter().all(|byte| byte.is_ascii_digit())
        || !bytes[9..].iter().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let date = parse_date(&text[..8])?;
    let time = Time::from_hms(
        text[9..11].parse().ok()?,
        text[11..13].parse().ok()?,
        text[13..15].parse().ok()?,
    )
    .ok()?;
    Some((date, time))
}

/// A UTC date-time in the renderer's form `YYYYMMDDTHHMMSSZ`.
fn parse_utc(text: &str) -> Option<(Date, Time)> {
    if !text.ends_with(['Z', 'z']) {
        return None;
    }
    parse_local(&text[..text.len() - 1])
}

/// UTC milliseconds of a date-time taken as UTC.
fn utc_ms(date: Date, time: Time) -> i64 {
    to_ms(PrimitiveDateTime::new(date, time).assume_utc())
}

/// UTC milliseconds of a date's midnight: an all-day bound.
fn day_ms(date: Date) -> i64 {
    utc_ms(date, Time::MIDNIGHT)
}

fn to_ms(instant: OffsetDateTime) -> i64 {
    i64::try_from(instant.unix_timestamp_nanos().div_euclid(1_000_000)).unwrap_or(0)
}

/// The address of an `ORGANIZER`/`ATTENDEE` value: the `mailto:` URI
/// form the renderer writes. Anything else is unusable — the
/// renderer drops such a person when it serves one, and an
/// organizer line that unusable is treated as absent.
fn mail_address(value: &str) -> Option<String> {
    let value = value.trim();
    if !value.get(..7)?.eq_ignore_ascii_case("mailto:") {
        return None;
    }
    let address = value[7..].trim();
    (!address.is_empty()).then(|| address.to_string())
}

/// The weekday codes a weekly `BYDAY` may carry.
const WEEKDAYS: [&str; 7] = ["MO", "TU", "WE", "TH", "FR", "SA", "SU"];

/// Map the `RRULE` forms the renderer emits back onto the domain
/// rule; anything else refuses the event. `start_day` is the start's
/// local day of the month — the month-end pattern is only ever the
/// renderer's clamp of a start on the 29th-31st — and `zone` the
/// zone the rule repeats in.
fn map_rule(
    value: &str,
    all_day: bool,
    start_day: u8,
    zone: &str,
) -> Result<RepeatRule, ImportError> {
    let mut frequency: Option<i64> = None;
    let mut interval: Option<i64> = None;
    let mut count: Option<i64> = None;
    let mut until: Option<String> = None;
    let mut byday: Option<Vec<String>> = None;
    let mut bymonthday: Option<Vec<String>> = None;
    let mut bysetpos: Option<Vec<String>> = None;
    for piece in value.split(';') {
        let Some((name, raw)) = piece.split_once('=') else {
            return Err(ImportError::BadRule);
        };
        let raw = raw.trim();
        if raw.is_empty() {
            return Err(ImportError::BadRule);
        }
        // Part order is free, as in every RFC 5545 reader; the part
        // set is pinned to the renderer's, and a duplicate or
        // unknown part refuses the rule.
        match name.trim().to_ascii_uppercase().as_str() {
            "FREQ" if frequency.is_none() => {
                frequency = Some(match raw.to_ascii_uppercase().as_str() {
                    "DAILY" => 0,
                    "WEEKLY" => 1,
                    "MONTHLY" => 2,
                    "YEARLY" => 3,
                    _ => return Err(ImportError::BadRule),
                });
            }
            "INTERVAL" if interval.is_none() => {
                interval = Some(positive(raw).ok_or(ImportError::BadRule)?);
            }
            "COUNT" if count.is_none() => {
                count = Some(positive(raw).ok_or(ImportError::BadRule)?);
            }
            "UNTIL" if until.is_none() => until = Some(raw.to_string()),
            "BYDAY" if byday.is_none() => {
                byday = Some(
                    raw.split(',')
                        .map(|day| day.trim().to_ascii_uppercase())
                        .collect(),
                );
            }
            "BYMONTHDAY" if bymonthday.is_none() => {
                bymonthday = Some(raw.split(',').map(|day| day.trim().to_string()).collect());
            }
            "BYSETPOS" if bysetpos.is_none() => {
                bysetpos = Some(raw.split(',').map(|pos| pos.trim().to_string()).collect());
            }
            _ => return Err(ImportError::BadRule),
        }
    }
    let frequency = frequency.ok_or(ImportError::BadRule)?;

    // Weekly BYDAY: plain weekday codes, no ordinals, no duplicates.
    let mut advanced: Vec<(i64, String)> = Vec::new();
    if let Some(days) = byday {
        if frequency != 1 || days.iter().any(|day| !WEEKDAYS.contains(&day.as_str())) {
            return Err(ImportError::BadRule);
        }
        let mut unique = days.clone();
        unique.sort();
        unique.dedup();
        if unique.len() != days.len() {
            return Err(ImportError::BadRule);
        }
        advanced = days.into_iter().map(|day| (2, day)).collect();
    }

    // The month-end pattern: the renderer's clamp of a monthly start
    // on the 29th-31st to each month's last day, and the only form
    // a BYMONTHDAY or BYSETPOS may take.
    match (&bymonthday, &bysetpos) {
        (None, None) => {}
        (Some(days), Some(positions)) => {
            if frequency != 2
                || positions.len() != 1
                || positions[0] != "-1"
                || !is_month_end(days, start_day)
            {
                return Err(ImportError::BadRule);
            }
        }
        _ => return Err(ImportError::BadRule),
    }

    let (end_type, end_value) = match (count, until) {
        (None, None) => (0, None),
        (Some(count), None) => (1, Some(count)),
        (None, Some(until)) => {
            // The renderer's `UNTIL` is the whole unit before Tuta's
            // exclusive end: a UTC second on a timed event, a date on
            // an all-day one, so the end is the whole unit after it.
            let ms = if all_day {
                day_ms(parse_date(&until).ok_or(ImportError::BadRule)?) + DAY_MS
            } else {
                let (date, time) = parse_utc(&until).ok_or(ImportError::BadRule)?;
                utc_ms(date, time) + 1000
            };
            (2, Some(ms))
        }
        (Some(_), Some(_)) => return Err(ImportError::BadRule),
    };

    Ok(RepeatRule {
        frequency,
        interval: interval.unwrap_or(1),
        end_type,
        end_value,
        time_zone: zone.to_string(),
        // An `EXDATE` refuses the event before the rule is mapped.
        excluded_ms: Vec::new(),
        advanced,
    })
}

/// Whether `BYMONTHDAY` is the renderer's month-end list for a
/// start on `start_day` — `28` up to the day itself, the only list
/// Tuta's clamp generates.
fn is_month_end(days: &[String], start_day: u8) -> bool {
    (29..=31).contains(&start_day)
        && days.len() == usize::from(start_day - 27)
        && days
            .iter()
            .zip(28..)
            .all(|(day, expected)| day == &expected.to_string())
}

/// A positive integer, the only form `INTERVAL` and `COUNT` accept.
fn positive(text: &str) -> Option<i64> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse::<i64>().ok().filter(|value| *value > 0)
}

/// Undo folding: a physical line that starts with a space or a tab
/// continues the previous one, the marker character itself dropped.
/// Both CRLF and LF line ends are accepted.
fn unfold(body: &str) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    for physical in body.split('\n') {
        let physical = physical.strip_suffix('\r').unwrap_or(physical);
        if let Some(continuation) = physical
            .strip_prefix(' ')
            .or_else(|| physical.strip_prefix('\t'))
        {
            if let Some(last) = lines.last_mut() {
                last.push_str(continuation);
                continue;
            }
            // Nothing to continue: the body starts mid-fold. Drop
            // the orphan fragment rather than invent content.
            continue;
        }
        lines.push(physical.to_string());
    }
    lines
}

/// Unescape a text value, the exact inverse of the renderer's
/// `escape_text` for the escapes it produces (`\\`, `\,`, `\;`,
/// `\n` and `\N`). A backslash before anything else survives (both
/// characters kept), and so does a trailing lone one: better a
/// literal backslash in a note than a lost one.
fn unescape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some('\\') => out.push('\\'),
            Some(',') => out.push(','),
            Some(';') => out.push(';'),
            Some('n') | Some('N') => out.push('\n'),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

/// One unfolded content line: the upper-case property name, every
/// parameter, and the raw value after the colon.
struct Property {
    name: String,
    params: Vec<(String, String)>,
    value: String,
}

impl Property {
    /// Parse one unfolded content line; `None` for a line without a
    /// colon (never a property, never an error).
    fn parse(line: &str) -> Option<Property> {
        let colon = unquoted_find(line, ':')?;
        let value = line[colon + 1..].to_string();
        let segments = split_outside_quotes(&line[..colon], ';');
        let name = segments[0].trim().to_ascii_uppercase();
        if name.is_empty() {
            return None;
        }
        let mut params = Vec::new();
        for segment in segments.iter().skip(1) {
            // A parameter without `=` is malformed iCal; it is kept
            // empty-named so the strict time-bound check refuses it
            // where it matters and dropped everywhere else.
            if let Some(equals) = unquoted_find(segment, '=') {
                let name = segment[..equals].trim().to_ascii_uppercase();
                if name.is_empty() {
                    return None;
                }
                params.push((name, segment[equals + 1..].to_string()));
            } else {
                params.push((String::new(), segment.to_string()));
            }
        }
        Some(Property {
            name,
            params,
            value,
        })
    }
}

/// The byte index of the first `target` outside double quotes.
fn unquoted_find(text: &str, target: char) -> Option<usize> {
    let mut quoted = false;
    for (index, ch) in text.char_indices() {
        if ch == '"' {
            quoted = !quoted;
        } else if ch == target && !quoted {
            return Some(index);
        }
    }
    None
}

/// Split on the `target` characters outside double quotes.
fn split_outside_quotes(text: &str, target: char) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    for ch in text.chars() {
        if ch == '"' {
            quoted = !quoted;
            current.push(ch);
        } else if ch == target && !quoted {
            parts.push(std::mem::take(&mut current));
        } else {
            current.push(ch);
        }
    }
    parts.push(current);
    parts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::caldav::ical::{escape_text, fold, render_calendar, EventToRender};
    use crate::domain::{CalendarEvent, EventAttendee};

    /// 2025-01-06 08:00:00 UTC, a Monday.
    const MONDAY_8_UTC: i64 = 1_736_150_400_000;
    const HOUR: i64 = 3_600_000;
    /// The plain UTC time bounds of the minimal body.
    const TIMES: &str = "DTSTART:20250106T080000Z\r\nDTEND:20250106T090000Z\r\n";

    /// A minimal timed event in UTC, the plain form.
    fn fields() -> EventFields {
        EventFields {
            summary: "Standup".into(),
            description: String::new(),
            location: String::new(),
            start_ms: MONDAY_8_UTC,
            end_ms: MONDAY_8_UTC + HOUR,
            all_day: false,
            time_zone: Some("UTC".into()),
            repeat: None,
            uid: Some("uid-1@tuta".into()),
            organizer: None,
        }
    }

    /// The renderer's own event fixture (ical.rs): the same input, so
    /// both sides of a round trip share one event.
    fn event() -> CalendarEvent {
        CalendarEvent {
            list_id: "L".into(),
            element_id: "E".into(),
            uid: Some("uid-1@tuta".into()),
            summary: "Standup".into(),
            description: String::new(),
            location: String::new(),
            start_ms: MONDAY_8_UTC,
            end_ms: MONDAY_8_UTC + HOUR,
            sequence: 0,
            recurrence_id_ms: None,
            repeat: None,
            alarm_ids: Vec::new(),
            organizer: None,
            attendees: Vec::new(),
        }
    }

    /// The renderer's default rule: weekly in Berlin, never ending.
    fn rule(frequency: i64) -> RepeatRule {
        RepeatRule {
            frequency,
            interval: 1,
            end_type: 0,
            end_value: None,
            time_zone: "Europe/Berlin".into(),
            excluded_ms: Vec::new(),
            advanced: Vec::new(),
        }
    }

    /// The renderer's body for events, no alarms, the fixed stamp.
    fn rendered(events: &[CalendarEvent]) -> String {
        let alarms: Vec<String> = Vec::new();
        let items: Vec<EventToRender> = events
            .iter()
            .map(|event| EventToRender {
                event,
                modified_ms: MONDAY_8_UTC,
                alarms: &alarms,
            })
            .collect();
        render_calendar(&items)
    }

    /// The renderer's body of `fields` as the writer will serve it
    /// back after a write: one event, the fields applied.
    fn render_fields(fields: &EventFields) -> String {
        let event = CalendarEvent {
            list_id: "L".into(),
            element_id: "E".into(),
            uid: fields.uid.clone(),
            summary: fields.summary.clone(),
            description: fields.description.clone(),
            location: fields.location.clone(),
            start_ms: fields.start_ms,
            end_ms: fields.end_ms,
            sequence: 0,
            recurrence_id_ms: None,
            repeat: fields.repeat.clone(),
            alarm_ids: Vec::new(),
            organizer: fields.organizer.clone(),
            attendees: Vec::new(),
        };
        rendered(&[event])
    }

    /// Field-by-field comparison: the fields hold personal data and
    /// have no `Debug`, so a failure names the field, never a value.
    fn assert_same(actual: &EventFields, expected: &EventFields) {
        for (name, actual, expected) in [
            ("summary", &actual.summary, &expected.summary),
            ("description", &actual.description, &expected.description),
            ("location", &actual.location, &expected.location),
        ] {
            assert!(actual == expected, "{name} mismatch");
        }
        assert_eq!(actual.start_ms, expected.start_ms, "start mismatch");
        assert_eq!(actual.end_ms, expected.end_ms, "end mismatch");
        assert_eq!(actual.all_day, expected.all_day, "all-day mismatch");
        assert!(actual.time_zone == expected.time_zone, "time zone mismatch");
        assert!(actual.uid == expected.uid, "uid mismatch");
        assert!(
            actual.organizer.is_some() == expected.organizer.is_some(),
            "organizer presence mismatch"
        );
        if let (Some(actual), Some(expected)) = (&actual.organizer, &expected.organizer) {
            assert!(
                actual.address == expected.address,
                "organizer address mismatch"
            );
            assert!(actual.name == expected.name, "organizer name mismatch");
        }
        assert!(
            actual.repeat.is_some() == expected.repeat.is_some(),
            "repeat presence mismatch"
        );
        if let (Some(actual), Some(expected)) = (&actual.repeat, &expected.repeat) {
            assert_eq!(actual.frequency, expected.frequency, "frequency mismatch");
            assert_eq!(actual.interval, expected.interval, "interval mismatch");
            assert_eq!(actual.end_type, expected.end_type, "end type mismatch");
            assert!(actual.end_value == expected.end_value, "end value mismatch");
            assert!(actual.time_zone == expected.time_zone, "rule zone mismatch");
            assert!(
                actual.excluded_ms == expected.excluded_ms,
                "excluded dates mismatch"
            );
            assert!(
                actual.advanced == expected.advanced,
                "advanced parts mismatch"
            );
        }
    }

    /// What the renderer's own losses make of `fields` on the way
    /// back: the documented normalizations, in the twin importer's
    /// style.
    fn round_tripped(fields: &EventFields) -> EventFields {
        let mut expected = fields.clone();
        // The importer maps the organizer's address only: the CN
        // never round-trips.
        if let Some(person) = &mut expected.organizer {
            person.name = String::new();
        }
        // An all-day rule repeats in no zone the body could name, and
        // the importer files UTC.
        if expected.all_day {
            if let Some(rule) = &mut expected.repeat {
                rule.time_zone = "UTC".into();
            }
        }
        expected
    }

    fn assert_round_trip(fields: &EventFields) {
        let expected = round_tripped(fields);
        let parsed = match parse_event(&render_fields(fields)) {
            Ok(parsed) => parsed,
            Err(_) => panic!("the rendered body was refused"),
        };
        assert_same(&parsed, &expected);
    }

    /// A minimal well-formed body around `inner`, the `VEVENT`'s own
    /// property lines.
    fn body(inner: &str) -> String {
        format!("BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\n{inner}END:VEVENT\r\nEND:VCALENDAR\r\n")
    }

    /// The error of a refused body: the fields carry personal data
    /// and have no `Debug`, so there is no `unwrap_err` to call.
    fn refused(body: &str) -> ImportError {
        match parse_event(body) {
            Err(error) => error,
            Ok(_) => panic!("the body was imported; a refusal was expected"),
        }
    }

    #[test]
    fn round_trips_a_plain_utc_event() {
        let mut fields = fields();
        fields.description = "Weekly sync\nwith the team".into();
        fields.location = "Room 1, floor; 2".into();
        assert_round_trip(&fields);
        let body = render_fields(&fields);
        assert!(body.contains("DTSTART:20250106T080000Z\r\nDTEND:20250106T090000Z\r\n"));
    }

    #[test]
    fn round_trips_a_weekly_event_with_a_zone_until_and_byday() {
        let mut fields = fields();
        fields.time_zone = Some("Europe/Berlin".into());
        fields.repeat = Some(RepeatRule {
            frequency: 1,
            interval: 1,
            end_type: 2,
            end_value: Some(1_743_379_200_000),
            time_zone: "Europe/Berlin".into(),
            excluded_ms: Vec::new(),
            advanced: vec![(2, "MO".into()), (2, "WE".into())],
        });
        assert_round_trip(&fields);
        let body = render_fields(&fields);
        assert!(body.contains("DTSTART;TZID=Europe/Berlin:20250106T090000\r\n"));
        assert!(body.contains("DTEND;TZID=Europe/Berlin:20250106T100000\r\n"));
        assert!(body.contains("RRULE:FREQ=WEEKLY;UNTIL=20250330T235959Z;BYDAY=MO,WE\r\n"));
        assert!(body.contains("BEGIN:VTIMEZONE\r\nTZID:Europe/Berlin\r\n"));
    }

    #[test]
    fn round_trips_an_all_day_event_with_an_until() {
        let mut fields = fields();
        fields.all_day = true;
        fields.time_zone = None;
        fields.start_ms = 20_094 * DAY_MS; // 2025-01-06
        fields.end_ms = 20_095 * DAY_MS;
        fields.repeat = Some(RepeatRule {
            frequency: 3,
            interval: 1,
            end_type: 2,
            end_value: Some(20_094 * DAY_MS + 5 * 365 * DAY_MS),
            time_zone: "Europe/Berlin".into(),
            excluded_ms: Vec::new(),
            advanced: Vec::new(),
        });
        assert_round_trip(&fields);
        let body = render_fields(&fields);
        assert!(body.contains("DTSTART;VALUE=DATE:20250106\r\nDTEND;VALUE=DATE:20250107\r\n"));
        assert!(body.contains("RRULE:FREQ=YEARLY;UNTIL=20300104\r\n"));
    }

    #[test]
    fn round_trips_a_month_end_monthly_rule() {
        // A start on the 31st: the renderer clamps the rule to each
        // month's last day, and the importer maps the pattern back
        // onto the plain rule Tuta clamps.
        let mut fields = fields();
        fields.time_zone = Some("Europe/Berlin".into());
        fields.start_ms = MONDAY_8_UTC + 25 * DAY_MS; // 2025-01-31 08:00 UTC
        fields.end_ms = fields.start_ms + HOUR;
        fields.repeat = Some(rule(2));
        assert_round_trip(&fields);
        let body = render_fields(&fields);
        assert!(body.contains("DTSTART;TZID=Europe/Berlin:20250131T090000\r\n"));
        assert!(body.contains("RRULE:FREQ=MONTHLY;BYMONTHDAY=28,29,30,31;BYSETPOS=-1\r\n"));

        // The same rule bounded by a count.
        let mut bounded = fields.repeat.clone().unwrap();
        bounded.end_type = 1;
        bounded.end_value = Some(5);
        fields.repeat = Some(bounded);
        assert_round_trip(&fields);
        let body = render_fields(&fields);
        assert!(body.contains("RRULE:FREQ=MONTHLY;COUNT=5;BYMONTHDAY=28,29,30,31;BYSETPOS=-1\r\n"));
    }

    #[test]
    fn round_trips_a_daily_utc_rule_with_interval_and_count() {
        let mut fields = fields();
        fields.repeat = Some(RepeatRule {
            frequency: 0,
            interval: 2,
            end_type: 1,
            end_value: Some(5),
            time_zone: "UTC".into(),
            excluded_ms: Vec::new(),
            advanced: Vec::new(),
        });
        assert_round_trip(&fields);
        let body = render_fields(&fields);
        assert!(body.contains("DTSTART:20250106T080000Z\r\n"));
        assert!(body.contains("RRULE:FREQ=DAILY;INTERVAL=2;COUNT=5\r\n"));

        // A zone the bundled data does not know repeats in UTC when
        // served; the import maps what the body says.
        fields.repeat.as_mut().unwrap().time_zone = "Nowhere/Special".into();
        let parsed = parse_event(&render_fields(&fields)).unwrap();
        assert!(parsed.time_zone.as_deref() == Some("UTC"));
        assert!(parsed
            .repeat
            .as_ref()
            .is_some_and(|rule| rule.time_zone == "UTC"));
    }

    #[test]
    fn round_trips_a_daily_rule_with_an_until() {
        // Tuta's end is exclusive: ending at the start of the third
        // occurrence leaves two.
        let mut fields = fields();
        fields.repeat = Some(RepeatRule {
            frequency: 0,
            interval: 1,
            end_type: 2,
            end_value: Some(MONDAY_8_UTC + 2 * DAY_MS),
            time_zone: "UTC".into(),
            excluded_ms: Vec::new(),
            advanced: Vec::new(),
        });
        assert_round_trip(&fields);
        let body = render_fields(&fields);
        assert!(body.contains("RRULE:FREQ=DAILY;UNTIL=20250108T075959Z\r\n"));
    }

    #[test]
    fn round_trips_an_escape_hostile_event() {
        let mut fields = fields();
        // Every escape-worthy character, and a summary that would
        // smuggle a component if the newline were not escaped.
        fields.summary = "Lunch; with, Bob\nBEGIN:VALARM".into();
        fields.description = format!("one; two, three\nfour\n{}end", "word ".repeat(60));
        fields.location = "Room \"1\"; back\\slash".into();
        fields.uid = Some("weird,uid;x@tuta".into());
        fields.organizer = Some(EventPerson {
            name: "Ann, \"Boss\"".into(),
            address: "ann@example.invalid".into(),
        });
        assert_round_trip(&fields);
        let body = render_fields(&fields);
        assert!(body.contains("SUMMARY:Lunch\\; with\\, Bob\\nBEGIN:VALARM\r\n"));
        assert!(!body.contains("\r\nBEGIN:VALARM"));
    }

    #[test]
    fn a_body_without_a_complete_vevent_is_refused() {
        for body in [
            "",
            "not an icalendar",
            "BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n",
            // No VCALENDAR wrapper: the bridge serves none such.
            "BEGIN:VEVENT\r\nSUMMARY:X\r\nEND:VEVENT\r\n",
            // Unterminated.
            "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nSUMMARY:X\r\n",
            // An END without its BEGIN.
            "BEGIN:VCALENDAR\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n",
        ] {
            let error = refused(body);
            assert!(error == ImportError::NoVevent, "{body:?}");
            assert_eq!(error.message(), "the request body holds no complete vevent");
        }
    }

    #[test]
    fn a_body_with_more_than_one_vevent_is_refused() {
        let body = concat!(
            "BEGIN:VCALENDAR\r\n",
            "BEGIN:VEVENT\r\n",
            "DTSTART:20250106T080000Z\r\n",
            "DTEND:20250106T090000Z\r\n",
            "SUMMARY:One\r\n",
            "END:VEVENT\r\n",
            "BEGIN:VEVENT\r\n",
            "DTSTART:20250106T080000Z\r\n",
            "DTEND:20250106T090000Z\r\n",
            "SUMMARY:Two\r\n",
            "END:VEVENT\r\n",
            "END:VCALENDAR\r\n",
        );
        let error = refused(body);
        assert!(error == ImportError::TooManyVevents);
        assert_eq!(
            error.message(),
            "the request body holds more than one vevent"
        );
    }

    #[test]
    fn an_edited_occurrence_body_is_refused() {
        // The body a client writes back after moving one occurrence:
        // the master and the override, as the reader serves them.
        let mut master = event();
        let mut repeat = rule(1);
        let moved = MONDAY_8_UTC + 7 * DAY_MS;
        let removed = MONDAY_8_UTC + 14 * DAY_MS;
        repeat.excluded_ms = vec![moved, removed];
        master.repeat = Some(repeat);
        let mut altered = event();
        altered.element_id = "E2".into();
        altered.recurrence_id_ms = Some(moved);
        altered.start_ms = moved + 2 * HOUR;
        altered.end_ms = moved + 3 * HOUR;
        let error = refused(&rendered(&[altered, master]));
        assert!(error == ImportError::PerOccurrence);
        assert_eq!(
            error.message(),
            "the event edits or lists single occurrences of a series, which the \
bridge does not support"
        );
    }

    #[test]
    fn a_body_with_an_exdate_is_refused() {
        let mut weekly = event();
        let mut repeat = rule(1);
        repeat.excluded_ms = vec![MONDAY_8_UTC + 7 * DAY_MS];
        weekly.repeat = Some(repeat);
        let error = refused(&rendered(&[weekly]));
        assert!(error == ImportError::PerOccurrence);
    }

    #[test]
    fn a_leap_year_end_of_month_rule_is_refused() {
        // The renderer's Feb-29 clamp carries a BYMONTH the importer
        // does not accept: refused, never accepted and mangled.
        let mut leap = event();
        leap.start_ms = 19_782 * DAY_MS; // 2024-02-29
        leap.end_ms = 19_783 * DAY_MS;
        leap.repeat = Some(rule(3));
        let error = refused(&rendered(&[leap]));
        assert!(error == ImportError::BadRule);
        assert_eq!(
            error.message(),
            "the event's repeat rule is not in a form the bridge serves"
        );
    }

    #[test]
    fn an_attendee_other_than_the_organizer_refuses_the_event() {
        let mut meeting = event();
        meeting.organizer = Some(EventPerson {
            name: "Ann".into(),
            address: "ann@example.invalid".into(),
        });
        meeting.attendees = vec![EventAttendee {
            person: EventPerson {
                name: "Bob".into(),
                address: "bob@example.invalid".into(),
            },
            status: 2,
        }];
        let error = refused(&rendered(&[meeting]));
        assert!(error == ImportError::OtherAttendees);
        assert_eq!(
            error.message(),
            "the event carries attendees other than the organizer, which the \
bridge cannot send invitations for"
        );
    }

    #[test]
    fn an_attendee_that_is_the_organizer_drops_silently() {
        let body = concat!(
            "BEGIN:VCALENDAR\r\n",
            "BEGIN:VEVENT\r\n",
            "DTSTART:20250106T080000Z\r\n",
            "DTEND:20250106T090000Z\r\n",
            "SUMMARY:Personal\r\n",
            "ORGANIZER;CN=Me:mailto:Me@Example.invalid\r\n",
            "ATTENDEE;CN=Me;CUTYPE=INDIVIDUAL;ROLE=REQ-PARTICIPANT;PARTSTAT=ACCEPTED:mailto:me@example.invalid\r\n",
            "END:VEVENT\r\n",
            "END:VCALENDAR\r\n",
        );
        let parsed = parse_event(body).unwrap();
        assert!(parsed
            .organizer
            .as_ref()
            .is_some_and(|person| person.address == "Me@Example.invalid"));
        // Without an organizer, no attendee can be a personal one.
        let without = body.replace("ORGANIZER;CN=Me:mailto:Me@Example.invalid\r\n", "");
        assert!(refused(&without) == ImportError::OtherAttendees);
    }

    #[test]
    fn unmappable_start_and_end_forms_are_refused() {
        for inner in [
            // No times at all, or only one bound.
            "SUMMARY:X\r\n",
            "DTSTART:20250106T080000Z\r\n",
            "DTEND:20250106T090000Z\r\n",
            // Mixed forms between the bounds.
            "DTSTART;VALUE=DATE:20250106\r\nDTEND:20250106T090000Z\r\n",
            "DTSTART:20250106T080000Z\r\nDTEND;VALUE=DATE:20250107\r\n",
            "DTSTART:20250106T080000Z\r\nDTEND;TZID=Europe/Berlin:20250106T100000\r\n",
            // The same zone on both bounds only.
            "DTSTART;TZID=Europe/Berlin:20250106T090000\r\nDTEND:20250106T100000Z\r\n",
            "DTSTART;TZID=Europe/Berlin:20250106T090000\r\nDTEND;TZID=Europe/Rome:20250106T100000\r\n",
            // All-day bounds take no zone.
            "DTSTART;VALUE=DATE;TZID=Europe/Berlin:20250106\r\nDTEND;VALUE=DATE:20250107\r\n",
            // Explicit offsets, floating times and other shapes the
            // renderer never serves.
            "DTSTART:20250106T090000+0100\r\nDTEND:20250106T100000+0100\r\n",
            "DTSTART:20250106T090000\r\nDTEND:20250106T100000\r\n",
            "DTSTART;VALUE=DATE-TIME:20250106T080000Z\r\nDTEND:20250106T090000Z\r\n",
            "DTSTART:20250106T0800Z\r\nDTEND:20250106T0900Z\r\n",
            "DTSTART:20251301T080000Z\r\nDTEND:20251301T090000Z\r\n",
            "DTSTART:20250106T248000Z\r\nDTEND:20250106T258000Z\r\n",
        ] {
            let error = refused(&body(inner));
            assert!(error == ImportError::BadTimes, "{inner:?}");
        }
        assert_eq!(
            ImportError::BadTimes.message(),
            "the event's start or end is not in a form the bridge serves"
        );
    }

    #[test]
    fn a_zone_the_bundled_data_does_not_know_is_refused() {
        for tzid in ["Mars/Olympus_Mons", "UTC", "Europe/Nowhere"] {
            let inner = format!(
                "DTSTART;TZID={tzid}:20250106T090000\r\nDTEND;TZID={tzid}:20250106T100000\r\n"
            );
            let error = refused(&body(&inner));
            assert!(error == ImportError::UnknownZone, "{tzid}");
        }
        assert_eq!(
            ImportError::UnknownZone.message(),
            "the event's time zone is not known to the bridge"
        );
    }

    #[test]
    fn a_repeat_rule_the_renderer_never_writes_is_refused() {
        let base = "DTSTART:20250106T080000Z\r\nDTEND:20250106T090000Z\r\n";
        for rrule in [
            // Frequencies outside the four the bridge serves.
            "FREQ=SECONDLY",
            "FREQ=MINUTELY",
            "FREQ=HOURLY",
            // Values the renderer never writes.
            "FREQ=DAILY;INTERVAL=0",
            "FREQ=DAILY;INTERVAL=-2",
            "FREQ=DAILY;COUNT=0",
            "FREQ=DAILY;COUNT=x",
            "FREQ=DAILY;COUNT=2;UNTIL=20250108T075959Z",
            "FREQ=DAILY;UNTIL=20250107",
            "FREQ=DAILY;UNTIL=garbage",
            "FREQ=DAILY;COUNT=2;COUNT=3",
            "FREQ=DAILY;FREQ=WEEKLY",
            "COUNT=2",
            "FREQ",
            "FREQ=",
            "FREQ=DAILY;;COUNT=2",
            "FREQ=DAILY;",
            // BYDAY only as the weekly plain form.
            "FREQ=WEEKLY;BYDAY=MO,-1FR",
            "FREQ=MONTHLY;BYDAY=-1FR",
            "FREQ=WEEKLY;BYDAY=MO,XX",
            "FREQ=WEEKLY;BYDAY=MO,MO",
            // Parts the month-end form does not take.
            "FREQ=MONTHLY;BYMONTH=2",
            "FREQ=YEARLY;BYMONTH=2;BYMONTHDAY=28,29;BYSETPOS=-1",
            "FREQ=MONTHLY;BYMONTHDAY=28;BYSETPOS=-1",
            "FREQ=MONTHLY;BYMONTHDAY=28,29,30,31",
            "FREQ=MONTHLY;BYSETPOS=-1",
            "FREQ=MONTHLY;BYMONTHDAY=28,29,30,31;BYSETPOS=1",
            // Parts the renderer never emits at all.
            "FREQ=DAILY;BYHOUR=9",
            "FREQ=DAILY;BYMINUTE=0",
            "FREQ=DAILY;BYYEARDAY=1",
            "FREQ=DAILY;BYWEEKNO=1",
            "FREQ=DAILY;WKST=MO",
            "FREQ=WEEKLY;BYDAY=MO;BYSETPOS=1",
        ] {
            let inner = format!("{base}RRULE:{rrule}\r\n");
            let error = refused(&body(&inner));
            assert!(error == ImportError::BadRule, "{rrule}");
        }
        // Two rules refuse the event as well.
        let inner = concat!(
            "DTSTART:20250106T080000Z\r\nDTEND:20250106T090000Z\r\n",
            "RRULE:FREQ=DAILY\r\nRRULE:FREQ=WEEKLY\r\n",
        );
        assert!(refused(&body(inner)) == ImportError::BadRule);
        // An all-day rule ends on a date, never a UTC instant.
        let all_day = concat!(
            "DTSTART;VALUE=DATE:20250106\r\nDTEND;VALUE=DATE:20250107\r\n",
            "RRULE:FREQ=DAILY;UNTIL=20250107T235959Z\r\n",
        );
        assert!(refused(&body(all_day)) == ImportError::BadRule);
        assert_eq!(
            ImportError::BadRule.message(),
            "the event's repeat rule is not in a form the bridge serves"
        );
    }

    #[test]
    fn a_month_end_list_that_is_not_the_clamp_is_refused() {
        // A start on the 31st: only the exact clamp list maps, so a
        // shorter, longer or gapped list never imports as the plain
        // rule (which would silently change the event's meaning).
        let day31 = "DTSTART:20250131T080000Z\r\nDTEND:20250131T090000Z\r\n";
        for rrule in [
            "FREQ=MONTHLY;BYMONTHDAY=28,29;BYSETPOS=-1",
            "FREQ=MONTHLY;BYMONTHDAY=31;BYSETPOS=-1",
            "FREQ=MONTHLY;BYMONTHDAY=28,29,30,31,32;BYSETPOS=-1",
        ] {
            let inner = format!("{day31}RRULE:{rrule}\r\n");
            let error = refused(&body(&inner));
            assert!(error == ImportError::BadRule, "{rrule}");
        }
        // And the clamp list itself never maps onto another day.
        let day6 = "DTSTART:20250106T080000Z\r\nDTEND:20250106T090000Z\r\n";
        let inner = format!("{day6}RRULE:FREQ=MONTHLY;BYMONTHDAY=28,29,30,31;BYSETPOS=-1\r\n");
        assert!(refused(&body(&inner)) == ImportError::BadRule);
    }

    #[test]
    fn an_rdate_refuses_the_event_like_other_occurrence_data() {
        let inner = concat!(
            "DTSTART:20250106T080000Z\r\nDTEND:20250106T090000Z\r\n",
            "RDATE:20250107T080000Z\r\n",
        );
        assert!(refused(&body(inner)) == ImportError::PerOccurrence);
    }

    #[test]
    fn alarms_and_timezones_in_the_body_are_ignored() {
        // The renderer's own body for an event with alarms.
        let meeting = event();
        let alarms = vec!["15M".to_string(), "1D".to_string(), "bogus".to_string()];
        let body = render_calendar(&[EventToRender {
            event: &meeting,
            modified_ms: MONDAY_8_UTC,
            alarms: &alarms,
        }]);
        let parsed = parse_event(&body).unwrap();
        assert_eq!(parsed.summary, "Standup");
        assert!(parsed.repeat.is_none());

        // A hand-written VTIMEZONE beside a zoned event: accepted and
        // ignored — the DTSTART's TZID is what counts, and it is
        // valid. The observance's own DTSTART must not leak into the
        // event's times.
        let body = concat!(
            "BEGIN:VCALENDAR\r\n",
            "BEGIN:VTIMEZONE\r\n",
            "TZID:Europe/Berlin\r\n",
            "BEGIN:STANDARD\r\n",
            "DTSTART:19700101T000000\r\n",
            "TZOFFSETFROM:+0100\r\n",
            "TZOFFSETTO:+0100\r\n",
            "END:STANDARD\r\n",
            "END:VTIMEZONE\r\n",
            "BEGIN:VEVENT\r\n",
            "DTSTART;TZID=Europe/Berlin:20250106T090000\r\n",
            "DTEND;TZID=Europe/Berlin:20250106T100000\r\n",
            "SUMMARY:Zoned\r\n",
            "END:VEVENT\r\n",
            "END:VCALENDAR\r\n",
        );
        let parsed = parse_event(body).unwrap();
        assert!(parsed.time_zone.as_deref() == Some("Europe/Berlin"));
        assert_eq!(parsed.start_ms, MONDAY_8_UTC);
    }

    #[test]
    fn properties_the_renderer_never_serves_are_dropped() {
        let body = concat!(
            "BEGIN:VCALENDAR\r\n",
            "METHOD:PUBLISH\r\n",
            "VERSION:2.0\r\n",
            "PRODID:-//Example//EN\r\n",
            "CALSCALE:GREGORIAN\r\n",
            "BEGIN:VEVENT\r\n",
            "DTSTART:20250106T080000Z\r\n",
            "DTEND:20250106T090000Z\r\n",
            "DTSTAMP:20250106T080000Z\r\n",
            "SEQUENCE:3\r\n",
            "CREATED:20250106T070000Z\r\n",
            "LAST-MODIFIED:20250106T073000Z\r\n",
            "STATUS:CONFIRMED\r\n",
            "TRANSP:OPAQUE\r\n",
            "CLASS:PRIVATE\r\n",
            "PRIORITY:1\r\n",
            "transp:opaque\r\n",
            "X-CUSTOM-THING:whatever\r\n",
            "SOMETHING-UNKNOWN:value\r\n",
            "a colon-less line\r\n",
            "END:VEVENT\r\n",
            "END:VCALENDAR\r\n",
        );
        let parsed = parse_event(body).unwrap();
        assert_eq!(parsed.summary, "");
        assert_eq!(parsed.start_ms, MONDAY_8_UTC);
    }

    #[test]
    fn folded_lines_parse_from_crlf_lf_and_tab_continuations() {
        let description = "a ".repeat(60);
        let folded = fold(&format!("{TIMES}DESCRIPTION:{description}"));
        assert!(folded.contains("\r\n "), "the fixture is folded");
        let parsed = parse_event(&body(&folded)).unwrap();
        assert_eq!(parsed.description, description);

        // The same body with bare LF ends, as some clients send.
        let lf = parse_event(&body(&folded).replace("\r\n", "\n")).unwrap();
        assert_eq!(lf.description, description);

        // A tab continuation, the other legal marker.
        let tab = parse_event(&body(&format!("{TIMES}DESCRIPTION:one\n\ttwo\n"))).unwrap();
        assert_eq!(tab.description, "onetwo");
    }

    #[test]
    fn text_unescaping_inverts_the_renderer() {
        // The renderer's own escaping fixture, inverted; a CR never
        // survives the renderer (it drops control characters).
        let escaped = escape_text("a,b;c\\d\ne\tf");
        let inner = format!("{TIMES}SUMMARY:{escaped}\r\n");
        let parsed = parse_event(&body(&inner)).unwrap();
        assert_eq!(parsed.summary, "a,b;c\\d\ne\tf");
        // Both newline escapes, a backslash before anything else, and
        // a trailing one: never lose a character.
        let inner = format!("{TIMES}SUMMARY:x\\Ny\\Nz\\;\\,\\\\q\\\r\n");
        let parsed = parse_event(&body(&inner)).unwrap();
        assert_eq!(parsed.summary, "x\ny\nz;,\\q\\");
    }

    #[test]
    fn a_body_without_a_uid_keeps_none() {
        let inner = "DTSTART:20250106T080000Z\r\nDTEND:20250106T090000Z\r\n";
        assert!(parse_event(&body(inner)).unwrap().uid.is_none());
        // An empty UID is the same as none, and an organizer line
        // without a mailto address is treated as absent — the
        // renderer drops both shapes itself.
        let with_uid = format!("{inner}UID:\r\n");
        assert!(parse_event(&body(&with_uid)).unwrap().uid.is_none());
        let with_organizer = format!("{inner}ORGANIZER:urn:uuid:x\r\n");
        assert!(parse_event(&body(&with_organizer))
            .unwrap()
            .organizer
            .is_none());
    }

    #[test]
    fn case_and_quoting_tolerances_of_the_common_clients() {
        let body = concat!(
            "BEGIN:VCALENDAR\r\n",
            "BEGIN:VEVENT\r\n",
            "dtstart;tzid=\"Europe/Berlin\":20250106T090000\r\n",
            "dtend;TZID=Europe/Berlin:20250106T100000\r\n",
            "rrule:freq=weekly;until=20250330T235959Z;byday=mo,we\r\n",
            "END:VEVENT\r\n",
            "END:VCALENDAR\r\n",
        );
        let parsed = parse_event(body).unwrap();
        assert!(parsed.time_zone.as_deref() == Some("Europe/Berlin"));
        let rule = parsed.repeat.unwrap();
        assert_eq!(rule.frequency, 1);
        assert_eq!(rule.end_type, 2);
        assert_eq!(rule.end_value, Some(1_743_379_200_000));
        assert_eq!(
            rule.advanced,
            vec![(2, "MO".to_string()), (2, "WE".to_string())]
        );
    }

    #[test]
    fn a_zoned_single_event_without_a_rule_imports() {
        // The common client shape: a local event without a rule.
        let inner =
            "DTSTART;TZID=Europe/Berlin:20250106T090000\r\nDTEND;TZID=Europe/Berlin:20250106T100000\r\n";
        let parsed = parse_event(&body(inner)).unwrap();
        assert!(parsed.time_zone.as_deref() == Some("Europe/Berlin"));
        assert_eq!(parsed.start_ms, MONDAY_8_UTC);
        assert!(parsed.repeat.is_none());
    }
}
