//! iCalendar (RFC 5545) rendering of Tuta events.
//!
//! One CalDAV resource is one `VCALENDAR`: the repeating event (if the
//! calendar holds it) and every altered occurrence sharing its UID. A
//! series Tuta split in two ("edit this and all future events") is two
//! resources, the later one under a derived UID (see
//! [`crate::domain::calendar::group_resources`]); the caller sets that
//! UID on the events it hands in.
//!
//! Times:
//! - A non-repeating timed event, and every altered occurrence, is
//!   written in UTC (`...Z`): Tuta stores UTC instants, so this is exact
//!   and every client shows it in its own zone.
//! - All-day events (both bounds on UTC midnight, the way Tuta stores
//!   them) are `VALUE=DATE` with an exclusive `DTEND`.
//! - A repeating timed event is written in the zone its Tuta rule
//!   repeats in (`DTSTART;TZID=...` plus a `VTIMEZONE`), so clients
//!   expand it across DST changes exactly like Tuta. A zone the bundled
//!   data does not know falls back to UTC, which is also what the Tuta
//!   SDK does with it.
//!
//! Recurrence: frequency, interval, `COUNT`/`UNTIL` and the advanced
//! `BYxxx` parts map to an `RRULE`, removed occurrences to `EXDATE`
//! (in the rule's zone, like `DTSTART`). Where Tuta differs from RFC
//! 5545 the rule is rewritten to match Tuta: a monthly rule on day
//! 29-31 and a yearly rule on Feb 29 fall back to the month's last day.
//! `COUNT` is plain RFC 5545, removed occurrences included, which is
//! how the Tuta web app expands and exports it. A rule that cannot be
//! expressed is never approximated: the event is served as its first
//! occurrence only, and its description says so (see
//! [`UNSUPPORTED_NOTE`]).
//!
//! Text values are escaped, parameter values quoted with RFC 6868
//! caret encoding, lines folded at 75 octets on character boundaries,
//! and every line ends in CRLF.

use std::collections::BTreeMap;

use time::{Month, OffsetDateTime, PrimitiveDateTime};

use super::timezone::{format_local, year_start, Zone};
use crate::domain::calendar::DAY_MS;
use crate::domain::{CalendarEvent, EventPerson, RepeatRule};

/// The `PRODID` of every rendered calendar.
pub const PRODID: &str = "-//tuta-bridge//CalDAV read-only//EN";

/// Prepended to the description of a repeating event whose rule cannot
/// be expressed in iCalendar; only the first occurrence is served.
pub const UNSUPPORTED_NOTE: &str = "[tuta-bridge: this event repeats in Tuta, but its repeat rule \
cannot be expressed in iCalendar. Only the first occurrence is shown here; see the Tuta app \
for the others.]";

/// One event of a resource, with what the renderer needs besides it.
pub struct EventToRender<'a> {
    pub event: &'a CalendarEvent,
    /// When the bridge first saw this content: the `DTSTAMP`.
    pub modified_ms: i64,
    /// The user's alarm triggers (`"15M"`, `"1H"`, ...).
    pub alarms: &'a [String],
}

/// Render one resource. `events` may come in any order; the output is
/// deterministic for equal input.
pub fn render_calendar(events: &[EventToRender<'_>]) -> String {
    let mut ordered: Vec<&EventToRender<'_>> = events.iter().collect();
    ordered.sort_by(|a, b| {
        (
            a.event.recurrence_id_ms.is_some(),
            a.event.recurrence_id_ms,
            &a.event.list_id,
            &a.event.element_id,
        )
            .cmp(&(
                b.event.recurrence_id_ms.is_some(),
                b.event.recurrence_id_ms,
                &b.event.list_id,
                &b.event.element_id,
            ))
    });
    let master = ordered
        .iter()
        .find(|item| item.event.repeat.is_some() && item.event.recurrence_id_ms.is_none())
        .map(|item| item.event);
    let overridden: Vec<i64> = ordered
        .iter()
        .filter_map(|item| item.event.recurrence_id_ms)
        .collect();
    let master_all_day = master.map(CalendarEvent::is_all_day);

    let mut lines: Vec<String> = vec![
        "BEGIN:VCALENDAR".into(),
        "VERSION:2.0".into(),
        format!("PRODID:{PRODID}"),
        "CALSCALE:GREGORIAN".into(),
    ];
    let mut zones: Vec<String> = Vec::new();
    let mut components: Vec<String> = Vec::new();
    for item in &ordered {
        let rendered = render_event(item, &overridden, master_all_day);
        if let Some((zone, from, to)) = rendered.zone {
            if !zones.contains(&zone.name) {
                zones.push(zone.name.clone());
                lines.extend(zone.vtimezone(from, to));
            }
        }
        components.extend(rendered.lines);
    }
    lines.extend(components);
    lines.push("END:VCALENDAR".into());

    let mut out = String::new();
    for line in lines {
        out.push_str(&fold(&line));
    }
    out
}

struct RenderedEvent {
    lines: Vec<String>,
    /// The zone a `TZID` names, with the range its `VTIMEZONE` covers.
    zone: Option<(Zone, OffsetDateTime, OffsetDateTime)>,
}

fn render_event(
    item: &EventToRender<'_>,
    overridden: &[i64],
    master_all_day: Option<bool>,
) -> RenderedEvent {
    let event = item.event;
    let all_day = event.is_all_day();
    let mut lines = vec!["BEGIN:VEVENT".to_string()];
    let uid = match &event.uid {
        Some(uid) if !uid.is_empty() => uid.clone(),
        _ => format!("{}-{}@tuta-bridge.invalid", event.list_id, event.element_id),
    };
    lines.push(format!("UID:{}", escape_text(&uid)));
    lines.push(format!("DTSTAMP:{}", format_utc(item.modified_ms)));

    let mut zone_out = None;
    let mut note = None;
    let recurrence = match (&event.repeat, event.recurrence_id_ms) {
        (Some(rule), None) => Some(map_rule(event, rule, overridden)),
        _ => None,
    };
    match &recurrence {
        Some(Ok(mapped)) if mapped.zone.is_some() => {
            let zone = mapped.zone.as_ref().expect("checked");
            lines.push(format!(
                "DTSTART;TZID={}:{}",
                zone.name,
                format_local(zone.local(instant(event.start_ms)))
            ));
            lines.push(format!(
                "DTEND;TZID={}:{}",
                zone.name,
                format_local(zone.local(instant(event.end_ms.max(event.start_ms))))
            ));
        }
        _ => push_times(&mut lines, event, all_day),
    }
    if let Some(recurrence_id) = event.recurrence_id_ms {
        if master_all_day.unwrap_or(all_day) {
            lines.push(format!(
                "RECURRENCE-ID;VALUE=DATE:{}",
                format_date(recurrence_id)
            ));
        } else {
            lines.push(format!("RECURRENCE-ID:{}", format_utc(recurrence_id)));
        }
    }
    match recurrence {
        Some(Ok(mapped)) => {
            lines.push(format!("RRULE:{}", mapped.rrule));
            // One EXDATE line per value keeps lines short and diffable;
            // same form as DTSTART, so clients match it to an instance.
            for excluded in mapped.exdates {
                match (&mapped.zone, all_day) {
                    (_, true) => lines.push(format!("EXDATE;VALUE=DATE:{}", format_date(excluded))),
                    (Some(zone), false) => lines.push(format!(
                        "EXDATE;TZID={}:{}",
                        zone.name,
                        format_local(zone.local(instant(excluded)))
                    )),
                    (None, false) => lines.push(format!("EXDATE:{}", format_utc(excluded))),
                }
            }
            if let Some(zone) = mapped.zone {
                // The VTIMEZONE covers the year before the start to ten
                // years past the later of the start and the last edit:
                // fixed by the data, so the body stays byte-identical
                // for one ETag.
                let start_year = instant(event.start_ms).year();
                let anchor_year = instant(event.start_ms.max(item.modified_ms)).year();
                zone_out = Some((
                    zone,
                    year_start(start_year - 1),
                    year_start(anchor_year + 11),
                ));
            }
        }
        Some(Err(())) => {
            note = Some(UNSUPPORTED_NOTE);
            lines.push("X-TUTA-BRIDGE-RECURRENCE:UNSUPPORTED".into());
        }
        None => {}
    }
    if event.sequence > 0 {
        lines.push(format!("SEQUENCE:{}", event.sequence));
    }
    lines.push(format!("SUMMARY:{}", escape_text(&event.summary)));

    let (plain, html) = description_parts(&event.description);
    let description = match (note, plain.is_empty()) {
        (Some(note), true) => note.to_string(),
        (Some(note), false) => format!("{note}\n\n{plain}"),
        (None, _) => plain,
    };
    if !description.is_empty() {
        lines.push(format!("DESCRIPTION:{}", escape_text(&description)));
    }
    if let Some(html) = html {
        lines.push(format!(
            "X-ALT-DESC;FMTTYPE=text/html:{}",
            escape_text(&html)
        ));
    }
    if !event.location.is_empty() {
        lines.push(format!("LOCATION:{}", escape_text(&event.location)));
    }
    if let Some(organizer) = &event.organizer {
        if let Some(line) = person_line("ORGANIZER", organizer, None) {
            lines.push(line);
        }
    }
    for attendee in &event.attendees {
        if let Some(line) = person_line("ATTENDEE", &attendee.person, Some(attendee.status)) {
            lines.push(line);
        }
    }
    for trigger in item.alarms {
        if let Some(duration) = alarm_trigger(trigger) {
            lines.push("BEGIN:VALARM".into());
            lines.push("ACTION:DISPLAY".into());
            lines.push("DESCRIPTION:Reminder".into());
            lines.push(format!("TRIGGER:{duration}"));
            lines.push("END:VALARM".into());
        }
    }
    lines.push("END:VEVENT".into());
    RenderedEvent {
        lines,
        zone: zone_out,
    }
}

/// `DTSTART`/`DTEND` in UTC, or as dates for an all-day event.
fn push_times(lines: &mut Vec<String>, event: &CalendarEvent, all_day: bool) {
    if all_day {
        lines.push(format!(
            "DTSTART;VALUE=DATE:{}",
            format_date(event.start_ms)
        ));
        lines.push(format!("DTEND;VALUE=DATE:{}", format_date(event.end_ms)));
    } else {
        lines.push(format!("DTSTART:{}", format_utc(event.start_ms)));
        lines.push(format!(
            "DTEND:{}",
            format_utc(event.end_ms.max(event.start_ms))
        ));
    }
}

/// An `RRULE` with its `EXDATE`s and the zone its `DTSTART` uses.
struct MappedRule {
    rrule: String,
    exdates: Vec<i64>,
    zone: Option<Zone>,
}

const FREQUENCIES: [&str; 4] = ["DAILY", "WEEKLY", "MONTHLY", "YEARLY"];
/// Tuta rule type → RRULE part name, in Tuta's numbering.
const PARTS: [&str; 9] = [
    "BYMINUTE",
    "BYHOUR",
    "BYDAY",
    "BYMONTHDAY",
    "BYYEARDAY",
    "BYWEEKNO",
    "BYMONTH",
    "BYSETPOS",
    "WKST",
];
/// The order parts are written in.
const PART_ORDER: [&str; 9] = [
    "BYMONTH",
    "BYWEEKNO",
    "BYYEARDAY",
    "BYMONTHDAY",
    "BYDAY",
    "BYHOUR",
    "BYMINUTE",
    "BYSETPOS",
    "WKST",
];
const WEEKDAYS: [&str; 7] = ["MO", "TU", "WE", "TH", "FR", "SA", "SU"];

/// Map a Tuta repeat rule; `Err` when it cannot be expressed faithfully.
fn map_rule(
    event: &CalendarEvent,
    rule: &RepeatRule,
    overridden: &[i64],
) -> Result<MappedRule, ()> {
    let all_day = event.is_all_day();
    let frequency = usize::try_from(rule.frequency)
        .ok()
        .and_then(|index| FREQUENCIES.get(index))
        .ok_or(())?;
    let interval = rule.interval.max(1);

    // Advanced parts, grouped by name and validated.
    let mut parts: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for (kind, value) in &rule.advanced {
        let name = usize::try_from(*kind)
            .ok()
            .and_then(|index| PARTS.get(index))
            .ok_or(())?;
        for piece in value.split(',') {
            let piece = piece.trim().to_ascii_uppercase();
            if !valid_part_value(name, &piece) {
                return Err(());
            }
            let values = parts.entry(name).or_default();
            if !values.contains(&piece) {
                values.push(piece);
            }
        }
    }
    check_combination(frequency, &parts, all_day)?;

    let zone = if all_day {
        None
    } else {
        Zone::by_name(&rule.time_zone)
    };
    let start_local = local_start(event.start_ms, all_day, zone.as_ref());

    // Tuta moves a monthly occurrence on the 29th-31st (and a yearly
    // one on Feb 29) to the last day of shorter months; RFC 5545 skips
    // those months. Pick the last of the candidate days instead.
    if parts.is_empty() {
        let day = start_local.day();
        if *frequency == "MONTHLY" && day > 28 {
            parts.insert("BYMONTHDAY", (28..=day).map(|d| d.to_string()).collect());
            parts.insert("BYSETPOS", vec!["-1".into()]);
        } else if *frequency == "YEARLY" && start_local.month() == Month::February && day == 29 {
            parts.insert("BYMONTH", vec!["2".into()]);
            parts.insert("BYMONTHDAY", vec!["28".into(), "29".into()]);
            parts.insert("BYSETPOS", vec!["-1".into()]);
        }
    }

    let mut rrule = format!("FREQ={frequency}");
    if interval > 1 {
        rrule.push_str(&format!(";INTERVAL={interval}"));
    }
    let exdates: Vec<i64> = {
        let mut excluded: Vec<i64> = rule
            .excluded_ms
            .iter()
            .map(|&ms| {
                if all_day {
                    ms.div_euclid(DAY_MS) * DAY_MS
                } else {
                    ms
                }
            })
            .filter(|ms| {
                // An altered occurrence replaces the instance; an EXDATE
                // for it would hide the replacement in some clients.
                !overridden.iter().any(|o| {
                    if all_day {
                        o.div_euclid(DAY_MS) == ms.div_euclid(DAY_MS)
                    } else {
                        o == ms
                    }
                })
            })
            .collect();
        excluded.sort_unstable();
        excluded.dedup();
        excluded
    };
    match (rule.end_type, rule.end_value) {
        (0, _) => {}
        // Removed occurrences count, as in the Tuta web app.
        (1, Some(count)) if count > 0 => rrule.push_str(&format!(";COUNT={count}")),
        // Tuta's end instant is exclusive, UNTIL is inclusive.
        (2, Some(until)) => rrule.push_str(&format!(";UNTIL={}", until_value(until, all_day))),
        _ => return Err(()),
    }
    for name in PART_ORDER {
        if let Some(values) = parts.get(name) {
            rrule.push_str(&format!(";{name}={}", values.join(",")));
        }
    }
    Ok(MappedRule {
        rrule,
        exdates,
        zone,
    })
}

/// The inclusive `UNTIL` for Tuta's exclusive end instant.
fn until_value(exclusive_end_ms: i64, all_day: bool) -> String {
    let last_ms = exclusive_end_ms - 1;
    if all_day {
        format_date(last_ms)
    } else {
        format_utc(last_ms.div_euclid(1000) * 1000)
    }
}

fn local_start(start_ms: i64, all_day: bool, zone: Option<&Zone>) -> PrimitiveDateTime {
    let start = instant(start_ms);
    match (all_day, zone) {
        (false, Some(zone)) => zone.local(start),
        _ => PrimitiveDateTime::new(start.date(), start.time()),
    }
}

fn valid_part_value(name: &str, value: &str) -> bool {
    let number = |min: i64, max: i64, signed: bool| {
        let digits = value.strip_prefix(['+', '-']).unwrap_or(value);
        if !signed && digits.len() != value.len() {
            return false;
        }
        if digits.is_empty() || digits.len() > 3 || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
        let parsed: i64 = digits.parse().unwrap_or(-1);
        parsed >= min && parsed <= max
    };
    match name {
        "BYMINUTE" => number(0, 59, false),
        "BYHOUR" => number(0, 23, false),
        "BYMONTHDAY" => number(1, 31, true),
        "BYYEARDAY" | "BYSETPOS" => number(1, 366, true),
        "BYWEEKNO" => number(1, 53, true),
        "BYMONTH" => number(1, 12, false),
        "WKST" => WEEKDAYS.contains(&value),
        "BYDAY" => {
            if value.len() < 2 || !value.is_char_boundary(value.len() - 2) {
                return false;
            }
            let (ordinal, day) = value.split_at(value.len() - 2);
            if !WEEKDAYS.contains(&day) {
                return false;
            }
            if ordinal.is_empty() {
                return true;
            }
            let digits = ordinal.strip_prefix(['+', '-']).unwrap_or(ordinal);
            !digits.is_empty()
                && digits.len() <= 2
                && digits.bytes().all(|b| b.is_ascii_digit())
                && (1..=53).contains(&digits.parse::<i64>().unwrap_or(0))
        }
        _ => false,
    }
}

/// RFC 5545 §3.3.10 restrictions on which parts go with which
/// frequency; Tuta's expansion of a combination RFC forbids is unknown.
fn check_combination(
    frequency: &str,
    parts: &BTreeMap<&str, Vec<String>>,
    all_day: bool,
) -> Result<(), ()> {
    let has = |name: &str| parts.contains_key(name);
    if has("BYWEEKNO") && frequency != "YEARLY" {
        return Err(());
    }
    if has("BYYEARDAY") && matches!(frequency, "DAILY" | "WEEKLY" | "MONTHLY") {
        return Err(());
    }
    if has("BYMONTHDAY") && frequency == "WEEKLY" {
        return Err(());
    }
    if let Some(days) = parts.get("BYDAY") {
        let ordinal = days
            .iter()
            .any(|day| day.len() > 2 || day.starts_with(['+', '-']));
        if ordinal && (!matches!(frequency, "MONTHLY" | "YEARLY") || has("BYWEEKNO")) {
            return Err(());
        }
    }
    if has("BYSETPOS") && parts.keys().filter(|name| **name != "WKST").count() < 2 {
        return Err(());
    }
    if parts.get("WKST").is_some_and(|values| values.len() > 1) {
        return Err(());
    }
    if all_day && (has("BYHOUR") || has("BYMINUTE")) {
        return Err(());
    }
    Ok(())
}

/// A Tuta alarm trigger (`<n>M|H|D|W`, minutes to weeks before the
/// start) as an iCalendar duration; `None` for anything else.
pub fn alarm_trigger(trigger: &str) -> Option<String> {
    let trigger = trigger.trim();
    if trigger.len() < 2 || !trigger.is_char_boundary(trigger.len() - 1) {
        return None;
    }
    let (amount, unit) = trigger.split_at(trigger.len() - 1);
    if amount.is_empty() || amount.len() > 6 || !amount.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let amount: u32 = amount.parse().ok()?;
    if amount == 0 {
        return Some("PT0S".into());
    }
    match unit {
        "M" => Some(format!("-PT{amount}M")),
        "H" => Some(format!("-PT{amount}H")),
        "D" => Some(format!("-P{amount}D")),
        "W" => Some(format!("-P{amount}W")),
        _ => None,
    }
}

/// `ORGANIZER`/`ATTENDEE` with a `CN` and, for attendees, `PARTSTAT`.
fn person_line(property: &str, person: &EventPerson, status: Option<i64>) -> Option<String> {
    let address: String = person
        .address
        .chars()
        .filter(|c| !c.is_control() && !c.is_whitespace() && *c != '"')
        .collect();
    if address.is_empty() {
        return None;
    }
    let mut line = property.to_string();
    let name = param_value(&person.name);
    if !name.is_empty() {
        line.push_str(&format!(";CN={name}"));
    }
    if let Some(status) = status {
        let partstat = match status {
            2 => "ACCEPTED",
            3 => "DECLINED",
            4 => "TENTATIVE",
            _ => "NEEDS-ACTION",
        };
        line.push_str(&format!(
            ";CUTYPE=INDIVIDUAL;ROLE=REQ-PARTICIPANT;PARTSTAT={partstat}"
        ));
    }
    line.push_str(&format!(":mailto:{address}"));
    Some(line)
}

/// A quoted parameter value (empty when nothing is left), RFC 6868
/// caret-encoded: RFC 5545 parameter values have no escaping and cannot
/// hold `"` or a line break, so `^` becomes `^^`, `"` becomes `^'` and
/// a line break `^n`; other control characters are dropped. Quoting
/// every value keeps `;`, `:`, `,` and `\` literal.
pub fn param_value(value: &str) -> String {
    let value = value.trim().replace("\r\n", "\n");
    let mut out = String::with_capacity(value.len() + 2);
    for character in value.chars() {
        match character {
            '^' => out.push_str("^^"),
            '"' => out.push_str("^'"),
            '\n' | '\r' => out.push_str("^n"),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    if out.is_empty() {
        out
    } else {
        format!("\"{out}\"")
    }
}

/// Escape a TEXT value (RFC 5545 §3.3.11): backslash, semicolon, comma
/// and newline; CR and other control characters (tab excepted) are
/// dropped.
pub fn escape_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '\\' => out.push_str("\\\\"),
            ';' => out.push_str("\\;"),
            ',' => out.push_str("\\,"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push('\t'),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

/// Fold one content line at 75 octets without splitting a UTF-8
/// sequence, and terminate it with CRLF.
pub fn fold(line: &str) -> String {
    const LIMIT: usize = 75;
    let mut out = String::with_capacity(line.len() + line.len() / LIMIT * 3 + 2);
    let mut used = 0;
    for character in line.chars() {
        let width = character.len_utf8();
        if used + width > LIMIT {
            out.push_str("\r\n ");
            // The continuation line's leading space counts.
            used = 1;
        }
        out.push(character);
        used += width;
    }
    out.push_str("\r\n");
    out
}

/// A Tuta description as plain text, plus the original when it is HTML
/// (Tuta's editor writes HTML; imported events carry plain text).
pub fn description_parts(description: &str) -> (String, Option<String>) {
    let trimmed = description.trim();
    if trimmed.is_empty() {
        return (String::new(), None);
    }
    if !looks_like_html(trimmed) {
        return (trimmed.to_string(), None);
    }
    (html_to_text(trimmed), Some(trimmed.to_string()))
}

fn looks_like_html(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.windows(2).any(|pair| {
        pair[0] == b'<' && (pair[1].is_ascii_alphabetic() || pair[1] == b'/' || pair[1] == b'!')
    }) && text.contains('>')
}

/// A small HTML-to-text conversion: block ends and `<br>` become line
/// breaks, list items get a dash, other tags are dropped and the common
/// entities decoded.
fn html_to_text(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut rest = html;
    while let Some(open) = rest.find('<') {
        push_decoded(&mut out, &rest[..open]);
        let after = &rest[open + 1..];
        let Some(close) = after.find('>') else {
            push_decoded(&mut out, &rest[open..]);
            rest = "";
            break;
        };
        let tag = after[..close].trim().to_ascii_lowercase();
        let name: String = tag
            .trim_start_matches('/')
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric())
            .collect();
        let closing = tag.starts_with('/');
        match name.as_str() {
            "br" => out.push('\n'),
            "li" if !closing => out.push_str("\n- "),
            "p" | "div" | "ul" | "ol" | "tr" | "h1" | "h2" | "h3" | "h4" | "h5" | "h6"
            | "blockquote"
                if closing =>
            {
                out.push('\n')
            }
            _ => {}
        }
        rest = &after[close + 1..];
    }
    push_decoded(&mut out, rest);
    // At most one empty line in a row, no trailing spaces.
    let mut text = String::with_capacity(out.len());
    let mut blank = 0;
    for line in out.lines() {
        let line = line.trim_end();
        if line.trim().is_empty() {
            blank += 1;
            if blank > 1 {
                continue;
            }
        } else {
            blank = 0;
        }
        text.push_str(line);
        text.push('\n');
    }
    text.trim().to_string()
}

fn push_decoded(out: &mut String, text: &str) {
    let mut rest = text;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let after = &rest[amp..];
        let Some(semi) = after.find(';').filter(|&semi| semi <= 10) else {
            out.push('&');
            rest = &after[1..];
            continue;
        };
        let entity = &after[1..semi];
        let decoded = match entity {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            "nbsp" => Some(' '),
            _ => entity
                .strip_prefix("#x")
                .or_else(|| entity.strip_prefix("#X"))
                .and_then(|hex| u32::from_str_radix(hex, 16).ok())
                .or_else(|| entity.strip_prefix('#').and_then(|dec| dec.parse().ok()))
                .and_then(char::from_u32),
        };
        match decoded {
            Some(character) => {
                out.push(character);
                rest = &after[semi + 1..];
            }
            None => {
                out.push('&');
                rest = &after[1..];
            }
        }
    }
    out.push_str(rest);
}

fn instant(ms: i64) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms) * 1_000_000)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH)
}

/// `YYYYMMDDTHHMMSSZ`.
pub fn format_utc(ms: i64) -> String {
    let at = instant(ms);
    format!(
        "{}Z",
        format_local(PrimitiveDateTime::new(at.date(), at.time()))
    )
}

/// `YYYYMMDD` of the UTC date.
pub fn format_date(ms: i64) -> String {
    let at = instant(ms);
    format!("{:04}{:02}{:02}", at.year(), u8::from(at.month()), at.day())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::EventAttendee;

    /// 2025-01-06 08:00:00 UTC, a Monday.
    const MONDAY_8_UTC: i64 = 1_736_150_400_000;
    const HOUR: i64 = 3_600_000;

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

    fn render(events: &[CalendarEvent]) -> String {
        let alarms: Vec<String> = Vec::new();
        let items: Vec<EventToRender<'_>> = events
            .iter()
            .map(|event| EventToRender {
                event,
                modified_ms: MONDAY_8_UTC,
                alarms: &alarms,
            })
            .collect();
        render_calendar(&items)
    }

    fn unfolded(body: &str) -> String {
        body.replace("\r\n ", "")
    }

    #[test]
    fn a_plain_event_renders_in_utc_with_crlf() {
        let body = render(&[event()]);
        assert!(body.starts_with("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:"));
        assert!(body.ends_with("END:VEVENT\r\nEND:VCALENDAR\r\n"));
        assert!(body.contains("\r\nUID:uid-1@tuta\r\n"));
        assert!(body.contains("\r\nDTSTAMP:20250106T080000Z\r\n"));
        assert!(body.contains("\r\nDTSTART:20250106T080000Z\r\nDTEND:20250106T090000Z\r\n"));
        assert!(body.contains("\r\nSUMMARY:Standup\r\n"));
        assert!(!body.contains("RRULE"));
        assert!(!body.contains("VTIMEZONE"));
        assert!(!body.replace("\r\n", "").contains('\n'));
        assert_eq!(body, render(&[event()]), "deterministic");
    }

    #[test]
    fn all_day_events_use_dates_with_an_exclusive_end() {
        let mut day = event();
        day.start_ms = 20_094 * DAY_MS; // 2025-01-06
        day.end_ms = 20_096 * DAY_MS;
        let body = render(&[day]);
        assert!(body.contains("DTSTART;VALUE=DATE:20250106\r\nDTEND;VALUE=DATE:20250108\r\n"));
    }

    #[test]
    fn text_is_escaped() {
        assert_eq!(
            escape_text("a,b;c\\d\r\ne\u{7}\tf"),
            "a\\,b\\;c\\\\d\\ne\tf"
        );
        let mut tricky = event();
        tricky.summary = "Lunch; with, Bob\nBEGIN:VALARM".into();
        tricky.location = "Room \"1\"".into();
        let body = render(&[tricky]);
        assert!(body.contains("SUMMARY:Lunch\\; with\\, Bob\\nBEGIN:VALARM\r\n"));
        assert!(body.contains("LOCATION:Room \"1\"\r\n"));
        assert!(!body.contains("\r\nBEGIN:VALARM"));
    }

    #[test]
    fn long_lines_fold_at_75_octets_on_char_boundaries() {
        let line = format!("SUMMARY:{}", "ü".repeat(100));
        let folded = fold(&line);
        for physical in folded.split("\r\n").filter(|l| !l.is_empty()) {
            assert!(physical.len() <= 75, "{} octets", physical.len());
        }
        assert_eq!(folded.replace("\r\n ", ""), format!("{line}\r\n"));
        let ascii = fold(&"x".repeat(160));
        let lines: Vec<&str> = ascii.split("\r\n").collect();
        assert_eq!(lines[0].len(), 75);
        assert_eq!(lines[1].len(), 75);
        assert!(lines[1].starts_with(' '));
        // An emoji (4 octets) never straddles a fold.
        let emoji = fold(&format!("X:{}", "😀".repeat(40)));
        assert!(String::from_utf8(emoji.clone().into_bytes()).is_ok());
        for physical in emoji.split("\r\n") {
            assert!(physical.len() <= 75);
        }
    }

    #[test]
    fn weekly_rules_repeat_in_the_rule_zone_with_a_vtimezone() {
        let mut weekly = event();
        let mut repeat = rule(1);
        repeat.end_type = 2;
        // Tuta ends before 2025-03-31 00:00 UTC (exclusive).
        repeat.end_value = Some(1_743_379_200_000);
        repeat.excluded_ms = vec![MONDAY_8_UTC + 7 * DAY_MS];
        repeat.advanced = vec![(2, "MO".into()), (2, "we".into())];
        weekly.repeat = Some(repeat);
        let body = unfolded(&render(&[weekly]));
        assert!(
            body.contains("DTSTART;TZID=Europe/Berlin:20250106T090000\r\n"),
            "{body}"
        );
        assert!(body.contains("DTEND;TZID=Europe/Berlin:20250106T100000\r\n"));
        assert!(body.contains("RRULE:FREQ=WEEKLY;UNTIL=20250330T235959Z;BYDAY=MO,WE\r\n"));
        assert!(body.contains("EXDATE;TZID=Europe/Berlin:20250113T090000\r\n"));
        assert!(body.contains("BEGIN:VTIMEZONE\r\nTZID:Europe/Berlin\r\n"));
        let vtimezone_at = body.find("BEGIN:VTIMEZONE").unwrap();
        assert!(vtimezone_at < body.find("BEGIN:VEVENT").unwrap());
    }

    #[test]
    fn an_unknown_zone_repeats_in_utc() {
        let mut daily = event();
        let mut repeat = rule(0);
        repeat.time_zone = "Nowhere/Special".into();
        repeat.interval = 2;
        repeat.end_type = 1;
        repeat.end_value = Some(5);
        daily.repeat = Some(repeat);
        let body = render(&[daily]);
        assert!(body.contains("DTSTART:20250106T080000Z\r\n"));
        assert!(body.contains("RRULE:FREQ=DAILY;INTERVAL=2;COUNT=5\r\n"));
        assert!(!body.contains("VTIMEZONE"));
    }

    #[test]
    fn all_day_rules_use_dates_for_until_and_exdate() {
        let mut yearly = event();
        yearly.start_ms = 20_094 * DAY_MS;
        yearly.end_ms = 20_095 * DAY_MS;
        let mut repeat = rule(3);
        repeat.end_type = 2;
        repeat.end_value = Some(20_094 * DAY_MS + 5 * 365 * DAY_MS);
        repeat.excluded_ms = vec![20_094 * DAY_MS + 365 * DAY_MS];
        yearly.repeat = Some(repeat);
        let body = render(&[yearly]);
        assert!(body.contains("DTSTART;VALUE=DATE:20250106\r\n"));
        assert!(
            body.contains("RRULE:FREQ=YEARLY;UNTIL=20300104\r\n"),
            "{body}"
        );
        assert!(body.contains("EXDATE;VALUE=DATE:20260106\r\n"));
        assert!(!body.contains("VTIMEZONE"));
    }

    #[test]
    fn month_end_rules_clamp_like_tuta() {
        let mut monthly = event();
        // 2025-01-31 08:00 UTC = 09:00 Berlin.
        monthly.start_ms = MONDAY_8_UTC + 25 * DAY_MS;
        monthly.end_ms = monthly.start_ms + HOUR;
        monthly.repeat = Some(rule(2));
        let body = render(&[monthly]);
        assert!(
            body.contains("RRULE:FREQ=MONTHLY;BYMONTHDAY=28,29,30,31;BYSETPOS=-1\r\n"),
            "{body}"
        );

        let mut leap = event();
        leap.start_ms = 19_782 * DAY_MS; // 2024-02-29
        leap.end_ms = 19_783 * DAY_MS;
        leap.repeat = Some(rule(3));
        let body = render(&[leap]);
        assert!(body.contains("RRULE:FREQ=YEARLY;BYMONTH=2;BYMONTHDAY=28,29;BYSETPOS=-1\r\n"));
    }

    #[test]
    fn count_with_removed_occurrences_stays_count() {
        let mut daily = event();
        let mut repeat = rule(0);
        repeat.time_zone = "UTC".into();
        repeat.end_type = 1;
        repeat.end_value = Some(3);
        // The second occurrence is removed and still counts, as in the
        // Tuta web app: days 1 and 3 are shown.
        repeat.excluded_ms = vec![MONDAY_8_UTC + DAY_MS];
        daily.repeat = Some(repeat);
        let body = render(&[daily]);
        assert!(body.contains("RRULE:FREQ=DAILY;COUNT=3\r\n"), "{body}");
        assert!(body.contains("EXDATE:20250107T080000Z\r\n"));
    }

    #[test]
    fn month_end_count_and_exdate_is_a_real_rule() {
        let mut monthly = event();
        // 2025-01-31 08:00 UTC = 09:00 Berlin; February falls on the 28th.
        monthly.start_ms = MONDAY_8_UTC + 25 * DAY_MS;
        monthly.end_ms = monthly.start_ms + HOUR;
        let mut repeat = rule(2);
        repeat.end_type = 1;
        repeat.end_value = Some(5);
        // 2025-02-28 09:00 Berlin.
        repeat.excluded_ms = vec![MONDAY_8_UTC + 53 * DAY_MS];
        monthly.repeat = Some(repeat);
        let body = unfolded(&render(&[monthly]));
        assert!(
            body.contains("RRULE:FREQ=MONTHLY;COUNT=5;BYMONTHDAY=28,29,30,31;BYSETPOS=-1\r\n"),
            "{body}"
        );
        assert!(body.contains("EXDATE;TZID=Europe/Berlin:20250228T090000\r\n"));
        assert!(!body.contains("UNSUPPORTED"));
    }

    #[test]
    fn count_and_exdate_keep_the_wall_clock_across_dst() {
        // Weekly at 09:00 Berlin from 2025-03-24 (CET, 08:00 UTC); the
        // removed 2025-03-31 occurrence is in CEST (07:00 UTC).
        let mut weekly = event();
        weekly.start_ms = MONDAY_8_UTC + 77 * DAY_MS;
        weekly.end_ms = weekly.start_ms + HOUR;
        let mut repeat = rule(1);
        repeat.end_type = 1;
        repeat.end_value = Some(4);
        repeat.excluded_ms = vec![weekly.start_ms + 7 * DAY_MS - HOUR];
        weekly.repeat = Some(repeat);
        let body = unfolded(&render(&[weekly]));
        assert!(body.contains("DTSTART;TZID=Europe/Berlin:20250324T090000\r\n"));
        assert!(body.contains("RRULE:FREQ=WEEKLY;COUNT=4\r\n"), "{body}");
        assert!(
            body.contains("EXDATE;TZID=Europe/Berlin:20250331T090000\r\n"),
            "{body}"
        );
    }

    #[test]
    fn an_end_on_an_occurrence_excludes_it() {
        // Tuta's end is exclusive: ending at the start of the third
        // occurrence leaves two, so UNTIL is one second before it.
        let mut daily = event();
        let mut repeat = rule(0);
        repeat.end_type = 2;
        repeat.end_value = Some(MONDAY_8_UTC + 2 * DAY_MS);
        daily.repeat = Some(repeat);
        let body = render(&[daily]);
        assert!(
            body.contains("RRULE:FREQ=DAILY;UNTIL=20250108T075959Z\r\n"),
            "{body}"
        );
        // All-day: the last kept date.
        let mut day = event();
        day.start_ms = 20_094 * DAY_MS;
        day.end_ms = 20_095 * DAY_MS;
        let mut repeat = rule(0);
        repeat.end_type = 2;
        repeat.end_value = Some(20_096 * DAY_MS);
        day.repeat = Some(repeat);
        let body = render(&[day]);
        assert!(
            body.contains("RRULE:FREQ=DAILY;UNTIL=20250107\r\n"),
            "{body}"
        );
    }

    #[test]
    fn inexpressible_rules_degrade_explicitly() {
        for (frequency, advanced) in [
            (7, vec![]),
            (1, vec![(42, "1".to_string())]),
            (1, vec![(3, "15".to_string())]), // BYMONTHDAY with WEEKLY
            (2, vec![(2, "MO\r\nX".to_string())]),
            (0, vec![(7, "1".to_string())]), // BYSETPOS alone
        ] {
            let mut odd = event();
            let mut repeat = rule(frequency);
            repeat.advanced = advanced;
            odd.repeat = Some(repeat);
            odd.description = "Agenda".into();
            let body = unfolded(&render(&[odd]));
            assert!(!body.contains("RRULE"), "{body}");
            assert!(body.contains("X-TUTA-BRIDGE-RECURRENCE:UNSUPPORTED\r\n"));
            assert!(body.contains("DESCRIPTION:[tuta-bridge: this event repeats in Tuta"));
            assert!(body.contains("\\n\\nAgenda\r\n"));
            assert!(body.contains("DTSTART:20250106T080000Z\r\n"));
        }
    }

    #[test]
    fn altered_occurrences_join_the_master_and_replace_their_exdate() {
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
        let body = render(&[altered, master]);
        assert_eq!(body.matches("BEGIN:VEVENT").count(), 2);
        let first = body.find("RRULE").unwrap();
        let second = body.find("RECURRENCE-ID:20250113T080000Z").unwrap();
        assert!(first < second, "master first");
        assert!(!body.contains("EXDATE;TZID=Europe/Berlin:20250113T090000"));
        assert!(body.contains("EXDATE;TZID=Europe/Berlin:20250120T090000\r\n"));
        assert!(body.contains("DTSTART:20250113T100000Z"));
    }

    #[test]
    fn people_and_alarms() {
        let mut meeting = event();
        meeting.organizer = Some(EventPerson {
            name: "Ann, \"Boss\"".into(),
            address: "ann@example.invalid".into(),
        });
        meeting.attendees = vec![
            EventAttendee {
                person: EventPerson {
                    name: "Bob".into(),
                    address: "bob@example.invalid".into(),
                },
                status: 2,
            },
            EventAttendee {
                person: EventPerson {
                    name: String::new(),
                    address: "cy@example.invalid".into(),
                },
                status: 0,
            },
        ];
        let alarms = vec!["15M".to_string(), "1D".to_string(), "bogus".to_string()];
        let body = unfolded(&render_calendar(&[EventToRender {
            event: &meeting,
            modified_ms: 0,
            alarms: &alarms,
        }]));
        assert!(body.contains("ORGANIZER;CN=\"Ann, ^'Boss^'\":mailto:ann@example.invalid\r\n"));
        assert!(body.contains("ATTENDEE;CN=\"Bob\";CUTYPE=INDIVIDUAL;ROLE=REQ-PARTICIPANT;PARTSTAT=ACCEPTED:mailto:bob@example.invalid\r\n"));
        assert!(body.contains("ATTENDEE;CUTYPE=INDIVIDUAL;ROLE=REQ-PARTICIPANT;PARTSTAT=NEEDS-ACTION:mailto:cy@example.invalid\r\n"));
        assert_eq!(body.matches("BEGIN:VALARM").count(), 2);
        assert!(body.contains("TRIGGER:-PT15M\r\n"));
        assert!(body.contains("TRIGGER:-P1D\r\n"));
        assert_eq!(alarm_trigger("2W").as_deref(), Some("-P2W"));
        assert_eq!(alarm_trigger("3H").as_deref(), Some("-PT3H"));
        assert_eq!(alarm_trigger("0M").as_deref(), Some("PT0S"));
        assert_eq!(alarm_trigger("M"), None);
        assert_eq!(alarm_trigger("5Y"), None);
    }

    #[test]
    fn parameter_values_are_quoted_and_caret_encoded() {
        assert_eq!(param_value("Bob"), "\"Bob\"");
        assert_eq!(param_value("  "), "");
        assert_eq!(param_value("a\\b;c:d,e"), "\"a\\b;c:d,e\"");
        assert_eq!(param_value("say \"hi\" ^_^"), "\"say ^'hi^' ^^_^^\"");
        assert_eq!(param_value("one\r\ntwo\nthree\u{7}"), "\"one^ntwo^nthree\"");
        let mut meeting = event();
        meeting.organizer = Some(EventPerson {
            name: "Dom\\Ann \"A\"".into(),
            address: "ann@example.invalid".into(),
        });
        let body = unfolded(&render(&[meeting]));
        assert!(
            body.contains("ORGANIZER;CN=\"Dom\\Ann ^'A^'\":mailto:ann@example.invalid\r\n"),
            "{body}"
        );
    }

    #[test]
    fn html_descriptions_get_a_plain_text_version() {
        let (plain, html) = description_parts(
            "<p>Bring <b>snacks</b> &amp; drinks</p><ul><li>a</li><li>b</li></ul>",
        );
        assert_eq!(plain, "Bring snacks & drinks\n\n- a\n- b");
        assert!(html.is_some());
        let (plain, html) = description_parts("1 < 2 and 3 > 2");
        assert_eq!(plain, "1 < 2 and 3 > 2");
        assert!(html.is_none());
        let mut described = event();
        described.description = "<div>line one<br>line two</div>".into();
        let body = unfolded(&render(&[described]));
        assert!(body.contains("DESCRIPTION:line one\\nline two\r\n"));
        assert!(body.contains("X-ALT-DESC;FMTTYPE=text/html:<div>line one<br>line two</div>\r\n"));
    }
}
