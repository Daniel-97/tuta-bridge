//! IANA zones for the iCalendar output: local times and `VTIMEZONE`
//! components built from the zone data `time-tz` bundles.
//!
//! A `VTIMEZONE` here lists every UTC-offset change of the zone between
//! two instants as explicit onsets (one `STANDARD`/`DAYLIGHT` component
//! per kind of change, its further onsets as `RDATE`s). After the last
//! listed onset the last observance applies, so the range is chosen by
//! the renderer to cover the event's dates generously; clients with
//! their own zone database (Thunderbird among them) resolve the IANA
//! `TZID` themselves anyway.

use time::{Date, Duration, Month, OffsetDateTime, PrimitiveDateTime, Time, UtcOffset};
use time_tz::{timezones, Offset, OffsetResult, PrimitiveDateTimeExt, TimeZone, Tz};

/// A zone the renderer can name in a `TZID`.
pub struct Zone {
    pub name: String,
    tz: &'static Tz,
}

impl Zone {
    /// The zone for an IANA name, or `None` when the bundled data does
    /// not know it (the SDK then repeats in UTC as well).
    pub fn by_name(name: &str) -> Option<Self> {
        let trimmed = name.trim();
        if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("UTC") {
            return None;
        }
        // Only plain IANA names: they never need quoting in a TZID
        // parameter and cannot smuggle iCalendar syntax.
        if !trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '_' | '-' | '+'))
        {
            return None;
        }
        let tz = timezones::get_by_name(trimmed)?;
        Some(Self {
            name: trimmed.to_string(),
            tz,
        })
    }

    /// The local wall-clock time of a UTC instant.
    pub fn local(&self, instant: OffsetDateTime) -> PrimitiveDateTime {
        let offset = self.tz.get_offset_utc(&instant).to_utc();
        let local = instant.to_offset(offset);
        PrimitiveDateTime::new(local.date(), local.time())
    }

    /// The UTC instant of a local wall-clock time: the earlier one when
    /// the time is ambiguous, and one hour later when it falls into a
    /// gap (a skipped hour).
    pub fn instant(&self, local: PrimitiveDateTime) -> OffsetDateTime {
        match local.assume_timezone(self.tz) {
            OffsetResult::Some(instant) => instant,
            OffsetResult::Ambiguous(first, second) => first.min(second),
            OffsetResult::None => match (local + Duration::hours(1)).assume_timezone(self.tz) {
                OffsetResult::Some(instant) => instant,
                OffsetResult::Ambiguous(first, second) => first.min(second),
                OffsetResult::None => local.assume_utc(),
            },
        }
    }

    /// The `VTIMEZONE` lines (unfolded, without CRLF) covering
    /// `[from, to)`.
    pub fn vtimezone(&self, from: OffsetDateTime, to: OffsetDateTime) -> Vec<String> {
        let state = |instant: &OffsetDateTime| {
            let offset = self.tz.get_offset_utc(instant);
            (offset.to_utc(), offset.is_dst(), offset.name().to_string())
        };
        let initial = state(&from);
        // Scan day by day and pin each change to the second. Offsets
        // never change twice within one day.
        let mut changes: Vec<(OffsetDateTime, (UtcOffset, bool, String))> = Vec::new();
        let mut previous_instant = from;
        let mut previous = initial.clone();
        let mut instant = from + Duration::days(1);
        while instant < to {
            let current = state(&instant);
            if current != previous {
                let (mut low, mut high) = (previous_instant, instant);
                while (high - low) > Duration::seconds(1) {
                    let middle = low + (high - low) / 2;
                    if state(&middle) == previous {
                        low = middle;
                    } else {
                        high = middle;
                    }
                }
                changes.push((high, current.clone()));
            }
            previous = current;
            previous_instant = instant;
            instant += Duration::days(1);
        }

        // One observance per kind of change: the first onset as its
        // DTSTART, the others as RDATEs. Onsets are local times in the
        // offset in force before the change (RFC 5545 §3.6.5).
        struct Observance {
            dst: bool,
            from: UtcOffset,
            to: UtcOffset,
            name: String,
            onsets: Vec<PrimitiveDateTime>,
        }
        let mut observances: Vec<Observance> = vec![Observance {
            dst: initial.1,
            from: initial.0,
            to: initial.0,
            name: initial.2.clone(),
            onsets: vec![local_in(from, initial.0)],
        }];
        let mut before = initial.0;
        for (at, (offset, dst, name)) in changes {
            let onset = local_in(at, before);
            match observances.iter_mut().find(|observance| {
                observance.dst == dst
                    && observance.from == before
                    && observance.to == offset
                    && observance.name == name
            }) {
                Some(observance) => observance.onsets.push(onset),
                None => observances.push(Observance {
                    dst,
                    from: before,
                    to: offset,
                    name,
                    onsets: vec![onset],
                }),
            }
            before = offset;
        }

        let mut lines = vec!["BEGIN:VTIMEZONE".to_string(), format!("TZID:{}", self.name)];
        for observance in observances {
            let kind = if observance.dst {
                "DAYLIGHT"
            } else {
                "STANDARD"
            };
            lines.push(format!("BEGIN:{kind}"));
            lines.push(format!("DTSTART:{}", format_local(observance.onsets[0])));
            for onset in &observance.onsets[1..] {
                lines.push(format!("RDATE:{}", format_local(*onset)));
            }
            lines.push(format!("TZOFFSETFROM:{}", format_offset(observance.from)));
            lines.push(format!("TZOFFSETTO:{}", format_offset(observance.to)));
            // Abbreviations are plain letters, digits and signs; anything
            // else is left out rather than escaped.
            if !observance.name.is_empty()
                && observance
                    .name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-'))
            {
                lines.push(format!("TZNAME:{}", observance.name));
            }
            lines.push(format!("END:{kind}"));
        }
        lines.push("END:VTIMEZONE".to_string());
        lines
    }
}

fn local_in(instant: OffsetDateTime, offset: UtcOffset) -> PrimitiveDateTime {
    let local = instant.to_offset(offset);
    PrimitiveDateTime::new(local.date(), local.time())
}

/// `YYYYMMDDTHHMMSS` (a local or floating date-time).
pub fn format_local(local: PrimitiveDateTime) -> String {
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}",
        local.year(),
        u8::from(local.month()),
        local.day(),
        local.hour(),
        local.minute(),
        local.second()
    )
}

/// `±HHMM`, or `±HHMMSS` when the offset has seconds.
pub fn format_offset(offset: UtcOffset) -> String {
    let (hours, minutes, seconds) = offset.as_hms();
    let sign = if offset.is_negative() { '-' } else { '+' };
    let (hours, minutes, seconds) = (hours.abs(), minutes.abs(), seconds.abs());
    if seconds == 0 {
        format!("{sign}{hours:02}{minutes:02}")
    } else {
        format!("{sign}{hours:02}{minutes:02}{seconds:02}")
    }
}

/// January 1st, 00:00 UTC, of `year`, clamped to the supported range.
pub fn year_start(year: i32) -> OffsetDateTime {
    let year = year.clamp(1971, 9998);
    PrimitiveDateTime::new(
        Date::from_calendar_date(year, Month::January, 1).unwrap_or(Date::MIN),
        Time::MIDNIGHT,
    )
    .assume_utc()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_utc_and_odd_names_have_no_zone() {
        assert!(Zone::by_name("Mars/Olympus_Mons").is_none());
        assert!(Zone::by_name("UTC").is_none());
        assert!(Zone::by_name("").is_none());
        assert!(Zone::by_name("Europe/Berlin\r\nX").is_none());
        assert!(Zone::by_name("Europe/Berlin").is_some());
    }

    #[test]
    fn berlin_local_times_follow_dst() {
        let zone = Zone::by_name("Europe/Berlin").unwrap();
        // 2025-01-06 08:00 UTC is 09:00 CET; 2025-07-07 07:00 UTC is 09:00 CEST.
        let winter = OffsetDateTime::from_unix_timestamp(1_736_150_400).unwrap();
        assert_eq!(format_local(zone.local(winter)), "20250106T090000");
        let summer = OffsetDateTime::from_unix_timestamp(1_751_871_600).unwrap();
        assert_eq!(format_local(zone.local(summer)), "20250707T090000");
        assert_eq!(zone.instant(zone.local(summer)), summer);
    }

    #[test]
    fn a_vtimezone_lists_both_kinds_of_onsets() {
        let zone = Zone::by_name("Europe/Berlin").unwrap();
        let lines = zone.vtimezone(year_start(2024), year_start(2026));
        let text = lines.join("\n");
        assert!(text.starts_with("BEGIN:VTIMEZONE\nTZID:Europe/Berlin\n"));
        assert!(text.contains("BEGIN:DAYLIGHT\nDTSTART:20240331T020000\nRDATE:20250330T020000\nTZOFFSETFROM:+0100\nTZOFFSETTO:+0200\nTZNAME:CEST\nEND:DAYLIGHT"), "{text}");
        assert!(text.contains("BEGIN:STANDARD\nDTSTART:20241027T030000\nRDATE:20251026T030000\nTZOFFSETFROM:+0200\nTZOFFSETTO:+0100"), "{text}");
        assert!(text.ends_with("END:VTIMEZONE"));
    }

    #[test]
    fn offsets_format_with_sign_and_seconds() {
        assert_eq!(
            format_offset(UtcOffset::from_hms(5, 30, 0).unwrap()),
            "+0530"
        );
        assert_eq!(
            format_offset(UtcOffset::from_hms(-3, -30, 0).unwrap()),
            "-0330"
        );
        assert_eq!(
            format_offset(UtcOffset::from_hms(0, 0, 0).unwrap()),
            "+0000"
        );
        assert_eq!(
            format_offset(UtcOffset::from_hms(0, 17, 30).unwrap()),
            "+001730"
        );
    }
}
