//! Pure SEARCH criteria parser.
//!
//! [`parse_search`] turns the tokenized arguments of a `SEARCH` command
//! into a tree of [`SearchKey`]s: `NOT` owns exactly one key, `OR`
//! exactly two, and a parenthesized group is one key that matches when
//! all of its members do (RFC 3501 §6.4.4). Nothing here touches the
//! store; the backend evaluates the tree against stored messages.
//! Every error is a fixed string that never echoes a search value.

use time::Date;

use super::codec::{parse_seq_set, ImapArg, SeqSet};
use crate::domain::{Error, Result};

/// One parsed SEARCH key.
// No `Debug`: header values are search terms the user typed and must
// not be printable into logs.
#[derive(Clone, PartialEq, Eq)]
pub enum SearchKey {
    All,
    Unseen,
    Seen,
    /// `UID <set>`.
    Uid(SeqSet),
    /// A bare sequence set: message numbers.
    Sequence(SeqSet),
    /// `SINCE <date>`: received on or after the UTC day start.
    Since(i64),
    /// `BEFORE <date>`: received strictly before the UTC day start.
    Before(i64),
    /// `ON <date>`: received within the UTC day `[start, end)`.
    On(i64, i64),
    /// `SENTSINCE <date>`: like `SINCE`, on the `Date:` header.
    SentSince(i64),
    /// `SENTBEFORE <date>`: like `BEFORE`, on the `Date:` header.
    SentBefore(i64),
    /// `SENTON <date>`: like `ON`, on the `Date:` header.
    SentOn(i64, i64),
    /// `SUBJECT/FROM/TO/CC/BCC/HEADER <field> <value>`: a
    /// case-insensitive substring match over one stored header field.
    Header {
        field: String,
        value: String,
    },
    /// `LARGER <n>`: stored RFC 822 size strictly larger than `n`.
    Larger(u64),
    /// `SMALLER <n>`: stored RFC 822 size strictly smaller than `n`.
    Smaller(u64),
    Not(Box<SearchKey>),
    Or(Box<SearchKey>, Box<SearchKey>),
    /// A parenthesized group: every member must match.
    And(Vec<SearchKey>),
}

fn invalid_search_criteria() -> Error {
    Error::Unsupported("invalid search criteria".into())
}

fn unsupported_search_key() -> Error {
    Error::Unsupported("search key not supported".into())
}

fn invalid_search_date() -> Error {
    Error::Unsupported("invalid search date".into())
}

/// The tagged-NO text for a charset the bridge cannot search in. The
/// response code names the ones it can (RFC 3501 §6.4.4).
fn bad_charset() -> Error {
    Error::Unsupported("[BADCHARSET (UTF-8)] charset not supported".into())
}

/// Deepest NOT/OR/group nesting accepted; deeper trees fail with the
/// fixed criteria error instead of recursing without bound.
const MAX_SEARCH_KEY_DEPTH: usize = 16;

/// Parse the arguments of a SEARCH command into the keys every message
/// must match.
///
/// An optional leading `CHARSET <name>` is accepted for `UTF-8` and
/// `US-ASCII` — search values are compared as UTF-8 text either way —
/// and refused with `[BADCHARSET (UTF-8)]` for anything else.
pub fn parse_search(args: &[ImapArg]) -> Result<Vec<SearchKey>> {
    let args = match args {
        [ImapArg::Atom(key), charset, rest @ ..] if key.eq_ignore_ascii_case("CHARSET") => {
            let charset = value(Some(charset))?;
            if !charset.eq_ignore_ascii_case("UTF-8") && !charset.eq_ignore_ascii_case("US-ASCII") {
                return Err(bad_charset());
            }
            rest
        }
        other => other,
    };
    parse_keys(args, 0)
}

/// Parse a run of keys: the whole command, or the inside of a group.
fn parse_keys(args: &[ImapArg], depth: usize) -> Result<Vec<SearchKey>> {
    if args.is_empty() {
        return Err(invalid_search_criteria());
    }
    let mut cursor = args.iter();
    let mut keys = Vec::new();
    while cursor.len() > 0 {
        keys.push(parse_key(&mut cursor, depth)?);
    }
    Ok(keys)
}

/// A key's string argument: an atom, a quoted string, or a literal.
fn value(arg: Option<&ImapArg>) -> Result<String> {
    match arg {
        Some(ImapArg::Atom(text) | ImapArg::Quoted(text)) => Ok(text.clone()),
        Some(ImapArg::Literal(bytes)) => Ok(String::from_utf8_lossy(bytes).into_owned()),
        Some(ImapArg::List(_)) | None => Err(invalid_search_criteria()),
    }
}

/// Parse an IMAP date `dd-Mmm-yyyy`.
///
/// RFC 3501 spells the month `Nov`, but clients send any casing; the
/// fixed `time` format matches the month case-sensitively by default,
/// so the component parses with `case_sensitive=false`, which accepts
/// `nov`, `NOV`, and `Nov` alike. RFC 3501 date-days carry one or two
/// digits; the one-digit form retries zero-padded.
fn parse_search_date(raw: &str) -> Result<Date> {
    let format =
        time::macros::format_description!("[day]-[month repr:short case_sensitive:false]-[year]");
    let trimmed = raw.trim();
    if let Ok(date) = Date::parse(trimmed, &format) {
        return Ok(date);
    }
    let padded = match trimmed.split_once('-') {
        Some((day, rest)) if day.len() == 1 && day.bytes().all(|b| b.is_ascii_digit()) => {
            format!("0{day}-{rest}")
        }
        _ => return Err(invalid_search_date()),
    };
    Date::parse(&padded, &format).map_err(|_| invalid_search_date())
}

/// UTC milliseconds at the start of the given day.
fn day_start_ms(date: Date) -> i64 {
    date.midnight()
        .assume_utc()
        .unix_timestamp()
        .saturating_mul(1000)
}

/// UTC milliseconds at the start of the day after `date`.
fn next_day_start_ms(date: Date) -> i64 {
    match date.next_day() {
        Some(next) => day_start_ms(next),
        None => i64::MAX,
    }
}

/// Parse one key, consuming its arguments from `cursor`.
fn parse_key(cursor: &mut std::slice::Iter<'_, ImapArg>, depth: usize) -> Result<SearchKey> {
    if depth > MAX_SEARCH_KEY_DEPTH {
        return Err(invalid_search_criteria());
    }
    let token = match cursor.next() {
        Some(ImapArg::Atom(token)) => token,
        // A group is one key: all of its members must match.
        Some(ImapArg::List(group)) => return Ok(SearchKey::And(parse_keys(group, depth + 1)?)),
        _ => return Err(invalid_search_criteria()),
    };
    let header = |field: &str, cursor: &mut std::slice::Iter<'_, ImapArg>| -> Result<SearchKey> {
        Ok(SearchKey::Header {
            field: field.to_string(),
            value: value(cursor.next())?,
        })
    };
    let day = |cursor: &mut std::slice::Iter<'_, ImapArg>| -> Result<Date> {
        parse_search_date(&value(cursor.next())?)
    };
    let number = |cursor: &mut std::slice::Iter<'_, ImapArg>| -> Result<u64> {
        value(cursor.next())?
            .parse()
            .map_err(|_| invalid_search_criteria())
    };
    match token.to_ascii_uppercase().as_str() {
        "ALL" => Ok(SearchKey::All),
        "UNSEEN" => Ok(SearchKey::Unseen),
        "SEEN" => Ok(SearchKey::Seen),
        // The bridge stores no \Answered, \Deleted, \Draft, or \Flagged
        // state and never reports those flags, so no message has them:
        // their negations match every message.
        "UNANSWERED" | "UNDELETED" | "UNDRAFT" | "UNFLAGGED" => Ok(SearchKey::All),
        "UID" => Ok(SearchKey::Uid(parse_seq_set(&value(cursor.next())?)?)),
        "SINCE" => Ok(SearchKey::Since(day_start_ms(day(cursor)?))),
        "BEFORE" => Ok(SearchKey::Before(day_start_ms(day(cursor)?))),
        "ON" => {
            let date = day(cursor)?;
            Ok(SearchKey::On(day_start_ms(date), next_day_start_ms(date)))
        }
        "SENTSINCE" => Ok(SearchKey::SentSince(day_start_ms(day(cursor)?))),
        "SENTBEFORE" => Ok(SearchKey::SentBefore(day_start_ms(day(cursor)?))),
        "SENTON" => {
            let date = day(cursor)?;
            Ok(SearchKey::SentOn(
                day_start_ms(date),
                next_day_start_ms(date),
            ))
        }
        "SUBJECT" => header("Subject", cursor),
        "FROM" => header("From", cursor),
        "TO" => header("To", cursor),
        "CC" => header("Cc", cursor),
        "BCC" => header("Bcc", cursor),
        "HEADER" => {
            let field = value(cursor.next())?;
            header(&field, cursor)
        }
        "LARGER" => Ok(SearchKey::Larger(number(cursor)?)),
        "SMALLER" => Ok(SearchKey::Smaller(number(cursor)?)),
        "NOT" => Ok(SearchKey::Not(Box::new(parse_key(cursor, depth + 1)?))),
        "OR" => {
            let first = parse_key(cursor, depth + 1)?;
            let second = parse_key(cursor, depth + 1)?;
            Ok(SearchKey::Or(Box::new(first), Box::new(second)))
        }
        // Body/text search needs decrypted bodies in the store, which the
        // bridge deliberately never keeps. Keyword and remaining flag
        // keys have no Tuta equivalent — NEW/OLD are \Recent-based, and
        // their only faithful reductions (nothing / everything) would be
        // a lie, so they are refused like the rest.
        "BODY" | "TEXT" | "KEYWORD" | "UNKEYWORD" | "ANSWERED" | "DELETED" | "DRAFT"
        | "FLAGGED" | "RECENT" | "NEW" | "OLD" => Err(unsupported_search_key()),
        _ => match parse_seq_set(token) {
            // A bare sequence set (SEARCH 1:2) selects message numbers.
            Ok(set) => Ok(SearchKey::Sequence(set)),
            Err(_) => Err(unsupported_search_key()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::super::codec::parse_line;
    use super::*;

    /// The keys of `a SEARCH <raw>`, tokenized the way the session does.
    fn parse(raw: &str) -> Result<Vec<SearchKey>> {
        parse_search(&parse_line(&format!("a SEARCH {raw}"))?.args)
    }

    /// `parse`, for input that must succeed (`SearchKey` has no `Debug`).
    fn keys(raw: &str) -> Vec<SearchKey> {
        match parse(raw) {
            Ok(keys) => keys,
            Err(_) => panic!("{raw} must parse"),
        }
    }

    fn fails_with(raw: &str, expected: &str) -> bool {
        matches!(parse(raw), Err(Error::Unsupported(message)) if message == expected)
    }

    fn subject(value: &str) -> SearchKey {
        SearchKey::Header {
            field: "Subject".into(),
            value: value.into(),
        }
    }

    fn from(value: &str) -> SearchKey {
        SearchKey::Header {
            field: "From".into(),
            value: value.into(),
        }
    }

    #[test]
    fn search_dates_map_to_utc_day_boundaries() {
        // 14-Nov-2023 00:00 UTC, and the day after.
        let date = parse_search_date("14-Nov-2023").unwrap();
        assert_eq!(day_start_ms(date), 1_699_920_000_000);
        assert_eq!(next_day_start_ms(date), 1_700_006_400_000);
        // One-digit days parse too (RFC 3501 date-day is unpadded).
        assert_eq!(
            day_start_ms(parse_search_date("4-Nov-2023").unwrap()),
            1_699_056_000_000
        );
        // The month parses in any casing: `nov` and `NOV` alike.
        for raw in ["14-nov-2023", "14-NOV-2023"] {
            assert_eq!(
                day_start_ms(parse_search_date(raw).unwrap()),
                1_699_920_000_000,
                "{raw} must parse in any casing"
            );
        }
        // The one-digit-day retry path keeps that behavior too.
        assert_eq!(
            day_start_ms(parse_search_date("4-nOV-2023").unwrap()),
            1_699_056_000_000
        );
        // Fixed error strings, no client input echoed.
        assert!(matches!(
            parse_search_date("2023-11-14"),
            Err(Error::Unsupported(message)) if message == "invalid search date"
        ));
        assert!(matches!(
            parse_search_date("99-Xxx-9999"),
            Err(Error::Unsupported(message)) if message == "invalid search date"
        ));
    }

    #[test]
    fn parses_index_keys() {
        assert!(keys("ALL") == vec![SearchKey::All]);
        assert!(keys("unseen SEEN") == vec![SearchKey::Unseen, SearchKey::Seen]);
        assert!(matches!(keys("UID 1:2")[0], SearchKey::Uid(_)));
        assert!(matches!(keys("1:2")[0], SearchKey::Sequence(_)));
        assert!(keys("SINCE 15-Nov-2023") == vec![SearchKey::Since(1_700_006_400_000)]);
        assert!(
            keys("SENTON 14-Nov-2023")
                == vec![SearchKey::SentOn(1_699_920_000_000, 1_700_006_400_000)]
        );
        assert!(keys("SENTSINCE 14-Nov-2023") == vec![SearchKey::SentSince(1_699_920_000_000)]);
        assert!(keys("SENTBEFORE 14-Nov-2023") == vec![SearchKey::SentBefore(1_699_920_000_000)]);
        assert!(
            keys("LARGER 10 SMALLER 20") == vec![SearchKey::Larger(10), SearchKey::Smaller(20)]
        );
        // String arguments are atoms, quoted strings, or literals; a
        // quoted keyword is a value, not a key.
        assert!(keys("SUBJECT \"NOT\"") == vec![subject("NOT")]);
        assert!(
            keys("BCC x")
                == vec![SearchKey::Header {
                    field: "Bcc".into(),
                    value: "x".into()
                }]
        );
        assert!(
            keys("HEADER Message-ID \"<a@b>\"")
                == vec![SearchKey::Header {
                    field: "Message-ID".into(),
                    value: "<a@b>".into()
                }]
        );
    }

    #[test]
    fn flag_negations_the_bridge_never_sets_match_everything() {
        // Clients routinely prefix searches with UNDELETED.
        assert!(
            keys("UNDELETED SUBJECT x UNANSWERED UNFLAGGED UNDRAFT")
                == vec![
                    SearchKey::All,
                    subject("x"),
                    SearchKey::All,
                    SearchKey::All,
                    SearchKey::All,
                ]
        );
    }

    #[test]
    fn not_or_and_groups_keep_their_structure() {
        // NOT owns the whole group, not just its first key.
        assert!(
            keys("NOT (SEEN SUBJECT x)")
                == vec![SearchKey::Not(Box::new(SearchKey::And(vec![
                    SearchKey::Seen,
                    subject("x"),
                ])))]
        );
        // OR takes exactly two keys, each of which may be a group; what
        // follows is a further top-level key.
        assert!(
            keys("OR (FROM a SUBJECT b) FROM c SEEN")
                == vec![
                    SearchKey::Or(
                        Box::new(SearchKey::And(vec![from("a"), subject("b")])),
                        Box::new(from("c")),
                    ),
                    SearchKey::Seen,
                ]
        );
        assert!(
            keys("OR NOT SEEN OR FROM a FROM b")
                == vec![SearchKey::Or(
                    Box::new(SearchKey::Not(Box::new(SearchKey::Seen))),
                    Box::new(SearchKey::Or(Box::new(from("a")), Box::new(from("b")))),
                )]
        );
        assert!(
            keys("(OR (SEEN) (UNSEEN))")
                == vec![SearchKey::And(vec![SearchKey::Or(
                    Box::new(SearchKey::And(vec![SearchKey::Seen])),
                    Box::new(SearchKey::And(vec![SearchKey::Unseen])),
                )])]
        );
    }

    #[test]
    fn charset_is_accepted_for_utf8_and_ascii_only() {
        assert!(keys("CHARSET UTF-8 SUBJECT \"Caffè\"") == vec![subject("Caffè")]);
        assert!(keys("charset \"us-ascii\" ALL") == vec![SearchKey::All]);
        assert!(fails_with(
            "CHARSET ISO-8859-1 SUBJECT x",
            "[BADCHARSET (UTF-8)] charset not supported"
        ));
        // CHARSET with nothing to search is a malformed command.
        assert!(fails_with("CHARSET UTF-8", "invalid search criteria"));
        assert!(fails_with("CHARSET", "search key not supported"));
    }

    #[test]
    fn malformed_and_unsupported_criteria_answer_fixed_strings() {
        for raw in [
            "SUBJECT",
            "UID 0",
            "HEADER Subject",
            "NOT",
            "OR SEEN",
            "()",
            "\"ALL\"",
            "SUBJECT (x)",
            "LARGER x",
        ] {
            assert!(
                matches!(parse(raw), Err(Error::Unsupported(message))
                    if message == "invalid search criteria" || message == "invalid sequence set"),
                "{raw} must be refused as malformed"
            );
        }
        assert!(parse_search(&[]).is_err());

        // Unsupported keys answer the fixed unsupported string — NEW/OLD
        // included: they are \Recent-based, and their only faithful
        // reductions (nothing / everything) would be a lie.
        for raw in [
            "BODY x",
            "TEXT x",
            "KEYWORD f",
            "FLAGGED",
            "NEW",
            "OLD",
            "BOGUS",
        ] {
            assert!(
                fails_with(raw, "search key not supported"),
                "{raw} must be refused"
            );
        }

        // Deep nesting is refused instead of recursing without bound.
        let deep = format!("{}SEEN", "NOT ".repeat(20));
        assert!(fails_with(&deep, "invalid search criteria"));
    }
}
