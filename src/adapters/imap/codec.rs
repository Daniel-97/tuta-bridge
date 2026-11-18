//! Pure IMAP4rev1 request codec: command-line tokenizer, sequence sets,
//! fetch item lists, and response string encoding.
//!
//! Nothing here performs I/O — the session owns reading and writing. Every
//! error is a fixed string that never echoes client input, so no subject,
//! address, or credential can leak through a parse failure. The tokenizer
//! is deliberately dumb: it splits argument shapes but never interprets
//! commands; dispatch on the command (plus the `UID` sub-command atom)
//! belongs to the session.

use crate::domain::{Error, Result};

/// One argument of a parsed client command line.
///
/// Balanced parenthesized groups (FETCH item lists, `ID` parameters, SEARCH
/// keys) are captured as [`ImapArg::Raw`]: the inner text without the outer
/// parentheses, tracked by scanning depth. Later consumers slice that
/// string with the structure they know.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImapArg {
    /// Whitespace-delimited atom (`FETCH`, `1:*`, `INBOX`, …).
    Atom(String),
    /// Quoted string with `\\` and `\"` escapes already resolved.
    Quoted(String),
    /// Literal placeholder: a trailing `{n}` marker parses as empty bytes;
    /// the session reads the announced data and fills them in.
    Literal(Vec<u8>),
    /// Balanced parenthesized group, inner text verbatim.
    Raw(String),
}

/// A parsed client command line.
// No `Debug`: a casual `{:?}` would dump arguments (subjects, credentials)
// into logs; the session logs tags, commands, and counts only.
pub struct Request {
    pub tag: String,
    pub command: String,
    pub args: Vec<ImapArg>,
}

fn invalid_command() -> Error {
    Error::Unsupported("invalid command".into())
}

/// Tokenize one client line into tag, command, and arguments.
///
/// Extra whitespace between tokens is tolerated. A trailing `{n}` literal
/// marker becomes an empty [`ImapArg::Literal`] placeholder (the size is
/// surfaced separately by [`pending_literal`]); anywhere else a literal
/// marker is a parse error. The codec never interprets the command.
pub fn parse_line(line: &str) -> Result<Request> {
    let mut rest = line.trim_start();
    let (tag, tail) = split_atom(rest);
    if tag.is_empty() {
        return Err(invalid_command());
    }

    rest = tail.trim_start();
    let (command, tail) = split_atom(rest);
    if command.is_empty() {
        return Err(invalid_command());
    }

    let mut args = Vec::new();
    rest = tail.trim_start();
    while !rest.is_empty() {
        match rest.as_bytes()[0] {
            b'(' => {
                let (inner, tail) = split_group(rest)?;
                args.push(ImapArg::Raw(inner.to_string()));
                rest = tail.trim_start();
            }
            b'"' => {
                let (value, tail) = split_quoted(rest)?;
                args.push(ImapArg::Quoted(value));
                rest = tail.trim_start();
            }
            b'{' => {
                // A literal marker must end the line: `{n}` then nothing.
                let close = rest.find('}').ok_or_else(invalid_command)?;
                let digits = &rest[1..close];
                if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(invalid_command());
                }
                if !rest[close + 1..].trim().is_empty() {
                    return Err(invalid_command());
                }
                args.push(ImapArg::Literal(Vec::new()));
                rest = "";
            }
            _ => {
                let (atom, tail) = split_atom(rest);
                args.push(ImapArg::Atom(atom.to_string()));
                rest = tail.trim_start();
            }
        }
    }

    Ok(Request {
        tag: tag.to_string(),
        command: command.to_string(),
        args,
    })
}

/// Split off the first whitespace-delimited atom, returning the remainder
/// starting at the delimiter.
fn split_atom(rest: &str) -> (&str, &str) {
    match rest.find(char::is_whitespace) {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    }
}

/// Split off a balanced parenthesized group; `rest` starts with `(`.
///
/// Scanning tracks depth only, as the controller ruling prescribes, so
/// nested groups stay inside one capture.
fn split_group(rest: &str) -> Result<(&str, &str)> {
    let mut depth = 0usize;
    for (i, c) in rest.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Ok((&rest[1..i], &rest[i + 1..]));
                }
            }
            _ => {}
        }
    }
    Err(invalid_command())
}

/// Split off a quoted string; `rest` starts with `"`.
///
/// Only `\\` and `\"` escapes are valid; CR/LF never enter a quoted value.
fn split_quoted(rest: &str) -> Result<(String, &str)> {
    let mut value = String::new();
    let mut escaped = false;
    for (i, c) in rest.char_indices().skip(1) {
        if escaped {
            if !matches!(c, '\\' | '"') {
                return Err(invalid_command());
            }
            value.push(c);
            escaped = false;
            continue;
        }
        match c {
            '\\' => escaped = true,
            '"' => return Ok((value, &rest[i + 1..])),
            '\r' | '\n' => return Err(invalid_command()),
            _ => value.push(c),
        }
    }
    // Unterminated string, or a dangling escape at the end.
    Err(invalid_command())
}

/// The byte count of a trailing `{n}` literal marker, if the line carries
/// one. The session answers `+ ` and reads that many bytes. Synchronizing
/// literals only: `{n+}` is not supported and surfaces as `None`.
pub fn pending_literal(line: &str) -> Option<usize> {
    let trimmed = line.trim_end();
    let token = match trimmed.rfind(char::is_whitespace) {
        Some(i) => &trimmed[i + 1..],
        None => trimmed,
    };
    let inner = token.strip_prefix('{')?.strip_suffix('}')?;
    if inner.is_empty() || !inner.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    inner.parse().ok()
}

/// A parsed IMAP sequence set.
///
/// `ranges` holds `(start, stop)` pairs where a `None` stop is the
/// unbounded upper end produced by `*`. A pure codec cannot know the
/// mailbox size, so a lone `*` — which in IMAP names the largest number in
/// use — anchors at the highest concrete number in the set, or at 1 when
/// the set names none: the ALL set `1:*`. The session clamps ranges
/// against the mailbox when resolving message numbers.
#[derive(Debug, Clone)]
pub struct SeqSet {
    ranges: Vec<(u32, Option<u32>)>,
}

impl SeqSet {
    /// The ALL set: every number from 1 up — the semantics of `1:*`.
    pub fn all() -> Self {
        Self {
            ranges: vec![(1, None)],
        }
    }

    /// True when `n` falls inside any range (a `None` stop is unbounded).
    pub fn contains(&self, n: u32) -> bool {
        self.ranges.iter().any(|&(start, stop)| match stop {
            Some(stop) => start <= n && n <= stop,
            None => n >= start,
        })
    }
}

fn invalid_sequence_set() -> Error {
    Error::Unsupported("invalid sequence set".into())
}

fn seq_number(raw: &str) -> Result<u32> {
    let n: u32 = raw.parse().map_err(|_| invalid_sequence_set())?;
    if n == 0 {
        return Err(invalid_sequence_set());
    }
    Ok(n)
}

/// Parse an IMAP sequence set such as `2,4:6,*`.
///
/// `*` is the unbounded upper end wherever it appears: `4:*` covers every
/// number from 4 up, and `*:4` is normalized to the same range. A lone `*`
/// (or `*:*`) anchors as described on [`SeqSet`]. Sequence number `0` and
/// reversed finite ranges (`5:1`) are rejected with the fixed error
/// `invalid sequence set`.
pub fn parse_seq_set(raw: &str) -> Result<SeqSet> {
    if raw.trim().is_empty() {
        return Err(invalid_sequence_set());
    }

    let mut ranges: Vec<(u32, Option<u32>)> = Vec::new();
    let mut stars = 0usize;
    let mut highest: u32 = 1;
    for part in raw.split(',') {
        let part = part.trim();
        if part.is_empty() {
            return Err(invalid_sequence_set());
        }
        match part.split_once(':') {
            None => {
                if part == "*" {
                    stars += 1;
                    continue;
                }
                let n = seq_number(part)?;
                ranges.push((n, Some(n)));
                highest = highest.max(n);
            }
            Some((raw_start, raw_end)) => match (raw_start.trim(), raw_end.trim()) {
                ("*", "*") => stars += 1,
                // `*` is the unbounded upper end wherever it appears.
                ("*", finite) | (finite, "*") => {
                    let n = seq_number(finite)?;
                    ranges.push((n, None));
                    highest = highest.max(n);
                }
                (start, end) => {
                    let (start, end) = (seq_number(start)?, seq_number(end)?);
                    if start > end {
                        return Err(invalid_sequence_set());
                    }
                    ranges.push((start, Some(end)));
                    highest = highest.max(end);
                }
            },
        }
    }
    for _ in 0..stars {
        ranges.push((highest, None));
    }
    Ok(SeqSet { ranges })
}

/// A string encoded for an IMAP response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImapString {
    /// Safe to send inside a quoted string.
    Quoted(String),
    /// Must be sent as a literal; the `{n}\r\n` framing is the writer's job.
    Literal(Vec<u8>),
}

/// Encode `value` as a quoted string when it is printable ASCII — the
/// empty string included, which renders as `""` — without CR/LF, `"`,
/// or `\`; every other value becomes a literal byte string.
pub fn encode_string(value: &str) -> ImapString {
    let quotable =
        value.bytes().all(|b| (0x20..=0x7e).contains(&b)) && !value.contains(['"', '\\']);
    if quotable {
        ImapString::Quoted(value.to_string())
    } else {
        ImapString::Literal(value.as_bytes().to_vec())
    }
}

/// The section of a `BODY[...]` fetch item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodySection {
    /// `BODY[]` — the whole message.
    Empty,
    /// `BODY[HEADER]` — the RFC 822 header.
    Header,
    /// `BODY[HEADER.FIELDS (NAME NAME …)]` — the listed header fields.
    HeaderFields(Vec<String>),
    /// `BODY[TEXT]` — the body text.
    Text,
    /// A MIME part section (`BODY[1.2]`, `BODY[2.MIME]`, …), captured
    /// verbatim for the backend.
    Part(String),
}

/// One item of a FETCH request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchItem {
    Body { peek: bool, section: BodySection },
    BodyStructure,
    Envelope,
    Flags,
    InternalDate,
    Rfc822,
    Rfc822Header,
    Rfc822Size,
    Rfc822Text,
    Uid,
}

fn invalid_fetch_items() -> Error {
    Error::Unsupported("invalid fetch items".into())
}

/// Parse a FETCH item list: either the parenthesized form `(FLAGS UID)` or
/// a bare item or macro (`ALL`, `FAST`).
///
/// Macros expand per RFC 3501 — `FAST` → FLAGS INTERNALDATE RFC822.SIZE,
/// `ALL` → plus ENVELOPE, `FULL` → plus BODY, where a bare `BODY` requests
/// the non-extensible structure (RFC 3501 §6.4.5) and maps to
/// [`FetchItem::BodyStructure`]. Item names are case-insensitive.
/// `HEADER.FIELDS.NOT` sections are a v1 limitation and are rejected with
/// the fixed error `invalid fetch items`.
pub fn parse_fetch_items(raw: &str) -> Result<Vec<FetchItem>> {
    let trimmed = raw.trim();
    let inner = unwrap_group(trimmed).unwrap_or(trimmed);
    let mut items = Vec::new();
    for token in split_fetch_tokens(inner)? {
        items.extend(expand_fetch_token(&token)?);
    }
    if items.is_empty() {
        return Err(invalid_fetch_items());
    }
    Ok(items)
}

/// When `raw` is exactly one balanced parenthesized group, return its inner
/// text; otherwise `None`.
fn unwrap_group(raw: &str) -> Option<&str> {
    if !raw.starts_with('(') || !raw.ends_with(')') {
        return None;
    }
    let mut depth = 0usize;
    for (i, c) in raw.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return (i + 1 == raw.len()).then_some(&raw[1..raw.len() - 1]);
                }
            }
            _ => {}
        }
    }
    None
}

/// Split a fetch list into item tokens. Bracket sections keep their inner
/// spaces and parentheses, so `BODY.PEEK[HEADER.FIELDS (SUBJECT FROM)]`
/// stays one token.
fn split_fetch_tokens(inner: &str) -> Result<Vec<String>> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut brackets = 0usize;
    for c in inner.chars() {
        match c {
            '[' => {
                brackets += 1;
                current.push(c);
            }
            ']' => {
                brackets = brackets.saturating_sub(1);
                current.push(c);
            }
            _ if c.is_whitespace() && brackets == 0 => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(c),
        }
    }
    if brackets > 0 {
        return Err(invalid_fetch_items());
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    Ok(tokens)
}

/// Expand one fetch token; macros expand to several items.
fn expand_fetch_token(token: &str) -> Result<Vec<FetchItem>> {
    let (name, section) = match token.find('[') {
        Some(open) => {
            let close = token.rfind(']').ok_or_else(invalid_fetch_items)?;
            if close != token.len() - 1 || open + 1 > close {
                return Err(invalid_fetch_items());
            }
            (&token[..open], Some(&token[open + 1..close]))
        }
        None => (token, None),
    };

    match section {
        Some(section) => {
            let peek = if name.eq_ignore_ascii_case("BODY.PEEK") {
                true
            } else if name.eq_ignore_ascii_case("BODY") {
                false
            } else {
                // A bracket section only applies to BODY / BODY.PEEK.
                return Err(invalid_fetch_items());
            };
            Ok(vec![FetchItem::Body {
                peek,
                section: parse_body_section(section)?,
            }])
        }
        None => {
            let upper = name.to_ascii_uppercase();
            match upper.as_str() {
                "ALL" => Ok(vec![
                    FetchItem::Flags,
                    FetchItem::InternalDate,
                    FetchItem::Rfc822Size,
                    FetchItem::Envelope,
                ]),
                "FAST" => Ok(vec![
                    FetchItem::Flags,
                    FetchItem::InternalDate,
                    FetchItem::Rfc822Size,
                ]),
                "FULL" => Ok(vec![
                    FetchItem::Flags,
                    FetchItem::InternalDate,
                    FetchItem::Rfc822Size,
                    FetchItem::Envelope,
                    FetchItem::BodyStructure,
                ]),
                "FLAGS" => Ok(vec![FetchItem::Flags]),
                "UID" => Ok(vec![FetchItem::Uid]),
                "INTERNALDATE" => Ok(vec![FetchItem::InternalDate]),
                "ENVELOPE" => Ok(vec![FetchItem::Envelope]),
                "RFC822" => Ok(vec![FetchItem::Rfc822]),
                "RFC822.HEADER" => Ok(vec![FetchItem::Rfc822Header]),
                "RFC822.SIZE" => Ok(vec![FetchItem::Rfc822Size]),
                "RFC822.TEXT" => Ok(vec![FetchItem::Rfc822Text]),
                "BODYSTRUCTURE" => Ok(vec![FetchItem::BodyStructure]),
                // A bare BODY requests the structure (RFC 3501 §6.4.5).
                "BODY" => Ok(vec![FetchItem::BodyStructure]),
                _ => Err(invalid_fetch_items()),
            }
        }
    }
}

/// Parse the text between `BODY[` and `]`.
fn parse_body_section(section: &str) -> Result<BodySection> {
    let section = section.trim();
    if section.is_empty() {
        return Ok(BodySection::Empty);
    }
    if section.eq_ignore_ascii_case("HEADER") {
        return Ok(BodySection::Header);
    }
    if section.eq_ignore_ascii_case("TEXT") {
        return Ok(BodySection::Text);
    }
    if let Some((head, rest)) = section.split_once(char::is_whitespace) {
        if head.eq_ignore_ascii_case("HEADER.FIELDS") {
            let inner = unwrap_group(rest.trim()).ok_or_else(invalid_fetch_items)?;
            let fields: Vec<String> = inner.split_whitespace().map(String::from).collect();
            if fields.is_empty() {
                return Err(invalid_fetch_items());
            }
            return Ok(BodySection::HeaderFields(fields));
        }
    }
    if section.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        return Ok(BodySection::Part(section.to_string()));
    }
    Err(invalid_fetch_items())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_login_list_select_and_uid_fetch() {
        let request = parse_line("a001 LOGIN \"user@example\" \"pass word\"").unwrap();
        assert_eq!(request.tag, "a001");
        assert_eq!(request.command, "LOGIN");
        assert_eq!(request.args[0], ImapArg::Quoted("user@example".into()));
        assert_eq!(request.args[1], ImapArg::Quoted("pass word".into()));

        let request = parse_line("a009 LIST \"\" \"*\"").unwrap();
        assert_eq!(request.command, "LIST");
        assert_eq!(
            request.args,
            vec![ImapArg::Quoted(String::new()), ImapArg::Quoted("*".into())]
        );

        let request = parse_line("a010 SELECT INBOX").unwrap();
        assert_eq!(request.command, "SELECT");
        assert_eq!(request.args, vec![ImapArg::Atom("INBOX".into())]);

        let request =
            parse_line("a002 UID FETCH 1:* (FLAGS BODY.PEEK[HEADER.FIELDS (SUBJECT FROM)] UID)")
                .unwrap();
        assert_eq!(request.command, "UID");
        assert_eq!(request.args[0], ImapArg::Atom("FETCH".into()));
        assert_eq!(
            request.args[2],
            ImapArg::Raw("FLAGS BODY.PEEK[HEADER.FIELDS (SUBJECT FROM)] UID".into())
        );
        let items =
            parse_fetch_items("(FLAGS BODY.PEEK[HEADER.FIELDS (SUBJECT FROM)] UID)").unwrap();
        assert_eq!(items[0], FetchItem::Flags);
        assert!(
            matches!(items[1], FetchItem::Body { peek: true, section: BodySection::HeaderFields(ref f) } if f == &[String::from("SUBJECT"), String::from("FROM")])
        );
        assert_eq!(items[2], FetchItem::Uid);
    }

    #[test]
    fn tolerates_extra_whitespace_and_captures_groups_raw() {
        let request = parse_line("  a004   ID  (\"name\" \"test\")  ").unwrap();
        assert_eq!(request.tag, "a004");
        assert_eq!(request.command, "ID");
        assert_eq!(request.args, vec![ImapArg::Raw("\"name\" \"test\"".into())]);
    }

    #[test]
    fn sequence_sets_cover_ranges_and_star() {
        let set = parse_seq_set("2,4:6,*").unwrap();
        assert!(!set.contains(1) && set.contains(2) && !set.contains(3) && set.contains(999_999));
        assert!(parse_seq_set("0").is_err());
        assert!(parse_seq_set("5:1").is_err());
    }

    #[test]
    fn sequence_sets_anchor_lone_star_and_all_ranges() {
        let lone = parse_seq_set("*").unwrap();
        assert!(lone.contains(1) && lone.contains(999_999));
        let all = SeqSet::all();
        assert!(all.contains(1) && all.contains(999_999));
        let ranged = parse_seq_set("4:*").unwrap();
        assert!(ranged.contains(4) && !ranged.contains(3));
        let trailing = parse_seq_set("9:10,1,*").unwrap();
        assert!(trailing.contains(1) && trailing.contains(9) && trailing.contains(999_999));
        assert!(!trailing.contains(8));
        let reversed_star = parse_seq_set("*:4").unwrap();
        assert!(reversed_star.contains(4) && !reversed_star.contains(3));
        let error = parse_seq_set("0").expect_err("zero must not parse");
        assert!(matches!(error, Error::Unsupported(message) if message == "invalid sequence set"));
    }

    #[test]
    fn strings_quote_ascii_and_use_literals_otherwise() {
        assert!(matches!(encode_string("simple"), ImapString::Quoted(_)));
        assert!(matches!(
            encode_string("say \"hi\""),
            ImapString::Literal(_)
        ));
        assert!(
            matches!(encode_string("Caffè"), ImapString::Literal(bytes) if bytes == "Caffè".as_bytes().to_vec())
        );
        // An empty string renders as "" — never a `{0}` literal.
        assert_eq!(encode_string(""), ImapString::Quoted(String::new()));
        assert!(matches!(
            encode_string("line\nbreak"),
            ImapString::Literal(_)
        ));
    }

    #[test]
    fn detects_pending_literals() {
        assert_eq!(pending_literal("a003 LOGIN {5}"), Some(5));
        assert_eq!(pending_literal("a003 LOGIN {5} "), Some(5));
        assert_eq!(pending_literal("a003 LOGIN {5+}"), None);
        assert_eq!(pending_literal("a003 LOGIN \"x{5}\""), None);
        assert_eq!(pending_literal("a003 LOGIN user"), None);
        // The trailing marker parses as an empty literal placeholder that
        // the session fills after reading the announced bytes.
        let request = parse_line("a003 LOGIN {5}").unwrap();
        assert!(matches!(request.args[0], ImapArg::Literal(ref bytes) if bytes.is_empty()));
    }

    #[test]
    fn expands_fetch_macros() {
        assert_eq!(
            parse_fetch_items("FAST").unwrap(),
            vec![
                FetchItem::Flags,
                FetchItem::InternalDate,
                FetchItem::Rfc822Size
            ]
        );
        assert_eq!(
            parse_fetch_items("ALL").unwrap(),
            vec![
                FetchItem::Flags,
                FetchItem::InternalDate,
                FetchItem::Rfc822Size,
                FetchItem::Envelope,
            ]
        );
        assert_eq!(
            parse_fetch_items("(full)").unwrap(),
            vec![
                FetchItem::Flags,
                FetchItem::InternalDate,
                FetchItem::Rfc822Size,
                FetchItem::Envelope,
                FetchItem::BodyStructure,
            ]
        );
    }

    #[test]
    fn parses_body_sections() {
        let items =
            parse_fetch_items("(BODY[] BODY[HEADER] BODY[TEXT] BODY.PEEK[] BODY[1.2] BODY)")
                .unwrap();
        assert_eq!(
            items,
            vec![
                FetchItem::Body {
                    peek: false,
                    section: BodySection::Empty
                },
                FetchItem::Body {
                    peek: false,
                    section: BodySection::Header
                },
                FetchItem::Body {
                    peek: false,
                    section: BodySection::Text
                },
                FetchItem::Body {
                    peek: true,
                    section: BodySection::Empty
                },
                FetchItem::Body {
                    peek: false,
                    section: BodySection::Part("1.2".into())
                },
                FetchItem::BodyStructure,
            ]
        );
    }

    #[test]
    fn item_names_are_case_insensitive() {
        assert_eq!(
            parse_fetch_items("(flags uid)").unwrap(),
            vec![FetchItem::Flags, FetchItem::Uid]
        );
    }

    #[test]
    fn rejects_malformed_fetch_lists() {
        assert!(parse_fetch_items("(FLAGS").is_err());
        assert!(parse_fetch_items("BOGUS").is_err());
        assert!(parse_fetch_items("(BODY[HEADER").is_err());
        let error = parse_fetch_items("BOGUS").expect_err("bogus item must not parse");
        assert!(matches!(error, Error::Unsupported(message) if message == "invalid fetch items"));
    }

    #[test]
    fn rejects_malformed_command_lines() {
        assert!(parse_line("").is_err());
        assert!(parse_line("   ").is_err());
        assert!(parse_line("a001").is_err());
        assert!(parse_line("a001 LOGIN \"unterminated").is_err());
        assert!(parse_line("a001 LOGIN (unclosed").is_err());
        assert!(parse_line("a001 LOGIN {5} trailing").is_err());
        // `Request` deliberately has no `Debug`, so the outcome is
        // discarded without `expect_err`.
        let error = parse_line("").err().expect("empty line must not parse");
        assert!(matches!(error, Error::Unsupported(message) if message == "invalid command"));
    }
}
