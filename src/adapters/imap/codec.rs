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

/// One argument of a parsed client command.
///
/// Parenthesized lists nest: FETCH item lists, `ID` parameters, STATUS
/// items, and SEARCH groups all arrive as [`ImapArg::List`], so no
/// consumer ever re-splits a string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImapArg {
    /// An atom (`FETCH`, `1:*`, `INBOX`, …). A bracketed section stays
    /// inside its atom whole, spaces and parentheses included:
    /// `BODY.PEEK[HEADER.FIELDS (DATE FROM)]` is one atom.
    Atom(String),
    /// Quoted string with `\\` and `\"` escapes already resolved.
    Quoted(String),
    /// The bytes of a client literal.
    Literal(Vec<u8>),
    /// A parenthesized list.
    List(Vec<ImapArg>),
}

/// A parsed client command.
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

/// Lists nested deeper than this are refused instead of recursed into.
const MAX_LIST_DEPTH: usize = 32;

/// Tokenize a command that fits on one line (no client literal).
pub fn parse_line(line: &str) -> Result<Request> {
    parse_command(&[line], Vec::new())
}

/// Tokenize one whole client command into tag, command, and arguments.
///
/// `lines` are the command's lines in order: every line but the last
/// ends in a `{n}` literal marker, and `literals` holds the announced
/// bytes in the same order (the session reads them; see
/// [`pending_literal`]). A literal may sit anywhere an argument may,
/// inside a list included. The codec never interprets the command.
pub fn parse_command<S: AsRef<str>>(lines: &[S], literals: Vec<Vec<u8>>) -> Result<Request> {
    let (first, continuations) = lines.split_first().ok_or_else(invalid_command)?;
    let (tag, tail) = split_word(first.as_ref().trim_start());
    if tag.is_empty() {
        return Err(invalid_command());
    }
    let (command, tail) = split_word(tail.trim_start());
    if command.is_empty() {
        return Err(invalid_command());
    }

    let mut tokenizer = Tokenizer {
        stack: vec![Vec::new()],
        literals: literals.into_iter(),
    };
    tokenizer.line(tail)?;
    for line in continuations {
        tokenizer.line(line.as_ref())?;
    }
    Ok(Request {
        tag: tag.to_string(),
        command: command.to_string(),
        args: tokenizer.finish()?,
    })
}

/// Tokenize a run of arguments with no tag, command, or literal: the
/// text inside a `BODY[...]` section.
fn parse_arguments(text: &str) -> Result<Vec<ImapArg>> {
    let mut tokenizer = Tokenizer {
        stack: vec![Vec::new()],
        literals: Vec::new().into_iter(),
    };
    tokenizer.line(text)?;
    tokenizer.finish()
}

/// Split off the first whitespace-delimited word, returning the
/// remainder starting at the delimiter.
fn split_word(rest: &str) -> (&str, &str) {
    match rest.find(char::is_whitespace) {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    }
}

/// The argument tokenizer: a stack of open lists, the innermost last.
struct Tokenizer {
    stack: Vec<Vec<ImapArg>>,
    literals: std::vec::IntoIter<Vec<u8>>,
}

impl Tokenizer {
    fn push(&mut self, arg: ImapArg) {
        if let Some(open) = self.stack.last_mut() {
            open.push(arg);
        }
    }

    /// Consume one line of arguments. Open lists carry over to the
    /// next line, which is how a literal sits inside a list.
    fn line(&mut self, line: &str) -> Result<()> {
        let bytes = line.as_bytes();
        let mut at = 0;
        while at < bytes.len() {
            match bytes[at] {
                byte if byte.is_ascii_whitespace() => at += 1,
                b'(' => {
                    if self.stack.len() > MAX_LIST_DEPTH {
                        return Err(invalid_command());
                    }
                    self.stack.push(Vec::new());
                    at += 1;
                }
                b')' => {
                    let list = self.stack.pop().ok_or_else(invalid_command)?;
                    if self.stack.is_empty() {
                        return Err(invalid_command());
                    }
                    self.push(ImapArg::List(list));
                    at += 1;
                }
                b'"' => {
                    let (value, next) = read_quoted(line, at)?;
                    self.push(ImapArg::Quoted(value));
                    at = next;
                }
                b'{' => {
                    // A literal marker ends its line: `{n}` then nothing.
                    let announced = literal_marker(&line[at..])?;
                    let data = self.literals.next().ok_or_else(invalid_command)?;
                    if data.len() != announced {
                        return Err(invalid_command());
                    }
                    self.push(ImapArg::Literal(data));
                    at = bytes.len();
                }
                _ => {
                    let next = atom_end(line, at)?;
                    self.push(ImapArg::Atom(line[at..next].to_string()));
                    at = next;
                }
            }
        }
        Ok(())
    }

    /// The top-level arguments, once every list is closed and every
    /// literal has found its marker.
    fn finish(mut self) -> Result<Vec<ImapArg>> {
        if self.stack.len() != 1 || self.literals.next().is_some() {
            return Err(invalid_command());
        }
        Ok(self.stack.pop().unwrap_or_default())
    }
}

/// The end of the atom starting at `start`: whitespace or a parenthesis
/// outside any `[...]` section. Inside a section everything belongs to
/// the atom, and quoted strings are skipped whole so a `]` or `)` in
/// one never ends the section.
fn atom_end(line: &str, start: usize) -> Result<usize> {
    let bytes = line.as_bytes();
    let mut depth = 0usize;
    let mut at = start;
    while at < bytes.len() {
        match bytes[at] {
            b'[' => depth += 1,
            b']' => depth = depth.saturating_sub(1),
            b'"' if depth > 0 => {
                at = read_quoted(line, at)?.1;
                continue;
            }
            b'(' | b')' if depth == 0 => break,
            byte if byte.is_ascii_whitespace() && depth == 0 => break,
            _ => {}
        }
        at += 1;
    }
    if depth > 0 {
        return Err(invalid_command());
    }
    Ok(at)
}

/// Read the quoted string whose opening quote is at `start`, returning
/// its value and the index after the closing quote.
///
/// Only `\\` and `\"` escapes are valid; CR/LF never enter a quoted value.
fn read_quoted(line: &str, start: usize) -> Result<(String, usize)> {
    let mut value = String::new();
    let mut escaped = false;
    for (offset, c) in line[start + 1..].char_indices() {
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
            '"' => return Ok((value, start + 1 + offset + 1)),
            '\r' | '\n' => return Err(invalid_command()),
            _ => value.push(c),
        }
    }
    // Unterminated string, or a dangling escape at the end.
    Err(invalid_command())
}

/// The byte count of a `{n}` marker that is the whole of `text` apart
/// from trailing whitespace. Synchronizing literals only: `{n+}` is
/// refused like any other malformed marker.
fn literal_marker(text: &str) -> Result<usize> {
    let digits = text
        .trim_end()
        .strip_prefix('{')
        .and_then(|rest| rest.strip_suffix('}'))
        .ok_or_else(invalid_command)?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid_command());
    }
    digits.parse().map_err(|_| invalid_command())
}

/// The byte count of the literal this line announces, if it ends in a
/// `{n}` marker. The session answers `+ ` and reads that many bytes
/// before the command's next line.
///
/// The scan knows quoted strings, so `"x {5}"` announces nothing; a
/// line that cannot be part of a valid command — an unterminated
/// quoted string, a marker that is malformed or not the last token —
/// is an error the session answers without ever sending a continuation.
pub fn pending_literal(line: &str) -> Result<Option<usize>> {
    let bytes = line.as_bytes();
    let mut token_start = true;
    let mut at = 0;
    while at < bytes.len() {
        match bytes[at] {
            b'"' => {
                at = read_quoted(line, at)?.1;
                token_start = false;
                continue;
            }
            b'{' if token_start => return literal_marker(&line[at..]).map(Some),
            b'(' => token_start = true,
            byte => token_start = byte.is_ascii_whitespace(),
        }
        at += 1;
    }
    Ok(None)
}

/// One end of a sequence-set range: a concrete number or `*`, the
/// largest number in use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SeqBound {
    Number(u32),
    Star,
}

impl SeqBound {
    fn resolve(self, max: u32) -> u32 {
        match self {
            SeqBound::Number(n) => n,
            SeqBound::Star => max,
        }
    }
}

/// A parsed IMAP sequence set.
///
/// A pure codec cannot know the mailbox size, so `*` stays symbolic and
/// [`SeqSet::contains`] resolves it against the largest number in use,
/// in whatever space the caller works (message numbers or UIDs). `*` is
/// an ordinary endpoint (RFC 3501 §9 `seq-number`): `2,*` names two
/// messages, and a range is the span between its two ends whichever
/// way round they were written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeqSet {
    ranges: Vec<(SeqBound, SeqBound)>,
}

impl SeqSet {
    /// The ALL set: every number from 1 up — the semantics of `1:*`.
    pub fn all() -> Self {
        Self {
            ranges: vec![(SeqBound::Number(1), SeqBound::Star)],
        }
    }

    /// True when `n` falls inside any range once `*` is resolved to
    /// `max`. `7:*` with a `max` of 5 is the range `5:7`, so a
    /// `<max+1>:*` probe still names the last message; in an empty
    /// mailbox (`max` 0) nothing is contained.
    pub fn contains(&self, n: u32, max: u32) -> bool {
        n != 0
            && n <= max
            && self.ranges.iter().any(|&(first, second)| {
                let (first, second) = (first.resolve(max), second.resolve(max));
                first.min(second) <= n && n <= first.max(second)
            })
    }
}

fn invalid_sequence_set() -> Error {
    Error::Unsupported("invalid sequence set".into())
}

fn seq_bound(raw: &str) -> Result<SeqBound> {
    if raw == "*" {
        return Ok(SeqBound::Star);
    }
    if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid_sequence_set());
    }
    match raw.parse::<u32>() {
        Ok(n) if n != 0 => Ok(SeqBound::Number(n)),
        _ => Err(invalid_sequence_set()),
    }
}

/// Parse an IMAP sequence set such as `2,4:6,*`.
///
/// Each comma-separated part is one number, `*`, or a range of two of
/// them. Sequence number `0`, empty parts, and anything that is not a
/// number are rejected with the fixed error `invalid sequence set`.
pub fn parse_seq_set(raw: &str) -> Result<SeqSet> {
    let mut ranges = Vec::new();
    for part in raw.split(',') {
        let range = match part.split_once(':') {
            None => {
                let bound = seq_bound(part)?;
                (bound, bound)
            }
            Some((first, second)) => (seq_bound(first)?, seq_bound(second)?),
        };
        ranges.push(range);
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
    /// `BODY[section]` or `BODY.PEEK[section]`, optionally limited to
    /// the `<offset.count>` octets of a partial fetch.
    Body {
        peek: bool,
        section: BodySection,
        partial: Option<(u32, u32)>,
    },
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

/// Parse the FETCH item arguments (everything after the sequence set):
/// either one parenthesized list `(FLAGS UID)` or one bare item or
/// macro (`ALL`, `FAST`, `BODY[HEADER.FIELDS (DATE)]`).
///
/// Macros expand per RFC 3501 — `FAST` → FLAGS INTERNALDATE RFC822.SIZE,
/// `ALL` → plus ENVELOPE, `FULL` → plus BODY, where a bare `BODY` requests
/// the non-extensible structure (RFC 3501 §6.4.5) and maps to
/// [`FetchItem::BodyStructure`]. Item names are case-insensitive.
/// `HEADER.FIELDS.NOT` sections are a v1 limitation and are rejected with
/// the fixed error `invalid fetch items`.
pub fn parse_fetch_items(args: &[ImapArg]) -> Result<Vec<FetchItem>> {
    let tokens: Vec<&ImapArg> = match args {
        [ImapArg::List(list)] => list.iter().collect(),
        [single] => vec![single],
        _ => return Err(invalid_fetch_items()),
    };
    let mut items = Vec::new();
    for token in tokens {
        let ImapArg::Atom(token) = token else {
            return Err(invalid_fetch_items());
        };
        items.extend(expand_fetch_token(token)?);
    }
    if items.is_empty() {
        return Err(invalid_fetch_items());
    }
    Ok(items)
}

/// Expand one fetch token; macros expand to several items.
fn expand_fetch_token(token: &str) -> Result<Vec<FetchItem>> {
    let (name, section, partial) = match token.find('[') {
        Some(open) => {
            let close = token.rfind(']').ok_or_else(invalid_fetch_items)?;
            if open + 1 > close {
                return Err(invalid_fetch_items());
            }
            let partial = parse_partial(&token[close + 1..])?;
            (&token[..open], Some(&token[open + 1..close]), partial)
        }
        None => (token, None, None),
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
                partial,
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

/// Parse what follows the `]` of a body item: nothing, or the
/// `<offset.count>` of a partial fetch (RFC 3501 §6.4.5; the count is
/// a non-zero number).
fn parse_partial(raw: &str) -> Result<Option<(u32, u32)>> {
    if raw.is_empty() {
        return Ok(None);
    }
    let (offset, count) = raw
        .strip_prefix('<')
        .and_then(|rest| rest.strip_suffix('>'))
        .and_then(|inner| inner.split_once('.'))
        .ok_or_else(invalid_fetch_items)?;
    let number = |digits: &str| -> Result<u32> {
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return Err(invalid_fetch_items());
        }
        digits.parse().map_err(|_| invalid_fetch_items())
    };
    let (offset, count) = (number(offset)?, number(count)?);
    if count == 0 {
        return Err(invalid_fetch_items());
    }
    Ok(Some((offset, count)))
}

/// Parse the text between `BODY[` and `]`.
fn parse_body_section(section: &str) -> Result<BodySection> {
    let args = parse_arguments(section).map_err(|_| invalid_fetch_items())?;
    match args.as_slice() {
        [] => Ok(BodySection::Empty),
        [ImapArg::Atom(name)] if name.eq_ignore_ascii_case("HEADER") => Ok(BodySection::Header),
        [ImapArg::Atom(name)] if name.eq_ignore_ascii_case("TEXT") => Ok(BodySection::Text),
        [ImapArg::Atom(name), ImapArg::List(list)]
            if name.eq_ignore_ascii_case("HEADER.FIELDS") =>
        {
            let mut fields = Vec::new();
            for field in list {
                match field {
                    ImapArg::Atom(field) | ImapArg::Quoted(field) if !field.is_empty() => {
                        fields.push(field.clone());
                    }
                    _ => return Err(invalid_fetch_items()),
                }
            }
            if fields.is_empty() {
                return Err(invalid_fetch_items());
            }
            Ok(BodySection::HeaderFields(fields))
        }
        [ImapArg::Atom(name), ..] if name.starts_with(|c: char| c.is_ascii_digit()) => {
            Ok(BodySection::Part(section.trim().to_string()))
        }
        _ => Err(invalid_fetch_items()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn atom(text: &str) -> ImapArg {
        ImapArg::Atom(text.into())
    }

    fn quoted(text: &str) -> ImapArg {
        ImapArg::Quoted(text.into())
    }

    /// The FETCH items of `a FETCH 1 <raw>`, parsed the way the session
    /// parses them: tokenized as a command first.
    fn fetch_items(raw: &str) -> Result<Vec<FetchItem>> {
        let request = parse_line(&format!("a FETCH 1 {raw}"))?;
        parse_fetch_items(&request.args[1..])
    }

    #[test]
    fn parses_login_list_select_and_uid_fetch() {
        let request = parse_line("a001 LOGIN \"user@example\" \"pass word\"").unwrap();
        assert_eq!(request.tag, "a001");
        assert_eq!(request.command, "LOGIN");
        assert_eq!(
            request.args,
            vec![quoted("user@example"), quoted("pass word")]
        );

        let request = parse_line("a009 LIST \"\" \"*\"").unwrap();
        assert_eq!(request.command, "LIST");
        assert_eq!(request.args, vec![quoted(""), quoted("*")]);

        let request = parse_line("a010 SELECT INBOX").unwrap();
        assert_eq!(request.command, "SELECT");
        assert_eq!(request.args, vec![atom("INBOX")]);

        let request =
            parse_line("a002 UID FETCH 1:* (FLAGS BODY.PEEK[HEADER.FIELDS (SUBJECT FROM)] UID)")
                .unwrap();
        assert_eq!(request.command, "UID");
        assert_eq!(request.args[0], atom("FETCH"));
        assert_eq!(
            request.args[2],
            ImapArg::List(vec![
                atom("FLAGS"),
                atom("BODY.PEEK[HEADER.FIELDS (SUBJECT FROM)]"),
                atom("UID"),
            ])
        );
        let items = parse_fetch_items(&request.args[2..]).unwrap();
        assert_eq!(items[0], FetchItem::Flags);
        assert!(
            matches!(items[1], FetchItem::Body { peek: true, section: BodySection::HeaderFields(ref f), .. } if f == &[String::from("SUBJECT"), String::from("FROM")])
        );
        assert_eq!(items[2], FetchItem::Uid);
    }

    #[test]
    fn tolerates_extra_whitespace_and_nests_lists() {
        let request = parse_line("  a004   ID  (\"name\" \"test\")  ").unwrap();
        assert_eq!(request.tag, "a004");
        assert_eq!(request.command, "ID");
        assert_eq!(
            request.args,
            vec![ImapArg::List(vec![quoted("name"), quoted("test")])]
        );

        // Lists nest, and a parenthesis ends an atom on either side.
        let request = parse_line("a SEARCH OR (SEEN (FROM a)) NOT(UNSEEN)").unwrap();
        assert_eq!(
            request.args,
            vec![
                atom("OR"),
                ImapArg::List(vec![
                    atom("SEEN"),
                    ImapArg::List(vec![atom("FROM"), atom("a")]),
                ]),
                atom("NOT"),
                ImapArg::List(vec![atom("UNSEEN")]),
            ]
        );
    }

    #[test]
    fn lists_respect_quoted_strings() {
        // A parenthesis inside a quoted string is text, not structure.
        let request = parse_line("a SEARCH (SUBJECT \"a)b\" FROM \"(\")").unwrap();
        assert_eq!(
            request.args,
            vec![ImapArg::List(vec![
                atom("SUBJECT"),
                quoted("a)b"),
                atom("FROM"),
                quoted("("),
            ])]
        );
        // So is a bracket or parenthesis quoted inside a section.
        let request = parse_line("a FETCH 1 BODY[HEADER.FIELDS (\"a]b\" \"c)d\")]").unwrap();
        assert_eq!(
            request.args[1],
            atom("BODY[HEADER.FIELDS (\"a]b\" \"c)d\")]")
        );
    }

    #[test]
    fn literals_fill_their_markers_anywhere_in_a_command() {
        // Chained literals at the top level.
        let request = parse_command(
            &["a003 LOGIN {4}", " {7}", ""],
            vec![b"user".to_vec(), b"hunter2".to_vec()],
        )
        .unwrap();
        assert_eq!(
            request.args,
            vec![
                ImapArg::Literal(b"user".to_vec()),
                ImapArg::Literal(b"hunter2".to_vec()),
            ]
        );

        // A literal inside a list: the list closes on the next line.
        let request = parse_command(
            &["a SEARCH (SUBJECT {3}", " SEEN) UNSEEN"],
            vec![b"a b".to_vec()],
        )
        .unwrap();
        assert_eq!(
            request.args,
            vec![
                ImapArg::List(vec![
                    atom("SUBJECT"),
                    ImapArg::Literal(b"a b".to_vec()),
                    atom("SEEN"),
                ]),
                atom("UNSEEN"),
            ]
        );

        // Markers and literals must pair up exactly.
        assert!(parse_command(&["a LOGIN {4}", ""], Vec::new()).is_err());
        assert!(parse_command(&["a LOGIN x"], vec![b"user".to_vec()]).is_err());
        assert!(parse_command(&["a LOGIN {5}", ""], vec![b"user".to_vec()]).is_err());
        assert!(parse_command(&["a LOGIN {4} trailing"], vec![b"user".to_vec()]).is_err());
    }

    #[test]
    fn detects_pending_literals() {
        assert_eq!(pending_literal("a003 LOGIN {5}").unwrap(), Some(5));
        assert_eq!(pending_literal("a003 LOGIN {5} ").unwrap(), Some(5));
        assert_eq!(pending_literal(" {7}").unwrap(), Some(7));
        assert_eq!(pending_literal("a SEARCH (SUBJECT {3}").unwrap(), Some(3));
        assert_eq!(pending_literal("a003 LOGIN user").unwrap(), None);
        assert_eq!(pending_literal("").unwrap(), None);
        // Inside a quoted string a marker is text.
        assert_eq!(pending_literal("a003 LOGIN \"x{5}\"").unwrap(), None);
        assert_eq!(pending_literal("a003 LOGIN \"x {5}\"").unwrap(), None);
        // A line that can never be valid announces nothing: the session
        // answers BAD without a continuation.
        assert!(pending_literal("a003 LOGIN {5+}").is_err());
        assert!(pending_literal("a003 LOGIN {5} trailing").is_err());
        assert!(pending_literal("a003 LOGIN \"x {5}").is_err());
        assert!(pending_literal("a003 LOGIN {}").is_err());
    }

    /// Every number in `1..=max` the set selects.
    fn selected(raw: &str, max: u32) -> Vec<u32> {
        let set = parse_seq_set(raw).unwrap();
        (1..=max).filter(|n| set.contains(*n, max)).collect()
    }

    #[test]
    fn sequence_sets_treat_star_as_an_ordinary_endpoint() {
        // `*` next to concrete numbers names the last message only —
        // it never widens into a range.
        assert_eq!(selected("2,4:6,*", 10), vec![2, 4, 5, 6, 10]);
        assert_eq!(selected("1,*", 5), vec![1, 5]);
        assert_eq!(selected("*", 5), vec![5]);
        assert_eq!(selected("*:*", 5), vec![5]);
        assert_eq!(selected("1:*", 5), vec![1, 2, 3, 4, 5]);
        assert_eq!(selected("4:*", 5), vec![4, 5]);
        assert_eq!(selected("*:4", 5), vec![4, 5]);
        // A start beyond the end still names the last message: the
        // range is `5:6` once `*` resolves.
        assert_eq!(selected("6:*", 5), vec![5]);
        // Finite ranges select what they name, nothing past the end.
        assert_eq!(selected("2:4", 5), vec![2, 3, 4]);
        assert!(selected("9:100", 5).is_empty());
        // An empty mailbox selects nothing at all.
        assert!(selected("*", 0).is_empty());
        assert!(selected("1:*", 0).is_empty());
        assert_eq!(SeqSet::all(), parse_seq_set("1:*").unwrap());
    }

    #[test]
    fn sequence_sets_normalise_reversed_ranges() {
        // RFC 3501 §9: `4:2` and `2:4` are the same set.
        assert_eq!(selected("5:1", 6), vec![1, 2, 3, 4, 5]);
        assert_eq!(selected("4:2,6", 6), vec![2, 3, 4, 6]);
    }

    #[test]
    fn sequence_sets_reject_malformed_input() {
        for raw in [
            "",
            " ",
            "0",
            "1,",
            ",1",
            "1:",
            ":1",
            "a",
            "1:2:3",
            "+1",
            "4294967296",
        ] {
            let error = parse_seq_set(raw).expect_err("malformed set must not parse");
            assert!(
                matches!(error, Error::Unsupported(message) if message == "invalid sequence set")
            );
        }
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
    fn expands_fetch_macros() {
        assert_eq!(
            fetch_items("FAST").unwrap(),
            vec![
                FetchItem::Flags,
                FetchItem::InternalDate,
                FetchItem::Rfc822Size
            ]
        );
        assert_eq!(
            fetch_items("ALL").unwrap(),
            vec![
                FetchItem::Flags,
                FetchItem::InternalDate,
                FetchItem::Rfc822Size,
                FetchItem::Envelope,
            ]
        );
        assert_eq!(
            fetch_items("(full)").unwrap(),
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
            fetch_items("(BODY[] BODY[HEADER] BODY[TEXT] BODY.PEEK[] BODY[1.2] BODY)").unwrap();
        assert_eq!(
            items,
            vec![
                FetchItem::Body {
                    peek: false,
                    section: BodySection::Empty,
                    partial: None,
                },
                FetchItem::Body {
                    peek: false,
                    section: BodySection::Header,
                    partial: None,
                },
                FetchItem::Body {
                    peek: false,
                    section: BodySection::Text,
                    partial: None,
                },
                FetchItem::Body {
                    peek: true,
                    section: BodySection::Empty,
                    partial: None,
                },
                FetchItem::Body {
                    peek: false,
                    section: BodySection::Part("1.2".into()),
                    partial: None,
                },
                FetchItem::BodyStructure,
            ]
        );
    }

    #[test]
    fn header_field_sections_parse_bare_or_in_a_list() {
        let wanted = vec![FetchItem::Body {
            peek: false,
            section: BodySection::HeaderFields(vec!["DATE".into(), "FROM".into()]),
            partial: None,
        }];
        // The unparenthesized form is one item, not three tokens.
        assert_eq!(
            fetch_items("BODY[HEADER.FIELDS (DATE FROM)]").unwrap(),
            wanted
        );
        assert_eq!(
            fetch_items("(BODY[HEADER.FIELDS (DATE FROM)])").unwrap(),
            wanted
        );
        // Quoted field names are the names themselves.
        assert_eq!(
            fetch_items("body[header.fields (\"DATE\" FROM)]").unwrap(),
            wanted
        );
        assert!(fetch_items("BODY[HEADER.FIELDS ()]").is_err());
        assert!(fetch_items("BODY[HEADER.FIELDS DATE]").is_err());
        assert!(fetch_items("BODY[HEADER.FIELDS.NOT (DATE)]").is_err());
    }

    #[test]
    fn parses_partial_fetches() {
        assert_eq!(
            fetch_items("(BODY.PEEK[]<0.65536> BODY[TEXT]<10.5>)").unwrap(),
            vec![
                FetchItem::Body {
                    peek: true,
                    section: BodySection::Empty,
                    partial: Some((0, 65536)),
                },
                FetchItem::Body {
                    peek: false,
                    section: BodySection::Text,
                    partial: Some((10, 5)),
                },
            ]
        );
        assert!(matches!(
            fetch_items("BODY[HEADER.FIELDS (DATE)]<0.1>").unwrap()[0],
            FetchItem::Body {
                partial: Some((0, 1)),
                ..
            }
        ));
        for raw in [
            "BODY[]<0>",
            "BODY[]<0.0>",
            "BODY[]<.5>",
            "BODY[]<0.5",
            "BODY[]0.5>",
            "BODY[]<a.5>",
            "BODY[]<0.5>x",
            "BODY[]<0.99999999999>",
            "RFC822<0.5>",
        ] {
            assert!(fetch_items(raw).is_err(), "{raw} must not parse");
        }
    }

    #[test]
    fn item_names_are_case_insensitive() {
        assert_eq!(
            fetch_items("(flags uid)").unwrap(),
            vec![FetchItem::Flags, FetchItem::Uid]
        );
    }

    #[test]
    fn rejects_malformed_fetch_lists() {
        assert!(fetch_items("(FLAGS").is_err());
        assert!(fetch_items("BOGUS").is_err());
        assert!(fetch_items("(BODY[HEADER").is_err());
        assert!(fetch_items("FLAGS UID").is_err());
        assert!(fetch_items("(FLAGS (UID))").is_err());
        assert!(fetch_items("()").is_err());
        let error = fetch_items("BOGUS").expect_err("bogus item must not parse");
        assert!(matches!(error, Error::Unsupported(message) if message == "invalid fetch items"));
    }

    #[test]
    fn rejects_malformed_command_lines() {
        assert!(parse_line("").is_err());
        assert!(parse_line("   ").is_err());
        assert!(parse_line("a001").is_err());
        assert!(parse_line("a001 LOGIN \"unterminated").is_err());
        assert!(parse_line("a001 LOGIN (unclosed").is_err());
        assert!(parse_line("a001 LOGIN unopened)").is_err());
        assert!(parse_line("a001 LOGIN {5} trailing").is_err());
        assert!(parse_line("a001 FETCH 1 BODY[unclosed").is_err());
        let deep = format!("a SEARCH {}ALL{}", "(".repeat(64), ")".repeat(64));
        assert!(parse_line(&deep).is_err());
        // `Request` deliberately has no `Debug`, so the outcome is
        // discarded without `expect_err`.
        let error = parse_line("").err().expect("empty line must not parse");
        assert!(matches!(error, Error::Unsupported(message) if message == "invalid command"));
    }
}
