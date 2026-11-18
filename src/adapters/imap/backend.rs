//! The read-only IMAP backend over the local state store.
//!
//! `TutaImapBackend` answers every request from stored metadata: envelopes
//! render from the stored header, structures from the stored
//! `mime_structure` string, and only bodies re-render on demand through
//! the injected [`MailSource`] and [`MessageRenderer`]. Nothing here logs,
//! formats with `Debug`, or puts a subject, address, credential, or body
//! byte inside an error string.
//!
//! Network discipline: `ENVELOPE`, `FLAGS`, `UID`, `INTERNALDATE`, and
//! `SEARCH` never touch the source. `BODYSTRUCTURE` and `RFC822.SIZE`
//! load content at most once per message (the enricher persists the
//! result). `BODY[]`/`BODY.PEEK[]` always re-render — there is no body
//! cache by design.

use std::sync::Arc;

use secrecy::{ExposeSecret, SecretString};
use time::Date;

use super::codec::{parse_seq_set, BodySection, FetchItem, SeqSet};
use super::render;
use crate::app::enrich::EnvelopeEnricher;
use crate::domain::{
    Address, Error, FolderKind, MailboxId, MessageHeader, MessageSummary, Result, StoredMailbox,
    StoredMessage,
};
use crate::ports::imap_backend::{FetchResponse, ImapBackend, MailboxView, SelectedMailbox};
use crate::ports::local_password::LocalPasswordStore;
use crate::ports::mail_source::MailSource;
use crate::ports::renderer::MessageRenderer;
use crate::ports::state_store::StateStore;

/// The backend one IMAP session talks to.
///
/// No session lives inside: `serve` injects the owned `Arc<dyn
/// MailSource>` obtained from the SDK session, so the backend stays a
/// pure seam over the store, the enricher, and the renderer. The type
/// deliberately does not implement `Debug` — `expected_user` is the
/// account address and must not be printable into logs.
pub struct TutaImapBackend {
    pub account_id: i64,
    pub expected_user: String,
    pub passwords: Arc<dyn LocalPasswordStore>,
    pub store: Arc<dyn StateStore>,
    pub enricher: Arc<EnvelopeEnricher>,
    pub source: Arc<dyn MailSource>,
    pub renderer: Arc<dyn MessageRenderer>,
}

/// Compare two byte strings ASCII-case-insensitively without leaking
/// their contents through timing: the same loop shape as
/// [`constant_time_eq`], with every byte folded through the std
/// lowercase table (a branch-free lookup) before the XOR. Used for
/// the account address, which clients type in any casing.
pub fn constant_time_eq_ignore_ascii_case(a: &[u8], b: &[u8]) -> bool {
    let mut diff: u64 = (a.len() ^ b.len()) as u64;
    for i in 0..a.len().max(b.len()) {
        let byte_a = u64::from(a.get(i).copied().unwrap_or(0).to_ascii_lowercase());
        let byte_b = u64::from(b.get(i).copied().unwrap_or(0).to_ascii_lowercase());
        diff |= byte_a ^ byte_b;
    }
    diff == 0
}

/// Compare two byte strings without leaking their contents through
/// timing.
///
/// The loop always runs `max(a.len(), b.len())` iterations and every
/// iteration performs the same branch-free work: read one byte from
/// each side (zero past the end) and OR the XOR into the accumulator.
/// The iteration count is attacker-controlled only when the submitted
/// value is at least as long as the stored one; a shorter submission
/// runs the stored length's iterations, which is fine because the
/// stored length is not secret material. The length difference is
/// folded into the same accumulator instead of short-circuiting, so a
/// length mismatch costs the same work as a byte mismatch and byte
/// values never influence control flow. Only the final accumulator
/// decides equality; a differing length can never cancel out because
/// the whole 64-bit length XOR is part of it.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff: u64 = (a.len() ^ b.len()) as u64;
    for i in 0..a.len().max(b.len()) {
        let byte_a = u64::from(a.get(i).copied().unwrap_or(0));
        let byte_b = u64::from(b.get(i).copied().unwrap_or(0));
        diff |= byte_a ^ byte_b;
    }
    diff == 0
}

/// Resolve one requested mailbox name against a stored mailbox.
///
/// `INBOX` is case-insensitive and resolves the folder whose *kind* is
/// Inbox (its display name may be localized); every other name matches
/// exactly.
fn name_matches(requested: &str, mailbox: &StoredMailbox) -> bool {
    if requested.eq_ignore_ascii_case("INBOX") {
        return mailbox.kind == FolderKind::Inbox;
    }
    requested == mailbox.name
}

/// The summary every content load derives from a stored header — the
/// same derivation the enricher uses.
fn summary_of(stored: &StoredMessage) -> MessageSummary {
    MessageSummary {
        list_id: stored.header.list_id.clone(),
        element_id: stored.header.element_id.clone(),
        received_at_ms: stored.header.received_at_ms,
        subject: stored.header.subject.clone(),
        unread: stored.header.unread,
    }
}

// ---------------------------------------------------------------------------
// Body slicing
// ---------------------------------------------------------------------------

/// The fixed error for numeric `BODY[n]` part sections.
fn unsupported_part_section() -> Error {
    Error::Unsupported("message part sections are not supported".into())
}

/// Split rendered MIME bytes at the header/body blank-line separator.
///
/// The header slice includes the delimiting blank line, as RFC 3501
/// `BODY[HEADER]` does; a message without a separator is all header.
fn split_mime(rendered: &[u8]) -> (&[u8], &[u8]) {
    const SEPARATOR: &[u8] = b"\r\n\r\n";
    match rendered
        .windows(SEPARATOR.len())
        .position(|window| window == SEPARATOR)
    {
        Some(at) => (
            &rendered[..at + SEPARATOR.len()],
            &rendered[at + SEPARATOR.len()..],
        ),
        None => (rendered, &rendered[rendered.len()..]),
    }
}

/// Strip the surrounding quotes a client may put around a
/// `HEADER.FIELDS` field name: the codec keeps section text verbatim, so
/// `"SUBJECT"` must still match the `Subject:` header.
fn strip_field_quotes(name: &str) -> &str {
    let trimmed = name.trim();
    if trimmed.len() >= 2 && trimmed.starts_with('"') && trimmed.ends_with('"') {
        &trimmed[1..trimmed.len() - 1]
    } else {
        trimmed
    }
}

/// Slice the kept header lines for `BODY[HEADER.FIELDS (...)]`.
///
/// Matching field names compare case-insensitively after quote
/// stripping; folded continuation lines follow the line they belong to.
/// The output is terminated by the delimiting blank line, per RFC 3501.
fn header_fields(header: &[u8], fields: &[String]) -> Vec<u8> {
    let wanted: Vec<String> = fields
        .iter()
        .map(|field| strip_field_quotes(field).to_ascii_lowercase())
        .collect();

    let mut out = Vec::new();
    let mut keep_continuation = false;
    for raw_line in header.split(|&b| b == b'\n') {
        let line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        if line.is_empty() {
            continue;
        }
        if line.first().is_some_and(|&b| b == b' ' || b == b'\t') {
            if keep_continuation {
                out.extend_from_slice(line);
                out.extend_from_slice(b"\r\n");
            }
            continue;
        }
        keep_continuation = match line.iter().position(|&b| b == b':') {
            Some(at) => {
                let name = String::from_utf8_lossy(&line[..at])
                    .trim()
                    .to_ascii_lowercase();
                wanted.contains(&name)
            }
            None => false,
        };
        if keep_continuation {
            out.extend_from_slice(line);
            out.extend_from_slice(b"\r\n");
        }
    }
    out.extend_from_slice(b"\r\n");
    out
}

/// Slice the rendered bytes for one body section.
fn slice_body_section(rendered: &[u8], section: &BodySection) -> Result<Vec<u8>> {
    let (header, text) = split_mime(rendered);
    match section {
        BodySection::Empty => Ok(rendered.to_vec()),
        BodySection::Header => Ok(header.to_vec()),
        BodySection::Text => Ok(text.to_vec()),
        BodySection::HeaderFields(fields) => Ok(header_fields(header, fields)),
        BodySection::Part(_) => Err(unsupported_part_section()),
    }
}

// ---------------------------------------------------------------------------
// SEARCH
// ---------------------------------------------------------------------------

/// One parsed SEARCH criterion.
enum SearchKey {
    All,
    Unseen,
    Seen,
    /// `UID <set>`.
    Uid(SeqSet),
    /// A bare sequence set: message numbers, 1-based positions.
    Sequence(SeqSet),
    /// `SINCE <date>`: received on or after the UTC day start.
    Since(i64),
    /// `BEFORE <date>`: received strictly before the UTC day start.
    Before(i64),
    /// `ON <date>`: received within the UTC day `[start, end)`.
    On(i64, i64),
    /// `SUBJECT/FROM/TO/CC/HEADER <field> <value>`: case-insensitive
    /// substring match over the stored (partial or enriched) header
    /// field.
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

/// Consume the next criterion token or fail with the fixed message.
fn next_token<'a>(criteria: &'a [String], cursor: &mut usize) -> Result<&'a str> {
    match criteria.get(*cursor) {
        Some(token) => {
            *cursor += 1;
            Ok(token.as_str())
        }
        None => Err(invalid_search_criteria()),
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

/// Parse one key at `cursor`, consuming its argument tokens.
fn parse_search_key(criteria: &[String], cursor: &mut usize, depth: usize) -> Result<SearchKey> {
    if depth > MAX_SEARCH_KEY_DEPTH {
        return Err(invalid_search_criteria());
    }
    let token = next_token(criteria, cursor)?;
    match token.to_ascii_uppercase().as_str() {
        "ALL" => Ok(SearchKey::All),
        "UNSEEN" => Ok(SearchKey::Unseen),
        "SEEN" => Ok(SearchKey::Seen),
        "UID" => Ok(SearchKey::Uid(parse_seq_set(next_token(
            criteria, cursor,
        )?)?)),
        "SINCE" => Ok(SearchKey::Since(day_start_ms(parse_search_date(
            next_token(criteria, cursor)?,
        )?))),
        "BEFORE" => Ok(SearchKey::Before(day_start_ms(parse_search_date(
            next_token(criteria, cursor)?,
        )?))),
        "ON" => {
            let date = parse_search_date(next_token(criteria, cursor)?)?;
            Ok(SearchKey::On(day_start_ms(date), next_day_start_ms(date)))
        }
        "SUBJECT" => Ok(SearchKey::Header {
            field: "Subject".into(),
            value: next_token(criteria, cursor)?.to_string(),
        }),
        "FROM" => Ok(SearchKey::Header {
            field: "From".into(),
            value: next_token(criteria, cursor)?.to_string(),
        }),
        "TO" => Ok(SearchKey::Header {
            field: "To".into(),
            value: next_token(criteria, cursor)?.to_string(),
        }),
        "CC" => Ok(SearchKey::Header {
            field: "Cc".into(),
            value: next_token(criteria, cursor)?.to_string(),
        }),
        "HEADER" => Ok(SearchKey::Header {
            field: next_token(criteria, cursor)?.to_string(),
            value: next_token(criteria, cursor)?.to_string(),
        }),
        "LARGER" => Ok(SearchKey::Larger(
            next_token(criteria, cursor)?
                .parse()
                .map_err(|_| invalid_search_criteria())?,
        )),
        "SMALLER" => Ok(SearchKey::Smaller(
            next_token(criteria, cursor)?
                .parse()
                .map_err(|_| invalid_search_criteria())?,
        )),
        "NOT" => Ok(SearchKey::Not(Box::new(parse_search_key(
            criteria,
            cursor,
            depth + 1,
        )?))),
        "OR" => {
            let first = parse_search_key(criteria, cursor, depth + 1)?;
            let second = parse_search_key(criteria, cursor, depth + 1)?;
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

/// Deepest NOT/OR nesting accepted; deeper trees fail with the fixed
/// criteria error instead of recursing without bound.
const MAX_SEARCH_KEY_DEPTH: usize = 16;

/// Parse the full criterion list into the keys every message must match.
fn parse_search_criteria(criteria: &[String]) -> Result<Vec<SearchKey>> {
    if criteria.is_empty() {
        return Err(invalid_search_criteria());
    }
    let mut cursor = 0;
    let mut keys = Vec::new();
    while cursor < criteria.len() {
        keys.push(parse_search_key(criteria, &mut cursor, 0)?);
    }
    Ok(keys)
}

/// One address as searchable text: name and address both match.
fn address_text(address: &Address) -> String {
    match &address.name {
        Some(name) => format!("{name} {}", address.address),
        None => address.address.clone(),
    }
}

/// The stored header value a `HEADER <field> <value>` key matches
/// against. Unknown fields answer `None` — nothing was stored for them,
/// so no message can match.
fn stored_header_value(header: &MessageHeader, field: &str) -> Option<String> {
    match strip_field_quotes(field).to_ascii_lowercase().as_str() {
        "subject" => Some(header.subject.clone()),
        "from" => Some(address_text(&header.from)),
        "to" => Some(
            header
                .to
                .iter()
                .map(address_text)
                .collect::<Vec<_>>()
                .join(" "),
        ),
        "cc" => Some(
            header
                .cc
                .iter()
                .map(address_text)
                .collect::<Vec<_>>()
                .join(" "),
        ),
        "bcc" => Some(
            header
                .bcc
                .iter()
                .map(address_text)
                .collect::<Vec<_>>()
                .join(" "),
        ),
        "reply-to" => Some(
            header
                .reply_to
                .iter()
                .map(address_text)
                .collect::<Vec<_>>()
                .join(" "),
        ),
        "message-id" => header.message_id.clone(),
        "in-reply-to" => header.in_reply_to.clone(),
        "references" => Some(header.references.join(" ")),
        _ => None,
    }
}

/// Whether `n` falls inside the set, with the star semantics of
/// RFC 3501 §6.4.8 resolved against `max` — the largest number in
/// use in the caller's space (positions or uids):
///
/// * a lone `*` (`(0, None)`) selects exactly the last number;
/// * `x:*` selects `x..max`, and an `x` beyond `max` still selects
///   the last number, so a `UID <max+1>:*` probe never misses the
///   newest mail;
/// * finite ranges select what they name.
///
/// This mirrors the resolution the session applies on the FETCH
/// path, kept backend-side on purpose: a shared helper would couple
/// the two modules for a refinement that does not need it yet.
fn number_in_set(set: &SeqSet, n: u32, max: u32) -> bool {
    set.ranges().iter().any(|&(start, stop)| match stop {
        Some(stop) => start <= n && n <= stop,
        None if start == 0 => n == max,
        None => start <= n || n == max,
    })
}

/// Evaluate one key against a stored message; `msn` is the message's
/// 1-based position in the mailbox, `len` the mailbox's message
/// count, and `max_uid` its highest uid — the ends star ranges
/// resolve against in each space.
fn search_key_matches(
    key: &SearchKey,
    msn: u32,
    len: u32,
    max_uid: u32,
    message: &StoredMessage,
) -> bool {
    match key {
        SearchKey::All => true,
        SearchKey::Unseen => message.header.unread,
        SearchKey::Seen => !message.header.unread,
        SearchKey::Uid(set) => number_in_set(set, message.uid, max_uid),
        SearchKey::Sequence(set) => number_in_set(set, msn, len),
        SearchKey::Since(start) => message.header.received_at_ms >= *start,
        SearchKey::Before(start) => message.header.received_at_ms < *start,
        SearchKey::On(start, end) => {
            message.header.received_at_ms >= *start && message.header.received_at_ms < *end
        }
        SearchKey::Header { field, value } => {
            match stored_header_value(&message.header, field) {
                // A case-insensitive substring over the stored field.
                Some(hay) => hay.to_lowercase().contains(&value.to_lowercase()),
                None => false,
            }
        }
        // Sizes come from the store; SEARCH never enriches, so a message
        // without a stored size matches neither LARGER nor SMALLER.
        SearchKey::Larger(n) => message.rfc822_size.is_some_and(|size| size > *n),
        SearchKey::Smaller(n) => message.rfc822_size.is_some_and(|size| size < *n),
        SearchKey::Not(inner) => !search_key_matches(inner, msn, len, max_uid, message),
        SearchKey::Or(first, second) => {
            search_key_matches(first, msn, len, max_uid, message)
                || search_key_matches(second, msn, len, max_uid, message)
        }
    }
}

// ---------------------------------------------------------------------------
// Backend
// ---------------------------------------------------------------------------

impl TutaImapBackend {
    /// Render one body section for `stored`, loading content exactly
    /// once.
    ///
    /// Non-peek renders persist a still-missing `rfc822_size` (the
    /// length is known the moment the bytes exist); PEEK renders but
    /// never persists anything. Part sections are refused before any
    /// load.
    async fn body_section(
        &self,
        mailbox: MailboxId,
        stored: &mut StoredMessage,
        peek: bool,
        section: &BodySection,
    ) -> Result<Vec<u8>> {
        if matches!(section, BodySection::Part(_)) {
            return Err(unsupported_part_section());
        }

        let content = self.source.content(&summary_of(stored)).await?;
        let rendered = self.renderer.render(&content)?;

        if !peek && stored.rfc822_size.is_none() {
            let size = u64::try_from(rendered.len())
                .map_err(|_| Error::Storage("message size out of range".into()))?;
            self.store
                .update_metadata(mailbox, stored.uid, &stored.header, Some(size))
                .await?;
            stored.rfc822_size = Some(size);
        }

        slice_body_section(&rendered, section)
    }

    /// Enrich `stored` once, returning the enriched snapshot.
    async fn enrich(&self, mailbox: MailboxId, stored: &StoredMessage) -> Result<StoredMessage> {
        self.enricher
            .enrich(mailbox, stored, self.source.as_ref())
            .await
    }
}

#[async_trait::async_trait]
impl ImapBackend for TutaImapBackend {
    async fn login(&self, user: &str, password: &SecretString) -> Result<bool> {
        // The user name compares ASCII-case-insensitively (clients
        // type the address in any casing); the password stays exact.
        // Both comparisons run to completion in the same constant-
        // time shape, nothing about the outcome is observable except
        // the returned boolean, and no credential ever reaches a log
        // line or an error string.
        let Some(stored) = self.passwords.load().await? else {
            return Ok(false);
        };
        let user_ok =
            constant_time_eq_ignore_ascii_case(user.as_bytes(), self.expected_user.as_bytes());
        let password_ok = constant_time_eq(
            password.expose_secret().as_bytes(),
            stored.expose_secret().as_bytes(),
        );
        Ok(user_ok && password_ok)
    }

    async fn mailboxes(&self) -> Result<Vec<MailboxView>> {
        Ok(self
            .store
            .mailboxes(self.account_id)
            .await?
            .into_iter()
            .map(|mailbox| MailboxView {
                id: mailbox.id,
                name: mailbox.name,
                special_use: render::special_use(&mailbox.kind),
            })
            .collect())
    }

    async fn select(&self, name: &str) -> Result<Option<SelectedMailbox>> {
        let mailboxes = self.store.mailboxes(self.account_id).await?;
        let Some(found) = mailboxes.iter().find(|mailbox| name_matches(name, mailbox)) else {
            return Ok(None);
        };
        let view = MailboxView {
            id: found.id,
            name: found.name.clone(),
            special_use: render::special_use(&found.kind),
        };
        let messages = self.store.messages(found.id).await?;
        Ok(Some(SelectedMailbox {
            view,
            uidvalidity: found.uidvalidity,
            uidnext: found.next_uid,
            exists: messages.len(),
            unseen: messages
                .iter()
                .filter(|message| message.header.unread)
                .count(),
        }))
    }

    async fn fetch(
        &self,
        mailbox: MailboxId,
        uid: u32,
        items: &[FetchItem],
    ) -> Result<Option<FetchResponse>> {
        let Some(mut stored) = self.store.message_by_uid(mailbox, uid).await? else {
            return Ok(None);
        };

        // UID, FLAGS, and INTERNALDATE come free from the stored header.
        let mut response = FetchResponse {
            uid: stored.uid,
            flags: render::flags(stored.header.unread),
            internal_date: render::internal_date(stored.header.received_at_ms),
            envelope: None,
            bodystructure: None,
            rfc822_size: None,
            body: None,
        };

        for item in items {
            match item {
                FetchItem::Uid | FetchItem::Flags | FetchItem::InternalDate => {}
                // The envelope renders from the stored header as-is —
                // partial or complete — and never a network load.
                FetchItem::Envelope => {
                    response.envelope = Some(render::envelope(&stored.header));
                }
                // The structure answers from the store; a missing one
                // costs exactly one enrichment, already persisted.
                FetchItem::BodyStructure => {
                    if stored.mime_structure.is_none() {
                        stored = self.enrich(mailbox, &stored).await?;
                    }
                    response.bodystructure = stored.mime_structure.clone();
                }
                // The size answers from the store; a missing one costs
                // exactly one enrichment, without re-rendering here.
                FetchItem::Rfc822Size => {
                    if stored.rfc822_size.is_none() {
                        stored = self.enrich(mailbox, &stored).await?;
                    }
                    response.rfc822_size = stored.rfc822_size;
                }
                FetchItem::Body { peek, section } => {
                    let bytes = self
                        .body_section(mailbox, &mut stored, *peek, section)
                        .await?;
                    response.body = Some(bytes);
                }
                // RFC822 and RFC822.TEXT are the non-peek equivalents of
                // BODY[]/BODY[TEXT] (RFC 3501 §6.4.5). RFC822.HEADER is
                // functionally equivalent to BODY.PEEK[HEADER] — §6.4.5
                // says so outright, and §7.4.2's "Equivalent to
                // BODY[HEADER]" is response-data naming whose own note
                // says \Seen is not set — so it renders and slices but
                // never persists.
                FetchItem::Rfc822 | FetchItem::Rfc822Text | FetchItem::Rfc822Header => {
                    let (peek, section) = match item {
                        FetchItem::Rfc822 => (false, BodySection::Empty),
                        FetchItem::Rfc822Text => (false, BodySection::Text),
                        _ => (true, BodySection::Header),
                    };
                    let bytes = self
                        .body_section(mailbox, &mut stored, peek, &section)
                        .await?;
                    response.body = Some(bytes);
                }
            }
        }
        Ok(Some(response))
    }

    async fn search(&self, mailbox: MailboxId, criteria: &[String]) -> Result<Vec<u32>> {
        let keys = parse_search_criteria(criteria)?;
        let messages = self.store.messages(mailbox).await?;
        // Star ranges resolve against the ends actually in use: the
        // message count in MSN space, the highest uid in UID space.
        let len = u32::try_from(messages.len()).unwrap_or(u32::MAX);
        let max_uid = messages
            .iter()
            .map(|message| message.uid)
            .max()
            .unwrap_or(0);
        Ok(messages
            .iter()
            .enumerate()
            .filter(|(index, message)| {
                let msn = u32::try_from(index + 1).unwrap_or(u32::MAX);
                keys.iter()
                    .all(|key| search_key_matches(key, msn, len, max_uid, message))
            })
            .map(|(_, message)| message.uid)
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_compares_without_length_short_circuit() {
        assert!(constant_time_eq(b"", b""));
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        // A prefix must not pass for equality.
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(!constant_time_eq(b"ab", b"abc"));
        // Missing bytes compare against zero, so NUL padding can never
        // blur a length difference.
        assert!(!constant_time_eq(b"a\0", b"a\0\0"));
        assert!(!constant_time_eq(b"xxxxxxxx", b"xxxxxxxxx"));
    }

    #[test]
    fn caseless_compares_fold_ascii_case_without_length_short_circuit() {
        assert!(constant_time_eq_ignore_ascii_case(b"", b""));
        assert!(constant_time_eq_ignore_ascii_case(
            b"Owner@Example",
            b"OWNER@example"
        ));
        assert!(constant_time_eq_ignore_ascii_case(
            b"owner@example",
            b"Owner@Example"
        ));
        assert!(!constant_time_eq_ignore_ascii_case(
            b"owner@example",
            b"owner@examples"
        ));
        // A prefix must not pass for equality, in either direction.
        assert!(!constant_time_eq_ignore_ascii_case(
            b"own",
            b"owner@example"
        ));
        assert!(!constant_time_eq_ignore_ascii_case(
            b"owner@example",
            b"own"
        ));
        // Folding is ASCII-only: non-ASCII bytes compare exactly.
        assert!(!constant_time_eq_ignore_ascii_case(&[0xC4], &[0xE4]));
        assert!(constant_time_eq_ignore_ascii_case(&[0xC4], &[0xC4]));
    }

    #[test]
    fn search_star_ranges_resolve_against_the_mailbox_ends() {
        // A lone `*` selects exactly the last number, never every
        // number.
        let lone = parse_seq_set("*").unwrap();
        assert!(number_in_set(&lone, 5, 5) && !number_in_set(&lone, 4, 5));
        // `x:*` runs to the end, and an `x` beyond the end still
        // selects the last number: the `<max+1>:*` probe mbsync sends.
        let mbsync = parse_seq_set("6:*").unwrap();
        assert!(number_in_set(&mbsync, 5, 5) && !number_in_set(&mbsync, 4, 5));
        // Finite ranges select what they name.
        let finite = parse_seq_set("2:4").unwrap();
        assert!(number_in_set(&finite, 3, 5) && !number_in_set(&finite, 5, 5));
    }

    #[test]
    fn body_sections_slice_at_the_blank_line_separator() {
        let rendered = b"From: a@b\r\nSubject: hi\r\n\r\nHello there\r\n".to_vec();
        let (header, text) = split_mime(&rendered);
        assert_eq!(header, b"From: a@b\r\nSubject: hi\r\n\r\n".as_slice());
        assert_eq!(text, b"Hello there\r\n".as_slice());

        // No separator: everything is header, the body is empty.
        let head_only = b"From: a@b\r\nSubject: hi\r\n".to_vec();
        let (header, text) = split_mime(&head_only);
        assert_eq!(header, head_only.as_slice());
        assert!(text.is_empty());
    }

    #[test]
    fn quoted_field_names_strip_to_the_bare_header_name() {
        assert_eq!(strip_field_quotes("\"SUBJECT\""), "SUBJECT");
        assert_eq!(strip_field_quotes("  \"Subject\"  "), "Subject");
        assert_eq!(strip_field_quotes("FROM"), "FROM");
        // A lone quote or an empty name stays verbatim.
        assert_eq!(strip_field_quotes("\""), "\"");
        assert_eq!(strip_field_quotes("\"\""), "");
    }

    #[test]
    fn header_fields_strip_quotes_and_fold_continuations() {
        let header =
            b"From: Alice <a@b>\r\nSubject: folded\r\n  continuation\r\nX-Ignored: 1\r\n\r\n";
        let out = header_fields(header, &["\"SUBJECT\"".to_string(), "from".to_string()]);
        // Original line order is preserved; the output carries the
        // matching fields and ends with the delimiting blank line.
        assert_eq!(
            out,
            b"From: Alice <a@b>\r\nSubject: folded\r\n  continuation\r\n\r\n".to_vec()
        );

        // Nothing matched: just the blank terminator.
        let out = header_fields(header, &["\"X-Missing\"".to_string()]);
        assert_eq!(out, b"\r\n".to_vec());
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
    fn search_criteria_parse_index_keys_and_refuse_bodies() {
        let parse = |criteria: &[&str]| {
            let owned: Vec<String> = criteria.iter().map(|c| c.to_string()).collect();
            parse_search_criteria(&owned)
        };

        assert!(matches!(parse(&["ALL"]).unwrap()[0], SearchKey::All));
        assert!(matches!(parse(&["UNSEEN"]).unwrap()[0], SearchKey::Unseen));
        assert!(matches!(parse(&["SEEN"]).unwrap()[0], SearchKey::Seen));
        assert!(matches!(
            parse(&["UID", "1:2"]).unwrap()[0],
            SearchKey::Uid(_)
        ));
        assert!(matches!(
            parse(&["1:2"]).unwrap()[0],
            SearchKey::Sequence(_)
        ));
        assert!(matches!(
            parse(&["NOT", "SEEN"]).unwrap()[0],
            SearchKey::Not(_)
        ));
        assert!(matches!(
            parse(&["OR", "UNSEEN", "SUBJECT", "x"]).unwrap()[0],
            SearchKey::Or(_, _)
        ));
        assert!(matches!(
            parse(&["SINCE", "15-Nov-2023"]).unwrap()[0],
            SearchKey::Since(start) if start == 1_700_006_400_000
        ));

        // Structural failures answer the fixed criteria string.
        assert!(parse(&[]).is_err());
        assert!(parse(&["SUBJECT"]).is_err());
        assert!(parse(&["UID", "0"]).is_err());
        assert!(matches!(
            parse(&["HEADER", "Subject"]),
            Err(Error::Unsupported(message)) if message == "invalid search criteria"
        ));

        // Unsupported keys answer the fixed unsupported string — NEW/OLD
        // included: they are \Recent-based, and their only faithful
        // reductions (nothing / everything) would be a lie.
        for criteria in [
            ["BODY", "x"],
            ["TEXT", "x"],
            ["KEYWORD", "f"],
            ["FLAGGED", ""],
            ["NEW", ""],
            ["OLD", ""],
        ] {
            assert!(
                matches!(parse(&criteria), Err(Error::Unsupported(message)) if message == "search key not supported"),
                "{criteria:?} must be refused"
            );
        }

        // Deep NOT nesting is refused instead of recursing without bound.
        let mut deep: Vec<String> = (0..20).map(|_| "NOT".to_string()).collect();
        deep.push("SEEN".to_string());
        assert!(matches!(
            parse_search_criteria(&deep),
            Err(Error::Unsupported(message)) if message == "invalid search criteria"
        ));
    }

    #[test]
    fn stored_header_values_cover_the_index_fields() {
        let header = partial_like_header();
        assert_eq!(
            stored_header_value(&header, "Subject").as_deref(),
            Some("list subject")
        );
        assert_eq!(
            stored_header_value(&header, "\"MESSAGE-ID\""),
            header.message_id.clone()
        );
        // FROM matches both the display name and the address.
        assert_eq!(
            stored_header_value(&header, "From").as_deref(),
            Some("Alice list@example.invalid")
        );
        // Fields nothing was stored for can never match.
        assert_eq!(stored_header_value(&header, "X-Custom"), None);
    }

    /// A partial header shaped like the synced rows.
    fn partial_like_header() -> MessageHeader {
        MessageHeader {
            list_id: "mail-list".into(),
            element_id: "e1".into(),
            received_at_ms: 1_700_000_000_000,
            sent_at_ms: 0,
            subject: "list subject".into(),
            from: Address {
                name: Some("Alice".into()),
                address: "list@example.invalid".into(),
            },
            to: Vec::new(),
            cc: Vec::new(),
            bcc: Vec::new(),
            reply_to: Vec::new(),
            unread: true,
            message_id: None,
            in_reply_to: None,
            references: Vec::new(),
            envelope_complete: false,
        }
    }
}
