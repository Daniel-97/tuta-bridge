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
use tokio::sync::Mutex;

use super::codec::{BodySection, FetchItem};
use super::render;
use super::search::SearchKey;
use crate::app::enrich::EnvelopeEnricher;
use crate::domain::{
    Address, Error, Folder, FolderKind, MailboxId, MessageContent, MessageHeader, MessagePage,
    MessageSummary, Result, StoredMailbox, StoredMessage,
};
use crate::ports::imap_backend::{FetchResponse, ImapBackend, MailboxView, SelectedMailbox};
use crate::ports::local_password::LocalPasswordStore;
use crate::ports::mail_source::MailSource;
use crate::ports::mailbox_writer::{MailRef, MailboxWriter};
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
    /// The write seam: every STORE/MOVE/EXPUNGE goes through it before
    /// the local index changes.
    pub writer: Arc<dyn MailboxWriter>,
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

/// What a `/` inside a folder name is listed as: DIVISION SLASH, which
/// looks the same and is not the hierarchy delimiter.
const SOLIDUS_STAND_IN: &str = "\u{2215}";

/// `INBOX` in any casing: the one mailbox name RFC 3501 compares
/// case-insensitively.
fn is_inbox_name(name: &str) -> bool {
    name.eq_ignore_ascii_case("INBOX")
}

/// The name each stored mailbox is listed and selected under, in the
/// order given. The store is flat and Tuta lets folder names repeat, so
/// the stored name is not always usable as it is:
///
/// * the Inbox-kind folder keeps its name when that is `INBOX` in some
///   casing and is listed as `INBOX` otherwise, so it is always the
///   mailbox `INBOX` names;
/// * a `/` in a name becomes [`SOLIDUS_STAND_IN`], so the delimiter
///   never invents a hierarchy that does not exist;
/// * names are unique: of several mailboxes with the same name the
///   first keeps it and the others get ` (2)`, ` (3)`, … — system
///   folders first, then lowest mailbox id, so the outcome does not
///   depend on listing order. Any casing of `INBOX` counts as the
///   Inbox's name.
///
/// The suffix is the smallest that is free, which keeps both
/// mailboxes reachable; if the first of two namesakes is deleted the
/// second takes over the plain name and its clients see a rename.
fn imap_names(mailboxes: &[StoredMailbox]) -> Vec<String> {
    let rank = |kind: &FolderKind| match kind {
        FolderKind::Inbox => 0,
        FolderKind::Custom => 2,
        _ => 1,
    };
    let mut order: Vec<usize> = (0..mailboxes.len()).collect();
    order.sort_by_key(|&index| (rank(&mailboxes[index].kind), mailboxes[index].id.0));

    let same = |a: &str, b: &str| a == b || (is_inbox_name(a) && is_inbox_name(b));
    let mut names = vec![String::new(); mailboxes.len()];
    let mut taken: Vec<String> = Vec::new();
    for index in order {
        let mailbox = &mailboxes[index];
        let base = if mailbox.kind != FolderKind::Inbox {
            mailbox.name.replace('/', SOLIDUS_STAND_IN)
        } else if is_inbox_name(&mailbox.name) {
            mailbox.name.clone()
        } else {
            "INBOX".to_string()
        };
        let mut name = base.clone();
        let mut copy = 2usize;
        while taken.iter().any(|other| same(other, &name)) {
            name = format!("{base} ({copy})");
            copy += 1;
        }
        taken.push(name.clone());
        names[index] = name;
    }
    names
}

/// Whether `requested` names the mailbox listed as `listed`: exactly,
/// or as `INBOX` in any casing.
fn name_matches(requested: &str, listed: &str) -> bool {
    requested == listed || (is_inbox_name(requested) && is_inbox_name(listed))
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

/// The time the `SENT*` keys compare: the `Date:` header once the row
/// is enriched, the received time until then — the same fallback the
/// stored sent date itself uses for undated mail.
fn sent_ms(header: &MessageHeader) -> i64 {
    if header.sent_at_ms > 0 {
        header.sent_at_ms
    } else {
        header.received_at_ms
    }
}

/// Evaluate one key against a stored message; `msn` is the message's
/// number in the searching session's view, `len` that view's message
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
        SearchKey::Uid(set) => set.contains(message.uid, max_uid),
        SearchKey::Sequence(set) => set.contains(msn, len),
        SearchKey::Since(start) => message.header.received_at_ms >= *start,
        SearchKey::Before(start) => message.header.received_at_ms < *start,
        SearchKey::On(start, end) => {
            message.header.received_at_ms >= *start && message.header.received_at_ms < *end
        }
        SearchKey::SentSince(start) => sent_ms(&message.header) >= *start,
        SearchKey::SentBefore(start) => sent_ms(&message.header) < *start,
        SearchKey::SentOn(start, end) => {
            let sent = sent_ms(&message.header);
            sent >= *start && sent < *end
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
        SearchKey::And(keys) => keys
            .iter()
            .all(|key| search_key_matches(key, msn, len, max_uid, message)),
    }
}

// ---------------------------------------------------------------------------
// Backend
// ---------------------------------------------------------------------------

/// A [`MailSource`] view that loads one message's content at most
/// once: the enricher and the body renderer of a single FETCH share
/// it, so a request needing both costs one download, not two.
struct OnceSource<'a> {
    inner: &'a dyn MailSource,
    loaded: Mutex<Option<MessageContent>>,
}

impl<'a> OnceSource<'a> {
    fn new(inner: &'a dyn MailSource) -> Self {
        Self {
            inner,
            loaded: Mutex::new(None),
        }
    }

    /// The content, handed over for good: the copy an earlier load
    /// kept, or a first load.
    async fn take(&self, message: &MessageSummary) -> Result<MessageContent> {
        match self.loaded.lock().await.take() {
            Some(content) => Ok(content),
            None => self.inner.content(message).await,
        }
    }
}

#[async_trait::async_trait]
impl MailSource for OnceSource<'_> {
    async fn folders(&self) -> Result<Vec<Folder>> {
        self.inner.folders().await
    }

    async fn messages(&self, folder: &Folder, limit: usize) -> Result<Vec<MessageSummary>> {
        self.inner.messages(folder, limit).await
    }

    async fn content(&self, message: &MessageSummary) -> Result<MessageContent> {
        let mut loaded = self.loaded.lock().await;
        if let Some(content) = loaded.as_ref() {
            return Ok(content.clone());
        }
        let content = self.inner.content(message).await?;
        *loaded = Some(content.clone());
        Ok(content)
    }

    async fn headers_page(
        &self,
        folder: &Folder,
        start: Option<&str>,
        limit: usize,
    ) -> Result<MessagePage> {
        self.inner.headers_page(folder, start, limit).await
    }
}

/// One mailbox as LIST answers it, under its listed name.
fn view_of(mailbox: &StoredMailbox, name: String) -> MailboxView {
    MailboxView {
        id: mailbox.id,
        name,
        special_use: render::special_use(&mailbox.kind),
    }
}

impl TutaImapBackend {
    /// Every stored mailbox with the name it is listed under.
    async fn listed(&self) -> Result<Vec<(StoredMailbox, String)>> {
        let mailboxes = self.store.mailboxes(self.account_id).await?;
        let names = imap_names(&mailboxes);
        Ok(mailboxes.into_iter().zip(names).collect())
    }

    /// The current state of one stored mailbox. The message list is the
    /// store's cheap `(uid, unread)` read: no header is loaded.
    async fn opened(&self, found: &StoredMailbox, listed: String) -> Result<SelectedMailbox> {
        Ok(SelectedMailbox {
            view: view_of(found, listed),
            uidvalidity: found.uidvalidity,
            uidnext: found.next_uid,
            messages: self.store.message_uids(found.id).await?,
        })
    }

    /// The stored mailbox with this id, or `None` once it is gone.
    async fn stored_mailbox(&self, mailbox: MailboxId) -> Result<Option<StoredMailbox>> {
        Ok(self
            .store
            .mailboxes(self.account_id)
            .await?
            .into_iter()
            .find(|stored| stored.id == mailbox))
    }

    /// The stored rows of these UIDs, ascending and deduplicated;
    /// UIDs without a row are skipped.
    async fn rows(&self, mailbox: MailboxId, uids: &[u32]) -> Result<Vec<StoredMessage>> {
        let mut wanted = uids.to_vec();
        wanted.sort_unstable();
        wanted.dedup();
        let mut rows = Vec::with_capacity(wanted.len());
        for uid in wanted {
            if let Some(row) = self.store.message_by_uid(mailbox, uid).await? {
                rows.push(row);
            }
        }
        Ok(rows)
    }

    /// Remove rows locally after a successful remote move/delete and
    /// return their UIDs.
    async fn remove_rows(&self, mailbox: MailboxId, rows: &[StoredMessage]) -> Result<Vec<u32>> {
        for row in rows {
            self.store.remove_message(mailbox, row.uid).await?;
        }
        Ok(rows.iter().map(|row| row.uid).collect())
    }
}

fn mail_refs(rows: &[StoredMessage]) -> Vec<MailRef> {
    rows.iter()
        .map(|row| MailRef {
            list_id: row.header.list_id.clone(),
            element_id: row.header.element_id.clone(),
        })
        .collect()
}

/// A row marked complete whose sent date never landed — the shape the
/// M2-era external-mail population left in existing databases, where
/// Tuta's `MailDetails.sentDate` is 0 and the real send time lived only
/// in the `Date:` header. Such a row is deliberately not complete (see
/// [`EnvelopeEnricher::enrich`]), so every body-class fetch routes it
/// through the enricher once; it comes back with the header's date and
/// short-circuits from then on. Genuinely dateless mail keeps paying one
/// content load per request, the same accepted posture as
/// permanently-unavailable content.
fn stale_complete(stored: &StoredMessage) -> bool {
    stored.header.envelope_complete && stored.header.sent_at_ms <= 0
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
            .listed()
            .await?
            .into_iter()
            .map(|(mailbox, name)| view_of(&mailbox, name))
            .collect())
    }

    async fn select(&self, name: &str) -> Result<Option<SelectedMailbox>> {
        match self
            .listed()
            .await?
            .into_iter()
            .find(|(_, listed)| name_matches(name, listed))
        {
            Some((found, listed)) => Ok(Some(self.opened(&found, listed).await?)),
            None => Ok(None),
        }
    }

    async fn snapshot(&self, mailbox: MailboxId) -> Result<Option<SelectedMailbox>> {
        match self
            .listed()
            .await?
            .into_iter()
            .find(|(stored, _)| stored.id == mailbox)
        {
            Some((found, listed)) => Ok(Some(self.opened(&found, listed).await?)),
            None => Ok(None),
        }
    }

    async fn uidvalidity(&self, mailbox: MailboxId) -> Result<Option<u32>> {
        Ok(self
            .store
            .mailboxes(self.account_id)
            .await?
            .iter()
            .find(|stored| stored.id == mailbox)
            .map(|stored| stored.uidvalidity))
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

        // Numeric part sections are refused before any load: a verdict
        // about the request, not about this message.
        if items.iter().any(|item| {
            matches!(
                item,
                FetchItem::Body {
                    section: BodySection::Part(_),
                    ..
                }
            )
        }) {
            return Err(unsupported_part_section());
        }

        let wants_body = items.iter().any(FetchItem::is_body);
        let wants_structure = items
            .iter()
            .any(|item| matches!(item, FetchItem::BodyStructure | FetchItem::BodyBasic));
        let wants_size = items.contains(&FetchItem::Rfc822Size);

        // One content load serves the whole request: the enricher and
        // the body renderer read through the same once-only source.
        let source = OnceSource::new(self.source.as_ref());

        // The structure and the size answer from the store; a missing
        // one costs exactly one enrichment, already persisted. A stale
        // row — marked complete, zero sent date — heals through the
        // same enrichment before anything is rendered from it.
        if (wants_structure && stored.mime_structure.is_none())
            || (wants_size && stored.rfc822_size.is_none())
            || ((wants_structure || wants_size || wants_body) && stale_complete(&stored))
        {
            stored = self.enricher.enrich(mailbox, &stored, &source).await?;
        }

        // Bodies always re-render — there is no stored body — but once
        // per request, however many sections it asks for.
        let mut bodies = Vec::new();
        if wants_body {
            let content = source.take(&summary_of(&stored)).await?;
            let rendered = self.renderer.render(&content)?;
            drop(content);

            // RFC822 and RFC822.TEXT are the non-peek equivalents of
            // BODY[]/BODY[TEXT] (RFC 3501 §6.4.5). RFC822.HEADER is
            // functionally equivalent to BODY.PEEK[HEADER] — §6.4.5
            // says so outright, and §7.4.2's "Equivalent to
            // BODY[HEADER]" is response-data naming whose own note
            // says \Seen is not set — so it never persists anything.
            let non_peek = items.iter().any(|item| {
                matches!(
                    item,
                    FetchItem::Body { peek: false, .. } | FetchItem::Rfc822 | FetchItem::Rfc822Text
                )
            });
            // A non-peek render persists a still-missing size (the
            // length is known the moment the bytes exist); PEEK renders
            // but never persists anything.
            if non_peek && stored.rfc822_size.is_none() {
                let size = u64::try_from(rendered.len())
                    .map_err(|_| Error::Storage("message size out of range".into()))?;
                self.store
                    .update_metadata(mailbox, stored.uid, &stored.header, Some(size))
                    .await?;
                stored.rfc822_size = Some(size);
            }

            for item in items {
                let section = match item {
                    FetchItem::Body { section, .. } => section,
                    FetchItem::Rfc822 => &BodySection::Empty,
                    FetchItem::Rfc822Text => &BodySection::Text,
                    FetchItem::Rfc822Header => &BodySection::Header,
                    _ => continue,
                };
                bodies.push(slice_body_section(&rendered, section)?);
            }
        }

        // UID, FLAGS, and INTERNALDATE come free from the stored
        // header, and the envelope renders from it as-is — partial or
        // complete — never a network load.
        Ok(Some(FetchResponse {
            uid: stored.uid,
            flags: render::flags(stored.header.unread),
            internal_date: render::internal_date(stored.header.received_at_ms),
            envelope: items
                .contains(&FetchItem::Envelope)
                .then(|| render::envelope(&stored.header)),
            bodystructure: if wants_structure {
                stored.mime_structure.clone()
            } else {
                None
            },
            rfc822_size: if wants_size { stored.rfc822_size } else { None },
            bodies,
        }))
    }

    async fn search(
        &self,
        mailbox: MailboxId,
        keys: &[SearchKey],
        view: &[u32],
    ) -> Result<Vec<u32>> {
        let messages = self.store.messages(mailbox).await?;
        // Numbers and star ranges resolve against the session's view:
        // its message count in number space, its highest uid in UID
        // space. A stored message outside the view is not a candidate.
        let len = u32::try_from(view.len()).unwrap_or(u32::MAX);
        let max_uid = view.last().copied().unwrap_or(0);
        Ok(messages
            .iter()
            .filter(|message| {
                let Ok(position) = view.binary_search(&message.uid) else {
                    return false;
                };
                let msn = u32::try_from(position + 1).unwrap_or(u32::MAX);
                keys.iter()
                    .all(|key| search_key_matches(key, msn, len, max_uid, message))
            })
            .map(|message| message.uid)
            .collect())
    }

    async fn store_seen(
        &self,
        mailbox: MailboxId,
        uids: &[u32],
        seen: bool,
    ) -> Result<Vec<(u32, bool)>> {
        let unread = !seen;
        // Rows already in the requested state need no remote call, but
        // still answer a FETCH line (RFC 3501 §6.4.6 reports the flags
        // whether or not they changed).
        let rows = self.rows(mailbox, uids).await?;
        let changing: Vec<StoredMessage> = rows
            .iter()
            .filter(|row| row.header.unread != unread)
            .cloned()
            .collect();
        if !changing.is_empty() {
            self.writer
                .set_unread(&mail_refs(&changing), unread)
                .await?;
            for row in &changing {
                let mut header = row.header.clone();
                header.unread = unread;
                self.store
                    .update_metadata(mailbox, row.uid, &header, row.rfc822_size)
                    .await?;
            }
        }
        Ok(rows.iter().map(|row| (row.uid, unread)).collect())
    }

    async fn move_mails(
        &self,
        mailbox: MailboxId,
        uids: &[u32],
        target: MailboxId,
    ) -> Result<Vec<u32>> {
        if mailbox == target {
            return Ok(Vec::new());
        }
        let Some(target) = self.stored_mailbox(target).await? else {
            return Err(Error::Unsupported("mailbox not found".into()));
        };
        let rows = self.rows(mailbox, uids).await?;
        if rows.is_empty() {
            return Ok(Vec::new());
        }
        self.writer
            .move_to_folder(&target.list_id, &mail_refs(&rows))
            .await?;
        self.remove_rows(mailbox, &rows).await
    }

    async fn expunge_mails(&self, mailbox: MailboxId, uids: &[u32]) -> Result<Vec<u32>> {
        let Some(source) = self.stored_mailbox(mailbox).await? else {
            return Ok(Vec::new());
        };
        let rows = self.rows(mailbox, uids).await?;
        if rows.is_empty() {
            return Ok(Vec::new());
        }
        let mails = mail_refs(&rows);
        // Only Trash ever destroys mail: everywhere else a delete is a
        // move, exactly like the Tuta clients do it.
        if source.kind == FolderKind::Trash {
            self.writer
                .delete_permanently(&source.list_id, &mails)
                .await?;
        } else {
            self.writer.move_to_trash(&mails).await?;
        }
        self.remove_rows(mailbox, &rows).await
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

    fn stored(id: i64, name: &str, kind: FolderKind) -> StoredMailbox {
        StoredMailbox {
            id: MailboxId(id),
            account_id: 1,
            list_id: format!("list-{id}"),
            name: name.into(),
            kind,
            uidvalidity: 1,
            next_uid: 1,
        }
    }

    #[test]
    fn listed_names_are_unique_flat_and_keep_inbox_special() {
        // Plain names pass through, in the order given.
        let names = imap_names(&[
            stored(1, "Inbox", FolderKind::Inbox),
            stored(2, "Archive", FolderKind::Archive),
            stored(3, "Work", FolderKind::Custom),
        ]);
        assert_eq!(names, ["Inbox", "Archive", "Work"]);

        // A slash never reaches the wire as the hierarchy delimiter.
        let names = imap_names(&[stored(3, "Clients/ACME", FolderKind::Custom)]);
        assert_eq!(names, ["Clients\u{2215}ACME"]);

        // Namesakes: the lowest id keeps the name whatever the listing
        // order, a system folder beats a custom one, and a suffix that
        // is itself taken is skipped.
        let names = imap_names(&[
            stored(9, "Work", FolderKind::Custom),
            stored(4, "Work", FolderKind::Custom),
            stored(5, "Work (2)", FolderKind::Custom),
            stored(2, "Archive", FolderKind::Custom),
            stored(7, "Archive", FolderKind::Archive),
        ]);
        assert_eq!(
            names,
            ["Work (3)", "Work", "Work (2)", "Archive (2)", "Archive"]
        );

        // Only the Inbox-kind folder answers to INBOX: a custom folder
        // called "inbox" is a namesake, and a localized Inbox is listed
        // under the name every client knows.
        let names = imap_names(&[
            stored(3, "inbox", FolderKind::Custom),
            stored(8, "Inbox", FolderKind::Inbox),
        ]);
        assert_eq!(names, ["inbox (2)", "Inbox"]);
        let names = imap_names(&[
            stored(1, "Posteingang", FolderKind::Inbox),
            stored(2, "INBOX", FolderKind::Custom),
        ]);
        assert_eq!(names, ["INBOX", "INBOX (2)"]);

        assert!(name_matches("inbox", "Inbox"));
        assert!(name_matches("Work (2)", "Work (2)"));
        assert!(!name_matches("work", "Work"));
        assert!(!name_matches("INBOX", "inbox (2)"));
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
