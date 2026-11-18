//! Pure IMAP4rev1 response renderers: ENVELOPE, BODYSTRUCTURE,
//! INTERNALDATE, flags, and SPECIAL-USE attributes.
//!
//! Every function is pure — no I/O, no session state, no logging of
//! message data — and byte-exact, because the returned strings go
//! straight onto the wire. Every domain-derived string is encoded with
//! [`super::codec::encode_string`]; a value that must travel as a
//! literal is already framed as `{n}\r\n<bytes>` inside the returned
//! string, so the session can write the rendered text verbatim. Fixed
//! protocol tokens (`NIL`, `"TEXT"`, `"BASE64"`, …) are compile-time
//! constants and appear as-is.

use time::format_description::well_known::Rfc2822;
use time::OffsetDateTime;

use super::codec::{encode_string, ImapString};
use crate::domain::{Address, Attachment, FolderKind, MessageContent, MessageHeader};

/// The three-letter month names an INTERNALDATE carries, `Jan..Dec`.
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// The flat all-NIL group an empty address list renders as.
///
/// This is the exact shape the response format pins for empty lists:
/// a syntactically valid address list whose all-NIL entries are what
/// RFC 3501 uses to mark group boundaries, so clients skip them.
const EMPTY_ADDRESS_LIST: &str = "(NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL)";

/// Encode one value for the wire: a quoted string when `encode_string`
/// allows it, otherwise a literal already framed as `{n}\r\n<bytes>`
/// so the session can write the rendered text verbatim.
fn qs(value: &str) -> String {
    match encode_string(value) {
        ImapString::Quoted(quoted) => format!("\"{quoted}\""),
        ImapString::Literal(bytes) => format!("{{{}}}\r\n{value}", bytes.len()),
    }
}

/// Render an optional header value: `NIL` when absent.
fn option_qs(value: &Option<String>) -> String {
    value.as_deref().map_or_else(|| "NIL".to_string(), qs)
}

/// Render an INTERNALDATE value, always in UTC:
/// `"14 Nov 2023 22:13:20 +0000"`.
///
/// A timestamp at or before the epoch — or one the calendar cannot
/// represent — clamps to the epoch itself: pre-epoch dates are never
/// fabricated.
pub fn internal_date(ms: i64) -> String {
    let dt = OffsetDateTime::from_unix_timestamp_nanos(ms.max(0) as i128 * 1_000_000)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH);
    format!(
        "\"{:02} {} {:04} {:02}:{:02}:{:02} +0000\"",
        dt.day(),
        MONTHS[usize::from(u8::from(dt.month())) - 1],
        dt.year(),
        dt.hour(),
        dt.minute(),
        dt.second()
    )
}

/// Render a message's flag list: unread messages carry no flags, read
/// messages carry `\Seen`.
pub fn flags(unread: bool) -> String {
    if unread {
        String::new()
    } else {
        "\\Seen".to_string()
    }
}

/// The SPECIAL-USE attribute for a folder kind; custom folders carry
/// none.
pub fn special_use(kind: &FolderKind) -> &'static str {
    match kind {
        FolderKind::Inbox => "\\Inbox",
        FolderKind::Sent => "\\Sent",
        FolderKind::Drafts => "\\Drafts",
        FolderKind::Trash => "\\Trash",
        FolderKind::Junk => "\\Junk",
        FolderKind::Archive => "\\Archive",
        FolderKind::Custom => "",
    }
}

/// Render one address as `(name adl mailbox host)`: `NIL` adl, the
/// mailbox and host split at the last `@`. An address without `@` keeps
/// the whole value in the mailbox slot with a `NIL` host.
fn address(addr: &Address) -> String {
    let name = match addr.name.as_deref() {
        Some(name) => qs(name),
        None => "NIL".to_string(),
    };
    let (mailbox, host) = match addr.address.rsplit_once('@') {
        Some((mailbox, host)) => (qs(mailbox), qs(host)),
        None => (qs(&addr.address), "NIL".to_string()),
    };
    format!("({name} NIL {mailbox} {host})")
}

/// Render an address list; an empty list renders as the all-NIL group.
fn address_list(addrs: &[Address]) -> String {
    if addrs.is_empty() {
        return EMPTY_ADDRESS_LIST.to_string();
    }
    let inner = addrs.iter().map(address).collect::<Vec<_>>().join(" ");
    format!("({inner})")
}

/// Render the ENVELOPE fetch item for one header:
/// `(date subject from sender reply-to to cc bcc in-reply-to message-id)`.
///
/// The date is RFC 2822 in UTC. `sender` and `reply-to` default to the
/// from address when absent — standard practice. A `sent_at_ms` at or
/// before the epoch, or one the calendar cannot represent, renders a
/// `NIL` date: pre-epoch dates are never fabricated.
pub fn envelope(header: &MessageHeader) -> String {
    let date = if header.sent_at_ms <= 0 {
        "NIL".to_string()
    } else {
        OffsetDateTime::from_unix_timestamp_nanos(header.sent_at_ms as i128 * 1_000_000)
            .ok()
            .and_then(|dt| dt.format(&Rfc2822).ok())
            .map(|date| qs(&date))
            .unwrap_or_else(|| "NIL".to_string())
    };

    let from = address_list(std::slice::from_ref(&header.from));
    let reply_to = if header.reply_to.is_empty() {
        from.clone()
    } else {
        address_list(&header.reply_to)
    };

    let fields = [
        date,
        qs(&header.subject),
        from.clone(),
        // No separate sender exists: it defaults to the from value.
        from,
        reply_to,
        address_list(&header.to),
        address_list(&header.cc),
        address_list(&header.bcc),
        option_qs(&header.in_reply_to),
        option_qs(&header.message_id),
    ];
    format!("({})", fields.join(" "))
}

/// The plain text the MIME renderer embeds: the stored text, the HTML
/// flattened to text, or nothing — the same derivation `MimeRenderer`
/// uses, so the reported sizes describe the part that goes on the wire.
fn plain_text(content: &MessageContent) -> String {
    content
        .body_text
        .clone()
        .or_else(|| content.body_html.as_deref().map(mail_parser::html_to_text))
        .unwrap_or_default()
}

/// One text part:
/// `("TEXT" <subtype> ("CHARSET" "UTF-8") NIL NIL "8BIT" <len> <lines>)`.
///
/// `<len>` counts the stored text bytes and `<lines>` its line count.
fn text_part(subtype: &str, body: &str) -> String {
    format!(
        "(\"TEXT\" \"{subtype}\" (\"CHARSET\" \"UTF-8\") NIL NIL \"8BIT\" {} {})",
        body.len(),
        body.lines().count()
    )
}

/// One attachment part:
/// `("application" <subtype> ("NAME" <name>) NIL NIL "BASE64" <len> NIL)`
/// with the subtype taken from the lowercased file name extension — or
/// `octet-stream` when the name has none — and `<len>` counting the
/// decoded payload bytes.
fn attachment_part(attachment: &Attachment) -> String {
    let subtype = attachment
        .name
        .rsplit_once('.')
        .map(|(_, ext)| ext.to_ascii_lowercase())
        .filter(|ext| !ext.is_empty())
        .unwrap_or_else(|| "octet-stream".to_string());
    format!(
        "(\"application\" {} (\"NAME\" {}) NIL NIL \"BASE64\" {} NIL)",
        qs(&subtype),
        qs(&attachment.name),
        attachment.data.len()
    )
}

/// Render the BODYSTRUCTURE fetch item, mirroring the shapes the MIME
/// renderer writes:
///
/// * text-only — a single `("TEXT" "PLAIN" …)` part;
/// * HTML present — the part wrapped as `("alternative" <plain>
///   <html>)`;
/// * attachments — everything under a `("mixed" …)` root with one
///   part per attachment.
///
/// Non-multipart extension data is omitted.
pub fn bodystructure(content: &MessageContent) -> String {
    let plain = text_part("PLAIN", &plain_text(content));
    let text = match content.body_html.as_deref() {
        None => plain,
        Some(html) => format!("(\"alternative\" {} {})", plain, text_part("HTML", html)),
    };
    if content.attachments.is_empty() {
        return text;
    }
    let parts = std::iter::once(text)
        .chain(content.attachments.iter().map(attachment_part))
        .collect::<Vec<_>>()
        .join(" ");
    format!("(\"mixed\" {parts})")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The brief's ENVELOPE fixture: from `alice@x.y` (no display
    /// name), to `Bob <bob@x.y>`, subject `Hi`, message id `<m1@x.y>`,
    /// `sent_at_ms` 1_700_000_000_000, empty cc/bcc/reply-to.
    fn complete_header() -> MessageHeader {
        MessageHeader {
            list_id: "list".into(),
            element_id: "m1".into(),
            received_at_ms: 1_700_000_000_000,
            sent_at_ms: 1_700_000_000_000,
            subject: "Hi".into(),
            from: Address {
                name: None,
                address: "alice@x.y".into(),
            },
            to: vec![Address {
                name: Some("Bob".into()),
                address: "bob@x.y".into(),
            }],
            cc: vec![],
            bcc: vec![],
            reply_to: vec![],
            unread: false,
            message_id: Some("<m1@x.y>".into()),
            in_reply_to: None,
            references: vec![],
            envelope_complete: true,
        }
    }

    /// A body with an HTML alternative and one attachment `doc.pdf`.
    fn sample_content() -> MessageContent {
        MessageContent {
            summary: crate::domain::MessageSummary {
                list_id: "list".into(),
                element_id: "m1".into(),
                received_at_ms: 1_700_000_000_000,
                subject: "Report".into(),
                unread: true,
            },
            from: complete_header().from,
            to: vec![Address {
                name: Some("Bob".into()),
                address: "bob@x.y".into(),
            }],
            cc: vec![],
            bcc: vec![],
            reply_to: vec![],
            sent_at_ms: 1_700_000_000_000,
            subject: "Report".into(),
            message_id: Some("<m1@x.y>".into()),
            in_reply_to: None,
            references: vec![],
            body_html: Some("<p>Hello</p>".into()),
            body_text: Some("Hello".into()),
            attachments: vec![Attachment {
                name: "doc.pdf".into(),
                mime_type: "application/pdf".into(),
                data: b"%PDF-1.4".to_vec(),
                cid: None,
            }],
        }
    }

    #[test]
    fn envelope_renders_nils_and_addresses() {
        let header = complete_header();
        let rendered = envelope(&header);
        assert!(rendered.starts_with("(\"Tue, 14 Nov 2023 22:13:20 +0000\""));
        assert!(rendered.contains("((NIL NIL \"alice\" \"x.y\"))"));
        assert!(rendered.contains("((\"Bob\" NIL \"bob\" \"x.y\"))"));
        assert!(rendered.contains("\"Hi\""));
        assert!(rendered.ends_with("NIL \"<m1@x.y>\")"));
        // Empty cc/bcc render as the all-NIL group the format pins.
        assert!(rendered.contains("(NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL)"));
    }

    #[test]
    fn bodystructure_matches_the_mime_renderer_shape() {
        // Content with an html body plus one attachment named "doc.pdf".
        let content = sample_content();
        let rendered = bodystructure(&content);
        assert!(rendered.starts_with("(\"mixed\""));
        assert!(rendered.contains("(\"alternative\""));
        assert!(rendered.contains("(\"application\" \"pdf\" (\"NAME\" \"doc.pdf\")"));

        // A single-part plain body renders as ("TEXT" "PLAIN" ...).
        let mut text_only = sample_content();
        text_only.body_html = None;
        text_only.attachments.clear();
        assert_eq!(
            bodystructure(&text_only),
            "(\"TEXT\" \"PLAIN\" (\"CHARSET\" \"UTF-8\") NIL NIL \"8BIT\" 5 1)"
        );
    }

    #[test]
    fn internal_date_and_flags_are_fixed_format() {
        assert_eq!(
            internal_date(1_700_000_000_000),
            "\"14 Nov 2023 22:13:20 +0000\""
        );
        assert_eq!(flags(true), "");
        assert_eq!(flags(false), "\\Seen");
        assert_eq!(special_use(&FolderKind::Inbox), "\\Inbox");
    }

    #[test]
    fn envelope_renders_nil_date_and_bare_addresses() {
        let mut header = complete_header();
        header.sent_at_ms = 0;
        header.from = Address {
            name: None,
            address: "bare".into(),
        };
        header.to.clear();
        let rendered = envelope(&header);
        assert!(rendered.starts_with("(NIL \"Hi\""));
        // A bare address without `@` keeps the whole value in the
        // mailbox slot with a NIL host.
        assert!(rendered.contains("((NIL NIL \"bare\" NIL))"));
        // From, sender, and the defaulted reply-to all carry the from
        // address.
        assert_eq!(rendered.matches("((NIL NIL \"bare\" NIL))").count(), 3);
    }

    #[test]
    fn envelope_uses_explicit_reply_to_when_present() {
        let mut header = complete_header();
        header.reply_to = vec![Address {
            name: None,
            address: "support@x.y".into(),
        }];
        let rendered = envelope(&header);
        assert!(rendered.contains("((NIL NIL \"support\" \"x.y\"))"));
        // Only from and sender fall back to the from address.
        assert_eq!(rendered.matches("((NIL NIL \"alice\" \"x.y\"))").count(), 2);
    }

    #[test]
    fn non_ascii_subject_renders_as_a_framed_literal() {
        let mut header = complete_header();
        header.subject = "Caffè".into();
        let rendered = envelope(&header);
        assert!(rendered.contains(" {6}\r\nCaffè "));
    }

    #[test]
    fn special_use_covers_every_folder_kind() {
        assert_eq!(special_use(&FolderKind::Sent), "\\Sent");
        assert_eq!(special_use(&FolderKind::Drafts), "\\Drafts");
        assert_eq!(special_use(&FolderKind::Trash), "\\Trash");
        assert_eq!(special_use(&FolderKind::Junk), "\\Junk");
        assert_eq!(special_use(&FolderKind::Archive), "\\Archive");
        assert_eq!(special_use(&FolderKind::Custom), "");
    }

    #[test]
    fn internal_date_clamps_pre_epoch_and_overflow_to_epoch() {
        assert_eq!(internal_date(0), "\"01 Jan 1970 00:00:00 +0000\"");
        assert_eq!(internal_date(-86_400_000), "\"01 Jan 1970 00:00:00 +0000\"");
        assert_eq!(internal_date(i64::MAX), "\"01 Jan 1970 00:00:00 +0000\"");
    }

    #[test]
    fn attachments_without_extension_fall_back_to_octet_stream() {
        let mut content = sample_content();
        content.attachments[0].name = "data".into();
        assert!(bodystructure(&content)
            .contains("(\"application\" \"octet-stream\" (\"NAME\" \"data\")"));
    }

    #[test]
    fn bodystructure_derives_plain_text_from_html_like_the_mime_renderer() {
        let mut content = sample_content();
        content.body_text = None;
        let rendered = bodystructure(&content);
        assert!(rendered.contains("(\"TEXT\" \"PLAIN\" (\"CHARSET\" \"UTF-8\") NIL NIL \"8BIT\""));
        // The derived plain part is not empty: the MIME renderer embeds
        // the HTML flattened to text, and the reported sizes follow it.
        assert!(!rendered.contains("\"8BIT\" 0 0)"));
    }
}
