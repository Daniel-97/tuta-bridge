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
use crate::adapters::mime::{
    boundary_seed, deterministic_boundary, sanitize_cid, sanitize_media_type,
};
use crate::domain::{Address, Attachment, FolderKind, MessageContent, MessageHeader};

/// The three-letter month names an INTERNALDATE carries, `Jan..Dec`.
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

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
/// `"14-Nov-2023 22:13:20 +0000"`.
///
/// RFC 3501 date-time: dashes between day, month, and year, spaces
/// elsewhere, single-digit days space-padded (Python `imaplib`'s
/// `Internaldate2tuple` expects exactly this shape). A timestamp at or
/// before the epoch — or one the calendar cannot represent — clamps to
/// the epoch itself: pre-epoch dates are never fabricated.
pub fn internal_date(ms: i64) -> String {
    let dt = OffsetDateTime::from_unix_timestamp_nanos(ms.max(0) as i128 * 1_000_000)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH);
    format!(
        "\"{:2}-{}-{:04} {:02}:{:02}:{:02} +0000\"",
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

/// The SPECIAL-USE attribute for a folder kind.
///
/// INBOX is identified by its name, not by an attribute, and custom
/// folders carry none — both render as an empty string.
pub fn special_use(kind: &FolderKind) -> &'static str {
    match kind {
        FolderKind::Inbox => "",
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

/// Render an address list: `(address…)` when present, the bare token
/// `NIL` when empty (RFC 3501: `env-cc = "(" 1*address ")" / nil`).
fn address_list(addrs: &[Address]) -> String {
    if addrs.is_empty() {
        return "NIL".to_string();
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

/// How one leaf part travels in the rendered message: its
/// Content-Transfer-Encoding, the octets of its encoded body, and that
/// body's line count — the three BODYSTRUCTURE fields that describe
/// bytes rather than content.
struct Leaf {
    encoding: String,
    octets: usize,
    lines: usize,
}

impl Leaf {
    /// What a part would report if nothing were known about its
    /// rendering: the content's own length, unencoded.
    fn unrendered(body: &[u8]) -> Self {
        Self {
            encoding: "8BIT".to_string(),
            octets: body.len(),
            lines: line_count(body),
        }
    }
}

/// The lines of an encoded body: every line break, plus a last line
/// that has none.
fn line_count(body: &[u8]) -> usize {
    let breaks = body.iter().filter(|&&byte| byte == b'\n').count();
    breaks + usize::from(body.last().is_some_and(|&byte| byte != b'\n'))
}

/// Measure every leaf part of the rendered message, in document order.
///
/// The renderer chooses each part's transfer encoding from its content
/// (7bit, quoted-printable, or base64), so the only reliable source for
/// the encoding and the encoded size is the bytes it produced. `None`
/// when the bytes do not parse as a message.
fn rendered_leaves(rendered: &[u8]) -> Option<Vec<Leaf>> {
    fn collect(part: mail_parser::MessagePart<'_>, leaves: &mut Vec<Leaf>) {
        if part.is_multipart() {
            for child in part.children() {
                collect(child, leaves);
            }
            return;
        }
        let body = part.raw_body();
        leaves.push(Leaf {
            encoding: part.content_transfer_encoding().map_or_else(
                || "7BIT".to_string(),
                |encoding| encoding.to_ascii_uppercase(),
            ),
            octets: body.len(),
            lines: line_count(body),
        });
    }

    let message = mail_parser::MessageParser::default().parse(rendered)?;
    let mut leaves = Vec::new();
    collect(message.root_part(), &mut leaves);
    Some(leaves)
}

/// One text part:
/// `("TEXT" <subtype> ("CHARSET" "UTF-8") NIL NIL <encoding> <octets> <lines>)`.
fn text_part(subtype: &str, leaf: &Leaf) -> String {
    format!(
        "(\"TEXT\" \"{subtype}\" (\"CHARSET\" \"UTF-8\") NIL NIL {} {} {})",
        qs(&leaf.encoding),
        leaf.octets,
        leaf.lines
    )
}

/// One attachment part:
/// `(<MAJOR> <SUBTYPE> ("NAME" <name>) NIL NIL <encoding> <octets> [<lines>] NIL NIL NIL NIL)`.
///
/// The media type and subtype come from the same `sanitize_media_type`
/// the MIME renderer writes, upper-cased; invalid or missing values
/// fall back to `("APPLICATION" "OCTET-STREAM")`. A `text/*` attachment
/// is a `body-type-text` and carries its line count after the size
/// (RFC 3501 §9). `message/rfc822` would have to carry the envelope
/// and structure of the attached message, and `multipart/*` its parts;
/// the bridge treats an attachment as opaque bytes, so both are
/// reported as `APPLICATION/OCTET-STREAM` — a form every parser accepts
/// — while the part header in the rendered message keeps the original
/// type. The four trailing NILs complete the `body-ext-1part` fields.
fn attachment_part(attachment: &Attachment, leaf: &Leaf) -> String {
    let opaque = || ("APPLICATION".to_string(), "OCTET-STREAM".to_string());
    let (major, subtype) = match sanitize_media_type(&attachment.mime_type).split_once('/') {
        Some((major, subtype)) => {
            let (major, subtype) = (major.to_ascii_uppercase(), subtype.to_ascii_uppercase());
            if major == "MULTIPART" || (major == "MESSAGE" && subtype == "RFC822") {
                opaque()
            } else {
                (major, subtype)
            }
        }
        None => opaque(),
    };
    let lines = if major == "TEXT" {
        format!(" {}", leaf.lines)
    } else {
        String::new()
    };
    format!(
        "({} {} (\"NAME\" {}) NIL NIL {} {}{lines} NIL NIL NIL NIL)",
        qs(&major),
        qs(&subtype),
        qs(&attachment.name),
        qs(&leaf.encoding),
        leaf.octets
    )
}

/// One multipart body. RFC 3501 `body-type-mpart = 1*body SP
/// media-subtype SP body-fld-param`: the parts come first, then the
/// subtype, then the `("BOUNDARY" …)` parameter.
fn multipart(parts: &[String], subtype: &str, boundary: &str) -> String {
    format!(
        "({} \"{subtype}\" (\"BOUNDARY\" {}))",
        parts.join(" "),
        qs(boundary)
    )
}

/// Render the BODYSTRUCTURE fetch item, replicating the MIME tree
/// `build_message` actually writes:
///
/// * the root is always `multipart/mixed`;
/// * its first part is `multipart/alternative( text/plain
///   [multipart/related( text/html + inline attachments )] )`;
/// * inline attachments (those with a sanitize-able cid) sit inside
///   `related` when HTML exists and at the root otherwise; regular
///   attachments follow at the root.
///
/// Boundaries come from [`deterministic_boundary`] with the same seed
/// `build_message` derives, so the structure names the exact
/// boundaries the rendered MIME bytes carry.
///
/// `rendered` is the message as the renderer wrote it for `content`:
/// each leaf's transfer encoding, size, and line count are measured
/// from it, so they describe the bytes a client actually downloads.
/// Bytes that do not hold exactly the expected parts fall back to
/// describing the unencoded content.
pub fn bodystructure(content: &MessageContent, rendered: &[u8]) -> String {
    let seed = boundary_seed(content);

    // Partition attachments exactly like `build_message`: a
    // sanitize-able cid makes an attachment inline.
    let mut inline: Vec<&Attachment> = Vec::new();
    let mut regular: Vec<&Attachment> = Vec::new();
    for attachment in &content.attachments {
        match attachment.cid.as_deref().and_then(sanitize_cid) {
            Some(_) => inline.push(attachment),
            None => regular.push(attachment),
        }
    }

    // The leaves in the order `build_message` writes them: the plain
    // text, the HTML, the inline attachments, the regular ones.
    let html_parts = usize::from(content.body_html.is_some());
    let expected = 1 + html_parts + content.attachments.len();
    let mut measured = rendered_leaves(rendered)
        .filter(|leaves| leaves.len() == expected)
        .map(Vec::into_iter);
    let mut leaf = |body: &[u8]| {
        measured
            .as_mut()
            .and_then(Iterator::next)
            .unwrap_or_else(|| Leaf::unrendered(body))
    };

    let mut alternative_parts = vec![text_part("PLAIN", &leaf(plain_text(content).as_bytes()))];

    // Without HTML there is no related part, so inline attachments are
    // emitted at the root instead of dropped.
    let mut root_inline: Vec<&Attachment> = Vec::new();
    match content.body_html.as_deref() {
        Some(html) => {
            let mut related_parts = vec![text_part("HTML", &leaf(html.as_bytes()))];
            for attachment in inline {
                related_parts.push(attachment_part(attachment, &leaf(&attachment.data)));
            }
            alternative_parts.push(multipart(
                &related_parts,
                "RELATED",
                &deterministic_boundary(&seed, "related"),
            ));
        }
        None => root_inline = inline,
    }
    let alternative = multipart(
        &alternative_parts,
        "ALTERNATIVE",
        &deterministic_boundary(&seed, "alt"),
    );

    let mut root_parts = vec![alternative];
    for attachment in root_inline.into_iter().chain(regular) {
        root_parts.push(attachment_part(attachment, &leaf(&attachment.data)));
    }
    multipart(
        &root_parts,
        "MIXED",
        &deterministic_boundary(&seed, "mixed"),
    )
}

/// One token of a rendered structure string: a nested list, or
/// anything else kept verbatim (a quoted string, `NIL`, a number, or
/// a literal with its `{n}\r\n` framing).
enum Node<'a> {
    List(Vec<Node<'a>>),
    Token(&'a str),
}

/// Parse the list that starts at `at` (just past its `(`), returning
/// its members and the offset past its `)`.
fn parse_list(structure: &str, mut at: usize) -> Option<(Vec<Node<'_>>, usize)> {
    let bytes = structure.as_bytes();
    let mut nodes = Vec::new();
    loop {
        match *bytes.get(at)? {
            b' ' => at += 1,
            b')' => return Some((nodes, at + 1)),
            b'(' => {
                let (inner, next) = parse_list(structure, at + 1)?;
                nodes.push(Node::List(inner));
                at = next;
            }
            b'"' => {
                // `qs` never escapes: a quoted string ends at the
                // next quote.
                let end = at + 1 + structure.get(at + 1..)?.find('"')? + 1;
                nodes.push(Node::Token(&structure[at..end]));
                at = end;
            }
            b'{' => {
                let close = at + structure.get(at..)?.find('}')?;
                let count: usize = structure.get(at + 1..close)?.parse().ok()?;
                let end = close.checked_add(3)?.checked_add(count)?;
                nodes.push(Node::Token(structure.get(at..end)?));
                at = end;
            }
            _ => {
                let end = at
                    + structure
                        .get(at..)?
                        .find([' ', ')'])
                        .unwrap_or(structure.len() - at);
                nodes.push(Node::Token(&structure[at..end]));
                at = end;
            }
        }
    }
}

/// Write one body without its extension data.
fn write_basic(nodes: &[Node<'_>], out: &mut String) {
    // A multipart is its parts and its subtype; a single part is its
    // seven basic fields, plus the line count of a text part.
    let keep = match nodes.first() {
        Some(Node::List(_)) => {
            nodes
                .iter()
                .take_while(|node| matches!(node, Node::List(_)))
                .count()
                + 1
        }
        Some(Node::Token(major)) if major.eq_ignore_ascii_case("\"TEXT\"") => 8,
        _ => 7,
    };
    let multipart = matches!(nodes.first(), Some(Node::List(_)));
    out.push('(');
    for (index, node) in nodes.iter().take(keep).enumerate() {
        if index > 0 {
            out.push(' ');
        }
        match node {
            // Nested lists of a multipart are bodies; those of a
            // single part (its parameters) are copied as they are.
            Node::List(inner) if multipart => write_basic(inner, out),
            other => write_verbatim(other, out),
        }
    }
    out.push(')');
}

fn write_verbatim(node: &Node<'_>, out: &mut String) {
    match node {
        Node::Token(token) => out.push_str(token),
        Node::List(inner) => {
            out.push('(');
            for (index, node) in inner.iter().enumerate() {
                if index > 0 {
                    out.push(' ');
                }
                write_verbatim(node, out);
            }
            out.push(')');
        }
    }
}

/// The `BODY` fetch item for a stored BODYSTRUCTURE string: the same
/// structure without extension data (RFC 3501 §7.4.2) — no multipart
/// parameters, no MD5/disposition/language/location fields. A string
/// that is not a structure this module wrote is returned unchanged.
pub fn body_basic(structure: &str) -> String {
    let parsed = structure
        .strip_prefix('(')
        .and_then(|_| parse_list(structure, 1))
        .filter(|(_, end)| *end == structure.len());
    match parsed {
        Some((nodes, _)) => {
            let mut out = String::new();
            write_basic(&nodes, &mut out);
            out
        }
        None => structure.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::mime::deterministic_boundary;
    use crate::adapters::mime::MimeRenderer;
    use crate::ports::renderer::MessageRenderer;

    /// The structure of `content` as the enricher computes it: from
    /// the bytes the real renderer writes.
    fn bodystructure(content: &MessageContent) -> String {
        let rendered = MimeRenderer.render(content).unwrap();
        super::bodystructure(content, &rendered)
    }
    use crate::domain::MessageSummary;

    /// The plan's ENVELOPE fixture: from "Alice <alice@x.y>", to
    /// "Bob <bob@x.y>", subject "Hi", message id "<m1@x.y>",
    /// `sent_at_ms` 1_700_000_000_000, empty cc/bcc, no in-reply-to.
    fn complete_header() -> MessageHeader {
        MessageHeader {
            list_id: "list".into(),
            element_id: "m1".into(),
            received_at_ms: 1_700_000_000_000,
            sent_at_ms: 1_700_000_000_000,
            subject: "Hi".into(),
            from: Address {
                name: Some("Alice".into()),
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

    /// A body with an HTML alternative and the given attachments.
    fn content_with(attachments: Vec<Attachment>) -> MessageContent {
        MessageContent {
            summary: MessageSummary {
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
            attachments,
        }
    }

    fn content_with_html_and_attachment_named(name: &str) -> MessageContent {
        content_with(vec![pdf_attachment(name)])
    }

    fn pdf_attachment(name: &str) -> Attachment {
        Attachment {
            name: name.into(),
            mime_type: "application/pdf".into(),
            data: b"%PDF-1.4".to_vec(),
            cid: None,
        }
    }

    #[test]
    fn envelope_renders_nils_and_addresses() {
        let header = complete_header();
        let rendered = envelope(&header);
        // Pin the COMPLETE byte-exact string; empty cc/bcc and a
        // missing in-reply-to are bare NIL tokens (RFC 3501
        // env-cc/env-bcc = "(" 1*address ")" / nil — never a
        // parenthesized group of NILs), and sender/reply-to default to
        // the from value.
        assert_eq!(
            rendered,
            "(\"Tue, 14 Nov 2023 22:13:20 +0000\" \"Hi\" \
              ((\"Alice\" NIL \"alice\" \"x.y\")) \
              ((\"Alice\" NIL \"alice\" \"x.y\")) \
              ((\"Alice\" NIL \"alice\" \"x.y\")) \
              ((\"Bob\" NIL \"bob\" \"x.y\")) \
              NIL NIL NIL \"<m1@x.y>\")"
        );
    }

    #[test]
    fn bodystructure_mirrors_the_mime_renderer_tree() {
        // The renderer ALWAYS writes multipart/mixed(
        // multipart/alternative( text/plain [multipart/related(
        // text/html + inline attachments)] ) + regular attachments )
        // with deterministic boundaries. RFC 3501 body-type-mpart =
        // 1*body SP media-subtype SP body-fld-param: the parts come
        // first, then the subtype, then ("BOUNDARY" <boundary>).
        let rendered = bodystructure(&content_with_html_and_attachment_named("doc.pdf"));
        // Three opening parens: the mixed root, the alternative inside
        // it, and the text part inside that. (The plan's snippet shows
        // two, but its own root notation `(<parts> "MIXED" …)` and the
        // pinned tree mixed(alternative(plain,…)) both require three —
        // with two the returned string would lack the root's paren and
        // would not be a complete wire body.)
        assert!(rendered.starts_with("(((\"TEXT\" \"PLAIN\""));
        assert!(rendered.contains("\"ALTERNATIVE\" (\"BOUNDARY\""));
        assert!(rendered.contains("\"RELATED\" (\"BOUNDARY\""));
        assert!(rendered.contains("\"MIXED\" (\"BOUNDARY\""));
        assert!(rendered.contains("(\"APPLICATION\" \"PDF\" (\"NAME\" \"doc.pdf\")"));
    }

    #[test]
    fn internal_date_and_flags_are_fixed_format() {
        assert_eq!(
            internal_date(1_700_000_000_000),
            "\"14-Nov-2023 22:13:20 +0000\""
        );
        // RFC 3501 date-day-fixed: single-digit days are SPACE-padded,
        // not zero-padded (2023-11-04 00:00:00 UTC).
        assert_eq!(
            internal_date(1_699_056_000_000),
            "\" 4-Nov-2023 00:00:00 +0000\""
        );
        assert_eq!(flags(true), "");
        assert_eq!(flags(false), "\\Seen");
        assert_eq!(
            special_use(&FolderKind::Inbox),
            "",
            "INBOX needs no special-use attribute"
        );
        assert_eq!(special_use(&FolderKind::Archive), "\\Archive");
    }

    #[test]
    fn inline_attachments_render_inside_related_or_at_the_root() {
        // A sanitize-able cid makes the attachment inline: with HTML it
        // nests inside multipart/related after the text/html part;
        // without HTML it sits at the mixed root after the
        // alternative — exactly where `build_message` writes it.
        let inline = Attachment {
            name: "logo.png".into(),
            mime_type: "image/png".into(),
            data: vec![1, 2, 3],
            cid: Some("img1".into()),
        };
        let with_html = content_with(vec![inline.clone(), pdf_attachment("doc.pdf")]);
        let rendered = bodystructure(&with_html);
        let html_at = rendered
            .find("(\"TEXT\" \"HTML\"")
            .expect("html part renders");
        let image_at = rendered
            .find("(\"IMAGE\" \"PNG\" (\"NAME\" \"logo.png\")")
            .expect("inline part renders inside related");
        let related_at = rendered
            .find("\"RELATED\" (\"BOUNDARY\"")
            .expect("related group renders");
        let alt_at = rendered
            .find("\"ALTERNATIVE\" (\"BOUNDARY\"")
            .expect("alternative group renders");
        let pdf_at = rendered
            .find("(\"APPLICATION\" \"PDF\" (\"NAME\" \"doc.pdf\")")
            .expect("regular attachment renders");
        let mixed_at = rendered
            .find("\"MIXED\" (\"BOUNDARY\"")
            .expect("mixed root renders");
        assert!(html_at < image_at, "inline part follows the html part");
        assert!(image_at < related_at, "inline part sits inside related");
        assert!(
            related_at < alt_at,
            "related closes before the alternative marker"
        );
        assert!(alt_at < pdf_at, "regular attachments sit at the root");
        assert!(pdf_at < mixed_at, "root parts come before the mixed marker");

        // Without HTML the inline attachment moves to the root, right
        // after the alternative group, and no related part exists.
        let mut text_only = with_html.clone();
        text_only.body_html = None;
        text_only.attachments = vec![inline];
        let rendered = bodystructure(&text_only);
        assert!(rendered.contains(")) (\"IMAGE\" \"PNG\" (\"NAME\" \"logo.png\")"));
        assert!(!rendered.contains("\"RELATED\""));
    }

    #[test]
    fn bodystructure_is_mixed_alternative_even_for_plain_text_only() {
        // Even a text-only body is written as the full
        // mixed(alternative(text/plain)) tree, with the same
        // seed-derived boundaries `build_message` uses.
        let mut text_only = content_with_html_and_attachment_named("doc.pdf");
        text_only.body_html = None;
        text_only.attachments.clear();
        let rendered = bodystructure(&text_only);
        let alt = deterministic_boundary("<m1@x.y>", "alt");
        let mixed = deterministic_boundary("<m1@x.y>", "mixed");
        assert_eq!(
            rendered,
            format!(
                "(({plain} \"ALTERNATIVE\" (\"BOUNDARY\" \"{alt}\")) \
                  \"MIXED\" (\"BOUNDARY\" \"{mixed}\"))",
                plain = "(\"TEXT\" \"PLAIN\" (\"CHARSET\" \"UTF-8\") NIL NIL \"7BIT\" 5 1)",
            )
        );
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
        // An empty `to` renders as a bare NIL, like cc/bcc.
        assert!(rendered.ends_with(" NIL NIL NIL NIL \"<m1@x.y>\")"));
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
        assert_eq!(
            rendered
                .matches("((\"Alice\" NIL \"alice\" \"x.y\"))")
                .count(),
            2
        );
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
        assert_eq!(special_use(&FolderKind::Inbox), "");
        assert_eq!(special_use(&FolderKind::Sent), "\\Sent");
        assert_eq!(special_use(&FolderKind::Drafts), "\\Drafts");
        assert_eq!(special_use(&FolderKind::Trash), "\\Trash");
        assert_eq!(special_use(&FolderKind::Junk), "\\Junk");
        assert_eq!(special_use(&FolderKind::Archive), "\\Archive");
        assert_eq!(special_use(&FolderKind::Custom), "");
    }

    #[test]
    fn internal_date_clamps_pre_epoch_and_overflow_to_epoch() {
        assert_eq!(internal_date(0), "\" 1-Jan-1970 00:00:00 +0000\"");
        assert_eq!(internal_date(-86_400_000), "\" 1-Jan-1970 00:00:00 +0000\"");
        assert_eq!(internal_date(i64::MAX), "\" 1-Jan-1970 00:00:00 +0000\"");
    }

    #[test]
    fn invalid_media_types_fall_back_to_octet_stream() {
        let mut content = content_with_html_and_attachment_named("data");
        content.attachments[0].mime_type = "not a media type".into();
        assert!(bodystructure(&content)
            .contains("(\"APPLICATION\" \"OCTET-STREAM\" (\"NAME\" \"data\")"));

        // Sanitized media types are upper-cased.
        content.attachments[0].mime_type = "application/PDF".into();
        assert!(bodystructure(&content).contains("(\"APPLICATION\" \"PDF\" (\"NAME\" \"data\")"));
    }

    #[test]
    fn bodystructure_derives_plain_text_from_html_like_the_mime_renderer() {
        let mut content = content_with_html_and_attachment_named("doc.pdf");
        content.body_text = None;
        let rendered = bodystructure(&content);
        assert!(rendered.contains("(\"TEXT\" \"PLAIN\" (\"CHARSET\" \"UTF-8\") NIL NIL \"7BIT\""));
        // The derived plain part is not empty: the MIME renderer embeds
        // the HTML flattened to text, and the reported sizes follow it.
        assert!(!rendered.contains("\"7BIT\" 0 0)"));
    }
    #[test]
    fn leaf_sizes_and_encodings_are_measured_from_the_rendered_bytes() {
        // Non-ASCII text makes the renderer pick a real transfer
        // encoding, and attachments travel base64-encoded: the
        // structure reports what is on the wire, not the raw lengths.
        let mut content = content_with(vec![pdf_attachment("doc.pdf")]);
        content.body_text = Some("Caffè\r\ncon panna\r\n".into());
        content.body_html = Some("<p>Caffè</p>".into());
        let rendered = MimeRenderer.render(&content).unwrap();
        let structure = super::bodystructure(&content, &rendered);

        let message = mail_parser::MessageParser::default()
            .parse(&rendered)
            .unwrap();
        let leaves: Vec<_> = message
            .parts()
            .filter(|part| !part.is_multipart())
            .collect();
        assert_eq!(leaves.len(), 3);
        for (leaf, major) in leaves.iter().zip(["TEXT", "TEXT", "APPLICATION"]) {
            let encoding = leaf
                .content_transfer_encoding()
                .unwrap()
                .to_ascii_uppercase();
            assert_ne!(encoding, "8BIT");
            let expected = format!(" NIL NIL \"{encoding}\" {}", leaf.raw_body().len());
            assert!(
                structure.contains(&expected),
                "{major} leaf must report {expected:?} in {structure}"
            );
        }
        // "%PDF-1.4" is 8 bytes: 12 base64 octets and the line break
        // the encoder ends them with.
        assert!(structure.contains(
            "(\"APPLICATION\" \"PDF\" (\"NAME\" \"doc.pdf\") NIL NIL \"BASE64\" 14 NIL NIL NIL NIL)"
        ));
        // The two-line text reports two lines whatever its encoding.
        let plain = &leaves[0];
        assert!(structure.contains(&format!(
            "{} {})",
            plain.raw_body().len(),
            line_count(plain.raw_body())
        )));
    }

    #[test]
    fn text_attachments_carry_a_line_count_and_messages_are_opaque() {
        let attachment = |name: &str, mime_type: &str, data: &[u8]| Attachment {
            name: name.into(),
            mime_type: mime_type.into(),
            data: data.to_vec(),
            cid: None,
        };
        let content = content_with(vec![
            attachment("notes.txt", "text/plain", b"one\r\ntwo\r\nthree"),
            attachment("mail.eml", "message/rfc822", b"Subject: x\r\n\r\nbody\r\n"),
            attachment("odd", "multipart/mixed", b"--x--"),
        ]);
        let structure = bodystructure(&content);

        // body-type-text: the size is followed by a line count before
        // the extension fields (RFC 3501 §9).
        let text = structure
            .split("(\"TEXT\" \"PLAIN\" (\"NAME\" \"notes.txt\") NIL NIL ")
            .nth(1)
            .expect("the text attachment renders as a text part");
        let fields: Vec<&str> = text.split(')').next().unwrap().split(' ').collect();
        assert_eq!(
            fields.len(),
            7,
            "encoding, size, lines, four NILs: {fields:?}"
        );
        assert!(fields[1].parse::<usize>().is_ok());
        assert_eq!(fields[2], "3");
        assert_eq!(&fields[3..], ["NIL"; 4]);

        // An attached message or multipart is described as opaque
        // bytes: a body-type-msg would need the envelope and structure
        // of the attached message.
        assert!(structure.contains("(\"APPLICATION\" \"OCTET-STREAM\" (\"NAME\" \"mail.eml\")"));
        assert!(structure.contains("(\"APPLICATION\" \"OCTET-STREAM\" (\"NAME\" \"odd\")"));
        assert!(!structure.contains("\"MESSAGE\""));
        assert!(!structure.contains("\"MULTIPART\""));
    }

    #[test]
    fn unparseable_bytes_fall_back_to_the_unencoded_content() {
        let content = content_with(vec![pdf_attachment("doc.pdf")]);
        let structure = super::bodystructure(&content, b"0123456789");
        assert!(
            structure.contains("(\"TEXT\" \"PLAIN\" (\"CHARSET\" \"UTF-8\") NIL NIL \"8BIT\" 5 1)")
        );
        assert!(structure.contains("(\"NAME\" \"doc.pdf\") NIL NIL \"8BIT\" 8 NIL"));
    }

    #[test]
    fn body_basic_drops_extension_data_only() {
        let mut content = content_with(vec![
            pdf_attachment("doc.pdf"),
            Attachment {
                name: "Caffè.txt".into(),
                mime_type: "text/plain".into(),
                data: b"x".to_vec(),
                cid: None,
            },
        ]);
        content.body_html = None;
        let full = bodystructure(&content);
        let basic = body_basic(&full);
        // No multipart parameters, no trailing extension NILs; the
        // parts, their parameters, and a literal name are untouched.
        assert_eq!(
            basic,
            "(((\"TEXT\" \"PLAIN\" (\"CHARSET\" \"UTF-8\") NIL NIL \"7BIT\" 5 1) \"ALTERNATIVE\") \
              (\"APPLICATION\" \"PDF\" (\"NAME\" \"doc.pdf\") NIL NIL \"BASE64\" 14) \
              (\"TEXT\" \"PLAIN\" (\"NAME\" {10}\r\nCaffè.txt) NIL NIL \"7BIT\" 1 1) \
              \"MIXED\")"
        );
        assert!(!basic.contains("BOUNDARY"));
        assert!(full.contains("BOUNDARY"));

        // Anything that is not one complete list is left alone.
        for odd in ["", "NIL", "(\"TEXT\"", "(\"A\") trailing", "({5}\r\nab)"] {
            assert_eq!(body_basic(odd), odd);
        }
    }
}
