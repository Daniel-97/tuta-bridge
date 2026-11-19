//! Deterministic renderer of [`MessageContent`] into RFC 5322 MIME bytes.
//!
//! The renderer is pure: it never touches the network or the SDK session, and
//! it never logs message contents. The same input always produces the same
//! bytes because every MIME boundary is derived from a stable seed rather than
//! being generated randomly.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use mail_builder::headers::address::Address as MbAddress;
use mail_builder::headers::content_type::ContentType;
use mail_builder::headers::raw::Raw;
use mail_builder::headers::text::Text;
use mail_builder::mime::{BodyPart, MimePart};
use mail_builder::MessageBuilder;
use time::format_description::well_known::Rfc2822;
use time::OffsetDateTime;

use crate::domain::{Address, Attachment, Error, MessageContent, Result};
use crate::ports::renderer::MessageRenderer;

/// Renders [`MessageContent`] into RFC 5322 MIME bytes deterministically.
pub struct MimeRenderer;

/// Derive a stable MIME boundary from a seed and a label.
pub fn deterministic_boundary(seed: &str, label: &str) -> String {
    let hash = tutasdk::crypto::sha256(seed.as_bytes());
    format!(
        "{BOUNDARY_PREFIX}{}_{}",
        label,
        URL_SAFE_NO_PAD.encode(&hash[..9])
    )
}

/// Replace CR/LF so a value can never inject a header line.
fn sanitize(value: &str) -> String {
    value.replace(['\r', '\n'], " ")
}

/// Return true when `s` is a valid RFC 2045 token: non-empty and made only of
/// characters that are not separators, whitespace, or control bytes.
fn is_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

/// Validate a MIME media type as `type/subtype` built from RFC tokens.
///
/// Anything else — including values that carry a CR/LF or a separator and could
/// inject a header line — falls back to `application/octet-stream`.
///
/// Crate-shared: the IMAP BODYSTRUCTURE renderer calls this so its
/// reported media types always match the headers `build_message` writes.
pub(crate) fn sanitize_media_type(mime: &str) -> String {
    let (ty, sub) = match mime.split_once('/') {
        Some((t, s)) if !t.is_empty() && !s.is_empty() && !s.contains('/') => (t, s),
        _ => return "application/octet-stream".to_string(),
    };
    if is_token(ty) && is_token(sub) {
        mime.to_string()
    } else {
        "application/octet-stream".to_string()
    }
}

/// Validate a Content-ID, stripping a single pair of surrounding angle brackets.
///
/// Returns `None` when the value contains CR/LF, whitespace, or `<`/`>` and so
/// could inject a header line; the caller then treats it as a normal attachment.
///
/// Crate-shared: the IMAP BODYSTRUCTURE renderer calls this to split
/// inline from regular attachments exactly like `build_message` does.
pub(crate) fn sanitize_cid(cid: &str) -> Option<String> {
    let trimmed = cid.trim();
    let inner = if trimmed.len() >= 2 && trimmed.starts_with('<') && trimmed.ends_with('>') {
        &trimmed[1..trimmed.len() - 1]
    } else {
        trimmed
    };
    if inner.is_empty() {
        return None;
    }
    if inner
        .chars()
        .any(|c| c == '\r' || c == '\n' || c == '<' || c == '>' || c.is_whitespace())
    {
        return None;
    }
    Some(inner.to_string())
}

/// Build an inline (`Content-Disposition: inline` + `Content-ID`) MIME part.
fn inline_part(attachment: &Attachment, cid: &str) -> MimePart<'static> {
    MimePart::new(
        ContentType::new(sanitize_media_type(&attachment.mime_type)),
        BodyPart::Binary(attachment.data.clone().into()),
    )
    .inline()
    .cid(cid.to_string())
}

fn convert_address(addr: &Address) -> MbAddress<'static> {
    MbAddress::new_address(addr.name.as_deref().map(sanitize), sanitize(&addr.address))
}

fn convert_list(addrs: &[Address]) -> MbAddress<'static> {
    MbAddress::new_list(addrs.iter().map(convert_address).collect())
}

/// Prefix shared by every boundary this renderer emits.
const BOUNDARY_PREFIX: &str = "=_tuta_bridge_";

/// Labels of the three multipart levels `build_message` writes.
const BOUNDARY_LABELS: [&str; 3] = ["mixed", "alt", "related"];

/// The plain-text alternative: the stored text body, the HTML body
/// flattened to text, or nothing.
fn plain_text_of(content: &MessageContent) -> String {
    content
        .body_text
        .clone()
        .or_else(|| {
            content
                .body_html
                .as_ref()
                .map(|html| mail_parser::html_to_text(html))
        })
        .unwrap_or_default()
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

/// True when `needle` occurs in any byte the renderer may write verbatim.
fn content_contains(content: &MessageContent, plain_text: &str, needle: &str) -> bool {
    plain_text.contains(needle)
        || content
            .body_html
            .as_deref()
            .is_some_and(|html| html.contains(needle))
        || content
            .attachments
            .iter()
            .any(|attachment| contains_bytes(&attachment.data, needle.as_bytes()))
}

/// The seed every boundary of `content` is derived from.
///
/// The base seed is the Message-ID (or the Tuta ids), which the sender
/// chooses, and ASCII text parts are written unencoded — so a sender could
/// precompute the boundaries and plant one in a body to forge the MIME
/// structure. When the content mentions a bridge boundary at all, the seed
/// is extended with a digest of that content (and a counter, until no
/// derived boundary occurs in it), which the sender cannot aim at. Mail
/// that never mentions one keeps the plain seed, so its rendering is
/// unchanged. The result is still a pure function of the content.
///
/// Crate-shared: the IMAP BODYSTRUCTURE renderer derives its boundary
/// parameters from the same seed so they match the rendered message.
pub(crate) fn boundary_seed(content: &MessageContent) -> String {
    pick_boundary_seed(content, &plain_text_of(content))
}

fn pick_boundary_seed(content: &MessageContent, plain_text: &str) -> String {
    let base = content
        .message_id
        .clone()
        .unwrap_or_else(|| format!("{}/{}", content.summary.list_id, content.summary.element_id));
    if !content_contains(content, plain_text, BOUNDARY_PREFIX) {
        return base;
    }

    let mut hashed = Vec::new();
    for part in [plain_text, content.body_html.as_deref().unwrap_or_default()] {
        hashed.extend_from_slice(&(part.len() as u64).to_be_bytes());
        hashed.extend_from_slice(part.as_bytes());
    }
    for attachment in &content.attachments {
        hashed.extend_from_slice(&(attachment.data.len() as u64).to_be_bytes());
        hashed.extend_from_slice(&attachment.data);
    }
    let digest = URL_SAFE_NO_PAD.encode(tutasdk::crypto::sha256(&hashed));

    let mut counter = 0u32;
    loop {
        let seed = format!("{base}\n{digest}\n{counter}");
        let collides = BOUNDARY_LABELS.iter().any(|label| {
            content_contains(content, plain_text, &deterministic_boundary(&seed, label))
        });
        if !collides {
            return seed;
        }
        counter += 1;
    }
}

fn build_message(content: &MessageContent) -> Result<Vec<u8>> {
    let plain_text = plain_text_of(content);
    let seed = pick_boundary_seed(content, &plain_text);

    let mixed_boundary = deterministic_boundary(&seed, "mixed");
    let alt_boundary = deterministic_boundary(&seed, "alt");
    let related_boundary = deterministic_boundary(&seed, "related");

    // Partition attachments: those with a valid Content-ID become inline parts,
    // everything else (no cid, or an invalid cid) is a regular attachment.
    let mut inline_attachments: Vec<(String, &Attachment)> = Vec::new();
    let mut regular_attachments: Vec<&Attachment> = Vec::new();
    for attachment in &content.attachments {
        match attachment.cid.as_deref().and_then(sanitize_cid) {
            Some(cid) => inline_attachments.push((cid, attachment)),
            None => regular_attachments.push(attachment),
        }
    }

    let mut alternative = MimePart::new(
        ContentType::new("multipart/alternative").attribute("boundary", alt_boundary),
        BodyPart::Multipart(Vec::new()),
    );
    alternative.add_part(MimePart::new(
        "text/plain",
        BodyPart::Text(plain_text.into()),
    ));

    if let Some(html) = &content.body_html {
        let mut related = MimePart::new(
            ContentType::new("multipart/related").attribute("boundary", related_boundary),
            BodyPart::Multipart(Vec::new()),
        );
        related.add_part(MimePart::new(
            "text/html",
            BodyPart::Text(html.clone().into()),
        ));
        for (cid, attachment) in &inline_attachments {
            related.add_part(inline_part(attachment, cid));
        }
        alternative.add_part(related);
    }

    let mut root = MimePart::new(
        ContentType::new("multipart/mixed").attribute("boundary", mixed_boundary),
        BodyPart::Multipart(Vec::new()),
    );
    root.add_part(alternative);

    // Without an HTML body there is no multipart/related to host them, so inline
    // attachments are emitted at the root as inline parts instead of dropped.
    if content.body_html.is_none() {
        for (cid, attachment) in &inline_attachments {
            root.add_part(inline_part(attachment, cid));
        }
    }

    for attachment in &regular_attachments {
        root.add_part(
            MimePart::new(
                ContentType::new(sanitize_media_type(&attachment.mime_type)),
                BodyPart::Binary(attachment.data.clone().into()),
            )
            .attachment(sanitize(&attachment.name)),
        );
    }

    let mut builder = MessageBuilder::new()
        .from(convert_address(&content.from))
        .to(convert_list(&content.to));

    if !content.cc.is_empty() {
        builder = builder.cc(convert_list(&content.cc));
    }
    if !content.bcc.is_empty() {
        builder = builder.bcc(convert_list(&content.bcc));
    }
    if !content.reply_to.is_empty() {
        builder = builder.reply_to(convert_list(&content.reply_to));
    }

    builder = builder.subject(Text::new(sanitize(&content.subject)));

    let date = OffsetDateTime::from_unix_timestamp_nanos((content.sent_at_ms as i128) * 1_000_000)
        .map_err(|_| Error::Message("failed to render message".into()))?
        .format(&Rfc2822)
        .map_err(|_| Error::Message("failed to render message".into()))?;
    builder = builder.header("Date", Raw::new(date));

    let message_id = content.message_id.clone().unwrap_or_else(|| {
        format!(
            "<tuta-{}-{}@tuta-bridge.invalid>",
            content.summary.list_id, content.summary.element_id
        )
    });
    builder = builder.header("Message-ID", Raw::new(sanitize(&message_id)));

    if let Some(in_reply_to) = &content.in_reply_to {
        builder = builder.header("In-Reply-To", Raw::new(sanitize(in_reply_to)));
    }
    if !content.references.is_empty() {
        let references = content
            .references
            .iter()
            .map(|reference| sanitize(reference))
            .collect::<Vec<_>>()
            .join(" ");
        builder = builder.header("References", Raw::new(references));
    }

    builder = builder.header("MIME-Version", Raw::new("1.0"));

    builder
        .body(root)
        .write_to_vec()
        .map_err(|_| Error::Message("failed to render message".into()))
}

impl MessageRenderer for MimeRenderer {
    fn render(&self, content: &MessageContent) -> Result<Vec<u8>> {
        build_message(content)
    }
}
