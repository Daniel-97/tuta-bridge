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

use crate::domain::{Address, Error, MessageContent, Result};
use crate::ports::renderer::MessageRenderer;

/// Renders [`MessageContent`] into RFC 5322 MIME bytes deterministically.
pub struct MimeRenderer;

/// Derive a stable MIME boundary from a seed and a label.
pub fn deterministic_boundary(seed: &str, label: &str) -> String {
    let hash = tutasdk::crypto::sha256(seed.as_bytes());
    format!(
        "=_tuta_bridge_{}_{}",
        label,
        URL_SAFE_NO_PAD.encode(&hash[..9])
    )
}

/// Replace CR/LF so a value can never inject a header line.
fn sanitize(value: &str) -> String {
    value.replace(['\r', '\n'], " ")
}

fn convert_address(addr: &Address) -> MbAddress<'static> {
    MbAddress::new_address(addr.name.as_deref().map(sanitize), sanitize(&addr.address))
}

fn convert_list(addrs: &[Address]) -> MbAddress<'static> {
    MbAddress::new_list(addrs.iter().map(convert_address).collect())
}

fn build_message(content: &MessageContent) -> Result<Vec<u8>> {
    let seed = content
        .message_id
        .clone()
        .unwrap_or_else(|| format!("{}/{}", content.summary.list_id, content.summary.element_id));

    let mixed_boundary = deterministic_boundary(&seed, "mixed");
    let alt_boundary = deterministic_boundary(&seed, "alt");
    let related_boundary = deterministic_boundary(&seed, "related");

    let plain_text = content
        .body_text
        .clone()
        .or_else(|| {
            content
                .body_html
                .as_ref()
                .map(|html| mail_parser::html_to_text(html))
        })
        .unwrap_or_default();

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
        for attachment in content.attachments.iter().filter(|a| a.cid.is_some()) {
            related.add_part(
                MimePart::new(
                    ContentType::new(attachment.mime_type.clone()),
                    BodyPart::Binary(attachment.data.clone().into()),
                )
                .inline()
                .cid(attachment.cid.clone().expect("filtered to a cid")),
            );
        }
        alternative.add_part(related);
    }

    let mut root = MimePart::new(
        ContentType::new("multipart/mixed").attribute("boundary", mixed_boundary),
        BodyPart::Multipart(Vec::new()),
    );
    root.add_part(alternative);
    for attachment in content.attachments.iter().filter(|a| a.cid.is_none()) {
        root.add_part(
            MimePart::new(
                ContentType::new(attachment.mime_type.clone()),
                BodyPart::Binary(attachment.data.clone().into()),
            )
            .attachment(attachment.name.clone()),
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
