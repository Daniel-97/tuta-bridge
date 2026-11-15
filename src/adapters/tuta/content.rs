//! Pure mapping helpers for Tuta mail details: body selection, HTML detection,
//! header parsing, and address conversion.
//!
//! These functions are deliberately free of I/O so they can be unit-tested
//! without a live session or server.

use std::collections::HashMap;

use tutasdk::entities::generated::tutanota::{Body, EncryptedMailAddress, MailAddress};

use crate::domain::Address;

/// Choose the body text from a Tuta [`Body`], returning `(html, text)`.
///
/// The compressed variant is preferred when present and non-empty; the SDK
/// already decompresses it during mapping. The chosen string is classified as
/// HTML or plain text via [`looks_like_html`].
pub fn select_body(body: &Body) -> (Option<String>, Option<String>) {
    let source = body
        .compressedText
        .as_deref()
        .filter(|text| !text.is_empty())
        .or_else(|| body.text.as_deref().filter(|text| !text.is_empty()));

    let Some(source) = source else {
        return (None, None);
    };

    if looks_like_html(source) {
        (Some(source.to_string()), None)
    } else {
        (None, Some(source.to_string()))
    }
}

/// Heuristically decide whether `text` looks like an HTML document or fragment.
pub fn looks_like_html(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    ["<html", "<body", "<div", "<p", "<br", "<table", "<a "]
        .iter()
        .any(|needle| lower.contains(needle))
}

/// Parse a raw RFC 5322 header block into lower-cased header names and their
/// values. Folded continuation lines are joined to the previous value with a
/// single space, and repeated headers keep their order within each name.
pub fn parse_headers(raw: &str) -> HashMap<String, Vec<String>> {
    let mut headers: HashMap<String, Vec<String>> = HashMap::new();
    let mut last_name: Option<String> = None;

    for line in raw.lines() {
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some(name) = &last_name {
                if let Some(values) = headers.get_mut(name) {
                    if let Some(last) = values.last_mut() {
                        last.push(' ');
                        last.push_str(line.trim());
                    }
                }
            }
            continue;
        }

        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim().to_ascii_lowercase();
            headers
                .entry(name.clone())
                .or_default()
                .push(value.trim().to_string());
            last_name = Some(name);
        }
    }

    headers
}

/// Extract threading headers from a parsed header map as
/// `(message_id, in_reply_to, references)`. References are split on whitespace.
pub fn threading_headers(
    headers: &HashMap<String, Vec<String>>,
) -> (Option<String>, Option<String>, Vec<String>) {
    let first = |name: &str| headers.get(name).and_then(|values| values.first().cloned());

    let message_id = first("message-id");
    let in_reply_to = first("in-reply-to");
    let references = headers
        .get("references")
        .map(|values| {
            values
                .iter()
                .flat_map(|value| value.split_whitespace().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();

    (message_id, in_reply_to, references)
}

/// Convert a Tuta [`MailAddress`] into our [`Address`], dropping empty names.
pub fn address_from_mail_address(address: &MailAddress) -> Address {
    Address {
        name: (!address.name.is_empty()).then(|| address.name.clone()),
        address: address.address.clone(),
    }
}

/// Convert a Tuta [`EncryptedMailAddress`] into our [`Address`], dropping empty names.
pub fn address_from_encrypted(address: &EncryptedMailAddress) -> Address {
    Address {
        name: (!address.name.is_empty()).then(|| address.name.clone()),
        address: address.address.clone(),
    }
}
