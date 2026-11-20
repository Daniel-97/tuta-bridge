//! Turn a submitted RFC 5322 message plus its SMTP envelope into an
//! [`OutgoingMail`].
//!
//! The envelope decides who receives the mail (RFC 5321 §3.3): every
//! `RCPT TO` address is a recipient, the `To`/`Cc` headers only decide
//! how each is shown, and envelope recipients absent from both become
//! Bcc — which is how clients submit Bcc (they strip the header). A
//! header recipient missing from the envelope is not sent to.

use mail_parser::{AddressList, MessageParser, MessagePart, PartId};

use crate::ports::mail_sender::{OutgoingAddress, OutgoingAttachment, OutgoingMail};

/// The largest HTML body Tuta accepts, in bytes (the web client's
/// `UNCOMPRESSED_MAX_SIZE`, 1 MiB).
pub const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Why a submitted message cannot be sent. Each maps to one fixed SMTP
/// reply; none carries message content.
#[derive(Debug, PartialEq, Eq)]
pub enum OutgoingError {
    /// The bytes are not a parseable message.
    Unparseable,
    /// No usable `From:` header.
    MissingFrom,
    /// The body is larger than Tuta accepts.
    BodyTooLarge,
    /// No recipient at all.
    NoRecipients,
    /// A header address that is not a plain `local@domain`, or a display
    /// name with control characters.
    InvalidAddress,
}

/// Whether `address` is a plain `local@domain` the draft may carry: no
/// control characters, no whitespace, no angle brackets or list
/// separators, exactly one `@` with both sides non-empty, and at most
/// 254 octets (RFC 5321 §4.5.3.1.3). Quoted local parts are not
/// accepted.
pub fn is_valid_address(address: &str) -> bool {
    if address.is_empty() || address.len() > 254 {
        return false;
    }
    if address
        .chars()
        .any(|c| c.is_control() || c.is_whitespace() || matches!(c, '<' | '>' | ',' | ';' | '"'))
    {
        return false;
    }
    match address.split_once('@') {
        Some((local, domain)) => {
            !local.is_empty()
                && !domain.is_empty()
                && !domain.contains('@')
                && !domain.starts_with('.')
                && !domain.ends_with('.')
        }
        None => false,
    }
}

fn has_control(text: &str) -> bool {
    text.chars().any(char::is_control)
}

fn same_address(a: &str, b: &str) -> bool {
    a.trim().eq_ignore_ascii_case(b.trim())
}

/// The mailboxes of one address header, groups flattened.
fn addresses(list: Option<AddressList<'_>>) -> Vec<OutgoingAddress> {
    let Some(list) = list else {
        return Vec::new();
    };
    list.mailboxes()
        .filter_map(|mailbox| {
            let address = mailbox.address()?.trim();
            (!address.is_empty()).then(|| OutgoingAddress {
                name: mailbox.name().unwrap_or("").trim().to_string(),
                address: address.to_string(),
            })
        })
        .collect()
}

/// Escape plain text into HTML that keeps its line breaks.
pub fn text_to_html(text: &str) -> String {
    let mut html = String::with_capacity(text.len() + 32);
    for ch in text.chars() {
        match ch {
            '&' => html.push_str("&amp;"),
            '<' => html.push_str("&lt;"),
            '>' => html.push_str("&gt;"),
            '"' => html.push_str("&quot;"),
            '\r' => {}
            '\n' => html.push_str("<br>\n"),
            other => html.push(other),
        }
    }
    html
}

/// Parse `raw` and split recipients per the envelope `rcpt_to`.
pub fn outgoing_from_message(
    raw: &[u8],
    rcpt_to: &[String],
) -> Result<OutgoingMail, OutgoingError> {
    let message = MessageParser::default()
        .parse(raw)
        .ok_or(OutgoingError::Unparseable)?;
    let from = addresses(message.from())
        .into_iter()
        .next()
        .ok_or(OutgoingError::MissingFrom)?;

    let in_envelope = |address: &OutgoingAddress| {
        rcpt_to
            .iter()
            .any(|rcpt| same_address(rcpt, &address.address))
    };
    let mut to: Vec<OutgoingAddress> = Vec::new();
    for address in addresses(message.to()) {
        if in_envelope(&address)
            && !to
                .iter()
                .any(|seen| same_address(&seen.address, &address.address))
        {
            to.push(address);
        }
    }
    let mut cc: Vec<OutgoingAddress> = Vec::new();
    for address in addresses(message.cc()) {
        let shown = to
            .iter()
            .chain(&cc)
            .any(|seen| same_address(&seen.address, &address.address));
        if in_envelope(&address) && !shown {
            cc.push(address);
        }
    }
    let mut bcc: Vec<OutgoingAddress> = Vec::new();
    for rcpt in rcpt_to {
        let shown = to
            .iter()
            .chain(&cc)
            .chain(&bcc)
            .any(|seen| same_address(&seen.address, rcpt));
        if !shown && !rcpt.trim().is_empty() {
            bcc.push(OutgoingAddress {
                name: String::new(),
                address: rcpt.trim().to_string(),
            });
        }
    }
    if to.is_empty() && cc.is_empty() && bcc.is_empty() {
        return Err(OutgoingError::NoRecipients);
    }
    let reply_to = addresses(message.reply_to());
    let every = std::iter::once(&from)
        .chain(&to)
        .chain(&cc)
        .chain(&bcc)
        .chain(&reply_to);
    for address in every {
        if !is_valid_address(&address.address) || has_control(&address.name) {
            return Err(OutgoingError::InvalidAddress);
        }
    }

    // mail-parser synthesizes an HTML body from a text-only mail; only a
    // real text/html part is taken as HTML, a text body is escaped.
    // The HTML body is the first real text/html part. mail-parser can
    // file it outside the HTML body list: in a multipart/related that
    // starts with an inline image, the image becomes "the body" and the
    // text/html part an attachment. So the body list is searched first,
    // then undeclared (not `Content-Disposition: attachment`) text/html
    // parts among the attachments — and the part chosen is not sent as an
    // attachment too. mail-parser also synthesizes HTML from a text-only
    // mail, so without a real HTML part the text body is escaped instead.
    let is_html = |part: &MessagePart<'_>| part.is_content_type("text", "html");
    let declared_attachment = |part: &MessagePart<'_>| {
        part.content_disposition()
            .is_some_and(|disposition| disposition.ctype().eq_ignore_ascii_case("attachment"))
    };
    let mut html_from_attachment: Option<PartId> = None;
    let html_part = match message.html_body().find(|part| is_html(part)) {
        Some(part) => part.text(),
        None => message
            .attachments()
            .find(|part| is_html(part) && !declared_attachment(part))
            .and_then(|part| {
                html_from_attachment = Some(part.id());
                part.text()
            }),
    };
    let html_body = match (html_part, message.body_text(0)) {
        (Some(html), _) => html.into_owned(),
        (None, Some(text)) => text_to_html(&text),
        (None, None) => message
            .body_html(0)
            .map(|html| html.into_owned())
            .unwrap_or_default(),
    };
    if html_body.len() > MAX_BODY_BYTES {
        return Err(OutgoingError::BodyTooLarge);
    }

    // Attachments: the attachment list minus the part used as the body,
    // plus non-text parts mail-parser filed as body (an inline image at
    // the start of a multipart/related), each part once.
    let mut seen: Vec<PartId> = Vec::new();
    let mut attachments = Vec::new();
    let body_parts = message.html_body().chain(message.text_body());
    for part in message.attachments().chain(body_parts) {
        let id = part.id();
        if seen.contains(&id) || Some(id) == html_from_attachment {
            continue;
        }
        let is_body_text = part.is_text() && !declared_attachment(&part);
        let from_body_list = !message
            .attachments()
            .any(|attachment| attachment.id() == id);
        if from_body_list && is_body_text {
            continue;
        }
        seen.push(id);
        attachments.push(attachment_of(&part));
    }

    Ok(OutgoingMail {
        from,
        to,
        cc,
        bcc,
        reply_to,
        subject: message.subject().unwrap_or("").to_string(),
        html_body,
        attachments,
    })
}

/// One MIME part as a draft attachment.
fn attachment_of(part: &MessagePart<'_>) -> OutgoingAttachment {
    let mime_type = part
        .content_type()
        .map(|ct| match ct.subtype() {
            Some(sub) => format!("{}/{}", ct.ctype(), sub),
            None => ct.ctype().to_string(),
        })
        .unwrap_or_else(|| "application/octet-stream".to_string())
        .to_ascii_lowercase();
    OutgoingAttachment {
        name: part
            .attachment_name()
            .filter(|name| !name.trim().is_empty())
            .unwrap_or("attachment")
            .to_string(),
        mime_type,
        cid: part
            .content_id()
            .map(|cid| cid.trim_matches(|c| c == '<' || c == '>').to_string())
            .filter(|cid| !cid.is_empty()),
        data: part.decoded().into_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rcpts(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    const PLAIN: &[u8] = b"From: Me <me@tuta.example>\r\n\
To: Ann <ann@x.example>, ghost@x.example\r\n\
Cc: bob@y.example\r\n\
Reply-To: replies@tuta.example\r\n\
Subject: =?UTF-8?Q?Caff=C3=A8?=\r\n\
\r\n\
a < b & c\r\nsecond line\r\n";

    #[test]
    fn envelope_decides_recipients_and_extra_ones_are_bcc() {
        let mail = outgoing_from_message(
            PLAIN,
            &rcpts(&["ANN@x.example", "bob@y.example", "hidden@z.example"]),
        )
        .unwrap();
        assert_eq!(mail.from.address, "me@tuta.example");
        assert_eq!(mail.from.name, "Me");
        // ghost@ is in the header but not the envelope: not sent to.
        assert_eq!(mail.to.len(), 1);
        assert_eq!(mail.to[0].address, "ann@x.example");
        assert_eq!(mail.to[0].name, "Ann");
        assert_eq!(mail.cc.len(), 1);
        assert_eq!(mail.bcc.len(), 1);
        assert_eq!(mail.bcc[0].address, "hidden@z.example");
        assert_eq!(mail.reply_to[0].address, "replies@tuta.example");
        assert_eq!(mail.subject, "Caffè");
        assert_eq!(mail.recipients().count(), 3);
    }

    #[test]
    fn text_bodies_are_escaped_into_html() {
        let mail = outgoing_from_message(PLAIN, &rcpts(&["ann@x.example"])).unwrap();
        assert_eq!(mail.html_body, "a &lt; b &amp; c<br>\nsecond line<br>\n");
    }

    #[test]
    fn html_parts_and_attachments_are_kept() {
        let raw = b"From: me@tuta.example\r\n\
To: ann@x.example\r\n\
Subject: s\r\n\
MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"b\"\r\n\
\r\n\
--b\r\n\
Content-Type: multipart/alternative; boundary=\"a\"\r\n\
\r\n\
--a\r\n\
Content-Type: text/plain\r\n\
\r\n\
plain\r\n\
--a\r\n\
Content-Type: text/html\r\n\
\r\n\
<p>rich</p>\r\n\
--a--\r\n\
--b\r\n\
Content-Type: application/pdf; name=\"doc.pdf\"\r\n\
Content-Disposition: attachment; filename=\"doc.pdf\"\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
aGVsbG8=\r\n\
--b--\r\n";
        let mail = outgoing_from_message(raw, &rcpts(&["ann@x.example"])).unwrap();
        assert!(mail.html_body.contains("<p>rich</p>"));
        assert_eq!(mail.attachments.len(), 1);
        assert_eq!(mail.attachments[0].name, "doc.pdf");
        assert_eq!(mail.attachments[0].mime_type, "application/pdf");
        assert_eq!(mail.attachments[0].data, b"hello");
    }

    #[test]
    fn refusals_are_specific() {
        assert_eq!(
            outgoing_from_message(b"To: a@b.example\r\n\r\nx", &rcpts(&["a@b.example"])).err(),
            Some(OutgoingError::MissingFrom)
        );
        assert_eq!(
            outgoing_from_message(PLAIN, &[]).err(),
            Some(OutgoingError::NoRecipients)
        );
        let mut big = b"From: me@tuta.example\r\nTo: a@b.example\r\n\r\n".to_vec();
        big.extend(std::iter::repeat_n(b'x', MAX_BODY_BYTES + 1));
        assert_eq!(
            outgoing_from_message(&big, &rcpts(&["a@b.example"])).err(),
            Some(OutgoingError::BodyTooLarge)
        );
    }
}
