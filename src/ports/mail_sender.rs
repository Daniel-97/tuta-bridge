use crate::domain::Result;

/// One address of an outgoing mail. Like every data-carrying port type
/// it does not implement `Debug`: addresses are personal data.
#[derive(Clone, PartialEq, Eq)]
pub struct OutgoingAddress {
    pub name: String,
    pub address: String,
}

/// One attachment of an outgoing mail, already transfer-decoded.
#[derive(Clone)]
pub struct OutgoingAttachment {
    pub name: String,
    pub mime_type: String,
    /// The Content-ID without angle brackets, for inline parts.
    pub cid: Option<String>,
    pub data: Vec<u8>,
}

/// A mail ready to hand to Tuta: what a client submitted over SMTP,
/// reduced to the fields Tuta's draft model keeps.
#[derive(Clone)]
pub struct OutgoingMail {
    pub from: OutgoingAddress,
    pub to: Vec<OutgoingAddress>,
    pub cc: Vec<OutgoingAddress>,
    /// Envelope recipients that appear in neither To nor Cc.
    pub bcc: Vec<OutgoingAddress>,
    pub reply_to: Vec<OutgoingAddress>,
    pub subject: String,
    /// The body as HTML (plain-text bodies are escaped into HTML).
    pub html_body: String,
    pub attachments: Vec<OutgoingAttachment>,
}

impl OutgoingMail {
    /// Every recipient, in To, Cc, Bcc order.
    pub fn recipients(&self) -> impl Iterator<Item = &OutgoingAddress> {
        self.to.iter().chain(&self.cc).chain(&self.bcc)
    }
}

/// The send seam towards Tuta.
///
/// An implementation either hands the whole mail to Tuta (which files
/// the copy in Sent itself) or fails with a fixed message that names no
/// address, subject or body.
#[async_trait::async_trait]
pub trait MailSender: Send + Sync {
    async fn send(&self, mail: &OutgoingMail) -> Result<()>;

    /// Whether `address` may be used as the sender: `Ok(false)` when it
    /// is not one of the account's addresses, an error when that cannot
    /// be determined right now (a network failure — the caller answers
    /// with a temporary failure). Compared ASCII-case-insensitively.
    /// Defaults to accepting every address; `send` checks again.
    async fn accepts_sender(&self, address: &str) -> Result<bool> {
        let _ = address;
        Ok(true)
    }
}
