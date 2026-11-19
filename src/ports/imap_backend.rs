use secrecy::SecretString;

use crate::adapters::imap::codec::FetchItem;
use crate::adapters::imap::search::SearchKey;
use crate::domain::{MailboxId, Result};

/// One mailbox as `LIST`/`LSUB` answer it.
///
/// `special_use` is the rendered SPECIAL-USE attribute ("" for INBOX and
/// custom folders). Like every data-carrying port type it deliberately
/// does not implement `Debug`: mailbox names are personal data that must
/// not end up in logs.
pub struct MailboxView {
    pub id: MailboxId,
    pub name: String,
    pub special_use: &'static str,
}

/// The state of one mailbox at one moment: what `SELECT` reports, and
/// what a selected session compares its own view against.
pub struct SelectedMailbox {
    pub view: MailboxView,
    pub uidvalidity: u32,
    pub uidnext: u32,
    /// `(uid, unread)` of every message, in ascending UID order: a
    /// message's position, plus one, is its message sequence number.
    pub messages: Vec<(u32, bool)>,
}

impl SelectedMailbox {
    /// How many messages are unread.
    pub fn unseen(&self) -> usize {
        self.messages.iter().filter(|(_, unread)| *unread).count()
    }
}

/// One FETCH response, built from the requested item list.
///
/// `envelope`, `bodystructure`, and `rfc822_size` stay `None` when the
/// request did not ask for them. `bodies` holds one entry per body
/// item of the request (`BODY[...]`, `BODY.PEEK[...]`, `RFC822`,
/// `RFC822.HEADER`, `RFC822.TEXT`), in request order: the whole
/// section, before any partial `<offset.count>` cut, which is the
/// session's job. The strings are already IMAP-encoded (literals framed
/// as `{n}\r\n<bytes>` where needed), so the session writes them
/// verbatim. No `Debug`: envelopes and bodies are personal data that
/// must never reach a log line.
pub struct FetchResponse {
    pub uid: u32,
    pub flags: String,
    pub internal_date: String,
    pub envelope: Option<String>,
    pub bodystructure: Option<String>,
    pub rfc822_size: Option<u64>,
    pub bodies: Vec<Vec<u8>>,
}

/// The read-only backend seam a session talks to.
///
/// Implementations answer from the local state store; only body fetches
/// may load content on demand. Login compares against the locally stored
/// bridge password.
#[async_trait::async_trait]
pub trait ImapBackend: Send + Sync {
    /// Compare `user`/`password` against the expected account login and
    /// the stored bridge password. `false` on any mismatch; never an
    /// error, and never a log line.
    async fn login(&self, user: &str, password: &SecretString) -> Result<bool>;
    async fn mailboxes(&self) -> Result<Vec<MailboxView>>;
    /// Resolve one mailbox by name: exact, plus `INBOX` case-insensitively.
    async fn select(&self, name: &str) -> Result<Option<SelectedMailbox>>;
    /// The current state of the mailbox with this id, or `None` once it
    /// no longer exists. A selected session addresses its mailbox this
    /// way — never by name again, so a renamed or same-named mailbox can
    /// not be mistaken for it.
    async fn snapshot(&self, mailbox: MailboxId) -> Result<Option<SelectedMailbox>>;
    /// The current UIDVALIDITY of the mailbox with this id, or `None`
    /// once it no longer exists: the check a selected session runs
    /// before every command, so implementations should answer it
    /// without reading messages.
    async fn uidvalidity(&self, mailbox: MailboxId) -> Result<Option<u32>> {
        Ok(self
            .snapshot(mailbox)
            .await?
            .map(|snapshot| snapshot.uidvalidity))
    }
    /// Fetch one stored message by UID, or `None` when the mailbox has no
    /// such row.
    async fn fetch(
        &self,
        mailbox: MailboxId,
        uid: u32,
        items: &[FetchItem],
    ) -> Result<Option<FetchResponse>>;
    /// Evaluate SEARCH keys — every one must match — over the stored
    /// index; the returned numbers are UIDs, ascending.
    ///
    /// `view` is the searching session's uid list in message-number
    /// order: only its messages are candidates, and sequence-number
    /// keys and `*` resolve against it, never against the live store.
    async fn search(
        &self,
        mailbox: MailboxId,
        keys: &[SearchKey],
        view: &[u32],
    ) -> Result<Vec<u32>>;
}
