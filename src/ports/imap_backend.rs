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
    /// How many messages are unread — the STATUS `UNSEEN` count.
    pub fn unseen(&self) -> usize {
        self.messages.iter().filter(|(_, unread)| *unread).count()
    }

    /// The message number of the first unread message — the SELECT
    /// `[UNSEEN n]` response code (RFC 3501 §7.1), unlike STATUS, which
    /// reports a count. `None` when every message is read.
    pub fn first_unseen(&self) -> Option<usize> {
        self.messages
            .iter()
            .position(|(_, unread)| *unread)
            .map(|index| index + 1)
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

    /// Mark the messages with these UIDs read (`seen`) or unread, first
    /// in Tuta, then in the local index. Returns the `(uid, unread)`
    /// pairs actually applied, ascending; UIDs the mailbox no longer has
    /// are skipped silently, like FETCH skips them. A failed remote
    /// write changes nothing locally.
    async fn store_seen(
        &self,
        mailbox: MailboxId,
        uids: &[u32],
        seen: bool,
    ) -> Result<Vec<(u32, bool)>> {
        let _ = (mailbox, uids, seen);
        Err(read_only())
    }

    /// Move the messages with these UIDs into `target`. Returns the
    /// UIDs removed from `mailbox`, ascending. The target gets its rows
    /// (with fresh UIDs) from the event that echoes the move, never
    /// from this call. Moving into the same mailbox is a no-op.
    async fn move_mails(
        &self,
        mailbox: MailboxId,
        uids: &[u32],
        target: MailboxId,
    ) -> Result<Vec<u32>> {
        let _ = (mailbox, uids, target);
        Err(read_only())
    }

    /// Delete the messages with these UIDs: outside Trash they move to
    /// Trash; inside Trash they are deleted for good. Returns the UIDs
    /// removed from `mailbox`, ascending.
    async fn expunge_mails(&self, mailbox: MailboxId, uids: &[u32]) -> Result<Vec<u32>> {
        let _ = (mailbox, uids);
        Err(read_only())
    }
}

fn read_only() -> crate::domain::Error {
    crate::domain::Error::Unsupported("read-only backend".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn selected(messages: Vec<(u32, bool)>) -> SelectedMailbox {
        SelectedMailbox {
            view: MailboxView {
                id: MailboxId(1),
                name: "Inbox".into(),
                special_use: "",
            },
            uidvalidity: 7,
            uidnext: 9,
            messages,
        }
    }

    #[test]
    fn select_reports_the_first_unseen_number_and_status_the_count() {
        let mailbox = selected(vec![(1, false), (3, true), (4, false), (8, true)]);
        assert_eq!(mailbox.first_unseen(), Some(2));
        assert_eq!(mailbox.unseen(), 2);

        let all_read = selected(vec![(1, false), (2, false)]);
        assert_eq!(all_read.first_unseen(), None);
        assert_eq!(all_read.unseen(), 0);
    }
}
