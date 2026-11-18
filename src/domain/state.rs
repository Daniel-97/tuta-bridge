use super::mail::{Address, Folder, FolderKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MailboxId(pub i64);

/// Mailboxes one applied batch actually changed.
///
/// `touched` lists every mailbox whose rows the batch's transaction
/// inserted, updated, or deleted, deduplicated and in the order the
/// changes first touched them. Idling sessions use it to learn that
/// their cached view of a mailbox may be stale. Like the batch types
/// around it, this type deliberately does not implement `Debug`.
#[derive(Clone)]
pub struct BatchOutcome {
    pub touched: Vec<MailboxId>,
}

/// One stored placement of a mail: the mailbox it belongs to and its header.
///
/// `mailbox_list_id` is the folder's entries list id and resolves the
/// mailbox row. `header.list_id` is the Mail's own list id, stored in
/// `messages.tuta_list_id` for later content reloads, and must never be used
/// to resolve the mailbox. Like headers, this type deliberately does not
/// implement `Debug` so personal data cannot end up in logs.
#[derive(Clone)]
pub struct MailPlacement {
    pub mailbox_list_id: String,
    pub header: MessageHeader,
}

/// A single mutation produced from one or more Tuta events.
///
/// Changes are applied as one transaction by
/// [`StateStore::apply_batch`](crate::ports::state_store::StateStore::apply_batch),
/// so the batch marker and every row change become visible together. The type
/// deliberately does not implement `Debug`: headers carry personal data that
/// must not be logged.
#[derive(Clone)]
// The header variant is large, but the interface keeps headers inline so
// building and replaying a batch allocates nothing extra per change.
#[allow(clippy::large_enum_variant)]
pub enum StateChange {
    /// Create or update a folder, preserving the existing UID sequence.
    UpsertMailbox { folder: Folder, uidvalidity: u32 },
    /// Add or refresh a mail's placement in the mailbox named by
    /// `mailbox_list_id` (the folder's entries list id). The header's own
    /// `list_id` is the Mail's list id and is stored for content reloads.
    UpsertHeader {
        mailbox_list_id: String,
        header: MessageHeader,
    },
    /// Remove every stored placement of a mail.
    RemoveHeaderEverywhere { element_id: String },
    /// Remove placements of a mail except those in `keep_list_ids`.
    RemoveOtherPlacements {
        element_id: String,
        keep_list_ids: Vec<String>,
    },
}

#[derive(Clone)]
pub struct StoredMailbox {
    pub id: MailboxId,
    pub account_id: i64,
    pub list_id: String,
    pub name: String,
    pub kind: FolderKind,
    pub uidvalidity: u32,
    pub next_uid: u32,
}

#[derive(Clone)]
pub struct MessageHeader {
    pub list_id: String,
    pub element_id: String,
    pub received_at_ms: i64,
    pub sent_at_ms: i64,
    pub subject: String,
    pub from: Address,
    pub to: Vec<Address>,
    pub cc: Vec<Address>,
    pub bcc: Vec<Address>,
    pub reply_to: Vec<Address>,
    pub unread: bool,
    pub message_id: Option<String>,
    pub in_reply_to: Option<String>,
    pub references: Vec<String>,
    pub envelope_complete: bool,
}

#[derive(Clone)]
pub struct StoredMessage {
    pub uid: u32,
    pub header: MessageHeader,
    pub rfc822_size: Option<u64>,
    /// Precomputed BODYSTRUCTURE string; `None` until first enrichment.
    ///
    /// Metadata only: the rendered message bytes it describes are never
    /// stored.
    pub mime_structure: Option<String>,
}

#[derive(Clone)]
pub struct MessagePage {
    pub headers: Vec<MessageHeader>,
    pub next_start: Option<String>,
    /// Number of mails the source could not load into this page.
    pub skipped: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Address;

    #[test]
    fn stored_mailbox_uses_typed_id() {
        let mailbox = StoredMailbox {
            id: MailboxId(7),
            account_id: 1,
            list_id: "list".into(),
            name: "Custom".into(),
            kind: FolderKind::Custom,
            uidvalidity: 100,
            next_uid: 3,
        };
        assert_eq!(mailbox.id, MailboxId(7));
        assert_eq!(mailbox.kind, FolderKind::Custom);
    }

    #[test]
    fn header_keeps_ids_and_optional_metadata() {
        let header = MessageHeader {
            list_id: "l".into(),
            element_id: "e".into(),
            received_at_ms: 5,
            sent_at_ms: 0,
            subject: "s".into(),
            from: Address {
                name: None,
                address: "a@b.c".into(),
            },
            to: vec![],
            cc: vec![],
            bcc: vec![],
            reply_to: vec![],
            unread: true,
            message_id: None,
            in_reply_to: None,
            references: vec![],
            envelope_complete: false,
        };
        assert_eq!(header.list_id, "l");
        assert!(!header.envelope_complete);
    }
}
