use super::mail::{Address, FolderKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MailboxId(pub i64);

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
}

#[derive(Clone)]
pub struct MessagePage {
    pub headers: Vec<MessageHeader>,
    pub next_start: Option<String>,
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
