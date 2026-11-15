use time::format_description;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FolderKind {
    Inbox,
    Sent,
    Drafts,
    Trash,
    Junk,
    Archive,
    Custom,
}

impl FolderKind {
    pub fn from_alias(alias: &str) -> Option<Self> {
        match alias.to_ascii_lowercase().as_str() {
            "inbox" => Some(Self::Inbox),
            "sent" => Some(Self::Sent),
            "drafts" => Some(Self::Drafts),
            "trash" => Some(Self::Trash),
            "junk" => Some(Self::Junk),
            "archive" => Some(Self::Archive),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Folder {
    pub list_id: String,
    pub name: String,
    pub kind: FolderKind,
}

#[derive(Clone)]
pub struct MessageSummary {
    pub list_id: String,
    pub element_id: String,
    pub received_at_ms: i64,
    pub subject: String,
    pub unread: bool,
}

impl MessageSummary {
    pub fn file_stem(&self) -> String {
        let date_str = time::OffsetDateTime::from_unix_timestamp_nanos(
            self.received_at_ms as i128 * 1_000_000,
        )
        .ok()
        .and_then(|dt| {
            let fmt = format_description::parse_borrowed::<2>(
                "[year][month][day]-[hour][minute][second]",
            )
            .ok()?;
            dt.format(&fmt).ok()
        })
        .unwrap_or_else(|| "19700101-000000".to_string());

        let sanitized: String = self
            .element_id
            .chars()
            .map(|c| match c {
                'A'..='Z' | 'a'..='z' | '0'..='9' | '_' | '-' => c,
                _ => '_',
            })
            .collect();

        format!("{}-{}", date_str, sanitized)
    }
}

#[derive(Clone)]
pub struct Address {
    pub name: Option<String>,
    pub address: String,
}

#[derive(Clone)]
pub struct Attachment {
    pub name: String,
    pub mime_type: String,
    pub data: Vec<u8>,
    pub cid: Option<String>,
}

#[derive(Clone)]
pub struct MessageContent {
    pub summary: MessageSummary,
    pub from: Address,
    pub to: Vec<Address>,
    pub cc: Vec<Address>,
    pub bcc: Vec<Address>,
    pub reply_to: Vec<Address>,
    pub sent_at_ms: i64,
    pub subject: String,
    pub message_id: Option<String>,
    pub in_reply_to: Option<String>,
    pub references: Vec<String>,
    pub body_html: Option<String>,
    pub body_text: Option<String>,
    pub attachments: Vec<Attachment>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aliases_are_case_insensitive() {
        assert_eq!(FolderKind::from_alias("Inbox"), Some(FolderKind::Inbox));
        assert_eq!(FolderKind::from_alias("TRASH"), Some(FolderKind::Trash));
        assert_eq!(FolderKind::from_alias("custom-folder"), None);
    }

    #[test]
    fn file_stem_is_stable_and_safe() {
        let s = MessageSummary {
            list_id: "list".into(),
            element_id: "abc-_123".into(),
            received_at_ms: 1_700_000_000_000,
            subject: "ignored".into(),
            unread: false,
        };
        assert_eq!(s.file_stem(), "20231114-221320-abc-_123");
    }
}
