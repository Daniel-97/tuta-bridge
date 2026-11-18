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

    /// Display name for system MailSets, which Tuta stores with an empty
    /// `name` on the server (clients localize the label by folder type).
    /// Custom folders carry real names, so they have no default.
    pub fn default_name(&self) -> &'static str {
        match self {
            Self::Inbox => "Inbox",
            Self::Sent => "Sent",
            Self::Drafts => "Drafts",
            Self::Trash => "Trash",
            Self::Junk => "Junk",
            Self::Archive => "Archive",
            Self::Custom => "",
        }
    }

    /// Stable string stored in the SQLite `mailboxes.kind` column.
    pub fn as_db_str(&self) -> &'static str {
        match self {
            Self::Inbox => "inbox",
            Self::Sent => "sent",
            Self::Drafts => "drafts",
            Self::Trash => "trash",
            Self::Junk => "junk",
            Self::Archive => "archive",
            Self::Custom => "custom",
        }
    }

    /// Parse a value produced by [`Self::as_db_str`].
    ///
    /// Unlike [`Self::from_alias`], this accepts the generic `custom` kind.
    pub fn from_db_str(value: &str) -> Option<Self> {
        match value {
            "inbox" => Some(Self::Inbox),
            "sent" => Some(Self::Sent),
            "drafts" => Some(Self::Drafts),
            "trash" => Some(Self::Trash),
            "junk" => Some(Self::Junk),
            "archive" => Some(Self::Archive),
            "custom" => Some(Self::Custom),
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
    fn folder_kind_db_strings_roundtrip_all_variants() {
        let kinds = [
            FolderKind::Inbox,
            FolderKind::Sent,
            FolderKind::Drafts,
            FolderKind::Trash,
            FolderKind::Junk,
            FolderKind::Archive,
            FolderKind::Custom,
        ];
        for kind in kinds {
            assert_eq!(
                FolderKind::from_db_str(kind.as_db_str()),
                Some(kind),
                "kind must round-trip through its database string"
            );
        }
        assert_eq!(FolderKind::Custom.as_db_str(), "custom");
        assert_eq!(FolderKind::from_db_str("custom-folder"), None);
    }

    #[test]
    fn aliases_do_not_accept_the_custom_db_string() {
        assert_eq!(FolderKind::from_alias("custom"), None);
        assert_eq!(FolderKind::from_db_str("custom"), Some(FolderKind::Custom));
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
