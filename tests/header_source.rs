use tuta_bridge::adapters::tuta::mail_source::header_from_parts;
use tutasdk::entities::generated::tutanota::MailAddress;

fn mail_address(name: &str, address: &str) -> MailAddress {
    MailAddress {
        _id: None,
        name: name.into(),
        address: address.into(),
        contact: None,
        _errors: Default::default(),
    }
}

#[test]
fn maps_only_fields_available_in_mail_list() {
    let sender = mail_address("Sender", "sender@example.com");
    let recipient = mail_address("", "recipient@example.com");
    let header = header_from_parts(
        "list",
        "elem",
        5,
        "subject",
        &sender,
        Some(&recipient),
        true,
    )
    .expect("header with element id must map");

    assert_eq!(header.list_id, "list");
    assert_eq!(header.element_id, "elem");
    assert_eq!(header.received_at_ms, 5);
    assert_eq!(header.subject, "subject");
    assert_eq!(header.from.address, "sender@example.com");
    assert_eq!(header.from.name.as_deref(), Some("Sender"));
    assert_eq!(header.to.len(), 1);
    assert_eq!(header.to[0].address, "recipient@example.com");
    assert!(header.to[0].name.is_none());
    assert!(header.unread);
    assert!(!header.envelope_complete);
    assert_eq!(header.sent_at_ms, 0);
    assert!(header.message_id.is_none());
    assert!(header.in_reply_to.is_none());
    assert!(header.references.is_empty());
    assert!(header.cc.is_empty());
    assert!(header.bcc.is_empty());
    assert!(header.reply_to.is_empty());
}

#[test]
fn missing_first_recipient_leaves_to_empty() {
    let sender = mail_address("", "sender@example.com");
    let header = header_from_parts("list", "elem", 5, "subject", &sender, None, false)
        .expect("header with element id must map");

    assert!(header.to.is_empty());
    assert_eq!(header.from.address, "sender@example.com");
    assert!(header.from.name.is_none());
    assert!(!header.unread);
}

#[test]
fn empty_element_id_is_skipped() {
    let sender = mail_address("", "sender@example.com");
    assert!(header_from_parts("list", "", 5, "subject", &sender, None, false).is_none());
}
