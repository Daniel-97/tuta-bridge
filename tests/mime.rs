use tuta_bridge::adapters::mime::MimeRenderer;
use tuta_bridge::domain::{Address, Attachment, MessageContent, MessageSummary};
use tuta_bridge::ports::MessageRenderer;

fn fixture() -> MessageContent {
    MessageContent {
        summary: MessageSummary {
            list_id: "list1".into(),
            element_id: "elem1".into(),
            received_at_ms: 1_700_000_000_000,
            subject: "Ciao — ünïcode".into(),
            unread: false,
        },
        from: Address {
            name: Some("Sender".into()),
            address: "sender@example.com".into(),
        },
        to: vec![Address {
            name: Some("Recipient".into()),
            address: "recipient@example.com".into(),
        }],
        cc: vec![],
        bcc: vec![],
        reply_to: vec![],
        sent_at_ms: 1_700_000_000_000,
        subject: "Ciao — ünïcode".into(),
        message_id: Some("<id@example>".into()),
        in_reply_to: None,
        references: vec![],
        body_html: Some("<p>Hello <img src=\"cid:img1\"></p>".into()),
        body_text: None,
        attachments: vec![
            Attachment {
                name: "report.pdf".into(),
                mime_type: "application/pdf".into(),
                data: b"%PDF".to_vec(),
                cid: None,
            },
            Attachment {
                name: "logo.png".into(),
                mime_type: "image/png".into(),
                data: b"PNG".to_vec(),
                cid: Some("img1".into()),
            },
        ],
    }
}

#[test]
fn renders_twice_identically() {
    let r = MimeRenderer;
    let a = r.render(&fixture()).unwrap();
    let b = r.render(&fixture()).unwrap();
    assert_eq!(a, b);
    assert!(String::from_utf8_lossy(&a).contains("multipart/alternative"));
}

#[test]
fn html_only_body_gets_plain_alternative_and_inline_image() {
    let bytes = MimeRenderer.render(&fixture()).unwrap();
    let parsed = mail_parser::MessageParser::default().parse(&bytes).unwrap();
    assert!(parsed.body_text(0).is_some());
    assert!(parsed.body_html(0).unwrap().contains("cid:img1"));
    // attachment metadata and Content-ID must be present
    let raw = String::from_utf8_lossy(&bytes);
    assert!(raw.contains("Content-ID: <img1>"));
    assert!(raw.contains("filename=\"report.pdf\""));
}

#[test]
fn header_injection_is_impossible() {
    let mut c = fixture();
    c.subject = "hello\r\nBcc: evil@example.com".into();
    let bytes = MimeRenderer.render(&c).unwrap();
    let parsed = mail_parser::MessageParser::default().parse(&bytes).unwrap();
    assert!(parsed.bcc().is_none());
    assert!(!String::from_utf8_lossy(&bytes).contains("\r\nBcc: evil@example.com"));
    assert!(parsed.subject().unwrap().contains("hello"));
}

#[test]
fn date_comes_from_sent_at_not_clock() {
    let bytes = MimeRenderer.render(&fixture()).unwrap();
    let parsed = mail_parser::MessageParser::default().parse(&bytes).unwrap();
    assert_eq!(parsed.date().unwrap().to_timestamp(), 1_700_000_000);
}
