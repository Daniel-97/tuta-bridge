use std::collections::HashMap;

use tuta_bridge::adapters::tuta::content::{
    address_from_encrypted, address_from_mail_address, looks_like_html, parse_headers, select_body,
    threading_headers,
};
use tutasdk::entities::generated::tutanota::{Body, EncryptedMailAddress, MailAddress};

#[test]
fn prefers_compressed_text_and_detects_html() {
    let body = Body {
        _id: None,
        text: Some("plain".into()),
        compressedText: Some("<p>html</p>".into()),
        _errors: Default::default(),
    };
    let (html, text) = select_body(&body);
    assert_eq!(html, Some("<p>html</p>".into()));
    assert_eq!(text, None);
    assert!(looks_like_html("<div>x</div>"));
    assert!(!looks_like_html("just text"));
}

#[test]
fn falls_back_to_plain_text_when_no_compressed_text() {
    let body = Body {
        _id: None,
        text: Some("hello".into()),
        compressedText: None,
        _errors: Default::default(),
    };
    let (html, text) = select_body(&body);
    assert_eq!(html, None);
    assert_eq!(text, Some("hello".into()));
}

#[test]
fn detects_html_case_insensitively() {
    assert!(looks_like_html("<HTML><BODY>x</BODY></HTML>"));
    assert!(looks_like_html("<A href=\"https://example.com\">x</A>"));
    assert!(looks_like_html("<Table>"));
    assert!(!looks_like_html("a < b and c > d"));
}

#[test]
fn parses_folded_and_repeated_headers() {
    let raw =
        "Message-ID: <a@b>\r\nReferences: <x@y>\r\n <z@w>\r\nReceived: one\r\nReceived: two\r\n";
    let h = parse_headers(raw);
    assert_eq!(h["message-id"], vec!["<a@b>"]);
    assert_eq!(h["references"], vec!["<x@y> <z@w>"]);
    assert_eq!(h["received"].len(), 2);
}

#[test]
fn extracts_threading_headers() {
    let h = HashMap::from([
        ("message-id".into(), vec!["<m@x>".into()]),
        ("in-reply-to".into(), vec!["<r@x>".into()]),
        ("references".into(), vec!["<a@x> <b@x>".into()]),
    ]);
    let (id, reply, refs) = threading_headers(&h);
    assert_eq!(id.as_deref(), Some("<m@x>"));
    assert_eq!(reply.as_deref(), Some("<r@x>"));
    assert_eq!(refs, vec!["<a@x>", "<b@x>"]);
}

#[test]
fn maps_addresses_and_drops_empty_names() {
    let named = MailAddress {
        _id: None,
        name: "Alice".into(),
        address: "alice@example.com".into(),
        contact: None,
        _errors: Default::default(),
    };
    let addr = address_from_mail_address(&named);
    assert_eq!(addr.name.as_deref(), Some("Alice"));
    assert_eq!(addr.address, "alice@example.com");

    let unnamed = MailAddress {
        _id: None,
        name: String::new(),
        address: "a@b".into(),
        contact: None,
        _errors: Default::default(),
    };
    assert_eq!(address_from_mail_address(&unnamed).name, None);

    let encrypted = EncryptedMailAddress {
        _id: None,
        name: String::new(),
        address: "e@f".into(),
        _errors: Default::default(),
    };
    assert_eq!(address_from_encrypted(&encrypted).name, None);
}
