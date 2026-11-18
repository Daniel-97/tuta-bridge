use std::collections::HashMap;

use tuta_bridge::adapters::tuta::content::{
    address_from_encrypted, address_from_mail_address, looks_like_html, parse_headers, select_body,
    sent_at_from, threading_headers,
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
fn extracts_the_sent_date_from_a_valid_rfc5322_date_header() {
    let h = parse_headers("Date: Tue, 14 Nov 2023 22:13:20 +0000\r\n");
    assert_eq!(sent_at_from(&h, 99), 1_700_000_000_000);
}

#[test]
fn parses_folded_and_repeated_date_headers() {
    // A folded continuation is joined by parse_headers, and the zone
    // offset is applied by the date parser.
    let folded = parse_headers("Date: Tue, 14 Nov 2023\r\n 23:13:20 +0100\r\n");
    assert_eq!(sent_at_from(&folded, 0), 1_700_000_000_000);
    // Repeated Date headers keep separate values; they are joined and
    // the first date in the joined string wins.
    let repeated = parse_headers(
        "Date: Tue, 14 Nov 2023 22:13:20 +0000\r\nDate: Wed, 15 Nov 2023 10:00:00 +0000\r\n",
    );
    assert_eq!(sent_at_from(&repeated, 0), 1_700_000_000_000);
}

#[test]
fn missing_date_falls_back_to_a_positive_fallback() {
    let h = parse_headers("Subject: no date here\r\n");
    assert_eq!(sent_at_from(&h, 1_700_000_000_000), 1_700_000_000_000);
}

#[test]
fn missing_date_with_zero_fallback_returns_zero() {
    let h = parse_headers("Subject: no date here\r\n");
    assert_eq!(sent_at_from(&h, 0), 0);
}

#[test]
fn malformed_date_falls_back_like_a_missing_one() {
    let h = parse_headers("Date: definitely not a timestamp\r\n");
    assert_eq!(sent_at_from(&h, 1_700_000_000_000), 1_700_000_000_000);
    // A non-positive fallback never masquerades as a real date.
    assert_eq!(sent_at_from(&h, 0), 0);
}

#[test]
fn date_header_name_matches_case_insensitively() {
    let upper = parse_headers("DATE: Tue, 14 Nov 2023 22:13:20 +0000\r\n");
    assert_eq!(sent_at_from(&upper, 0), 1_700_000_000_000);
    let mixed = parse_headers("dAtE: Tue, 14 Nov 2023 22:13:20 +0000\r\n");
    assert_eq!(sent_at_from(&mixed, 0), 1_700_000_000_000);
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
