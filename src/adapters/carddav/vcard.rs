//! Render a contact as a vCard 4.0 (RFC 6350).
//!
//! Output is deterministic — the same contact always renders to the
//! same bytes — because the strong ETag is a hash of those bytes: a
//! full reload must not change the ETag of an unchanged contact.
//!
//! - Lines end with CRLF and are folded at 75 octets, never inside a
//!   UTF-8 sequence; continuation lines start with one space.
//! - Text values escape `\`, `,`, `;` and newlines (`\n`); structured
//!   values (`N`, `ADR`, `ORG`) escape each component and join them with
//!   `;`. URI values (`URL`) carry no line breaks.
//! - Dates (`BDAY`, `ANNIVERSARY`) use the basic ISO form RFC 6350
//!   §4.3.1 defines (`19850412`, `--0412`).

use crypto_primitives::sha::sha256;

use crate::domain::{ContactCard, ContactFieldKind, ContactRelationKind};

/// The content type of a rendered card.
pub const VCARD_CONTENT_TYPE: &str = "text/vcard; charset=utf-8";

/// Octets per physical line, CRLF excluded (RFC 6350 §3.2).
const FOLD_AT: usize = 75;

/// The `UID` of a contact: stable, derived from its Tuta element id.
pub fn contact_uid(element_id: &str) -> String {
    format!("tuta-contact-{element_id}")
}

/// The strong ETag (quoted) of a rendered card: the first 128 bits of
/// its SHA-256, in hex.
pub fn vcard_etag(vcard: &str) -> String {
    let digest = sha256(vcard.as_bytes());
    let hex: String = digest[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("\"{hex}\"")
}

/// Render `card` as a vCard 4.0.
pub fn render_vcard(card: &ContactCard) -> String {
    let mut out = String::new();
    line(&mut out, "BEGIN:VCARD");
    line(&mut out, "VERSION:4.0");
    line(
        &mut out,
        &format!("UID:{}", escape(&contact_uid(&card.element_id))),
    );
    line(&mut out, &format!("FN:{}", escape(&formatted_name(card))));
    line(
        &mut out,
        &format!(
            "N:{}",
            structured(&[
                &card.last_name,
                &card.first_name,
                &card.middle_name,
                &card.title,
                &card.name_suffix,
            ])
        ),
    );
    if !card.nickname.trim().is_empty() {
        line(&mut out, &format!("NICKNAME:{}", escape(&card.nickname)));
    }
    for email in &card.emails {
        if email.value.trim().is_empty() {
            continue;
        }
        let params = type_param(match email.kind {
            ContactFieldKind::Home => Some("home"),
            ContactFieldKind::Work => Some("work"),
            _ => None,
        });
        line(
            &mut out,
            &format!("EMAIL{params}:{}", escape(email.value.trim())),
        );
    }
    for phone in &card.phones {
        if phone.value.trim().is_empty() {
            continue;
        }
        let params = type_param(match phone.kind {
            ContactFieldKind::Home => Some("home"),
            ContactFieldKind::Work => Some("work"),
            ContactFieldKind::Mobile => Some("cell"),
            ContactFieldKind::Fax => Some("fax"),
            _ => None,
        });
        line(
            &mut out,
            &format!("TEL{params}:{}", escape(phone.value.trim())),
        );
    }
    for address in &card.addresses {
        if address.value.trim().is_empty() {
            continue;
        }
        let params = type_param(match address.kind {
            ContactFieldKind::Home => Some("home"),
            ContactFieldKind::Work => Some("work"),
            _ => None,
        });
        // Tuta keeps a postal address as free text: it becomes the
        // street component, line breaks included.
        line(
            &mut out,
            &format!(
                "ADR{params}:{}",
                structured(&["", "", address.value.trim(), "", "", "", ""])
            ),
        );
    }
    if !card.company.trim().is_empty() || !card.department.trim().is_empty() {
        let org = if card.department.trim().is_empty() {
            structured(&[&card.company])
        } else {
            structured(&[&card.company, &card.department])
        };
        line(&mut out, &format!("ORG:{org}"));
    }
    if !card.role.trim().is_empty() {
        line(&mut out, &format!("TITLE:{}", escape(&card.role)));
    }
    if let Some(birthday) = card.birthday.as_deref().and_then(vcard_date) {
        line(&mut out, &format!("BDAY:{birthday}"));
    }
    // ANNIVERSARY may appear once.
    if let Some(anniversary) = card.anniversaries.iter().find_map(|date| vcard_date(date)) {
        line(&mut out, &format!("ANNIVERSARY:{anniversary}"));
    }
    for site in &card.websites {
        let Some(url) = website_url(&site.value) else {
            continue;
        };
        let params = type_param(match site.kind {
            ContactFieldKind::Home => Some("home"),
            ContactFieldKind::Work => Some("work"),
            _ => None,
        });
        line(&mut out, &format!("URL{params}:{url}"));
    }
    for relation in &card.relations {
        if relation.person.trim().is_empty() {
            continue;
        }
        let kind = match relation.kind {
            ContactRelationKind::Parent => Some("parent"),
            ContactRelationKind::Sibling => Some("sibling"),
            ContactRelationKind::Child => Some("child"),
            ContactRelationKind::Friend => Some("friend"),
            ContactRelationKind::Relative => Some("kin"),
            ContactRelationKind::Spouse => Some("spouse"),
            ContactRelationKind::Partner => Some("sweetheart"),
            ContactRelationKind::Assistant => Some("agent"),
            ContactRelationKind::Manager => Some("co-worker"),
            ContactRelationKind::Other => None,
        };
        let params = type_param(kind);
        line(
            &mut out,
            &format!(
                "RELATED{params};VALUE=text:{}",
                escape(relation.person.trim())
            ),
        );
    }
    if !card.comment.trim().is_empty() {
        line(&mut out, &format!("NOTE:{}", escape(&card.comment)));
    }
    line(&mut out, "END:VCARD");
    out
}

/// `FN` is mandatory: the composed name, else the nickname, the
/// company, the first email or the first phone number.
fn formatted_name(card: &ContactCard) -> String {
    let mut name = [
        card.title.trim(),
        card.first_name.trim(),
        card.middle_name.trim(),
        card.last_name.trim(),
    ]
    .iter()
    .filter(|part| !part.is_empty())
    .copied()
    .collect::<Vec<_>>()
    .join(" ");
    if !name.is_empty() && !card.name_suffix.trim().is_empty() {
        name.push_str(", ");
        name.push_str(card.name_suffix.trim());
    }
    let fallbacks = [
        card.nickname.trim(),
        card.company.trim(),
        card.emails
            .iter()
            .map(|email| email.value.trim())
            .find(|value| !value.is_empty())
            .unwrap_or(""),
        card.phones
            .iter()
            .map(|phone| phone.value.trim())
            .find(|value| !value.is_empty())
            .unwrap_or(""),
    ];
    if name.is_empty() {
        if let Some(fallback) = fallbacks.iter().find(|value| !value.is_empty()) {
            name = (*fallback).to_string();
        }
    }
    name
}

/// `;TYPE=…`, or nothing.
fn type_param(kind: Option<&str>) -> String {
    match kind {
        Some(kind) => format!(";TYPE={kind}"),
        None => String::new(),
    }
}

/// Escape a text value (RFC 6350 §3.4): backslash, comma, semicolon,
/// and every line break as `\n`. Other control characters are dropped.
pub fn escape(value: &str) -> String {
    let normalized = value.replace("\r\n", "\n").replace('\r', "\n");
    let mut out = String::with_capacity(normalized.len());
    for ch in normalized.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            ',' => out.push_str("\\,"),
            ';' => out.push_str("\\;"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push(' '),
            ch if ch.is_control() => {}
            ch => out.push(ch),
        }
    }
    out
}

/// A structured value: each component escaped, joined with `;`.
fn structured(components: &[&str]) -> String {
    components
        .iter()
        .map(|component| escape(component.trim()))
        .collect::<Vec<_>>()
        .join(";")
}

/// A Tuta ISO date (`YYYY-MM-DD`, `--MM-DD`) in vCard basic form, or
/// `None` when it is not one.
pub fn vcard_date(iso: &str) -> Option<String> {
    let iso = iso.trim();
    let digits =
        |part: &str, len: usize| part.len() == len && part.bytes().all(|b| b.is_ascii_digit());
    if let Some(rest) = iso.strip_prefix("--") {
        let (month, day) = rest.split_once('-')?;
        return (digits(month, 2) && digits(day, 2)).then(|| format!("--{month}{day}"));
    }
    let mut parts = iso.split('-');
    let (year, month, day) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    (digits(year, 4) && digits(month, 2) && digits(day, 2)).then(|| format!("{year}{month}{day}"))
}

/// A website as a URI: trimmed, without whitespace controls, with
/// `https://` when it names no scheme (as the Tuta client does).
fn website_url(value: &str) -> Option<String> {
    let url: String = value.trim().chars().filter(|ch| !ch.is_control()).collect();
    if url.is_empty() {
        return None;
    }
    if url.contains("://") || url.starts_with("mailto:") {
        Some(url)
    } else {
        Some(format!("https://{url}"))
    }
}

/// Append one content line, folded, with CRLF.
fn line(out: &mut String, content: &str) {
    out.push_str(&fold(content));
    out.push_str("\r\n");
}

/// Fold a content line at [`FOLD_AT`] octets without splitting a UTF-8
/// sequence. Continuation lines start with a space, which counts toward
/// their 75 octets.
pub fn fold(content: &str) -> String {
    if content.len() <= FOLD_AT {
        return content.to_string();
    }
    let mut out = String::with_capacity(content.len() + content.len() / FOLD_AT * 3);
    let mut used = 0;
    let mut limit = FOLD_AT;
    for ch in content.chars() {
        let width = ch.len_utf8();
        if used + width > limit {
            out.push_str("\r\n ");
            used = 0;
            limit = FOLD_AT - 1;
        }
        out.push(ch);
        used += width;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{ContactField, ContactRelation};

    fn card() -> ContactCard {
        ContactCard {
            list_id: "list".into(),
            element_id: "elem-1".into(),
            first_name: "Ada".into(),
            last_name: "Lovelace".into(),
            ..ContactCard::default()
        }
    }

    fn lines(vcard: &str) -> Vec<&str> {
        assert!(vcard.ends_with("\r\n"));
        vcard.trim_end_matches("\r\n").split("\r\n").collect()
    }

    /// Undo folding: a CRLF followed by a space joins the lines.
    fn unfold(vcard: &str) -> String {
        vcard.replace("\r\n ", "")
    }

    #[test]
    fn a_minimal_card_has_the_mandatory_properties() {
        let vcard = render_vcard(&card());
        assert_eq!(
            lines(&vcard),
            [
                "BEGIN:VCARD",
                "VERSION:4.0",
                "UID:tuta-contact-elem-1",
                "FN:Ada Lovelace",
                "N:Lovelace;Ada;;;",
                "END:VCARD",
            ]
        );
    }

    #[test]
    fn every_mapped_field_renders() {
        let mut card = card();
        card.title = "Dr.".into();
        card.middle_name = "King".into();
        card.name_suffix = "PhD".into();
        card.nickname = "Countess".into();
        card.company = "Analytical, Engines".into();
        card.department = "R&D".into();
        card.role = "Programmer".into();
        card.birthday = Some("1815-12-10".into());
        card.anniversaries = vec!["--06-08".into(), "1835-07-08".into()];
        card.comment = "line one\nline two; with \\ backslash".into();
        card.emails = vec![
            ContactField {
                kind: ContactFieldKind::Home,
                value: "ada@example.invalid".into(),
            },
            ContactField {
                kind: ContactFieldKind::Work,
                value: "work@example.invalid".into(),
            },
            ContactField {
                kind: ContactFieldKind::Custom,
                value: "other@example.invalid".into(),
            },
            ContactField {
                kind: ContactFieldKind::Other,
                value: "  ".into(),
            },
        ];
        card.phones = vec![
            ContactField {
                kind: ContactFieldKind::Mobile,
                value: "+44 1".into(),
            },
            ContactField {
                kind: ContactFieldKind::Fax,
                value: "+44 2".into(),
            },
            ContactField {
                kind: ContactFieldKind::Work,
                value: "+44 3".into(),
            },
            ContactField {
                kind: ContactFieldKind::Home,
                value: "+44 4".into(),
            },
        ];
        card.addresses = vec![ContactField {
            kind: ContactFieldKind::Home,
            value: "12 St James's Square\nLondon".into(),
        }];
        card.websites = vec![ContactField {
            kind: ContactFieldKind::Work,
            value: "example.invalid/ada".into(),
        }];
        card.relations = vec![ContactRelation {
            kind: ContactRelationKind::Parent,
            person: "Lord Byron".into(),
        }];
        let vcard = unfold(&render_vcard(&card));
        let lines = lines(&vcard);
        for expected in [
            "FN:Dr. Ada King Lovelace\\, PhD",
            "N:Lovelace;Ada;King;Dr.;PhD",
            "NICKNAME:Countess",
            "EMAIL;TYPE=home:ada@example.invalid",
            "EMAIL;TYPE=work:work@example.invalid",
            "EMAIL:other@example.invalid",
            "TEL;TYPE=cell:+44 1",
            "TEL;TYPE=fax:+44 2",
            "TEL;TYPE=work:+44 3",
            "TEL;TYPE=home:+44 4",
            "ADR;TYPE=home:;;12 St James's Square\\nLondon;;;;",
            "ORG:Analytical\\, Engines;R&D",
            "TITLE:Programmer",
            "BDAY:18151210",
            "ANNIVERSARY:--0608",
            "URL;TYPE=work:https://example.invalid/ada",
            "RELATED;TYPE=parent;VALUE=text:Lord Byron",
            "NOTE:line one\\nline two\\; with \\\\ backslash",
        ] {
            assert!(
                lines.contains(&expected),
                "missing {expected:?} in {lines:?}"
            );
        }
        // The blank email is skipped, and only one ANNIVERSARY appears.
        assert_eq!(lines.iter().filter(|l| l.starts_with("EMAIL")).count(), 3);
        assert_eq!(
            lines
                .iter()
                .filter(|l| l.starts_with("ANNIVERSARY"))
                .count(),
            1
        );
    }

    #[test]
    fn escaping_covers_the_special_characters() {
        assert_eq!(escape("a,b;c\\d\ne\r\nf\rg"), "a\\,b\\;c\\\\d\\ne\\nf\\ng");
        assert_eq!(escape("tab\there\u{7}"), "tab here");
        assert_eq!(escape("ünïcødé"), "ünïcødé");
    }

    #[test]
    fn folding_keeps_lines_within_75_octets_and_utf8_intact() {
        let long = format!(
            "NOTE:{}",
            "é".repeat(100) + &"x".repeat(50) + &"😀".repeat(30)
        );
        let folded = fold(&long);
        for (index, physical) in folded.split("\r\n").enumerate() {
            assert!(
                physical.len() <= 75,
                "line {index} has {} octets",
                physical.len()
            );
            if index > 0 {
                assert!(physical.starts_with(' '));
            }
        }
        // Folding is reversible.
        assert_eq!(folded.replace("\r\n ", ""), long);
        // A short line is untouched; one of exactly 75 octets too.
        assert_eq!(fold("FN:x"), "FN:x");
        let exact = "x".repeat(75);
        assert_eq!(fold(&exact), exact);
        assert_eq!(fold(&"x".repeat(76)), format!("{}\r\n x", "x".repeat(75)));
    }

    #[test]
    fn a_rendered_card_is_folded_and_crlf_only() {
        let mut card = card();
        card.comment = "ä".repeat(200);
        let vcard = render_vcard(&card);
        for physical in vcard.split("\r\n") {
            assert!(physical.len() <= 75);
            assert!(!physical.contains('\n') && !physical.contains('\r'));
        }
        assert!(unfold(&vcard).contains(&format!("NOTE:{}", "ä".repeat(200))));
    }

    #[test]
    fn dates_convert_to_basic_form_or_are_dropped() {
        assert_eq!(vcard_date("1990-01-15").as_deref(), Some("19900115"));
        assert_eq!(vcard_date("--01-15").as_deref(), Some("--0115"));
        for invalid in [
            "",
            "1990",
            "1990-1-15",
            "--0115",
            "abcd-01-15",
            "1990-01-15-01",
        ] {
            assert_eq!(vcard_date(invalid), None, "{invalid:?}");
        }
    }

    #[test]
    fn fn_falls_back_when_there_is_no_name() {
        let mut card = ContactCard {
            element_id: "e".into(),
            ..ContactCard::default()
        };
        card.emails = vec![ContactField {
            kind: ContactFieldKind::Other,
            value: "x@example.invalid".into(),
        }];
        assert!(render_vcard(&card).contains("\r\nFN:x@example.invalid\r\n"));
        card.company = "ACME".into();
        assert!(render_vcard(&card).contains("\r\nFN:ACME\r\n"));
        card.nickname = "Nick".into();
        assert!(render_vcard(&card).contains("\r\nFN:Nick\r\n"));
    }

    #[test]
    fn the_etag_is_stable_and_content_derived() {
        let first = render_vcard(&card());
        assert_eq!(vcard_etag(&first), vcard_etag(&render_vcard(&card())));
        assert_eq!(vcard_etag(&first).len(), 34);
        let mut changed = card();
        changed.nickname = "A".into();
        assert_ne!(vcard_etag(&first), vcard_etag(&render_vcard(&changed)));
    }
}
