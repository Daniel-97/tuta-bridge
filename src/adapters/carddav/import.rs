//! Import the vCard 4.0 body of a CardDAV `PUT` into the writable
//! contact fields: the exact inverse of [`super::vcard`]'s render,
//! the field mapping of the plan's decision 1.
//!
//! - Folding is undone first: a line that starts with a space or a
//!   tab continues the previous one, and both CRLF and LF bodies are
//!   accepted (the RFC demands CRLF; real clients send both).
//! - Only the first vCard of the body is imported, and a body
//!   without a complete `BEGIN:VCARD`…`END:VCARD` pair is refused.
//!   [`ImportError`] carries fixed messages only — no fragment of
//!   the card, no name, address or note ever reaches an error, and
//!   this module never logs.
//! - The mapped properties are the ones the renderer emits plus the
//!   standard variations the common clients write: vCard 3.0
//!   grouping (`item1.TEL`), bare and quoted `TYPE` parameters.
//!   `FN` fills the first name only when the card carries no `N`.
//!   Every other property — `VERSION`, `PRODID`, `REV`, `UID` (the
//!   href owns the identity), `PHOTO`, `CATEGORIES`, `GEO`, `TZ`,
//!   every `X-` property and every unrecognized name — is dropped
//!   silently, exactly like Tuta's own importer: what the bridge
//!   never served was never supported. An unknown property never
//!   fails the import.
//! - Dates must be in the basic form the renderer serves
//!   (`19900115`, `--0412`); any other shape refuses the whole card
//!   — fail closed — instead of importing a silently changed date.
//! - Two renderer losses carry over: it writes no `TYPE` for both
//!   Other and Custom fields, so an exported Other field re-imports
//!   as Custom and only a client's explicit `TYPE=other` reaches
//!   the reader's Other; and it serves one anniversary at most,
//!   while the importer accepts every `ANNIVERSARY` property.

use std::fmt;

use crate::domain::{ContactField, ContactFieldKind, ContactRelation, ContactRelationKind};
use crate::ports::dav_writer::ContactFields;

/// Why a body could not be imported. The messages are fixed: no id,
/// name, address or note ever appears in one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportError {
    /// The body holds no complete `BEGIN:VCARD`…`END:VCARD` pair.
    NoVcard,
    /// A `BDAY` or `ANNIVERSARY` value is not a date in the basic
    /// form the bridge serves.
    BadDate,
}

impl ImportError {
    /// The fixed message of the failure.
    pub fn message(&self) -> &'static str {
        match self {
            ImportError::NoVcard => "the request body holds no complete vcard",
            ImportError::BadDate => "a date property is not in the basic form the bridge serves",
        }
    }
}

impl fmt::Display for ImportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

/// Import the first vCard of `body` (a client sends one card per
/// `PUT`). The body is parsed in memory and never written anywhere;
/// an unrecognized property is dropped silently, a date that cannot
/// be mapped refuses the whole import.
pub fn parse_vcard(body: &str) -> Result<ContactFields, ImportError> {
    let mut fields = ContactFields::default();
    let mut seen = Seen::default();
    let mut inside = false;
    let mut terminated = false;
    for line in unfold(body) {
        let Some(property) = Property::parse(&line) else {
            continue;
        };
        if !inside {
            if property.begins_card() {
                inside = true;
            }
            continue;
        }
        if property.ends_card() {
            terminated = true;
            break;
        }
        apply(&mut fields, &mut seen, &property)?;
    }
    if !inside || !terminated {
        return Err(ImportError::NoVcard);
    }
    // A card without an N keeps a display name at least: FN is what
    // the renderer derives there and what Tuta shows without one.
    if !seen.n {
        if let Some(formatted) = seen.formatted {
            fields.first_name = formatted.trim().to_string();
        }
    }
    Ok(fields)
}

/// Which single-valued properties were already applied: the first
/// occurrence wins, the way the renderer emits exactly one.
#[derive(Default)]
struct Seen {
    n: bool,
    formatted: Option<String>,
    nickname: bool,
    role: bool,
    org: bool,
    note: bool,
    birthday: bool,
}

/// Apply one property. The fall-through arm is the importer's
/// contract: what the renderer never emits was never supported.
fn apply(
    fields: &mut ContactFields,
    seen: &mut Seen,
    property: &Property,
) -> Result<(), ImportError> {
    match property.name.as_str() {
        // A nested BEGIN (concatenated cards) is none of the
        // importer's business: the first END closed the card.
        "BEGIN" => {}
        "N" => {
            if !seen.n {
                seen.n = true;
                let parts = split_components(&property.value);
                fields.last_name = text_component(&parts, 0);
                fields.first_name = text_component(&parts, 1);
                fields.middle_name = text_component(&parts, 2);
                fields.title = text_component(&parts, 3);
                fields.name_suffix = text_component(&parts, 4);
            }
        }
        "FN" => {
            if seen.formatted.is_none() {
                seen.formatted = Some(unescape(&property.value));
            }
        }
        "NICKNAME" => {
            if !seen.nickname {
                seen.nickname = true;
                fields.nickname = unescape(&property.value);
            }
        }
        // The renderer writes the job title as TITLE; ROLE is the
        // standard variant of the same field. The first of the two
        // wins, in document order.
        "TITLE" | "ROLE" => {
            if !seen.role {
                seen.role = true;
                fields.role = unescape(&property.value);
            }
        }
        "ORG" => {
            if !seen.org {
                seen.org = true;
                let parts = split_components(&property.value);
                fields.company = text_component(&parts, 0);
                fields.department = text_component(&parts, 1);
            }
        }
        // Every date property must parse, even after a valid one:
        // a date we cannot map refuses the card, never a silent
        // truncation.
        "BDAY" => {
            let iso = iso_date(&property.value)?;
            if !seen.birthday {
                seen.birthday = true;
                fields.birthday = Some(iso);
            }
        }
        "ANNIVERSARY" => fields.anniversaries.push(iso_date(&property.value)?),
        "NOTE" => {
            if !seen.note {
                seen.note = true;
                fields.comment = unescape(&property.value);
            }
        }
        "EMAIL" => {
            let value = unescape(&property.value).trim().to_string();
            if !value.is_empty() {
                fields.emails.push(ContactField {
                    kind: address_kind(&property.types),
                    value,
                });
            }
        }
        "TEL" => {
            let value = unescape(&property.value).trim().to_string();
            if !value.is_empty() {
                fields.phones.push(ContactField {
                    kind: phone_kind(&property.types),
                    value,
                });
            }
        }
        "ADR" => {
            // Tuta keeps an address as free text, so every non-empty
            // component becomes one line of it — the renderer's
            // inverse (it writes the whole address into the street
            // component) extended to the components a client fills.
            let address = split_components(&property.value)
                .iter()
                .map(|part| unescape(part).trim().to_string())
                .filter(|part| !part.is_empty())
                .collect::<Vec<_>>()
                .join("\n");
            if !address.is_empty() {
                fields.addresses.push(ContactField {
                    kind: address_kind(&property.types),
                    value: address,
                });
            }
        }
        // A URI the renderer writes unescaped: taken as-is.
        "URL" => {
            let value = property.value.trim().to_string();
            if !value.is_empty() {
                fields.websites.push(ContactField {
                    kind: address_kind(&property.types),
                    value,
                });
            }
        }
        "RELATED" => {
            let person = unescape(&property.value).trim().to_string();
            if !person.is_empty() {
                fields.relations.push(ContactRelation {
                    kind: relation_kind(&property.types),
                    person,
                });
            }
        }
        _ => {}
    }
    Ok(())
}

/// One unfolded content line: the ungrouped, upper-case property
/// name, every `TYPE` value, and the raw value after the colon.
struct Property {
    name: String,
    types: Vec<String>,
    value: String,
}

impl Property {
    /// Parse one unfolded content line; `None` for a line without a
    /// colon (never a property, never an error).
    fn parse(line: &str) -> Option<Property> {
        let colon = unquoted_find(line, ':')?;
        let value = line[colon + 1..].to_string();
        let segments = split_outside_quotes(&line[..colon], ';');
        let name = ungrouped(segments[0].trim()).to_ascii_uppercase();
        if name.is_empty() {
            return None;
        }
        let mut types = Vec::new();
        for segment in segments.iter().skip(1) {
            if let Some(equals) = unquoted_find(segment, '=') {
                if segment[..equals].trim().eq_ignore_ascii_case("type") {
                    types.extend(split_types(&segment[equals + 1..]));
                }
            } else {
                // A bare vCard 3.0 parameter (TEL;CELL:+44 1).
                types.push(segment.trim().to_ascii_lowercase());
            }
        }
        Some(Property { name, types, value })
    }

    fn begins_card(&self) -> bool {
        self.name == "BEGIN" && self.value.trim().eq_ignore_ascii_case("VCARD")
    }

    fn ends_card(&self) -> bool {
        self.name == "END" && self.value.trim().eq_ignore_ascii_case("VCARD")
    }
}

/// Undo folding: a physical line that starts with a space or a tab
/// continues the previous one, the marker character itself dropped.
/// Both CRLF and LF line ends are accepted.
fn unfold(body: &str) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    for physical in body.split('\n') {
        let physical = physical.strip_suffix('\r').unwrap_or(physical);
        if let Some(continuation) = physical
            .strip_prefix(' ')
            .or_else(|| physical.strip_prefix('\t'))
        {
            if let Some(last) = lines.last_mut() {
                last.push_str(continuation);
                continue;
            }
            // Nothing to continue: the body starts mid-fold. Drop
            // the orphan fragment rather than invent content.
            continue;
        }
        lines.push(physical.to_string());
    }
    lines
}

/// The property name without its vCard 3.0 grouping prefix
/// (`item1.TEL` → `TEL`): names contain no dot otherwise.
fn ungrouped(name: &str) -> &str {
    match name.rsplit_once('.') {
        Some((_, real)) if !real.is_empty() => real,
        _ => name,
    }
}

/// The byte index of the first `target` outside double quotes.
fn unquoted_find(text: &str, target: char) -> Option<usize> {
    let mut quoted = false;
    for (index, ch) in text.char_indices() {
        if ch == '"' {
            quoted = !quoted;
        } else if ch == target && !quoted {
            return Some(index);
        }
    }
    None
}

/// Split on the `target` characters outside double quotes.
fn split_outside_quotes(text: &str, target: char) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    for ch in text.chars() {
        if ch == '"' {
            quoted = !quoted;
            current.push(ch);
        } else if ch == target && !quoted {
            parts.push(std::mem::take(&mut current));
        } else {
            current.push(ch);
        }
    }
    parts.push(current);
    parts
}

/// The values of a `TYPE` parameter: the quote characters are
/// delimiters and dropped, commas separate the values —
/// `TYPE="work,voice"` is the RFC's own example form — and each
/// piece is trimmed and lower-cased.
fn split_types(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(|piece| piece.trim_matches('"').trim().to_ascii_lowercase())
        .collect()
}

/// Split a structured value into its components: an unescaped
/// semicolon separates two, and a backslash escapes the next
/// character (which stays for [`unescape`] to read).
fn split_components(value: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut escaped = false;
    for ch in value.chars() {
        if escaped {
            current.push('\\');
            current.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == ';' {
            parts.push(std::mem::take(&mut current));
        } else {
            current.push(ch);
        }
    }
    if escaped {
        current.push('\\');
    }
    parts.push(current);
    parts
}

/// Component `index` of a structured value, unescaped and trimmed —
/// the inverse of the renderer's `structured`, which trims every
/// component it writes.
fn text_component(parts: &[String], index: usize) -> String {
    parts
        .get(index)
        .map(|part| unescape(part).trim().to_string())
        .unwrap_or_default()
}

/// Unescape a text value, the exact inverse of the renderer's
/// `vcard::escape` for the escapes it produces (`\\`, `\,`, `\;`,
/// `\n` and `\N`). A backslash before anything else survives (both
/// characters kept), and so does a trailing lone one: better a
/// literal backslash in a note than a lost one.
fn unescape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some('\\') => out.push('\\'),
            Some(',') => out.push(','),
            Some(';') => out.push(';'),
            Some('n') | Some('N') => out.push('\n'),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

/// The inverse of the renderer's `vcard_date`: a basic-form date
/// (`19900115`, `--0412`) back to Tuta's ISO form. Anything else
/// refuses the import — a date that cannot be mapped exactly must
/// not become a silently different one.
fn iso_date(basic: &str) -> Result<String, ImportError> {
    let basic = basic.trim();
    if let Some(rest) = basic.strip_prefix("--") {
        if rest.len() == 4 && rest.bytes().all(|byte| byte.is_ascii_digit()) {
            return Ok(format!("--{}-{}", &rest[..2], &rest[2..]));
        }
        return Err(ImportError::BadDate);
    }
    if basic.len() == 8 && basic.bytes().all(|byte| byte.is_ascii_digit()) {
        return Ok(format!("{}-{}-{}", &basic[..4], &basic[4..6], &basic[6..]));
    }
    Err(ImportError::BadDate)
}

/// The `TYPE` values of an email, address or website, mapped back
/// onto the reader's table (`ContactAddressType` /
/// `ContactWebsiteType`: PRIVATE 0, WORK 1, OTHER 2, CUSTOM 3).
/// The first recognized value decides — the renderer writes one —
/// and a `TYPE` we do not know, or none at all, is a custom label:
/// the renderer writes custom labels without a `TYPE`.
fn address_kind(types: &[String]) -> ContactFieldKind {
    if types.iter().any(|kind| kind == "home" || kind == "private") {
        ContactFieldKind::Home
    } else if types.iter().any(|kind| kind == "work") {
        ContactFieldKind::Work
    } else if types.iter().any(|kind| kind == "other") {
        ContactFieldKind::Other
    } else {
        ContactFieldKind::Custom
    }
}

/// The `TYPE` values of a phone, mapped back onto the reader's
/// table (`ContactPhoneNumberType`: PRIVATE 0, WORK 1, MOBILE 2,
/// FAX 3, OTHER 4, CUSTOM 5).
fn phone_kind(types: &[String]) -> ContactFieldKind {
    if types.iter().any(|kind| kind == "home" || kind == "private") {
        ContactFieldKind::Home
    } else if types.iter().any(|kind| kind == "work") {
        ContactFieldKind::Work
    } else if types.iter().any(|kind| kind == "cell" || kind == "mobile") {
        ContactFieldKind::Mobile
    } else if types.iter().any(|kind| kind == "fax") {
        ContactFieldKind::Fax
    } else if types.iter().any(|kind| kind == "other") {
        ContactFieldKind::Other
    } else {
        ContactFieldKind::Custom
    }
}

/// The `TYPE` values of a relation, mapped back onto the reader's
/// table (`ContactRelationshipType`). No `TYPE` — the renderer's
/// form of Other — and an unrecognized one both stay Other: the
/// reader folds CUSTOM 11 into Other as well.
fn relation_kind(types: &[String]) -> ContactRelationKind {
    for kind in types {
        match kind.as_str() {
            "parent" => return ContactRelationKind::Parent,
            "sibling" | "brother" | "sister" => return ContactRelationKind::Sibling,
            "child" => return ContactRelationKind::Child,
            "friend" => return ContactRelationKind::Friend,
            "kin" | "relative" => return ContactRelationKind::Relative,
            "spouse" => return ContactRelationKind::Spouse,
            "sweetheart" | "partner" => return ContactRelationKind::Partner,
            "agent" | "assistant" => return ContactRelationKind::Assistant,
            "co-worker" | "manager" => return ContactRelationKind::Manager,
            _ => {}
        }
    }
    ContactRelationKind::Other
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::carddav::vcard::{escape, fold, render_vcard};
    use crate::domain::ContactCard;

    /// The card's writable fields, copied one by one: what a round
    /// trip must reproduce.
    fn fields_of(card: &ContactCard) -> ContactFields {
        ContactFields {
            title: card.title.clone(),
            first_name: card.first_name.clone(),
            middle_name: card.middle_name.clone(),
            last_name: card.last_name.clone(),
            name_suffix: card.name_suffix.clone(),
            nickname: card.nickname.clone(),
            company: card.company.clone(),
            department: card.department.clone(),
            role: card.role.clone(),
            birthday: card.birthday.clone(),
            anniversaries: card.anniversaries.clone(),
            comment: card.comment.clone(),
            emails: card.emails.clone(),
            phones: card.phones.clone(),
            addresses: card.addresses.clone(),
            websites: card.websites.clone(),
            relations: card.relations.clone(),
        }
    }

    /// Field-by-field comparison. `ContactFields` holds personal
    /// data and has no `Debug`, so a failure names the field, never
    /// a value.
    fn assert_same(actual: &ContactFields, expected: &ContactFields) {
        for (name, actual, expected) in [
            ("title", &actual.title, &expected.title),
            ("first name", &actual.first_name, &expected.first_name),
            ("middle name", &actual.middle_name, &expected.middle_name),
            ("last name", &actual.last_name, &expected.last_name),
            ("name suffix", &actual.name_suffix, &expected.name_suffix),
            ("nickname", &actual.nickname, &expected.nickname),
            ("company", &actual.company, &expected.company),
            ("department", &actual.department, &expected.department),
            ("role", &actual.role, &expected.role),
            ("comment", &actual.comment, &expected.comment),
        ] {
            assert!(actual == expected, "{name} mismatch");
        }
        assert!(actual.birthday == expected.birthday, "birthday mismatch");
        assert!(
            actual.anniversaries == expected.anniversaries,
            "anniversaries mismatch"
        );
        for (name, actual, expected) in [
            ("emails", &actual.emails, &expected.emails),
            ("phones", &actual.phones, &expected.phones),
            ("addresses", &actual.addresses, &expected.addresses),
            ("websites", &actual.websites, &expected.websites),
        ] {
            assert!(actual.len() == expected.len(), "{name} count mismatch");
            for (index, (actual, expected)) in actual.iter().zip(expected.iter()).enumerate() {
                assert!(actual.kind == expected.kind, "{name} {index} kind mismatch");
                assert!(
                    actual.value == expected.value,
                    "{name} {index} value mismatch"
                );
            }
        }
        assert!(
            actual.relations.len() == expected.relations.len(),
            "relations count mismatch"
        );
        for (index, (actual, expected)) in actual
            .relations
            .iter()
            .zip(expected.relations.iter())
            .enumerate()
        {
            assert!(
                actual.kind == expected.kind,
                "relations {index} kind mismatch"
            );
            assert!(
                actual.person == expected.person,
                "relations {index} person mismatch"
            );
        }
    }

    /// The renderer test's own fixture (vcard.rs): the same input,
    /// so both sides of the round trip share one card.
    fn renderer_fixture() -> ContactCard {
        let mut card = ContactCard {
            list_id: "list".into(),
            element_id: "elem-1".into(),
            first_name: "Ada".into(),
            last_name: "Lovelace".into(),
            ..ContactCard::default()
        };
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
        card
    }

    #[test]
    fn round_trips_the_renderers_own_fixture() {
        let card = renderer_fixture();
        let parsed = parse_vcard(&render_vcard(&card)).unwrap();
        let mut expected = fields_of(&card);
        // The renderer serves one anniversary at most.
        expected.anniversaries = vec!["--06-08".into()];
        // A website without a scheme gains https:// on the way out.
        expected.websites = vec![ContactField {
            kind: ContactFieldKind::Work,
            value: "https://example.invalid/ada".into(),
        }];
        // The blank email is never rendered, so never imported.
        expected.emails.truncate(3);
        assert_same(&parsed, &expected);
    }

    /// A card hostile to the format: every escape-worthy character
    /// in every mapped field, all phone and address kinds, every
    /// relation kind, and a note long enough to be folded.
    fn hostile_card() -> ContactCard {
        let mut card = ContactCard {
            list_id: "list".into(),
            element_id: "elem-2".into(),
            title: "Dr.;".into(),
            first_name: "Ada\\".into(),
            middle_name: "B.,".into(),
            last_name: "Lovelace, of; Lovelace".into(),
            name_suffix: "PhD,".into(),
            ..ContactCard::default()
        };
        card.nickname = "Countess; of,\nAnalytical".into();
        card.company = "Analytical, Engines; Ltd".into();
        card.department = "R&D; Dev,Ops".into();
        card.role = "Programmer; senior".into();
        card.birthday = Some("--07-10".into());
        card.anniversaries = vec!["1837-01-01".into()];
        card.comment = "first; line\nsecond, line\\third\n\
                        and a long final line that the renderer folds \
                        across physical lines, all of it imported back."
            .into();
        card.emails = vec![
            ContactField {
                kind: ContactFieldKind::Home,
                value: "a@x.invalid".into(),
            },
            ContactField {
                kind: ContactFieldKind::Work,
                value: "w@x.invalid".into(),
            },
            ContactField {
                kind: ContactFieldKind::Custom,
                value: "c@x.invalid".into(),
            },
        ];
        card.phones = vec![
            ContactField {
                kind: ContactFieldKind::Mobile,
                value: "+1 1".into(),
            },
            ContactField {
                kind: ContactFieldKind::Fax,
                value: "+1 2".into(),
            },
            ContactField {
                kind: ContactFieldKind::Work,
                value: "+1 3".into(),
            },
            ContactField {
                kind: ContactFieldKind::Home,
                value: "+1 4".into(),
            },
            ContactField {
                kind: ContactFieldKind::Custom,
                value: "+1 5".into(),
            },
        ];
        card.addresses = vec![
            ContactField {
                kind: ContactFieldKind::Home,
                value: "12 St James's Square\nLondon\nSW1".into(),
            },
            ContactField {
                kind: ContactFieldKind::Work,
                value: "2 Work Rd".into(),
            },
            ContactField {
                kind: ContactFieldKind::Custom,
                value: "3 Custom Pl".into(),
            },
        ];
        card.websites = vec![
            ContactField {
                kind: ContactFieldKind::Work,
                value: "https://x.invalid/w".into(),
            },
            ContactField {
                kind: ContactFieldKind::Home,
                value: "https://x.invalid/h".into(),
            },
            ContactField {
                kind: ContactFieldKind::Custom,
                value: "https://x.invalid/c".into(),
            },
        ];
        card.relations = vec![
            ContactRelation {
                kind: ContactRelationKind::Parent,
                person: "Ann".into(),
            },
            ContactRelation {
                kind: ContactRelationKind::Sibling,
                person: "Ben".into(),
            },
            ContactRelation {
                kind: ContactRelationKind::Child,
                person: "Cy".into(),
            },
            ContactRelation {
                kind: ContactRelationKind::Friend,
                person: "Fay".into(),
            },
            ContactRelation {
                kind: ContactRelationKind::Relative,
                person: "Ray".into(),
            },
            ContactRelation {
                kind: ContactRelationKind::Spouse,
                person: "Sam".into(),
            },
            ContactRelation {
                kind: ContactRelationKind::Partner,
                person: "Pat".into(),
            },
            ContactRelation {
                kind: ContactRelationKind::Assistant,
                person: "Ash".into(),
            },
            ContactRelation {
                kind: ContactRelationKind::Manager,
                person: "Manny".into(),
            },
            ContactRelation {
                kind: ContactRelationKind::Other,
                person: "Otto".into(),
            },
        ];
        card
    }

    #[test]
    fn round_trips_an_escape_hostile_card() {
        let card = hostile_card();
        let parsed = parse_vcard(&render_vcard(&card)).unwrap();
        assert_same(&parsed, &fields_of(&card));
    }

    #[test]
    fn round_trips_a_minimal_card() {
        let card = ContactCard {
            list_id: "list".into(),
            element_id: "elem-3".into(),
            first_name: "Ada".into(),
            last_name: "Lovelace".into(),
            ..ContactCard::default()
        };
        let parsed = parse_vcard(&render_vcard(&card)).unwrap();
        assert_same(&parsed, &fields_of(&card));
    }

    #[test]
    fn the_render_never_distinguishes_other_from_custom() {
        // The renderer writes no TYPE for both Other and Custom
        // fields, so an exported Other field re-imports as Custom:
        // only a client's explicit TYPE=other reaches the reader's
        // Other. Pinned, so a renderer change cannot pass silently.
        let card = ContactCard {
            list_id: "list".into(),
            element_id: "elem-4".into(),
            emails: vec![ContactField {
                kind: ContactFieldKind::Other,
                value: "o@x.invalid".into(),
            }],
            ..ContactCard::default()
        };
        let parsed = parse_vcard(&render_vcard(&card)).unwrap();
        assert!(parsed.emails[0].kind == ContactFieldKind::Custom);
    }

    #[test]
    fn folded_lines_unfold_from_crlf_lf_and_tab_continuations() {
        let content = format!("NOTE:{}", "a ".repeat(50));
        let folded = fold(&content);
        assert!(folded.contains("\r\n "), "the fixture is folded");

        let body = format!("BEGIN:VCARD\r\n{folded}\r\nEND:VCARD\r\n");
        let crlf = parse_vcard(&body).unwrap();
        assert_eq!(crlf.comment, "a ".repeat(50));

        // The same body with bare LF line ends, as some clients send.
        let lf_body = body.replace("\r\n", "\n");
        let lf = parse_vcard(&lf_body).unwrap();
        assert_eq!(lf.comment, "a ".repeat(50));

        // A tab continuation, the other legal marker.
        let tab = parse_vcard("BEGIN:VCARD\nNOTE:one\n\ttwo\nEND:VCARD\n").unwrap();
        assert_eq!(tab.comment, "onetwo");
    }

    #[test]
    fn grouped_quoted_and_bare_parameters_are_accepted() {
        let body = concat!(
            "BEGIN:VCARD\r\n",
            "item1.EMAIL;TYPE=home:ada@example.invalid\r\n",
            "ITEM2.TEL;CELL:+44 5\r\n",
            "TEL;TYPE=\"work,voice\":+44 6\r\n",
            "item3.ADR;TYPE=home:;;Hood\r\n",
            "END:VCARD\r\n",
        );
        let parsed = parse_vcard(body).unwrap();
        assert!(parsed.emails[0].kind == ContactFieldKind::Home);
        assert_eq!(parsed.emails[0].value, "ada@example.invalid");
        assert!(parsed.phones[0].kind == ContactFieldKind::Mobile);
        assert!(parsed.phones[1].kind == ContactFieldKind::Work);
        assert!(parsed.addresses[0].kind == ContactFieldKind::Home);
        assert_eq!(parsed.addresses[0].value, "Hood");
    }

    #[test]
    fn unrecognized_properties_are_dropped_silently() {
        let body = concat!(
            "BEGIN:VCARD\r\n",
            "VERSION:3.0\r\n",
            "PRODID:-//Example//EN\r\n",
            "REV:2026-11-24T10:00:00Z\r\n",
            "UID:client-side-id\r\n",
            "FN:Ignored Display\r\n",
            "N:Last;First;;;\r\n",
            "PHOTO:SGVsbG8\r\n",
            " d29ybGQ=\r\n",
            "CATEGORIES:work,friends\r\n",
            "GEO:37.386013;-122.082932\r\n",
            "TZ:Europe/Rome\r\n",
            "X-TUTA-THING:value\r\n",
            "X-SIGNATURE:folded signature\r\n",
            " continued here\r\n",
            "ADR;LABEL=\"a;b\":;;Street;;;;\r\n",
            "a colon-less line\r\n",
            "END:VCARD\r\n",
        );
        let parsed = parse_vcard(body).unwrap();
        let expected = ContactFields {
            first_name: "First".into(),
            last_name: "Last".into(),
            addresses: vec![ContactField {
                kind: ContactFieldKind::Custom,
                value: "Street".into(),
            }],
            ..ContactFields::default()
        };
        assert_same(&parsed, &expected);
    }

    /// The error of a refused body: the fields carry personal data
    /// and have no `Debug`, so there is no `unwrap_err` to call.
    fn refused(body: &str) -> ImportError {
        match parse_vcard(body) {
            Err(error) => error,
            Ok(_) => panic!("the body was imported; a refusal was expected"),
        }
    }

    #[test]
    fn a_body_without_a_complete_vcard_is_refused() {
        for body in [
            "",
            "not a vcard",
            "BEGIN:VCARD\r\nFN:X\r\n",
            "BEGIN:VCARD",
            "BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n",
        ] {
            let error = refused(body);
            assert!(error == ImportError::NoVcard);
            assert_eq!(error.message(), "the request body holds no complete vcard");
        }
    }

    #[test]
    fn only_the_first_vcard_is_imported() {
        let body = concat!(
            "BEGIN:VCARD\r\n",
            "N:One;A;;;\r\n",
            "NOTE:first card\r\n",
            "END:VCARD\r\n",
            "BEGIN:VCARD\r\n",
            "N:Two;B;;;\r\n",
            "END:VCARD\r\n",
        );
        let parsed = parse_vcard(body).unwrap();
        assert_eq!(parsed.last_name, "One");
        assert_eq!(parsed.first_name, "A");
        assert_eq!(parsed.comment, "first card");
    }

    #[test]
    fn a_date_we_cannot_map_refuses_the_whole_card() {
        for property in [
            "BDAY:1990-01-15",
            "BDAY:1990",
            "BDAY:19900115T1200Z",
            "BDAY:--115",
            "ANNIVERSARY:x",
            "ANNIVERSARY:1985-04-12",
            // Even after a valid date: fail closed, never truncate.
            "BDAY:19900115\r\nBDAY:April",
        ] {
            let body = format!("BEGIN:VCARD\r\n{property}\r\nEND:VCARD\r\n");
            let error = refused(&body);
            assert!(error == ImportError::BadDate, "{property:?}");
            assert_eq!(
                error.message(),
                "a date property is not in the basic form the bridge serves"
            );
        }
    }

    #[test]
    fn fn_fills_the_first_name_only_without_an_n() {
        // The shape the refused-write test sends (carddav.rs): FN
        // and nothing else.
        let body = "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:X\r\nEND:VCARD\r\n";
        let parsed = parse_vcard(body).unwrap();
        assert_eq!(parsed.first_name, "X");

        // With an N, FN stays derived and is ignored.
        let body = "BEGIN:VCARD\r\nFN:Display Name\r\nN:Last;First;;;\r\nEND:VCARD\r\n";
        let parsed = parse_vcard(body).unwrap();
        assert_eq!(parsed.first_name, "First");
        assert_eq!(parsed.last_name, "Last");
    }

    #[test]
    fn type_parameters_map_back_onto_the_reader_tables() {
        let body = concat!(
            "BEGIN:VCARD\r\n",
            "EMAIL;TYPE=home:e1@x.invalid\r\n",
            "EMAIL;TYPE=PRIVATE:e2@x.invalid\r\n",
            "EMAIL;TYPE=work:e3@x.invalid\r\n",
            "EMAIL;TYPE=other:e4@x.invalid\r\n",
            "EMAIL;TYPE=custom-label:e5@x.invalid\r\n",
            "EMAIL:e6@x.invalid\r\n",
            "EMAIL;TYPE=\"home,pref\":e7@x.invalid\r\n",
            "TEL;TYPE=cell:t1\r\n",
            "TEL;TYPE=MOBILE:t2\r\n",
            "TEL;TYPE=fax:t3\r\n",
            "TEL;TYPE=home:t4\r\n",
            "TEL;TYPE=work:t5\r\n",
            "TEL;TYPE=other:t6\r\n",
            "TEL:t7\r\n",
            "TEL;TYPE=pref:t8\r\n",
            "TEL;TYPE=home,cell:t9\r\n",
            "URL;TYPE=home:https://x.invalid/u1\r\n",
            "URL:https://x.invalid/u2\r\n",
            "ADR;TYPE=work:;;W1\r\n",
            "END:VCARD\r\n",
        );
        let parsed = parse_vcard(body).unwrap();
        let email_kind = |index: usize| parsed.emails[index].kind;
        assert!(email_kind(0) == ContactFieldKind::Home);
        assert!(email_kind(1) == ContactFieldKind::Home);
        assert!(email_kind(2) == ContactFieldKind::Work);
        assert!(email_kind(3) == ContactFieldKind::Other);
        assert!(email_kind(4) == ContactFieldKind::Custom);
        assert!(email_kind(5) == ContactFieldKind::Custom);
        assert!(email_kind(6) == ContactFieldKind::Home);
        let phone_kind_at = |index: usize| parsed.phones[index].kind;
        assert!(phone_kind_at(0) == ContactFieldKind::Mobile);
        assert!(phone_kind_at(1) == ContactFieldKind::Mobile);
        assert!(phone_kind_at(2) == ContactFieldKind::Fax);
        assert!(phone_kind_at(3) == ContactFieldKind::Home);
        assert!(phone_kind_at(4) == ContactFieldKind::Work);
        assert!(phone_kind_at(5) == ContactFieldKind::Other);
        assert!(phone_kind_at(6) == ContactFieldKind::Custom);
        assert!(phone_kind_at(7) == ContactFieldKind::Custom);
        // The first recognized value decides.
        assert!(phone_kind_at(8) == ContactFieldKind::Home);
        assert!(parsed.websites[0].kind == ContactFieldKind::Home);
        assert!(parsed.websites[1].kind == ContactFieldKind::Custom);
        assert!(parsed.addresses[0].kind == ContactFieldKind::Work);
        assert_eq!(parsed.emails.len(), 7);
        assert_eq!(parsed.phones.len(), 9);
    }

    #[test]
    fn relation_types_map_back_onto_the_reader_table() {
        let body = concat!(
            "BEGIN:VCARD\r\n",
            "RELATED;TYPE=parent:r1\r\n",
            "RELATED;TYPE=sibling:r2\r\n",
            "RELATED;TYPE=brother:r3\r\n",
            "RELATED;TYPE=sister:r4\r\n",
            "RELATED;TYPE=child:r5\r\n",
            "RELATED;TYPE=friend:r6\r\n",
            "RELATED;TYPE=kin:r7\r\n",
            "RELATED;TYPE=relative:r8\r\n",
            "RELATED;TYPE=spouse:r9\r\n",
            "RELATED;TYPE=sweetheart:r10\r\n",
            "RELATED;TYPE=partner:r11\r\n",
            "RELATED;TYPE=agent:r12\r\n",
            "RELATED;TYPE=assistant:r13\r\n",
            "RELATED;TYPE=co-worker:r14\r\n",
            "RELATED;TYPE=manager:r15\r\n",
            "RELATED;TYPE=contact:r16\r\n",
            "RELATED;VALUE=text:r17\r\n",
            "END:VCARD\r\n",
        );
        let parsed = parse_vcard(body).unwrap();
        let expected = [
            ContactRelationKind::Parent,
            ContactRelationKind::Sibling,
            ContactRelationKind::Sibling,
            ContactRelationKind::Sibling,
            ContactRelationKind::Child,
            ContactRelationKind::Friend,
            ContactRelationKind::Relative,
            ContactRelationKind::Relative,
            ContactRelationKind::Spouse,
            ContactRelationKind::Partner,
            ContactRelationKind::Partner,
            ContactRelationKind::Assistant,
            ContactRelationKind::Assistant,
            ContactRelationKind::Manager,
            ContactRelationKind::Manager,
            ContactRelationKind::Other,
            // No TYPE: the renderer's own form of Other.
            ContactRelationKind::Other,
        ];
        assert_eq!(parsed.relations.len(), expected.len());
        for (relation, kind) in parsed.relations.iter().zip(expected) {
            assert!(relation.kind == kind, "relation kind mismatch");
        }
    }

    #[test]
    fn duplicates_keep_the_first_property() {
        let body = concat!(
            "BEGIN:VCARD\r\n",
            "N:L1;F1;;;\r\n",
            "N:L2;F2;;;\r\n",
            "NICKNAME:One\r\n",
            "NICKNAME:Two\r\n",
            "NOTE:first\r\n",
            "NOTE:second\r\n",
            "ORG:C1;D1\r\n",
            "ORG:C2;D2\r\n",
            "TITLE:Job\r\n",
            "ROLE:Function\r\n",
            "BDAY:19900115\r\n",
            "BDAY:20000202\r\n",
            "END:VCARD\r\n",
        );
        let parsed = parse_vcard(body).unwrap();
        assert_eq!(parsed.last_name, "L1");
        assert_eq!(parsed.first_name, "F1");
        assert_eq!(parsed.nickname, "One");
        assert_eq!(parsed.comment, "first");
        assert_eq!(parsed.company, "C1");
        assert_eq!(parsed.department, "D1");
        // Whichever of TITLE and ROLE comes first wins.
        assert_eq!(parsed.role, "Job");
        // Both dates parsed; the first was kept.
        assert_eq!(parsed.birthday.as_deref(), Some("1990-01-15"));

        let body = "BEGIN:VCARD\r\nROLE:Function\r\nTITLE:Job\r\nEND:VCARD\r\n";
        let parsed = parse_vcard(body).unwrap();
        assert_eq!(parsed.role, "Function");
    }

    #[test]
    fn unescape_inverts_the_renderers_escape() {
        // The renderer's own escaping fixture, inverted: line ends
        // normalize to LF on the way through.
        let escaped = escape("a,b;c\\d\ne\r\nf\rg");
        assert_eq!(unescape(&escaped), "a,b;c\\d\ne\nf\ng");
        // Both newline escapes, including the upper-case one.
        assert_eq!(unescape("x\\ny\\Nz"), "x\ny\nz");
        // A backslash before anything else stays, and so does a
        // trailing one: never lose a character.
        assert_eq!(unescape("C:\\path"), "C:\\path");
        assert_eq!(unescape("end\\"), "end\\");
    }

    #[test]
    fn address_components_join_into_free_text_lines() {
        let body = concat!(
            "BEGIN:VCARD\r\n",
            "ADR;TYPE=home:;;Via Roma 1;London;;SW1;England\r\n",
            "ADR:;;;;Bare;;;\r\n",
            "ADR:;;;;;;;\r\n",
            "ADR:p.o. box;ext;Street;City;Region;Zip;Country\r\n",
            "END:VCARD\r\n",
        );
        let parsed = parse_vcard(body).unwrap();
        assert_eq!(parsed.addresses.len(), 3);
        assert!(parsed.addresses[0].kind == ContactFieldKind::Home);
        assert_eq!(
            parsed.addresses[0].value,
            "Via Roma 1\nLondon\nSW1\nEngland"
        );
        assert!(parsed.addresses[1].kind == ContactFieldKind::Custom);
        assert_eq!(parsed.addresses[1].value, "Bare");
        assert!(parsed.addresses[2].kind == ContactFieldKind::Custom);
        assert_eq!(
            parsed.addresses[2].value,
            "p.o. box\next\nStreet\nCity\nRegion\nZip\nCountry"
        );
    }
}
