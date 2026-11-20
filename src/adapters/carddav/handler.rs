//! The read-only CardDAV handler (RFC 6352) behind the shared DAV layer.
//!
//! URL layout (fixed, documented in the README):
//!
//! | Path                                | Resource                          |
//! |-------------------------------------|-----------------------------------|
//! | `/`                                 | root collection, points onward    |
//! | `/principal/`                       | the user's principal              |
//! | `/addressbooks/`                    | addressbook-home-set              |
//! | `/addressbooks/contacts/`           | the one address book              |
//! | `/addressbooks/contacts/<id>.vcf`   | one contact (`<id>`: element id)  |
//!
//! `/.well-known/carddav` redirects to `/principal/`. `PROPFIND` serves
//! depth 0 and 1; `infinity` (or no `Depth`) is treated as 1. `REPORT`
//! serves `addressbook-multiget`, `addressbook-query` (no filter, or
//! `prop-filter` with `text-match` / `is-not-defined` on FN, N,
//! NICKNAME, EMAIL, TEL, ORG, NOTE) and `sync-collection`.
//!
//! Listings, ETags, the ctag and the sync token come from the contact
//! cache; vCards are rendered from the SDK only when `address-data` is
//! asked for or a card is fetched.

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;

use super::vcard::VCARD_CONTENT_TYPE;
use crate::adapters::dav::xml::{
    props, MultiStatusEntry, PropName, PropRequest, Report, XmlElement, XmlNode, CARDDAV_NS, DAV_NS,
};
use crate::adapters::dav::{
    DavHandler, DavMethod, DavRequest, DavResponse, Depth, WellKnown, XML_CONTENT_TYPE,
};
use crate::app::contacts::{ContactBook, RenderedCard};
use crate::domain::{ContactCard, Result};
use crate::ports::contact_store::{ContactBookState, StoredContact};

pub const ROOT_HREF: &str = "/";
pub const PRINCIPAL_HREF: &str = "/principal/";
pub const HOME_HREF: &str = "/addressbooks/";
pub const BOOK_HREF: &str = "/addressbooks/contacts/";

const BOOK_NAME: &str = "Tuta contacts";

/// The href of one contact.
pub fn card_href(element_id: &str) -> String {
    format!("{BOOK_HREF}{element_id}.vcf")
}

/// The ctag of a book state.
fn ctag(book: &ContactBookState) -> String {
    format!("{}-{}", book.epoch, book.revision)
}

const SYNC_TOKEN_PREFIX: &str = "urn:tuta-bridge:carddav:sync:";

/// The sync token of a book state.
fn sync_token(book: &ContactBookState) -> String {
    format!("{SYNC_TOKEN_PREFIX}{}-{}", book.epoch, book.revision)
}

/// The revision a sync token names, when it belongs to this book.
fn token_revision(token: &str, book: &ContactBookState) -> Option<i64> {
    let rest = token.trim().strip_prefix(SYNC_TOKEN_PREFIX)?;
    let (epoch, revision) = rest.rsplit_once('-')?;
    let revision: i64 = revision.parse().ok()?;
    (epoch == book.epoch && (0..=book.revision).contains(&revision)).then_some(revision)
}

/// What a request path addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Target {
    Root,
    Principal,
    Home,
    Book,
    Card(String),
}

/// Strip a scheme and authority (multiget hrefs may be absolute URLs),
/// percent-decode, and classify.
fn target(href: &str) -> Option<Target> {
    let mut path = href.trim();
    if let Some(at) = path.find("://") {
        let after = &path[at + 3..];
        path = after.find('/').map_or("/", |slash| &after[slash..]);
    }
    let path = path.split(['?', '#']).next().unwrap_or("");
    let decoded = urlencoding::decode(path).ok()?;
    let trimmed = decoded.trim_end_matches('/');
    match trimmed {
        "" => Some(Target::Root),
        "/principal" => Some(Target::Principal),
        "/addressbooks" => Some(Target::Home),
        "/addressbooks/contacts" => Some(Target::Book),
        _ => {
            let name = trimmed.strip_prefix("/addressbooks/contacts/")?;
            let id = name.strip_suffix(".vcf")?;
            let valid = !id.is_empty()
                && id.len() <= 64
                && id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
            valid.then(|| Target::Card(id.to_string()))
        }
    }
}

fn address_data() -> PropName {
    PropName::carddav("address-data")
}

/// `d:current-user-privilege-set` with read only: clients show the book
/// read-only.
fn read_only_privileges() -> XmlNode {
    let privilege = |name: &str| {
        XmlNode::children(
            PropName::dav("privilege"),
            vec![XmlNode::empty(PropName::dav(name))],
        )
    };
    XmlNode::children(
        PropName::dav("current-user-privilege-set"),
        vec![
            privilege("read"),
            privilege("read-current-user-privilege-set"),
        ],
    )
}

fn home_set() -> XmlNode {
    XmlNode::href(PropName::carddav("addressbook-home-set"), HOME_HREF)
}

/// A `<d:error>` body with one precondition element.
fn dav_error(status: u16, namespace: &str, local: &str) -> DavResponse {
    let element = if namespace == CARDDAV_NS {
        format!("<card:{local}/>")
    } else {
        format!("<d:{local}/>")
    };
    let body = format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<d:error xmlns:d=\"DAV:\" xmlns:card=\"{CARDDAV_NS}\">{element}</d:error>\n"
    );
    DavResponse::new(status)
        .with_header("Content-Type", XML_CONTENT_TYPE)
        .with_body(body.into_bytes())
}

/// The CardDAV handler.
pub struct CardDavHandler {
    book: Arc<ContactBook>,
}

impl CardDavHandler {
    pub fn new(book: Arc<ContactBook>) -> Self {
        Self { book }
    }

    /// The root collection's or the principal's properties.
    fn root_props(&self, principal: bool) -> Vec<XmlNode> {
        vec![
            if principal {
                props::resourcetype(false, &[PropName::dav("principal")])
            } else {
                props::resourcetype(true, &[])
            },
            props::displayname("tuta-bridge"),
            props::current_user_principal(PRINCIPAL_HREF),
            props::principal_url(PRINCIPAL_HREF),
            home_set(),
            read_only_privileges(),
        ]
    }

    fn home_props(&self) -> Vec<XmlNode> {
        vec![
            props::resourcetype(true, &[]),
            props::displayname("Address books"),
            props::current_user_principal(PRINCIPAL_HREF),
            home_set(),
            read_only_privileges(),
        ]
    }

    fn book_props(&self, book: &ContactBookState) -> Vec<XmlNode> {
        vec![
            props::resourcetype(true, &[PropName::carddav("addressbook")]),
            props::displayname(BOOK_NAME),
            props::getctag(&ctag(book)),
            props::sync_token(&sync_token(book)),
            props::supported_report_set(&[
                PropName::carddav("addressbook-multiget"),
                PropName::carddav("addressbook-query"),
                PropName::dav("sync-collection"),
            ]),
            props::current_user_principal(PRINCIPAL_HREF),
            read_only_privileges(),
            XmlNode::children(
                PropName::carddav("supported-address-data"),
                vec![XmlNode::empty(PropName::carddav("address-data-type"))
                    .with_attribute("content-type", "text/vcard")
                    .with_attribute("version", "4.0")],
            ),
        ]
    }

    /// A card's properties; `address-data` only when `rendered` is given.
    fn card_props(stored: &StoredContact, rendered: Option<&RenderedCard>) -> Vec<XmlNode> {
        let etag = rendered.map_or(stored.etag.as_str(), |card| card.etag.as_str());
        let mut found = vec![
            props::getetag(etag),
            props::getcontenttype(VCARD_CONTENT_TYPE),
            props::resourcetype(false, &[]),
        ];
        if let Some(card) = rendered {
            found.push(XmlNode::text(address_data(), card.vcard.clone()));
        }
        found
    }

    /// Entries for `contacts`, rendering them when `address-data` is
    /// named. Contacts that turn out to be gone answer `404`.
    async fn card_entries(
        &self,
        wanted: &PropRequest,
        contacts: &[StoredContact],
    ) -> Result<Vec<MultiStatusEntry>> {
        let rendered = if wanted.names(&address_data()) && !contacts.is_empty() {
            Some(self.book.render_many(contacts).await?)
        } else {
            None
        };
        Ok(contacts
            .iter()
            .map(|stored| {
                let href = card_href(&stored.element_id);
                match &rendered {
                    Some(map) => match map.get(&stored.element_id) {
                        Some(card) => MultiStatusEntry::for_request(
                            href,
                            wanted,
                            Self::card_props(stored, Some(card)),
                        ),
                        None => MultiStatusEntry::status(href, 404),
                    },
                    None => {
                        MultiStatusEntry::for_request(href, wanted, Self::card_props(stored, None))
                    }
                }
            })
            .collect())
    }

    async fn propfind(
        &self,
        target: Target,
        wanted: &PropRequest,
        depth: Depth,
    ) -> Result<DavResponse> {
        let deep = depth != Depth::Zero;
        let mut entries = Vec::new();
        match target {
            Target::Root => {
                entries.push(MultiStatusEntry::for_request(
                    ROOT_HREF,
                    wanted,
                    self.root_props(false),
                ));
                if deep {
                    entries.push(MultiStatusEntry::for_request(
                        PRINCIPAL_HREF,
                        wanted,
                        self.root_props(true),
                    ));
                    entries.push(MultiStatusEntry::for_request(
                        HOME_HREF,
                        wanted,
                        self.home_props(),
                    ));
                }
            }
            Target::Principal => entries.push(MultiStatusEntry::for_request(
                PRINCIPAL_HREF,
                wanted,
                self.root_props(true),
            )),
            Target::Home => {
                entries.push(MultiStatusEntry::for_request(
                    HOME_HREF,
                    wanted,
                    self.home_props(),
                ));
                if deep {
                    let book = self.book.ensure_fresh().await?;
                    entries.push(MultiStatusEntry::for_request(
                        BOOK_HREF,
                        wanted,
                        self.book_props(&book),
                    ));
                }
            }
            Target::Book => {
                let book = self.book.ensure_fresh().await?;
                entries.push(MultiStatusEntry::for_request(
                    BOOK_HREF,
                    wanted,
                    self.book_props(&book),
                ));
                if deep {
                    let contacts = self.book.listing().await?;
                    entries.extend(self.card_entries(wanted, &contacts).await?);
                }
            }
            Target::Card(id) => {
                self.book.ensure_fresh().await?;
                let Some(stored) = self.book.lookup(&id).await? else {
                    return Ok(DavResponse::not_found());
                };
                entries.extend(self.card_entries(wanted, &[stored]).await?);
            }
        }
        Ok(DavResponse::multistatus(&entries, None))
    }

    async fn get(&self, target: Target) -> Result<DavResponse> {
        let Target::Card(id) = target else {
            return Ok(DavResponse::text(200, "tuta-bridge CardDAV"));
        };
        self.book.ensure_fresh().await?;
        let Some(stored) = self.book.lookup(&id).await? else {
            return Ok(DavResponse::not_found());
        };
        match self.book.render(&stored).await? {
            Some(card) => {
                Ok(DavResponse::ok(VCARD_CONTENT_TYPE, card.vcard.into_bytes())
                    .with_etag(&card.etag))
            }
            None => Ok(DavResponse::not_found()),
        }
    }

    async fn report(&self, target: Target, report: &Report) -> Result<DavResponse> {
        let supported = report.is(CARDDAV_NS, "addressbook-multiget")
            || report.is(CARDDAV_NS, "addressbook-query")
            || report.is(DAV_NS, "sync-collection");
        if !supported {
            return Ok(dav_error(403, DAV_NS, "supported-report"));
        }
        if target != Target::Book {
            return Ok(dav_error(403, DAV_NS, "supported-report"));
        }
        // Without a `prop`, a report returns the ETag and the vCard.
        let default_props = PropRequest::Prop(vec![PropName::dav("getetag"), address_data()]);
        let wanted = report.props.clone().unwrap_or(default_props);
        if report.is(CARDDAV_NS, "addressbook-multiget") {
            self.multiget(report, &wanted).await
        } else if report.is(CARDDAV_NS, "addressbook-query") {
            self.query(report, &wanted).await
        } else {
            self.sync_collection(report, &wanted).await
        }
    }

    async fn multiget(&self, report: &Report, wanted: &PropRequest) -> Result<DavResponse> {
        self.book.ensure_fresh().await?;
        let mut found = Vec::new();
        let mut entries = Vec::new();
        let mut seen = HashSet::new();
        for href in &report.hrefs {
            let stored = match target(href) {
                Some(Target::Card(id)) => self.book.lookup(&id).await?,
                _ => None,
            };
            match stored {
                Some(stored) if seen.insert(stored.element_id.clone()) => found.push(stored),
                Some(_) => {}
                None => entries.push(MultiStatusEntry::status(href.clone(), 404)),
            }
        }
        entries.extend(self.card_entries(wanted, &found).await?);
        Ok(DavResponse::multistatus(&entries, None))
    }

    async fn query(&self, report: &Report, wanted: &PropRequest) -> Result<DavResponse> {
        let filter = match report.filter.as_ref() {
            Some(filter) => match CardFilter::parse(filter) {
                Some(filter) => filter,
                None => return Ok(dav_error(403, CARDDAV_NS, "supported-filter")),
            },
            None => CardFilter::default(),
        };
        let limit = report
            .root
            .child(CARDDAV_NS, "limit")
            .and_then(|limit| limit.child(CARDDAV_NS, "nresults"))
            .and_then(|count| count.text.trim().parse::<usize>().ok());
        self.book.ensure_fresh().await?;
        let mut entries = Vec::new();
        if filter.is_empty() && !wanted.names(&address_data()) {
            // Metadata only: straight from the cache.
            let contacts = self.book.listing().await?;
            entries.extend(self.card_entries(wanted, &contacts).await?);
        } else {
            let mut cards = self.book.render_all().await?;
            cards.retain(|card| filter.matches(&card.card));
            cards.sort_by(|a, b| a.card.element_id.cmp(&b.card.element_id));
            for card in &cards {
                let stored = StoredContact {
                    list_id: card.card.list_id.clone(),
                    element_id: card.card.element_id.clone(),
                    etag: card.etag.clone(),
                    revision: 0,
                    deleted: false,
                };
                let rendered = wanted.names(&address_data()).then_some(card);
                entries.push(MultiStatusEntry::for_request(
                    card_href(&stored.element_id),
                    wanted,
                    Self::card_props(&stored, rendered),
                ));
            }
        }
        if let Some(limit) = limit {
            if entries.len() > limit {
                entries.truncate(limit);
                entries.push(MultiStatusEntry::status(BOOK_HREF, 507));
            }
        }
        Ok(DavResponse::multistatus(&entries, None))
    }

    async fn sync_collection(&self, report: &Report, wanted: &PropRequest) -> Result<DavResponse> {
        let book = self.book.ensure_fresh().await?;
        let token = report
            .root
            .child(DAV_NS, "sync-token")
            .map(|token| token.text.trim().to_string())
            .unwrap_or_default();
        let since = if token.is_empty() {
            0
        } else {
            match token_revision(&token, &book) {
                Some(revision) => revision,
                None => return Ok(dav_error(403, DAV_NS, "valid-sync-token")),
            }
        };
        let (revision, changes) = self.book.changes_since(since).await?;
        let mut entries = Vec::new();
        let mut live = Vec::new();
        for row in changes {
            if row.deleted {
                // An initial sync lists members only.
                if since > 0 {
                    entries.push(MultiStatusEntry::status(card_href(&row.element_id), 404));
                }
            } else {
                live.push(row);
            }
        }
        live.sort_by(|a, b| a.element_id.cmp(&b.element_id));
        entries.extend(self.card_entries(wanted, &live).await?);
        let current = ContactBookState { revision, ..book };
        Ok(DavResponse::multistatus(
            &entries,
            Some(&sync_token(&current)),
        ))
    }
}

#[async_trait]
impl DavHandler for CardDavHandler {
    fn label(&self) -> &'static str {
        "carddav"
    }

    fn compliance_classes(&self) -> &'static [&'static str] {
        &["addressbook"]
    }

    fn well_known(&self, service: WellKnown) -> Option<String> {
        match service {
            WellKnown::CardDav => Some(PRINCIPAL_HREF.to_string()),
            WellKnown::CalDav => None,
        }
    }

    async fn handle(&self, request: &DavRequest) -> Result<DavResponse> {
        let Some(target) = target(&request.path) else {
            return Ok(DavResponse::not_found());
        };
        match &request.method {
            DavMethod::Get => self.get(target).await,
            DavMethod::Propfind(wanted) => {
                // `infinity` (or no Depth) is served as depth 1.
                let depth = request.depth.unwrap_or(Depth::Infinity);
                self.propfind(target, wanted, depth).await
            }
            DavMethod::Report(report) => self.report(target, report).await,
        }
    }
}

// ---------------------------------------------------------------------------
// addressbook-query filters
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MatchType {
    Equals,
    Contains,
    StartsWith,
    EndsWith,
}

/// One `text-match`.
#[derive(Debug, Clone)]
struct TextMatch {
    text: String,
    match_type: MatchType,
    negate: bool,
}

impl TextMatch {
    fn matches(&self, value: &str) -> bool {
        // `i;unicode-casemap` approximated by lowercase comparison.
        let value = value.to_lowercase();
        let hit = match self.match_type {
            MatchType::Equals => value == self.text,
            MatchType::Contains => value.contains(&self.text),
            MatchType::StartsWith => value.starts_with(&self.text),
            MatchType::EndsWith => value.ends_with(&self.text),
        };
        hit != self.negate
    }
}

/// One `prop-filter`.
#[derive(Debug, Clone)]
struct PropFilter {
    name: String,
    /// `is-not-defined`: matches when the property is absent.
    not_defined: bool,
    matches: Vec<TextMatch>,
    all_of: bool,
}

impl PropFilter {
    fn matches(&self, card: &ContactCard) -> bool {
        let values = property_values(card, &self.name);
        if self.not_defined {
            return values.is_empty();
        }
        if values.is_empty() {
            return false;
        }
        if self.matches.is_empty() {
            return true;
        }
        let test = |m: &TextMatch| values.iter().any(|value| m.matches(value));
        if self.all_of {
            self.matches.iter().all(test)
        } else {
            self.matches.iter().any(test)
        }
    }
}

/// A parsed `card:filter`. An empty filter matches every card.
#[derive(Debug, Clone, Default)]
struct CardFilter {
    props: Vec<PropFilter>,
    all_of: bool,
}

/// The properties a filter can test.
const FILTERABLE: &[&str] = &["FN", "N", "NICKNAME", "EMAIL", "TEL", "ORG", "NOTE"];

impl CardFilter {
    /// `None` for anything this server does not evaluate (another
    /// property, a `param-filter`, an unknown match type or collation).
    fn parse(filter: &XmlElement) -> Option<Self> {
        let all_of = filter.attribute("test") == Some("allof");
        let mut props = Vec::new();
        for child in &filter.children {
            if !child.is(CARDDAV_NS, "prop-filter") {
                return None;
            }
            let name = child.attribute("name")?.to_ascii_uppercase();
            if !FILTERABLE.contains(&name.as_str()) {
                return None;
            }
            let mut prop = PropFilter {
                name,
                not_defined: false,
                matches: Vec::new(),
                all_of: child.attribute("test") == Some("allof"),
            };
            for inner in &child.children {
                if inner.is(CARDDAV_NS, "is-not-defined") {
                    prop.not_defined = true;
                } else if inner.is(CARDDAV_NS, "text-match") {
                    let match_type = match inner.attribute("match-type").unwrap_or("contains") {
                        "equals" => MatchType::Equals,
                        "contains" => MatchType::Contains,
                        "starts-with" => MatchType::StartsWith,
                        "ends-with" => MatchType::EndsWith,
                        _ => return None,
                    };
                    match inner.attribute("collation") {
                        None | Some("i;unicode-casemap") | Some("i;ascii-casemap") => {}
                        _ => return None,
                    }
                    prop.matches.push(TextMatch {
                        text: inner.text.trim().to_lowercase(),
                        match_type,
                        negate: inner.attribute("negate-condition") == Some("yes"),
                    });
                } else {
                    return None;
                }
            }
            props.push(prop);
        }
        Some(Self { props, all_of })
    }

    fn is_empty(&self) -> bool {
        self.props.is_empty()
    }

    fn matches(&self, card: &ContactCard) -> bool {
        if self.props.is_empty() {
            return true;
        }
        if self.all_of {
            self.props.iter().all(|prop| prop.matches(card))
        } else {
            self.props.iter().any(|prop| prop.matches(card))
        }
    }
}

/// The plain values of a filterable property, empty ones left out.
fn property_values(card: &ContactCard, name: &str) -> Vec<String> {
    let values: Vec<String> = match name {
        "FN" => vec![[
            card.title.as_str(),
            &card.first_name,
            &card.middle_name,
            &card.last_name,
        ]
        .iter()
        .map(|part| part.trim())
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ")],
        "N" => vec![
            card.last_name.clone(),
            card.first_name.clone(),
            card.middle_name.clone(),
        ],
        "NICKNAME" => vec![card.nickname.clone()],
        "EMAIL" => card.emails.iter().map(|f| f.value.clone()).collect(),
        "TEL" => card.phones.iter().map(|f| f.value.clone()).collect(),
        "ORG" => vec![card.company.clone(), card.department.clone()],
        "NOTE" => vec![card.comment.clone()],
        _ => Vec::new(),
    };
    values
        .into_iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_classify() {
        assert_eq!(target("/"), Some(Target::Root));
        assert_eq!(target(""), Some(Target::Root));
        assert_eq!(target("/principal"), Some(Target::Principal));
        assert_eq!(target("/addressbooks/"), Some(Target::Home));
        assert_eq!(target("/addressbooks/contacts"), Some(Target::Book));
        assert_eq!(
            target("/addressbooks/contacts/Ab-_9.vcf"),
            Some(Target::Card("Ab-_9".into()))
        );
        assert_eq!(
            target("https://127.0.0.1:9932/addressbooks/contacts/a%2Db.vcf"),
            Some(Target::Card("a-b".into()))
        );
        assert_eq!(target("/addressbooks/contacts/a.b.vcf"), None);
        assert_eq!(target("/addressbooks/contacts/.vcf"), None);
        assert_eq!(target("/addressbooks/contacts/a"), None);
        assert_eq!(target("/elsewhere"), None);
    }

    #[test]
    fn sync_tokens_round_trip_only_within_their_book() {
        let book = ContactBookState {
            epoch: "00ff".into(),
            revision: 7,
            loaded: true,
            list_id: None,
        };
        let token = sync_token(&book);
        assert_eq!(token_revision(&token, &book), Some(7));
        let older = ContactBookState {
            revision: 3,
            ..book.clone()
        };
        assert_eq!(token_revision(&sync_token(&older), &book), Some(3));
        let other = ContactBookState {
            epoch: "1234".into(),
            ..book.clone()
        };
        assert_eq!(token_revision(&sync_token(&other), &book), None);
        let future = ContactBookState {
            revision: 8,
            ..book.clone()
        };
        assert_eq!(token_revision(&sync_token(&future), &book), None);
        assert_eq!(token_revision("garbage", &book), None);
    }
}
