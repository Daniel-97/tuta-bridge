//! The CardDAV handler (RFC 6352) behind the shared DAV layer.
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
//! NICKNAME, EMAIL, TEL, ORG, NOTE, matched against the values as
//! rendered, under the `i;octet`, `i;ascii-casemap` or
//! `i;unicode-casemap` collation) and `sync-collection`.
//!
//! Cards are vCard 4.0 only: an `address-data` that explicitly asks for
//! another `content-type` or `version` is refused with the
//! `CARDDAV:supported-address-data` precondition (one without attributes
//! gets 4.0). A `card:limit` truncates an `addressbook-query` and marks
//! it with a `507` response carrying `DAV:number-of-matches-within-limits`.
//! A `DAV:limit` on `sync-collection` is not honoured by truncation: when
//! more changes are due than it allows, the report fails with `507` and
//! the same condition (RFC 6578 §3.7), and the client retries without
//! a limit.
//!
//! Listings, ETags, the ctag and the sync token come from the contact
//! cache; vCards are rendered from the SDK only when `address-data` is
//! asked for or a card is fetched.
//!
//! `PUT` and `DELETE` are served when a writer is wired. `PUT` enforces
//! the RFC preconditions against the stored ETag (`If-Match`; an
//! `If-None-Match: *` refuses an overwrite) and hands the `If-Match`
//! on: the writer re-checks it against the freshly loaded entity, so
//! a cache-matching but stale write still answers `412` instead of
//! overwriting a remote edit the event bus has not delivered yet. One
//! whole write per book runs at a time — the put and the cache apply
//! of its outcome never interleave. The remote write comes first, a
//! create lands on the server-generated id (the client's href id is
//! never stored), and the cache is updated after the remote write
//! held — a cache apply that fails anyway still answers the success
//! the remote write earned (the stale mark heals the row on the next
//! read; a client that retried a write that already happened would
//! create a duplicate). `DELETE` tombstones a row only after the
//! remote delete held, and a failed cache apply stays the success the
//! same way. Without a writer both answer the fixed `403` the session
//! answered before.

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Mutex;

use super::import::{parse_vcard, ImportError};
use super::vcard::{formatted_name, VCARD_CONTENT_TYPE};
use crate::adapters::dav::xml::{
    props, MultiStatusEntry, PropName, PropRequest, Report, XmlElement, XmlNode, CARDDAV_NS, DAV_NS,
};
use crate::adapters::dav::{
    etag_matches, strong_etag_matches, writer_refusal, DavHandler, DavMethod, DavRequest,
    DavResponse, Depth, WellKnown, XML_CONTENT_TYPE,
};
use crate::app::contacts::{ContactBook, RenderedCard};
use crate::domain::{ContactCard, Result};
use crate::ports::contact_store::{ContactBookState, ContactEntry, StoredContact};
use crate::ports::dav_writer::{ContactFields, ContactRef, ContactWriter};

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

/// `d:current-user-privilege-set` with read only: the root, the
/// principal and the home cannot be written.
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

/// `d:current-user-privilege-set` of the one address book: read and
/// write, so clients stop marking the book read-only.
fn addressbook_privileges() -> XmlNode {
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
            privilege("write"),
        ],
    )
}

/// The fixed refusal of a handler without a writer: byte-identical
/// to the one the generic session answers for the write methods no
/// feature serves.
fn unwired() -> DavResponse {
    DavResponse::text(403, "forbidden: this server is read-only")
}

/// `412` with a fixed body.
fn precondition_failed() -> DavResponse {
    DavResponse::text(412, "precondition failed")
}

/// The canonical card of one written contact: the importer's fields on
/// the ids the write landed on. Rendering it is what the next read of
/// this contact does, so its ETag is the row's new one.
fn written_card(reference: &ContactRef, fields: &ContactFields) -> ContactCard {
    ContactCard {
        list_id: reference.list_id.clone(),
        element_id: reference.element_id.clone(),
        title: fields.title.clone(),
        first_name: fields.first_name.clone(),
        middle_name: fields.middle_name.clone(),
        last_name: fields.last_name.clone(),
        name_suffix: fields.name_suffix.clone(),
        nickname: fields.nickname.clone(),
        company: fields.company.clone(),
        department: fields.department.clone(),
        role: fields.role.clone(),
        birthday: fields.birthday.clone(),
        anniversaries: fields.anniversaries.clone(),
        comment: fields.comment.clone(),
        emails: fields.emails.clone(),
        phones: fields.phones.clone(),
        addresses: fields.addresses.clone(),
        websites: fields.websites.clone(),
        relations: fields.relations.clone(),
    }
}

fn home_set() -> XmlNode {
    XmlNode::href(PropName::carddav("addressbook-home-set"), HOME_HREF)
}

/// The collations `text-match` supports, as advertised.
const COLLATIONS: &[&str] = &["i;ascii-casemap", "i;octet", "i;unicode-casemap"];

/// Whether every `address-data` element of a report asks for a type this
/// server renders: `text/vcard` version 4.0. Absent attributes are
/// accepted (the card served is 4.0 regardless).
fn address_data_supported(report: &Report) -> bool {
    let Some(prop) = report.root.child(DAV_NS, "prop") else {
        return true;
    };
    prop.children_named(CARDDAV_NS, "address-data")
        .all(|element| {
            let content_type = element.attribute("content-type").is_none_or(|value| {
                value
                    .split(';')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .eq_ignore_ascii_case("text/vcard")
            });
            let version = element
                .attribute("version")
                .is_none_or(|value| value.trim() == "4.0");
            content_type && version
        })
}

/// The `nresults` of a `limit` element in `namespace` under the
/// report's root.
fn report_limit(report: &Report, namespace: &str) -> Option<usize> {
    report
        .root
        .child(namespace, "limit")
        .and_then(|limit| limit.child(namespace, "nresults"))
        .and_then(|count| count.text.trim().parse::<usize>().ok())
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
    /// The Tuta write seam; `None` keeps the handler read-only (the
    /// state `serve` serves until the writer is wired in).
    writer: Option<Arc<dyn ContactWriter>>,
    /// Serializes one whole write per book across connections: the
    /// remote put — which re-checks the precondition against the
    /// freshly loaded entity — and the cache apply of its outcome
    /// never interleave with another connection's.
    write: Mutex<()>,
}

impl CardDavHandler {
    pub fn new(book: Arc<ContactBook>) -> Self {
        Self {
            book,
            writer: None,
            write: Mutex::new(()),
        }
    }

    pub fn with_writer(book: Arc<ContactBook>, writer: Arc<dyn ContactWriter>) -> Self {
        Self {
            book,
            writer: Some(writer),
            write: Mutex::new(()),
        }
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
            addressbook_privileges(),
            XmlNode::children(
                PropName::carddav("supported-address-data"),
                vec![XmlNode::empty(PropName::carddav("address-data-type"))
                    .with_attribute("content-type", "text/vcard")
                    .with_attribute("version", "4.0")],
            ),
            XmlNode::children(
                PropName::carddav("supported-collation-set"),
                COLLATIONS
                    .iter()
                    .map(|name| XmlNode::text(PropName::carddav("supported-collation"), *name))
                    .collect(),
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

    async fn put(&self, target: Target, request: &DavRequest) -> Result<DavResponse> {
        // Without a writer every PUT answers the fixed read-only text,
        // whatever the target.
        let Some(writer) = self.writer.as_deref() else {
            return Ok(unwired());
        };
        // Only a card href is a resource a PUT can address: collections
        // are not writable.
        let Target::Card(id) = target else {
            return Ok(DavResponse::forbidden());
        };
        let book = self.book.ensure_fresh().await?;
        let stored = self.book.lookup(&id).await?;
        // Preconditions run against the stored row, never the rendered
        // body: an unchanged reload can never answer 412.
        if let Some(condition) = request.if_none_match.as_deref() {
            if stored
                .as_ref()
                .is_some_and(|row| etag_matches(condition, &row.etag))
            {
                return Ok(precondition_failed());
            }
        }
        if let Some(condition) = request.header("if-match") {
            if !stored
                .as_ref()
                .is_some_and(|row| strong_etag_matches(condition, &row.etag))
            {
                return Ok(precondition_failed());
            }
        }
        let Ok(body) = std::str::from_utf8(&request.body) else {
            return Ok(DavResponse::text(400, ImportError::NoVcard.message()));
        };
        let fields = match parse_vcard(body) {
            Ok(fields) => fields,
            Err(error) => return Ok(DavResponse::text(400, error.message())),
        };
        let existing = stored.as_ref().map(|row| ContactRef {
            list_id: row.list_id.clone(),
            element_id: row.element_id.clone(),
        });
        // An update stays in the row's own list; a create goes to the
        // book's list, which must be known before the remote write.
        let list_id = match &existing {
            Some(reference) => reference.list_id.clone(),
            None => match book.list_id {
                Some(list_id) => list_id,
                None => {
                    return Ok(DavResponse::text(
                        409,
                        "the address book's contact list is not known yet",
                    ))
                }
            },
        };
        // The request's `If-Match`, already verified above: the writer
        // re-checks it against the freshly loaded entity, which is
        // the authority behind that fast fail.
        let if_match = request.header("if-match");
        // One whole write per book at a time: the put and the cache
        // apply of its outcome never interleave with another
        // connection's write.
        let _guard = self.write.lock().await;
        let reference = match writer
            .put_contact(&list_id, &fields, existing.as_ref(), if_match)
            .await
        {
            Ok(reference) => reference,
            Err(error) => return writer_refusal(error),
        };
        let rendered = RenderedCard::new(written_card(&reference, &fields));
        let entry = ContactEntry {
            list_id: reference.list_id.clone(),
            element_id: reference.element_id.clone(),
            etag: rendered.etag.clone(),
        };
        // The store skips an unchanged ETag, so the echo of this change
        // does not advance the revision again. The remote write held:
        // a cache apply that fails now only marks the book stale (the
        // reload heals the row), and the answer stays the success the
        // remote write earned — a client that retried a write that
        // already happened would create a duplicate.
        let _ = self.book.apply_written(&entry).await;
        Ok(if existing.is_some() {
            DavResponse::new(204).with_etag(&rendered.etag)
        } else {
            // A create lands on the server-generated id, never the
            // href's.
            DavResponse::new(201)
                .with_header("Location", card_href(&reference.element_id))
                .with_etag(&rendered.etag)
        })
    }

    async fn delete(&self, target: Target, request: &DavRequest) -> Result<DavResponse> {
        // Without a writer every DELETE answers the fixed read-only text,
        // whatever the target.
        let Some(writer) = self.writer.as_deref() else {
            return Ok(unwired());
        };
        let Target::Card(id) = target else {
            return Ok(DavResponse::forbidden());
        };
        self.book.ensure_fresh().await?;
        let Some(stored) = self.book.lookup(&id).await? else {
            // A row that never existed is not a tombstone.
            return Ok(DavResponse::not_found());
        };
        if let Some(condition) = request.header("if-match") {
            if !strong_etag_matches(condition, &stored.etag) {
                return Ok(precondition_failed());
            }
        }
        let reference = ContactRef {
            list_id: stored.list_id.clone(),
            element_id: stored.element_id.clone(),
        };
        // Remote first. Both outcomes proceed: `Gone` has already
        // reached the end state the client asked for. A refusal
        // answers its fixed status; a session error and a transport
        // failure reach the session layer untouched.
        match writer.delete_contact(&reference).await {
            Ok(_) => {}
            Err(error) => return writer_refusal(error),
        }
        // The remote delete held: a cache apply that fails only marks
        // the book stale (the reload heals the row), and the answer
        // stays the success the remote delete earned.
        let _ = self.book.apply_deleted(&stored.element_id).await;
        Ok(DavResponse::new(204))
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
        if !address_data_supported(report) {
            return Ok(dav_error(403, CARDDAV_NS, "supported-address-data"));
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
                Ok(filter) => filter,
                Err(FilterError::Collation) => {
                    return Ok(dav_error(403, CARDDAV_NS, "supported-collation"))
                }
                Err(FilterError::Unsupported) => {
                    return Ok(dav_error(403, CARDDAV_NS, "supported-filter"))
                }
            },
            None => CardFilter::default(),
        };
        let limit = report_limit(report, CARDDAV_NS);
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
                entries.push(
                    MultiStatusEntry::status(BOOK_HREF, 507)
                        .with_error(PropName::dav("number-of-matches-within-limits")),
                );
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
        // A limit is not honoured by truncation: more changes than it
        // allows fail the report (RFC 6578 §3.7).
        if let Some(limit) = report_limit(report, DAV_NS) {
            if entries.len() + live.len() > limit {
                return Ok(dav_error(507, DAV_NS, "number-of-matches-within-limits"));
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

    fn extra_methods(&self) -> &'static [&'static str] {
        &["PUT", "DELETE"]
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
            DavMethod::Put => self.put(target, request).await,
            DavMethod::Delete => self.delete(target, request).await,
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

/// A `text-match` collation (RFC 4790).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Collation {
    /// Exact octets.
    Octet,
    /// ASCII letters fold to lowercase, nothing else does.
    AsciiCasemap,
    /// Approximated by Unicode lowercase folding. The default.
    UnicodeCasemap,
}

impl Collation {
    /// `None` for a collation this server does not implement.
    fn parse(name: Option<&str>) -> Option<Self> {
        match name {
            None | Some("i;unicode-casemap") => Some(Self::UnicodeCasemap),
            Some("i;ascii-casemap") => Some(Self::AsciiCasemap),
            Some("i;octet") => Some(Self::Octet),
            Some(_) => None,
        }
    }

    fn fold(self, text: &str) -> String {
        match self {
            Self::Octet => text.to_string(),
            Self::AsciiCasemap => text.to_ascii_lowercase(),
            Self::UnicodeCasemap => text.to_lowercase(),
        }
    }
}

/// One `text-match`; `text` is already folded by its collation.
#[derive(Debug, Clone)]
struct TextMatch {
    text: String,
    collation: Collation,
    match_type: MatchType,
    negate: bool,
}

impl TextMatch {
    fn matches(&self, value: &str) -> bool {
        let value = self.collation.fold(value);
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

/// Why a `card:filter` cannot be evaluated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FilterError {
    /// Another property, a `param-filter`, an unknown match type.
    Unsupported,
    /// A collation outside [`COLLATIONS`].
    Collation,
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
    /// An error for anything this server does not evaluate.
    fn parse(filter: &XmlElement) -> std::result::Result<Self, FilterError> {
        use FilterError::Unsupported;
        let all_of = filter.attribute("test") == Some("allof");
        let mut props = Vec::new();
        for child in &filter.children {
            if !child.is(CARDDAV_NS, "prop-filter") {
                return Err(Unsupported);
            }
            let name = child
                .attribute("name")
                .ok_or(Unsupported)?
                .to_ascii_uppercase();
            if !FILTERABLE.contains(&name.as_str()) {
                return Err(Unsupported);
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
                        _ => return Err(Unsupported),
                    };
                    let collation = Collation::parse(inner.attribute("collation"))
                        .ok_or(FilterError::Collation)?;
                    prop.matches.push(TextMatch {
                        text: collation.fold(inner.text.trim()),
                        collation,
                        match_type,
                        negate: inner.attribute("negate-condition") == Some("yes"),
                    });
                } else {
                    return Err(Unsupported);
                }
            }
            props.push(prop);
        }
        Ok(Self { props, all_of })
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

/// The plain (unescaped) values of a filterable property as the vCard
/// renders them, empty ones left out: `FN` is the rendered formatted
/// name (fallbacks and suffix included), `N` its five components.
fn property_values(card: &ContactCard, name: &str) -> Vec<String> {
    let values: Vec<String> = match name {
        "FN" => vec![formatted_name(card)],
        "N" => vec![
            card.last_name.clone(),
            card.first_name.clone(),
            card.middle_name.clone(),
            card.title.clone(),
            card.name_suffix.clone(),
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
