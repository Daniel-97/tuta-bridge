//! WebDAV XML: request bodies in, `207 Multi-Status` out.
//!
//! Parsing builds a small namespace-resolved tree ([`XmlElement`]) with
//! bounded depth and size, then interprets it as a `PROPFIND`
//! ([`PropRequest`]) or a `REPORT` ([`Report`]). A DOCTYPE is refused
//! outright, so no entity is ever declared or expanded; only the five
//! predefined entities and character references are resolved.
//!
//! Rendering ([`render_multistatus`]) writes fixed prefixes for the
//! namespaces DAV clients know (`d`, `card`, `cal`, `cs`, `ical`) and an
//! inline default namespace for any other; every text and attribute
//! value is escaped. A carriage return is written as `&#xD;`: a raw one
//! would be normalized away by the client's parser (XML 1.0 §2.11), and
//! vCard and iCalendar bodies need their CRLF line ends intact.
//!
//! Errors are fixed text: nothing from the body reaches an error string.

use std::fmt::Write as _;

use quick_xml::events::Event;
use quick_xml::name::ResolveResult;
use quick_xml::NsReader;
use time::macros::format_description;
use time::{OffsetDateTime, PrimitiveDateTime};

/// `DAV:` (RFC 4918).
pub const DAV_NS: &str = "DAV:";
/// CardDAV (RFC 6352).
pub const CARDDAV_NS: &str = "urn:ietf:params:xml:ns:carddav";
/// CalDAV (RFC 4791).
pub const CALDAV_NS: &str = "urn:ietf:params:xml:ns:caldav";
/// Calendar Server extensions (`getctag`).
pub const CALSERVER_NS: &str = "http://calendarserver.org/ns/";
/// Apple iCal extensions (`calendar-color`, `calendar-order`).
pub const APPLE_ICAL_NS: &str = "http://apple.com/ns/ical/";

/// The prefixes the renderer declares on the root element.
const PREFIXES: &[(&str, &str)] = &[
    (DAV_NS, "d"),
    (CARDDAV_NS, "card"),
    (CALDAV_NS, "cal"),
    (CALSERVER_NS, "cs"),
    (APPLE_ICAL_NS, "ical"),
];

/// Nesting deeper than this is refused.
const MAX_DEPTH: usize = 32;
/// More elements than this in one body are refused.
const MAX_ELEMENTS: usize = 10_000;

/// A body that could not be read as the expected XML. The text is fixed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct XmlError(&'static str);

pub type XmlResult<T> = std::result::Result<T, XmlError>;

/// A namespace-qualified element name. Elements without a namespace
/// have an empty `namespace`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PropName {
    pub namespace: String,
    pub local: String,
}

impl PropName {
    pub fn new(namespace: &str, local: &str) -> Self {
        Self {
            namespace: namespace.to_string(),
            local: local.to_string(),
        }
    }

    /// A name in `DAV:`.
    pub fn dav(local: &str) -> Self {
        Self::new(DAV_NS, local)
    }

    /// A name in the CardDAV namespace.
    pub fn carddav(local: &str) -> Self {
        Self::new(CARDDAV_NS, local)
    }

    /// A name in the CalDAV namespace.
    pub fn caldav(local: &str) -> Self {
        Self::new(CALDAV_NS, local)
    }

    /// A name in the Calendar Server namespace.
    pub fn calserver(local: &str) -> Self {
        Self::new(CALSERVER_NS, local)
    }

    /// Whether this is `local` in `namespace`.
    pub fn is(&self, namespace: &str, local: &str) -> bool {
        self.namespace == namespace && self.local == local
    }
}

/// One parsed request element: its name, attributes (by local name,
/// unescaped), child elements and concatenated text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XmlElement {
    pub name: PropName,
    pub attributes: Vec<(String, String)>,
    pub children: Vec<XmlElement>,
    pub text: String,
}

impl XmlElement {
    /// Whether this element is `local` in `namespace`.
    pub fn is(&self, namespace: &str, local: &str) -> bool {
        self.name.is(namespace, local)
    }

    /// The first child named `local` in `namespace`.
    pub fn child(&self, namespace: &str, local: &str) -> Option<&XmlElement> {
        self.children
            .iter()
            .find(|child| child.is(namespace, local))
    }

    /// Every child named `local` in `namespace`.
    pub fn children_named<'a>(
        &'a self,
        namespace: &'a str,
        local: &'a str,
    ) -> impl Iterator<Item = &'a XmlElement> + 'a {
        self.children
            .iter()
            .filter(move |child| child.is(namespace, local))
    }

    /// Every descendant (not this element) named `local` in
    /// `namespace`, depth first in document order.
    pub fn descendants(&self, namespace: &str, local: &str) -> Vec<&XmlElement> {
        let mut found = Vec::new();
        for child in &self.children {
            if child.is(namespace, local) {
                found.push(child);
            }
            found.extend(child.descendants(namespace, local));
        }
        found
    }

    /// The value of the attribute with this local name.
    pub fn attribute(&self, local: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|(name, _)| name == local)
            .map(|(_, value)| value.as_str())
    }
}

/// Parse a whole body into its root element.
pub fn parse_xml(body: &[u8]) -> XmlResult<XmlElement> {
    let mut reader = NsReader::from_reader(body);
    let config = reader.config_mut();
    config.expand_empty_elements = true;
    config.check_end_names = true;
    let mut buf = Vec::new();
    let mut stack: Vec<XmlElement> = Vec::new();
    let mut root: Option<XmlElement> = None;
    let mut elements = 0usize;
    loop {
        buf.clear();
        let (resolved, event) = reader
            .read_resolved_event_into(&mut buf)
            .map_err(|_| XmlError("malformed xml body"))?;
        match event {
            Event::Start(start) => {
                if root.is_some() {
                    return Err(XmlError("content after the root element"));
                }
                elements += 1;
                if elements > MAX_ELEMENTS {
                    return Err(XmlError("xml body has too many elements"));
                }
                if stack.len() >= MAX_DEPTH {
                    return Err(XmlError("xml body is nested too deeply"));
                }
                let namespace = match resolved {
                    ResolveResult::Bound(namespace) => std::str::from_utf8(namespace.as_ref())
                        .map_err(|_| XmlError("xml namespace is not utf-8"))?
                        .to_string(),
                    ResolveResult::Unbound => String::new(),
                    ResolveResult::Unknown(_) => return Err(XmlError("unbound xml prefix")),
                };
                let local = std::str::from_utf8(start.local_name().as_ref())
                    .map_err(|_| XmlError("xml name is not utf-8"))?
                    .to_string();
                let mut attributes = Vec::new();
                for attribute in start.attributes() {
                    let attribute = attribute.map_err(|_| XmlError("malformed xml attribute"))?;
                    let key = attribute.key;
                    if key.as_namespace_binding().is_some() {
                        continue;
                    }
                    let name = std::str::from_utf8(key.local_name().as_ref())
                        .map_err(|_| XmlError("xml name is not utf-8"))?
                        .to_string();
                    let value = attribute
                        .normalized_value(quick_xml::XmlVersion::Implicit1_0)
                        .map_err(|_| XmlError("malformed xml attribute"))?
                        .into_owned();
                    attributes.push((name, value));
                }
                stack.push(XmlElement {
                    name: PropName { namespace, local },
                    attributes,
                    children: Vec::new(),
                    text: String::new(),
                });
            }
            Event::End(_) => {
                let element = stack.pop().ok_or(XmlError("malformed xml body"))?;
                match stack.last_mut() {
                    Some(parent) => parent.children.push(element),
                    None => root = Some(element),
                }
            }
            // Line ends are normalized to LF (XML 1.0 §2.11).
            Event::Text(text) => {
                let text = text
                    .xml10_content()
                    .map_err(|_| XmlError("xml text is not utf-8"))?;
                match stack.last_mut() {
                    Some(element) => element.text.push_str(&text),
                    None if text.trim().is_empty() => {}
                    None => return Err(XmlError("text outside the root element")),
                }
            }
            Event::CData(data) => {
                let data = data
                    .xml10_content()
                    .map_err(|_| XmlError("xml text is not utf-8"))?;
                match stack.last_mut() {
                    Some(element) => element.text.push_str(&data),
                    None => return Err(XmlError("text outside the root element")),
                }
            }
            Event::GeneralRef(reference) => {
                let resolved = match reference.resolve_char_ref() {
                    Ok(Some(character)) => character,
                    Ok(None) => {
                        let name = reference
                            .decode()
                            .map_err(|_| XmlError("xml text is not utf-8"))?;
                        predefined_entity(&name).ok_or(XmlError("unknown xml entity"))?
                    }
                    Err(_) => return Err(XmlError("invalid xml character reference")),
                };
                match stack.last_mut() {
                    Some(element) => element.text.push(resolved),
                    None => return Err(XmlError("text outside the root element")),
                }
            }
            // `expand_empty_elements` turns these into Start + End.
            Event::Empty(_) => return Err(XmlError("malformed xml body")),
            Event::DocType(_) => return Err(XmlError("xml doctype is not accepted")),
            Event::Decl(_) | Event::PI(_) | Event::Comment(_) => {}
            Event::Eof => break,
        }
    }
    if !stack.is_empty() {
        return Err(XmlError("truncated xml body"));
    }
    root.ok_or(XmlError("empty xml body"))
}

fn predefined_entity(name: &str) -> Option<char> {
    match name {
        "amp" => Some('&'),
        "lt" => Some('<'),
        "gt" => Some('>'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        _ => None,
    }
}

/// What a `PROPFIND` (or the property part of a `REPORT`) asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PropRequest {
    /// `<allprop/>`, with the names of an optional `<include>`. An
    /// empty `PROPFIND` body means allprop too (RFC 4918 §9.1).
    AllProp { include: Vec<PropName> },
    /// `<propname/>`: names only, no values.
    PropName,
    /// `<prop>`: exactly these properties.
    Prop(Vec<PropName>),
}

impl PropRequest {
    /// Split the properties a resource has into the `found` (200) and
    /// `missing` (404) groups this request asks for.
    ///
    /// - `Prop`: every requested name, found when `available` has it.
    /// - `AllProp`: everything in `available`; `include` names it lacks
    ///   are not reported (RFC 4918 §9.1). A handler leaves expensive
    ///   properties (`address-data`, `calendar-data`) out of
    ///   `available` for allprop.
    /// - `PropName`: every name in `available`, with an empty value.
    pub fn select(&self, available: Vec<XmlNode>) -> (Vec<XmlNode>, Vec<PropName>) {
        match self {
            PropRequest::AllProp { .. } => (available, Vec::new()),
            PropRequest::PropName => (
                available
                    .into_iter()
                    .map(|node| XmlNode::empty(node.name))
                    .collect(),
                Vec::new(),
            ),
            PropRequest::Prop(names) => {
                let mut available = available;
                let mut found = Vec::new();
                let mut missing = Vec::new();
                for name in names {
                    match available.iter().position(|node| &node.name == name) {
                        Some(at) => found.push(available.swap_remove(at)),
                        None => missing.push(name.clone()),
                    }
                }
                (found, missing)
            }
        }
    }

    /// Whether the property `name` is to be computed for this request.
    /// `PropName` and `AllProp` want every property the handler lists.
    pub fn wants(&self, name: &PropName) -> bool {
        match self {
            PropRequest::Prop(names) => names.contains(name),
            PropRequest::AllProp { .. } | PropRequest::PropName => true,
        }
    }

    /// Whether `name` is named explicitly: in a `prop` list or an
    /// allprop `include`. Expensive properties (`address-data`,
    /// `calendar-data`) are served only when this holds.
    pub fn names(&self, name: &PropName) -> bool {
        match self {
            PropRequest::Prop(names) => names.contains(name),
            PropRequest::AllProp { include } => include.contains(name),
            PropRequest::PropName => false,
        }
    }
}

/// Parse a `PROPFIND` body. An empty (or whitespace-only) body is
/// allprop.
pub fn parse_propfind(body: &[u8]) -> XmlResult<PropRequest> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Ok(PropRequest::AllProp {
            include: Vec::new(),
        });
    }
    let root = parse_xml(body)?;
    if !root.is(DAV_NS, "propfind") {
        return Err(XmlError("propfind body has the wrong root element"));
    }
    prop_request(&root)?.ok_or(XmlError("propfind body asks for nothing"))
}

/// The `allprop`/`propname`/`prop` child of `parent`, if any.
fn prop_request(parent: &XmlElement) -> XmlResult<Option<PropRequest>> {
    if let Some(prop) = parent.child(DAV_NS, "prop") {
        return Ok(Some(PropRequest::Prop(
            prop.children
                .iter()
                .map(|child| child.name.clone())
                .collect(),
        )));
    }
    if parent.child(DAV_NS, "propname").is_some() {
        return Ok(Some(PropRequest::PropName));
    }
    if parent.child(DAV_NS, "allprop").is_some() {
        let include = parent
            .child(DAV_NS, "include")
            .map(|include| {
                include
                    .children
                    .iter()
                    .map(|child| child.name.clone())
                    .collect()
            })
            .unwrap_or_default();
        return Ok(Some(PropRequest::AllProp { include }));
    }
    Ok(None)
}

/// A CalDAV `time-range` (RFC 4791 §9.9), in UTC. Either bound may be
/// absent; a present one was a valid `YYYYMMDDTHHMMSSZ` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeRange {
    pub start: Option<OffsetDateTime>,
    pub end: Option<OffsetDateTime>,
}

/// A parsed `REPORT` body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// The root element's name, e.g. `card:addressbook-multiget`,
    /// `cal:calendar-query`, `d:sync-collection`.
    pub name: PropName,
    /// The `allprop`/`propname`/`prop` child, when present.
    pub props: Option<PropRequest>,
    /// The text of every `DAV:href` child of the root (multiget), in
    /// document order and trimmed, still percent-encoded as sent.
    pub hrefs: Vec<String>,
    /// The root's `filter` child (CardDAV or CalDAV namespace), as-is.
    pub filter: Option<XmlElement>,
    /// The first CalDAV `time-range` anywhere under `filter`.
    pub time_range: Option<TimeRange>,
    /// The whole body, for anything the fields above do not cover
    /// (`sync-token`, `limit`, `expand`, ...).
    pub root: XmlElement,
}

impl Report {
    /// Whether this is the report `local` in `namespace`.
    pub fn is(&self, namespace: &str, local: &str) -> bool {
        self.name.is(namespace, local)
    }
}

/// Parse a `REPORT` body. Any report name is accepted; the handler
/// decides which it supports.
pub fn parse_report(body: &[u8]) -> XmlResult<Report> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Err(XmlError("report body is empty"));
    }
    let root = parse_xml(body)?;
    let props = prop_request(&root)?;
    let hrefs = root
        .children_named(DAV_NS, "href")
        .map(|href| href.text.trim().to_string())
        .collect();
    let filter = root
        .child(CALDAV_NS, "filter")
        .or_else(|| root.child(CARDDAV_NS, "filter"))
        .cloned();
    let time_range = match &filter {
        Some(filter) => match filter.descendants(CALDAV_NS, "time-range").first() {
            Some(range) => Some(TimeRange {
                start: range.attribute("start").map(parse_utc).transpose()?,
                end: range.attribute("end").map(parse_utc).transpose()?,
            }),
            None => None,
        },
        None => None,
    };
    Ok(Report {
        name: root.name.clone(),
        props,
        hrefs,
        filter,
        time_range,
        root,
    })
}

/// Parse an iCalendar UTC date-time (`20060104T000000Z`).
pub fn parse_utc(value: &str) -> XmlResult<OffsetDateTime> {
    let format = format_description!("[year][month][day]T[hour][minute][second]Z");
    PrimitiveDateTime::parse(value.trim(), format)
        .map(PrimitiveDateTime::assume_utc)
        .map_err(|_| XmlError("invalid time-range value"))
}

/// A response element: a property with its value, or a node inside a
/// property value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XmlNode {
    pub name: PropName,
    pub attributes: Vec<(String, String)>,
    pub value: XmlValue,
}

/// The content of an [`XmlNode`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XmlValue {
    /// `<name/>`.
    Empty,
    /// Escaped text content.
    Text(String),
    /// Child elements.
    Children(Vec<XmlNode>),
}

impl XmlNode {
    /// `<name/>`.
    pub fn empty(name: PropName) -> Self {
        Self {
            name,
            attributes: Vec::new(),
            value: XmlValue::Empty,
        }
    }

    /// `<name>text</name>`, escaped on rendering.
    pub fn text(name: PropName, text: impl Into<String>) -> Self {
        Self {
            name,
            attributes: Vec::new(),
            value: XmlValue::Text(text.into()),
        }
    }

    /// `<name>children</name>`.
    pub fn children(name: PropName, children: Vec<XmlNode>) -> Self {
        Self {
            name,
            attributes: Vec::new(),
            value: XmlValue::Children(children),
        }
    }

    /// `<name><d:href>href</d:href></name>`.
    pub fn href(name: PropName, href: impl Into<String>) -> Self {
        Self::hrefs(name, vec![href.into()])
    }

    /// `<name>` with one `<d:href>` per entry.
    pub fn hrefs(name: PropName, hrefs: Vec<String>) -> Self {
        Self::children(
            name,
            hrefs
                .into_iter()
                .map(|href| XmlNode::text(PropName::dav("href"), href))
                .collect(),
        )
    }

    /// The same node with one more attribute.
    pub fn with_attribute(mut self, name: &str, value: impl Into<String>) -> Self {
        self.attributes.push((name.to_string(), value.into()));
        self
    }
}

/// Builders for the properties every DAV collection or principal
/// serves. Handlers add their own (`addressbook-home-set`,
/// `calendar-data`, ...) with [`XmlNode`] directly.
pub mod props {
    use super::{PropName, XmlNode};

    /// `d:resourcetype`: `<d:collection/>` when `collection`, plus the
    /// given extra types (`card:addressbook`, `cal:calendar`,
    /// `d:principal`).
    pub fn resourcetype(collection: bool, extra: &[PropName]) -> XmlNode {
        let mut types = Vec::new();
        if collection {
            types.push(XmlNode::empty(PropName::dav("collection")));
        }
        types.extend(extra.iter().cloned().map(XmlNode::empty));
        if types.is_empty() {
            XmlNode::empty(PropName::dav("resourcetype"))
        } else {
            XmlNode::children(PropName::dav("resourcetype"), types)
        }
    }

    /// `d:current-user-principal` (RFC 5397).
    pub fn current_user_principal(href: &str) -> XmlNode {
        XmlNode::href(PropName::dav("current-user-principal"), href)
    }

    /// `d:principal-URL`.
    pub fn principal_url(href: &str) -> XmlNode {
        XmlNode::href(PropName::dav("principal-URL"), href)
    }

    /// `d:displayname`.
    pub fn displayname(name: &str) -> XmlNode {
        XmlNode::text(PropName::dav("displayname"), name)
    }

    /// `d:getetag`; `etag` is the full quoted value (`"abc"`).
    pub fn getetag(etag: &str) -> XmlNode {
        XmlNode::text(PropName::dav("getetag"), etag)
    }

    /// `d:getcontenttype`.
    pub fn getcontenttype(content_type: &str) -> XmlNode {
        XmlNode::text(PropName::dav("getcontenttype"), content_type)
    }

    /// `d:sync-token` (RFC 6578), an opaque URI the handler mints.
    pub fn sync_token(token: &str) -> XmlNode {
        XmlNode::text(PropName::dav("sync-token"), token)
    }

    /// `cs:getctag`, the Calendar Server collection tag.
    pub fn getctag(tag: &str) -> XmlNode {
        XmlNode::text(PropName::calserver("getctag"), tag)
    }

    /// `d:supported-report-set` listing `reports`.
    pub fn supported_report_set(reports: &[PropName]) -> XmlNode {
        XmlNode::children(
            PropName::dav("supported-report-set"),
            reports
                .iter()
                .map(|report| {
                    XmlNode::children(
                        PropName::dav("supported-report"),
                        vec![XmlNode::children(
                            PropName::dav("report"),
                            vec![XmlNode::empty(report.clone())],
                        )],
                    )
                })
                .collect(),
        )
    }
}

/// One `<d:response>` of a multistatus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultiStatusEntry {
    /// The resource's href, already percent-encoded; escaped for XML on
    /// rendering.
    pub href: String,
    /// Properties returned with `200 OK`.
    pub found: Vec<XmlNode>,
    /// Properties returned (empty) with `404 Not Found`.
    pub missing: Vec<PropName>,
    /// A whole-resource status instead of propstats, e.g. `404` for a
    /// multiget href that does not exist.
    pub status: Option<u16>,
    /// A `<d:error>` precondition or postcondition element after the
    /// status, e.g. `d:number-of-matches-within-limits` with a `507`.
    pub error: Option<PropName>,
}

impl MultiStatusEntry {
    /// A propstat entry.
    pub fn props(href: impl Into<String>, found: Vec<XmlNode>, missing: Vec<PropName>) -> Self {
        Self {
            href: href.into(),
            found,
            missing,
            status: None,
            error: None,
        }
    }

    /// A propstat entry computed from a request and the resource's
    /// available properties (see [`PropRequest::select`]).
    pub fn for_request(
        href: impl Into<String>,
        request: &PropRequest,
        available: Vec<XmlNode>,
    ) -> Self {
        let (found, missing) = request.select(available);
        Self::props(href, found, missing)
    }

    /// A status-only entry.
    pub fn status(href: impl Into<String>, status: u16) -> Self {
        Self {
            href: href.into(),
            found: Vec::new(),
            missing: Vec::new(),
            status: Some(status),
            error: None,
        }
    }

    /// The same entry with a `<d:error>` element naming `condition`.
    pub fn with_error(mut self, condition: PropName) -> Self {
        self.error = Some(condition);
        self
    }
}

/// Render a `207 Multi-Status` body. `sync_token` adds the top-level
/// `<d:sync-token>` of a `sync-collection` report.
pub fn render_multistatus(entries: &[MultiStatusEntry], sync_token: Option<&str>) -> Vec<u8> {
    let mut out = String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<d:multistatus");
    for (namespace, prefix) in PREFIXES {
        let _ = write!(out, " xmlns:{prefix}=\"{}\"", escape(namespace));
    }
    out.push('>');
    for entry in entries {
        out.push_str("<d:response><d:href>");
        out.push_str(&escape(&entry.href));
        out.push_str("</d:href>");
        if let Some(status) = entry.status {
            push_status(&mut out, status);
            if let Some(condition) = &entry.error {
                out.push_str("<d:error>");
                render_node(&mut out, &XmlNode::empty(condition.clone()));
                out.push_str("</d:error>");
            }
        } else {
            if !entry.found.is_empty() || entry.missing.is_empty() {
                out.push_str("<d:propstat><d:prop>");
                for node in &entry.found {
                    render_node(&mut out, node);
                }
                out.push_str("</d:prop>");
                push_status(&mut out, 200);
                out.push_str("</d:propstat>");
            }
            if !entry.missing.is_empty() {
                out.push_str("<d:propstat><d:prop>");
                for name in &entry.missing {
                    render_node(&mut out, &XmlNode::empty(name.clone()));
                }
                out.push_str("</d:prop>");
                push_status(&mut out, 404);
                out.push_str("</d:propstat>");
            }
        }
        out.push_str("</d:response>");
    }
    if let Some(token) = sync_token {
        out.push_str("<d:sync-token>");
        out.push_str(&escape(token));
        out.push_str("</d:sync-token>");
    }
    out.push_str("</d:multistatus>\n");
    out.into_bytes()
}

fn push_status(out: &mut String, status: u16) {
    let _ = write!(
        out,
        "<d:status>HTTP/1.1 {status} {}</d:status>",
        super::http::reason_phrase(status)
    );
}

/// Render one node with its known prefix, or an inline default
/// namespace when the namespace has none.
fn render_node(out: &mut String, node: &XmlNode) {
    let (tag, declaration) = match PREFIXES
        .iter()
        .find(|(namespace, _)| *namespace == node.name.namespace)
    {
        Some((_, prefix)) => (format!("{prefix}:{}", node.name.local), None),
        None => (node.name.local.clone(), Some(&node.name.namespace)),
    };
    out.push('<');
    out.push_str(&tag);
    if let Some(namespace) = declaration {
        let _ = write!(out, " xmlns=\"{}\"", escape(namespace));
    }
    for (name, value) in &node.attributes {
        let _ = write!(out, " {name}=\"{}\"", escape(value));
    }
    match &node.value {
        XmlValue::Empty => out.push_str("/>"),
        XmlValue::Text(text) => {
            out.push('>');
            out.push_str(&escape(text));
            let _ = write!(out, "</{tag}>");
        }
        XmlValue::Children(children) => {
            out.push('>');
            for child in children {
                render_node(out, child);
            }
            let _ = write!(out, "</{tag}>");
        }
    }
}

/// Escape text for an XML element or a double-quoted attribute. CR is
/// written as a character reference so that CRLF reaches the client
/// intact; control characters XML 1.0 cannot carry are dropped.
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            // A raw CR would not survive the reader's line-end
            // normalization; the character reference does.
            '\r' => out.push_str("&#xD;"),
            '\t' | '\n' => out.push(character),
            c if (c as u32) < 0x20 || c == '\u{FFFE}' || c == '\u{FFFF}' => {}
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_propfind_is_allprop() {
        assert_eq!(
            parse_propfind(b"").unwrap(),
            PropRequest::AllProp {
                include: Vec::new()
            }
        );
        assert_eq!(
            parse_propfind(b" \r\n").unwrap(),
            PropRequest::AllProp {
                include: Vec::new()
            }
        );
    }

    #[test]
    fn propfind_prop_list_resolves_namespaces() {
        let body = br#"<?xml version="1.0"?>
            <A:propfind xmlns:A="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav"
                        xmlns:CS="http://calendarserver.org/ns/">
              <A:prop>
                <A:resourcetype/><A:displayname/>
                <C:addressbook-home-set/>
                <CS:getctag/>
                <x:other xmlns:x="urn:example"/>
                <plain/>
              </A:prop>
            </A:propfind>"#;
        let PropRequest::Prop(names) = parse_propfind(body).unwrap() else {
            panic!("a prop list");
        };
        assert_eq!(
            names,
            vec![
                PropName::dav("resourcetype"),
                PropName::dav("displayname"),
                PropName::carddav("addressbook-home-set"),
                PropName::calserver("getctag"),
                PropName::new("urn:example", "other"),
                PropName::new("", "plain"),
            ]
        );
    }

    #[test]
    fn propfind_default_namespace_and_variants() {
        let body = br#"<propfind xmlns="DAV:"><propname/></propfind>"#;
        assert_eq!(parse_propfind(body).unwrap(), PropRequest::PropName);
        let body = br#"<propfind xmlns="DAV:"><allprop/><include><getetag/></include></propfind>"#;
        assert_eq!(
            parse_propfind(body).unwrap(),
            PropRequest::AllProp {
                include: vec![PropName::dav("getetag")]
            }
        );
    }

    #[test]
    fn bad_propfind_bodies_are_refused() {
        for body in [
            &b"<propfind xmlns=\"DAV:\"><prop>"[..],
            b"<x:propfind><x:prop/></x:propfind>",
            b"<propfind xmlns=\"urn:other\"><prop/></propfind>",
            b"<propfind xmlns=\"DAV:\"/>",
            b"<!DOCTYPE d [<!ENTITY a \"b\">]><propfind xmlns=\"DAV:\"><prop/></propfind>",
            b"<propfind xmlns=\"DAV:\"><prop>&a;</prop></propfind>",
            b"<a xmlns=\"DAV:\"/><b/>",
            b"not xml",
        ] {
            assert!(parse_propfind(body).is_err(), "{body:?}");
        }
    }

    #[test]
    fn deep_nesting_is_refused() {
        let mut body = String::from("<propfind xmlns=\"DAV:\">");
        body.push_str(&"<a>".repeat(MAX_DEPTH + 1));
        body.push_str(&"</a>".repeat(MAX_DEPTH + 1));
        body.push_str("</propfind>");
        assert_eq!(
            parse_xml(body.as_bytes()).unwrap_err(),
            XmlError("xml body is nested too deeply")
        );
    }

    #[test]
    fn text_resolves_predefined_and_character_references() {
        let root = parse_xml(b"<a>x &amp; y &#60;&#x3E; <![CDATA[<z>]]></a>").unwrap();
        assert_eq!(root.text, "x & y <> <z>");
    }

    #[test]
    fn multiget_report_collects_hrefs_and_props() {
        let body = br#"<?xml version="1.0" encoding="utf-8" ?>
            <C:addressbook-multiget xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav">
              <D:prop><D:getetag/><C:address-data/></D:prop>
              <D:href>/card/a.vcf</D:href>
              <D:href> /card/b%20c.vcf </D:href>
            </C:addressbook-multiget>"#;
        let report = parse_report(body).unwrap();
        assert!(report.is(CARDDAV_NS, "addressbook-multiget"));
        assert_eq!(report.hrefs, vec!["/card/a.vcf", "/card/b%20c.vcf"]);
        assert_eq!(
            report.props,
            Some(PropRequest::Prop(vec![
                PropName::dav("getetag"),
                PropName::carddav("address-data")
            ]))
        );
        assert!(report.filter.is_none());
        assert!(report.time_range.is_none());
    }

    #[test]
    fn calendar_query_report_exposes_the_time_range() {
        let body = br#"<C:calendar-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
              <D:prop><D:getetag/></D:prop>
              <C:filter>
                <C:comp-filter name="VCALENDAR">
                  <C:comp-filter name="VEVENT">
                    <C:time-range start="20060104T000000Z" end="20060105T000000Z"/>
                  </C:comp-filter>
                </C:comp-filter>
              </C:filter>
            </C:calendar-query>"#;
        let report = parse_report(body).unwrap();
        assert!(report.is(CALDAV_NS, "calendar-query"));
        let range = report.time_range.unwrap();
        assert_eq!(range.start.unwrap().unix_timestamp(), 1_136_332_800);
        assert_eq!(range.end.unwrap().unix_timestamp(), 1_136_419_200);
        let filter = report.filter.unwrap();
        let comps = filter.descendants(CALDAV_NS, "comp-filter");
        assert_eq!(comps.len(), 2);
        assert_eq!(comps[1].attribute("name"), Some("VEVENT"));
    }

    #[test]
    fn an_open_time_range_and_a_bad_one() {
        let body = br#"<C:calendar-query xmlns:C="urn:ietf:params:xml:ns:caldav"><C:filter>
            <C:comp-filter name="VCALENDAR"><C:time-range start="20240101T000000Z"/></C:comp-filter>
            </C:filter></C:calendar-query>"#;
        let range = parse_report(body).unwrap().time_range.unwrap();
        assert!(range.start.is_some());
        assert!(range.end.is_none());
        let body = br#"<C:calendar-query xmlns:C="urn:ietf:params:xml:ns:caldav"><C:filter>
            <C:time-range start="yesterday"/></C:filter></C:calendar-query>"#;
        assert!(parse_report(body).is_err());
        assert!(parse_report(b"").is_err());
    }

    #[test]
    fn select_splits_found_and_missing() {
        let available = vec![
            props::displayname("Contacts"),
            props::getetag("\"1\""),
            props::resourcetype(true, &[PropName::carddav("addressbook")]),
        ];
        let request = PropRequest::Prop(vec![
            PropName::dav("getetag"),
            PropName::calserver("getctag"),
        ]);
        let (found, missing) = request.select(available.clone());
        assert_eq!(found, vec![props::getetag("\"1\"")]);
        assert_eq!(missing, vec![PropName::calserver("getctag")]);

        let (found, missing) = PropRequest::PropName.select(available.clone());
        assert_eq!(found.len(), 3);
        assert!(found.iter().all(|node| node.value == XmlValue::Empty));
        assert!(missing.is_empty());

        let all = PropRequest::AllProp {
            include: Vec::new(),
        };
        assert_eq!(all.select(available.clone()).0, available);
    }

    #[test]
    fn multistatus_renders_propstats_and_escapes() {
        let entries = vec![
            MultiStatusEntry::props(
                "/card/a&b.vcf",
                vec![
                    props::displayname("Tom & \"Jerry\" <x>"),
                    props::resourcetype(true, &[PropName::carddav("addressbook")]),
                    XmlNode::text(PropName::new("urn:example", "x"), "1"),
                    XmlNode::empty(PropName::caldav("comp")).with_attribute("name", "VEVENT"),
                ],
                vec![PropName::calserver("getctag")],
            ),
            MultiStatusEntry::status("/card/gone.vcf", 404),
        ];
        let body = String::from_utf8(render_multistatus(&entries, Some("tok&1"))).unwrap();
        assert!(body.starts_with(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<d:multistatus xmlns:d=\"DAV:\""
        ));
        assert!(body.contains("<d:href>/card/a&amp;b.vcf</d:href>"));
        assert!(
            body.contains("<d:displayname>Tom &amp; &quot;Jerry&quot; &lt;x&gt;</d:displayname>")
        );
        assert!(
            body.contains("<d:resourcetype><d:collection/><card:addressbook/></d:resourcetype>")
        );
        assert!(body.contains("<x xmlns=\"urn:example\">1</x>"));
        assert!(body.contains("<cal:comp name=\"VEVENT\"/>"));
        assert!(body.contains("<d:status>HTTP/1.1 200 OK</d:status>"));
        assert!(body.contains(
            "<d:propstat><d:prop><cs:getctag/></d:prop><d:status>HTTP/1.1 404 Not Found</d:status></d:propstat>"
        ));
        assert!(body.contains(
            "<d:response><d:href>/card/gone.vcf</d:href><d:status>HTTP/1.1 404 Not Found</d:status></d:response>"
        ));
        assert!(body.contains("<d:sync-token>tok&amp;1</d:sync-token>"));
        // The rendered body parses back.
        let root = parse_xml(body.as_bytes()).unwrap();
        assert!(root.is(DAV_NS, "multistatus"));
        assert_eq!(root.children_named(DAV_NS, "response").count(), 2);
        let name = root.descendants(DAV_NS, "displayname")[0];
        assert_eq!(name.text, "Tom & \"Jerry\" <x>");
    }

    #[test]
    fn escape_drops_unrepresentable_controls() {
        assert_eq!(escape("a\u{1}b\tc"), "ab\tc");
    }

    #[test]
    fn crlf_survives_rendering_and_parsing() {
        assert_eq!(escape("A\r\nB"), "A&#xD;\nB");
        let data = "BEGIN:VCARD\r\nFN:A\r\n  folded\r\nEND:VCARD\r\n";
        let body = render_multistatus(
            &[MultiStatusEntry::props(
                "/a.vcf",
                vec![XmlNode::text(PropName::carddav("address-data"), data)],
                Vec::new(),
            )],
            None,
        );
        assert!(!body.contains(&b'\r'));
        let root = parse_xml(&body).unwrap();
        assert_eq!(root.descendants(CARDDAV_NS, "address-data")[0].text, data);
        // A raw CRLF in a request body is read as LF.
        let root = parse_xml(b"<a xmlns=\"DAV:\">x\r\ny\rz</a>").unwrap();
        assert_eq!(root.text, "x\ny\nz");
    }

    #[test]
    fn a_status_entry_can_carry_an_error_element() {
        let entry = MultiStatusEntry::status("/book/", 507)
            .with_error(PropName::dav("number-of-matches-within-limits"));
        let body = String::from_utf8(render_multistatus(&[entry], None)).unwrap();
        assert!(body.contains(
            "<d:status>HTTP/1.1 507 Insufficient Storage</d:status><d:error><d:number-of-matches-within-limits/></d:error></d:response>"
        ));
    }

    #[test]
    fn supported_report_set_nests_reports() {
        let node = props::supported_report_set(&[PropName::carddav("addressbook-multiget")]);
        let body = String::from_utf8(render_multistatus(
            &[MultiStatusEntry::props("/", vec![node], Vec::new())],
            None,
        ))
        .unwrap();
        assert!(body.contains("<d:supported-report-set><d:supported-report><d:report><card:addressbook-multiget/></d:report></d:supported-report></d:supported-report-set>"));
    }
}
