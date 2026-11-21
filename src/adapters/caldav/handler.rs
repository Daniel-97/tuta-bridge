//! The CalDAV [`DavHandler`]: URL layout, properties and reports.
//!
//! Layout (every href is ASCII and needs no percent-encoding):
//!
//! | Path                                   | Resource                    |
//! |----------------------------------------|-----------------------------|
//! | `/` and `/caldav/`                     | entry points (discovery)    |
//! | `/caldav/principal/`                   | the user's principal        |
//! | `/caldav/calendars/`                   | the calendar home set       |
//! | `/caldav/calendars/<calendar>/`        | one Tuta calendar           |
//! | `/caldav/calendars/<calendar>/<r>.ics` | one event with its UID      |
//!
//! `<calendar>` is the Tuta calendar group id, `<r>` a hash of the
//! event's UID. A UID with several masters (a series Tuta split with
//! "edit this and all future events") is one resource per master: the
//! earliest keeps the UID's name, so an unsplit series never changes
//! href, and each later one gets a name and a UID derived from its own
//! ids (see [`group_resources`]).
//!
//! Listings, ETags and collection tags come from the metadata cache;
//! iCalendar bodies are rendered from the SDK on each `GET` and for
//! each `calendar-data` a report asks for. A body that no longer
//! matches its cached row (an edit the event bus has not delivered
//! yet) updates the row first, so the ETag served always describes the
//! body served.
//!
//! `Depth: infinity` (and a `PROPFIND` without `Depth`) is served as
//! `Depth: 1`. Reports: `calendar-query` (the first `time-range` of
//! its filter is honoured, `expand` is not) and `calendar-multiget`;
//! any other report is `403`.

use std::sync::Arc;

use async_trait::async_trait;
use futures_util::stream::{self, StreamExt, TryStreamExt};

use super::ical::{render_calendar, EventToRender};
use crate::adapters::dav::xml::{
    props, MultiStatusEntry, PropName, PropRequest, Report, XmlNode, APPLE_ICAL_NS, CALDAV_NS,
};
use crate::adapters::dav::{DavHandler, DavMethod, DavRequest, DavResponse, Depth, WellKnown};
use crate::domain::calendar::{
    collection_tag, group_resources, resource_etag, split_uid, Resource,
};
use crate::domain::{CalendarEvent, CalendarInfo, CalendarRow, Result};
use crate::ports::calendar::{CalendarSource, CalendarStore};
use crate::ports::clock::Clock;

/// The principal.
pub const PRINCIPAL_PATH: &str = "/caldav/principal/";
/// The calendar home set.
pub const HOME_PATH: &str = "/caldav/calendars/";
/// The content type of an event resource.
pub const CALENDAR_CONTENT_TYPE: &str = "text/calendar; charset=utf-8";
/// The content type listed for event resources.
const ITEM_CONTENT_TYPE: &str = "text/calendar; charset=utf-8; component=VEVENT";
/// Resources rendered at once for one report.
const RENDER_CONCURRENCY: usize = 8;

/// What a path names.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Target {
    Entry,
    Principal,
    Home,
    Calendar(String),
    Item(String, String),
    Unknown,
}

/// Resolve a request path or a report href (absolute URLs too).
fn target(path: &str) -> Target {
    let path = match path.find("://") {
        Some(scheme_end) => match path[scheme_end + 3..].find('/') {
            Some(slash) => &path[scheme_end + 3 + slash..],
            None => "/",
        },
        None => path,
    };
    let path = path.split(['?', '#']).next().unwrap_or("");
    let Ok(decoded) = urlencoding::decode(path) else {
        return Target::Unknown;
    };
    let segments: Vec<&str> = decoded.split('/').filter(|s| !s.is_empty()).collect();
    let safe = |segment: &str| {
        !segment.is_empty()
            && segment
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    };
    match segments.as_slice() {
        [] | ["caldav"] => Target::Entry,
        ["caldav", "principal"] => Target::Principal,
        ["caldav", "calendars"] => Target::Home,
        ["caldav", "calendars", calendar] if safe(calendar) => {
            Target::Calendar((*calendar).to_string())
        }
        ["caldav", "calendars", calendar, item] if safe(calendar) => {
            match item.strip_suffix(".ics") {
                Some(resource) if safe(resource) => {
                    Target::Item((*calendar).to_string(), resource.to_string())
                }
                _ => Target::Unknown,
            }
        }
        _ => Target::Unknown,
    }
}

fn calendar_href(calendar_id: &str) -> String {
    format!("{HOME_PATH}{calendar_id}/")
}

fn item_href(calendar_id: &str, resource: &str) -> String {
    format!("{HOME_PATH}{calendar_id}/{resource}.ics")
}

/// The read-only CalDAV handler.
pub struct CalDavHandler {
    pub account_id: i64,
    /// The account address: the principal's `calendar-user-address-set`.
    pub user_address: String,
    pub store: Arc<dyn CalendarStore>,
    pub source: Arc<dyn CalendarSource>,
    pub clock: Arc<dyn Clock>,
}

/// A rendered resource.
struct Rendered {
    etag: String,
    body: String,
}

impl CalDavHandler {
    async fn calendar(&self, calendar_id: &str) -> Result<Option<CalendarInfo>> {
        Ok(self
            .store
            .calendars(self.account_id)
            .await?
            .into_iter()
            .find(|calendar| calendar.calendar_id == calendar_id))
    }

    /// Load and render one resource from its cached rows. Rows whose
    /// event changed are updated first; rows whose event vanished are
    /// removed. `None` when nothing of the resource is left.
    async fn render(&self, calendar_id: &str, resource: &Resource) -> Result<Option<Rendered>> {
        let now = self.clock.now_ms();
        let mut loaded: Vec<(CalendarEvent, CalendarRow, Vec<String>)> = Vec::new();
        for row in &resource.rows {
            let Some(event) = self.source.event(&row.list_id, &row.element_id).await? else {
                self.store
                    .remove_calendar_row(self.account_id, &row.list_id, &row.element_id)
                    .await?;
                continue;
            };
            let fresh = event.row(calendar_id, now);
            let stored = if fresh.fingerprint == row.fingerprint && fresh.resource == row.resource {
                row.clone()
            } else {
                self.store
                    .upsert_calendar_row(self.account_id, &fresh)
                    .await?
            };
            if stored.resource != row.resource {
                // The UID changed: the event now lives at another href.
                continue;
            }
            let alarms = self.source.alarm_triggers(&event.alarm_ids).await?;
            let mut event = event;
            if let (Some((list_id, element_id)), Some(uid)) = (&resource.split_master, &event.uid) {
                // A later half of a split series: its own UID.
                event.uid = Some(split_uid(uid, list_id, element_id));
            }
            loaded.push((event, stored, alarms));
        }
        if loaded.is_empty() {
            return Ok(None);
        }
        let etag = resource_etag(loaded.iter().map(|(_, row, _)| row));
        let items: Vec<EventToRender<'_>> = loaded
            .iter()
            .map(|(event, row, alarms)| EventToRender {
                event,
                modified_ms: row.modified_ms,
                alarms,
            })
            .collect();
        Ok(Some(Rendered {
            etag,
            body: render_calendar(&items),
        }))
    }

    /// The propstat entry of one resource for `wanted`; renders only
    /// when `calendar-data` is named.
    async fn item_entry(
        &self,
        calendar_id: &str,
        name: &str,
        resource: &Resource,
        wanted: &PropRequest,
    ) -> Result<MultiStatusEntry> {
        let href = item_href(calendar_id, name);
        let calendar_data = PropName::caldav("calendar-data");
        let mut available = vec![
            props::getcontenttype(ITEM_CONTENT_TYPE),
            props::resourcetype(false, &[]),
        ];
        if wanted.names(&calendar_data) {
            match self.render(calendar_id, resource).await? {
                Some(rendered) => {
                    available.push(props::getetag(&rendered.etag));
                    available.push(XmlNode::text(calendar_data, rendered.body));
                }
                None => return Ok(MultiStatusEntry::status(href, 404)),
            }
        } else {
            available.push(props::getetag(&resource_etag(&resource.rows)));
        }
        Ok(MultiStatusEntry::for_request(href, wanted, available))
    }

    /// Entries for many resources, rendered a few at a time, in order.
    async fn item_entries(
        &self,
        calendar_id: &str,
        resources: Vec<(String, Resource)>,
        wanted: &PropRequest,
    ) -> Result<Vec<MultiStatusEntry>> {
        stream::iter(resources)
            .map(|(name, resource)| async move {
                self.item_entry(calendar_id, &name, &resource, wanted).await
            })
            .buffered(RENDER_CONCURRENCY)
            .try_collect()
            .await
    }

    fn entry_props(&self) -> Vec<XmlNode> {
        vec![
            props::resourcetype(true, &[]),
            props::current_user_principal(PRINCIPAL_PATH),
            XmlNode::href(PropName::caldav("calendar-home-set"), HOME_PATH),
        ]
    }

    fn principal_props(&self) -> Vec<XmlNode> {
        vec![
            props::resourcetype(true, &[PropName::dav("principal")]),
            props::displayname(&self.user_address),
            props::current_user_principal(PRINCIPAL_PATH),
            props::principal_url(PRINCIPAL_PATH),
            XmlNode::href(PropName::caldav("calendar-home-set"), HOME_PATH),
            XmlNode::href(
                PropName::caldav("calendar-user-address-set"),
                format!("mailto:{}", self.user_address),
            ),
        ]
    }

    fn home_props(&self) -> Vec<XmlNode> {
        vec![
            props::resourcetype(true, &[]),
            props::displayname("Calendars"),
            props::current_user_principal(PRINCIPAL_PATH),
            XmlNode::href(PropName::dav("owner"), PRINCIPAL_PATH),
            read_only_privileges(),
        ]
    }

    async fn calendar_props(&self, calendar: &CalendarInfo) -> Result<Vec<XmlNode>> {
        let rows = self
            .store
            .calendar_rows(self.account_id, &calendar.calendar_id)
            .await?;
        let tags: Vec<(String, String)> = group_resources(rows)
            .into_iter()
            .map(|(name, resource)| {
                let etag = resource_etag(&resource.rows);
                (name, etag)
            })
            .collect();
        let ctag = collection_tag(&tags);
        let name = if calendar.name.trim().is_empty() {
            "Calendar"
        } else {
            calendar.name.as_str()
        };
        let mut nodes = vec![
            props::resourcetype(true, &[PropName::caldav("calendar")]),
            props::displayname(name),
            props::current_user_principal(PRINCIPAL_PATH),
            XmlNode::href(PropName::dav("owner"), PRINCIPAL_PATH),
            XmlNode::children(
                PropName::caldav("supported-calendar-component-set"),
                vec![XmlNode::empty(PropName::caldav("comp")).with_attribute("name", "VEVENT")],
            ),
            props::supported_report_set(&[
                PropName::caldav("calendar-query"),
                PropName::caldav("calendar-multiget"),
            ]),
            props::getctag(&ctag),
            props::sync_token(&format!("http://tuta-bridge.invalid/ns/sync/{ctag}")),
            read_only_privileges(),
        ];
        let color = calendar.color.trim_start_matches('#');
        if color.len() == 6 && color.chars().all(|c| c.is_ascii_hexdigit()) {
            nodes.push(XmlNode::text(
                PropName::new(APPLE_ICAL_NS, "calendar-color"),
                format!("#{}", color.to_ascii_uppercase()),
            ));
        }
        Ok(nodes)
    }

    async fn propfind(&self, request: &DavRequest, wanted: &PropRequest) -> Result<DavResponse> {
        // Infinity (explicit or implied) is served as one level.
        let deep = !matches!(request.depth, Some(Depth::Zero));
        let mut entries = Vec::new();
        match target(&request.path) {
            Target::Entry => entries.push(MultiStatusEntry::for_request(
                request.path.clone(),
                wanted,
                self.entry_props(),
            )),
            Target::Principal => entries.push(MultiStatusEntry::for_request(
                PRINCIPAL_PATH,
                wanted,
                self.principal_props(),
            )),
            Target::Home => {
                entries.push(MultiStatusEntry::for_request(
                    HOME_PATH,
                    wanted,
                    self.home_props(),
                ));
                if deep {
                    for calendar in self.store.calendars(self.account_id).await? {
                        let nodes = self.calendar_props(&calendar).await?;
                        entries.push(MultiStatusEntry::for_request(
                            calendar_href(&calendar.calendar_id),
                            wanted,
                            nodes,
                        ));
                    }
                }
            }
            Target::Calendar(calendar_id) => {
                let Some(calendar) = self.calendar(&calendar_id).await? else {
                    return Ok(DavResponse::not_found());
                };
                let nodes = self.calendar_props(&calendar).await?;
                entries.push(MultiStatusEntry::for_request(
                    calendar_href(&calendar_id),
                    wanted,
                    nodes,
                ));
                if deep {
                    let rows = self
                        .store
                        .calendar_rows(self.account_id, &calendar_id)
                        .await?;
                    let resources: Vec<_> = group_resources(rows).into_iter().collect();
                    entries.extend(self.item_entries(&calendar_id, resources, wanted).await?);
                }
            }
            Target::Item(calendar_id, name) => {
                let Some(resource) = self.resource(&calendar_id, &name).await? else {
                    return Ok(DavResponse::not_found());
                };
                let entry = self
                    .item_entry(&calendar_id, &name, &resource, wanted)
                    .await?;
                if entry.status == Some(404) {
                    return Ok(DavResponse::not_found());
                }
                entries.push(entry);
            }
            Target::Unknown => return Ok(DavResponse::not_found()),
        }
        Ok(DavResponse::multistatus(&entries, None))
    }

    /// One resource of a calendar by name, `None` when it has no rows.
    async fn resource(&self, calendar_id: &str, name: &str) -> Result<Option<Resource>> {
        let rows = self
            .store
            .calendar_rows(self.account_id, calendar_id)
            .await?;
        Ok(group_resources(rows).remove(name))
    }

    async fn report(&self, request: &DavRequest, report: &Report) -> Result<DavResponse> {
        let Target::Calendar(calendar_id) = target(&request.path) else {
            return Ok(DavResponse::forbidden());
        };
        if self.calendar(&calendar_id).await?.is_none() {
            return Ok(DavResponse::not_found());
        }
        let wanted = report
            .props
            .clone()
            .unwrap_or_else(|| PropRequest::Prop(vec![PropName::dav("getetag")]));
        let groups = group_resources(
            self.store
                .calendar_rows(self.account_id, &calendar_id)
                .await?,
        );

        if report.is(CALDAV_NS, "calendar-multiget") {
            let mut entries = Vec::with_capacity(report.hrefs.len());
            let mut wanted_resources = Vec::new();
            for href in &report.hrefs {
                match target(href) {
                    Target::Item(calendar, resource)
                        if calendar == calendar_id && groups.contains_key(&resource) =>
                    {
                        wanted_resources.push((resource.clone(), groups[&resource].clone()));
                    }
                    _ => entries.push(MultiStatusEntry::status(href.clone(), 404)),
                }
            }
            entries.extend(
                self.item_entries(&calendar_id, wanted_resources, &wanted)
                    .await?,
            );
            return Ok(DavResponse::multistatus(&entries, None));
        }

        if report.is(CALDAV_NS, "calendar-query") {
            if !asks_for_events(report) {
                return Ok(DavResponse::multistatus(&[], None));
            }
            let (from, to) = match report.time_range {
                Some(range) => (
                    range.start.map(millis).unwrap_or(i64::MIN),
                    range.end.map(millis).unwrap_or(i64::MAX),
                ),
                None => (i64::MIN, i64::MAX),
            };
            let matching: Vec<_> = groups
                .into_iter()
                .filter(|(_, resource)| resource.rows.iter().any(|row| row.may_overlap(from, to)))
                .collect();
            let entries = self.item_entries(&calendar_id, matching, &wanted).await?;
            return Ok(DavResponse::multistatus(&entries, None));
        }

        Ok(DavResponse::forbidden())
    }

    async fn get(&self, request: &DavRequest) -> Result<DavResponse> {
        match target(&request.path) {
            Target::Item(calendar_id, name) => {
                let Some(resource) = self.resource(&calendar_id, &name).await? else {
                    return Ok(DavResponse::not_found());
                };
                match self.render(&calendar_id, &resource).await? {
                    Some(rendered) => Ok(DavResponse::ok(
                        CALENDAR_CONTENT_TYPE,
                        rendered.body.into_bytes(),
                    )
                    .with_etag(&rendered.etag)),
                    None => Ok(DavResponse::not_found()),
                }
            }
            Target::Unknown => Ok(DavResponse::not_found()),
            _ => Ok(DavResponse::text(405, "method not allowed")
                .with_header("Allow", "OPTIONS, PROPFIND, REPORT")),
        }
    }
}

/// `d:current-user-privilege-set` with `read` only: clients show the
/// calendars as read-only.
fn read_only_privileges() -> XmlNode {
    XmlNode::children(
        PropName::dav("current-user-privilege-set"),
        vec![XmlNode::children(
            PropName::dav("privilege"),
            vec![XmlNode::empty(PropName::dav("read"))],
        )],
    )
}

/// Whether a `calendar-query` filter can match a `VEVENT`: no filter,
/// or `VCALENDAR` with no inner component filter or a `VEVENT` one.
fn asks_for_events(report: &Report) -> bool {
    let Some(filter) = &report.filter else {
        return true;
    };
    let Some(calendar) = filter.child(CALDAV_NS, "comp-filter") else {
        return true;
    };
    if calendar
        .attribute("name")
        .is_some_and(|name| !name.eq_ignore_ascii_case("VCALENDAR"))
    {
        return false;
    }
    match calendar.child(CALDAV_NS, "comp-filter") {
        Some(component) => component
            .attribute("name")
            .is_none_or(|name| name.eq_ignore_ascii_case("VEVENT")),
        None => true,
    }
}

fn millis(at: time::OffsetDateTime) -> i64 {
    i64::try_from(at.unix_timestamp_nanos() / 1_000_000).unwrap_or(i64::MAX)
}

#[async_trait]
impl DavHandler for CalDavHandler {
    fn label(&self) -> &'static str {
        "caldav"
    }

    fn compliance_classes(&self) -> &'static [&'static str] {
        &["calendar-access"]
    }

    fn well_known(&self, service: WellKnown) -> Option<String> {
        match service {
            WellKnown::CalDav => Some(PRINCIPAL_PATH.to_string()),
            WellKnown::CardDav => None,
        }
    }

    async fn handle(&self, request: &DavRequest) -> Result<DavResponse> {
        match &request.method {
            DavMethod::Get => self.get(request).await,
            DavMethod::Propfind(wanted) => self.propfind(request, wanted).await,
            DavMethod::Report(report) => self.report(request, report).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_resolve_to_targets() {
        assert_eq!(target("/"), Target::Entry);
        assert_eq!(target("/caldav"), Target::Entry);
        assert_eq!(target("/caldav/principal/"), Target::Principal);
        assert_eq!(target("/caldav/calendars"), Target::Home);
        assert_eq!(
            target("/caldav/calendars/Ab-_9/"),
            Target::Calendar("Ab-_9".into())
        );
        assert_eq!(
            target("https://127.0.0.1:9933/caldav/calendars/c/0f.ics"),
            Target::Item("c".into(), "0f".into())
        );
        assert_eq!(
            target("/caldav/calendars/c/%30f.ics"),
            Target::Item("c".into(), "0f".into())
        );
        assert_eq!(target("/caldav/calendars/c/0f.vcf"), Target::Unknown);
        assert_eq!(target("/caldav/calendars/../x/"), Target::Unknown);
        assert_eq!(target("/other"), Target::Unknown);
    }
}
