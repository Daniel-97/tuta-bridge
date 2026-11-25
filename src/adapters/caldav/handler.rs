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
//! `PUT` and `DELETE` are served when a writer is wired. A `PUT` is an
//! update only: the href must name a cached event row — creating
//! events is refused with a fixed precondition (the SDK's generic
//! create cannot serve Tuta's custom-id events: a client creates its
//! events in the Tuta client and edits them here). The RFC
//! preconditions are honoured against the stored ETag, and the stored
//! master row's content fingerprint is handed on: the writer re-checks
//! it against the freshly loaded event, so a cache-matching but stale
//! write still answers `412` instead of overwriting a remote edit the
//! event bus has not delivered yet. One whole write per calendar runs
//! at a time — the put and the cache apply of its outcome never
//! interleave. The parsed event's organizer must be one of the
//! account's addresses, and the write goes to Tuta first; the row is
//! then refreshed from the reloaded event — the same refresh a `GET`
//! applies — so the ETag answered is the one the reader serves and
//! the event echo is a no-op against it. A cache apply that fails
//! after the remote write held still answers the success (the stale
//! mark heals the row on the next read). Two degenerate outcomes
//! answer honestly: a state that cannot be read back after a held
//! write answers the fixed `503` (the row stays as it was, the client
//! retries), and a legacy event whose uid a write repaired moves to
//! another href, answered `204` without an ETag for a row this href no
//! longer serves. A `DELETE` removes the whole resource: every
//! event of the series is deleted remotely first, then the rows are
//! removed the way a delete event removes them (the calendar cache
//! keeps no tombstones, so a href that never existed answers `404` and
//! writes nothing). Without a writer both answer the fixed `403` the
//! session answered before.
//!
//! `Depth: infinity` (and a `PROPFIND` without `Depth`) is served as
//! `Depth: 1`. Reports: `calendar-query` (the first `time-range` of
//! its filter is honoured, `expand` is not) and `calendar-multiget`;
//! any other report is `403`.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use futures_util::stream::{self, StreamExt, TryStreamExt};
use tokio::sync::Mutex;

use super::ical::{render_calendar, EventToRender};
use super::import::{parse_event, ImportError};
use crate::adapters::dav::xml::{
    props, MultiStatusEntry, PropName, PropRequest, Report, XmlNode, APPLE_ICAL_NS, CALDAV_NS,
};
use crate::adapters::dav::{
    etag_matches, strong_etag_matches, writer_refusal, DavHandler, DavMethod, DavRequest,
    DavResponse, Depth, WellKnown,
};
use crate::adapters::tuta::dav_writer::choose_event_list;
use crate::app::calendar_sync::CalendarSync;
use crate::domain::calendar::{
    collection_tag, group_resources, resource_etag, split_uid, Resource,
};
use crate::domain::{CalendarEvent, CalendarInfo, CalendarRow, Error, Result};
use crate::ports::calendar::{CalendarSource, CalendarStore};
use crate::ports::clock::Clock;
use crate::ports::dav_writer::{CalendarRef, CalendarWriter, EventRef};

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

/// The CalDAV handler: read-only until a [`CalendarWriter`] is wired,
/// writable in place through [`CalDavHandler::with_writer`].
pub struct CalDavHandler {
    /// The calendar cache: also the seam the optimistic row updates of
    /// a write land through.
    sync: Arc<CalendarSync>,
    account_id: i64,
    /// The account address: the principal's `calendar-user-address-set`.
    user_address: String,
    store: Arc<dyn CalendarStore>,
    source: Arc<dyn CalendarSource>,
    clock: Arc<dyn Clock>,
    /// The Tuta write seam; `None` keeps the handler read-only (the
    /// state `serve` serves until the writer is wired in).
    writer: Option<Arc<dyn CalendarWriter>>,
    /// The account's addresses: the only organizers an imported event
    /// may carry. Empty (the read-only handler's value) accepts none.
    allowed_organizers: Vec<String>,
    /// One whole write per calendar at a time: the remote put — which
    /// re-checks the precondition against the freshly loaded event —
    /// and the cache apply of its outcome never interleave with
    /// another connection's write.
    writes: Mutex<HashMap<String, Arc<Mutex<()>>>>,
}

/// A rendered resource.
struct Rendered {
    etag: String,
    body: String,
}

impl CalDavHandler {
    /// The read-only handler: every `PUT` and `DELETE` answers the
    /// fixed refusal.
    pub fn new(sync: Arc<CalendarSync>, user_address: String) -> Self {
        Self {
            account_id: sync.account_id,
            user_address,
            store: Arc::clone(&sync.store),
            source: Arc::clone(&sync.source),
            clock: Arc::clone(&sync.clock),
            sync,
            writer: None,
            allowed_organizers: Vec::new(),
            writes: Mutex::new(HashMap::new()),
        }
    }

    /// The writable handler: every `PUT` and `DELETE` goes to `writer`
    /// first and lands in the cache only after the remote write held.
    /// `allowed_organizers` are the account's own addresses.
    pub fn with_writer(
        sync: Arc<CalendarSync>,
        user_address: String,
        writer: Arc<dyn CalendarWriter>,
        allowed_organizers: Vec<String>,
    ) -> Self {
        Self {
            account_id: sync.account_id,
            user_address,
            store: Arc::clone(&sync.store),
            source: Arc::clone(&sync.source),
            clock: Arc::clone(&sync.clock),
            writer: Some(writer),
            allowed_organizers,
            writes: Mutex::new(HashMap::new()),
            sync,
        }
    }

    /// The per-calendar write lock of `calendar_id`.
    async fn write_guard(&self, calendar_id: &str) -> Arc<Mutex<()>> {
        let mut guards = self.writes.lock().await;
        guards.entry(calendar_id.to_string()).or_default().clone()
    }

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
            calendar_privileges(),
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

    /// `PUT`: an update of the one event the href names, remote first.
    /// A row that does not exist is a creation attempt and is refused
    /// before anything else — there is no create dance.
    async fn put(&self, request: &DavRequest) -> Result<DavResponse> {
        // Without a writer every PUT answers the fixed read-only text,
        // whatever the target.
        let Some(writer) = self.writer.as_deref() else {
            return Ok(unwired());
        };
        // Only an event href is a resource a PUT can address: the
        // collections are not writable.
        let (calendar_id, name) = match target(&request.path) {
            Target::Item(calendar, name) => (calendar, name),
            Target::Unknown => return Ok(DavResponse::not_found()),
            _ => return Ok(DavResponse::forbidden()),
        };
        // The row the href names must exist and be a series' own
        // master: a `PUT` body is one plain event, so it can describe
        // neither an event that is not there nor an altered
        // occurrence. Both refusals are the fixed creation body —
        // creating events is not supported, whatever the headers say.
        let Some(calendar) = self.calendar(&calendar_id).await? else {
            return Ok(creation_refused());
        };
        let rows = self
            .store
            .calendar_rows(self.account_id, &calendar_id)
            .await?;
        let Some(resource) = group_resources(rows).remove(&name) else {
            return Ok(creation_refused());
        };
        let Some(master) = resource
            .rows
            .iter()
            .find(|row| row.recurrence_id_ms.is_none())
        else {
            return Ok(creation_refused());
        };
        // Preconditions run against the stored row, never the rendered
        // body: an unchanged reload can never answer 412.
        let stored_etag = resource_etag(&resource.rows);
        if let Some(condition) = request.if_none_match.as_deref() {
            if etag_matches(condition, &stored_etag) {
                return Ok(precondition_failed());
            }
        }
        if let Some(condition) = request.header("if-match") {
            if !strong_etag_matches(condition, &stored_etag) {
                return Ok(precondition_failed());
            }
        }
        let Ok(body) = std::str::from_utf8(&request.body) else {
            return Ok(DavResponse::text(400, ImportError::NoVevent.message()));
        };
        let fields = match parse_event(body) {
            Ok(fields) => fields,
            // A policy refusal — a well-formed body the bridge
            // chooses not to write, the degraded recurrence form among
            // them — answers the `403` of the plan's decision 3; only
            // a malformed body answers `400`.
            Err(error) if error.is_policy() => return Ok(DavResponse::text(403, error.message())),
            Err(error) => return Ok(DavResponse::text(400, error.message())),
        };
        let calendar_ref = CalendarRef {
            group_id: calendar.calendar_id.clone(),
            short_list_id: calendar.short_list_id.clone(),
            long_list_id: calendar.long_list_id.clone(),
        };
        // An event may only be organized by one of the account's own
        // addresses; an event without an organizer is a personal one.
        if let Some(organizer) = &fields.organizer {
            if !self
                .allowed_organizers
                .iter()
                .any(|address| address.eq_ignore_ascii_case(&organizer.address))
            {
                return Ok(organizer_refused());
            }
        }
        // Backstop for a stored series: a body without an `RRULE` and
        // without the bridge's marker would flatten the series. This
        // also catches clients that hand-write such a body.
        if master.recurring && fields.repeat.is_none() {
            return Ok(series_backstop_refused());
        }
        // An in-place update cannot move an event's start. A short
        // event's id derives from its start time, and both the Tuta web
        // client and this bridge's reader load short events by id
        // range, so an update with the stale id would make the event
        // invisible in the Tuta apps. A long event has no start-derived
        // id, but the bridge still refuses a retime: the Tuta web
        // client deletes and re-creates the event on a start change
        // (the plan's decision 9 blocks that here), and the writer
        // never rewrites `alarmInfos`, so a retime would leave the
        // stored reminders stale. Refuse with the fixed creation
        // answer.
        //
        // iCalendar times are second-granular and the renderer's UTC
        // formatting truncates sub-second milliseconds: floor the
        // stored start so a PUT-back of the served body never looks
        // like a start move.
        let stored_start = master.start_ms.div_euclid(1000) * 1000;
        if fields.start_ms != stored_start {
            return Ok(creation_refused());
        }
        // The body's rule and duration decide the event list, the web
        // client's `isLongEvent`: a repeating event (any rule, bounded
        // or not) or a one-off longer than the event-id randomization
        // range is a long event. Moving the event between the short
        // and long lists is a creation-shaped change, not an in-place
        // update. Refuse it with the fixed creation answer too.
        let chosen = choose_event_list(&calendar_ref, &fields);
        if chosen != master.list_id.as_str() {
            return Ok(creation_refused());
        }
        // The precondition token: the stored master row's content
        // fingerprint — the version of the very event this write
        // updates — which the check above already verified against the
        // request's `If-Match`. The writer re-checks it against the
        // freshly loaded event, the authority behind that fast fail.
        // `If-Match: *` pins existence only, so it carries no token.
        let if_match = request
            .header("if-match")
            .filter(|condition| condition.trim() != "*")
            .map(|_| master.fingerprint.as_str());
        // Remote first: a refusal answers its fixed status, a session
        // error and a transport failure reach the session layer
        // untouched, and the cache is touched only after the remote
        // write held. The writer keeps the event's identity — uid,
        // sequence, recurrence, alarms, attendees — to itself; the
        // handler hands it the parsed fields and the existing ref only.
        let existing = EventRef {
            list_id: master.list_id.clone(),
            element_id: master.element_id.clone(),
        };
        // One whole write per calendar at a time: the put and the
        // cache apply of its outcome never interleave with another
        // connection's write.
        let guard = self.write_guard(&calendar_id).await;
        let _guard = guard.lock().await;
        let reference = match writer
            .put_event(&calendar_ref, &fields, Some(&existing), if_match)
            .await
        {
            Ok(reference) => reference,
            Err(error) => return writer_refusal(error),
        };
        // The optimistic row: the same refresh the reader's `GET`
        // applies, so the row (and the ETag with it) is the one the
        // next read serves and the event echo is a no-op against it.
        // A state that cannot be read back answers the fixed 503: the
        // row stays as it was and the client retries.
        let Some(event) = self
            .source
            .event(&reference.list_id, &reference.element_id)
            .await?
        else {
            return Err(Error::Network("calendar data unavailable".into()));
        };
        let row = event.row(&calendar_id, self.clock.now_ms());
        // The remote write held: a cache apply that fails now only
        // marks the calendar stale (the reload heals the row), and the
        // answer stays the success the remote write earned — a client
        // that retried a write that already happened would edit the
        // event twice.
        let stored = self
            .sync
            .apply_written(&row)
            .await
            .unwrap_or_else(|_| row.clone());
        // A legacy event whose uid the write repaired moves to another
        // href: this resource keeps its other rows, and the answer
        // carries no ETag for a row this href no longer serves.
        let moved = resource
            .rows
            .first()
            .is_none_or(|first| first.resource != stored.resource);
        let mut response = DavResponse::new(204);
        if !moved {
            let rows = rewritten_rows(&resource, &stored);
            response = response.with_etag(&resource_etag(&rows));
        }
        Ok(response)
    }

    /// `DELETE`: one whole resource, remote first. Every event of the
    /// series is deleted before any row is touched, and the rows are
    /// then removed the way the reader removes a deleted event's row.
    async fn delete(&self, request: &DavRequest) -> Result<DavResponse> {
        // Without a writer every DELETE answers the fixed read-only
        // text, whatever the target.
        let Some(writer) = self.writer.as_deref() else {
            return Ok(unwired());
        };
        let (calendar_id, name) = match target(&request.path) {
            Target::Item(calendar, name) => (calendar, name),
            Target::Unknown => return Ok(DavResponse::not_found()),
            _ => return Ok(DavResponse::forbidden()),
        };
        let Some(calendar) = self.calendar(&calendar_id).await? else {
            return Ok(DavResponse::not_found());
        };
        let rows = self
            .store
            .calendar_rows(self.account_id, &calendar_id)
            .await?;
        // A row that never existed is not a deletion: no tombstone.
        let Some(resource) = group_resources(rows).remove(&name) else {
            return Ok(DavResponse::not_found());
        };
        if let Some(condition) = request.header("if-match") {
            if !strong_etag_matches(condition, &resource_etag(&resource.rows)) {
                return Ok(precondition_failed());
            }
        }
        let calendar_ref = CalendarRef {
            group_id: calendar.calendar_id.clone(),
            short_list_id: calendar.short_list_id.clone(),
            long_list_id: calendar.long_list_id.clone(),
        };
        // Remote first. Both outcomes proceed: `Gone` has already
        // reached the end state the client asked for. A refusal
        // answers its fixed status; a session error and a transport
        // failure reach the session layer untouched. A failure part
        // way leaves the cache as it was; the client retries and the
        // events already gone answer `Gone`.
        for row in &resource.rows {
            let reference = EventRef {
                list_id: row.list_id.clone(),
                element_id: row.element_id.clone(),
            };
            match writer.delete_event(&calendar_ref, &reference).await {
                Ok(_) => {}
                Err(error) => return writer_refusal(error),
            }
        }
        // The remote delete held: a cache apply that fails only marks
        // the calendar stale (the reload heals the rows), and the
        // answer stays the success the remote delete earned.
        for row in &resource.rows {
            let _ = self.sync.apply_deleted(&row.list_id, &row.element_id).await;
        }
        Ok(DavResponse::new(204))
    }
}

/// `d:current-user-privilege-set` with `read` only: the home set and
/// everything above it stay read-only.
fn read_only_privileges() -> XmlNode {
    XmlNode::children(
        PropName::dav("current-user-privilege-set"),
        vec![XmlNode::children(
            PropName::dav("privilege"),
            vec![XmlNode::empty(PropName::dav("read"))],
        )],
    )
}

/// `d:current-user-privilege-set` of a calendar collection: read and
/// write, so clients stop marking the calendar read-only.
fn calendar_privileges() -> XmlNode {
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

/// The fixed refusal of a handler without a writer: byte-identical to
/// the one the generic session answers for the write methods no
/// feature serves.
fn unwired() -> DavResponse {
    DavResponse::text(403, "forbidden: this server is read-only")
}

/// `412` with a fixed body.
fn precondition_failed() -> DavResponse {
    DavResponse::text(412, "precondition failed")
}

/// The fixed refusal of an event creation: the SDK's generic create
/// cannot serve Tuta's custom-id events, so a client creates its
/// events in the Tuta client and edits them here. The body is fixed
/// text — nothing the client sent is ever echoed.
fn creation_refused() -> DavResponse {
    DavResponse::text(
        403,
        "creating events is not supported: create them in the Tuta client, then edit them here",
    )
}

/// The fixed refusal of a body that would flatten a stored series.
/// This also catches clients that hand-write a body without the
/// bridge's recurrence marker: a stored series must never be
/// flattened.
fn series_backstop_refused() -> DavResponse {
    DavResponse::text(403, "the stored series repeats but the body does not")
}

/// The fixed refusal of an organizer that is not one of the
/// account's addresses.
fn organizer_refused() -> DavResponse {
    DavResponse::text(403, "the organizer is not an address of this account")
}

/// The rows of one resource after a write rewrote one of them: the
/// stored row replaces its own. Every row of one resource carries the
/// same series name in its `resource` column — also under the split
/// href a series Tuta divided keeps, whose href name derives from the
/// master's ids — so the guard compares the stored row's series
/// against the rows' own, never the href's name; a row whose series
/// moved to another name (a legacy event whose uid a write repaired)
/// has left this resource.
fn rewritten_rows(resource: &Resource, stored: &CalendarRow) -> Vec<CalendarRow> {
    let mut rows: Vec<CalendarRow> = resource
        .rows
        .iter()
        .filter(|row| row.list_id != stored.list_id || row.element_id != stored.element_id)
        .cloned()
        .collect();
    if resource
        .rows
        .first()
        .is_some_and(|first| first.resource == stored.resource)
    {
        rows.push(stored.clone());
    }
    rows
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

    fn extra_methods(&self) -> &'static [&'static str] {
        &["PUT", "DELETE"]
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
            DavMethod::Put => self.put(request).await,
            DavMethod::Delete => self.delete(request).await,
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
