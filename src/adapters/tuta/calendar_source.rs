//! Tuta implementation of [`CalendarSource`].
//!
//! Calendar names and colours come from the SDK's calendar facade
//! (`get_calendars_render_data`). Events are loaded through the crypto
//! entity client directly rather than `get_calendar_events`: that call
//! expands repeating events into instances (losing the rule the CalDAV
//! output needs) and asks the operating system for the local UTC
//! offset, which the `time` crate refuses in a multi-threaded process.
//!
//! Every repeating event lives in the calendar's long-event list, which
//! is loaded in full. Short events live in a list keyed by start time
//! (shifted by up to 15 days to hide it), so only the ids around the
//! requested range are loaded. The client-side birthday calendar is not
//! a Tuta calendar and is not served.
//!
//! Every SDK failure maps to a fixed message; ids, names and titles
//! never appear in errors.

use std::sync::Arc;

use base64::Engine as _;
use tutasdk::date::calendar_facade::{BIRTHDAY_CALENDAR_BASE_ID, DAYS_SHIFTED_MS};
use tutasdk::entities::generated::sys::UserAlarmInfo;
use tutasdk::entities::generated::tutanota::{
    CalendarEvent as TutaEvent, CalendarGroupRoot, EncryptedMailAddress,
};
use tutasdk::rest_error::HttpError;
use tutasdk::{
    ApiCallError, CustomId, GeneratedId, IdTupleCustom, IdTupleGenerated, ListLoadDirection,
    LoggedInSdk,
};

use crate::domain::{
    CalendarEvent, CalendarInfo, Error, EventAttendee, EventPerson, RepeatRule, Result,
};
use crate::ports::calendar::CalendarSource;

/// Short events requested per range load.
const PAGE_SIZE: usize = 1000;

fn unavailable() -> Error {
    Error::Network("calendar data unavailable".into())
}

/// `Ok(None)` for a definitive "does not exist", the fixed network
/// error for everything else.
fn found<T>(loaded: std::result::Result<T, ApiCallError>) -> Result<Option<T>> {
    match loaded {
        Ok(entity) => Ok(Some(entity)),
        Err(ApiCallError::ServerResponseError {
            source: HttpError::NotFoundError,
        }) => Ok(None),
        Err(_) => Err(unavailable()),
    }
}

/// A Tuta event as a domain event, or `None` when it did not decrypt
/// intact or carries no id.
pub fn event_from_tuta(event: &TutaEvent) -> Option<CalendarEvent> {
    if !event._errors.is_empty() {
        return None;
    }
    if let Some(rule) = &event.repeatRule {
        if !rule._errors.is_empty() {
            return None;
        }
    }
    let id = event._id.as_ref()?;
    let person = |address: &EncryptedMailAddress| EventPerson {
        name: address.name.clone(),
        address: address.address.clone(),
    };
    Some(CalendarEvent {
        list_id: id.list_id.as_str().to_string(),
        element_id: id.element_id.as_str().to_string(),
        uid: event.uid.clone(),
        summary: event.summary.clone(),
        description: event.description.clone(),
        location: event.location.clone(),
        start_ms: millis(event.startTime.as_millis()),
        end_ms: millis(event.endTime.as_millis()),
        sequence: event.sequence,
        recurrence_id_ms: event.recurrenceId.map(|at| millis(at.as_millis())),
        repeat: event.repeatRule.as_ref().map(|rule| RepeatRule {
            frequency: rule.frequency,
            interval: rule.interval,
            end_type: rule.endType,
            end_value: rule.endValue,
            time_zone: rule.timeZone.clone(),
            excluded_ms: rule
                .excludedDates
                .iter()
                .map(|date| millis(date.date.as_millis()))
                .collect(),
            advanced: rule
                .advancedRules
                .iter()
                .map(|advanced| (advanced.ruleType, advanced.interval.clone()))
                .collect(),
        }),
        alarm_ids: event
            .alarmInfos
            .iter()
            .map(|id| {
                (
                    id.list_id.as_str().to_string(),
                    id.element_id.as_str().to_string(),
                )
            })
            .collect(),
        organizer: event.organizer.as_ref().map(person),
        attendees: event
            .attendees
            .iter()
            .map(|attendee| EventAttendee {
                person: person(&attendee.address),
                status: attendee.status,
            })
            .collect(),
    })
}

fn millis(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// The timestamp a short event's element id encodes (`None` when it
/// does not decode as one).
fn id_timestamp(element_id: &str) -> Option<u64> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(element_id)
        .ok()?;
    std::str::from_utf8(&bytes).ok()?.parse().ok()
}

/// Tuta implementation of the calendar source.
pub struct TutaCalendarSource {
    logged: Arc<LoggedInSdk>,
}

impl TutaCalendarSource {
    pub fn new(logged: Arc<LoggedInSdk>) -> Self {
        Self { logged }
    }
}

#[async_trait::async_trait]
impl CalendarSource for TutaCalendarSource {
    async fn calendars(&self) -> Result<Vec<CalendarInfo>> {
        let render = self
            .logged
            .calendar_facade()
            .get_calendars_render_data()
            .await
            .map_err(|_| unavailable())?;
        let crypto_client = self.logged.mail_facade().get_crypto_entity_client();
        let mut calendars = Vec::with_capacity(render.len());
        for (id, data) in render {
            if id.as_str().contains(BIRTHDAY_CALENDAR_BASE_ID) {
                continue;
            }
            let Some(root) = found::<CalendarGroupRoot>(crypto_client.load(&id).await)? else {
                continue;
            };
            calendars.push(CalendarInfo {
                calendar_id: id.as_str().to_string(),
                name: data.name,
                color: data.color,
                short_list_id: root.shortEvents.as_str().to_string(),
                long_list_id: root.longEvents.as_str().to_string(),
            });
        }
        calendars.sort_by(|a, b| a.calendar_id.cmp(&b.calendar_id));
        Ok(calendars)
    }

    async fn events(
        &self,
        calendar: &CalendarInfo,
        from_ms: i64,
        to_ms: i64,
    ) -> Result<Vec<CalendarEvent>> {
        let crypto_client = self.logged.mail_facade().get_crypto_entity_client();
        let mut events = Vec::new();

        let long: Vec<TutaEvent> = crypto_client
            .load_all(
                &GeneratedId(calendar.long_list_id.clone()),
                ListLoadDirection::ASC,
            )
            .await
            .map_err(|_| unavailable())?;
        events.extend(long.iter().filter_map(event_from_tuta));

        let shift = DAYS_SHIFTED_MS;
        let first = u64::try_from(from_ms).unwrap_or(0).saturating_sub(shift);
        let last = u64::try_from(to_ms).unwrap_or(0).saturating_add(shift);
        let short_list = GeneratedId(calendar.short_list_id.clone());
        let mut cursor = CustomId::from_custom_string(&first.to_string());
        loop {
            let page: Vec<TutaEvent> = crypto_client
                .load_range(&short_list, &cursor, PAGE_SIZE, ListLoadDirection::ASC)
                .await
                .map_err(|_| unavailable())?;
            let full = page.len() >= PAGE_SIZE;
            let next = page
                .last()
                .and_then(|event| event._id.as_ref())
                .map(|id| id.element_id.clone());
            events.extend(page.iter().filter_map(event_from_tuta));
            let Some(next) = next.filter(|_| full) else {
                break;
            };
            if next == cursor || id_timestamp(next.as_str()).is_some_and(|at| at > last) {
                break;
            }
            cursor = next;
        }

        events.retain(|event| event.may_overlap(from_ms, to_ms));
        Ok(events)
    }

    async fn event(&self, list_id: &str, element_id: &str) -> Result<Option<CalendarEvent>> {
        let crypto_client = self.logged.mail_facade().get_crypto_entity_client();
        let id = IdTupleCustom::new(
            GeneratedId(list_id.to_string()),
            CustomId(element_id.to_string()),
        );
        let loaded = found::<TutaEvent>(crypto_client.load(&id).await)?;
        Ok(loaded.as_ref().and_then(event_from_tuta))
    }

    async fn alarm_triggers(&self, alarm_ids: &[(String, String)]) -> Result<Vec<String>> {
        let crypto_client = self.logged.mail_facade().get_crypto_entity_client();
        let mut triggers = Vec::with_capacity(alarm_ids.len());
        for (list_id, element_id) in alarm_ids {
            let id = IdTupleGenerated::new(
                GeneratedId(list_id.clone()),
                GeneratedId(element_id.clone()),
            );
            match crypto_client.load::<UserAlarmInfo, _>(&id).await {
                Ok(alarm) if alarm._errors.is_empty() && alarm.alarmInfo._errors.is_empty() => {
                    triggers.push(alarm.alarmInfo.trigger)
                }
                // Another attendee's alarm, a deleted one, or one that
                // does not decrypt: not the user's to show.
                Ok(_) => {}
                Err(ApiCallError::ServerResponseError {
                    source:
                        HttpError::NotFoundError
                        | HttpError::NotAuthorizedError
                        | HttpError::NotAuthenticatedError,
                }) => {}
                Err(ApiCallError::InternalSdkError { .. }) => {}
                Err(_) => return Err(unavailable()),
            }
        }
        triggers.sort();
        Ok(triggers)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_event_ids_decode_to_their_timestamp() {
        let id = CustomId::from_custom_string("1736150400000");
        assert_eq!(id_timestamp(id.as_str()), Some(1_736_150_400_000));
        assert_eq!(id_timestamp("!!"), None);
    }
}
