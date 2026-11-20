//! Parse Tuta websocket frames into domain event frames.
//!
//! A websocket text message is formatted as `type;payload`. Only
//! `entityUpdate` and `initialSyncDone` are meaningful for the bridge; every
//! other message type is ignored.
//!
//! `entityUpdate` payloads are deserialized through private raw structs keyed
//! by Tuta's numeric attribute ids, not the SDK entity models: the server
//! serializes every `NumberString` field as a JSON string, which the SDK
//! models (plain integers) reject.

use std::fmt;
use std::str::FromStr;

use serde::de::{Error as DeError, Visitor};
use serde::{Deserialize, Deserializer};

use crate::domain::{EntityEvent, EntityOperation, Error, EventBatch, EventFrame, Result};

/// A number-like wire field.
///
/// The server sends `NumberString` attributes as JSON strings, so accept a
/// JSON number or a numeric string; anything else is a parse failure.
struct WireNumber(i64);

impl<'de> Deserialize<'de> for WireNumber {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct WireNumberVisitor;

        impl<'de> Visitor<'de> for WireNumberVisitor {
            type Value = WireNumber;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a number or a numeric string")
            }

            fn visit_u64<E>(self, value: u64) -> std::result::Result<Self::Value, E>
            where
                E: DeError,
            {
                i64::try_from(value)
                    .map(WireNumber)
                    .map_err(|_| E::custom("number out of range"))
            }

            fn visit_i64<E>(self, value: i64) -> std::result::Result<Self::Value, E>
            where
                E: DeError,
            {
                Ok(WireNumber(value))
            }

            fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
            where
                E: DeError,
            {
                i64::from_str(value)
                    .map(WireNumber)
                    .map_err(|_| E::custom("invalid numeric string"))
            }
        }

        deserializer.deserialize_any(WireNumberVisitor)
    }
}

/// Raw `entityUpdate` payload. Unknown attributes (batch counters, update
/// ids, instance bodies, patches) are ignored by serde and never stored.
#[derive(Deserialize)]
struct RawWebsocketEntityData {
    #[serde(rename = "1485", default)]
    event_batch_id: String,
    #[serde(rename = "1486", default)]
    event_batch_owner: String,
    #[serde(rename = "2558", default)]
    application_types_hash: String,
    #[serde(rename = "1487", default)]
    entity_updates: Vec<RawEntityUpdate>,
}

/// Raw event entry. `instance`, `blobInstance` and `patch` are deliberately
/// absent so their contents are never read or stored.
#[derive(Deserialize)]
struct RawEntityUpdate {
    #[serde(rename = "464", default)]
    application: String,
    #[serde(rename = "466", default)]
    instance_list_id: String,
    #[serde(rename = "467", default)]
    instance_id: String,
    #[serde(rename = "624")]
    operation: WireNumber,
    #[serde(rename = "2556")]
    type_id: WireNumber,
}

/// Parse one websocket text frame.
pub fn parse_frame(text: &str) -> Result<EventFrame> {
    let Some((message_type, payload)) = text.split_once(';') else {
        return Ok(EventFrame::Ignored);
    };
    match message_type {
        "entityUpdate" => parse_entity_update(payload),
        "initialSyncDone" => Ok(EventFrame::InitialSyncDone),
        _ => Ok(EventFrame::Ignored),
    }
}

/// Message of the error for an `entityUpdate` frame that does not parse.
const INVALID_EVENT_MESSAGE: &str = "invalid event message";

/// Whether `error` reports an `entityUpdate` frame that could not be
/// parsed, as opposed to a lost connection.
///
/// Both end the stream as network errors, but they need different
/// handling: a reconnect fixes a lost connection, while the server
/// replays an unparseable frame unchanged on every reconnect, so the
/// watch loop has to count these and move past the frame.
pub fn is_invalid_event(error: &Error) -> bool {
    matches!(error, Error::Network(message) if message == INVALID_EVENT_MESSAGE)
}

fn parse_entity_update(payload: &str) -> Result<EventFrame> {
    let data: RawWebsocketEntityData =
        serde_json::from_str(payload).map_err(|_| Error::Network(INVALID_EVENT_MESSAGE.into()))?;
    let events = data
        .entity_updates
        .into_iter()
        .filter_map(|update| {
            let operation = match update.operation.0 {
                0 => EntityOperation::Create,
                1 => EntityOperation::Update,
                2 => EntityOperation::Delete,
                _ => return None,
            };
            Some(EntityEvent {
                application: update.application,
                type_id: update.type_id.0,
                list_id: update.instance_list_id,
                element_id: update.instance_id,
                operation,
            })
        })
        .collect();
    Ok(EventFrame::Batch(EventBatch {
        batch_id: data.event_batch_id,
        owner_group_id: data.event_batch_owner,
        application_types_hash: data.application_types_hash,
        events,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_entity_update_batch() {
        // Real wire shape: the server sends every NumberString field as a
        // string.
        let json = r#"{"1484":"0","1485":"batch1","1486":"group1","2557":"7","2558":"hash","1487":[{"463":"u1","464":"tutanota","466":"list1","467":"mail1","624":"0","2556":"97","2617":null,"2701":null,"2618":null},{"463":"u2","464":"tutanota","466":"list1","467":"entry1","624":"2","2556":"1450","2617":null,"2701":null,"2618":null}]}"#;
        let frame = parse_frame(&format!("entityUpdate;{json}")).unwrap();
        let EventFrame::Batch(batch) = frame else {
            panic!("expected batch")
        };
        assert_eq!(batch.batch_id, "batch1");
        assert_eq!(batch.owner_group_id, "group1");
        assert_eq!(batch.application_types_hash, "hash");
        assert_eq!(batch.events.len(), 2);
        assert_eq!(batch.events[0].application, "tutanota");
        assert_eq!(batch.events[0].type_id, 97);
        assert_eq!(batch.events[0].list_id, "list1");
        assert_eq!(batch.events[0].element_id, "mail1");
        assert_eq!(batch.events[0].operation, EntityOperation::Create);
        assert_eq!(batch.events[1].operation, EntityOperation::Delete);
        assert_eq!(batch.events[1].list_id, "list1");
        assert_eq!(batch.events[1].element_id, "entry1");
    }

    #[test]
    fn accepts_the_same_batch_with_json_numbers() {
        let json = r#"{"1484":0,"1485":"batch1","1486":"group1","2557":7,"2558":"hash","1487":[{"463":null,"464":"tutanota","466":"list1","467":"mail1","624":0,"2556":97,"2617":null,"2701":null,"2618":null},{"463":null,"464":"tutanota","466":"list1","467":"entry1","624":2,"2556":1450,"2617":null,"2701":null,"2618":null}]}"#;
        let EventFrame::Batch(batch) = parse_frame(&format!("entityUpdate;{json}")).unwrap() else {
            panic!("expected batch")
        };
        assert_eq!(batch.batch_id, "batch1");
        assert_eq!(batch.owner_group_id, "group1");
        assert_eq!(batch.application_types_hash, "hash");
        assert_eq!(batch.events.len(), 2);
        assert_eq!(batch.events[0].type_id, 97);
        assert_eq!(batch.events[0].operation, EntityOperation::Create);
        assert_eq!(batch.events[1].type_id, 1450);
        assert_eq!(batch.events[1].operation, EntityOperation::Delete);
    }

    #[test]
    fn parses_update_operation() {
        let json = r#"{"1484":"0","1485":"b","1486":"g","2557":"0","2558":"h","1487":[{"463":null,"464":"tutanota","466":"l","467":"e","624":"1","2556":"97","2617":null,"2701":null,"2618":null}]}"#;
        let EventFrame::Batch(batch) = parse_frame(&format!("entityUpdate;{json}")).unwrap() else {
            panic!()
        };
        assert_eq!(batch.events[0].operation, EntityOperation::Update);
    }

    #[test]
    fn ignores_other_message_types_and_bad_operations() {
        assert!(matches!(
            parse_frame("initialSyncDone;").unwrap(),
            EventFrame::InitialSyncDone
        ));
        assert!(matches!(
            parse_frame("leaderStatus;{}").unwrap(),
            EventFrame::Ignored
        ));
        assert!(matches!(
            parse_frame("unreadCounterUpdate;{}").unwrap(),
            EventFrame::Ignored
        ));
        assert!(matches!(parse_frame("").unwrap(), EventFrame::Ignored));
        let json = r#"{"1484":"0","1485":"b","1486":"g","2557":"0","2558":"h","1487":[{"463":null,"464":"tutanota","466":"l","467":"e","624":"9","2556":"97","2617":null,"2701":null,"2618":null}]}"#;
        let EventFrame::Batch(batch) = parse_frame(&format!("entityUpdate;{json}")).unwrap() else {
            panic!()
        };
        assert!(batch.events.is_empty());
    }

    #[test]
    fn malformed_entity_update_is_a_fixed_error() {
        let Err(error) = parse_frame("entityUpdate;not-json") else {
            panic!("expected an error")
        };
        assert_eq!(error.to_string(), "network error: invalid event message");
        // The watch loop tells it apart from a lost connection.
        assert!(is_invalid_event(&error));
        assert!(!is_invalid_event(&Error::Network(
            "event stream disconnected".into()
        )));
        assert!(!is_invalid_event(&Error::Storage(
            "invalid event message".into()
        )));
    }

    #[test]
    fn non_numeric_number_string_is_a_fixed_error() {
        let json = r#"{"1484":"0","1485":"b","1486":"g","2557":"0","2558":"h","1487":[{"463":null,"464":"tutanota","466":"l","467":"e","624":"x","2556":"97","2617":null,"2701":null,"2618":null}]}"#;
        let Err(error) = parse_frame(&format!("entityUpdate;{json}")) else {
            panic!("expected an error")
        };
        assert_eq!(error.to_string(), "network error: invalid event message");
    }
}
