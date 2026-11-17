//! Parse Tuta websocket frames into domain event frames.
//!
//! A websocket text message is formatted as `type;payload`. Only
//! `entityUpdate` and `initialSyncDone` are meaningful for the bridge; every
//! other message type is ignored.

use tutasdk::entities::generated::sys::WebsocketEntityData;

use crate::domain::{EntityEvent, EntityOperation, Error, EventBatch, EventFrame, Result};

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

fn parse_entity_update(payload: &str) -> Result<EventFrame> {
    let data: WebsocketEntityData = serde_json::from_str(payload)
        .map_err(|_| Error::Network("invalid event message".into()))?;
    let events = data
        .entityUpdates
        .into_iter()
        .filter_map(|update| {
            let operation = match update.operation {
                0 => EntityOperation::Create,
                1 => EntityOperation::Update,
                2 => EntityOperation::Delete,
                _ => return None,
            };
            Some(EntityEvent {
                application: update.application,
                type_id: update.typeId,
                list_id: update.instanceListId,
                element_id: update.instanceId,
                operation,
            })
        })
        .collect();
    Ok(EventFrame::Batch(EventBatch {
        batch_id: data.eventBatchId.as_str().to_owned(),
        owner_group_id: data.eventBatchOwner.as_str().to_owned(),
        application_types_hash: data.applicationTypesHash,
        events,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_entity_update_batch() {
        let json = r#"{"1484":0,"1485":"batch1","1486":"group1","2557":7,"2558":"hash","1487":[{"463":null,"464":"tutanota","466":"list1","467":"mail1","624":0,"2556":97,"2617":null,"2701":null,"2618":null},{"463":null,"464":"tutanota","466":"list1","467":"entry1","624":2,"2556":1450,"2617":null,"2701":null,"2618":null}]}"#;
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
    fn parses_update_operation() {
        let json = r#"{"1484":0,"1485":"b","1486":"g","2557":0,"2558":"h","1487":[{"463":null,"464":"tutanota","466":"l","467":"e","624":1,"2556":97,"2617":null,"2701":null,"2618":null}]}"#;
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
        let json = r#"{"1484":0,"1485":"b","1486":"g","2557":0,"2558":"h","1487":[{"463":null,"464":"tutanota","466":"l","467":"e","624":9,"2556":97,"2617":null,"2701":null,"2618":null}]}"#;
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
    }
}
