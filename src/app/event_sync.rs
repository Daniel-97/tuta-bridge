//! Apply parsed websocket event batches to the header index.
//!
//! The processor consumes one [`EventBatch`] at a time: it reloads the
//! entities the events reference through [`EventLookup`], coalesces the
//! mail events of each element into one authoritative action, and persists
//! the resulting [`StateChange`]s together with the batch id in a single
//! [`StateStore::apply_batch`] call, so a replayed batch is a no-op and the
//! batch marker never advances past unapplied changes. All lookups are
//! metadata-only, and the report carries fixed-size counters: ids,
//! subjects, and addresses never appear in it.

use std::collections::HashMap;
use std::sync::Arc;

use crate::domain::{
    EntityEvent, EntityOperation, EventBatch, MailPlacement, Result, StateChange,
    MAIL_SET_ENTRY_TYPE_ID, MAIL_SET_TYPE_ID, MAIL_TYPE_ID, TUTANOTA_APP,
};
use crate::ports::event_lookup::EventLookup;
use crate::ports::state_store::StateStore;

/// Outcome of applying one event batch.
///
/// `changes` counts the events that changed the index; each of them
/// persists at least one change through `apply_batch`, and a mail event can
/// persist several (one upsert per placement plus a guard that drops stale
/// placements). `skipped` counts the events left untouched, so
/// `changes + skipped` always equals the number of events in the batch.
/// Both fields are fixed-size so a report never carries entity data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventReport {
    /// Events that produced a state change.
    pub changes: usize,
    /// Events skipped because their entity was unreadable, could not be
    /// loaded, or is not handled by the bridge.
    pub skipped: usize,
}

/// Coalesced effect of one element's mail events within a batch.
enum MailAction {
    /// The placements the lookup reported for the element; authoritative.
    Placements(Vec<MailPlacement>),
    /// The mail itself was deleted.
    Delete,
}

/// Applies entity events to the stored header index.
pub struct EventProcessor {
    pub store: Arc<dyn StateStore>,
}

impl EventProcessor {
    pub fn new(store: Arc<dyn StateStore>) -> Self {
        Self { store }
    }

    /// Apply one event batch and persist it atomically.
    ///
    /// Mail sets are upserted as folders as soon as their event is seen,
    /// so one batch can create a folder and file mail into it. Mail events
    /// are coalesced per element id — a `Mail` create/update replaces the
    /// element's action with the lookup's authoritative placements, a
    /// `Mail` delete sets `Delete`, and a `MailSetEntry` create/update adds
    /// a single placement — so one batch never emits both a removal and an
    /// upsert for the same element. Unreadable or failed lookups are
    /// skipped and keep the stored rows. Afterwards every action becomes
    /// state changes and `apply_batch` runs exactly once, even when nothing
    /// changed, so the batch id always advances.
    pub async fn apply(
        &self,
        account_id: i64,
        lookup: &dyn EventLookup,
        uidvalidity: u32,
        batch: &EventBatch,
    ) -> Result<EventReport> {
        let mut changes: Vec<StateChange> = Vec::new();
        let mut actions: HashMap<String, MailAction> = HashMap::new();
        let mut applied = 0;
        let mut skipped = 0;

        for event in &batch.events {
            if event.application != TUTANOTA_APP {
                skipped += 1;
                continue;
            }
            match event.type_id {
                MAIL_SET_TYPE_ID => match mail_set_change(lookup, uidvalidity, event).await {
                    Some(change) => {
                        changes.push(change);
                        applied += 1;
                    }
                    None => skipped += 1,
                },
                MAIL_TYPE_ID => match mail_action(lookup, event).await {
                    Some(action) => {
                        actions.insert(event.element_id.clone(), action);
                        applied += 1;
                    }
                    None => skipped += 1,
                },
                MAIL_SET_ENTRY_TYPE_ID => match entry_placement(lookup, event).await {
                    // An entry event adds one placement; a mail deleted in
                    // the same batch stays deleted.
                    Some(placement) => {
                        if add_placement(&mut actions, &event.element_id, placement) {
                            applied += 1;
                        } else {
                            skipped += 1;
                        }
                    }
                    None => skipped += 1,
                },
                _ => skipped += 1,
            }
        }

        changes.extend(
            actions
                .into_iter()
                .flat_map(|(element_id, action)| action_changes(element_id, action)),
        );

        self.store
            .apply_batch(account_id, &batch.owner_group_id, &batch.batch_id, &changes)
            .await?;

        Ok(EventReport {
            changes: applied,
            skipped,
        })
    }
}

/// Resolve a mail-set event into a folder upsert; `None` skips the event.
///
/// A set the bridge does not store (for example the virtual "All" set)
/// answers `Ok(None)` and is skipped, as is every failed load. Folder
/// deletion is left to `sync`, which reconciles the full folder list.
async fn mail_set_change(
    lookup: &dyn EventLookup,
    uidvalidity: u32,
    event: &EntityEvent,
) -> Option<StateChange> {
    match event.operation {
        EntityOperation::Create | EntityOperation::Update => {
            match lookup.folder(&event.list_id, &event.element_id).await {
                Ok(Some(folder)) => Some(StateChange::UpsertMailbox {
                    folder,
                    uidvalidity,
                }),
                Ok(None) | Err(_) => None,
            }
        }
        EntityOperation::Delete => None,
    }
}

/// Resolve a mail event into the element's new action; `None` skips the
/// event and keeps the stored rows.
///
/// The placements reported by the lookup are authoritative for the whole
/// mail, so they replace whatever earlier events in the same batch
/// recorded. `Ok(None)` (an unreadable mail) and failed loads are skipped
/// rather than treated as "no placements".
async fn mail_action(lookup: &dyn EventLookup, event: &EntityEvent) -> Option<MailAction> {
    match event.operation {
        EntityOperation::Create | EntityOperation::Update => {
            match lookup
                .headers_for_mail(&event.list_id, &event.element_id)
                .await
            {
                Ok(Some(placements)) => Some(MailAction::Placements(placements)),
                Ok(None) | Err(_) => None,
            }
        }
        EntityOperation::Delete => Some(MailAction::Delete),
    }
}

/// Resolve a mail-set-entry event into one placement; `None` skips the
/// event.
///
/// Entry deletes are skipped: the accompanying `Mail` update or a later
/// sync reconciles the entry's placement.
async fn entry_placement(lookup: &dyn EventLookup, event: &EntityEvent) -> Option<MailPlacement> {
    match event.operation {
        EntityOperation::Create | EntityOperation::Update => {
            match lookup
                .header_for_entry(&event.list_id, &event.element_id)
                .await
            {
                Ok(Some(placement)) => Some(placement),
                Ok(None) | Err(_) => None,
            }
        }
        EntityOperation::Delete => None,
    }
}

/// Record one entry placement for `element_id`.
///
/// The placement joins the element's existing placements, deduplicated by
/// `mailbox_list_id`; a missing entry starts one. Returns `false` when the
/// element's mail was deleted in the same batch, in which case the delete
/// stays authoritative and the event counts as skipped.
fn add_placement(
    actions: &mut HashMap<String, MailAction>,
    element_id: &str,
    placement: MailPlacement,
) -> bool {
    if let Some(MailAction::Delete) = actions.get(element_id) {
        // A mail deleted in the same batch stays deleted.
        return false;
    }
    if let Some(MailAction::Placements(placements)) = actions.get_mut(element_id) {
        // The first placement per mailbox wins, like the lookup's own
        // dedupe.
        if placements
            .iter()
            .any(|stored| stored.mailbox_list_id == placement.mailbox_list_id)
        {
            return true;
        }
        placements.push(placement);
        return true;
    }
    // No action yet: this entry starts one.
    actions.insert(
        element_id.to_string(),
        MailAction::Placements(vec![placement]),
    );
    true
}

/// Turn one coalesced action into its state changes.
///
/// A deleted mail, or one the lookup reports without any placement, loses
/// every stored row. A placed mail is upserted once per placement and
/// every placement outside the reported mailboxes is removed; the two
/// outcomes never mix for one element, so a batch cannot remove and upsert
/// the same mail at once.
fn action_changes(element_id: String, action: MailAction) -> Vec<StateChange> {
    match action {
        MailAction::Delete => vec![StateChange::RemoveHeaderEverywhere { element_id }],
        MailAction::Placements(placements) if placements.is_empty() => {
            vec![StateChange::RemoveHeaderEverywhere { element_id }]
        }
        MailAction::Placements(placements) => {
            let keep_list_ids: Vec<String> = placements
                .iter()
                .map(|placement| placement.mailbox_list_id.clone())
                .collect();
            let mut changes: Vec<StateChange> = placements
                .into_iter()
                .map(|placement| StateChange::UpsertHeader {
                    mailbox_list_id: placement.mailbox_list_id,
                    header: placement.header,
                })
                .collect();
            changes.push(StateChange::RemoveOtherPlacements {
                element_id,
                keep_list_ids,
            });
            changes
        }
    }
}
