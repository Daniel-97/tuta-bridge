//! One-shot envelope enrichment for stored messages.
//!
//! A synced header carries only list-level metadata. The enricher loads
//! the decrypted content once, then persists everything the IMAP layer
//! can serve without another network round trip: the complete envelope,
//! `rfc822_size`, and the precomputed BODYSTRUCTURE string. The rendered
//! message bytes exist only to measure that size and are dropped
//! immediately — nothing but metadata ever reaches the store.
//!
//! The operation is idempotent: a message whose envelope is complete and
//! whose size and structure are stored is returned untouched, without
//! touching the mail source or the renderer.

use std::sync::Arc;

use crate::adapters::imap::render;
use crate::domain::{Error, MailboxId, MessageHeader, MessageSummary, Result, StoredMessage};
use crate::ports::mail_source::MailSource;
use crate::ports::renderer::MessageRenderer;
use crate::ports::state_store::StateStore;

/// Completes stored envelopes on demand, persisting metadata only.
pub struct EnvelopeEnricher {
    pub store: Arc<dyn StateStore>,
    pub renderer: Arc<dyn MessageRenderer>,
}

impl EnvelopeEnricher {
    /// Enrich `stored` in `mailbox` and return the completed message.
    ///
    /// A message counts as enriched when its envelope is complete and
    /// both the size and the MIME structure are stored; such input is
    /// returned unchanged and the source is never contacted. Any missing
    /// piece triggers exactly one content load and one render, after
    /// which the complete header, the rendered byte length, and the
    /// structure string are persisted. Errors are fixed strings; no
    /// subject, address, or id travels inside them.
    pub async fn enrich(
        &self,
        mailbox: MailboxId,
        stored: &StoredMessage,
        source: &dyn MailSource,
    ) -> Result<StoredMessage> {
        // One-shot guard: an enriched message never hits the source again.
        if stored.header.envelope_complete
            && stored.rfc822_size.is_some()
            && stored.mime_structure.is_some()
        {
            return Ok(stored.clone());
        }

        let summary = MessageSummary {
            list_id: stored.header.list_id.clone(),
            element_id: stored.header.element_id.clone(),
            received_at_ms: stored.header.received_at_ms,
            subject: stored.header.subject.clone(),
            unread: stored.header.unread,
        };
        let content = source.content(&summary).await?;

        // Exactly one render, for the byte length only. The bytes are
        // dropped on the next line; nothing but the length is persisted.
        let rendered = self.renderer.render(&content)?;
        let size = u64::try_from(rendered.len())
            .map_err(|_| Error::Storage("message size out of range".into()))?;
        drop(rendered);

        let header = MessageHeader {
            // Placement and list-level fields stay as stored.
            list_id: stored.header.list_id.clone(),
            element_id: stored.header.element_id.clone(),
            received_at_ms: stored.header.received_at_ms,
            unread: stored.header.unread,
            // Envelope fields come from the decrypted content.
            subject: content.subject.clone(),
            from: content.from.clone(),
            to: content.to.clone(),
            cc: content.cc.clone(),
            bcc: content.bcc.clone(),
            reply_to: content.reply_to.clone(),
            sent_at_ms: content.sent_at_ms,
            message_id: content.message_id.clone(),
            in_reply_to: content.in_reply_to.clone(),
            references: content.references.clone(),
            envelope_complete: true,
        };

        self.store
            .update_metadata(mailbox, stored.uid, &header, Some(size))
            .await?;
        let structure = render::bodystructure(&content);
        self.store
            .set_mime_structure(mailbox, stored.uid, &structure)
            .await?;

        Ok(StoredMessage {
            uid: stored.uid,
            header,
            rfc822_size: Some(size),
            mime_structure: Some(structure),
        })
    }
}
