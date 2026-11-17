use std::sync::Arc;

use crate::domain::{EventFrame, Result};

use super::event_lookup::EventLookup;

/// One direction of the Tuta event bus: a sequence of parsed frames.
///
/// Implementations connect lazily or on construction; every read failure is
/// terminal and the caller must reconnect through the session.
#[async_trait::async_trait]
pub trait EventStream: Send {
    /// Read the next meaningful frame from the event bus.
    ///
    /// Pings are answered transparently and ignored messages are skipped, so
    /// only batches, sync markers, and errors surface here.
    async fn next_frame(&mut self) -> Result<EventFrame>;
}

/// Everything the event processor needs to consume the bus.
pub struct EventHandles {
    pub stream: Box<dyn EventStream>,
    pub lookup: Arc<dyn EventLookup>,
}
