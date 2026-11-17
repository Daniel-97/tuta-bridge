//! Wall-clock time as a port.
//!
//! The watch loop reads the clock to decide whether a stored batch marker
//! is still replayable and to stamp resume markers; making it a port keeps
//! those decisions deterministic in tests.

/// Milliseconds since the Unix epoch.
pub trait Clock: Send + Sync {
    fn now_ms(&self) -> i64;
}
