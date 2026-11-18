//! Read-only IMAP4rev1 adapter.
//!
//! The codec lands first (pure request parsing); the renderers, backend,
//! session, and TLS server arrive with the later M5 tasks.

pub mod codec;
