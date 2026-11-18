//! Read-only IMAP4rev1 adapter.
//!
//! The codec parses client requests and the renderers format pure
//! response fragments; the backend, session, and TLS server arrive with
//! the later M5 tasks.

pub mod codec;
pub mod render;
