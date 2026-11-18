//! Read-only IMAP4rev1 adapter.
//!
//! The codec parses client requests, the renderers format pure response
//! fragments, and the backend answers from the local state store. The
//! session and TLS server arrive with the later M5 tasks.

pub mod backend;
pub mod codec;
pub mod render;
