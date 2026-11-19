//! Read-only IMAP4rev1 adapter.
//!
//! The codec parses client requests, the renderers format pure response
//! fragments, the backend answers from the local state store, and the
//! session drives one connection over the TLS server.

pub mod backend;
pub mod codec;
pub mod render;
pub mod search;
pub mod server;
pub mod session;
