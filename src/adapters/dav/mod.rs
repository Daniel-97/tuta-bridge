//! The protocol-agnostic WebDAV layer the CardDAV and CalDAV listeners
//! share: an implicit-TLS accept loop ([`server::serve_dav`]), a minimal
//! HTTP/1.1 server with Basic auth against the bridge password
//! ([`session::run_dav_session`]), the [`handler::DavHandler`] seam a
//! feature implements, and the WebDAV XML parsing and `207 Multi-Status`
//! rendering ([`xml`]).
//!
//! Read-only: every write method answers `403` with a fixed body.

pub mod handler;
mod http;
pub mod server;
pub mod session;
pub mod xml;

pub use handler::{
    DavHandler, DavMethod, DavRequest, DavResponse, Depth, WellKnown, TEXT_PLAIN, XML_CONTENT_TYPE,
};
pub use server::{serve_dav, DavServeLimits};
pub use session::{run_dav_session, DavLimits};
