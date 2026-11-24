//! The protocol-agnostic WebDAV layer the CardDAV and CalDAV listeners
//! share: an implicit-TLS accept loop ([`server::serve_dav`]), a minimal
//! HTTP/1.1 server with Basic auth against the bridge password
//! ([`session::run_dav_session`]), the [`handler::DavHandler`] seam a
//! feature implements, and the WebDAV XML parsing and `207 Multi-Status`
//! rendering ([`xml`]).
//!
//! The write methods no feature serves answer `403` with a fixed body;
//! `PUT` and `DELETE` reach the handler.

pub mod handler;
mod http;
pub mod server;
pub mod session;
pub mod xml;

pub use handler::{
    etag_matches, strong_etag_matches, writer_refusal, DavHandler, DavMethod, DavRequest,
    DavResponse, Depth, WellKnown, TEXT_PLAIN, XML_CONTENT_TYPE,
};
pub use server::{serve_dav, DavServeLimits};
pub use session::{run_dav_session, DavLimits};
