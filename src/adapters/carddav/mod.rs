//! The read-only CardDAV listener (issue #7): a [`handler::CardDavHandler`]
//! on the shared DAV layer, serving the Tuta address book as vCard 4.0
//! ([`vcard`]).

pub mod handler;
pub mod import;
pub mod vcard;

pub use handler::CardDavHandler;
