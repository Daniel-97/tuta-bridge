//! The read-only CalDAV server: Tuta calendars as iCalendar over the
//! shared DAV layer ([`crate::adapters::dav`]).
//!
//! [`handler::CalDavHandler`] serves the URL layout, properties and
//! reports; [`ical`] renders events as RFC 5545 text; [`timezone`]
//! builds the `VTIMEZONE` components repeating events need.

pub mod handler;
pub mod ical;
pub mod timezone;

pub use handler::CalDavHandler;
