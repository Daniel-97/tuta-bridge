//! SMTP submission: a local, TLS-only listener that hands submitted mail
//! to Tuta through the [`MailSender`](crate::ports::mail_sender::MailSender)
//! port.

pub mod outgoing;
pub mod server;
pub mod session;
