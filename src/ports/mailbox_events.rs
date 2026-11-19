//! Mailbox-change broadcast events.
//!
//! The watch loop publishes one [`MailboxChanged`] per mailbox a batch
//! touched — and one per current mailbox after a recovery sync, which
//! never goes through `apply_batch` — so idling sessions can learn that
//! cached mailbox state may be stale. The
//! events carry a [`MailboxId`] only: no subjects, addresses, or entity
//! ids ever travel on this channel.

use crate::domain::MailboxId;

/// The stored contents of one mailbox changed: rows were inserted,
/// updated, or deleted, and cached views of the mailbox may be stale.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MailboxChanged(pub MailboxId);

/// Sender side of the mailbox-change broadcast channel.
///
/// Send errors from a closed channel are the caller's business to
/// ignore: no receivers means nobody idles.
pub type MailboxEventSender = tokio::sync::broadcast::Sender<MailboxChanged>;
