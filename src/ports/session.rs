use std::collections::HashMap;
use std::sync::Arc;

use secrecy::SecretString;

use super::calendar::CalendarSource;
use super::contact_source::{ContactSource, NoContacts};
use super::event_stream::EventHandles;
use super::mail_sender::{MailSender, OutgoingMail};
use super::mail_source::MailSource;
use super::mailbox_writer::{MailRef, MailboxWriter};
use crate::domain::{AccountInfo, Error, Result, StoredCredentials};

pub struct SessionRequest {
    pub mail_address: String,
    pub password: SecretString,
    pub totp: Arc<dyn Fn() -> Result<String> + Send + Sync>,
}

pub struct NewSession {
    pub user_id: String,
    pub access_token: String,
    pub encrypted_passphrase_key: Vec<u8>,
}

#[async_trait::async_trait]
pub trait Session: Send + Sync {
    fn account(&self) -> AccountInfo;
    fn mail(&self) -> &dyn MailSource;

    /// The same mail source as [`Session::mail`], but owned.
    ///
    /// `serve` hands this to the long-lived IMAP backend while the
    /// session itself stays with the watch loop; the shared `Arc`
    /// keeps the logged-in state alive independently of either holder.
    fn shared_mail(&self) -> Arc<dyn MailSource>;

    /// The write seam `serve` hands to the IMAP backend.
    ///
    /// Defaults to a writer that refuses every change, so adapters
    /// without write support keep the bridge read-only.
    fn shared_writer(&self) -> Arc<dyn MailboxWriter> {
        Arc::new(ReadOnlyWriter)
    }

    /// The send seam `serve` hands to the SMTP listener. Defaults to a
    /// sender that refuses every mail.
    fn shared_sender(&self) -> Arc<dyn MailSender> {
        Arc::new(NoSender)
    }

    /// The contact seam `serve` hands to the CardDAV listener. Defaults
    /// to a source that refuses every load.
    fn shared_contacts(&self) -> Arc<dyn ContactSource> {
        Arc::new(NoContacts)
    }

    /// The calendar seam `serve` hands to the CalDAV listener. Defaults
    /// to none: adapters without calendars serve no CalDAV.
    fn shared_calendar(&self) -> Option<Arc<dyn CalendarSource>> {
        None
    }

    /// Group ids the event bus must be subscribed to, in subscription order.
    ///
    /// Defaults to none: adapters without an event bus report no groups and
    /// their [`Session::events`] stays unsupported.
    fn event_groups(&self) -> Vec<String> {
        Vec::new()
    }

    /// Connect to the event bus and return the stream plus the lookup used to
    /// resolve the entities the events reference.
    ///
    /// `last_batches` maps each group from [`Session::event_groups`] to the
    /// last processed batch id; groups without a marker resume from
    /// `now_ms - 5000`. Adapters without an event bus keep the default
    /// unsupported error.
    async fn events(
        &self,
        last_batches: &HashMap<String, String>,
        now_ms: i64,
    ) -> Result<EventHandles> {
        let _ = (last_batches, now_ms);
        Err(Error::Unsupported("events not implemented".into()))
    }

    async fn close(&self) -> Result<()>;
}

#[async_trait::async_trait]
pub trait SessionFactory: Send + Sync {
    async fn create(&self, request: SessionRequest) -> Result<NewSession>;
    async fn resume(&self, credentials: &StoredCredentials) -> Result<Box<dyn Session>>;

    /// Remove a server session that was created but cannot be resumed, so
    /// a login that fails half-way does not leave it behind.
    ///
    /// A resumed session is closed through [`Session::close`] instead; this
    /// is only for the window where no [`Session`] exists yet. Defaults to
    /// a no-op for adapters without server-side sessions.
    async fn discard(&self, access_token: &str) -> Result<()> {
        let _ = access_token;
        Ok(())
    }
}

/// A [`MailboxWriter`] that refuses every write.
pub struct ReadOnlyWriter;

#[async_trait::async_trait]
impl MailboxWriter for ReadOnlyWriter {
    async fn set_unread(&self, _mails: &[MailRef], _unread: bool) -> Result<()> {
        Err(Error::Unsupported("read-only session".into()))
    }

    async fn move_to_folder(&self, _target: &str, _mails: &[MailRef]) -> Result<()> {
        Err(Error::Unsupported("read-only session".into()))
    }

    async fn move_to_trash(&self, _mails: &[MailRef]) -> Result<()> {
        Err(Error::Unsupported("read-only session".into()))
    }

    async fn delete_permanently(&self, _folder: &str, _mails: &[MailRef]) -> Result<()> {
        Err(Error::Unsupported("read-only session".into()))
    }
}

/// A [`MailSender`] that refuses every mail.
pub struct NoSender;

#[async_trait::async_trait]
impl MailSender for NoSender {
    async fn send(&self, _mail: &OutgoingMail) -> Result<()> {
        Err(Error::Unsupported(
            "sending is not supported by this session".into(),
        ))
    }
}
