use std::collections::HashMap;
use std::sync::Arc;

use secrecy::SecretString;

use super::event_stream::EventHandles;
use super::mail_source::MailSource;
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
}
