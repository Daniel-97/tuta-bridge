use std::sync::Arc;

use secrecy::SecretString;

use super::mail_source::MailSource;
use crate::domain::{AccountInfo, Result, StoredCredentials};

pub struct SessionRequest {
    pub mail_address: String,
    pub password: SecretString,
    pub totp: Arc<dyn Fn() -> Result<String> + Send + Sync>,
    pub on_device_approval: Arc<dyn Fn() + Send + Sync>,
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
    async fn close(&self) -> Result<()>;
}

#[async_trait::async_trait]
pub trait SessionFactory: Send + Sync {
    async fn create(&self, request: SessionRequest) -> Result<NewSession>;
    async fn resume(&self, credentials: &StoredCredentials) -> Result<Box<dyn Session>>;
}
