use crate::domain::{AccountId, Result, StoredCredentials};

pub trait CredentialStore: Send + Sync {
    fn save(&self, account: &AccountId, credentials: &StoredCredentials) -> Result<()>;
    fn load(&self, account: &AccountId) -> Result<Option<StoredCredentials>>;
    fn delete(&self, account: &AccountId) -> Result<()>;
}
