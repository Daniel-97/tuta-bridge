use std::path::PathBuf;
use std::sync::Arc;

use crate::config::Config;
use crate::domain::{AccountId, AccountInfo, Error, Result};
use crate::ports::credentials::CredentialStore;

pub struct StatusUseCase {
    pub store: Arc<dyn CredentialStore>,
    pub config_path: PathBuf,
}

impl StatusUseCase {
    pub async fn execute(&self) -> Result<Option<AccountInfo>> {
        // 1. Load configuration.
        let config = Config::load(&self.config_path).map_err(|e| Error::Config(e.to_string()))?;

        // 2. If there is no active account, return Ok(None).
        let account = match config.active_account {
            Some(a) => a,
            None => return Ok(None),
        };

        // 3. Load credentials from the store.
        let account_id = AccountId(account);
        let credentials = match self.store.load(&account_id)? {
            Some(c) => c,
            None => return Err(Error::MissingCredentials),
        };

        // 4. Return AccountInfo derived from the stored credentials.
        Ok(Some(AccountInfo {
            mail_address: credentials.login,
            user_id: credentials.user_id,
        }))
    }
}
