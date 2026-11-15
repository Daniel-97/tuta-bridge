use std::path::PathBuf;
use std::sync::Arc;

use crate::config::Config;
use crate::domain::{AccountId, Error, Result};
use crate::ports::credentials::CredentialStore;
use crate::ports::session::SessionFactory;

pub struct LogoutUseCase {
    pub factory: Arc<dyn SessionFactory>,
    pub store: Arc<dyn CredentialStore>,
    pub config_path: PathBuf,
}

impl LogoutUseCase {
    pub async fn execute(&self) -> Result<()> {
        // 1. Load configuration.
        let mut config =
            Config::load(&self.config_path).map_err(|e| Error::Config(e.to_string()))?;

        // 2. If there is no active account, return Ok(()) immediately.
        let account = match config.active_account.take() {
            Some(a) => a,
            None => return Ok(()),
        };

        let account_id = AccountId(account);

        // 3. Best-effort session close: resume and close, logging on failure.
        //    Storage errors from load propagate; only resume/close are best-effort.
        if let Some(credentials) = self.store.load(&account_id)? {
            match self.factory.resume(&credentials).await {
                Ok(session) if session.close().await.is_err() => {
                    tracing::warn!("server session close failed");
                }
                Err(_) => {
                    tracing::warn!("server session close failed");
                }
                _ => {}
            }
        }

        // 4. Delete the keyring entry (storage errors propagate).
        self.store.delete(&account_id)?;

        // 5. Save config with active_account cleared.
        config
            .save(&self.config_path)
            .map_err(|e| Error::Config(e.to_string()))?;

        Ok(())
    }
}
