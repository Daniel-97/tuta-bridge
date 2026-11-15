use std::path::PathBuf;
use std::sync::Arc;

use crate::config::Config;
use crate::domain::{AccountId, AccountInfo, Result, StoredCredentials};
use crate::ports::credentials::CredentialStore;
use crate::ports::prompt::LoginPrompt;
use crate::ports::session::SessionFactory;

pub struct LoginUseCase {
    pub factory: Arc<dyn SessionFactory>,
    pub store: Arc<dyn CredentialStore>,
    pub prompt: Arc<dyn LoginPrompt>,
    pub config_path: PathBuf,
}

impl LoginUseCase {
    pub fn new(
        factory: Arc<dyn SessionFactory>,
        store: Arc<dyn CredentialStore>,
        prompt: Arc<dyn LoginPrompt>,
        config_path: PathBuf,
    ) -> Self {
        Self {
            factory,
            store,
            prompt,
            config_path,
        }
    }

    pub async fn execute(&self, email: Option<String>) -> Result<AccountInfo> {
        // 1. Get mail address (prompt or argument), then normalize.
        let mail = match email {
            Some(e) => e,
            None => self.prompt.mail_address()?,
        };
        let mail = mail.trim().to_lowercase();

        // 2. Get password (moved into the request, never cloned).
        let password = self.prompt.password()?;

        // 3. Build session request with a TOTP callback.
        let prompt_for_totp = Arc::clone(&self.prompt);
        let request = crate::ports::session::SessionRequest {
            mail_address: mail.clone(),
            password,
            totp: Arc::new(move || prompt_for_totp.totp_code()),
        };

        // 4. Create a new session through the factory.
        let new = self.factory.create(request).await?;

        // 5. Build stored credentials from the factory result.
        let credentials = StoredCredentials {
            login: mail.clone(),
            user_id: new.user_id,
            access_token: new.access_token,
            encrypted_passphrase_key: new.encrypted_passphrase_key,
        };

        // 6. Resume the session and read account info.
        let session = self.factory.resume(&credentials).await?;
        let info = session.account();

        // 7. Persist credentials in the secret store. On failure, close the
        //    session best-effort (warn only) and return the storage error.
        let account_id = AccountId(mail.clone());
        if let Err(e) = self.store.save(&account_id, &credentials) {
            if session.close().await.is_err() {
                tracing::warn!("server session close failed");
            }
            return Err(e);
        }

        // 8. Update config with the active account. On failure, clean up the
        //    stored credentials, close the session best-effort, then return the
        //    config error.
        let mut config = Config::load(&self.config_path)
            .map_err(|e| crate::domain::Error::Config(e.to_string()))?;
        config.active_account = Some(mail);
        if let Err(e) = config
            .save(&self.config_path)
            .map_err(|e| crate::domain::Error::Config(e.to_string()))
        {
            if self.store.delete(&account_id).is_err() {
                tracing::warn!("credential cleanup failed");
            }
            if session.close().await.is_err() {
                tracing::warn!("server session close failed");
            }
            return Err(e);
        }

        // 9. Return account info.
        Ok(info)
    }
}
