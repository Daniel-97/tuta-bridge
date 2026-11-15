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

        // 3. Build session request with TOTP and device-approval callbacks.
        let prompt_for_totp = Arc::clone(&self.prompt);
        let request = crate::ports::session::SessionRequest {
            mail_address: mail.clone(),
            password,
            totp: Arc::new(move || prompt_for_totp.totp_code()),
            on_device_approval: Arc::new(|| {
                eprintln!("Approve the login from another Tuta client.");
            }),
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

        // 7. Persist credentials in the secret store.
        self.store.save(&AccountId(mail.clone()), &credentials)?;

        // 8. Update config with the active account.
        let mut config = Config::load(&self.config_path)
            .map_err(|e| crate::domain::Error::Config(e.to_string()))?;
        config.active_account = Some(mail);
        config
            .save(&self.config_path)
            .map_err(|e| crate::domain::Error::Config(e.to_string()))?;

        // 9. Return account info.
        Ok(info)
    }
}
