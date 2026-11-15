use crate::domain::{AccountId, Error, Result, StoredCredentials};
use crate::ports::credentials::CredentialStore;

pub struct KeyringCredentialStore {
    service: String,
}

impl KeyringCredentialStore {
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }
}

impl CredentialStore for KeyringCredentialStore {
    fn save(&self, account: &AccountId, credentials: &StoredCredentials) -> Result<()> {
        let json = serde_json::to_string(credentials)
            .map_err(|_| Error::Storage("keyring write failed".into()))?;
        keyring::Entry::new(&self.service, account.0.as_str())
            .and_then(|entry| entry.set_password(&json))
            .map_err(|_| Error::Storage("keyring write failed".into()))
    }

    fn load(&self, account: &AccountId) -> Result<Option<StoredCredentials>> {
        let entry = keyring::Entry::new(&self.service, account.0.as_str())
            .map_err(|_| Error::Storage("keyring read failed".into()))?;
        match entry.get_password() {
            Ok(json) => serde_json::from_str(&json)
                .map(Some)
                .map_err(|_| Error::Storage("keyring read failed".into())),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(_) => Err(Error::Storage("keyring read failed".into())),
        }
    }

    fn delete(&self, account: &AccountId) -> Result<()> {
        let entry = keyring::Entry::new(&self.service, account.0.as_str())
            .map_err(|_| Error::Storage("keyring delete failed".into()))?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(_) => Err(Error::Storage("keyring delete failed".into())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_credentials_json_roundtrip() {
        let c = StoredCredentials {
            login: "a@b.c".into(),
            user_id: "u".into(),
            access_token: "t".into(),
            encrypted_passphrase_key: vec![1, 2, 3],
        };
        let json = serde_json::to_string(&c).unwrap();
        assert_eq!(
            serde_json::from_str::<StoredCredentials>(&json)
                .unwrap()
                .login,
            "a@b.c"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn default_store_is_secret_service_not_mock() {
        let entry = keyring::Entry::new("tuta-bridge-test", "backend-check").unwrap();
        assert!(
            entry
                .get_credential()
                .downcast_ref::<keyring::secret_service::SsCredential>()
                .is_some(),
            "default keyring backend must be Secret Service, not mock"
        );
    }

    #[test]
    #[ignore = "requires a running Secret Service; run manually"]
    fn keyring_roundtrip() {
        let store = KeyringCredentialStore::new("tuta-bridge-test");
        let account = AccountId("test@example.invalid".into());
        let c = StoredCredentials {
            login: "test@example.invalid".into(),
            user_id: "u".into(),
            access_token: "t".into(),
            encrypted_passphrase_key: vec![9],
        };
        store.save(&account, &c).unwrap();
        assert_eq!(store.load(&account).unwrap().unwrap().user_id, "u");
        store.delete(&account).unwrap();
        assert!(store.load(&account).unwrap().is_none());
    }
}
