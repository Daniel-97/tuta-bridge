use crate::domain::{AccountId, Error, Result, StoredCredentials};
use crate::ports::credentials::CredentialStore;

/// Fixed explanation for a keyring that cannot be reached or is locked.
pub const KEYRING_UNAVAILABLE: &str =
    "the Secret Service is not running or the keyring is locked; unlock it and start again";

/// Map a failed keyring operation to a fixed message.
///
/// A keyring that cannot be reached at all (no Secret Service on the
/// session bus, a locked collection, an unlock prompt that cannot be
/// shown) becomes [`Error::Keyring`]: it needs the user, so a supervisor
/// must not restart into it. Anything else stays an opaque storage
/// error naming only the operation.
pub fn keyring_error(error: &keyring::Error, operation: &str) -> Error {
    match error {
        keyring::Error::NoStorageAccess(_) | keyring::Error::PlatformFailure(_) => {
            Error::Keyring(KEYRING_UNAVAILABLE.into())
        }
        _ => Error::Storage(format!("keyring {operation} failed")),
    }
}

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
            .map_err(|e| keyring_error(&e, "write"))
    }

    fn load(&self, account: &AccountId) -> Result<Option<StoredCredentials>> {
        let entry = keyring::Entry::new(&self.service, account.0.as_str())
            .map_err(|e| keyring_error(&e, "read"))?;
        match entry.get_password() {
            Ok(json) => serde_json::from_str(&json)
                .map(Some)
                .map_err(|_| Error::Storage("keyring read failed".into())),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(keyring_error(&e, "read")),
        }
    }

    fn delete(&self, account: &AccountId) -> Result<()> {
        let entry = keyring::Entry::new(&self.service, account.0.as_str())
            .map_err(|e| keyring_error(&e, "delete"))?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(keyring_error(&e, "delete")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unreachable_or_locked_keyring_is_a_keyring_error() {
        for error in [
            keyring::Error::NoStorageAccess("locked".into()),
            keyring::Error::PlatformFailure("no bus".into()),
        ] {
            let mapped = keyring_error(&error, "read");
            assert!(matches!(mapped, Error::Keyring(ref m) if m == KEYRING_UNAVAILABLE));
            assert_eq!(mapped.exit_code(), 8);
        }
    }

    #[test]
    fn other_keyring_failures_stay_opaque_storage_errors() {
        let mapped = keyring_error(&keyring::Error::BadEncoding(vec![0xff]), "read");
        assert!(matches!(mapped, Error::Storage(ref m) if m == "keyring read failed"));
    }

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

    #[cfg(target_os = "macos")]
    #[test]
    fn default_store_is_the_keychain_not_mock() {
        // Without the `apple-native` feature keyring silently falls back
        // to its in-memory mock store, which forgets everything on exit.
        let entry = keyring::Entry::new("tuta-bridge-test", "backend-check").unwrap();
        assert!(
            entry
                .get_credential()
                .downcast_ref::<keyring::macos::MacCredential>()
                .is_some(),
            "default keyring backend must be the macOS Keychain, not mock"
        );
    }

    #[test]
    #[ignore = "requires the system keyring; run manually"]
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
