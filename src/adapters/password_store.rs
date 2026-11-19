//! System-keyring storage for the local IMAP password.
//!
//! The bridge password never touches the SQLite store, the config file,
//! or a log line: it lives in the Secret Service under the same service
//! name as the account credentials, under the fixed account
//! `imap-bridge`. `set` stores the secret verbatim — no JSON, no
//! serialization format, nothing to version.

use secrecy::{ExposeSecret, SecretString};

use crate::domain::{Error, Result};
use crate::ports::local_password::LocalPasswordStore;

/// Service the bridge password is stored under (shared with the account
/// credentials store).
pub const SERVICE: &str = "tuta-bridge";
/// Keyring account naming the bridge password entry.
pub const ACCOUNT: &str = "imap-bridge";

/// The keyring entry for the bridge password.
///
/// Constructing an entry only records the (service, account) pair; it
/// never contacts the Secret Service, so this works in any environment.
fn entry() -> Result<keyring::Entry> {
    keyring::Entry::new(SERVICE, ACCOUNT).map_err(|_| Error::Storage("keyring unavailable".into()))
}

/// [`LocalPasswordStore`] backed by the system keyring.
pub struct KeyringPasswordStore;

#[async_trait::async_trait]
impl LocalPasswordStore for KeyringPasswordStore {
    async fn set(&self, password: &SecretString) -> Result<()> {
        entry()?
            .set_password(password.expose_secret())
            .map_err(|_| Error::Storage("keyring write failed".into()))
    }

    async fn load(&self) -> Result<Option<SecretString>> {
        match entry()?.get_password() {
            // The returned String is moved into the secret (boxed); the
            // same allocation is zeroized when the value drops.
            Ok(password) => Ok(Some(SecretString::new(password.into()))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(_) => Err(Error::Storage("keyring read failed".into())),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[test]
    fn service_and_account_are_the_pinned_bridge_pair() {
        // The plan pins the exact entry: keyring::Entry::new(
        // "tuta-bridge", "imap-bridge").
        assert_eq!(SERVICE, "tuta-bridge");
        assert_eq!(ACCOUNT, "imap-bridge");
    }

    #[test]
    fn entry_construction_never_contacts_the_secret_service() {
        // Building the entry must succeed with no Secret Service running:
        // construction only records the (service, account) pair.
        entry().expect("entry construction is offline");
    }

    #[test]
    fn store_coerces_to_the_shared_local_password_port() {
        // The backend and the serve wiring hold Arc<dyn
        // LocalPasswordStore>; the coercion site is the contract.
        fn takes_shared_store(_: &Arc<dyn LocalPasswordStore>) {}
        let store: Arc<dyn LocalPasswordStore> = Arc::new(KeyringPasswordStore);
        takes_shared_store(&store);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bridge_entry_targets_the_secret_service_backend() {
        let entry = entry().expect("entry construction is offline");
        assert!(
            entry
                .get_credential()
                .downcast_ref::<keyring::secret_service::SsCredential>()
                .is_some(),
            "default keyring backend must be Secret Service, not mock"
        );
    }

    #[tokio::test]
    #[ignore = "requires the system keyring; run manually"]
    async fn keyring_password_roundtrip() {
        let store = KeyringPasswordStore;
        store
            .set(&SecretString::new("test-bridge-password".into()))
            .await
            .unwrap();
        let loaded = store.load().await.unwrap().expect("password was stored");
        assert_eq!(loaded.expose_secret(), "test-bridge-password");

        // Clean up through the pinned entry so the next run starts fresh.
        keyring::Entry::new(SERVICE, ACCOUNT)
            .unwrap()
            .delete_credential()
            .unwrap();
        assert!(store.load().await.unwrap().is_none());
    }
}
