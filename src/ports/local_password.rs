use secrecy::SecretString;

use crate::domain::Result;

/// The bridge's local IMAP password, stored in the system keyring.
///
/// This is the password IMAP clients log in with — deliberately distinct
/// from the Tuta account password, which only ever exists inside the
/// SDK session.
#[async_trait::async_trait]
pub trait LocalPasswordStore: Send + Sync {
    async fn set(&self, password: &SecretString) -> Result<()>;
    async fn load(&self) -> Result<Option<SecretString>>;
}
