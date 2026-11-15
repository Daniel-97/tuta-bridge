use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroize;

#[derive(Clone, PartialEq, Eq)]
pub struct AccountId(pub String);

impl fmt::Display for AccountId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct StoredCredentials {
    pub login: String,
    pub user_id: String,
    pub access_token: String,
    pub encrypted_passphrase_key: Vec<u8>,
}

impl Drop for StoredCredentials {
    fn drop(&mut self) {
        self.access_token.zeroize();
        self.encrypted_passphrase_key.zeroize();
    }
}

#[derive(Clone)]
pub struct AccountInfo {
    pub mail_address: String,
    pub user_id: String,
}
