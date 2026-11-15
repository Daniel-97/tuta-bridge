use crate::domain::Result;
use secrecy::SecretString;

pub trait LoginPrompt: Send + Sync {
    fn mail_address(&self) -> Result<String>;
    fn password(&self) -> Result<SecretString>;
    fn totp_code(&self) -> Result<String>;
}
