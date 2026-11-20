use thiserror::Error as ThisError;

#[derive(Debug, ThisError)]
pub enum Error {
    #[error("no active account configured")]
    NoActiveAccount,
    #[error("no stored credentials for the active account")]
    MissingCredentials,
    #[error("login failed: {0}")]
    Login(String),
    #[error("second factor required: {0}")]
    SecondFactor(String),
    #[error("bcrypt hashing is not supported in this build")]
    BcryptUnsupported,
    #[error("folder not found: {0}")]
    FolderNotFound(String),
    #[error("network error: {0}")]
    Network(String),
    #[error("storage error: {0}")]
    Storage(String),
    #[error("configuration error: {0}")]
    Config(String),
    #[error("message error: {0}")]
    Message(String),
    #[error("unsupported: {0}")]
    Unsupported(String),
    #[error("partial dump: {failed} messages failed")]
    PartialDump { failed: usize },
    #[error("system keyring unavailable: {0}")]
    Keyring(String),
    #[error("already in use: {0}")]
    InUse(String),
}

impl Error {
    /// The process exit code for this error.
    ///
    /// The codes are a contract with supervisors such as the shipped
    /// systemd unit: transient failures (2 storage, 6 network) may be
    /// retried by restarting the process, while every other non-zero
    /// code needs the user to act — log in again, unlock the keyring,
    /// stop the other instance — and a restart would only repeat it.
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::NoActiveAccount => 3,
            Self::MissingCredentials => 3,
            Self::Login(_) => 4,
            Self::SecondFactor(_) => 4,
            Self::BcryptUnsupported => 4,
            Self::FolderNotFound(_) => 5,
            Self::Network(_) => 6,
            Self::PartialDump { .. } => 7,
            Self::Config(_) => 1,
            Self::Storage(_) => 2,
            Self::Message(_) => 2,
            Self::Unsupported(_) => 9,
            Self::Keyring(_) => 8,
            Self::InUse(_) => 10,
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_are_distinct() {
        assert_eq!(Error::NoActiveAccount.exit_code(), 3);
        assert_eq!(Error::MissingCredentials.exit_code(), 3);
        assert_eq!(Error::Login("x".into()).exit_code(), 4);
        assert_eq!(Error::SecondFactor("x".into()).exit_code(), 4);
        assert_eq!(Error::BcryptUnsupported.exit_code(), 4);
        assert_eq!(Error::FolderNotFound("x".into()).exit_code(), 5);
        assert_eq!(Error::Network("x".into()).exit_code(), 6);
        assert_eq!(Error::PartialDump { failed: 2 }.exit_code(), 7);
        assert_eq!(Error::Config("x".into()).exit_code(), 1);
        assert_eq!(Error::Storage("x".into()).exit_code(), 2);
        assert_eq!(Error::Keyring("x".into()).exit_code(), 8);
        assert_eq!(Error::Unsupported("x".into()).exit_code(), 9);
        assert_eq!(Error::InUse("x".into()).exit_code(), 10);
    }
}
