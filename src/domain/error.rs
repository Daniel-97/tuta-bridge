use thiserror::Error as ThisError;

#[derive(Debug, ThisError)]
pub enum Error {
    #[error("no active account configured")]
    NoActiveAccount,
    #[error("missing credentials: {0}")]
    MissingCredentials(String),
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
}

impl Error {
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::NoActiveAccount => 3,
            Self::MissingCredentials(_) => 3,
            Self::Login(_) => 4,
            Self::SecondFactor(_) => 4,
            Self::BcryptUnsupported => 4,
            Self::FolderNotFound(_) => 5,
            Self::Network(_) => 6,
            Self::PartialDump { .. } => 7,
            Self::Config(_) => 1,
            Self::Storage(_) => 2,
            Self::Message(_) => 2,
            Self::Unsupported(_) => 2,
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
        assert_eq!(Error::MissingCredentials("x".into()).exit_code(), 3);
        assert_eq!(Error::Login("x".into()).exit_code(), 4);
        assert_eq!(Error::SecondFactor("x".into()).exit_code(), 4);
        assert_eq!(Error::BcryptUnsupported.exit_code(), 4);
        assert_eq!(Error::FolderNotFound("x".into()).exit_code(), 5);
        assert_eq!(Error::Network("x".into()).exit_code(), 6);
        assert_eq!(Error::PartialDump { failed: 2 }.exit_code(), 7);
        assert_eq!(Error::Config("x".into()).exit_code(), 1);
    }
}
