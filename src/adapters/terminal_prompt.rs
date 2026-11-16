use std::io::{self, BufRead, Write};

use secrecy::SecretString;

use crate::domain::{Error, Result};
use crate::ports::prompt::LoginPrompt;

/// A [`LoginPrompt`] that reads from the controlling terminal.
///
/// The password is read with `rpassword` so that it is not echoed. The TOTP
/// code is read as a plain line so the user can see and correct it. The mail
/// address is also read as a plain line.
pub struct TerminalPrompt;

impl LoginPrompt for TerminalPrompt {
    fn mail_address(&self) -> Result<String> {
        let mut stdin = io::stdin().lock();
        let mut line = String::new();
        eprint!("Mail address: ");
        io::stderr().flush().ok();
        stdin
            .read_line(&mut line)
            .map_err(|_| Error::Login("prompt failed".into()))?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return Err(Error::Login("prompt failed".into()));
        }
        Ok(trimmed.to_owned())
    }

    fn password(&self) -> Result<SecretString> {
        let pw = rpassword::prompt_password("Password: ")
            .map_err(|_| Error::Login("prompt failed".into()))?;
        if pw.is_empty() {
            return Err(Error::Login("prompt failed".into()));
        }
        Ok(SecretString::new(pw.into()))
    }

    fn totp_code(&self) -> Result<String> {
        let mut stdin = io::stdin().lock();
        let mut line = String::new();
        eprint!("TOTP code: ");
        io::stderr().flush().ok();
        stdin
            .read_line(&mut line)
            .map_err(|_| Error::Login("prompt failed".into()))?;
        let trimmed = line.trim().replace(' ', "");
        if trimmed.is_empty() {
            return Err(Error::Login("prompt failed".into()));
        }
        Ok(trimmed)
    }
}
