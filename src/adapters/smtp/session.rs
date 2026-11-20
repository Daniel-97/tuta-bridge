//! One SMTP submission session (RFC 5321 / RFC 6409, AUTH per RFC 4954)
//! over implicit TLS.
//!
//! Authentication reuses the bridge password through the IMAP backend's
//! `login`. A message is accepted only after `AUTH`; its recipients come
//! from the envelope, its content from the DATA bytes, and it is handed
//! to the [`MailSender`] before the final reply, so a `250` means Tuta
//! took the mail. Log lines carry fixed command names and counts only.

use std::sync::Arc;
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use secrecy::SecretString;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;
use tokio::time::{sleep, timeout, timeout_at, Instant};

use super::outgoing::{is_valid_address, outgoing_from_message, OutgoingError};
use crate::adapters::stall::StallGuard;
use crate::domain::{Error, Result};
use crate::ports::imap_backend::ImapBackend;
use crate::ports::mail_sender::MailSender;

/// The bounds of one SMTP session.
#[derive(Clone)]
pub struct SmtpLimits {
    /// How long a connection may stay unauthenticated, measured from the
    /// greeting — the whole phase, like IMAP.
    pub pre_auth_timeout: Duration,
    /// Inactivity before the session is closed (RFC 5321 §4.5.3.2 asks
    /// servers for at least 5 minutes).
    pub idle_timeout: Duration,
    /// How long one write may make no progress before the session ends.
    pub write_timeout: Duration,
    /// How long one whole DATA transfer may take, however steadily the
    /// lines trickle in.
    pub max_data_duration: Duration,
    /// The largest message accepted, advertised as `SIZE`.
    pub max_message_bytes: usize,
    /// Recipients accepted per message.
    pub max_recipients: usize,
    pub login_failure_delay: Duration,
    pub max_login_attempts: u32,
    /// Serializes failed-login delays across all connections.
    pub login_gate: Arc<Mutex<()>>,
}

impl Default for SmtpLimits {
    fn default() -> Self {
        Self {
            pre_auth_timeout: Duration::from_secs(60),
            idle_timeout: Duration::from_secs(5 * 60),
            write_timeout: Duration::from_secs(60),
            max_data_duration: Duration::from_secs(10 * 60),
            max_message_bytes: 25 * 1024 * 1024,
            max_recipients: 100,
            login_failure_delay: Duration::from_secs(3),
            max_login_attempts: 3,
            login_gate: Arc::new(Mutex::new(())),
        }
    }
}

/// The longest command line (RFC 5321 §4.5.3.1.4: 512 octets) and the
/// longest DATA line accepted (998 + CRLF is the RFC limit; real
/// clients exceed it, so a generous bound keeps them working).
const MAX_COMMAND_LINE: usize = 512;
const MAX_DATA_LINE: usize = 64 * 1024;

const IO_FAILED: &str = "smtp connection io failed";

fn io_failed(_: std::io::Error) -> Error {
    Error::Network(IO_FAILED.into())
}

const KNOWN_COMMANDS: &[&str] = &[
    "EHLO", "HELO", "AUTH", "MAIL", "RCPT", "DATA", "RSET", "NOOP", "QUIT", "VRFY", "STARTTLS",
];

fn log_command(verb: &str) -> &'static str {
    KNOWN_COMMANDS
        .iter()
        .copied()
        .find(|known| *known == verb)
        .unwrap_or("<unknown>")
}

enum Line {
    Text(Vec<u8>),
    TooLong,
}

/// Read one line without its terminator, bounded by `max`. `None` at
/// the end of the stream.
async fn read_line<R: AsyncBufRead + Unpin>(reader: &mut R, max: usize) -> Result<Option<Line>> {
    let mut bytes = Vec::new();
    let mut too_long = false;
    loop {
        let available = reader.fill_buf().await.map_err(io_failed)?;
        if available.is_empty() {
            return Ok(if bytes.is_empty() && !too_long {
                None
            } else {
                Some(Line::TooLong)
            });
        }
        let (chunk, done) = match available.iter().position(|byte| *byte == b'\n') {
            Some(at) => (&available[..=at], true),
            None => (available, false),
        };
        let used = chunk.len();
        if !too_long {
            bytes.extend_from_slice(chunk);
            if bytes.len() > max + 2 {
                too_long = true;
                bytes = Vec::new();
            }
        }
        reader.consume(used);
        if done {
            break;
        }
    }
    if too_long {
        return Ok(Some(Line::TooLong));
    }
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    Ok(Some(Line::Text(bytes)))
}

async fn reply<W: AsyncWrite + Unpin>(writer: &mut W, text: &str) -> Result<()> {
    writer.write_all(text.as_bytes()).await.map_err(io_failed)?;
    writer.write_all(b"\r\n").await.map_err(io_failed)?;
    writer.flush().await.map_err(io_failed)
}

/// The address inside `FROM:<…>` / `TO:<…>`, and the rest (parameters).
fn path_argument<'a>(rest: &'a str, keyword: &str) -> Option<(&'a str, &'a str)> {
    let head = rest.get(..keyword.len())?;
    if !head.eq_ignore_ascii_case(keyword) {
        return None;
    }
    let rest = rest[keyword.len()..].trim_start();
    let rest = rest.strip_prefix('<')?;
    let end = rest.find('>')?;
    Some((rest[..end].trim(), rest[end + 1..].trim()))
}

/// Decode an `AUTH PLAIN` response: `authzid NUL authcid NUL passwd`.
fn decode_plain(encoded: &str) -> Option<(String, String)> {
    let bytes = BASE64.decode(encoded.trim()).ok()?;
    let mut parts = bytes.split(|byte| *byte == 0);
    let _authzid = parts.next()?;
    let user = String::from_utf8(parts.next()?.to_vec()).ok()?;
    let password = String::from_utf8(parts.next()?.to_vec()).ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((user, password))
}

fn decode_b64_text(encoded: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(encoded).ok()?;
    String::from_utf8(BASE64.decode(text.trim()).ok()?).ok()
}

/// The SMTP reply for a refused message.
fn refusal(error: &OutgoingError) -> &'static str {
    match error {
        OutgoingError::Unparseable => "554 5.6.0 message could not be parsed",
        OutgoingError::MissingFrom => "554 5.6.0 message has no From header",
        OutgoingError::BodyTooLarge => "552 5.3.4 message body too large for Tuta",
        OutgoingError::NoRecipients => "554 5.5.1 no valid recipients",
        OutgoingError::InvalidAddress => "554 5.1.7 message has an invalid address or name",
    }
}

/// The SMTP reply for a failed send. Network trouble is transient, so
/// the client retries later; anything else is final.
fn send_failure(error: &Error) -> String {
    match error {
        Error::Network(message) => format!("451 4.4.0 {message}"),
        Error::Unsupported(message) => format!("554 5.7.1 {message}"),
        other => format!("554 5.0.0 {other}"),
    }
}

struct Session {
    auth: Arc<dyn ImapBackend>,
    sender: Arc<dyn MailSender>,
    limits: SmtpLimits,
    greeted: bool,
    authenticated: bool,
    failed_logins: u32,
    mail_from: Option<String>,
    rcpt_to: Vec<String>,
}

enum Flow {
    Continue,
    Close,
}

/// Serve one SMTP session over `stream`.
pub async fn run_smtp_session<S>(
    stream: S,
    auth: Arc<dyn ImapBackend>,
    sender: Arc<dyn MailSender>,
    limits: SmtpLimits,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (reader, writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);
    let mut writer = StallGuard::new(writer, limits.write_timeout);
    let pre_auth_deadline = Instant::now() + limits.pre_auth_timeout;
    let mut session = Session {
        auth,
        sender,
        limits,
        greeted: false,
        authenticated: false,
        failed_logins: 0,
        mail_from: None,
        rcpt_to: Vec::new(),
    };
    reply(&mut writer, "220 tuta-bridge ESMTP ready").await?;
    loop {
        let deadline = if session.authenticated {
            Instant::now() + session.limits.idle_timeout
        } else {
            pre_auth_deadline
        };
        let line = match timeout_at(deadline, read_line(&mut reader, MAX_COMMAND_LINE)).await {
            Err(_) => {
                reply(&mut writer, "421 4.4.2 idle for too long; closing").await?;
                break;
            }
            Ok(result) => match result? {
                None => break,
                Some(Line::TooLong) => {
                    reply(&mut writer, "500 5.5.2 line too long").await?;
                    continue;
                }
                Some(Line::Text(bytes)) => String::from_utf8_lossy(&bytes).into_owned(),
            },
        };
        match session.dispatch(&mut reader, &mut writer, &line).await? {
            Flow::Continue => {}
            Flow::Close => break,
        }
    }
    writer.shutdown().await.ok();
    Ok(())
}

impl Session {
    fn reset(&mut self) {
        self.mail_from = None;
        self.rcpt_to.clear();
    }

    async fn dispatch<R, W>(&mut self, reader: &mut R, writer: &mut W, line: &str) -> Result<Flow>
    where
        R: AsyncBufRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let (verb, rest) = match line.split_once(' ') {
            Some((verb, rest)) => (verb.to_ascii_uppercase(), rest.trim()),
            None => (line.trim().to_ascii_uppercase(), ""),
        };
        tracing::debug!(command = log_command(&verb), "smtp command");
        match verb.as_str() {
            "EHLO" => {
                self.greeted = true;
                self.reset();
                reply(writer, "250-tuta-bridge").await?;
                reply(
                    writer,
                    &format!("250-SIZE {}", self.limits.max_message_bytes),
                )
                .await?;
                reply(writer, "250-8BITMIME").await?;
                reply(writer, "250-ENHANCEDSTATUSCODES").await?;
                reply(writer, "250 AUTH PLAIN LOGIN").await?;
            }
            "HELO" => {
                self.greeted = true;
                self.reset();
                reply(writer, "250 tuta-bridge").await?;
            }
            "AUTH" => return self.handle_auth(reader, writer, rest).await,
            "MAIL" => self.handle_mail(writer, rest).await?,
            "RCPT" => self.handle_rcpt(writer, rest).await?,
            "DATA" => self.handle_data(reader, writer).await?,
            "RSET" => {
                self.reset();
                reply(writer, "250 2.0.0 ok").await?;
            }
            "NOOP" => reply(writer, "250 2.0.0 ok").await?,
            "VRFY" => reply(writer, "252 2.5.0 cannot verify; send and see").await?,
            "QUIT" => {
                reply(writer, "221 2.0.0 tuta-bridge closing").await?;
                return Ok(Flow::Close);
            }
            "STARTTLS" => reply(writer, "454 4.7.0 already on TLS").await?,
            _ => reply(writer, "502 5.5.1 command not implemented").await?,
        }
        Ok(Flow::Continue)
    }

    async fn handle_auth<R, W>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        rest: &str,
    ) -> Result<Flow>
    where
        R: AsyncBufRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        if !self.greeted {
            reply(writer, "503 5.5.1 send EHLO first").await?;
            return Ok(Flow::Continue);
        }
        if self.authenticated {
            reply(writer, "503 5.5.1 already authenticated").await?;
            return Ok(Flow::Continue);
        }
        let mut words = rest.split_whitespace();
        let mechanism = words.next().unwrap_or("").to_ascii_uppercase();
        let initial = words.next();
        let credentials = match mechanism.as_str() {
            "PLAIN" => {
                let response = match initial {
                    Some(initial) => initial.to_string(),
                    None => {
                        reply(writer, "334 ").await?;
                        match self.read_response(reader).await? {
                            Some(response) => response,
                            None => return Ok(Flow::Close),
                        }
                    }
                };
                if response == "*" {
                    reply(writer, "501 5.0.0 authentication cancelled").await?;
                    return Ok(Flow::Continue);
                }
                decode_plain(&response)
            }
            "LOGIN" => {
                let user = match initial {
                    Some(initial) => decode_b64_text(initial.as_bytes()),
                    None => {
                        reply(writer, "334 VXNlcm5hbWU6").await?;
                        match self.read_response(reader).await? {
                            Some(response) => decode_b64_text(response.as_bytes()),
                            None => return Ok(Flow::Close),
                        }
                    }
                };
                reply(writer, "334 UGFzc3dvcmQ6").await?;
                let password = match self.read_response(reader).await? {
                    Some(response) => decode_b64_text(response.as_bytes()),
                    None => return Ok(Flow::Close),
                };
                user.zip(password)
            }
            _ => {
                reply(writer, "504 5.5.4 unrecognized authentication mechanism").await?;
                return Ok(Flow::Continue);
            }
        };
        let Some((user, password)) = credentials else {
            reply(writer, "501 5.5.2 cannot decode response").await?;
            return Ok(Flow::Continue);
        };
        let password = SecretString::new(password.into_boxed_str());
        if self.auth.login(&user, &password).await? {
            self.authenticated = true;
            reply(writer, "235 2.7.0 authentication succeeded").await?;
            return Ok(Flow::Continue);
        }
        self.failed_logins += 1;
        tracing::warn!(attempt = self.failed_logins, "smtp login failed");
        {
            let _gate = self.limits.login_gate.lock().await;
            sleep(self.limits.login_failure_delay).await;
        }
        reply(writer, "535 5.7.8 authentication failed").await?;
        if self.failed_logins >= self.limits.max_login_attempts {
            reply(writer, "421 4.7.0 too many failed logins").await?;
            return Ok(Flow::Close);
        }
        Ok(Flow::Continue)
    }

    /// One continuation response line of an AUTH exchange.
    async fn read_response<R: AsyncBufRead + Unpin>(
        &self,
        reader: &mut R,
    ) -> Result<Option<String>> {
        match timeout(
            self.limits.idle_timeout,
            read_line(reader, MAX_COMMAND_LINE),
        )
        .await
        {
            Err(_) => Ok(None),
            Ok(result) => Ok(match result? {
                Some(Line::Text(bytes)) => Some(String::from_utf8_lossy(&bytes).into_owned()),
                _ => None,
            }),
        }
    }

    async fn handle_mail<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        rest: &str,
    ) -> Result<()> {
        if !self.authenticated {
            return reply(writer, "530 5.7.0 authentication required").await;
        }
        if self.mail_from.is_some() {
            return reply(writer, "503 5.5.1 nested MAIL command").await;
        }
        let Some((address, params)) = path_argument(rest, "FROM:") else {
            return reply(writer, "501 5.5.4 syntax: MAIL FROM:<address>").await;
        };
        if !is_valid_address(address) {
            return reply(writer, "553 5.1.7 invalid sender address").await;
        }
        for param in params.split_whitespace() {
            if let Some(size) = param
                .get(..5)
                .filter(|key| key.eq_ignore_ascii_case("SIZE="))
                .and_then(|_| param[5..].parse::<usize>().ok())
            {
                if size > self.limits.max_message_bytes {
                    return reply(writer, "552 5.3.4 message size exceeds the limit").await;
                }
            }
        }
        // RFC 6409 §8.3: refuse a sender the account may not use here,
        // before the client uploads the message.
        match self.sender.accepts_sender(address).await {
            Ok(true) => {}
            Ok(false) => {
                return reply(
                    writer,
                    "553 5.7.1 sender address is not an address of this account",
                )
                .await
            }
            Err(_) => return reply(writer, "451 4.4.0 sender check failed; try again").await,
        }
        self.mail_from = Some(address.to_string());
        reply(writer, "250 2.1.0 ok").await
    }

    async fn handle_rcpt<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        rest: &str,
    ) -> Result<()> {
        if self.mail_from.is_none() {
            return reply(writer, "503 5.5.1 send MAIL first").await;
        }
        let Some((address, _)) = path_argument(rest, "TO:") else {
            return reply(writer, "501 5.5.4 syntax: RCPT TO:<address>").await;
        };
        if !is_valid_address(address) {
            return reply(writer, "553 5.1.3 invalid recipient address").await;
        }
        if self.rcpt_to.len() >= self.limits.max_recipients {
            return reply(writer, "452 4.5.3 too many recipients").await;
        }
        self.rcpt_to.push(address.to_string());
        reply(writer, "250 2.1.5 ok").await
    }

    async fn handle_data<R, W>(&mut self, reader: &mut R, writer: &mut W) -> Result<()>
    where
        R: AsyncBufRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        if self.mail_from.is_none() {
            return reply(writer, "503 5.5.1 send MAIL first").await;
        }
        if self.rcpt_to.is_empty() {
            return reply(writer, "554 5.5.1 no valid recipients").await;
        }
        reply(writer, "354 end data with <CR><LF>.<CR><LF>").await?;

        // Read to the terminating dot even when the message turns out
        // too large, so the stream stays in sync with the client.
        let mut message = Vec::new();
        let mut oversized = false;
        let data_deadline = Instant::now() + self.limits.max_data_duration;
        loop {
            let line_deadline = (Instant::now() + self.limits.idle_timeout).min(data_deadline);
            let line = match timeout_at(line_deadline, read_line(reader, MAX_DATA_LINE)).await {
                Err(_) => return Err(Error::Network(IO_FAILED.into())),
                Ok(result) => match result? {
                    None => return Err(Error::Network(IO_FAILED.into())),
                    Some(Line::TooLong) => {
                        oversized = true;
                        continue;
                    }
                    Some(Line::Text(bytes)) => bytes,
                },
            };
            if line == b"." {
                break;
            }
            // RFC 5321 §4.5.2: drop the stuffed leading dot.
            let line = line.strip_prefix(b".").unwrap_or(&line);
            if !oversized {
                message.extend_from_slice(line);
                message.extend_from_slice(b"\r\n");
                if message.len() > self.limits.max_message_bytes {
                    oversized = true;
                    message = Vec::new();
                }
            }
        }
        let rcpt_to = std::mem::take(&mut self.rcpt_to);
        self.reset();
        if oversized {
            return reply(writer, "552 5.3.4 message size exceeds the limit").await;
        }

        let mail = match outgoing_from_message(&message, &rcpt_to) {
            Ok(mail) => mail,
            Err(error) => return reply(writer, refusal(&error)).await,
        };
        drop(message);
        tracing::info!(
            recipients = mail.recipients().count(),
            attachments = mail.attachments.len(),
            "smtp message accepted for sending"
        );
        match self.sender.send(&mail).await {
            Ok(()) => reply(writer, "250 2.0.0 message sent").await,
            Err(error) => {
                tracing::warn!("smtp send failed");
                reply(writer, &send_failure(&error)).await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_parse_with_and_without_parameters() {
        assert_eq!(
            path_argument("FROM:<a@b.example> SIZE=10", "FROM:"),
            Some(("a@b.example", "SIZE=10"))
        );
        assert_eq!(
            path_argument("to: <c@d.example>", "TO:"),
            Some(("c@d.example", ""))
        );
        assert_eq!(path_argument("FROM:a@b.example", "FROM:"), None);
    }

    #[test]
    fn plain_responses_decode_three_fields() {
        let encoded = BASE64.encode(b"\0user@x.example\0secret");
        assert_eq!(
            decode_plain(&encoded),
            Some(("user@x.example".to_string(), "secret".to_string()))
        );
        assert_eq!(decode_plain("not base64!"), None);
        assert_eq!(decode_plain(&BASE64.encode(b"only-one-field")), None);
    }

    #[test]
    fn network_failures_are_transient() {
        assert!(send_failure(&Error::Network("x".into())).starts_with("451 "));
        assert!(send_failure(&Error::Unsupported("x".into())).starts_with("554 "));
    }
}
