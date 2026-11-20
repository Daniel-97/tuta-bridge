//! One POP3 session (RFC 1939, with CAPA from RFC 2449).
//!
//! The session is a thin protocol layer over the same [`ImapBackend`]
//! the IMAP server uses: LOGIN checks the bridge password, the maildrop
//! is the Inbox as it was when the session logged in, sizes come from
//! `RFC822.SIZE`, and RETR/TOP render the message on demand exactly like
//! an IMAP `BODY[]`. Nothing is ever deleted: Tuta mail stays on the
//! server, so `DELE` answers `-ERR` and clients must leave mail on the
//! server (the default of Thunderbird and of `fetchmail --keep`).
//!
//! Hygiene matches the IMAP session: log lines carry fixed command
//! names and counts only, never a user name, password, or message byte.

use std::sync::Arc;
use std::time::Duration;

use secrecy::SecretString;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, BufWriter};
use tokio::sync::Mutex;
use tokio::time::{sleep, timeout_at, Instant};

use crate::adapters::imap::codec::FetchItem;
use crate::adapters::stall::StallGuard;
use crate::domain::{Error, MailboxId, Result};
use crate::ports::imap_backend::ImapBackend;

/// The bounds of one POP3 session.
#[derive(Clone)]
pub struct Pop3Limits {
    /// How long a connection may stay unauthenticated, measured from the
    /// greeting — the whole phase, like IMAP.
    pub pre_auth_timeout: Duration,
    /// Inactivity before an authenticated session is closed. RFC 1939
    /// §3 asks for at least 10 minutes.
    pub idle_timeout: Duration,
    /// How long one write may make no progress before the session ends:
    /// a client that stops reading does not pin its connection slot.
    pub write_timeout: Duration,
    /// The delay every failed PASS waits out, one at a time across the
    /// whole listener (see `login_gate`).
    pub login_failure_delay: Duration,
    /// Failed logins tolerated per connection before it is closed.
    pub max_login_attempts: u32,
    /// Serializes failed-login delays across connections, so opening
    /// more connections does not buy more guesses.
    pub login_gate: Arc<Mutex<()>>,
}

impl Default for Pop3Limits {
    fn default() -> Self {
        Self {
            pre_auth_timeout: Duration::from_secs(60),
            idle_timeout: Duration::from_secs(10 * 60),
            write_timeout: Duration::from_secs(60),
            login_failure_delay: Duration::from_secs(3),
            max_login_attempts: 3,
            login_gate: Arc::new(Mutex::new(())),
        }
    }
}

/// The longest command line accepted, CRLF included. RFC 2449 §4 caps
/// commands at 255 octets; a little slack costs nothing.
const MAX_LINE: usize = 512;

const GREETING: &str = "+OK tuta-bridge POP3 ready";

/// The text of the connection's own io error.
const IO_FAILED: &str = "pop3 connection io failed";

fn io_failed(_: std::io::Error) -> Error {
    Error::Network(IO_FAILED.into())
}

/// The commands that may appear in a log line; anything else logs a
/// fixed placeholder so client bytes never reach a log.
const KNOWN_COMMANDS: &[&str] = &[
    "CAPA", "USER", "PASS", "STAT", "LIST", "UIDL", "RETR", "TOP", "DELE", "NOOP", "RSET", "QUIT",
    "APOP", "AUTH", "STLS",
];

fn log_command(verb: &str) -> &'static str {
    KNOWN_COMMANDS
        .iter()
        .copied()
        .find(|known| *known == verb)
        .unwrap_or("<unknown>")
}

/// The locked maildrop: the Inbox as it was at login.
struct Maildrop {
    mailbox: MailboxId,
    uidvalidity: u32,
    /// UIDs in ascending order: position + 1 is the message number.
    uids: Vec<u32>,
    /// Sizes, filled on first need.
    sizes: Vec<Option<u64>>,
    /// Messages that left the store (or whose size cannot be loaded)
    /// since login: LIST, STAT and UIDL all omit them, so the three
    /// listings always agree.
    gone: Vec<bool>,
}

enum State {
    /// AUTHORIZATION, with the user name from a previous USER.
    Authorization {
        user: Option<String>,
    },
    Transaction(Maildrop),
}

struct Session {
    backend: Arc<dyn ImapBackend>,
    limits: Pop3Limits,
    state: State,
    failed_logins: u32,
}

enum Flow {
    Continue,
    Close,
}

/// Serve one POP3 session over `stream` until QUIT, the inactivity
/// timeout, too many failed logins, or the end of the stream.
pub async fn run_pop3_session<S>(
    stream: S,
    backend: Arc<dyn ImapBackend>,
    limits: Pop3Limits,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (reader, writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);
    let mut writer = BufWriter::new(StallGuard::new(writer, limits.write_timeout));
    let pre_auth_deadline = Instant::now() + limits.pre_auth_timeout;
    let mut session = Session {
        backend,
        limits,
        state: State::Authorization { user: None },
        failed_logins: 0,
    };
    write_line(&mut writer, GREETING).await?;
    loop {
        let deadline = match session.state {
            State::Transaction(_) => Instant::now() + session.limits.idle_timeout,
            State::Authorization { .. } => pre_auth_deadline,
        };
        let line = match timeout_at(deadline, read_line(&mut reader)).await {
            Err(_) => {
                write_line(&mut writer, "-ERR autologout; idle for too long").await?;
                break;
            }
            Ok(Err(error)) => return Err(error),
            Ok(Ok(None)) => break,
            Ok(Ok(Some(Line::TooLong))) => {
                write_line(&mut writer, "-ERR line too long").await?;
                continue;
            }
            Ok(Ok(Some(Line::Text(line)))) => line,
        };
        match session.dispatch(&mut writer, &line).await {
            Ok(Flow::Continue) => {}
            Ok(Flow::Close) => break,
            Err(error) if matches!(&error, Error::Network(message) if message == IO_FAILED) => {
                return Err(error)
            }
            Err(error) => {
                let text = match &error {
                    Error::Unsupported(message) => message.clone(),
                    other => other.to_string(),
                };
                write_line(&mut writer, &format!("-ERR {text}")).await?;
            }
        }
    }
    writer.shutdown().await.ok();
    Ok(())
}

enum Line {
    Text(String),
    TooLong,
}

/// Read one CRLF (or LF) terminated line, bounded by [`MAX_LINE`].
/// `None` at the end of the stream.
async fn read_line<R: tokio::io::AsyncBufRead + Unpin>(reader: &mut R) -> Result<Option<Line>> {
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
            if bytes.len() > MAX_LINE {
                too_long = true;
                bytes.clear();
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
    while matches!(bytes.last(), Some(b'\n' | b'\r')) {
        bytes.pop();
    }
    Ok(Some(Line::Text(
        String::from_utf8_lossy(&bytes).into_owned(),
    )))
}

async fn write_line<W: AsyncWrite + Unpin>(writer: &mut W, text: &str) -> Result<()> {
    writer.write_all(text.as_bytes()).await.map_err(io_failed)?;
    writer.write_all(b"\r\n").await.map_err(io_failed)?;
    writer.flush().await.map_err(io_failed)
}

/// Write the first `count` lines of a message as a multi-line response,
/// line by line through the (buffered) writer: every line starting with
/// `.` is byte-stuffed, bare LFs become CRLF, and the response ends with
/// the `.` terminator (RFC 1939 §3). No byte-stuffed copy of the message
/// is ever built.
async fn write_multiline<W: AsyncWrite + Unpin>(writer: &mut W, lines: &[&[u8]]) -> Result<()> {
    for line in lines {
        if line.first() == Some(&b'.') {
            writer.write_all(b".").await.map_err(io_failed)?;
        }
        writer.write_all(line).await.map_err(io_failed)?;
        writer.write_all(b"\r\n").await.map_err(io_failed)?;
    }
    writer.write_all(b".\r\n").await.map_err(io_failed)?;
    writer.flush().await.map_err(io_failed)
}

/// The lines of `body` without their terminators. A final line without
/// a terminator still counts; a trailing terminator adds no empty line.
fn split_lines(body: &[u8]) -> Vec<&[u8]> {
    let mut lines = Vec::new();
    let mut start = 0;
    for (index, byte) in body.iter().enumerate() {
        if *byte == b'\n' {
            let mut end = index;
            if end > start && body[end - 1] == b'\r' {
                end -= 1;
            }
            lines.push(&body[start..end]);
            start = index + 1;
        }
    }
    if start < body.len() {
        lines.push(&body[start..]);
    }
    lines
}

/// How many lines the TOP answer keeps: the header, the blank
/// separator, and `count` body lines. A message without a blank
/// separator is all header.
fn top_line_count(lines: &[&[u8]], count: usize) -> usize {
    match lines.iter().position(|line| line.is_empty()) {
        Some(at) => (at + 1 + count).min(lines.len()),
        None => lines.len(),
    }
}

/// The unique-id listing of one message: stable as long as the UID and
/// the mailbox's UIDVALIDITY are (RFC 1939 §7 allows 1–70 characters
/// in 0x21–0x7E).
fn unique_id(uidvalidity: u32, uid: u32) -> String {
    format!("{uidvalidity}.{uid}")
}

/// Parse a message number argument.
fn message_number(arg: Option<&str>) -> Option<usize> {
    arg?.parse::<usize>().ok().filter(|n| *n > 0)
}

impl Session {
    async fn dispatch<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        line: &str,
    ) -> Result<Flow> {
        let mut parts = line.splitn(2, ' ');
        let verb = parts.next().unwrap_or("").to_ascii_uppercase();
        let rest = parts.next().unwrap_or("");
        tracing::debug!(command = log_command(&verb), "pop3 command");

        // Every transaction command first checks the maildrop against the
        // store: a resync (new UIDVALIDITY, UIDs restarting at 1) would
        // otherwise hand out a different message under the same number
        // and unique id.
        if matches!(self.state, State::Transaction(_))
            && matches!(
                verb.as_str(),
                "STAT" | "LIST" | "UIDL" | "RETR" | "TOP" | "NOOP"
            )
            && !self.revalidate().await?
        {
            write_line(writer, "-ERR [SYS/TEMP] mailbox was resynced; reconnect").await?;
            return Ok(Flow::Close);
        }

        match (&self.state, verb.as_str()) {
            (_, "CAPA") => {
                write_line(writer, "+OK capability list follows").await?;
                for capability in [
                    "USER",
                    "UIDL",
                    "TOP",
                    "RESP-CODES",
                    "EXPIRE NEVER",
                    "IMPLEMENTATION tuta-bridge",
                ] {
                    write_line(writer, capability).await?;
                }
                write_line(writer, ".").await?;
            }
            (_, "QUIT") => {
                write_line(writer, "+OK tuta-bridge signing off").await?;
                return Ok(Flow::Close);
            }
            (_, "NOOP") if matches!(self.state, State::Transaction(_)) => {
                write_line(writer, "+OK").await?;
            }
            (State::Authorization { .. }, "USER") => {
                if rest.is_empty() {
                    write_line(writer, "-ERR missing user name").await?;
                } else {
                    self.state = State::Authorization {
                        user: Some(rest.to_string()),
                    };
                    write_line(writer, "+OK send PASS").await?;
                }
            }
            (State::Authorization { user }, "PASS") => {
                let Some(user) = user.clone() else {
                    write_line(writer, "-ERR send USER first").await?;
                    return Ok(Flow::Continue);
                };
                return self.handle_pass(writer, &user, rest).await;
            }
            (State::Transaction(_), "STAT") => {
                let (count, total) = self.totals().await?;
                write_line(writer, &format!("+OK {count} {total}")).await?;
            }
            (State::Transaction(_), "LIST") => self.handle_list(writer, rest).await?,
            (State::Transaction(_), "UIDL") => self.handle_uidl(writer, rest).await?,
            (State::Transaction(_), "RETR") => {
                let Some(number) = message_number(Some(rest.trim())) else {
                    write_line(writer, "-ERR invalid message number").await?;
                    return Ok(Flow::Continue);
                };
                self.handle_retr(writer, number, None).await?;
            }
            (State::Transaction(_), "TOP") => {
                let mut args = rest.split_whitespace();
                let number = message_number(args.next());
                let lines = args.next().and_then(|count| count.parse::<usize>().ok());
                match (number, lines, args.next()) {
                    (Some(number), Some(lines), None) => {
                        self.handle_retr(writer, number, Some(lines)).await?
                    }
                    _ => write_line(writer, "-ERR invalid TOP").await?,
                }
            }
            (State::Transaction(_), "DELE") => {
                write_line(
                    writer,
                    "-ERR DELE is not supported; mail stays on the server",
                )
                .await?;
            }
            (State::Transaction(_), "RSET") => {
                write_line(writer, "+OK").await?;
            }
            _ => {
                write_line(writer, "-ERR unknown command or wrong state").await?;
            }
        }
        Ok(Flow::Continue)
    }

    async fn handle_pass<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        user: &str,
        password: &str,
    ) -> Result<Flow> {
        let password = SecretString::new(password.to_string().into_boxed_str());
        if self.backend.login(user, &password).await? {
            let Some(inbox) = self.backend.select("INBOX").await? else {
                write_line(writer, "-ERR [SYS/TEMP] no inbox yet; run sync first").await?;
                return Ok(Flow::Close);
            };
            let uids: Vec<u32> = inbox.messages.iter().map(|(uid, _)| *uid).collect();
            let count = uids.len();
            self.state = State::Transaction(Maildrop {
                mailbox: inbox.view.id,
                uidvalidity: inbox.uidvalidity,
                sizes: vec![None; count],
                gone: vec![false; count],
                uids,
            });
            write_line(writer, &format!("+OK maildrop has {count} messages")).await?;
            return Ok(Flow::Continue);
        }

        self.failed_logins += 1;
        tracing::warn!(attempt = self.failed_logins, "pop3 login failed");
        {
            let _gate = self.limits.login_gate.lock().await;
            sleep(self.limits.login_failure_delay).await;
        }
        self.state = State::Authorization { user: None };
        write_line(writer, "-ERR [AUTH] authentication failed").await?;
        if self.failed_logins >= self.limits.max_login_attempts {
            return Ok(Flow::Close);
        }
        Ok(Flow::Continue)
    }

    /// Compare the maildrop with the store: `false` when the Inbox is
    /// gone or its UIDVALIDITY changed; otherwise every message the
    /// store no longer has is marked gone.
    async fn revalidate(&mut self) -> Result<bool> {
        let Some(mailbox) = self.maildrop().map(|drop| drop.mailbox) else {
            return Ok(true);
        };
        let Some(current) = self.backend.snapshot(mailbox).await? else {
            return Ok(false);
        };
        let State::Transaction(drop) = &mut self.state else {
            return Ok(true);
        };
        if current.uidvalidity != drop.uidvalidity {
            return Ok(false);
        }
        let present: std::collections::HashSet<u32> =
            current.messages.iter().map(|(uid, _)| *uid).collect();
        for (index, uid) in drop.uids.iter().enumerate() {
            if !present.contains(uid) {
                drop.gone[index] = true;
            }
        }
        Ok(true)
    }

    fn maildrop(&self) -> Option<&Maildrop> {
        match &self.state {
            State::Transaction(maildrop) => Some(maildrop),
            State::Authorization { .. } => None,
        }
    }

    /// The size of message `number` (1-based), loaded once. `None` when
    /// the message is gone from the store since login, or its size
    /// cannot be loaded: one such message is then left out of every
    /// listing (and marked gone), never failing the whole command. A
    /// refusal of the request itself (`Unsupported`) stays an error.
    async fn size_of(&mut self, number: usize) -> Result<Option<u64>> {
        let (mailbox, uid, cached) = match &self.state {
            State::Transaction(drop) => match drop.uids.get(number - 1) {
                Some(_) if drop.gone[number - 1] => return Ok(None),
                Some(uid) => (drop.mailbox, *uid, drop.sizes[number - 1]),
                None => return Ok(None),
            },
            State::Authorization { .. } => return Ok(None),
        };
        if cached.is_some() {
            return Ok(cached);
        }
        let size = match self
            .backend
            .fetch(mailbox, uid, &[FetchItem::Rfc822Size])
            .await
        {
            Ok(response) => response.and_then(|response| response.rfc822_size),
            Err(error @ Error::Unsupported(_)) => return Err(error),
            Err(_) => None,
        };
        if let State::Transaction(drop) = &mut self.state {
            drop.sizes[number - 1] = size;
            if size.is_none() {
                drop.gone[number - 1] = true;
            }
        }
        Ok(size)
    }

    /// Message count and total octets of the messages still present.
    async fn totals(&mut self) -> Result<(usize, u64)> {
        let count = self.maildrop().map_or(0, |drop| drop.uids.len());
        let (mut present, mut total) = (0, 0);
        for number in 1..=count {
            if let Some(size) = self.size_of(number).await? {
                present += 1;
                total += size;
            }
        }
        Ok((present, total))
    }

    async fn handle_list<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        rest: &str,
    ) -> Result<()> {
        let count = self.maildrop().map_or(0, |drop| drop.uids.len());
        if !rest.trim().is_empty() {
            let Some(number) = message_number(Some(rest.trim())).filter(|n| *n <= count) else {
                write_line(writer, "-ERR no such message").await?;
                return Ok(());
            };
            match self.size_of(number).await? {
                Some(size) => write_line(writer, &format!("+OK {number} {size}")).await?,
                None => write_line(writer, "-ERR no such message").await?,
            }
            return Ok(());
        }
        let mut lines = Vec::with_capacity(count);
        for number in 1..=count {
            if let Some(size) = self.size_of(number).await? {
                lines.push(format!("{number} {size}"));
            }
        }
        write_line(writer, &format!("+OK {} messages", lines.len())).await?;
        for line in lines {
            write_line(writer, &line).await?;
        }
        write_line(writer, ".").await
    }

    async fn handle_uidl<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        rest: &str,
    ) -> Result<()> {
        let Some(drop) = self.maildrop() else {
            return Ok(());
        };
        // Same membership as LIST/STAT: messages gone since login are
        // left out.
        let listing: Vec<(usize, String)> = drop
            .uids
            .iter()
            .enumerate()
            .filter(|(index, _)| !drop.gone[*index])
            .map(|(index, uid)| (index + 1, unique_id(drop.uidvalidity, *uid)))
            .collect();
        if !rest.trim().is_empty() {
            let wanted = message_number(Some(rest.trim()));
            match listing.iter().find(|(number, _)| Some(*number) == wanted) {
                Some((number, id)) => write_line(writer, &format!("+OK {number} {id}")).await?,
                None => write_line(writer, "-ERR no such message").await?,
            }
            return Ok(());
        }
        write_line(writer, "+OK unique-id listing follows").await?;
        for (number, id) in listing {
            write_line(writer, &format!("{number} {id}")).await?;
        }
        write_line(writer, ".").await
    }

    /// RETR (`top == None`) or TOP: render the message and send it.
    async fn handle_retr<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        number: usize,
        top: Option<usize>,
    ) -> Result<()> {
        let Some((mailbox, uid)) = self
            .maildrop()
            .and_then(|drop| drop.uids.get(number - 1).map(|uid| (drop.mailbox, *uid)))
        else {
            write_line(writer, "-ERR no such message").await?;
            return Ok(());
        };
        let Some(mut response) = self
            .backend
            .fetch(mailbox, uid, &[FetchItem::Rfc822])
            .await?
        else {
            write_line(writer, "-ERR message is no longer available").await?;
            return Ok(());
        };
        let body = response.bodies.pop().unwrap_or_default();
        let lines = split_lines(&body);
        let (keep, label) = match top {
            Some(count) => (
                top_line_count(&lines, count),
                "top of message follows".to_string(),
            ),
            None => {
                let size = body.len();
                if let State::Transaction(drop) = &mut self.state {
                    drop.sizes[number - 1].get_or_insert(size as u64);
                }
                (lines.len(), format!("{size} octets"))
            }
        };
        write_line(writer, &format!("+OK {label}")).await?;
        write_multiline(writer, &lines[..keep]).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_split_on_lf_and_crlf_without_a_trailing_empty_line() {
        assert_eq!(
            split_lines(b"a\r\nb\nc"),
            vec![&b"a"[..], &b"b"[..], &b"c"[..]]
        );
        assert_eq!(split_lines(b"a\r\n\r\n"), vec![&b"a"[..], &b""[..]]);
        assert!(split_lines(b"").is_empty());
    }

    #[test]
    fn top_keeps_the_header_the_separator_and_n_body_lines() {
        let message = b"Subject: x\r\nFrom: y\r\n\r\none\r\ntwo\r\nthree\r\n";
        let lines = split_lines(message);
        assert_eq!(top_line_count(&lines, 0), 3);
        assert_eq!(top_line_count(&lines, 2), 5);
        assert_eq!(top_line_count(&lines, 99), 6);
        let headers_only = split_lines(b"Subject: x\r\nFrom: y\r\n");
        assert_eq!(top_line_count(&headers_only, 5), 2);
    }

    #[test]
    fn unique_ids_are_printable_and_stable() {
        let id = unique_id(7, 42);
        assert_eq!(id, "7.42");
        assert!(id.bytes().all(|byte| (0x21..=0x7e).contains(&byte)));
    }

    #[test]
    fn logged_commands_are_fixed_names() {
        assert_eq!(log_command("RETR"), "RETR");
        assert_eq!(log_command("secret-password"), "<unknown>");
    }
}
