//! The per-connection IMAP4rev1 session.
//!
//! [`run_session`] owns one stream: it reads line-terminated commands
//! (assembling client literals along the way), dispatches against the
//! [`ImapBackend`] seam, and writes responses with CRLF line endings.
//! The state machine is `NotAuthenticated` → LOGIN → `Authenticated` →
//! SELECT/EXAMINE → `Selected`; CAPABILITY, NOOP, ID, and LOGOUT are
//! valid everywhere, commands outside their state answer BAD, and IDLE
//! is a `Selected`-state command.
//!
//! Two disciplines shape the flow:
//!
//! * **Snapshot validity** (the Proton Bridge lesson): a `Selected`
//!   session holds its own view of the mailbox — the mailbox id, its
//!   UIDVALIDITY, and the `(uid, unread)` list whose positions are the
//!   message sequence numbers the client knows. Before every command
//!   that could act on it the session compares the UIDVALIDITY with the
//!   store's and, on a mismatch or a vanished mailbox, sends one fixed
//!   untagged BYE and closes — the client must reconnect. FETCH and
//!   SEARCH resolve numbers against the session's view, never the live
//!   store, so a number always names the message the client means.
//!
//! * **Announced changes**: the view moves only where RFC 3501 lets a
//!   server announce it — NOOP, CHECK, and IDLE, never during FETCH,
//!   STORE, or SEARCH (§7.4.1). There the session compares its view
//!   with the store and sends `* <n> EXPUNGE` for every message that
//!   left (highest number first), `* <n> EXISTS` when any arrived, and
//!   `* <n> FETCH (FLAGS (...))` for every read-state change. IDLE
//!   (RFC 2177) pushes the same comparison live: it answers `+ idling`,
//!   compares at once so nothing is lost at the boundary, and waits on
//!   the command reader and the mailbox-change broadcast together —
//!   `DONE` ends it with the tagged OK, LOGOUT behaves as always, and
//!   any other command answers BAD and returns to normal dispatch. A
//!   lagged receiver treats "everything may have changed" literally.
//!
//! * **Log hygiene**: the session logs with `tracing::debug!` only, with
//!   tag, command, and count fields — the tag only after the same
//!   printable-ASCII validation a BAD response applies, so raw client
//!   bytes never reach a log line. Mailbox names, subjects, bodies,
//!   credentials, and argument vectors never reach a log line, and no
//!   `Debug` printing exists for the types that carry them.

use std::sync::Arc;

use secrecy::SecretString;
use tokio::io::{
    split, AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt,
    BufReader, BufWriter,
};
use tokio::sync::broadcast;

use super::codec::{self, BodySection, FetchItem, ImapArg, Request};
use super::render;
use super::search;
use crate::domain::MailboxId;
use crate::domain::{Error, Result};
use crate::ports::imap_backend::{FetchResponse, ImapBackend};
use crate::ports::mailbox_events::MailboxChanged;

/// The capability set the greeting, the CAPABILITY responses, and the
/// LOGIN OK carry: the RFC 3501 base plus the extensions this bridge
/// speaks. LOGINDISABLED never appears — the listener is TLS-only, so
/// LOGIN is always available.
const CAPABILITIES: &str = "IMAP4rev1 IDLE ID";

/// A fixed io error: connection failures carry no client data.
fn io_failed(_: std::io::Error) -> Error {
    Error::Network("imap connection io failed".into())
}

/// Bodies are written through the response writer in chunks of this
/// size, so one rendered message never sits in the writer's buffer
/// whole (the backend already holds at most one in memory).
const BODY_CHUNK: usize = 64 * 1024;

/// A client literal announcement beyond this bound is refused without a
/// continuation and the session ends: `pending_literal` parses `usize`,
/// so the guard exists to bound the allocation, not the parse.
const MAX_LITERAL_BYTES: usize = 16 * 1024 * 1024;

/// A command line beyond this bound is refused, and the read is
/// bounded with it: lines are scanned window by window and discarded
/// once they cross the cap, so a runaway line never sits in memory
/// whole. Message bodies arrive through literals, never through a
/// line.
const MAX_LINE_BYTES: usize = 64 * 1024;

/// The untagged BYE a stale snapshot sends before closing.
const RESYNC_BYE: &str = "* BYE mailbox state was resynced; reconnect";

// ---------------------------------------------------------------------------
// Session state
// ---------------------------------------------------------------------------

/// Where one connection is in the command state machine.
enum State {
    NotAuthenticated,
    Authenticated,
    Selected {
        /// The mailbox, addressed by id from here on: its name is
        /// never resolved again.
        mailbox: MailboxId,
        /// Opened with EXAMINE rather than SELECT. Every write is
        /// refused today whichever it was; the flag is recorded so a
        /// write-capable server can refuse them on an EXAMINEd mailbox.
        #[allow(dead_code)]
        read_only: bool,
        uidvalidity: u32,
        /// The session's view: `(uid, unread)` in ascending UID order.
        /// Position + 1 is the message sequence number the client
        /// knows; it changes only at the announced sync points.
        messages: Vec<(u32, bool)>,
    },
}

impl State {
    fn authenticated(&self) -> bool {
        matches!(self, State::Authenticated | State::Selected { .. })
    }

    fn selected(&self) -> bool {
        matches!(self, State::Selected { .. })
    }
}

/// What the dispatch loop does after one command.
enum Flow {
    Continue,
    Close,
}

struct Session {
    state: State,
    backend: Arc<dyn ImapBackend>,
    watch: broadcast::Receiver<MailboxChanged>,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Serve one IMAP session over `stream` until the client logs out, the
/// snapshot goes stale, or the stream ends.
pub async fn run_session<S>(
    stream: S,
    backend: Arc<dyn ImapBackend>,
    watch: broadcast::Receiver<MailboxChanged>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (reader, writer) = split(stream);
    let mut reader = BufReader::new(reader);
    let mut writer = BufWriter::new(writer);
    let mut session = Session {
        state: State::NotAuthenticated,
        backend,
        watch,
    };

    write_line(&mut writer, &greeting()).await?;
    writer.flush().await.map_err(io_failed)?;

    loop {
        match read_request(&mut reader, &mut writer).await? {
            Incoming::Eof => break,
            Incoming::Invalid(tag) => {
                write_line(&mut writer, &format!("{tag} BAD invalid command")).await?;
            }
            Incoming::LiteralTooLarge(tag) => {
                write_line(&mut writer, &format!("{tag} NO literal too large")).await?;
                break;
            }
            Incoming::Request(request) => {
                let flow = session.dispatch(&mut reader, &mut writer, request).await?;
                if matches!(flow, Flow::Close) {
                    break;
                }
            }
        }
        writer.flush().await.map_err(io_failed)?;
    }
    writer.flush().await.map_err(io_failed)?;
    // Close the TLS layer properly: on a TLS stream this sends the
    // close_notify before the socket closes; on a plain duplex it is a
    // no-op that still signals EOF.
    writer.shutdown().await.map_err(io_failed)?;
    Ok(())
}

fn greeting() -> String {
    format!("* OK [CAPABILITY {CAPABILITIES}] tuta-bridge ready")
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

/// What one read cycle produced.
enum Incoming {
    Request(Request),
    /// The line did not parse; the tag (or `*`) to answer BAD with.
    Invalid(String),
    /// A literal announcement exceeded the bound; refuse and close.
    LiteralTooLarge(String),
    Eof,
}

/// Read one full command: its first line, and for every announced
/// literal the continuation `+ `, the exact byte count, and the line
/// that follows. The whole command is tokenized once it is complete.
///
/// A line beyond [`MAX_LINE_BYTES`] is refused exactly as it always
/// was, but never buffered whole: the bounded read scans the stream
/// window by window and discards a line once it crosses the cap. A
/// literal that never arrives is an EOF: the client is gone. A line
/// that can never be part of a valid command answers BAD before any
/// continuation is sent, with the command's own tag.
async fn read_request<R, W>(reader: &mut R, writer: &mut W) -> Result<Incoming>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut bytes = Vec::new();
    let mut lines: Vec<String> = Vec::new();
    let mut literals: Vec<Vec<u8>> = Vec::new();
    loop {
        let line = match read_line(reader, &mut bytes).await? {
            Some(LineRead::Line(line)) => line,
            // An over-cap line: the fixed refusal, with the connection
            // left at the start of the next line.
            Some(LineRead::TooLong) => return Ok(Incoming::Invalid(command_tag(&lines))),
            None => return Ok(Incoming::Eof),
        };
        let pending = codec::pending_literal(&line);
        lines.push(line);
        let count = match pending {
            Ok(Some(count)) => count,
            Ok(None) => break,
            Err(_) => return Ok(Incoming::Invalid(command_tag(&lines))),
        };

        // A client literal: answer the continuation and read the
        // announced bytes exactly; the rest of the command follows on
        // the next line, which may announce another literal.
        if count > MAX_LITERAL_BYTES {
            return Ok(Incoming::LiteralTooLarge(command_tag(&lines)));
        }
        write_line(writer, "+ ").await?;
        writer.flush().await.map_err(io_failed)?;

        let mut data = vec![0u8; count];
        if reader.read_exact(&mut data).await.is_err() {
            return Ok(Incoming::Eof);
        }
        literals.push(data);
    }
    match codec::parse_command(&lines, literals) {
        Ok(request) => Ok(Incoming::Request(request)),
        Err(_) => Ok(Incoming::Invalid(command_tag(&lines))),
    }
}

/// The tag a refused command is answered with: the first token of its
/// first line when that is safe to echo, `*` otherwise.
fn command_tag(lines: &[String]) -> String {
    lines
        .first()
        .map_or_else(|| "*".to_string(), |line| bad_tag(line))
}

/// What one bounded line read produced.
enum LineRead {
    /// A line within the cap: CRLF stripped, invalid UTF-8 degraded
    /// to replacement characters the parser rejects with its fixed
    /// error.
    Line(String),
    /// The line crossed the cap with no newline: its remainder is
    /// discarded so the connection resumes at the next line, and the
    /// caller answers the same BAD as before.
    TooLong,
}

/// How one scan window moved the read along.
enum Scan {
    /// The newline arrived inside the window.
    Done,
    /// No newline; the window joined the line within the cap.
    More,
    /// The cap was crossed and the newline with it: the line is fully
    /// consumed, nothing more to discard.
    OverLine,
    /// The cap was crossed before any newline: the rest of the line
    /// still has to be discarded.
    OverRest,
}

/// Read one CRLF-terminated line without ever buffering a line beyond
/// [`MAX_LINE_BYTES`]: each pass inspects the reader's buffered window,
/// copies it into `bytes` only while the running total stays within
/// the cap, and consumes what it has already accounted for.
///
/// `bytes` is the caller's buffer: whatever a partially-completed read
/// consumed stays in it, so a read that is abandoned mid-line (the IDLE
/// select drops one) resumes where it stopped instead of losing stream
/// bytes. On a completed line the buffer is emptied for the next read.
async fn read_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    bytes: &mut Vec<u8>,
) -> Result<Option<LineRead>> {
    loop {
        let window = match reader.fill_buf().await {
            Ok(window) => window,
            Err(error) => return Err(io_failed(error)),
        };
        if window.is_empty() {
            // EOF: nothing more will arrive. An empty buffer with an
            // empty line means the client is gone; a partial line
            // within the cap behaves as it always has — it is the
            // line the client sent before vanishing.
            if bytes.is_empty() {
                return Ok(None);
            }
            return Ok(Some(LineRead::Line(partial_line(bytes))));
        }
        // The newline search and the cap check run on the borrowed
        // window; the copy and the consume follow the decision, so
        // the borrow ends before the reader advances.
        let (scan, consumed) = match window.iter().position(|&b| b == b'\n') {
            Some(at) => {
                // The trailing `\r` of a CRLF terminator never counts
                // against the cap: the finished line strips it, as
                // the unbounded read always did.
                let cr = if at == 0 {
                    bytes.last() == Some(&b'\r')
                } else {
                    window[at - 1] == b'\r'
                };
                if bytes.len() + at - usize::from(cr) > MAX_LINE_BYTES {
                    (Scan::OverLine, at + 1)
                } else {
                    bytes.extend_from_slice(&window[..at + 1]);
                    (Scan::Done, at + 1)
                }
            }
            None => {
                let len = window.len();
                if bytes.len() + len > MAX_LINE_BYTES {
                    (Scan::OverRest, len)
                } else {
                    bytes.extend_from_slice(window);
                    (Scan::More, len)
                }
            }
        };
        reader.consume(consumed);
        match scan {
            Scan::Done => return Ok(Some(LineRead::Line(completed_line(bytes)))),
            Scan::More => {}
            Scan::OverLine => return Ok(Some(LineRead::TooLong)),
            Scan::OverRest => {
                discard_rest_of_line(reader).await?;
                return Ok(Some(LineRead::TooLong));
            }
        }
    }
}

/// The accumulated bytes as a completed line: strip the CRLF
/// terminator the newline brought, then hand the rest to
/// [`partial_line`].
fn completed_line(bytes: &mut Vec<u8>) -> String {
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    if bytes.last() == Some(&b'\r') {
        bytes.pop();
    }
    partial_line(bytes)
}

/// The accumulated bytes as a partial line at EOF: no terminator to
/// strip — the same bytes the unbounded read handed up — with
/// invalid UTF-8 degraded to replacement characters the parser
/// rejects with its fixed error. The buffer empties for the next
/// read.
fn partial_line(bytes: &mut Vec<u8>) -> String {
    let line = String::from_utf8_lossy(bytes).into_owned();
    bytes.clear();
    line
}

/// Discard the remainder of a line that already crossed the cap,
/// window by window, until its newline or the end of the stream: the
/// bytes are consumed, never stored.
async fn discard_rest_of_line<R: AsyncBufRead + Unpin>(reader: &mut R) -> Result<()> {
    loop {
        let (newline, consumed) = {
            let window = match reader.fill_buf().await {
                Ok(window) => window,
                Err(error) => return Err(io_failed(error)),
            };
            match window.iter().position(|&b| b == b'\n') {
                Some(at) => (true, at + 1),
                None => (false, window.len()),
            }
        };
        if consumed == 0 {
            // EOF mid-line: the caller answers BAD and the next read
            // observes the EOF, exactly as before.
            return Ok(());
        }
        reader.consume(consumed);
        if newline {
            return Ok(());
        }
    }
}

/// Whether a token may serve as a tag: printable ASCII without the
/// response-code brackets or the literal-opening brace. Control
/// characters must never enter a response line, and neither may a
/// garbage `{5}` token — the client could misread its echo as a
/// continuation announcement.
fn tag_is_safe(token: &str) -> bool {
    !token.is_empty()
        && token.bytes().all(|b| (0x21..=0x7e).contains(&b))
        && !token.contains(['[', ']', '{'])
}

/// The tag to answer a BAD with when the line did not parse: the first
/// token when it is safe, `*` otherwise.
fn bad_tag(line: &str) -> String {
    let token = line.split_whitespace().next().unwrap_or("*");
    if tag_is_safe(token) {
        token.to_string()
    } else {
        "*".to_string()
    }
}

/// The placeholder logged for a tag that fails the same validation a
/// BAD response applies: log lines carry fixed strings, never raw
/// client bytes.
const INVALID_LOG_TAG: &str = "<invalid>";

/// The tag as it may appear in a log line: itself when it passes
/// [`tag_is_safe`], a fixed placeholder otherwise. The wire never
/// changes — this is the log field only.
fn log_tag(tag: &str) -> &str {
    if tag_is_safe(tag) {
        tag
    } else {
        INVALID_LOG_TAG
    }
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

/// Write one response line (CRLF included). Lines that embed literal
/// framing carry their own `\r\n` inside `text`; this adds the final
/// terminator only.
async fn write_line<W: AsyncWrite + Unpin>(writer: &mut W, text: &str) -> Result<()> {
    writer.write_all(text.as_bytes()).await.map_err(io_failed)?;
    writer.write_all(b"\r\n").await.map_err(io_failed)?;
    Ok(())
}

/// The fixed LOGOUT response: one untagged BYE, the tagged OK, and the
/// end of the session. Shared by the normal dispatch and by LOGOUT
/// arriving during IDLE, which behaves exactly as it always does.
async fn respond_logout<W: AsyncWrite + Unpin>(writer: &mut W, tag: &str) -> Result<()> {
    write_line(writer, "* BYE tuta-bridge signing off").await?;
    write_line(writer, &format!("{tag} OK LOGOUT completed")).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

impl Session {
    /// Dispatch one command, catching backend errors into a tagged NO
    /// with the error's fixed text.
    async fn dispatch<R, W>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        request: Request,
    ) -> Result<Flow>
    where
        R: AsyncBufRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let Request { tag, command, args } = request;
        let command = command.to_ascii_uppercase();
        // The logged tag passes the same printable-ASCII gate a BAD
        // response applies; a tag that fails it logs a fixed
        // placeholder, so raw client bytes never reach a log line.
        tracing::debug!(tag = %log_tag(&tag), command = %command, "imap command");

        // Snapshot validity: a Selected session never acts on a stale
        // view. SELECT/EXAMINE replace it, CLOSE drops it, LOGOUT ends
        // the connection — every other command is validated first.
        if self.state.selected()
            && !matches!(command.as_str(), "SELECT" | "EXAMINE" | "CLOSE" | "LOGOUT")
            && !self.snapshot_is_current().await?
        {
            write_line(writer, RESYNC_BYE).await?;
            return Ok(Flow::Close);
        }

        let verb = normalize(&command, &args);
        // IDLE is served here rather than in dispatch_command because
        // its DONE loop reads from the connection.
        if verb == "IDLE" {
            if self.state.selected() {
                return self.handle_idle(reader, writer, &tag).await;
            }
            write_line(
                writer,
                &format!("{tag} BAD command not valid in this state"),
            )
            .await?;
            return Ok(Flow::Continue);
        }
        let flow = self.dispatch_command(writer, &tag, &verb, &args).await;
        match flow {
            Ok(flow) => Ok(flow),
            Err(error) => {
                let text = match &error {
                    Error::Unsupported(message) => message.clone(),
                    other => other.to_string(),
                };
                write_line(writer, &format!("{tag} NO {text}")).await?;
                Ok(Flow::Continue)
            }
        }
    }

    async fn dispatch_command<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        tag: &str,
        verb: &str,
        args: &[ImapArg],
    ) -> Result<Flow> {
        match verb {
            "CAPABILITY" => {
                write_line(writer, &format!("* CAPABILITY {CAPABILITIES}")).await?;
                write_line(writer, &format!("{tag} OK CAPABILITY completed")).await?;
            }
            "NOOP" => {
                if matches!(self.announce_changes(writer).await?, Flow::Close) {
                    return Ok(Flow::Close);
                }
                write_line(writer, &format!("{tag} OK NOOP completed")).await?;
            }
            "ID" => {
                // RFC 2971: answer with the server's identity and do not
                // interpret the client payload.
                write_line(writer, "* ID (\"name\" \"tuta-bridge\")").await?;
                write_line(writer, &format!("{tag} OK ID completed")).await?;
            }
            "LOGOUT" => {
                respond_logout(writer, tag).await?;
                return Ok(Flow::Close);
            }
            "LOGIN" => {
                if matches!(self.state, State::NotAuthenticated) {
                    self.handle_login(writer, tag, args).await?;
                } else {
                    write_line(
                        writer,
                        &format!("{tag} BAD command not valid in this state"),
                    )
                    .await?;
                }
            }
            "SELECT" => {
                self.handle_select(writer, tag, args, false).await?;
            }
            "EXAMINE" => {
                self.handle_select(writer, tag, args, true).await?;
            }
            "LIST" | "LSUB" => {
                if self.state.authenticated() {
                    self.handle_list(writer, tag, verb == "LSUB", args).await?;
                } else {
                    write_line(
                        writer,
                        &format!("{tag} BAD command not valid in this state"),
                    )
                    .await?;
                }
            }
            "STATUS" => {
                if self.state.authenticated() {
                    self.handle_status(writer, tag, args).await?;
                } else {
                    write_line(
                        writer,
                        &format!("{tag} BAD command not valid in this state"),
                    )
                    .await?;
                }
            }
            "FETCH" => {
                if self.state.selected() {
                    self.handle_fetch(writer, tag, false, args).await?;
                } else {
                    write_line(
                        writer,
                        &format!("{tag} BAD command not valid in this state"),
                    )
                    .await?;
                }
            }
            "UID FETCH" => {
                if self.state.selected() {
                    self.handle_fetch(writer, tag, true, &args[1.min(args.len())..])
                        .await?;
                } else {
                    write_line(
                        writer,
                        &format!("{tag} BAD command not valid in this state"),
                    )
                    .await?;
                }
            }
            "SEARCH" => {
                if self.state.selected() {
                    self.handle_search(writer, tag, false, args).await?;
                } else {
                    write_line(
                        writer,
                        &format!("{tag} BAD command not valid in this state"),
                    )
                    .await?;
                }
            }
            "UID SEARCH" => {
                if self.state.selected() {
                    self.handle_search(writer, tag, true, &args[1.min(args.len())..])
                        .await?;
                } else {
                    write_line(
                        writer,
                        &format!("{tag} BAD command not valid in this state"),
                    )
                    .await?;
                }
            }
            "CHECK" => {
                if self.state.selected() {
                    if matches!(self.announce_changes(writer).await?, Flow::Close) {
                        return Ok(Flow::Close);
                    }
                    write_line(writer, &format!("{tag} OK CHECK completed")).await?;
                } else {
                    write_line(
                        writer,
                        &format!("{tag} BAD command not valid in this state"),
                    )
                    .await?;
                }
            }
            "CLOSE" => {
                if self.state.selected() {
                    self.state = State::Authenticated;
                    write_line(writer, &format!("{tag} OK CLOSE completed")).await?;
                } else {
                    write_line(
                        writer,
                        &format!("{tag} BAD command not valid in this state"),
                    )
                    .await?;
                }
            }
            "STORE" | "APPEND" | "EXPUNGE" | "COPY" | "MOVE" | "CREATE" | "DELETE" | "RENAME"
            | "SUBSCRIBE" | "UNSUBSCRIBE" | "UID STORE" | "UID COPY" => {
                // Understood, always refused: the bridge is read-only.
                if self.state.authenticated() {
                    write_line(
                        writer,
                        &format!("{tag} NO not supported by this read-only bridge"),
                    )
                    .await?;
                } else {
                    write_line(
                        writer,
                        &format!("{tag} BAD command not valid in this state"),
                    )
                    .await?;
                }
            }
            _ => {
                write_line(writer, &format!("{tag} BAD unknown command")).await?;
            }
        }
        Ok(Flow::Continue)
    }

    // -- LOGIN -----------------------------------------------------------

    async fn handle_login<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        tag: &str,
        args: &[ImapArg],
    ) -> Result<()> {
        if args.len() != 2 {
            write_line(writer, &format!("{tag} BAD invalid LOGIN")).await?;
            return Ok(());
        }
        let user = arg_string(&args[0]);
        let password = SecretString::new(arg_string(&args[1]).into_boxed_str());
        if self.backend.login(&user, &password).await? {
            self.state = State::Authenticated;
            write_line(
                writer,
                &format!("{tag} OK [CAPABILITY {CAPABILITIES}] LOGIN completed"),
            )
            .await?;
        } else {
            write_line(writer, &format!("{tag} NO authentication failed")).await?;
        }
        Ok(())
    }

    // -- SELECT / EXAMINE -------------------------------------------------

    async fn handle_select<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        tag: &str,
        args: &[ImapArg],
        examine: bool,
    ) -> Result<()> {
        if !self.state.authenticated() {
            write_line(
                writer,
                &format!("{tag} BAD command not valid in this state"),
            )
            .await?;
            return Ok(());
        }
        let Some(name_arg) = args.first() else {
            write_line(
                writer,
                &format!(
                    "{tag} BAD invalid {}",
                    if examine { "EXAMINE" } else { "SELECT" }
                ),
            )
            .await?;
            return Ok(());
        };
        let name = mailbox_name(name_arg);
        let Some(selected) = self.backend.select(&name).await? else {
            write_line(writer, &format!("{tag} NO no such mailbox")).await?;
            return Ok(());
        };

        write_line(writer, "* FLAGS (\\Seen)").await?;
        let (exists, unseen) = (selected.messages.len(), selected.unseen());
        write_line(writer, &format!("* {exists} EXISTS")).await?;
        write_line(writer, "* 0 RECENT").await?;
        if unseen > 0 {
            write_line(writer, &format!("* OK [UNSEEN {unseen}]")).await?;
        }
        write_line(writer, "* OK [PERMANENTFLAGS ()] Read-only mailbox").await?;
        write_line(
            writer,
            &format!("* OK [UIDVALIDITY {}]", selected.uidvalidity),
        )
        .await?;
        write_line(writer, &format!("* OK [UIDNEXT {}]", selected.uidnext)).await?;

        tracing::debug!(exists, unseen, read_only = examine, "mailbox selected");
        // Notifications queued before this view was taken are already
        // part of it.
        self.drain_notifications();
        self.state = State::Selected {
            mailbox: selected.view.id,
            read_only: examine,
            uidvalidity: selected.uidvalidity,
            messages: selected.messages,
        };
        let (code, verb) = if examine {
            ("READ-ONLY", "EXAMINE")
        } else {
            ("READ-WRITE", "SELECT")
        };
        write_line(writer, &format!("{tag} OK [{code}] {verb} completed")).await?;
        Ok(())
    }

    // -- LIST / LSUB -------------------------------------------------------

    async fn handle_list<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        tag: &str,
        lsub: bool,
        args: &[ImapArg],
    ) -> Result<()> {
        if args.len() != 2 {
            let verb = if lsub { "LSUB" } else { "LIST" };
            write_line(writer, &format!("{tag} BAD invalid {verb}")).await?;
            return Ok(());
        }
        let keyword = if lsub { "LSUB" } else { "LIST" };
        let (reference, pattern) = (mailbox_name(&args[0]), mailbox_name(&args[1]));
        if pattern.is_empty() {
            // RFC 3501 §6.3.8: an empty pattern asks for the hierarchy
            // delimiter and the root of the reference, nothing else.
            write_line(writer, &format!("* {keyword} (\\Noselect) \"/\" \"\"")).await?;
            write_line(writer, &format!("{tag} OK {keyword} completed")).await?;
            return Ok(());
        }
        // The reference is a prefix of the names the pattern is
        // matched against.
        let pattern = format!("{reference}{pattern}");
        let views = self.backend.mailboxes().await?;
        for view in &views {
            if !list_matches(&pattern, &view.name) {
                continue;
            }
            write_line(
                writer,
                &format!(
                    "* {keyword} ({}) \"/\" {}",
                    view.special_use,
                    wire_mailbox(&view.name)
                ),
            )
            .await?;
        }
        write_line(writer, &format!("{tag} OK {keyword} completed")).await?;
        Ok(())
    }

    // -- STATUS ---------------------------------------------------------

    async fn handle_status<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        tag: &str,
        args: &[ImapArg],
    ) -> Result<()> {
        let (name_arg, items_arg) = match args {
            [name_arg, items_arg] => (name_arg, items_arg),
            _ => {
                write_line(writer, &format!("{tag} BAD invalid STATUS")).await?;
                return Ok(());
            }
        };
        let items: Option<Vec<String>> = match items_arg {
            ImapArg::List(list) => list
                .iter()
                .map(|item| match item {
                    ImapArg::Atom(item) => Some(item.to_ascii_uppercase()),
                    _ => None,
                })
                .collect(),
            _ => None,
        };
        let Some(items) = items else {
            write_line(writer, &format!("{tag} BAD invalid STATUS")).await?;
            return Ok(());
        };
        for item in &items {
            if !matches!(
                item.as_str(),
                "MESSAGES" | "RECENT" | "UIDNEXT" | "UIDVALIDITY" | "UNSEEN"
            ) {
                write_line(writer, &format!("{tag} BAD invalid status items")).await?;
                return Ok(());
            }
        }
        let name = mailbox_name(name_arg);
        let Some(selected) = self.backend.select(&name).await? else {
            write_line(writer, &format!("{tag} NO no such mailbox")).await?;
            return Ok(());
        };
        let pairs: Vec<String> = items
            .iter()
            .filter_map(|item| {
                let value = match item.as_str() {
                    "MESSAGES" => selected.messages.len().to_string(),
                    "RECENT" => "0".to_string(),
                    "UIDNEXT" => selected.uidnext.to_string(),
                    "UIDVALIDITY" => selected.uidvalidity.to_string(),
                    "UNSEEN" => selected.unseen().to_string(),
                    _ => return None,
                };
                Some(format!("{item} {value}"))
            })
            .collect();
        write_line(
            writer,
            &format!(
                "* STATUS {} ({})",
                wire_mailbox(&selected.view.name),
                pairs.join(" ")
            ),
        )
        .await?;
        write_line(writer, &format!("{tag} OK STATUS completed")).await?;
        Ok(())
    }

    // -- FETCH ------------------------------------------------------------

    async fn handle_fetch<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        tag: &str,
        uid_command: bool,
        args: &[ImapArg],
    ) -> Result<()> {
        let Some(set_arg) = args.first() else {
            write_line(writer, &format!("{tag} BAD invalid FETCH")).await?;
            return Ok(());
        };
        let set = match codec::parse_seq_set(&arg_string(set_arg)) {
            Ok(set) => set,
            Err(_) => {
                write_line(writer, &format!("{tag} BAD invalid sequence set")).await?;
                return Ok(());
            }
        };
        let mut items = match codec::parse_fetch_items(&args[1.min(args.len())..]) {
            Ok(items) => items,
            Err(_) => {
                write_line(writer, &format!("{tag} BAD invalid fetch items")).await?;
                return Ok(());
            }
        };
        // RFC 3501 §6.4.8: a UID command response carries the UID even
        // when the client did not list it.
        if uid_command && !items.contains(&FetchItem::Uid) {
            items.push(FetchItem::Uid);
        }

        // The session's view is the message order the client knows:
        // position + 1 is the message sequence number, and the last
        // uid is the `*` of a UID set.
        let Some((mailbox, uids)) = self.selected_view() else {
            write_line(
                writer,
                &format!("{tag} BAD command not valid in this state"),
            )
            .await?;
            return Ok(());
        };
        let max_uid = uids.last().copied().unwrap_or(0);

        for (index, uid) in uids.iter().enumerate() {
            let msn = u32::try_from(index + 1).unwrap_or(u32::MAX);
            let selected = if uid_command {
                set.contains(*uid, max_uid)
            } else {
                set.contains(msn, u32::try_from(uids.len()).unwrap_or(u32::MAX))
            };
            if !selected {
                continue;
            }
            // A uid the store no longer has answers nothing — its
            // EXPUNGE waits for the next sync point, since none may be
            // sent during a FETCH — and so does a uid whose
            // details cannot be loaded: one poisoned row must not
            // abort the whole `UID FETCH 1:*` — no FETCH line for it,
            // the rest of the loop continues, and the row disappears
            // on the next sync or event. An Unsupported refusal is a
            // verdict about the request itself, not about one row: it
            // fails every uid identically and stays fatal.
            let mut response = match self.backend.fetch(mailbox, *uid, &items).await {
                Ok(Some(response)) => response,
                Ok(None) => continue,
                Err(error @ Error::Unsupported(_)) => return Err(error),
                Err(_) => continue,
            };
            for piece in render_fetch(msn, &mut response, &items) {
                match piece {
                    Piece::Text(text) => {
                        writer.write_all(text.as_bytes()).await.map_err(io_failed)?
                    }
                    Piece::Body(body) => {
                        for chunk in body.chunks(BODY_CHUNK) {
                            writer.write_all(chunk).await.map_err(io_failed)?;
                        }
                    }
                }
            }
        }
        let verb = if uid_command { "UID FETCH" } else { "FETCH" };
        write_line(writer, &format!("{tag} OK {verb} completed")).await?;
        Ok(())
    }

    // -- SEARCH ----------------------------------------------------------

    async fn handle_search<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        tag: &str,
        uid_command: bool,
        args: &[ImapArg],
    ) -> Result<()> {
        if args.is_empty() {
            write_line(writer, &format!("{tag} BAD invalid SEARCH")).await?;
            return Ok(());
        }
        // A refused key or charset is a tagged NO with its fixed text.
        let keys = search::parse_search(args)?;
        let Some((mailbox, uids)) = self.selected_view() else {
            write_line(
                writer,
                &format!("{tag} BAD command not valid in this state"),
            )
            .await?;
            return Ok(());
        };
        // The backend answers uids. Only messages of the session's
        // view are reported — one the client has not been told about
        // has no number yet — and a plain SEARCH reports the positions
        // the uids occupy in that view.
        let matched = self.backend.search(mailbox, &keys, &uids).await?;
        let numbers: Vec<String> = matched
            .iter()
            .filter_map(|uid| uids.binary_search(uid).ok().map(|position| (position, uid)))
            .map(|(position, uid)| {
                if uid_command {
                    uid.to_string()
                } else {
                    (position + 1).to_string()
                }
            })
            .collect();
        let joined = numbers.join(" ");
        if joined.is_empty() {
            write_line(writer, "* SEARCH").await?;
        } else {
            write_line(writer, &format!("* SEARCH {joined}")).await?;
        }
        let verb = if uid_command { "UID SEARCH" } else { "SEARCH" };
        write_line(writer, &format!("{tag} OK {verb} completed")).await?;
        Ok(())
    }

    // -- Snapshot maintenance ----------------------------------------------

    /// The selected mailbox and the uids of the session's view, in
    /// message-number order; `None` outside the `Selected` state.
    fn selected_view(&self) -> Option<(MailboxId, Vec<u32>)> {
        match &self.state {
            State::Selected {
                mailbox, messages, ..
            } => Some((*mailbox, messages.iter().map(|(uid, _)| *uid).collect())),
            _ => None,
        }
    }

    /// Whether the selected snapshot still matches the store: the same
    /// mailbox id at the same UIDVALIDITY. A resynced, renamed, or
    /// deleted mailbox is stale.
    async fn snapshot_is_current(&self) -> Result<bool> {
        let (mailbox, session_uidvalidity) = match &self.state {
            State::Selected {
                mailbox,
                uidvalidity,
                ..
            } => (*mailbox, *uidvalidity),
            _ => return Ok(true),
        };
        Ok(self.backend.uidvalidity(mailbox).await? == Some(session_uidvalidity))
    }

    /// Empty the mailbox-change queue. The session compares its whole
    /// view at every sync point, so the notifications themselves carry
    /// nothing it still needs; draining only keeps the receiver from
    /// lagging.
    fn drain_notifications(&mut self) {
        while !matches!(
            self.watch.try_recv(),
            Err(broadcast::error::TryRecvError::Empty | broadcast::error::TryRecvError::Closed)
        ) {}
    }

    /// One sync point: compare the session's view with the store and
    /// announce every difference. A vanished mailbox or a moved
    /// UIDVALIDITY sends the resync BYE and ends the session; otherwise
    /// the client is told what left, whether anything arrived, and
    /// which read states changed, and the view becomes the store's.
    /// Outside the `Selected` state there is nothing to announce.
    async fn announce_changes<W: AsyncWrite + Unpin>(&mut self, writer: &mut W) -> Result<Flow> {
        let (mailbox, session_uidvalidity) = match &self.state {
            State::Selected {
                mailbox,
                uidvalidity,
                ..
            } => (*mailbox, *uidvalidity),
            _ => return Ok(Flow::Continue),
        };
        self.drain_notifications();

        let current = match self.backend.snapshot(mailbox).await? {
            Some(current) if current.uidvalidity == session_uidvalidity => current,
            _ => {
                write_line(writer, RESYNC_BYE).await?;
                return Ok(Flow::Close);
            }
        };
        if let State::Selected { messages, .. } = &mut self.state {
            let announcements = reconcile(messages, &current.messages);
            tracing::debug!(
                exists = messages.len(),
                announced = announcements.len(),
                "mailbox compared"
            );
            for line in announcements {
                write_line(writer, &line).await?;
            }
        }
        Ok(Flow::Continue)
    }

    // -- IDLE -------------------------------------------------------------

    /// Serve IDLE (RFC 2177) in the `Selected` state: answer `+ idling`,
    /// announce what changed while the session was not idling — never
    /// lose an update at the IDLE boundary — then wait on the command
    /// reader and the watcher at once. `DONE` ends IDLE with
    /// the tagged OK; LOGOUT behaves as it always does; any other
    /// command answers BAD and returns to normal dispatch. A change for
    /// the selected mailbox re-checks the snapshot; changes for other
    /// mailboxes emit nothing; a lagged receiver means everything may
    /// have changed and re-checks too.
    async fn handle_idle<R, W>(&mut self, reader: &mut R, writer: &mut W, tag: &str) -> Result<Flow>
    where
        R: AsyncBufRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mailbox = match &self.state {
            State::Selected { mailbox, .. } => *mailbox,
            _ => return Ok(Flow::Continue),
        };

        write_line(writer, "+ idling").await?;
        writer.flush().await.map_err(io_failed)?;

        // The boundary comparison: a change that happened while the
        // session was not idling is reported before the first wait.
        let flow = self.announce_changes(writer).await?;
        writer.flush().await.map_err(io_failed)?;
        if matches!(flow, Flow::Close) {
            return Ok(Flow::Close);
        }

        // Carries a partially-read command across select iterations, so
        // an abandoned read resumes instead of losing stream bytes.
        let mut fragment = Vec::new();
        // Whether the watcher can still fire; once every sender is gone
        // only the command reader is left to wait on.
        let mut watching = true;
        loop {
            tokio::select! {
                changed = self.watch.recv(), if watching => {
                    match changed {
                        Ok(MailboxChanged(changed)) if changed == mailbox => {
                            if matches!(self.idle_recheck(writer).await?, Flow::Close) {
                                return Ok(Flow::Close);
                            }
                        }
                        // Other mailboxes emit nothing here.
                        Ok(_) => {}
                        // Everything may have changed: full re-check.
                        Err(broadcast::error::RecvError::Lagged(_)) => {
                            if matches!(self.idle_recheck(writer).await?, Flow::Close) {
                                return Ok(Flow::Close);
                            }
                        }
                        Err(broadcast::error::RecvError::Closed) => watching = false,
                    }
                }
                line = read_line(reader, &mut fragment) => {
                    let read = match line? {
                        Some(read) => read,
                        None => {
                            // The client is gone; the main loop's next read
                            // observes the EOF and ends the session.
                            return Ok(Flow::Continue);
                        }
                    };
                    let line = match read {
                        // Beyond the cap: the same BAD the main loop
                        // answers, with the connection left at the
                        // next line.
                        LineRead::TooLong => {
                            write_line(writer, "* BAD invalid command").await?;
                            return Ok(Flow::Continue);
                        }
                        LineRead::Line(line) => line,
                    };
                    if line.trim().eq_ignore_ascii_case("done") {
                        write_line(writer, &format!("{tag} OK IDLE completed")).await?;
                        return Ok(Flow::Continue);
                    }
                    if let Ok(request) = codec::parse_line(&line) {
                        if request.command.eq_ignore_ascii_case("LOGOUT") {
                            // LOGOUT behaves as it always does.
                            respond_logout(writer, &request.tag).await?;
                            return Ok(Flow::Close);
                        }
                    }
                    write_line(
                        writer,
                        &format!("{} BAD only DONE ends IDLE", bad_tag(&line)),
                    )
                    .await?;
                    return Ok(Flow::Continue);
                }
            }
        }
    }

    /// One live re-check while idling. Unlike NOOP's post-command flush,
    /// nobody will flush after this: the client is waiting on the
    /// connection, so the response — or the BYE that ends it — must not
    /// sit in the writer's buffer.
    async fn idle_recheck<W: AsyncWrite + Unpin>(&mut self, writer: &mut W) -> Result<Flow> {
        let flow = self.announce_changes(writer).await?;
        writer.flush().await.map_err(io_failed)?;
        Ok(flow)
    }
}

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

/// Fold a `UID` command into its verb — `UID FETCH` becomes
/// `"UID FETCH"` — and pass anything else through unchanged.
fn normalize(command: &str, args: &[ImapArg]) -> String {
    if command == "UID" {
        let sub = args.first().map(arg_string).unwrap_or_default();
        format!("UID {}", sub.to_ascii_uppercase())
    } else {
        command.to_string()
    }
}

/// One argument as plain text: atoms and quoted strings as themselves,
/// a literal as its bytes. A list has no text and reads as empty.
fn arg_string(arg: &ImapArg) -> String {
    match arg {
        ImapArg::Atom(atom) => atom.clone(),
        ImapArg::Quoted(value) => value.clone(),
        ImapArg::Literal(bytes) => String::from_utf8_lossy(bytes).into_owned(),
        ImapArg::List(_) => String::new(),
    }
}

/// A mailbox name argument as the name it stands for. Mailbox names
/// travel in modified UTF-7; an argument that is not valid modified
/// UTF-7 is taken as written, so a client that sends the name raw
/// still reaches its mailbox.
fn mailbox_name(arg: &ImapArg) -> String {
    let wire = arg_string(arg);
    codec::decode_mailbox_name(&wire).unwrap_or(wire)
}

/// A mailbox name for the wire: modified UTF-7, quoted.
fn wire_mailbox(name: &str) -> String {
    qs(&codec::encode_mailbox_name(name))
}

/// Whether a LIST pattern selects the mailbox listed as `name`. The
/// mailbox whose name is `INBOX` in some casing is also matched as
/// `INBOX` case-insensitively, the way SELECT resolves it.
fn list_matches(pattern: &str, name: &str) -> bool {
    wildcard_match(pattern, name, false)
        || (name.eq_ignore_ascii_case("INBOX") && wildcard_match(pattern, "INBOX", true))
}

/// RFC 3501 §6.3.8 wildcard matching: `*` matches any run of
/// characters, `%` any run without the hierarchy delimiter `/`, and
/// everything else stands for itself (ASCII case-insensitively when
/// `fold` is set). Linear in pattern length times name length.
fn wildcard_match(pattern: &str, name: &str, fold: bool) -> bool {
    let name: Vec<char> = name.chars().collect();
    // reach[i]: the pattern consumed so far can match `name[..i]`.
    let mut reach = vec![false; name.len() + 1];
    reach[0] = true;
    for wanted in pattern.chars() {
        let mut next = vec![false; name.len() + 1];
        match wanted {
            '*' | '%' => {
                let mut open = false;
                for at in 0..=name.len() {
                    if at > 0 && wanted == '%' && name[at - 1] == '/' {
                        open = false;
                    }
                    open |= reach[at];
                    next[at] = open;
                }
            }
            _ => {
                for at in 0..name.len() {
                    let same =
                        wanted == name[at] || (fold && wanted.eq_ignore_ascii_case(&name[at]));
                    next[at + 1] = reach[at] && same;
                }
            }
        }
        reach = next;
    }
    reach[name.len()]
}

/// Encode one value for the wire: a quoted string when [`codec::
/// encode_string`] allows it, otherwise a literal already framed as
/// `{n}\r\n<bytes>`, mirroring the renderers' framing so the text can be
/// written verbatim.
fn qs(value: &str) -> String {
    match codec::encode_string(value) {
        codec::ImapString::Quoted(quoted) => format!("\"{quoted}\""),
        codec::ImapString::Literal(bytes) => format!("{{{}}}\r\n{value}", bytes.len()),
    }
}

/// The response-code section of a body fetch item, without the `BODY`
/// prefix or the peek marker: `[]`, `[HEADER]`, `[HEADER.FIELDS (...)]`.
fn body_section_name(section: &BodySection) -> String {
    match section {
        BodySection::Empty => String::new(),
        BodySection::Header => "HEADER".to_string(),
        BodySection::Text => "TEXT".to_string(),
        BodySection::HeaderFields(fields) => {
            format!("HEADER.FIELDS ({})", fields.join(" "))
        }
        BodySection::Part(raw) => raw.clone(),
    }
}

/// Bring the session's view to the store's `current` state and return
/// the untagged responses that tell the client, in the order they
/// must be sent.
///
/// * Every message that left is one `* <n> EXPUNGE`, highest number
///   first, so no announcement renumbers a message still to be named.
/// * Messages are only ever added at the end: a uid above the view's
///   highest is new, and any number of them is one `* <n> EXISTS` — sent
///   after the expunges, so a change that leaves the count unchanged
///   (one out, one in) is still two visible events.
/// * A changed read state of a message the client already knew is one
///   `* <n> FETCH (FLAGS (...))`.
fn reconcile(view: &mut Vec<(u32, bool)>, current: &[(u32, bool)]) -> Vec<String> {
    let mut announcements = Vec::new();
    let position = |uid: u32| current.binary_search_by_key(&uid, |(known, _)| *known);

    for index in (0..view.len()).rev() {
        if position(view[index].0).is_err() {
            view.remove(index);
            announcements.push(format!("* {} EXPUNGE", index + 1));
        }
    }

    for (index, (uid, unread)) in view.iter_mut().enumerate() {
        if let Ok(at) = position(*uid) {
            if current[at].1 != *unread {
                *unread = current[at].1;
                announcements.push(format!(
                    "* {} FETCH (FLAGS ({}))",
                    index + 1,
                    render::flags(*unread)
                ));
            }
        }
    }

    let highest = view.last().map_or(0, |(uid, _)| *uid);
    let known = view.len();
    view.extend(current.iter().filter(|(uid, _)| *uid > highest));
    if view.len() != known {
        // New messages are announced before the flag updates of old
        // ones would matter to them; EXISTS follows the expunges.
        let exists = format!("* {} EXISTS", view.len());
        let after_expunges = announcements
            .iter()
            .position(|line| !line.ends_with("EXPUNGE"))
            .unwrap_or(announcements.len());
        announcements.insert(after_expunges, exists);
    }
    announcements
}

/// The octets a partial fetch `<offset.count>` selects from a section.
/// An offset at or beyond the end selects nothing, and a count that
/// runs past the end is cut there (RFC 3501 §6.4.5).
fn partial_octets(mut body: Vec<u8>, partial: Option<(u32, u32)>) -> Vec<u8> {
    let Some((offset, count)) = partial else {
        return body;
    };
    let start = usize::try_from(offset).map_or(body.len(), |offset| offset.min(body.len()));
    let end = usize::try_from(count).map_or(body.len(), |count| {
        start.saturating_add(count).min(body.len())
    });
    body.truncate(end);
    body.drain(..start);
    body
}

/// One rendered fragment of a FETCH response: wire text, or body bytes
/// that stream as a server-sent literal.
enum Piece {
    Text(String),
    Body(Vec<u8>),
}

/// Render one `* <msn> FETCH (<items>)` response, byte-exact.
///
/// Items render in request order; the handler has already appended
/// `FetchItem::Uid` for a UID command when the client did not list it.
/// ENVELOPE and BODYSTRUCTURE use the backend's strings verbatim (they
/// already carry their own literal framing). Every body item takes the
/// next of the response's bodies and renders it as `{n}\r\n` framing
/// followed by the raw bytes: the client never round-trips a
/// continuation, and the bytes move out of the response instead of
/// being copied. Items the backend left unfilled are skipped, which the
/// real backend never produces.
fn render_fetch(msn: u32, response: &mut FetchResponse, items: &[FetchItem]) -> Vec<Piece> {
    let mut pieces: Vec<Piece> = Vec::new();
    let mut text = format!("* {msn} FETCH (");
    let mut bodies = std::mem::take(&mut response.bodies).into_iter();

    for item in items {
        let (name, partial) = match item {
            FetchItem::Body {
                section, partial, ..
            } => {
                // RFC 3501 §7.4.2: a partial answer names its origin
                // octet, `BODY[]<0>`, and never the requested count.
                let origin = partial.map_or_else(String::new, |(offset, _)| format!("<{offset}>"));
                (
                    format!("BODY[{}]{origin}", body_section_name(section)),
                    *partial,
                )
            }
            FetchItem::Rfc822 => ("RFC822".to_string(), None),
            FetchItem::Rfc822Header => ("RFC822.HEADER".to_string(), None),
            FetchItem::Rfc822Text => ("RFC822.TEXT".to_string(), None),
            FetchItem::Flags => {
                text.push_str(&format!("FLAGS ({}) ", response.flags));
                continue;
            }
            FetchItem::Uid => {
                text.push_str(&format!("UID {} ", response.uid));
                continue;
            }
            FetchItem::InternalDate => {
                text.push_str(&format!("INTERNALDATE {} ", response.internal_date));
                continue;
            }
            FetchItem::Envelope => {
                if let Some(envelope) = response.envelope.as_ref() {
                    text.push_str("ENVELOPE ");
                    text.push_str(envelope);
                    text.push(' ');
                }
                continue;
            }
            FetchItem::BodyStructure => {
                if let Some(bodystructure) = response.bodystructure.as_ref() {
                    text.push_str("BODYSTRUCTURE ");
                    text.push_str(bodystructure);
                    text.push(' ');
                }
                continue;
            }
            // A bare BODY is answered as BODY, without the extension
            // data BODYSTRUCTURE carries (RFC 3501 §7.4.2).
            FetchItem::BodyBasic => {
                if let Some(bodystructure) = response.bodystructure.as_ref() {
                    text.push_str("BODY ");
                    text.push_str(&render::body_basic(bodystructure));
                    text.push(' ');
                }
                continue;
            }
            FetchItem::Rfc822Size => {
                if let Some(size) = response.rfc822_size {
                    text.push_str(&format!("RFC822.SIZE {size} "));
                }
                continue;
            }
        };
        let Some(body) = bodies.next() else {
            continue;
        };
        let body = partial_octets(body, partial);
        pieces.push(Piece::Text(std::mem::take(&mut text)));
        pieces.push(Piece::Text(format!("{name} {{{}}}\r\n", body.len())));
        pieces.push(Piece::Body(body));
        // The literal bytes end an item run; the next item needs its
        // separator space back.
        text.push(' ');
    }

    if text.ends_with(' ') {
        text.pop();
    }
    text.push_str(")\r\n");
    pieces.push(Piece::Text(text));
    pieces
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// The rendered pieces as one comparable wire string.
    fn wire_of(pieces: Vec<Piece>) -> String {
        let mut wire = String::new();
        for piece in pieces {
            match piece {
                Piece::Text(text) => wire.push_str(&text),
                Piece::Body(body) => wire.push_str(&String::from_utf8_lossy(&body)),
            }
        }
        wire
    }

    /// The FETCH items of `raw`, parsed the way the handler parses
    /// them: tokenized as a command first.
    fn parse_fetch_items(raw: &str) -> Result<Vec<FetchItem>> {
        let request = codec::parse_line(&format!("a FETCH 1 {raw}"))?;
        codec::parse_fetch_items(&request.args[1..])
    }

    /// The item list a UID command carries: the client's items plus the
    /// auto-appended UID, exactly as the handler builds it.
    fn uid_items(items: &[FetchItem]) -> Vec<FetchItem> {
        let mut items = items.to_vec();
        if !items.contains(&FetchItem::Uid) {
            items.push(FetchItem::Uid);
        }
        items
    }

    /// One backend answer to render.
    fn sample_response() -> FetchResponse {
        FetchResponse {
            uid: 5,
            flags: "\\Seen".into(),
            internal_date: "\"14-Nov-2023 22:13:20 +0000\"".into(),
            envelope: Some("(NIL \"Hi\" NIL NIL NIL NIL NIL NIL NIL NIL)".into()),
            bodystructure: Some("(\"STRUCTURE\")".into()),
            rfc822_size: Some(1234),
            bodies: vec![b"hello\r\nworld".to_vec()],
        }
    }

    #[test]
    fn fetch_responses_render_with_inline_literals() {
        // UID auto-appends after the body literal. The body moves into
        // the response stream instead of being copied, so the response
        // is left without one.
        let mut response = sample_response();
        let items = uid_items(&parse_fetch_items("(FLAGS BODY[])").unwrap());
        let wire = wire_of(render_fetch(3, &mut response, &items));
        assert_eq!(
            wire,
            "* 3 FETCH (FLAGS (\\Seen) BODY[] {12}\r\nhello\r\nworld UID 5)\r\n"
        );
        assert!(response.bodies.is_empty());

        // An explicit UID renders at its requested position; the RFC822
        // aliases frame their body the same way.
        let mut response = sample_response();
        let items = parse_fetch_items("(UID RFC822)").unwrap();
        let wire = wire_of(render_fetch(3, &mut response, &items));
        assert_eq!(wire, "* 3 FETCH (UID 5 RFC822 {12}\r\nhello\r\nworld)\r\n");

        // Without a body item nothing frames a literal.
        let mut response = sample_response();
        let items =
            parse_fetch_items("(FLAGS ENVELOPE BODYSTRUCTURE RFC822.SIZE INTERNALDATE)").unwrap();
        let wire = wire_of(render_fetch(1, &mut response, &items));
        assert_eq!(
            wire,
            "* 1 FETCH (FLAGS (\\Seen) \
              ENVELOPE (NIL \"Hi\" NIL NIL NIL NIL NIL NIL NIL NIL) \
              BODYSTRUCTURE (\"STRUCTURE\") \
              RFC822.SIZE 1234 \
              INTERNALDATE \"14-Nov-2023 22:13:20 +0000\")\r\n"
        );
    }

    #[test]
    fn bare_body_is_named_body_and_drops_extension_data() {
        let mut response = sample_response();
        response.bodystructure = Some(
            "((\"TEXT\" \"PLAIN\" (\"CHARSET\" \"UTF-8\") NIL NIL \"7BIT\" 5 1) \
              \"MIXED\" (\"BOUNDARY\" \"b\"))"
                .into(),
        );
        let items = parse_fetch_items("(BODY BODYSTRUCTURE)").unwrap();
        let wire = wire_of(render_fetch(1, &mut response, &items));
        assert_eq!(
            wire,
            "* 1 FETCH (BODY ((\"TEXT\" \"PLAIN\" (\"CHARSET\" \"UTF-8\") NIL NIL \"7BIT\" 5 1) \"MIXED\") \
              BODYSTRUCTURE ((\"TEXT\" \"PLAIN\" (\"CHARSET\" \"UTF-8\") NIL NIL \"7BIT\" 5 1) \
              \"MIXED\" (\"BOUNDARY\" \"b\")))\r\n"
        );
    }

    #[test]
    fn every_body_item_renders_its_own_literal() {
        // Several body items in one FETCH: each takes the next body,
        // under its own name, in request order.
        let mut response = sample_response();
        response.bodies = vec![b"H: 1\r\n\r\n".to_vec(), b"text".to_vec()];
        let items = parse_fetch_items("(BODY.PEEK[HEADER] FLAGS BODY.PEEK[TEXT]<0.2>)").unwrap();
        let wire = wire_of(render_fetch(3, &mut response, &items));
        assert_eq!(
            wire,
            "* 3 FETCH (BODY[HEADER] {8}\r\nH: 1\r\n\r\n FLAGS (\\Seen) \
              BODY[TEXT]<0> {2}\r\nte)\r\n"
        );
    }

    #[test]
    fn partial_fetches_render_their_origin_and_slice() {
        // The item name carries `<origin>`, the literal the requested
        // octets only: "hello\r\nworld" is 12 octets.
        let render = |raw: &str| {
            let mut response = sample_response();
            let items = parse_fetch_items(raw).unwrap();
            wire_of(render_fetch(3, &mut response, &items))
        };
        assert_eq!(
            render("BODY.PEEK[]<0.5>"),
            "* 3 FETCH (BODY[]<0> {5}\r\nhello)\r\n"
        );
        assert_eq!(
            render("BODY[]<7.100>"),
            "* 3 FETCH (BODY[]<7> {5}\r\nworld)\r\n"
        );
        // At or past the end the answer is an empty string, still named.
        assert_eq!(render("BODY[]<12.4>"), "* 3 FETCH (BODY[]<12> {0}\r\n)\r\n");
        assert_eq!(render("BODY[]<99.4>"), "* 3 FETCH (BODY[]<99> {0}\r\n)\r\n");
        assert_eq!(
            render("(UID BODY[TEXT]<1.3>)"),
            "* 3 FETCH (UID 5 BODY[TEXT]<1> {3}\r\nell)\r\n"
        );
    }

    #[test]
    fn reconcile_announces_expunges_then_exists_then_flags() {
        let seen = false;
        let unread = true;

        // Nothing changed: nothing is said.
        let mut view = vec![(1, seen), (3, unread)];
        assert!(reconcile(&mut view, &[(1, seen), (3, unread)]).is_empty());

        // Arrivals are one EXISTS with the new count.
        let mut view = vec![(1, seen), (3, unread)];
        assert_eq!(
            reconcile(
                &mut view,
                &[(1, seen), (3, unread), (4, unread), (5, unread)]
            ),
            vec!["* 4 EXISTS"]
        );
        assert_eq!(view.len(), 4);

        // Departures are one EXPUNGE each, highest number first, so
        // every number is still valid when it is sent.
        let mut view = vec![(1, seen), (3, seen), (5, seen), (7, seen)];
        assert_eq!(
            reconcile(&mut view, &[(3, seen), (5, seen)]),
            vec!["* 4 EXPUNGE", "* 1 EXPUNGE"]
        );
        assert_eq!(view, vec![(3, seen), (5, seen)]);

        // One out, one in: the count is unchanged and both events are
        // still reported, the EXPUNGE first.
        let mut view = vec![(1, seen), (3, seen)];
        assert_eq!(
            reconcile(&mut view, &[(3, seen), (4, unread)]),
            vec!["* 1 EXPUNGE", "* 2 EXISTS"]
        );
        assert_eq!(view, vec![(3, seen), (4, unread)]);

        // Read-state changes name the message by its number after the
        // expunges; a new message's flags are not announced.
        let mut view = vec![(1, seen), (3, unread), (5, seen)];
        assert_eq!(
            reconcile(&mut view, &[(3, seen), (5, unread), (6, unread)]),
            vec![
                "* 1 EXPUNGE",
                "* 3 EXISTS",
                "* 1 FETCH (FLAGS (\\Seen))",
                "* 2 FETCH (FLAGS ())",
            ]
        );

        // The mailbox emptied, then filled again.
        let mut view = vec![(1, seen)];
        assert_eq!(reconcile(&mut view, &[]), vec!["* 1 EXPUNGE"]);
        assert_eq!(reconcile(&mut view, &[(9, unread)]), vec!["* 1 EXISTS"]);
    }

    #[test]
    fn list_patterns_match_with_real_wildcards() {
        // Without a wildcard the name must be exact.
        assert!(list_matches("Archive", "Archive"));
        assert!(!list_matches("archive", "Archive"));
        assert!(!list_matches("Arch", "Archive"));
        // `*` and `%` match runs, anywhere in the pattern.
        assert!(list_matches("*", "Archive"));
        assert!(list_matches("%", "Archive"));
        assert!(list_matches("*", ""));
        assert!(list_matches("Arch*", "Archive"));
        assert!(list_matches("*ive", "Archive"));
        assert!(list_matches("A%e", "Archive"));
        assert!(list_matches("A*c*e", "Archive"));
        assert!(list_matches("Archive*", "Archive"));
        assert!(!list_matches("Inbo*", "Archive"));
        assert!(!list_matches("*x", "Archive"));
        assert!(!list_matches("Archive/%", "Archive"));
        // `%` stops at the hierarchy delimiter, `*` does not.
        assert!(wildcard_match("a/%", "a/b", false));
        assert!(!wildcard_match("%", "a/b", false));
        assert!(!wildcard_match("a/%", "a/b/c", false));
        assert!(wildcard_match("a/*", "a/b/c", false));
        assert!(wildcard_match("%/%", "a/b", false));
        // INBOX is case-insensitive, under whatever casing it is listed.
        assert!(list_matches("INBOX", "Inbox"));
        assert!(list_matches("inbox", "Inbox"));
        assert!(list_matches("Inbox", "Inbox"));
        assert!(list_matches("in%", "Inbox"));
        assert!(list_matches("INB*", "INBOX"));
        assert!(!list_matches("INBOX", "Inbox (2)"));
        assert!(!list_matches("INBOX", "Archive"));
        // Many wildcards stay cheap.
        let pattern = "*a".repeat(200);
        assert!(!list_matches(&pattern, &"a".repeat(150)));
    }

    #[test]
    fn bad_tags_stay_printable_ascii() {
        assert_eq!(bad_tag("a1 LOGIN"), "a1");
        assert_eq!(bad_tag("garbage"), "garbage");
        assert_eq!(bad_tag("   "), "*");
        assert_eq!(bad_tag("\u{7f}weird\u{1b}"), "*");
        // A literal-looking first token must never be echoed as a tag:
        // the client could misread `{5} BAD …` as a continuation
        // announcement.
        assert_eq!(bad_tag("{5} NOOP"), "*");
    }

    #[test]
    fn logged_tags_pass_the_same_validation_as_responses() {
        assert_eq!(log_tag("a1"), "a1");
        assert_eq!(log_tag("A9999"), "A9999");
        // Anything a BAD response would refuse logs the fixed
        // placeholder instead of raw client bytes.
        assert_eq!(log_tag(""), INVALID_LOG_TAG);
        assert_eq!(log_tag("\u{7f}weird\u{1b}"), INVALID_LOG_TAG);
        assert_eq!(log_tag("{5}"), INVALID_LOG_TAG);
        assert_eq!(log_tag("a[b]"), INVALID_LOG_TAG);
    }

    #[test]
    fn uid_commands_normalize_their_sub_command() {
        assert_eq!(
            normalize("UID", &[ImapArg::Atom("fetch".into())]),
            "UID FETCH"
        );
        assert_eq!(normalize("LOGIN", &[]), "LOGIN");
    }
}
