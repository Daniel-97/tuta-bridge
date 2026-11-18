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
//!   session compares its UIDVALIDITY with the store's before every
//!   command that could act on it and, on mismatch, sends one fixed
//!   untagged BYE and closes — the client must reconnect. NOOP drains
//!   the mailbox-change broadcast, so polling clients see `* <n>`
//!   EXISTS updates without IDLE, and a lagged receiver treats
//!   "everything may have changed" literally. IDLE (RFC 2177) pushes
//!   the same drain live: it answers `+ idling`, flushes whatever
//!   queued at the boundary so no update is lost, and waits on the
//!   command reader and the watcher at once — `DONE` ends it with the
//!   tagged OK, LOGOUT behaves as always, and any other command
//!   answers BAD and returns to normal dispatch.
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

use super::codec::{self, BodySection, FetchItem, ImapArg, Request, SeqSet};
use crate::domain::{Error, Result};
use crate::ports::imap_backend::{FetchResponse, ImapBackend, MailboxView};
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
        view: MailboxView,
        exists: usize,
        unseen: usize,
        uidvalidity: u32,
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

/// Read one full command: the line, every announced literal (continuation
/// `+ `, exact byte count, continuation line), and nothing else.
///
/// A line beyond [`MAX_LINE_BYTES`] is refused exactly as it always
/// was, but never buffered whole: the bounded read scans the stream
/// window by window and discards a line once it crosses the cap. A
/// literal that never arrives is an EOF: the client is gone. A tail
/// line that fails to parse answers BAD with the command's own tag.
async fn read_request<R, W>(reader: &mut R, writer: &mut W) -> Result<Incoming>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut bytes = Vec::new();
    let mut line = match read_line(reader, &mut bytes).await? {
        Some(LineRead::Line(line)) => line,
        // An over-cap line: the fixed refusal, with the connection
        // left at the start of the next line.
        Some(LineRead::TooLong) => return Ok(Incoming::Invalid("*".into())),
        None => return Ok(Incoming::Eof),
    };
    let mut request = match codec::parse_line(&line) {
        Ok(request) => request,
        Err(_) => return Ok(Incoming::Invalid(bad_tag(&line))),
    };

    // A client literal: answer the continuation, read the announced
    // bytes exactly, fill the placeholder, and parse the rest of the
    // line — which may announce the next literal.
    while let Some(count) = codec::pending_literal(&line) {
        if count > MAX_LITERAL_BYTES {
            return Ok(Incoming::LiteralTooLarge(request.tag.clone()));
        }
        write_line(writer, "+ ").await?;
        writer.flush().await.map_err(io_failed)?;

        let mut data = vec![0u8; count];
        if reader.read_exact(&mut data).await.is_err() {
            return Ok(Incoming::Eof);
        }
        // The marker is always the last argument so far; fill it.
        for arg in request.args.iter_mut().rev() {
            if let ImapArg::Literal(slot) = arg {
                *slot = data;
                break;
            }
        }

        // The rest of the line follows the literal bytes.
        line = match read_line(reader, &mut bytes).await? {
            Some(LineRead::Line(line)) => line,
            Some(LineRead::TooLong) => return Ok(Incoming::Invalid(request.tag.clone())),
            None => return Ok(Incoming::Eof),
        };
        if codec::parse_continuation(&line, &mut request.args).is_err() {
            return Ok(Incoming::Invalid(request.tag.clone()));
        }
    }
    Ok(Incoming::Request(request))
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
                if self.state.selected() {
                    let flow = self.flush_notifications(writer).await?;
                    if matches!(flow, Flow::Close) {
                        return Ok(flow);
                    }
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
        let name = arg_string(name_arg);
        let Some(selected) = self.backend.select(&name).await? else {
            write_line(writer, &format!("{tag} NO no such mailbox")).await?;
            return Ok(());
        };

        write_line(writer, "* FLAGS (\\Seen)").await?;
        write_line(writer, &format!("* {} EXISTS", selected.exists)).await?;
        write_line(writer, "* 0 RECENT").await?;
        if selected.unseen > 0 {
            write_line(writer, &format!("* OK [UNSEEN {}]", selected.unseen)).await?;
        }
        write_line(writer, "* OK [PERMANENTFLAGS ()] Read-only mailbox").await?;
        write_line(
            writer,
            &format!("* OK [UIDVALIDITY {}]", selected.uidvalidity),
        )
        .await?;
        write_line(writer, &format!("* OK [UIDNEXT {}]", selected.uidnext)).await?;

        tracing::debug!(
            exists = selected.exists,
            unseen = selected.unseen,
            "mailbox selected"
        );
        self.state = State::Selected {
            view: selected.view,
            exists: selected.exists,
            unseen: selected.unseen,
            uidvalidity: selected.uidvalidity,
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
        // The reference is the root in this flat store; only the pattern
        // decides what lists.
        let pattern = arg_string(&args[1]);
        let views = self.backend.mailboxes().await?;
        let keyword = if lsub { "LSUB" } else { "LIST" };
        for view in &views {
            if !pattern_matches(&pattern, &view.name) {
                continue;
            }
            write_line(
                writer,
                &format!(
                    "* {keyword} ({}) \"/\" {}",
                    view.special_use,
                    qs(&view.name)
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
        let items = match items_arg {
            ImapArg::Raw(inner) => inner
                .split_whitespace()
                .map(|item| item.to_ascii_uppercase())
                .collect::<Vec<String>>(),
            _ => {
                write_line(writer, &format!("{tag} BAD invalid STATUS")).await?;
                return Ok(());
            }
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
        let name = arg_string(name_arg);
        let Some(selected) = self.backend.select(&name).await? else {
            write_line(writer, &format!("{tag} NO no such mailbox")).await?;
            return Ok(());
        };
        let pairs: Vec<String> = items
            .iter()
            .filter_map(|item| {
                let value = match item.as_str() {
                    "MESSAGES" => selected.exists.to_string(),
                    "RECENT" => "0".to_string(),
                    "UIDNEXT" => selected.uidnext.to_string(),
                    "UIDVALIDITY" => selected.uidvalidity.to_string(),
                    "UNSEEN" => selected.unseen.to_string(),
                    _ => return None,
                };
                Some(format!("{item} {value}"))
            })
            .collect();
        write_line(
            writer,
            &format!("* STATUS {} ({})", qs(&selected.view.name), pairs.join(" ")),
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
        let mut items = match codec::parse_fetch_items(&join_args(&args[1.min(args.len())..])) {
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

        let mailbox = match &self.state {
            State::Selected { view, .. } => view.id,
            _ => {
                write_line(
                    writer,
                    &format!("{tag} BAD command not valid in this state"),
                )
                .await?;
                return Ok(());
            }
        };
        // The uid list is the mailbox's message order: position + 1 is
        // the message sequence number, and the last uid is the `*`.
        let uids = self.backend.search(mailbox, &[String::from("ALL")]).await?;
        let max_uid = uids.last().copied().unwrap_or(0);

        for (index, uid) in uids.iter().enumerate() {
            let msn = u32::try_from(index + 1).unwrap_or(u32::MAX);
            let selected = if uid_command {
                number_selected(&set, *uid, max_uid)
            } else {
                number_selected(&set, msn, u32::try_from(uids.len()).unwrap_or(u32::MAX))
            };
            if !selected {
                continue;
            }
            // An expunged uid answers nothing (the Proton Bridge
            // lesson for mid-session expunges) and so does a uid whose
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
        let criteria = flatten_criteria(args);
        if criteria.is_empty() {
            write_line(writer, &format!("{tag} BAD invalid SEARCH")).await?;
            return Ok(());
        }
        let mailbox = match &self.state {
            State::Selected { view, .. } => view.id,
            _ => {
                write_line(
                    writer,
                    &format!("{tag} BAD command not valid in this state"),
                )
                .await?;
                return Ok(());
            }
        };
        // The backend answers uids; a plain SEARCH reports the positions
        // those uids occupy.
        let uids = self.backend.search(mailbox, &[String::from("ALL")]).await?;
        let matched = self.backend.search(mailbox, &criteria).await?;
        let numbers: Vec<String> = if uid_command {
            matched.iter().map(|uid| uid.to_string()).collect()
        } else {
            matched
                .iter()
                .filter_map(|uid| {
                    uids.iter()
                        .position(|known| known == uid)
                        .map(|position| (position + 1).to_string())
                })
                .collect()
        };
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

    /// Whether the selected snapshot still matches the store: the same
    /// mailbox at the same UIDVALIDITY. A resynced or deleted mailbox is
    /// stale.
    async fn snapshot_is_current(&self) -> Result<bool> {
        let (name, session_uidvalidity) = match &self.state {
            State::Selected {
                view, uidvalidity, ..
            } => (view.name.clone(), *uidvalidity),
            _ => return Ok(true),
        };
        match self.backend.select(&name).await? {
            Some(current) => Ok(current.uidvalidity == session_uidvalidity),
            None => Ok(false),
        }
    }

    /// Drain pending mailbox notifications. When one concerns the
    /// selected mailbox — or the receiver lagged, which means everything
    /// may have changed — the snapshot is re-checked with
    /// [`Session::refresh_selected_snapshot`].
    async fn flush_notifications<W: AsyncWrite + Unpin>(&mut self, writer: &mut W) -> Result<Flow> {
        let mailbox = match &self.state {
            State::Selected { view, .. } => view.id,
            _ => return Ok(Flow::Continue),
        };

        let mut relevant = false;
        loop {
            match self.watch.try_recv() {
                Ok(MailboxChanged(changed)) => relevant |= changed == mailbox,
                Err(broadcast::error::TryRecvError::Lagged(_)) => relevant = true,
                Err(broadcast::error::TryRecvError::Empty)
                | Err(broadcast::error::TryRecvError::Closed) => break,
            }
        }
        if !relevant {
            return Ok(Flow::Continue);
        }
        self.refresh_selected_snapshot(writer).await
    }

    /// Re-check the selected snapshot against the store in one
    /// round-trip: a vanished mailbox or a moved UIDVALIDITY sends the
    /// resync BYE and ends the session; a changed count is reported as
    /// `* <n> EXISTS`; the session's counts refresh either way.
    async fn refresh_selected_snapshot<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
    ) -> Result<Flow> {
        let (name, previous_exists, session_uidvalidity) = match &self.state {
            State::Selected {
                view,
                exists,
                uidvalidity,
                ..
            } => (view.name.clone(), *exists, *uidvalidity),
            _ => return Ok(Flow::Continue),
        };

        let Some(current) = self.backend.select(&name).await? else {
            write_line(writer, RESYNC_BYE).await?;
            return Ok(Flow::Close);
        };
        if current.uidvalidity != session_uidvalidity {
            write_line(writer, RESYNC_BYE).await?;
            return Ok(Flow::Close);
        }
        if current.exists != previous_exists {
            write_line(writer, &format!("* {} EXISTS", current.exists)).await?;
        }
        if let State::Selected {
            exists,
            unseen,
            uidvalidity,
            ..
        } = &mut self.state
        {
            *exists = current.exists;
            *unseen = current.unseen;
            *uidvalidity = current.uidvalidity;
        }
        tracing::debug!(
            exists = current.exists,
            unseen = current.unseen,
            "mailbox refreshed"
        );
        Ok(Flow::Continue)
    }

    // -- IDLE -------------------------------------------------------------

    /// Serve IDLE (RFC 2177) in the `Selected` state: answer `+ idling`,
    /// flush the notifications that queued while the session was not
    /// idling — never lose an update at the IDLE boundary — then wait on
    /// the command reader and the watcher at once. `DONE` ends IDLE with
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
            State::Selected { view, .. } => view.id,
            _ => return Ok(Flow::Continue),
        };

        write_line(writer, "+ idling").await?;
        writer.flush().await.map_err(io_failed)?;

        // The boundary flush: a change that queued while the session
        // was not idling is reported before the first wait.
        let flow = self.flush_notifications(writer).await?;
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
        let flow = self.refresh_selected_snapshot(writer).await?;
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

/// Whether `n` falls inside the set, with the star semantics resolved
/// against `max` (the largest number in use, in whatever space the
/// caller works — positions or uids):
///
/// * a lone `*` (`(0, None)`) selects exactly the last number;
/// * `x:*` selects `x..max`, and an `x` beyond `max` still selects the
///   last number, so mbsync's `UID FETCH <max+1>:*` sees the newest mail;
/// * finite ranges select what they name, nothing when past the end.
fn number_selected(set: &SeqSet, n: u32, max: u32) -> bool {
    set.ranges().iter().any(|&(start, stop)| match stop {
        Some(stop) => start <= n && n <= stop,
        None if start == 0 => n == max,
        None => start <= n || n == max,
    })
}

/// One argument as plain text: atoms and quoted strings as themselves, a
/// literal as its bytes, a parenthesized group as its inner text.
fn arg_string(arg: &ImapArg) -> String {
    match arg {
        ImapArg::Atom(atom) => atom.clone(),
        ImapArg::Quoted(value) => value.clone(),
        ImapArg::Literal(bytes) => String::from_utf8_lossy(bytes).into_owned(),
        ImapArg::Raw(inner) => inner.clone(),
    }
}

/// The FETCH item list as one string: the arguments after the sequence
/// set, joined with spaces so a parenthesized list stays one group.
fn join_args(args: &[ImapArg]) -> String {
    args.iter()
        .map(arg_string)
        .collect::<Vec<String>>()
        .join(" ")
}

/// SEARCH criteria as backend tokens: atoms, quoted values, and literal
/// bytes pass through as themselves; a parenthesized group splits into
/// its tokens, keeping quoted values with spaces whole.
fn flatten_criteria(args: &[ImapArg]) -> Vec<String> {
    let mut criteria = Vec::new();
    for arg in args {
        match arg {
            ImapArg::Raw(inner) => criteria.extend(split_raw(inner)),
            other => criteria.push(arg_string(other)),
        }
    }
    criteria
}

/// Whitespace-split a parenthesized group's inner text, honoring double
/// quotes around values with spaces (the quotes are stripped, like
/// top-level quoted arguments).
fn split_raw(inner: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    for c in inner.chars() {
        match c {
            '"' => quoted = !quoted,
            c if c.is_whitespace() && !quoted => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            c => current.push(c),
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

/// One-level LIST matching: a pattern containing a wildcard (`*` or `%`)
/// matches every mailbox — the store is flat, so the two forms agree —
/// and anything else must equal the name exactly. The reference argument
/// is the root and is not consulted.
fn pattern_matches(pattern: &str, name: &str) -> bool {
    pattern.contains('*') || pattern.contains('%') || pattern == name
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
/// already carry their own literal framing). The body — at most one per
/// response, per the port model — is taken out of the response and
/// rendered at the last body item as `{n}\r\n` framing followed by the
/// raw bytes: the client never round-trips a continuation, and only one
/// copy of the message is ever in memory. Items the backend left
/// unfilled are skipped, which the real backend never produces.
fn render_fetch(msn: u32, response: &mut FetchResponse, items: &[FetchItem]) -> Vec<Piece> {
    let mut pieces: Vec<Piece> = Vec::new();
    let mut text = format!("* {msn} FETCH (");
    let body_at = items.iter().rposition(|item| {
        matches!(
            item,
            FetchItem::Body { .. }
                | FetchItem::Rfc822
                | FetchItem::Rfc822Header
                | FetchItem::Rfc822Text
        )
    });

    for (index, item) in items.iter().enumerate() {
        let body_name = match item {
            FetchItem::Body { section, .. } if body_at == Some(index) => {
                Some(format!("BODY[{}]", body_section_name(section)))
            }
            FetchItem::Rfc822 if body_at == Some(index) => Some("RFC822".to_string()),
            FetchItem::Rfc822Header if body_at == Some(index) => Some("RFC822.HEADER".to_string()),
            FetchItem::Rfc822Text if body_at == Some(index) => Some("RFC822.TEXT".to_string()),
            FetchItem::Flags => {
                text.push_str(&format!("FLAGS ({}) ", response.flags));
                None
            }
            FetchItem::Uid => {
                text.push_str(&format!("UID {} ", response.uid));
                None
            }
            FetchItem::InternalDate => {
                text.push_str(&format!("INTERNALDATE {} ", response.internal_date));
                None
            }
            FetchItem::Envelope => {
                if let Some(envelope) = response.envelope.as_ref() {
                    text.push_str("ENVELOPE ");
                    text.push_str(envelope);
                    text.push(' ');
                }
                None
            }
            FetchItem::BodyStructure => {
                if let Some(bodystructure) = response.bodystructure.as_ref() {
                    text.push_str("BODYSTRUCTURE ");
                    text.push_str(bodystructure);
                    text.push(' ');
                }
                None
            }
            FetchItem::Rfc822Size => {
                if let Some(size) = response.rfc822_size {
                    text.push_str(&format!("RFC822.SIZE {size} "));
                }
                None
            }
            _ => None,
        };
        let Some(name) = body_name else {
            continue;
        };
        let Some(body) = response.body.take() else {
            continue;
        };
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
    use super::super::codec::{parse_fetch_items, parse_seq_set};
    use super::*;

    /// Every number in `1..=max` the set selects — the resolution the
    /// handlers perform per message, spelled out for assertions.
    fn numbers_selected(set: &SeqSet, max: u32) -> Vec<u32> {
        (1..=max)
            .filter(|n| number_selected(set, *n, max))
            .collect()
    }

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
            body: Some(b"hello\r\nworld".to_vec()),
        }
    }

    #[test]
    fn star_resolution_follows_rfc_3501() {
        // A lone `*` selects exactly the last message.
        let lone = parse_seq_set("*").unwrap();
        assert_eq!(numbers_selected(&lone, 5), vec![5]);
        // `1:*` is every message.
        let all = parse_seq_set("1:*").unwrap();
        assert_eq!(numbers_selected(&all, 5), vec![1, 2, 3, 4, 5]);
        // `x:*` runs to the end …
        let from_four = parse_seq_set("4:*").unwrap();
        assert_eq!(numbers_selected(&from_four, 5), vec![4, 5]);
        // … and an `x` beyond the end still selects the last message, so
        // mbsync's `UID FETCH <max+1>:*` never misses the newest mail.
        let mbsync = parse_seq_set("6:*").unwrap();
        assert_eq!(numbers_selected(&mbsync, 5), vec![5]);
        // Finite ranges clamp to the mailbox and select nothing past it.
        let early = parse_seq_set("2:4").unwrap();
        assert_eq!(numbers_selected(&early, 5), vec![2, 3, 4]);
        let over = parse_seq_set("9:100").unwrap();
        assert!(numbers_selected(&over, 5).is_empty());
        // An empty mailbox selects nothing at all.
        assert!(numbers_selected(&lone, 0).is_empty());
    }

    #[test]
    fn fetch_responses_render_with_inline_literals() {
        // UID auto-appends after the body literal. The body moves into
        // the response stream — peak memory is one copy per message —
        // so the response is left without one.
        let mut response = sample_response();
        let items = uid_items(&parse_fetch_items("(FLAGS BODY[])").unwrap());
        let wire = wire_of(render_fetch(3, &mut response, &items));
        assert_eq!(
            wire,
            "* 3 FETCH (FLAGS (\\Seen) BODY[] {12}\r\nhello\r\nworld UID 5)\r\n"
        );
        assert!(response.body.is_none());

        // An explicit UID renders at its requested position; the RFC822
        // aliases frame their body the same way.
        let mut response = sample_response();
        let items = parse_fetch_items("(UID RFC822)").unwrap();
        let wire = wire_of(render_fetch(3, &mut response, &items));
        assert_eq!(wire, "* 3 FETCH (UID 5 RFC822 {12}\r\nhello\r\nworld)\r\n");

        // Without a body item nothing frames a literal — and the body
        // the request never read stays in the response.
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
        assert!(response.body.is_some());
    }

    #[test]
    fn list_matching_is_flat() {
        assert!(pattern_matches("*", "Inbox"));
        assert!(pattern_matches("%", "Inbox"));
        assert!(pattern_matches("Inbo*", "Archive"));
        assert!(pattern_matches("Inbox", "Inbox"));
        assert!(!pattern_matches("Inbox", "Archive"));
    }

    #[test]
    fn criteria_flatten_groups_and_keep_quoted_values() {
        let criteria = flatten_criteria(&[
            ImapArg::Atom("UNSEEN".into()),
            ImapArg::Raw("OR FROM \"a b\" TO c".into()),
            ImapArg::Literal(b"lit".to_vec()),
        ]);
        assert_eq!(
            criteria,
            vec!["UNSEEN", "OR", "FROM", "a b", "TO", "c", "lit"]
        );
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
