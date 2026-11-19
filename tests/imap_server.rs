//! Integration contract for the IMAP session and its TLS server.
//!
//! Session tests drive `run_session` over `tokio::io::duplex` against the
//! scripted fake backend, pinning the exact wire bytes: the greeting and
//! capability set, LOGIN (plain and through client literals), the
//! SELECT/EXAMINE block, LIST framing (quoted and literal names), FETCH
//! with streamed body literals, skipped expunged uids, skipped
//! unloadable ones, the protocol refusal of part sections, the
//! oversized-line BAD that keeps the stream framed, SEARCH number
//! mapping, STATUS, the read-only refusals, the resync BYE, and NOOP's
//! notification flush. The last test runs one full client round over a
//! real loopback TLS listener with a test-only accept-all verifier.

mod support;

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{split, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, DuplexStream};
use tokio::sync::{broadcast, mpsc};
use tokio::time::Instant;
use tuta_bridge::adapters::imap::server::{
    ensure_certificate, serve, tls_acceptor, Accept, ServeLimits,
};
use tuta_bridge::adapters::imap::session::{run_session, SessionLimits};
use tuta_bridge::domain::{MailboxId, Result};
use tuta_bridge::ports::imap_backend::ImapBackend;
use tuta_bridge::ports::mailbox_events::MailboxChanged;

use support::{FakeFetched, FakeImapBackend, FakeSelected};

const GREETING: &str = "* OK [CAPABILITY IMAP4rev1 IDLE ID] tuta-bridge ready";
const LOGIN_OK: &str = "a1 OK [CAPABILITY IMAP4rev1 IDLE ID] LOGIN completed";
const USER: &str = "user@example.invalid";
const PASSWORD: &str = "hunter2";

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// One side of a test connection: line-oriented reads and writes over
/// the split halves of any duplex stream.
struct Wire<R, W> {
    reader: BufReader<R>,
    writer: W,
}

impl<R, W> Wire<R, W>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    async fn send(&mut self, line: &str) {
        self.writer.write_all(line.as_bytes()).await.unwrap();
        self.writer.write_all(b"\r\n").await.unwrap();
        self.writer.flush().await.unwrap();
    }

    /// Raw bytes without a line terminator — literal payloads.
    async fn send_raw(&mut self, bytes: &[u8]) {
        self.writer.write_all(bytes).await.unwrap();
        self.writer.flush().await.unwrap();
    }

    async fn line(&mut self) -> String {
        let mut buf = Vec::new();
        let read = self.reader.read_until(b'\n', &mut buf).await.unwrap();
        assert!(read > 0, "the session closed the stream unexpectedly");
        let mut text = String::from_utf8_lossy(&buf).into_owned();
        while text.ends_with('\n') || text.ends_with('\r') {
            text.pop();
        }
        text
    }

    async fn expect(&mut self, expected: &str) {
        assert_eq!(self.line().await, expected);
    }

    /// Read a `{n}`-framed literal: the line starting with `prefix` and
    /// ending in `{n}`, then exactly `n` raw bytes.
    async fn literal(&mut self, prefix: &str) -> Vec<u8> {
        let line = self.line().await;
        assert!(
            line.starts_with(prefix) && line.ends_with('}'),
            "expected {prefix:?}...{{n}}, got {line:?}"
        );
        let count: usize = line
            .rsplit('{')
            .next()
            .unwrap()
            .trim_end_matches('}')
            .parse()
            .unwrap();
        let mut bytes = vec![0u8; count];
        self.reader.read_exact(&mut bytes).await.unwrap();
        bytes
    }

    async fn expect_eof(&mut self) {
        let mut probe = [0u8; 1];
        let read = self.reader.read(&mut probe).await.unwrap();
        assert_eq!(read, 0, "expected the session to close the stream");
    }
}

type DuplexWire = Wire<
    tokio::io::ReadHalf<tokio::io::DuplexStream>,
    tokio::io::WriteHalf<tokio::io::DuplexStream>,
>;

/// Spawn one session over a duplex pair against `backend`.
async fn spawn_session(
    backend: Arc<FakeImapBackend>,
    capacity: usize,
) -> (
    DuplexWire,
    tokio::task::JoinHandle<Result<()>>,
    broadcast::Sender<MailboxChanged>,
) {
    spawn_session_with(backend, capacity, SessionLimits::default()).await
}

/// [`spawn_session`] with explicit limits.
async fn spawn_session_with(
    backend: Arc<FakeImapBackend>,
    capacity: usize,
    limits: SessionLimits,
) -> (
    DuplexWire,
    tokio::task::JoinHandle<Result<()>>,
    broadcast::Sender<MailboxChanged>,
) {
    let (client, server) = tokio::io::duplex(64 * 1024);
    let (sender, _) = broadcast::channel(capacity);
    let session = tokio::spawn(run_session(
        server,
        Arc::clone(&backend) as Arc<dyn ImapBackend>,
        sender.subscribe(),
        limits,
    ));
    let (reader, writer) = split(client);
    (
        Wire {
            reader: BufReader::new(reader),
            writer,
        },
        session,
        sender,
    )
}

/// The scripted backend every session test starts from: an Inbox with
/// uidvalidity 7, uids 1 and 3 (one unseen), an Archive, and a custom
/// folder whose non-ASCII name forces literal framing on the wire.
fn backend() -> Arc<FakeImapBackend> {
    Arc::new(
        FakeImapBackend::new(USER, PASSWORD)
            .with_mailbox(
                MailboxId(1),
                "Inbox",
                "",
                FakeSelected::new(7, 4, 1, vec![1, 3]),
            )
            .with_mailbox(
                MailboxId(2),
                "Archive",
                "\\Archive",
                FakeSelected::new(9, 1, 0, vec![]),
            )
            .with_mailbox(
                MailboxId(3),
                "Caffè",
                "",
                FakeSelected::new(11, 1, 0, vec![]),
            ),
    )
}

async fn login(wire: &mut DuplexWire) {
    wire.expect(GREETING).await;
    wire.send("a1 LOGIN user@example.invalid hunter2").await;
    wire.expect(LOGIN_OK).await;
}

/// Read the SELECT/EXAMINE untagged block and its tagged OK; `examine`
/// picks the `[READ-ONLY]` verb pair.
async fn expect_select_block<R, W>(
    wire: &mut Wire<R, W>,
    tag: &str,
    exists: usize,
    unseen: Option<usize>,
    uidvalidity: u32,
    uidnext: u32,
    examine: bool,
) where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let (code, verb) = if examine {
        ("READ-ONLY", "EXAMINE")
    } else {
        ("READ-WRITE", "SELECT")
    };
    wire.expect("* FLAGS (\\Seen)").await;
    wire.expect(&format!("* {exists} EXISTS")).await;
    wire.expect("* 0 RECENT").await;
    if let Some(unseen) = unseen {
        wire.expect(&format!("* OK [UNSEEN {unseen}]")).await;
    }
    wire.expect("* OK [PERMANENTFLAGS ()] Read-only mailbox")
        .await;
    wire.expect(&format!("* OK [UIDVALIDITY {uidvalidity}]"))
        .await;
    wire.expect(&format!("* OK [UIDNEXT {uidnext}]")).await;
    wire.expect(&format!("{tag} OK [{code}] {verb} completed"))
        .await;
}

async fn select_inbox(wire: &mut DuplexWire) {
    wire.send("a3 SELECT Inbox").await;
    expect_select_block(wire, "a3", 2, Some(1), 7, 4, false).await;
}

// ---------------------------------------------------------------------------
// Session contract
// ---------------------------------------------------------------------------

#[tokio::test]
async fn greets_authenticates_and_lists() {
    let (mut wire, session, _) = spawn_session(backend(), 16).await;

    wire.expect(GREETING).await;
    // A wrong password answers a tagged NO; the session stays usable.
    wire.send("a1 LOGIN user@example.invalid wrong").await;
    wire.expect("a1 NO authentication failed").await;
    wire.send("a1 LOGIN user@example.invalid hunter2").await;
    wire.expect(LOGIN_OK).await;

    // LIST "" "*": the Inbox carries no special-use attribute, the
    // Archive does, and the non-ASCII name travels in modified UTF-7.
    wire.send("a2 LIST \"\" \"*\"").await;
    wire.expect("* LIST () \"/\" \"Inbox\"").await;
    wire.expect("* LIST (\\Archive) \"/\" \"Archive\"").await;
    wire.expect("* LIST () \"/\" \"Caff&AOg-\"").await;
    wire.expect("a2 OK LIST completed").await;

    // LSUB mirrors LIST: the bridge has no separate subscription view.
    wire.send("a3 LSUB \"\" \"*\"").await;
    wire.expect("* LSUB () \"/\" \"Inbox\"").await;
    wire.expect("* LSUB (\\Archive) \"/\" \"Archive\"").await;
    wire.expect("* LSUB () \"/\" \"Caff&AOg-\"").await;
    wire.expect("a3 OK LSUB completed").await;

    // An exact pattern lists just that mailbox.
    wire.send("a4 LIST \"\" \"Archive\"").await;
    wire.expect("* LIST (\\Archive) \"/\" \"Archive\"").await;
    wire.expect("a4 OK LIST completed").await;

    // Real wildcards: a pattern selects what it matches, not
    // everything, and the reference is a prefix of it.
    wire.send("b1 LIST \"\" \"Arch%\"").await;
    wire.expect("* LIST (\\Archive) \"/\" \"Archive\"").await;
    wire.expect("b1 OK LIST completed").await;
    wire.send("b2 LIST \"Arch\" \"*e\"").await;
    wire.expect("* LIST (\\Archive) \"/\" \"Archive\"").await;
    wire.expect("b2 OK LIST completed").await;
    wire.send("b3 LIST \"\" \"Archive/%\"").await;
    wire.expect("b3 OK LIST completed").await;
    // INBOX is found in any casing, as SELECT finds it.
    wire.send("b4 LIST \"\" \"INBOX\"").await;
    wire.expect("* LIST () \"/\" \"Inbox\"").await;
    wire.expect("b4 OK LIST completed").await;
    wire.send("b5 LSUB \"\" inbox").await;
    wire.expect("* LSUB () \"/\" \"Inbox\"").await;
    wire.expect("b5 OK LSUB completed").await;
    // The empty pattern is the delimiter probe.
    wire.send("b6 LIST \"\" \"\"").await;
    wire.expect("* LIST (\\Noselect) \"/\" \"\"").await;
    wire.expect("b6 OK LIST completed").await;
    // A pattern in modified UTF-7 matches the name it encodes.
    wire.send("b7 LIST \"\" \"Caff&AOg-\"").await;
    wire.expect("* LIST () \"/\" \"Caff&AOg-\"").await;
    wire.expect("b7 OK LIST completed").await;

    // The name the client was given selects the mailbox, and STATUS
    // answers under the same wire name.
    wire.send("a5 STATUS \"Caff&AOg-\" (MESSAGES)").await;
    wire.expect("* STATUS \"Caff&AOg-\" (MESSAGES 0)").await;
    wire.expect("a5 OK STATUS completed").await;
    wire.send("a6 SELECT \"Caff&AOg-\"").await;
    expect_select_block(&mut wire, "a6", 0, None, 11, 1, false).await;
    // A client that sends the name raw instead still reaches it.
    wire.send("a7 EXAMINE {6}").await;
    wire.expect("+ ").await;
    wire.send_raw("Caffè\r\n".as_bytes()).await;
    expect_select_block(&mut wire, "a7", 0, None, 11, 1, true).await;

    drop(wire);
    session.await.unwrap().unwrap();
}

#[tokio::test]
async fn login_accepts_client_literals() {
    // The password arrives as a client literal: `+ `, then the bytes,
    // then the (empty) continuation line.
    let scripted = backend();
    let (mut wire, session, _) = spawn_session(Arc::clone(&scripted), 16).await;
    wire.expect(GREETING).await;
    wire.send("a1 LOGIN user@example.invalid {7}").await;
    wire.expect("+ ").await;
    wire.send_raw(b"hunter2\r\n").await;
    wire.expect(LOGIN_OK).await;
    drop(wire);
    session.await.unwrap().unwrap();

    // Two chained literals, one per argument, round-trip the same way.
    let scripted = backend();
    let (mut wire, session, _) = spawn_session(Arc::clone(&scripted), 16).await;
    wire.expect(GREETING).await;
    wire.send("b1 LOGIN {20}").await;
    wire.expect("+ ").await;
    wire.send_raw(b"user@example.invalid {7}\r\n").await;
    wire.expect("+ ").await;
    wire.send_raw(b"hunter2\r\n").await;
    wire.expect("b1 OK [CAPABILITY IMAP4rev1 IDLE ID] LOGIN completed")
        .await;

    // An oversized announcement is refused without a continuation and
    // the connection closes.
    wire.send("c1 LOGIN user {17000000}").await;
    wire.expect("c1 NO literal too large").await;
    wire.expect_eof().await;
    drop(wire);
    session.await.unwrap().unwrap();
}

#[tokio::test]
async fn select_reports_counts_and_read_only_flags() {
    let (mut wire, session, _) = spawn_session(backend(), 16).await;
    login(&mut wire).await;

    wire.send("a3 SELECT Inbox").await;
    expect_select_block(&mut wire, "a3", 2, Some(1), 7, 4, false).await;

    // EXAMINE reports the same block but answers READ-ONLY.
    wire.send("a4 EXAMINE Inbox").await;
    expect_select_block(&mut wire, "a4", 2, Some(1), 7, 4, true).await;

    // A mailbox without unseen messages skips the UNSEEN line.
    wire.send("a5 SELECT Archive").await;
    expect_select_block(&mut wire, "a5", 0, None, 9, 1, false).await;

    // Unknown mailboxes answer NO.
    wire.send("a6 SELECT Nope").await;
    wire.expect("a6 NO no such mailbox").await;

    drop(wire);
    session.await.unwrap().unwrap();
}

#[tokio::test]
async fn fetch_streams_bodies_and_skips_expunged_uids() {
    // A body larger than two 64 KiB chunks proves the streamed write.
    let body: Vec<u8> = (0..200_000u32)
        .map(|i| u8::try_from(i % 251).unwrap())
        .collect();
    let scripted = Arc::new(
        FakeImapBackend::new(USER, PASSWORD)
            .with_mailbox(
                MailboxId(1),
                "Inbox",
                "",
                FakeSelected::new(7, 4, 1, vec![1, 3]),
            )
            .with_mailbox(
                MailboxId(2),
                "Archive",
                "\\Archive",
                FakeSelected::new(9, 1, 0, vec![]),
            )
            .with_fetch(
                1,
                FakeFetched {
                    flags: "\\Seen".into(),
                    internal_date: "\"14-Nov-2023 22:13:20 +0000\"".into(),
                    envelope: Some("(NIL \"Hi\" NIL NIL NIL NIL NIL NIL NIL NIL)".into()),
                    bodystructure: Some("(\"STRUCTURE\")".into()),
                    rfc822_size: Some(200_000),
                    body: body.clone(),
                },
            ),
    );
    let (mut wire, session, _) = spawn_session(Arc::clone(&scripted), 16).await;
    login(&mut wire).await;
    select_inbox(&mut wire).await;

    // UID FETCH 1,3: uid 3 is not scripted, so it behaves like an
    // expunged message — exactly one FETCH line, then the tagged OK.
    // The body is a server-sent literal (no continuation round-trip),
    // and UID is auto-appended.
    wire.send("a4 UID FETCH 1,3 (FLAGS BODY[])").await;
    let bytes = wire.literal("* 1 FETCH (FLAGS (\\Seen) BODY[] ").await;
    assert_eq!(bytes.len(), body.len());
    assert_eq!(bytes, body);
    wire.expect(" UID 1)").await;
    wire.expect("a4 OK UID FETCH completed").await;

    // The vanished uid alone produces no untagged response at all.
    wire.send("a5 UID FETCH 3 (FLAGS)").await;
    wire.expect("a5 OK UID FETCH completed").await;

    // Plain FETCH maps sequence numbers to uids by position.
    wire.send("a6 FETCH 1 (UID FLAGS)").await;
    wire.expect("* 1 FETCH (UID 1 FLAGS (\\Seen))").await;
    wire.expect("a6 OK FETCH completed").await;

    // Metadata-only items render without touching the body.
    wire.send("a7 FETCH 1 (ENVELOPE RFC822.SIZE)").await;
    wire.expect(
        "* 1 FETCH (ENVELOPE (NIL \"Hi\" NIL NIL NIL NIL NIL NIL NIL NIL) RFC822.SIZE 200000)",
    )
    .await;
    wire.expect("a7 OK FETCH completed").await;

    // A bare item with a bracketed list is one item, with or without
    // the surrounding parentheses.
    wire.send("a8 FETCH 1 BODY.PEEK[HEADER.FIELDS (DATE FROM)]")
        .await;
    let bytes = wire
        .literal("* 1 FETCH (BODY[HEADER.FIELDS (DATE FROM)] ")
        .await;
    assert_eq!(bytes, body);
    wire.expect(")").await;
    wire.expect("a8 OK FETCH completed").await;

    drop(wire);
    session.await.unwrap().unwrap();
}

#[tokio::test]
async fn fetch_skips_poisoned_uids_and_refuses_part_sections() {
    // uid 1 fails on every fetch, uid 3 answers: one poisoned row
    // must not abort the batch — exactly one FETCH line, then the
    // tagged OK.
    let scripted = Arc::new(
        FakeImapBackend::new(USER, PASSWORD)
            .with_mailbox(
                MailboxId(1),
                "Inbox",
                "",
                FakeSelected::new(7, 4, 1, vec![1, 3]),
            )
            .with_failing_fetch(1)
            .with_fetch(
                3,
                FakeFetched {
                    flags: "\\Seen".into(),
                    internal_date: "\"14-Nov-2023 22:13:20 +0000\"".into(),
                    envelope: None,
                    bodystructure: None,
                    rfc822_size: None,
                    body: Vec::new(),
                },
            ),
    );
    let (mut wire, session, _) = spawn_session(scripted, 16).await;
    login(&mut wire).await;
    select_inbox(&mut wire).await;

    // The poisoned uid produces no FETCH line; the uid after it is
    // served, and the command still ends with its tagged OK.
    wire.send("a4 UID FETCH 1,3 (FLAGS UID)").await;
    wire.expect("* 2 FETCH (FLAGS (\\Seen) UID 3)").await;
    wire.expect("a4 OK UID FETCH completed").await;

    // The same batch as a plain FETCH: the poisoned position vanishes,
    // the last message still answers.
    wire.send("a5 FETCH 1:* (UID FLAGS)").await;
    wire.expect("* 2 FETCH (UID 3 FLAGS (\\Seen))").await;
    wire.expect("a5 OK FETCH completed").await;

    // A part-section request stays the protocol refusal it has always
    // been: a tagged NO, not a silently empty OK.
    wire.send("a6 FETCH 2 (BODY[1.2])").await;
    wire.expect("a6 NO message part sections are not supported")
        .await;

    drop(wire);
    session.await.unwrap().unwrap();
}

#[tokio::test]
async fn oversized_lines_answer_bad_and_keep_the_session_framed() {
    let (mut wire, session, _) = spawn_session(backend(), 16).await;
    wire.expect(GREETING).await;

    // A line past the 64 KiB cap: the same `* BAD invalid command`
    // the session has always answered — the line is detected while
    // being read and discarded, never buffered whole — and the
    // connection stays framed on the next line.
    let mut oversized = String::from("a1 LOGIN user ");
    oversized.push_str(&"A".repeat(70_000));
    wire.send_raw(oversized.as_bytes()).await;
    wire.send_raw(b"\r\n").await;
    wire.expect("* BAD invalid command").await;

    // The connection state matches today's behavior: the session
    // continues in the same state and the next line dispatches.
    wire.send("a1 LOGIN user@example.invalid hunter2").await;
    wire.expect(LOGIN_OK).await;

    // The same refusal during IDLE: the BAD ends the idling state
    // and the dispatch loop continues on the next line.
    wire.send("a3 SELECT Inbox").await;
    expect_select_block(&mut wire, "a3", 2, Some(1), 7, 4, false).await;
    wire.send("i1 IDLE").await;
    wire.expect("+ idling").await;
    let mut oversized_idle = String::from("x");
    oversized_idle.push_str(&"B".repeat(70_000));
    wire.send_raw(oversized_idle.as_bytes()).await;
    wire.send_raw(b"\r\n").await;
    wire.expect("* BAD invalid command").await;
    wire.send("i2 NOOP").await;
    wire.expect("i2 OK NOOP completed").await;

    drop(wire);
    session.await.unwrap().unwrap();
}

#[tokio::test]
async fn status_reports_requested_items() {
    let (mut wire, session, _) = spawn_session(backend(), 16).await;
    login(&mut wire).await;

    wire.send("a5 STATUS Inbox (MESSAGES UIDNEXT UIDVALIDITY UNSEEN RECENT)")
        .await;
    wire.expect("* STATUS \"Inbox\" (MESSAGES 2 UIDNEXT 4 UIDVALIDITY 7 UNSEEN 1 RECENT 0)")
        .await;
    wire.expect("a5 OK STATUS completed").await;

    wire.send("a6 STATUS Nope (MESSAGES)").await;
    wire.expect("a6 NO no such mailbox").await;
    wire.send("a7 STATUS Inbox (BOGUS)").await;
    wire.expect("a7 BAD invalid status items").await;

    drop(wire);
    session.await.unwrap().unwrap();
}

#[tokio::test]
async fn close_and_check() {
    let (mut wire, session, _) = spawn_session(backend(), 16).await;
    login(&mut wire).await;
    select_inbox(&mut wire).await;

    wire.send("a3 CHECK").await;
    wire.expect("a3 OK CHECK completed").await;
    wire.send("a4 CLOSE").await;
    wire.expect("a4 OK CLOSE completed").await;

    // Without a selected mailbox FETCH is state-inappropriate again.
    wire.send("a5 FETCH 1 (UID)").await;
    wire.expect("a5 BAD command not valid in this state").await;

    // SELECT works again after CLOSE.
    select_inbox(&mut wire).await;

    drop(wire);
    session.await.unwrap().unwrap();
}

#[tokio::test]
async fn logout_sends_bye() {
    let (mut wire, session, _) = spawn_session(backend(), 16).await;
    wire.expect(GREETING).await;

    wire.send("a9 LOGOUT").await;
    wire.expect("* BYE tuta-bridge signing off").await;
    wire.expect("a9 OK LOGOUT completed").await;
    wire.expect_eof().await;
    drop(wire);
    session.await.unwrap().unwrap();
}

#[tokio::test]
async fn writes_are_refused() {
    let (mut wire, session, _) = spawn_session(backend(), 16).await;
    login(&mut wire).await;
    select_inbox(&mut wire).await;

    for (tag, command) in [
        ("w1", "STORE 1 +FLAGS (\\Seen)"),
        ("w2", "EXPUNGE"),
        ("w3", "COPY 1 Inbox"),
        ("w4", "MOVE 1 Inbox"),
        ("w5", "CREATE Foo"),
        ("w6", "DELETE Foo"),
        ("w7", "RENAME Foo Bar"),
        ("w8", "SUBSCRIBE Foo"),
        ("w9", "UNSUBSCRIBE Foo"),
        ("wi", "UID STORE 1 +FLAGS (\\Seen)"),
        ("wj", "UID COPY 1 Inbox"),
    ] {
        wire.send(&format!("{tag} {command}")).await;
        wire.expect(&format!("{tag} NO not supported by this read-only bridge"))
            .await;
    }

    // APPEND announces its literal first; the session consumes it before
    // refusing, so the stream stays framed.
    wire.send("wa APPEND Inbox {5}").await;
    wire.expect("+ ").await;
    wire.send_raw(b"hello\r\n").await;
    wire.expect("wa NO not supported by this read-only bridge")
        .await;

    // Unknown commands answer BAD.
    wire.send("wz FROBNICATE now").await;
    wire.expect("wz BAD unknown command").await;

    drop(wire);
    session.await.unwrap().unwrap();
}

#[tokio::test]
async fn idle_emits_exists_on_changes_and_done_ends_it() {
    let scripted = backend();
    let (mut wire, session, sender) = spawn_session(Arc::clone(&scripted), 16).await;
    login(&mut wire).await;
    select_inbox(&mut wire).await;

    // IDLE answers the continuation and starts waiting.
    wire.send("i1 IDLE").await;
    wire.expect("+ idling").await;

    // The store gains a message and the notifier fires: the idling
    // session pushes the new count without being asked.
    scripted.add_message("Inbox", 4);
    sender.send(MailboxChanged(MailboxId(1))).unwrap();
    wire.expect("* 3 EXISTS").await;

    // DONE ends IDLE with the tagged OK, and dispatch is normal again.
    wire.send("DONE").await;
    wire.expect("i1 OK IDLE completed").await;
    wire.send("i2 NOOP").await;
    wire.expect("i2 OK NOOP completed").await;

    drop(wire);
    session.await.unwrap().unwrap();
}

/// A fetch answer that renders nothing but what the session itself
/// knows; enough for `(UID)` and `(UID FLAGS)` requests.
fn bare_fetch() -> FakeFetched {
    FakeFetched {
        flags: "\\Seen".into(),
        internal_date: "\"14-Nov-2023 22:13:20 +0000\"".into(),
        envelope: None,
        bodystructure: None,
        rfc822_size: None,
        body: Vec::new(),
    }
}

#[tokio::test]
async fn message_numbers_hold_until_an_expunge_is_announced() {
    let scripted = Arc::new(
        FakeImapBackend::new(USER, PASSWORD)
            .with_mailbox(
                MailboxId(1),
                "Inbox",
                "",
                FakeSelected::new(7, 6, 0, vec![1, 3, 5]),
            )
            .with_fetch(3, bare_fetch())
            .with_fetch(5, bare_fetch())
            .with_fetch(6, bare_fetch())
            .with_search(vec![1, 3, 5, 6]),
    );
    let (mut wire, session, _sender) = spawn_session(Arc::clone(&scripted), 16).await;
    login(&mut wire).await;
    wire.send("a3 SELECT Inbox").await;
    expect_select_block(&mut wire, "a3", 3, None, 7, 6, false).await;

    // The store loses uid 1 and gains uid 6 under the session. Until
    // the session says so, every number keeps naming the message the
    // client knows by it: 2 is still uid 3, 1 answers nothing, and the
    // unannounced arrival has no number at all.
    scripted.remove_message("Inbox", 1);
    scripted.add_message("Inbox", 6);
    wire.send("a4 FETCH 1:* (UID)").await;
    wire.expect("* 2 FETCH (UID 3)").await;
    wire.expect("* 3 FETCH (UID 5)").await;
    wire.expect("a4 OK FETCH completed").await;
    wire.send("a5 SEARCH SEEN").await;
    wire.expect("* SEARCH 1 2 3").await;
    wire.expect("a5 OK SEARCH completed").await;
    wire.send("a6 UID SEARCH SEEN").await;
    wire.expect("* SEARCH 1 3 5").await;
    wire.expect("a6 OK UID SEARCH completed").await;
    wire.send("a7 UID FETCH 6 (UID)").await;
    wire.expect("a7 OK UID FETCH completed").await;

    // NOOP is where the change may be announced: the expunge first,
    // then the arrival — the count is the same as before, and both
    // events are still reported.
    wire.send("a8 NOOP").await;
    wire.expect("* 1 EXPUNGE").await;
    wire.expect("* 3 EXISTS").await;
    wire.expect("a8 OK NOOP completed").await;
    wire.send("a9 FETCH 1:* (UID)").await;
    wire.expect("* 1 FETCH (UID 3)").await;
    wire.expect("* 2 FETCH (UID 5)").await;
    wire.expect("* 3 FETCH (UID 6)").await;
    wire.expect("a9 OK FETCH completed").await;

    // CHECK is a sync point too, and a read-state change is a FETCH.
    scripted.set_unread("Inbox", 5, true);
    wire.send("b1 CHECK").await;
    wire.expect("* 2 FETCH (FLAGS ())").await;
    wire.expect("b1 OK CHECK completed").await;

    drop(wire);
    session.await.unwrap().unwrap();
}

#[tokio::test]
async fn idle_announces_expunges_and_flag_changes_live() {
    let scripted = backend();
    let (mut wire, session, sender) = spawn_session(Arc::clone(&scripted), 16).await;
    login(&mut wire).await;
    select_inbox(&mut wire).await;
    wire.send("i1 IDLE").await;
    wire.expect("+ idling").await;

    // One mail out and one in between two notifications.
    scripted.remove_message("Inbox", 1);
    scripted.add_message("Inbox", 4);
    sender.send(MailboxChanged(MailboxId(1))).unwrap();
    wire.expect("* 1 EXPUNGE").await;
    wire.expect("* 2 EXISTS").await;

    // The remaining unread mail is read elsewhere.
    scripted.set_unread("Inbox", 3, false);
    sender.send(MailboxChanged(MailboxId(1))).unwrap();
    wire.expect("* 1 FETCH (FLAGS (\\Seen))").await;

    wire.send("DONE").await;
    wire.expect("i1 OK IDLE completed").await;
    drop(wire);
    session.await.unwrap().unwrap();
}

#[tokio::test]
async fn a_deleted_mailbox_ends_the_selected_session_with_bye() {
    // The folder is deleted in Tuta: the watcher removes the mailbox
    // and announces its id one last time. An idling session ends with
    // the fixed BYE instead of an error.
    let scripted = backend();
    let (mut wire, session, sender) = spawn_session(Arc::clone(&scripted), 16).await;
    login(&mut wire).await;
    select_inbox(&mut wire).await;
    wire.send("i1 IDLE").await;
    wire.expect("+ idling").await;
    scripted.remove_mailbox("Inbox");
    sender.send(MailboxChanged(MailboxId(1))).unwrap();
    wire.expect("* BYE mailbox state was resynced; reconnect")
        .await;
    wire.expect_eof().await;
    session.await.unwrap().unwrap();

    // Outside IDLE the next command finds the mailbox gone.
    let scripted = backend();
    let (mut wire, session, _sender) = spawn_session(Arc::clone(&scripted), 16).await;
    login(&mut wire).await;
    select_inbox(&mut wire).await;
    scripted.remove_mailbox("Inbox");
    wire.send("a4 FETCH 1 (UID)").await;
    wire.expect("* BYE mailbox state was resynced; reconnect")
        .await;
    wire.expect_eof().await;
    session.await.unwrap().unwrap();
}

#[tokio::test]
async fn uidvalidity_change_resets_the_session_with_bye() {
    let scripted = backend();
    let (mut wire, session, sender) = spawn_session(Arc::clone(&scripted), 16).await;
    login(&mut wire).await;
    select_inbox(&mut wire).await;

    wire.send("i1 IDLE").await;
    wire.expect("+ idling").await;

    // The store resyncs under the idling session: the UIDVALIDITY
    // moved, the snapshot is stale — one fixed BYE, no tagged response,
    // and the stream closes.
    scripted.resync("Inbox", 42);
    sender.send(MailboxChanged(MailboxId(1))).unwrap();
    wire.expect("* BYE mailbox state was resynced; reconnect")
        .await;
    wire.expect_eof().await;
    drop(wire);
    session.await.unwrap().unwrap();
}

#[tokio::test]
async fn idle_ignores_changes_to_other_mailboxes() {
    let scripted = backend();
    let (mut wire, session, sender) = spawn_session(Arc::clone(&scripted), 16).await;
    login(&mut wire).await;
    select_inbox(&mut wire).await;

    // A change for another mailbox queued before IDLE: the entry flush
    // stays quiet.
    scripted.add_message("Archive", 5);
    sender.send(MailboxChanged(MailboxId(2))).unwrap();

    wire.send("i1 IDLE").await;
    wire.expect("+ idling").await;

    // In-idle, another mailbox's change emits nothing: the selected
    // mailbox's change — queued after it, in channel order — is the
    // first thing the wire sees.
    scripted.add_message("Archive", 6);
    sender.send(MailboxChanged(MailboxId(2))).unwrap();
    scripted.add_message("Inbox", 4);
    sender.send(MailboxChanged(MailboxId(1))).unwrap();
    wire.expect("* 3 EXISTS").await;

    wire.send("DONE").await;
    wire.expect("i1 OK IDLE completed").await;

    drop(wire);
    session.await.unwrap().unwrap();
}

#[tokio::test]
async fn idle_outside_selected_answers_bad() {
    let (mut wire, session, _) = spawn_session(backend(), 16).await;
    wire.expect(GREETING).await;

    // IDLE is a Selected-state command: pre-auth...
    wire.send("i0 IDLE").await;
    wire.expect("i0 BAD command not valid in this state").await;

    // ...and authenticated without a selected mailbox both refuse it,
    // and the session stays usable.
    wire.send("a1 LOGIN user@example.invalid hunter2").await;
    wire.expect(LOGIN_OK).await;
    wire.send("i1 IDLE").await;
    wire.expect("i1 BAD command not valid in this state").await;
    wire.send("a2 NOOP").await;
    wire.expect("a2 OK NOOP completed").await;

    drop(wire);
    session.await.unwrap().unwrap();
}

#[tokio::test]
async fn idle_flushes_pending_notifications_on_entry() {
    let scripted = backend();
    let (mut wire, session, sender) = spawn_session(Arc::clone(&scripted), 16).await;
    login(&mut wire).await;
    select_inbox(&mut wire).await;

    // The change queued while the session was not idling: IDLE reports
    // it immediately after the continuation — nothing is lost at the
    // boundary (the Proton Bridge lesson).
    scripted.add_message("Inbox", 4);
    sender.send(MailboxChanged(MailboxId(1))).unwrap();

    wire.send("i1 IDLE").await;
    wire.expect("+ idling").await;
    wire.expect("* 3 EXISTS").await;

    // The boundary flush already reported the change: DONE ends IDLE
    // and a later NOOP stays quiet.
    wire.send("DONE").await;
    wire.expect("i1 OK IDLE completed").await;
    wire.send("i2 NOOP").await;
    wire.expect("i2 OK NOOP completed").await;

    drop(wire);
    session.await.unwrap().unwrap();
}

#[tokio::test]
async fn idle_rejects_other_commands_and_ends() {
    let (mut wire, session, _) = spawn_session(backend(), 16).await;
    login(&mut wire).await;
    select_inbox(&mut wire).await;

    // A command during IDLE answers BAD and ends the idling state...
    wire.send("i1 IDLE").await;
    wire.expect("+ idling").await;
    wire.send("i2 NOOP").await;
    wire.expect("i2 BAD only DONE ends IDLE").await;

    // ...and the session dispatches normally again.
    wire.send("i3 NOOP").await;
    wire.expect("i3 OK NOOP completed").await;

    // Garbage fares the same; the `{` polish keeps a literal-looking
    // token out of the echoed tag.
    wire.send("i4 IDLE").await;
    wire.expect("+ idling").await;
    wire.send("{5}").await;
    wire.expect("* BAD only DONE ends IDLE").await;

    // LOGOUT during IDLE behaves as it always does.
    wire.send("i5 IDLE").await;
    wire.expect("+ idling").await;
    wire.send("a9 LOGOUT").await;
    wire.expect("* BYE tuta-bridge signing off").await;
    wire.expect("a9 OK LOGOUT completed").await;
    wire.expect_eof().await;
    drop(wire);
    session.await.unwrap().unwrap();
}

#[tokio::test]
async fn uidvalidity_drift_resets_sessions_before_every_command() {
    for command in ["a5 NOOP", "a5 UID FETCH 1 (FLAGS)", "a5 CHECK"] {
        let scripted = backend();
        let (mut wire, session, _) = spawn_session(Arc::clone(&scripted), 16).await;
        login(&mut wire).await;
        select_inbox(&mut wire).await;

        // The store resyncs under the session: the next command of ANY
        // kind answers the fixed BYE and the stream closes — no tagged
        // response, the client must reconnect (Proton Bridge lesson:
        // validate the snapshot before every command, not only during
        // push).
        scripted.resync("Inbox", 42);
        wire.send(command).await;
        wire.expect("* BYE mailbox state was resynced; reconnect")
            .await;
        wire.expect_eof().await;
        drop(wire);
        session.await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn id_command_answers_and_noop_flushes_notifications() {
    let scripted = backend();
    let (mut wire, session, sender) = spawn_session(Arc::clone(&scripted), 16).await;
    wire.expect(GREETING).await;

    // ID is valid in every state and its payload is not interpreted.
    wire.send("a1 ID (\"name\" \"test\")").await;
    wire.expect("* ID (\"name\" \"tuta-bridge\")").await;
    wire.expect("a1 OK ID completed").await;

    wire.send("a2 LOGIN user@example.invalid hunter2").await;
    wire.expect("a2 OK [CAPABILITY IMAP4rev1 IDLE ID] LOGIN completed")
        .await;
    wire.send("a3 SELECT Inbox").await;
    expect_select_block(&mut wire, "a3", 2, Some(1), 7, 4, false).await;

    // A stored change for the selected mailbox arrives: NOOP reports the
    // new count even outside IDLE.
    scripted.add_message("Inbox", 4);
    sender.send(MailboxChanged(MailboxId(1))).unwrap();
    wire.send("a4 NOOP").await;
    wire.expect("* 3 EXISTS").await;
    wire.expect("a4 OK NOOP completed").await;

    // Nothing changed since: the next NOOP stays quiet.
    wire.send("a5 NOOP").await;
    wire.expect("a5 OK NOOP completed").await;

    // A notification for another mailbox reports nothing here.
    scripted.add_message("Archive", 5);
    sender.send(MailboxChanged(MailboxId(2))).unwrap();
    wire.send("a6 NOOP").await;
    wire.expect("a6 OK NOOP completed").await;

    // A change that does not move the count refreshes silently.
    sender.send(MailboxChanged(MailboxId(1))).unwrap();
    wire.send("a7 NOOP").await;
    wire.expect("a7 OK NOOP completed").await;

    drop(wire);
    session.await.unwrap().unwrap();
}

#[tokio::test]
async fn noop_treats_lag_as_everything_changed() {
    let scripted = backend();
    // Capacity one: three sends overflow the receiver, which must treat
    // the lag as "everything may have changed" and re-check anyway.
    let (mut wire, session, sender) = spawn_session(Arc::clone(&scripted), 1).await;
    login(&mut wire).await;
    select_inbox(&mut wire).await;

    scripted.add_message("Inbox", 4);
    for _ in 0..3 {
        let _ = sender.send(MailboxChanged(MailboxId(1)));
    }
    wire.send("a4 NOOP").await;
    wire.expect("* 3 EXISTS").await;
    wire.expect("a4 OK NOOP completed").await;

    drop(wire);
    session.await.unwrap().unwrap();
}

#[tokio::test]
async fn capability_advertises_the_subset() {
    let (mut wire, session, _) = spawn_session(backend(), 16).await;
    wire.expect(GREETING).await;

    wire.send("a0 CAPABILITY").await;
    wire.expect("* CAPABILITY IMAP4rev1 IDLE ID").await;
    wire.expect("a0 OK CAPABILITY completed").await;

    wire.send("a1 LOGIN user@example.invalid hunter2").await;
    wire.expect(LOGIN_OK).await;

    wire.send("a2 CAPABILITY").await;
    wire.expect("* CAPABILITY IMAP4rev1 IDLE ID").await;
    wire.expect("a2 OK CAPABILITY completed").await;

    drop(wire);
    session.await.unwrap().unwrap();
}

#[tokio::test]
async fn search_returns_uids() {
    let scripted = Arc::new(
        FakeImapBackend::new(USER, PASSWORD)
            .with_mailbox(
                MailboxId(1),
                "Inbox",
                "",
                FakeSelected::new(7, 6, 0, vec![1, 2, 5]),
            )
            .with_search_result(&["SEEN"], vec![2, 5])
            .with_search_result(&["UNSEEN"], vec![]),
    );
    let (mut wire, session, _) = spawn_session(Arc::clone(&scripted), 16).await;
    login(&mut wire).await;
    wire.send("a3 SELECT Inbox").await;
    expect_select_block(&mut wire, "a3", 3, None, 7, 6, false).await;

    // UID SEARCH answers the stored uids verbatim; ALL matches every
    // stored message.
    wire.send("a4 UID SEARCH ALL").await;
    wire.expect("* SEARCH 1 2 5").await;
    wire.expect("a4 OK UID SEARCH completed").await;

    // A criteria with a scripted result answers its uids.
    wire.send("a5 UID SEARCH SEEN").await;
    wire.expect("* SEARCH 2 5").await;
    wire.expect("a5 OK UID SEARCH completed").await;

    // Plain SEARCH maps uids to their 1-based positions: uid 2 is the
    // second message, uid 5 the third.
    wire.send("a6 SEARCH SEEN").await;
    wire.expect("* SEARCH 2 3").await;
    wire.expect("a6 OK SEARCH completed").await;

    // An empty result stays a bare `* SEARCH`.
    wire.send("a7 UID SEARCH UNSEEN").await;
    wire.expect("* SEARCH").await;
    wire.expect("a7 OK UID SEARCH completed").await;

    // UTF-8 and US-ASCII are the searchable charsets; anything else
    // is refused with the response code naming what is.
    wire.send("a8 UID SEARCH CHARSET UTF-8 SEEN").await;
    wire.expect("* SEARCH 2 5").await;
    wire.expect("a8 OK UID SEARCH completed").await;
    wire.send("a9 UID SEARCH CHARSET KOI8-R SEEN").await;
    wire.expect("a9 NO [BADCHARSET (UTF-8)] charset not supported")
        .await;
    // A key the index cannot answer is a NO, a bare SEARCH a BAD.
    wire.send("b1 SEARCH BODY x").await;
    wire.expect("b1 NO search key not supported").await;
    wire.send("b2 SEARCH").await;
    wire.expect("b2 BAD invalid SEARCH").await;

    drop(wire);
    session.await.unwrap().unwrap();
}

#[tokio::test]
async fn state_inappropriate_commands_answer_bad() {
    let (mut wire, session, _) = spawn_session(backend(), 16).await;
    wire.expect(GREETING).await;

    // Nothing but the universal commands and LOGIN work pre-auth.
    for (tag, command) in [
        ("a1", "SELECT Inbox"),
        ("a2", "FETCH 1 (UID)"),
        ("a3", "SEARCH ALL"),
        ("a4", "CHECK"),
        ("a5", "CLOSE"),
        ("a6", "STATUS Inbox (MESSAGES)"),
        ("a7", "LIST \"\" \"*\""),
    ] {
        wire.send(&format!("{tag} {command}")).await;
        wire.expect(&format!("{tag} BAD command not valid in this state"))
            .await;
    }

    wire.send("a8 LOGIN user@example.invalid hunter2").await;
    wire.expect("a8 OK [CAPABILITY IMAP4rev1 IDLE ID] LOGIN completed")
        .await;

    // LOGIN again, or read the selected state without one.
    wire.send("a9 LOGIN user@example.invalid hunter2").await;
    wire.expect("a9 BAD command not valid in this state").await;
    wire.send("b1 FETCH 1 (UID)").await;
    wire.expect("b1 BAD command not valid in this state").await;

    drop(wire);
    session.await.unwrap().unwrap();
}

// ---------------------------------------------------------------------------
// Time bounds (paused clock: no test waits on a real timeout)
// ---------------------------------------------------------------------------

const TIMEOUT_BYE: &str = "* BYE idle for too long; closing connection";

#[tokio::test(start_paused = true)]
async fn an_unauthenticated_connection_is_closed_at_its_deadline() {
    let limits = SessionLimits::default();
    let allowed = limits.pre_auth_timeout;
    let (mut wire, session, _) = spawn_session_with(backend(), 16, limits).await;
    let started = Instant::now();
    wire.expect(GREETING).await;

    // Commands do not extend the deadline: it bounds the whole phase,
    // so a client trickling input gains nothing.
    tokio::time::sleep(allowed / 2).await;
    wire.send("a1 NOOP").await;
    wire.expect("a1 OK NOOP completed").await;
    wire.expect(TIMEOUT_BYE).await;
    assert_eq!(started.elapsed(), allowed);
    wire.expect_eof().await;
    session.await.unwrap().unwrap();
}

#[tokio::test(start_paused = true)]
async fn an_authenticated_session_times_out_only_after_long_inactivity() {
    let limits = SessionLimits::default();
    let (pre_auth, idle) = (limits.pre_auth_timeout, limits.idle_timeout);
    assert!(idle >= Duration::from_secs(30 * 60), "RFC 3501 §5.4");
    let (mut wire, session, _) = spawn_session_with(backend(), 16, limits).await;
    login(&mut wire).await;

    // Past the unauthenticated deadline the session is still served,
    // and every command restarts the inactivity clock.
    tokio::time::sleep(pre_auth * 2).await;
    wire.send("a2 NOOP").await;
    wire.expect("a2 OK NOOP completed").await;
    let last_command = Instant::now();
    wire.expect(TIMEOUT_BYE).await;
    assert_eq!(last_command.elapsed(), idle);
    wire.expect_eof().await;
    session.await.unwrap().unwrap();
}

#[tokio::test(start_paused = true)]
async fn idle_runs_for_the_inactivity_timeout_at_most() {
    let limits = SessionLimits::default();
    let idle = limits.idle_timeout;
    let scripted = backend();
    let (mut wire, session, sender) = spawn_session_with(Arc::clone(&scripted), 16, limits).await;
    login(&mut wire).await;
    select_inbox(&mut wire).await;
    wire.send("i1 IDLE").await;
    wire.expect("+ idling").await;
    let idling_since = Instant::now();

    // A 29-minute IDLE, as RFC 2177 clients run them, is never cut,
    // and updates keep flowing through it.
    tokio::time::sleep(Duration::from_secs(29 * 60)).await;
    scripted.add_message("Inbox", 4);
    sender.send(MailboxChanged(MailboxId(1))).unwrap();
    wire.expect("* 3 EXISTS").await;

    // Updates do not extend it: a client that never re-issues IDLE
    // is logged off when the timeout is reached.
    wire.expect(TIMEOUT_BYE).await;
    assert_eq!(idling_since.elapsed(), idle);
    wire.expect_eof().await;
    session.await.unwrap().unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_client_that_stops_reading_ends_its_session() {
    // More body than the 64 KiB duplex buffer holds, and a client that
    // never reads it: the write stalls, and the session ends on the
    // write timeout instead of staying parked forever.
    let scripted = Arc::new(
        FakeImapBackend::new(USER, PASSWORD)
            .with_mailbox(
                MailboxId(1),
                "Inbox",
                "",
                FakeSelected::new(7, 4, 1, vec![1, 3]),
            )
            .with_fetch(
                1,
                FakeFetched {
                    body: vec![b'x'; 200_000],
                    ..bare_fetch()
                },
            ),
    );
    let limits = SessionLimits::default();
    let allowed = limits.write_timeout;
    let (mut wire, session, _) = spawn_session_with(scripted, 16, limits).await;
    login(&mut wire).await;
    select_inbox(&mut wire).await;
    wire.send("a4 FETCH 1 (BODY.PEEK[])").await;
    let stalled_since = Instant::now();

    let outcome = session.await.unwrap();
    assert!(outcome.is_err(), "a stalled write must end the session");
    assert_eq!(stalled_since.elapsed(), allowed);
}

// ---------------------------------------------------------------------------
// Accept loop
// ---------------------------------------------------------------------------

/// An in-memory listener: the test hands it connections — or accept
/// errors — through a channel.
struct ChannelListener(mpsc::UnboundedReceiver<std::io::Result<DuplexStream>>);

impl Accept for ChannelListener {
    type Stream = DuplexStream;

    async fn accept(&mut self) -> std::io::Result<DuplexStream> {
        match self.0.recv().await {
            Some(accepted) => accepted,
            None => std::future::pending().await,
        }
    }
}

/// The accept loop over an in-memory listener, with the production
/// certificate machinery and a test-only accept-all TLS client.
struct ServeHarness {
    incoming: mpsc::UnboundedSender<std::io::Result<DuplexStream>>,
    connector: tokio_rustls::TlsConnector,
    _dir: tempfile::TempDir,
}

type TlsWire = Wire<
    tokio::io::ReadHalf<tokio_rustls::client::TlsStream<DuplexStream>>,
    tokio::io::WriteHalf<tokio_rustls::client::TlsStream<DuplexStream>>,
>;

impl ServeHarness {
    fn start(limits: ServeLimits) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let (cert_pem, key_pem) = ensure_certificate(dir.path()).unwrap();
        let tls = tls_acceptor(&cert_pem, &key_pem).unwrap();
        let (incoming, accepted) = mpsc::unbounded_channel();
        let (sender, _) = broadcast::channel(16);
        tokio::spawn(serve(
            ChannelListener(accepted),
            tls,
            backend() as Arc<dyn ImapBackend>,
            sender,
            limits,
        ));
        Self {
            incoming,
            connector: accept_all_connector(),
            _dir: dir,
        }
    }

    /// Hand the listener one connection and return the client's end.
    fn dial(&self) -> DuplexStream {
        let (client, server) = tokio::io::duplex(64 * 1024);
        self.incoming.send(Ok(server)).unwrap();
        client
    }

    /// Connect a TLS client and read the greeting.
    async fn connect(&self) -> TlsWire {
        greeted(self.connector.clone(), self.dial()).await
    }
}

/// Complete the TLS handshake over `stream` and read the greeting.
async fn greeted(connector: tokio_rustls::TlsConnector, stream: DuplexStream) -> TlsWire {
    let server_name = rustls::pki_types::ServerName::try_from("localhost".to_string()).unwrap();
    let tls_client = connector.connect(server_name, stream).await.unwrap();
    let (reader, writer) = split(tls_client);
    let mut wire = Wire {
        reader: BufReader::new(reader),
        writer,
    };
    wire.expect(GREETING).await;
    wire
}

#[tokio::test(start_paused = true)]
async fn a_failed_accept_does_not_end_the_accept_loop() {
    let limits = ServeLimits::default();
    let pause = limits.accept_retry_delay;
    let harness = ServeHarness::start(limits);

    // The listener fails twice — out of descriptors, say — and the
    // loop is still there for the next client, after one pause each.
    let started = Instant::now();
    for _ in 0..2 {
        harness
            .incoming
            .send(Err(std::io::Error::other("too many open files")))
            .unwrap();
    }
    let mut wire = harness.connect().await;
    assert_eq!(started.elapsed(), pause * 2);
    wire.send("a1 LOGOUT").await;
    wire.expect("* BYE tuta-bridge signing off").await;
    wire.expect("a1 OK LOGOUT completed").await;
}

#[tokio::test(start_paused = true)]
async fn a_silent_client_is_dropped_at_the_handshake_timeout() {
    let limits = ServeLimits::default();
    let allowed = limits.handshake_timeout;
    let harness = ServeHarness::start(limits);

    // Connected, and then nothing: no ClientHello ever arrives.
    let mut silent = harness.dial();
    let started = Instant::now();
    let mut probe = [0u8; 1];
    assert_eq!(silent.read(&mut probe).await.unwrap(), 0);
    assert_eq!(started.elapsed(), allowed);

    // The loop serves the next client as usual.
    harness.connect().await;
}

#[tokio::test(start_paused = true)]
async fn connections_beyond_the_cap_wait_for_a_free_slot() {
    let harness = ServeHarness::start(ServeLimits {
        max_connections: 2,
        ..ServeLimits::default()
    });
    let mut first = harness.connect().await;
    let _second = harness.connect().await;

    // A third client is not served while both slots are taken …
    let third = tokio::spawn(greeted(harness.connector.clone(), harness.dial()));
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert!(!third.is_finished(), "the cap must hold the third client");

    // … and is served as soon as one of them ends.
    first.send("a1 LOGOUT").await;
    first.expect("* BYE tuta-bridge signing off").await;
    first.expect("a1 OK LOGOUT completed").await;
    third.await.unwrap();
}

// ---------------------------------------------------------------------------
// TLS
// ---------------------------------------------------------------------------

/// A test-only verifier that accepts any server certificate. It lives
/// in this integration test on purpose: production code must never
/// disable certificate verification, and the listener binds loopback
/// only.
#[derive(Debug)]
struct AcceptAll(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AcceptAll {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// A TLS client configuration whose verifier is test-only accept-all.
fn accept_all_connector() -> tokio_rustls::TlsConnector {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAll(provider)))
        .with_no_client_auth();
    tokio_rustls::TlsConnector::from(Arc::new(config))
}

#[tokio::test]
async fn serves_a_full_client_round_over_tls() {
    // 1. The certificate machinery the serve path uses: a generated pair
    //    persisted under 0600, reused on the next call.
    let dir = tempfile::tempdir().unwrap();
    let (cert_pem, key_pem) = ensure_certificate(dir.path()).unwrap();
    let (cert_again, key_again) = ensure_certificate(dir.path()).unwrap();
    assert_eq!(cert_again, cert_pem);
    assert_eq!(key_again, key_pem);
    #[cfg(unix)]
    for name in ["imap-cert.pem", "imap-key.pem"] {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.path().join(name))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    // 2. The production acceptor and accept loop on an ephemeral
    //    loopback port.
    let tls = tls_acceptor(&cert_pem, &key_pem).unwrap();
    let body = b"Subject: hi\r\n\r\nhello over tls\r\n".to_vec();
    let scripted = Arc::new(
        FakeImapBackend::new(USER, PASSWORD)
            .with_mailbox(
                MailboxId(1),
                "Inbox",
                "",
                FakeSelected::new(7, 4, 1, vec![1]),
            )
            .with_fetch(
                1,
                FakeFetched {
                    flags: "\\Seen".into(),
                    internal_date: "\"14-Nov-2023 22:13:20 +0000\"".into(),
                    envelope: None,
                    bodystructure: None,
                    rfc822_size: Some(34),
                    body,
                },
            ),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (sender, _) = broadcast::channel(16);
    tokio::spawn(serve(
        listener,
        tls,
        Arc::clone(&scripted) as Arc<dyn ImapBackend>,
        sender,
        ServeLimits::default(),
    ));

    // 3. A TLS client whose verifier is test-only accept-all.
    let connector = accept_all_connector();
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let server_name = rustls::pki_types::ServerName::try_from("localhost".to_string()).unwrap();
    let tls_client = connector.connect(server_name, tcp).await.unwrap();
    let (reader, writer) = split(tls_client);
    let mut wire = Wire {
        reader: BufReader::new(reader),
        writer,
    };

    // 4. One LOGIN/LIST/SELECT/UID FETCH/LOGOUT round over real TLS.
    wire.expect(GREETING).await;
    wire.send("a1 LOGIN user@example.invalid hunter2").await;
    wire.expect(LOGIN_OK).await;
    wire.send("a2 LIST \"\" \"*\"").await;
    wire.expect("* LIST () \"/\" \"Inbox\"").await;
    wire.expect("a2 OK LIST completed").await;
    wire.send("a3 SELECT Inbox").await;
    expect_select_block(&mut wire, "a3", 1, Some(1), 7, 4, false).await;
    wire.send("a4 UID FETCH 1 (RFC822.SIZE BODY[])").await;
    let bytes = wire.literal("* 1 FETCH (RFC822.SIZE 34 BODY[] ").await;
    assert_eq!(bytes, b"Subject: hi\r\n\r\nhello over tls\r\n".to_vec());
    wire.expect(" UID 1)").await;
    wire.expect("a4 OK UID FETCH completed").await;
    wire.send("a5 LOGOUT").await;
    wire.expect("* BYE tuta-bridge signing off").await;
    wire.expect("a5 OK LOGOUT completed").await;
    wire.expect_eof().await;
}
