//! Integration contract for the POP3 session: the exact wire bytes of
//! the greeting, CAPA, USER/PASS (and the failed-login bound), STAT,
//! LIST, UIDL (stable across sessions), RETR with byte-stuffing, TOP,
//! the refused DELE, and QUIT — all against the scripted fake backend
//! over an in-memory duplex.

mod support;

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{split, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tuta_bridge::adapters::pop3::session::{run_pop3_session, Pop3Limits};
use tuta_bridge::domain::{MailboxId, Result};
use tuta_bridge::ports::imap_backend::ImapBackend;

use support::{FakeFetched, FakeImapBackend, FakeSelected};

const USER: &str = "user@example.invalid";
const PASSWORD: &str = "hunter2";

struct Wire {
    reader: BufReader<tokio::io::ReadHalf<tokio::io::DuplexStream>>,
    writer: tokio::io::WriteHalf<tokio::io::DuplexStream>,
}

impl Wire {
    async fn send(&mut self, line: &str) {
        self.writer.write_all(line.as_bytes()).await.unwrap();
        self.writer.write_all(b"\r\n").await.unwrap();
        self.writer.flush().await.unwrap();
    }

    async fn line(&mut self) -> String {
        let mut buf = Vec::new();
        let read = self.reader.read_until(b'\n', &mut buf).await.unwrap();
        assert!(read > 0, "the session closed the stream unexpectedly");
        let text = String::from_utf8_lossy(&buf).into_owned();
        assert!(
            text.ends_with("\r\n"),
            "every line ends with CRLF: {text:?}"
        );
        text.trim_end_matches("\r\n").to_string()
    }

    async fn expect(&mut self, expected: &str) {
        assert_eq!(self.line().await, expected);
    }

    async fn expect_eof(&mut self) {
        let mut probe = [0u8; 1];
        assert_eq!(self.reader.read(&mut probe).await.unwrap(), 0);
    }
}

fn message(subject: &str) -> Vec<u8> {
    format!("Subject: {subject}\r\nFrom: a@example.invalid\r\n\r\nline one\r\n.dot line\r\nline three\r\n")
        .into_bytes()
}

fn fetched(body: Vec<u8>) -> FakeFetched {
    FakeFetched {
        flags: String::new(),
        internal_date: "\"01-Jan-2024 00:00:00 +0000\"".into(),
        envelope: None,
        bodystructure: None,
        rfc822_size: Some(body.len() as u64),
        body,
    }
}

fn backend() -> Arc<FakeImapBackend> {
    Arc::new(
        FakeImapBackend::new(USER, PASSWORD)
            .with_mailbox(
                MailboxId(1),
                "Inbox",
                "",
                FakeSelected::new(7, 4, 1, vec![1, 3]),
            )
            .with_fetch(1, fetched(message("first")))
            .with_fetch(3, fetched(message("second"))),
    )
}

fn fast_limits() -> Pop3Limits {
    Pop3Limits {
        login_failure_delay: Duration::from_millis(1),
        ..Pop3Limits::default()
    }
}

async fn spawn(backend: Arc<FakeImapBackend>) -> (Wire, tokio::task::JoinHandle<Result<()>>) {
    let (client, server) = tokio::io::duplex(64 * 1024);
    let session = tokio::spawn(run_pop3_session(
        server,
        backend as Arc<dyn ImapBackend>,
        fast_limits(),
    ));
    let (reader, writer) = split(client);
    let mut wire = Wire {
        reader: BufReader::new(reader),
        writer,
    };
    wire.expect("+OK tuta-bridge POP3 ready").await;
    (wire, session)
}

async fn login(wire: &mut Wire) {
    wire.send(&format!("USER {USER}")).await;
    wire.expect("+OK send PASS").await;
    wire.send(&format!("PASS {PASSWORD}")).await;
    wire.expect("+OK maildrop has 2 messages").await;
}

#[tokio::test]
async fn capa_lists_the_supported_extensions() {
    let (mut wire, session) = spawn(backend()).await;
    wire.send("CAPA").await;
    wire.expect("+OK capability list follows").await;
    for line in [
        "USER",
        "UIDL",
        "TOP",
        "RESP-CODES",
        "EXPIRE NEVER",
        "IMPLEMENTATION tuta-bridge",
        ".",
    ] {
        wire.expect(line).await;
    }
    wire.send("QUIT").await;
    wire.expect("+OK tuta-bridge signing off").await;
    wire.expect_eof().await;
    session.await.unwrap().unwrap();
}

#[tokio::test]
async fn transaction_commands_need_a_login() {
    let (mut wire, session) = spawn(backend()).await;
    wire.send("STAT").await;
    wire.expect("-ERR unknown command or wrong state").await;
    wire.send("PASS hunter2").await;
    wire.expect("-ERR send USER first").await;
    wire.send("QUIT").await;
    wire.expect("+OK tuta-bridge signing off").await;
    session.await.unwrap().unwrap();
}

#[tokio::test]
async fn stat_list_and_uidl_describe_the_inbox() {
    let (mut wire, session) = spawn(backend()).await;
    login(&mut wire).await;
    let (first, second) = (message("first").len(), message("second").len());

    wire.send("STAT").await;
    wire.expect(&format!("+OK 2 {}", first + second)).await;

    wire.send("LIST").await;
    wire.expect("+OK 2 messages").await;
    wire.expect(&format!("1 {first}")).await;
    wire.expect(&format!("2 {second}")).await;
    wire.expect(".").await;

    wire.send("LIST 2").await;
    wire.expect(&format!("+OK 2 {second}")).await;
    wire.send("LIST 9").await;
    wire.expect("-ERR no such message").await;

    // Unique ids are UIDVALIDITY.UID: stable across sessions.
    wire.send("UIDL").await;
    wire.expect("+OK unique-id listing follows").await;
    wire.expect("1 7.1").await;
    wire.expect("2 7.3").await;
    wire.expect(".").await;
    wire.send("UIDL 2").await;
    wire.expect("+OK 2 7.3").await;

    wire.send("QUIT").await;
    wire.expect("+OK tuta-bridge signing off").await;
    session.await.unwrap().unwrap();
}

#[tokio::test]
async fn retr_byte_stuffs_and_top_cuts_the_body() {
    let (mut wire, session) = spawn(backend()).await;
    login(&mut wire).await;

    wire.send("RETR 1").await;
    wire.expect(&format!("+OK {} octets", message("first").len()))
        .await;
    for line in [
        "Subject: first",
        "From: a@example.invalid",
        "",
        "line one",
        "..dot line",
        "line three",
        ".",
    ] {
        wire.expect(line).await;
    }

    wire.send("TOP 2 1").await;
    wire.expect("+OK top of message follows").await;
    for line in [
        "Subject: second",
        "From: a@example.invalid",
        "",
        "line one",
        ".",
    ] {
        wire.expect(line).await;
    }

    wire.send("RETR 0").await;
    wire.expect("-ERR invalid message number").await;
    wire.send("RETR 5").await;
    wire.expect("-ERR no such message").await;

    wire.send("QUIT").await;
    wire.expect("+OK tuta-bridge signing off").await;
    session.await.unwrap().unwrap();
}

#[tokio::test]
async fn dele_is_refused_and_nothing_is_written() {
    let fake = backend();
    let (mut wire, session) = spawn(Arc::clone(&fake)).await;
    login(&mut wire).await;
    wire.send("DELE 1").await;
    wire.expect("-ERR DELE is not supported; mail stays on the server")
        .await;
    wire.send("RSET").await;
    wire.expect("+OK").await;
    wire.send("NOOP").await;
    wire.expect("+OK").await;
    wire.send("QUIT").await;
    wire.expect("+OK tuta-bridge signing off").await;
    session.await.unwrap().unwrap();
    assert!(fake.writes().is_empty());
}

#[tokio::test]
async fn failed_logins_are_bounded() {
    let (mut wire, session) = spawn(backend()).await;
    for _ in 0..3 {
        wire.send(&format!("USER {USER}")).await;
        wire.expect("+OK send PASS").await;
        wire.send("PASS wrong").await;
        wire.expect("-ERR [AUTH] authentication failed").await;
    }
    wire.expect_eof().await;
    session.await.unwrap().unwrap();
}

#[tokio::test]
async fn a_resync_mid_session_ends_it_instead_of_renumbering() {
    let fake = backend();
    let (mut wire, session) = spawn(Arc::clone(&fake)).await;
    login(&mut wire).await;
    fake.resync("Inbox", 8);
    wire.send("RETR 1").await;
    wire.expect("-ERR [SYS/TEMP] mailbox was resynced; reconnect")
        .await;
    wire.expect_eof().await;
    session.await.unwrap().unwrap();
}

#[tokio::test]
async fn a_vanished_message_leaves_list_stat_and_uidl_alike() {
    let fake = backend();
    let (mut wire, session) = spawn(Arc::clone(&fake)).await;
    login(&mut wire).await;
    fake.remove_message("Inbox", 1);
    let second = message("second").len();

    wire.send("STAT").await;
    wire.expect(&format!("+OK 1 {second}")).await;
    wire.send("LIST").await;
    wire.expect("+OK 1 messages").await;
    wire.expect(&format!("2 {second}")).await;
    wire.expect(".").await;
    wire.send("UIDL").await;
    wire.expect("+OK unique-id listing follows").await;
    wire.expect("2 7.3").await;
    wire.expect(".").await;
    wire.send("UIDL 1").await;
    wire.expect("-ERR no such message").await;

    wire.send("QUIT").await;
    wire.expect("+OK tuta-bridge signing off").await;
    session.await.unwrap().unwrap();
}

#[tokio::test]
async fn one_unloadable_size_does_not_fail_the_listing() {
    let fake = Arc::new(
        FakeImapBackend::new(USER, PASSWORD)
            .with_mailbox(
                MailboxId(1),
                "Inbox",
                "",
                FakeSelected::new(7, 4, 1, vec![1, 3]),
            )
            .with_fetch(3, fetched(message("second")))
            .with_failing_fetch(1),
    );
    let (mut wire, session) = spawn(fake).await;
    login(&mut wire).await;
    wire.send("LIST").await;
    wire.expect("+OK 1 messages").await;
    wire.expect(&format!("2 {}", message("second").len())).await;
    wire.expect(".").await;
    wire.send("QUIT").await;
    wire.expect("+OK tuta-bridge signing off").await;
    session.await.unwrap().unwrap();
}

#[tokio::test]
async fn an_unauthenticated_connection_is_closed_at_its_deadline() {
    let (client, server) = tokio::io::duplex(64 * 1024);
    let limits = Pop3Limits {
        pre_auth_timeout: Duration::from_millis(50),
        ..fast_limits()
    };
    let session = tokio::spawn(run_pop3_session(
        server,
        backend() as Arc<dyn ImapBackend>,
        limits,
    ));
    let (reader, writer) = split(client);
    let mut wire = Wire {
        reader: BufReader::new(reader),
        writer,
    };
    wire.expect("+OK tuta-bridge POP3 ready").await;
    // Trickling commands does not extend the pre-auth phase.
    wire.send("CAPA").await;
    for _ in 0..8 {
        wire.line().await;
    }
    wire.expect("-ERR autologout; idle for too long").await;
    wire.expect_eof().await;
    session.await.unwrap().unwrap();
}
