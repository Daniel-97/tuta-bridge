//! Integration contract for the SMTP submission session: EHLO, AUTH
//! PLAIN and LOGIN against the bridge password (and the failed-login
//! bound), the MAIL/RCPT/DATA sequence with dot-unstuffing, Bcc from the
//! envelope, the size limit, and how send failures map to replies —
//! against fakes over an in-memory duplex.

mod support;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use tokio::io::{split, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tuta_bridge::adapters::smtp::session::{run_smtp_session, SmtpLimits};
use tuta_bridge::domain::{Error, Result};
use tuta_bridge::ports::imap_backend::ImapBackend;
use tuta_bridge::ports::mail_sender::{MailSender, OutgoingMail};

use support::FakeImapBackend;

const USER: &str = "me@tuta.example";
const PASSWORD: &str = "hunter2";

/// Records every mail; can fail like Tuta being unreachable.
#[derive(Default)]
struct FakeSender {
    sent: Mutex<Vec<OutgoingMail>>,
    failing: Mutex<Option<Error>>,
}

#[async_trait::async_trait]
impl MailSender for FakeSender {
    async fn send(&self, mail: &OutgoingMail) -> Result<()> {
        if let Some(error) = self.failing.lock().unwrap().take() {
            return Err(error);
        }
        self.sent.lock().unwrap().push(mail.clone());
        Ok(())
    }
}

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
        String::from_utf8_lossy(&buf)
            .trim_end_matches("\r\n")
            .to_string()
    }

    async fn expect(&mut self, expected: &str) {
        assert_eq!(self.line().await, expected);
    }

    async fn expect_eof(&mut self) {
        let mut probe = [0u8; 1];
        assert_eq!(self.reader.read(&mut probe).await.unwrap(), 0);
    }
}

async fn spawn(sender: Arc<FakeSender>) -> (Wire, tokio::task::JoinHandle<Result<()>>) {
    let backend = Arc::new(FakeImapBackend::new(USER, PASSWORD));
    let (client, server) = tokio::io::duplex(256 * 1024);
    let limits = SmtpLimits {
        login_failure_delay: Duration::from_millis(1),
        max_message_bytes: 4096,
        ..SmtpLimits::default()
    };
    let session = tokio::spawn(run_smtp_session(
        server,
        backend as Arc<dyn ImapBackend>,
        sender as Arc<dyn MailSender>,
        limits,
    ));
    let (reader, writer) = split(client);
    let mut wire = Wire {
        reader: BufReader::new(reader),
        writer,
    };
    wire.expect("220 tuta-bridge ESMTP ready").await;
    (wire, session)
}

async fn ehlo(wire: &mut Wire) {
    wire.send("EHLO client.example").await;
    for line in [
        "250-tuta-bridge",
        "250-SIZE 4096",
        "250-8BITMIME",
        "250-ENHANCEDSTATUSCODES",
        "250 AUTH PLAIN LOGIN",
    ] {
        wire.expect(line).await;
    }
}

async fn auth_plain(wire: &mut Wire) {
    let token = BASE64.encode(format!("\0{USER}\0{PASSWORD}"));
    wire.send(&format!("AUTH PLAIN {token}")).await;
    wire.expect("235 2.7.0 authentication succeeded").await;
}

#[tokio::test]
async fn submits_a_mail_with_bcc_from_the_envelope() {
    let sender = Arc::new(FakeSender::default());
    let (mut wire, session) = spawn(Arc::clone(&sender)).await;
    ehlo(&mut wire).await;
    auth_plain(&mut wire).await;

    wire.send("MAIL FROM:<me@tuta.example> SIZE=300").await;
    wire.expect("250 2.1.0 ok").await;
    wire.send("RCPT TO:<ann@x.example>").await;
    wire.expect("250 2.1.5 ok").await;
    wire.send("RCPT TO:<hidden@z.example>").await;
    wire.expect("250 2.1.5 ok").await;
    wire.send("DATA").await;
    wire.expect("354 end data with <CR><LF>.<CR><LF>").await;
    for line in [
        "From: Me <me@tuta.example>",
        "To: Ann <ann@x.example>",
        "Subject: hello",
        "",
        "first",
        "..starts with a dot",
        ".",
    ] {
        wire.send(line).await;
    }
    wire.expect("250 2.0.0 message sent").await;

    wire.send("QUIT").await;
    wire.expect("221 2.0.0 tuta-bridge closing").await;
    wire.expect_eof().await;
    session.await.unwrap().unwrap();

    let sent = sender.sent.lock().unwrap();
    assert_eq!(sent.len(), 1);
    let mail = &sent[0];
    assert_eq!(mail.from.address, "me@tuta.example");
    assert_eq!(mail.to[0].address, "ann@x.example");
    assert_eq!(mail.bcc[0].address, "hidden@z.example");
    assert_eq!(mail.subject, "hello");
    assert_eq!(mail.html_body, "first<br>\n.starts with a dot<br>\n");
}

#[tokio::test]
async fn auth_login_works_and_mail_needs_auth() {
    let sender = Arc::new(FakeSender::default());
    let (mut wire, session) = spawn(sender).await;
    ehlo(&mut wire).await;

    wire.send("MAIL FROM:<me@tuta.example>").await;
    wire.expect("530 5.7.0 authentication required").await;

    wire.send("AUTH LOGIN").await;
    wire.expect("334 VXNlcm5hbWU6").await;
    wire.send(&BASE64.encode(USER)).await;
    wire.expect("334 UGFzc3dvcmQ6").await;
    wire.send(&BASE64.encode(PASSWORD)).await;
    wire.expect("235 2.7.0 authentication succeeded").await;

    wire.send("RCPT TO:<a@b.example>").await;
    wire.expect("503 5.5.1 send MAIL first").await;
    wire.send("MAIL FROM:<me@tuta.example>").await;
    wire.expect("250 2.1.0 ok").await;
    wire.send("DATA").await;
    wire.expect("554 5.5.1 no valid recipients").await;
    wire.send("RSET").await;
    wire.expect("250 2.0.0 ok").await;
    wire.send("FROB").await;
    wire.expect("502 5.5.1 command not implemented").await;

    wire.send("QUIT").await;
    wire.expect("221 2.0.0 tuta-bridge closing").await;
    session.await.unwrap().unwrap();
}

#[tokio::test]
async fn failed_logins_are_bounded() {
    let (mut wire, session) = spawn(Arc::new(FakeSender::default())).await;
    ehlo(&mut wire).await;
    let wrong = BASE64.encode(format!("\0{USER}\0wrong"));
    for _ in 0..3 {
        wire.send(&format!("AUTH PLAIN {wrong}")).await;
        wire.expect("535 5.7.8 authentication failed").await;
    }
    wire.expect("421 4.7.0 too many failed logins").await;
    wire.expect_eof().await;
    session.await.unwrap().unwrap();
}

#[tokio::test]
async fn oversized_and_failed_messages_get_their_replies() {
    let sender = Arc::new(FakeSender::default());
    let (mut wire, session) = spawn(Arc::clone(&sender)).await;
    ehlo(&mut wire).await;
    auth_plain(&mut wire).await;

    wire.send("MAIL FROM:<me@tuta.example> SIZE=999999").await;
    wire.expect("552 5.3.4 message size exceeds the limit")
        .await;

    // Too large while streaming: read to the dot, then refuse.
    wire.send("MAIL FROM:<me@tuta.example>").await;
    wire.expect("250 2.1.0 ok").await;
    wire.send("RCPT TO:<a@b.example>").await;
    wire.expect("250 2.1.5 ok").await;
    wire.send("DATA").await;
    wire.expect("354 end data with <CR><LF>.<CR><LF>").await;
    wire.send("From: me@tuta.example").await;
    wire.send("").await;
    for _ in 0..100 {
        wire.send(&"x".repeat(80)).await;
    }
    wire.send(".").await;
    wire.expect("552 5.3.4 message size exceeds the limit")
        .await;

    // Tuta unreachable: a transient 451, so the client retries.
    *sender.failing.lock().unwrap() = Some(Error::Network("tuta send failed".into()));
    wire.send("MAIL FROM:<me@tuta.example>").await;
    wire.expect("250 2.1.0 ok").await;
    wire.send("RCPT TO:<a@b.example>").await;
    wire.expect("250 2.1.5 ok").await;
    wire.send("DATA").await;
    wire.expect("354 end data with <CR><LF>.<CR><LF>").await;
    for line in ["From: me@tuta.example", "To: a@b.example", "", "hi", "."] {
        wire.send(line).await;
    }
    wire.expect("451 4.4.0 tuta send failed").await;

    // A message without From is refused for good.
    wire.send("MAIL FROM:<me@tuta.example>").await;
    wire.expect("250 2.1.0 ok").await;
    wire.send("RCPT TO:<a@b.example>").await;
    wire.expect("250 2.1.5 ok").await;
    wire.send("DATA").await;
    wire.expect("354 end data with <CR><LF>.<CR><LF>").await;
    for line in ["To: a@b.example", "", "hi", "."] {
        wire.send(line).await;
    }
    wire.expect("554 5.6.0 message has no From header").await;

    assert!(sender.sent.lock().unwrap().is_empty());
    wire.send("QUIT").await;
    wire.expect("221 2.0.0 tuta-bridge closing").await;
    session.await.unwrap().unwrap();
}
