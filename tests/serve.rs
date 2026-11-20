//! Integration contract for the `serve` use case.
//!
//! One process runs both loops: the watch loop, against a scripted
//! event session whose stream never resolves, and the IMAP listener,
//! real loopback TLS over an ephemeral certificate. The client round
//! proves the served state comes from the seeded store — LOGIN, LIST,
//! SELECT INBOX, UID FETCH ENVELOPE, LOGOUT — and the stop channel
//! proves serve shuts down cleanly. Two failure tests pin the fixed
//! refusals: a missing bridge password and a reserved port, both
//! raised before anything listens.

mod support;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use secrecy::{ExposeSecret, SecretString};
use tokio::io::{split, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::sync::oneshot;
use tuta_bridge::adapters::tuta::generated_id::timestamp_to_generated_id;
use tuta_bridge::app::watch::{BackoffPolicy, ServeUseCase};
use tuta_bridge::config::Config;
use tuta_bridge::domain::{
    AccountInfo, Address, Error, Folder, FolderKind, MessageHeader, MessageSummary, Result,
    StoredCredentials,
};
use tuta_bridge::ports::clock::Clock;
use tuta_bridge::ports::credentials::CredentialStore;
use tuta_bridge::ports::local_password::LocalPasswordStore;
use tuta_bridge::ports::session::{NewSession, Session, SessionFactory, SessionRequest};
use tuta_bridge::ports::state_store::StateStore;

use support::{
    FakeEventSession, FakeEventSessionHandle, FakeMailSource, FakeStateStore, FakeStore,
};

const LOGIN: &str = "owner@example.invalid";
const BRIDGE_PASSWORD: &str = "bridge-hunter2";
/// Fixed instant for the expiry decisions the watch baseline makes.
const NOW_MS: i64 = 2_000_000_000_000;

const GREETING: &str = "* OK [CAPABILITY IMAP4rev1 IDLE ID MOVE] tuta-bridge ready";
const LOGIN_OK: &str = "a1 OK [CAPABILITY IMAP4rev1 IDLE ID MOVE] LOGIN completed";
/// ENVELOPE of the seeded partial header: NIL date (no `sent_at_ms`),
/// the one sender tripled into from/sender/reply-to, no recipients.
const ENVELOPE: &str = "(NIL \"subject\" ((NIL NIL \"sender\" \"example.invalid\")) ((NIL NIL \"sender\" \"example.invalid\")) ((NIL NIL \"sender\" \"example.invalid\")) NIL NIL NIL NIL NIL)";

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

/// A clock pinned to [`NOW_MS`].
struct FakeClock(i64);

impl Clock for FakeClock {
    fn now_ms(&self) -> i64 {
        self.0
    }
}

/// Hands out handles to one shared scripted session on every resume;
/// serve and its watch task each resume once.
struct FakeEventFactory {
    session: Arc<FakeEventSession>,
}

#[async_trait::async_trait]
impl SessionFactory for FakeEventFactory {
    async fn create(&self, _request: SessionRequest) -> Result<NewSession> {
        Err(Error::Unsupported("serve never creates a session".into()))
    }

    async fn resume(&self, _credentials: &StoredCredentials) -> Result<Box<dyn Session>> {
        Ok(Box::new(FakeEventSessionHandle(Arc::clone(&self.session))))
    }
}

/// In-memory bridge password store: the secret in a mutex.
struct FakePasswordStore {
    stored: Mutex<Option<String>>,
}

impl FakePasswordStore {
    fn with(password: &str) -> Self {
        Self {
            stored: Mutex::new(Some(password.to_string())),
        }
    }

    fn empty() -> Self {
        Self {
            stored: Mutex::new(None),
        }
    }
}

#[async_trait::async_trait]
impl LocalPasswordStore for FakePasswordStore {
    async fn set(&self, password: &SecretString) -> Result<()> {
        *self.stored.lock().unwrap() = Some(password.expose_secret().to_string());
        Ok(())
    }

    async fn load(&self) -> Result<Option<SecretString>> {
        Ok(self
            .stored
            .lock()
            .unwrap()
            .clone()
            .map(|password| SecretString::new(password.into())))
    }
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// Credentials store holding one dummy credential set.
fn fake_credentials() -> Arc<FakeStore> {
    let store = Arc::new(FakeStore::new());
    *store.load_result.lock().unwrap() = Some(StoredCredentials {
        login: LOGIN.to_string(),
        user_id: "u1".to_string(),
        access_token: "token".to_string(),
        encrypted_passphrase_key: vec![1],
    });
    store
}

fn account_info() -> AccountInfo {
    AccountInfo {
        mail_address: LOGIN.to_string(),
        user_id: "u1".to_string(),
    }
}

/// A partial header as the sync stores it: one sender, unread, no
/// envelope fields beyond the list-level ones.
fn header() -> MessageHeader {
    MessageHeader {
        list_id: "mail-list".to_string(),
        element_id: "e1".to_string(),
        received_at_ms: 1_700_000_000_000,
        sent_at_ms: 0,
        subject: "subject".to_string(),
        from: Address {
            name: None,
            address: "sender@example.invalid".to_string(),
        },
        to: Vec::new(),
        cc: Vec::new(),
        bcc: Vec::new(),
        reply_to: Vec::new(),
        unread: true,
        message_id: None,
        in_reply_to: None,
        references: Vec::new(),
        envelope_complete: false,
    }
}

fn inbox() -> Folder {
    Folder {
        list_id: "inbox-list".to_string(),
        name: "Inbox".to_string(),
        kind: FolderKind::Inbox,
    }
}

/// A scripted session subscribed to one group whose event stream never
/// resolves: the watch loop stays quiet and only the stop channel can
/// end it. The shared mail source carries one folder and one message.
fn event_session() -> Arc<FakeEventSession> {
    let mut mail = FakeMailSource::new();
    mail.folders.push(inbox());
    mail.messages.push(MessageSummary {
        list_id: "mail-list".to_string(),
        element_id: "e1".to_string(),
        received_at_ms: 1_700_000_000_000,
        subject: "subject".to_string(),
        unread: true,
    });
    let mail = Arc::new(mail);
    let session = Arc::new(
        FakeEventSession::new(account_info(), vec!["group1".to_string()])
            .with_mail(Arc::clone(&mail)),
    );
    session.push_pending();
    session
}

/// One mailbox (uidvalidity 7), one message (uid 1), and a current
/// marker for the group — the watch baseline finds nothing to sync.
async fn seeded_state() -> Arc<FakeStateStore> {
    let state = Arc::new(FakeStateStore::new());
    let account_id = state.upsert_account(LOGIN).await.unwrap();
    let mailbox = state.upsert_mailbox(account_id, &inbox(), 7).await.unwrap();
    state.assign_uid(mailbox, &header()).await.unwrap();
    state
        .set_last_batch(
            account_id,
            "group1",
            &timestamp_to_generated_id(NOW_MS - 5_000),
        )
        .await
        .unwrap();
    state
}

/// Write a temp config naming `imap_port` for the active account.
fn temp_config(port: u16) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    Config {
        active_account: Some(LOGIN.to_string()),
        base_url: "http://127.0.0.1:9".to_string(),
        imap_port: Some(port),
        pop3_port: None,
        smtp_port: None,
        carddav_port: None,
    }
    .save(&path)
    .unwrap();
    (dir, path)
}

/// A free loopback port, reserved by a bound-and-dropped listener.
///
/// serve rejects port 0 by design, so the test cannot ask the kernel
/// for an ephemeral port through serve itself.
fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

/// Build the use case around the fakes: zero backoff (an immediate
/// retry if the script reconnects) and a generous connect timeout.
fn serve_use_case(
    session: &Arc<FakeEventSession>,
    credentials: Arc<FakeStore>,
    passwords: Arc<FakePasswordStore>,
    config_path: PathBuf,
    state: Arc<FakeStateStore>,
    data_dir: &Path,
) -> ServeUseCase {
    ServeUseCase {
        factory: Arc::new(FakeEventFactory {
            session: Arc::clone(session),
        }) as Arc<dyn SessionFactory>,
        credentials: credentials as Arc<dyn CredentialStore>,
        passwords: passwords as Arc<dyn LocalPasswordStore>,
        config_path,
        state: state as Arc<dyn StateStore>,
        clock: Arc::new(FakeClock(NOW_MS)),
        data_dir: data_dir.to_path_buf(),
        backoff: BackoffPolicy {
            first_ms: 0,
            second_ms: 0,
            max_ms: 0,
        },
        connect_timeout: Duration::from_secs(5),
        lookup_failure_threshold: 10,
    }
}

// ---------------------------------------------------------------------------
// Wire
// ---------------------------------------------------------------------------

/// Line-oriented client over one half of a split stream.
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

    async fn expect_eof(&mut self) {
        let mut probe = [0u8; 1];
        let read = self.reader.read(&mut probe).await.unwrap();
        assert_eq!(read, 0, "expected the session to close the stream");
    }
}

// ---------------------------------------------------------------------------
// TLS client
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

/// Connect a TLS client to the serve listener on `port`, retrying
/// until serve has opened the listener.
async fn tls_client(
    port: u16,
) -> Wire<
    tokio::io::ReadHalf<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>,
    tokio::io::WriteHalf<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>,
> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAll(provider)))
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));

    let mut tcp = None;
    for _ in 0..400 {
        if let Ok(stream) = tokio::net::TcpStream::connect(("127.0.0.1", port)).await {
            tcp = Some(stream);
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let tcp = tcp.expect("serve never opened the listener");
    let server_name = rustls::pki_types::ServerName::try_from("localhost".to_string()).unwrap();
    let tls = connector.connect(server_name, tcp).await.unwrap();
    let (reader, writer) = split(tls);
    Wire {
        reader: BufReader::new(reader),
        writer,
    }
}

// ---------------------------------------------------------------------------
// The command
// ---------------------------------------------------------------------------

#[tokio::test]
async fn serve_logs_in_lists_and_fetches_end_to_end() {
    let port = free_port();
    let (_config_dir, config_path) = temp_config(port);
    let cert_dir = tempfile::tempdir().unwrap();
    let state = seeded_state().await;
    let session = event_session();

    let uc = serve_use_case(
        &session,
        fake_credentials(),
        Arc::new(FakePasswordStore::with(BRIDGE_PASSWORD)),
        config_path,
        state,
        cert_dir.path(),
    );
    let (stop_serve, stop_rx) = oneshot::channel::<()>();
    let serve_task = tokio::spawn(async move {
        uc.run_until(async move {
            let _ = stop_rx.await;
        })
        .await
    });

    let mut wire = tls_client(port).await;

    // LOGIN against the bridge password, then the served index: LIST
    // from the store, SELECT resolving INBOX by kind, ENVELOPE from
    // the stored partial header — no source call, no enrichment.
    wire.expect(GREETING).await;
    wire.send(&format!("a1 LOGIN {LOGIN} {BRIDGE_PASSWORD}"))
        .await;
    wire.expect(LOGIN_OK).await;

    wire.send("a2 LIST \"\" \"*\"").await;
    wire.expect("* LIST () \"/\" \"Inbox\"").await;
    wire.expect("a2 OK LIST completed").await;

    wire.send("a3 SELECT INBOX").await;
    wire.expect("* FLAGS (\\Seen \\Deleted)").await;
    wire.expect("* 1 EXISTS").await;
    wire.expect("* 0 RECENT").await;
    wire.expect("* OK [UNSEEN 1]").await;
    wire.expect("* OK [PERMANENTFLAGS (\\Seen)] Flags permitted")
        .await;
    wire.expect("* OK [UIDVALIDITY 7]").await;
    wire.expect("* OK [UIDNEXT 2]").await;
    wire.expect("a3 OK [READ-WRITE] SELECT completed").await;

    wire.send("a4 UID FETCH 1 (ENVELOPE)").await;
    wire.expect(&format!("* 1 FETCH (ENVELOPE {ENVELOPE} UID 1)"))
        .await;
    wire.expect("a4 OK UID FETCH completed").await;

    // The write seam reaches serve through Session::shared_writer: a
    // STORE goes to the session's writer and answers the new flags.
    wire.send("a6 UID STORE 1 +FLAGS (\\Seen)").await;
    wire.expect("* 1 FETCH (FLAGS (\\Seen) UID 1)").await;
    wire.expect("a6 OK UID STORE completed").await;
    assert_eq!(session.writer.calls().len(), 1);

    wire.send("a5 LOGOUT").await;
    wire.expect("* BYE tuta-bridge signing off").await;
    wire.expect("a5 OK LOGOUT completed").await;
    wire.expect_eof().await;
    drop(wire);

    // The watch task ran alongside: it reached the scripted event bus
    // exactly once, and the pending stream kept it quiet.
    assert_eq!(session.events_calls(), 1);

    // The stop channel ends the watch loop, serve collects its result,
    // and the command returns Ok.
    stop_serve.send(()).unwrap();
    let result = serve_task.await.unwrap();
    assert!(result.is_ok(), "serve ended with {result:?}");
}

#[tokio::test]
async fn serve_refuses_to_start_without_a_password() {
    let port = free_port();
    let (_config_dir, config_path) = temp_config(port);
    let cert_dir = tempfile::tempdir().unwrap();
    let session = event_session();

    let uc = serve_use_case(
        &session,
        fake_credentials(),
        Arc::new(FakePasswordStore::empty()),
        config_path,
        seeded_state().await,
        cert_dir.path(),
    );
    let result = uc
        .run_until(std::future::pending::<()>())
        .await
        .expect_err("serve must refuse without a bridge password");
    assert!(matches!(
        result,
        Error::Config(message)
            if message == "local IMAP password not set; run tuta-bridge passwd first"
    ));
    // Nothing was provisioned: the failure precedes the certificate
    // and the listener.
    assert!(!cert_dir.path().join("imap-cert.pem").exists());
}

#[tokio::test]
async fn serve_refuses_a_reserved_port() {
    // Port 0 is reserved: serve fails with the fixed message instead
    // of silently binding an ephemeral port.
    let (_config_dir, config_path) = temp_config(0);
    let cert_dir = tempfile::tempdir().unwrap();
    let session = event_session();
    let credentials = fake_credentials();

    let uc = serve_use_case(
        &session,
        Arc::clone(&credentials),
        Arc::new(FakePasswordStore::with(BRIDGE_PASSWORD)),
        config_path,
        seeded_state().await,
        cert_dir.path(),
    );
    let result = uc
        .run_until(std::future::pending::<()>())
        .await
        .expect_err("serve must refuse a reserved port");
    assert!(matches!(
        result,
        Error::Config(message) if message == "imap_port must be between 1 and 65535"
    ));
    // Validation runs first: no credentials were read and nothing was
    // provisioned.
    assert!(!credentials
        .calls
        .lock()
        .unwrap()
        .iter()
        .any(|call| call == "load"));
    assert!(!cert_dir.path().join("imap-cert.pem").exists());
}

// ---------------------------------------------------------------------------
// CardDAV
// ---------------------------------------------------------------------------

/// A config with IMAP on `port` and CardDAV on `carddav_port`.
fn carddav_config(port: u16, carddav_port: u16) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    Config {
        active_account: Some(LOGIN.to_string()),
        base_url: "http://127.0.0.1:9".to_string(),
        imap_port: Some(port),
        pop3_port: None,
        smtp_port: None,
        carddav_port: Some(carddav_port),
    }
    .save(&path)
    .unwrap();
    (dir, path)
}

/// SQLite state (the only store with a contact cache) seeded like
/// [`seeded_state`], so the watch baseline finds nothing to sync.
async fn seeded_sqlite_state() -> Arc<dyn StateStore> {
    let state = tuta_bridge::adapters::sqlite_state::SqliteStateStore::open_in_memory()
        .await
        .unwrap();
    let account_id = state.upsert_account(LOGIN).await.unwrap();
    let mailbox = state.upsert_mailbox(account_id, &inbox(), 7).await.unwrap();
    state.assign_uid(mailbox, &header()).await.unwrap();
    state
        .set_last_batch(
            account_id,
            "group1",
            &timestamp_to_generated_id(NOW_MS - 5_000),
        )
        .await
        .unwrap();
    Arc::new(state)
}

fn serve_with_state(
    session: &Arc<FakeEventSession>,
    config_path: PathBuf,
    state: Arc<dyn StateStore>,
    data_dir: &Path,
) -> ServeUseCase {
    ServeUseCase {
        state,
        ..serve_use_case(
            session,
            fake_credentials(),
            Arc::new(FakePasswordStore::with(BRIDGE_PASSWORD)),
            config_path,
            Arc::new(FakeStateStore::new()),
            data_dir,
        )
    }
}

/// Send one HTTP request with the bridge credentials and read the
/// status and body of its response.
async fn http<R, W>(
    wire: &mut Wire<R, W>,
    method: &str,
    path: &str,
    headers: &[&str],
    body: &str,
) -> (u16, String)
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    use base64::Engine as _;
    let credentials =
        base64::engine::general_purpose::STANDARD.encode(format!("{LOGIN}:{BRIDGE_PASSWORD}"));
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic {credentials}\r\n"
    );
    for header in headers {
        request.push_str(header);
        request.push_str("\r\n");
    }
    request.push_str(&format!("Content-Length: {}\r\n\r\n{body}", body.len()));
    wire.writer.write_all(request.as_bytes()).await.unwrap();
    wire.writer.flush().await.unwrap();
    let status_line = wire.line().await;
    let status: u16 = status_line.split(' ').nth(1).unwrap().parse().unwrap();
    let mut length = 0;
    loop {
        let line = wire.line().await;
        if line.is_empty() {
            break;
        }
        if let Some(value) = line.strip_prefix("Content-Length: ") {
            length = value.parse().unwrap();
        }
    }
    let mut body = vec![0; length];
    wire.reader.read_exact(&mut body).await.unwrap();
    (status, String::from_utf8(body).unwrap())
}

#[tokio::test]
async fn serve_answers_carddav_from_the_address_book() {
    let port = free_port();
    let carddav_port = free_port();
    let (_config_dir, config_path) = carddav_config(port, carddav_port);
    let cert_dir = tempfile::tempdir().unwrap();
    let session = event_session();
    session.contacts.put(tuta_bridge::domain::ContactCard {
        list_id: "contact-list".into(),
        element_id: "c1".into(),
        first_name: "Ada".into(),
        last_name: "Lovelace".into(),
        ..Default::default()
    });

    let uc = serve_with_state(
        &session,
        config_path,
        seeded_sqlite_state().await,
        cert_dir.path(),
    );
    let (stop_serve, stop_rx) = oneshot::channel::<()>();
    let serve_task = tokio::spawn(async move {
        uc.run_until(async move {
            let _ = stop_rx.await;
        })
        .await
    });

    // Loopback TLS with the shared certificate and the bridge password.
    let mut wire = tls_client(carddav_port).await;
    let body = r#"<propfind xmlns="DAV:"><prop><getetag/></prop></propfind>"#;
    let (status, listing) = http(
        &mut wire,
        "PROPFIND",
        "/addressbooks/contacts/",
        &["Depth: 1"],
        body,
    )
    .await;
    assert_eq!(status, 207);
    assert!(listing.contains("<d:href>/addressbooks/contacts/c1.vcf</d:href>"));

    let (status, vcard) = http(&mut wire, "GET", "/addressbooks/contacts/c1.vcf", &[], "").await;
    assert_eq!(status, 200);
    assert!(vcard.contains("FN:Ada Lovelace\r\n"));

    let (status, _) = http(&mut wire, "PUT", "/addressbooks/contacts/c1.vcf", &[], "x").await;
    assert_eq!(status, 403);
    drop(wire);

    stop_serve.send(()).unwrap();
    let result = serve_task.await.unwrap();
    assert!(result.is_ok(), "serve ended with {result:?}");
}

#[tokio::test]
async fn serve_reports_a_held_carddav_port_as_in_use() {
    let held = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let carddav_port = held.local_addr().unwrap().port();
    let (_config_dir, config_path) = carddav_config(free_port(), carddav_port);
    let cert_dir = tempfile::tempdir().unwrap();
    let uc = serve_with_state(
        &event_session(),
        config_path,
        seeded_sqlite_state().await,
        cert_dir.path(),
    );
    let error = uc
        .run_until(std::future::pending::<()>())
        .await
        .expect_err("a held port must fail serve");
    assert!(
        matches!(error, Error::InUse(ref message) if message == &format!("carddav port {carddav_port} is already in use"))
    );
    assert_eq!(error.exit_code(), 10);
}

#[tokio::test]
async fn serve_refuses_a_reserved_carddav_port() {
    let (_config_dir, config_path) = carddav_config(free_port(), 0);
    let cert_dir = tempfile::tempdir().unwrap();
    let uc = serve_with_state(
        &event_session(),
        config_path,
        seeded_sqlite_state().await,
        cert_dir.path(),
    );
    let error = uc
        .run_until(std::future::pending::<()>())
        .await
        .expect_err("a reserved port must fail serve");
    assert!(
        matches!(error, Error::Config(ref message) if message == "carddav_port must be between 1 and 65535")
    );
}
