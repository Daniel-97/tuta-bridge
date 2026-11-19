//! TLS certificate management and the loopback accept loop.
//!
//! [`ensure_certificate`] generates the bridge's certificate on first
//! use (CN `localhost`, SANs `DNS:localhost`, `IP:127.0.0.1`, `IP:::1`)
//! and persists it as `imap-cert.pem` / `imap-key.pem` with mode 0600;
//! existing files are reused. [`tls_acceptor`] builds the acceptor from
//! PEM material, and [`serve`] accepts loopback connections, upgrades
//! each to TLS, and hands it to `run_session` with its own broadcast
//! receiver.
//!
//! Hygiene: the certificate provider is pinned explicitly (this
//! dependency graph compiles two crypto providers, so the process default
//! is ambiguous), failures close one connection at most — a failed
//! `accept` included — the number of live connections and the time a
//! handshake may take are bounded, and nothing logs peer data or file
//! contents.

use std::fs;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;

use super::session::{run_session, SessionLimits};
use crate::domain::{Error, Result};
use crate::ports::imap_backend::ImapBackend;
use crate::ports::mailbox_events::MailboxEventSender;

/// The certificate file names inside the state directory.
const CERTIFICATE_FILE: &str = "imap-cert.pem";
const KEY_FILE: &str = "imap-key.pem";

/// Load or generate the bridge's TLS certificate.
///
/// When both files exist as regular, non-empty files they are reused
/// verbatim — after their mode is set to 0600, on every start, so a
/// pair that was created or left with looser permissions does not stay
/// that way. Otherwise a fresh pair is generated and persisted with
/// mode 0600. The returned strings are the PEM material
/// [`tls_acceptor`] takes.
pub fn ensure_certificate(dir: &Path) -> Result<(String, String)> {
    let cert_path = dir.join(CERTIFICATE_FILE);
    let key_path = dir.join(KEY_FILE);
    if let (Some(cert_pem), Some(key_pem)) = (stored_pem(&cert_path)?, stored_pem(&key_path)?) {
        return Ok((cert_pem, key_pem));
    }

    let (cert_pem, key_pem) = generate_certificate()?;
    write_private(&cert_path, &cert_pem)?;
    write_private(&key_path, &key_pem)?;
    Ok((cert_pem, key_pem))
}

/// The PEM text stored at `path`, private again before it is read, or
/// `None` when there is nothing reusable there: no file, an empty one,
/// or something that is not a regular file — a symlink is never
/// followed, and the pair is regenerated over it instead.
fn stored_pem(path: &Path) -> Result<Option<String>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() => {}
        _ => return Ok(None),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|_| Error::Config("certificate permissions could not be set".into()))?;
    }
    Ok(fs::read_to_string(path)
        .ok()
        .filter(|pem| !pem.trim().is_empty()))
}

/// Generate the self-signed loopback certificate pair.
fn generate_certificate() -> Result<(String, String)> {
    let mut params = rcgen::CertificateParams::default();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "localhost");
    params.subject_alt_names = vec![
        dns_san("localhost")?,
        rcgen::SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        rcgen::SanType::IpAddress(IpAddr::V6(Ipv6Addr::LOCALHOST)),
    ];
    let key_pair = rcgen::KeyPair::generate().map_err(certificate_failed)?;
    let certificate = params.self_signed(&key_pair).map_err(certificate_failed)?;
    Ok((certificate.pem(), key_pair.serialize_pem()))
}

fn dns_san(name: &str) -> Result<rcgen::SanType> {
    Ok(rcgen::SanType::DnsName(
        name.to_string().try_into().map_err(certificate_failed)?,
    ))
}

fn certificate_failed(_: rcgen::Error) -> Error {
    Error::Config("certificate generation failed".into())
}

/// Write one PEM file: atomically, with owner-only permissions from
/// the first byte, and never through a symlink.
fn write_private(path: &Path, contents: &str) -> Result<()> {
    crate::config::write_private_file(path, contents.as_bytes()).map_err(pem_write_failed)
}

fn pem_write_failed(_: std::io::Error) -> Error {
    Error::Config("certificate write failed".into())
}

/// Build the TLS acceptor from PEM material.
///
/// The crypto provider is pinned to ring explicitly: this dependency
/// graph compiles two providers, so the process-level default would be
/// ambiguous.
pub fn tls_acceptor(cert_pem: &str, key_pem: &str) -> Result<TlsAcceptor> {
    let certificates = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| Error::Config("invalid certificate pem".into()))?;
    if certificates.is_empty() {
        return Err(Error::Config("no certificate in pem".into()));
    }
    let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())
        .map_err(|_| Error::Config("invalid key pem".into()))?
        .ok_or_else(|| Error::Config("no private key in pem".into()))?;

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| Error::Config("unsupported tls protocol versions".into()))?
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .map_err(|_| Error::Config("invalid tls key material".into()))?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// The bounds of the accept loop and of every connection it serves.
#[derive(Clone)]
pub struct ServeLimits {
    /// Connections served at once, handshakes included. At the cap the
    /// listener is not polled: further clients wait in the kernel's
    /// backlog instead of costing a task and a descriptor each.
    pub max_connections: usize,
    /// How long a client may take to complete the TLS handshake.
    pub handshake_timeout: Duration,
    /// The pause after a failed `accept` before the next attempt, so a
    /// persistent failure (descriptor exhaustion) cannot spin.
    pub accept_retry_delay: Duration,
    /// The time bounds of each session.
    pub session: SessionLimits,
}

impl Default for ServeLimits {
    fn default() -> Self {
        Self {
            max_connections: 64,
            handshake_timeout: Duration::from_secs(10),
            accept_retry_delay: Duration::from_secs(1),
            session: SessionLimits::default(),
        }
    }
}

/// A source of incoming connections: the loopback listener in
/// production, an in-memory one in tests.
pub trait Accept {
    type Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static;

    fn accept(&mut self) -> impl Future<Output = std::io::Result<Self::Stream>> + Send;
}

impl Accept for TcpListener {
    type Stream = TcpStream;

    async fn accept(&mut self) -> std::io::Result<TcpStream> {
        TcpListener::accept(self)
            .await
            .map(|(stream, _peer)| stream)
    }
}

/// The TLS-only accept loop. It runs until it is dropped.
///
/// One `watch.subscribe()` receiver is created per connection, so every
/// session sees the notifications published while it lives. A failed
/// handshake, a handshake that takes too long, or a session error ends
/// that one connection. A failed `accept` ends nothing: it is logged
/// and retried after a pause, because the usual causes — the process
/// out of descriptors, a client that reset before being accepted — are
/// transient and must not take the bridge down.
pub async fn serve<A: Accept>(
    mut listener: A,
    tls: TlsAcceptor,
    backend: Arc<dyn ImapBackend>,
    watch: MailboxEventSender,
    limits: ServeLimits,
) {
    let slots = Arc::new(Semaphore::new(limits.max_connections));
    loop {
        // A free slot first, then a connection for it.
        let Ok(slot) = Arc::clone(&slots).acquire_owned().await else {
            return;
        };
        let stream = match listener.accept().await {
            Ok(stream) => stream,
            Err(_) => {
                tracing::warn!("imap accept failed; retrying");
                drop(slot);
                tokio::time::sleep(limits.accept_retry_delay).await;
                continue;
            }
        };
        let tls = tls.clone();
        let backend = Arc::clone(&backend);
        let watch = watch.subscribe();
        let handshake_timeout = limits.handshake_timeout;
        let session_limits = limits.session.clone();
        tokio::spawn(async move {
            // The slot is held until the connection is over.
            let _slot = slot;
            match tokio::time::timeout(handshake_timeout, tls.accept(stream)).await {
                Ok(Ok(tls_stream)) => {
                    let _ = run_session(tls_stream, backend, watch, session_limits).await;
                }
                Ok(Err(_)) => tracing::debug!("tls handshake failed"),
                Err(_) => tracing::debug!("tls handshake timed out"),
            }
            tracing::debug!("connection ended");
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_and_reuses_certificate_files() {
        let dir = tempfile::tempdir().unwrap();
        let (cert_pem, key_pem) = ensure_certificate(dir.path()).unwrap();
        assert!(cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(key_pem.contains("BEGIN PRIVATE KEY"));
        tls_acceptor(&cert_pem, &key_pem).unwrap();

        // Both files are owner-only.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for name in [CERTIFICATE_FILE, KEY_FILE] {
                let mode = fs::metadata(dir.path().join(name))
                    .unwrap()
                    .permissions()
                    .mode();
                assert_eq!(mode & 0o777, 0o600);
            }
        }

        // A second call reuses the files verbatim.
        let (cert_again, key_again) = ensure_certificate(dir.path()).unwrap();
        assert_eq!(cert_again, cert_pem);
        assert_eq!(key_again, key_pem);
    }

    #[cfg(unix)]
    #[test]
    fn reused_files_are_made_private_again_on_every_start() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let (cert_pem, key_pem) = ensure_certificate(dir.path()).unwrap();
        let mode = |name: &str| {
            fs::metadata(dir.path().join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o777
        };

        // Someone loosened the files after they were written.
        for name in [CERTIFICATE_FILE, KEY_FILE] {
            fs::set_permissions(dir.path().join(name), fs::Permissions::from_mode(0o644)).unwrap();
        }
        let (cert_again, key_again) = ensure_certificate(dir.path()).unwrap();
        assert_eq!((cert_again, key_again), (cert_pem, key_pem));
        assert_eq!(mode(CERTIFICATE_FILE), 0o600);
        assert_eq!(mode(KEY_FILE), 0o600);

        // A world-readable empty key is regenerated private, not
        // rewritten in place with the permissions it had.
        fs::write(dir.path().join(KEY_FILE), "").unwrap();
        fs::set_permissions(dir.path().join(KEY_FILE), fs::Permissions::from_mode(0o644)).unwrap();
        let (_, fresh_key) = ensure_certificate(dir.path()).unwrap();
        assert!(fresh_key.contains("BEGIN PRIVATE KEY"));
        assert_eq!(mode(KEY_FILE), 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_key_is_replaced_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        ensure_certificate(dir.path()).unwrap();
        let elsewhere = dir.path().join("elsewhere.pem");
        fs::rename(dir.path().join(KEY_FILE), &elsewhere).unwrap();
        let planted = fs::read_to_string(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, dir.path().join(KEY_FILE)).unwrap();

        // The link is not reused and not written through: a fresh pair
        // replaces it, and the file it pointed at is untouched.
        let (cert_pem, key_pem) = ensure_certificate(dir.path()).unwrap();
        assert_ne!(key_pem, planted);
        assert_eq!(fs::read_to_string(&elsewhere).unwrap(), planted);
        assert!(fs::symlink_metadata(dir.path().join(KEY_FILE))
            .unwrap()
            .is_file());
        tls_acceptor(&cert_pem, &key_pem).unwrap();
    }

    #[test]
    fn regenerates_when_one_file_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let (cert_pem, _) = ensure_certificate(dir.path()).unwrap();
        fs::remove_file(dir.path().join(KEY_FILE)).unwrap();

        // The orphaned certificate is not reused: a fresh pair is
        // generated and the acceptor accepts it.
        let (cert_again, key_again) = ensure_certificate(dir.path()).unwrap();
        assert_ne!(cert_again, cert_pem);
        assert!(key_again.contains("BEGIN PRIVATE KEY"));
        tls_acceptor(&cert_again, &key_again).unwrap();
    }
}
