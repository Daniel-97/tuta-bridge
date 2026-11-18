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
//! is ambiguous), failures close one connection at most, and nothing
//! logs peer data or file contents.

use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use super::session::run_session;
use crate::domain::{Error, Result};
use crate::ports::imap_backend::ImapBackend;
use crate::ports::mailbox_events::MailboxEventSender;

/// The certificate file names inside the state directory.
const CERTIFICATE_FILE: &str = "imap-cert.pem";
const KEY_FILE: &str = "imap-key.pem";

/// Load or generate the bridge's TLS certificate.
///
/// When both files exist and are non-empty they are reused verbatim;
/// otherwise a fresh pair is generated and persisted with mode 0600.
/// The returned strings are the PEM material [`tls_acceptor`] takes.
pub fn ensure_certificate(dir: &Path) -> Result<(String, String)> {
    let cert_path = dir.join(CERTIFICATE_FILE);
    let key_path = dir.join(KEY_FILE);
    if let (Ok(cert_pem), Ok(key_pem)) = (
        fs::read_to_string(&cert_path),
        fs::read_to_string(&key_path),
    ) {
        if !cert_pem.trim().is_empty() && !key_pem.trim().is_empty() {
            return Ok((cert_pem, key_pem));
        }
    }

    let (cert_pem, key_pem) = generate_certificate()?;
    write_private(&cert_path, &cert_pem)?;
    write_private(&key_path, &key_pem)?;
    Ok((cert_pem, key_pem))
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

/// Write one PEM file with owner-only permissions from the first byte.
fn write_private(path: &Path, contents: &str) -> Result<()> {
    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(pem_write_failed)?;
        file.write_all(contents.as_bytes())
            .map_err(pem_write_failed)?;
    }
    #[cfg(not(unix))]
    fs::write(path, contents).map_err(pem_write_failed)?;
    Ok(())
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

/// The TLS-only loopback accept loop.
///
/// One `watch.subscribe()` receiver is created per connection, so every
/// session sees the notifications published while it lives. A failed
/// handshake or a session error ends that one connection; the loop ends
/// only when the listener fails.
pub async fn serve(
    listener: TcpListener,
    tls: TlsAcceptor,
    backend: Arc<dyn ImapBackend>,
    watch: MailboxEventSender,
) -> Result<()> {
    loop {
        let (stream, _peer) = listener.accept().await.map_err(accept_failed)?;
        let tls = tls.clone();
        let backend = Arc::clone(&backend);
        let watch = watch.subscribe();
        tokio::spawn(async move {
            match tls.accept(stream).await {
                Ok(tls_stream) => {
                    let _ = run_session(tls_stream, backend, watch).await;
                }
                Err(_) => tracing::debug!("tls handshake failed"),
            }
            tracing::debug!("connection ended");
        });
    }
}

fn accept_failed(_: std::io::Error) -> Error {
    Error::Network("listener accept failed".into())
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
