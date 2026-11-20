//! The TLS-only SMTP submission accept loop (implicit TLS, RFC 8314).
//!
//! Same posture as the IMAP and POP3 listeners: loopback only, the
//! shared bridge certificate, bounded connections and handshake time,
//! and failures that close one connection at most.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;

use super::session::{run_smtp_session, SmtpLimits};
use crate::adapters::imap::server::Accept;
use crate::ports::imap_backend::ImapBackend;
use crate::ports::mail_sender::MailSender;

/// The bounds of the SMTP accept loop.
#[derive(Clone)]
pub struct SmtpServeLimits {
    pub max_connections: usize,
    pub handshake_timeout: Duration,
    pub accept_retry_delay: Duration,
    pub session: SmtpLimits,
}

impl Default for SmtpServeLimits {
    fn default() -> Self {
        Self {
            max_connections: 16,
            handshake_timeout: Duration::from_secs(10),
            accept_retry_delay: Duration::from_secs(1),
            session: SmtpLimits::default(),
        }
    }
}

/// Accept SMTP submission connections until dropped.
pub async fn serve_smtp<A: Accept>(
    mut listener: A,
    tls: TlsAcceptor,
    auth: Arc<dyn ImapBackend>,
    sender: Arc<dyn MailSender>,
    limits: SmtpServeLimits,
) {
    let slots = Arc::new(Semaphore::new(limits.max_connections));
    loop {
        let Ok(slot) = Arc::clone(&slots).acquire_owned().await else {
            return;
        };
        let stream = match listener.accept().await {
            Ok(stream) => stream,
            Err(_) => {
                tracing::warn!("smtp accept failed; retrying");
                drop(slot);
                tokio::time::sleep(limits.accept_retry_delay).await;
                continue;
            }
        };
        let tls = tls.clone();
        let auth = Arc::clone(&auth);
        let sender = Arc::clone(&sender);
        let handshake_timeout = limits.handshake_timeout;
        let session_limits = limits.session.clone();
        tokio::spawn(async move {
            let _slot = slot;
            match tokio::time::timeout(handshake_timeout, tls.accept(stream)).await {
                Ok(Ok(tls_stream)) => {
                    let _ = run_smtp_session(tls_stream, auth, sender, session_limits).await;
                }
                Ok(Err(_)) => tracing::debug!("smtp tls handshake failed"),
                Err(_) => tracing::debug!("smtp tls handshake timed out"),
            }
            tracing::debug!("smtp connection ended");
        });
    }
}
