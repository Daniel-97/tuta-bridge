//! The TLS-only POP3 accept loop (POP3S, RFC 8314 implicit TLS).
//!
//! It shares the IMAP listener's certificate and [`Accept`] seam and the
//! same posture: loopback only, a bounded number of connections and
//! handshake time, and failures that close one connection at most.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;

use super::session::{run_pop3_session, Pop3Limits};
use crate::adapters::imap::server::Accept;
use crate::ports::imap_backend::ImapBackend;

/// The default POP3S port of the bridge.
pub const DEFAULT_POP3_PORT: u16 = 9950;

/// The bounds of the POP3 accept loop.
#[derive(Clone)]
pub struct Pop3ServeLimits {
    pub max_connections: usize,
    pub handshake_timeout: Duration,
    pub accept_retry_delay: Duration,
    pub session: Pop3Limits,
}

impl Default for Pop3ServeLimits {
    fn default() -> Self {
        Self {
            max_connections: 16,
            handshake_timeout: Duration::from_secs(10),
            accept_retry_delay: Duration::from_secs(1),
            session: Pop3Limits::default(),
        }
    }
}

/// Accept POP3S connections until dropped.
pub async fn serve_pop3<A: Accept>(
    mut listener: A,
    tls: TlsAcceptor,
    backend: Arc<dyn ImapBackend>,
    limits: Pop3ServeLimits,
) {
    let slots = Arc::new(Semaphore::new(limits.max_connections));
    loop {
        let Ok(slot) = Arc::clone(&slots).acquire_owned().await else {
            return;
        };
        let stream = match listener.accept().await {
            Ok(stream) => stream,
            Err(_) => {
                tracing::warn!("pop3 accept failed; retrying");
                drop(slot);
                tokio::time::sleep(limits.accept_retry_delay).await;
                continue;
            }
        };
        let tls = tls.clone();
        let backend = Arc::clone(&backend);
        let handshake_timeout = limits.handshake_timeout;
        let session_limits = limits.session.clone();
        tokio::spawn(async move {
            let _slot = slot;
            match tokio::time::timeout(handshake_timeout, tls.accept(stream)).await {
                Ok(Ok(tls_stream)) => {
                    let _ = run_pop3_session(tls_stream, backend, session_limits).await;
                }
                Ok(Err(_)) => tracing::debug!("pop3 tls handshake failed"),
                Err(_) => tracing::debug!("pop3 tls handshake timed out"),
            }
            tracing::debug!("pop3 connection ended");
        });
    }
}
