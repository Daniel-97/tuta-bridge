//! The TLS-only DAV accept loop (implicit TLS, like POP3S and SMTPS).
//!
//! Same posture as the other listeners: loopback only (the caller binds
//! it), the shared bridge certificate, bounded connections and handshake
//! time, and failures that close one connection at most. Each feature
//! runs its own loop on its own port with its own [`DavHandler`]; the
//! suggested ports are 9932 for CardDAV and 9933 for CalDAV.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;

use super::handler::DavHandler;
use super::session::{run_dav_session, DavLimits};
use crate::adapters::imap::server::Accept;
use crate::ports::imap_backend::ImapBackend;

/// The bounds of one DAV accept loop.
#[derive(Clone)]
pub struct DavServeLimits {
    pub max_connections: usize,
    pub handshake_timeout: Duration,
    pub accept_retry_delay: Duration,
    pub session: DavLimits,
}

impl Default for DavServeLimits {
    fn default() -> Self {
        Self {
            max_connections: 16,
            handshake_timeout: Duration::from_secs(10),
            accept_retry_delay: Duration::from_secs(1),
            session: DavLimits::default(),
        }
    }
}

/// Accept DAV connections until dropped. `auth` checks the bridge
/// password ([`ImapBackend::login`]); `handler` serves the reads.
pub async fn serve_dav<A: Accept>(
    mut listener: A,
    tls: TlsAcceptor,
    auth: Arc<dyn ImapBackend>,
    handler: Arc<dyn DavHandler>,
    limits: DavServeLimits,
) {
    let label = handler.label();
    let slots = Arc::new(Semaphore::new(limits.max_connections));
    loop {
        let Ok(slot) = Arc::clone(&slots).acquire_owned().await else {
            return;
        };
        let stream = match listener.accept().await {
            Ok(stream) => stream,
            Err(_) => {
                tracing::warn!(protocol = label, "dav accept failed; retrying");
                drop(slot);
                tokio::time::sleep(limits.accept_retry_delay).await;
                continue;
            }
        };
        let tls = tls.clone();
        let auth = Arc::clone(&auth);
        let handler = Arc::clone(&handler);
        let handshake_timeout = limits.handshake_timeout;
        let session_limits = limits.session.clone();
        tokio::spawn(async move {
            let _slot = slot;
            match tokio::time::timeout(handshake_timeout, tls.accept(stream)).await {
                Ok(Ok(tls_stream)) => {
                    let _ = run_dav_session(tls_stream, auth, handler, session_limits).await;
                }
                Ok(Err(_)) => tracing::debug!(protocol = label, "dav tls handshake failed"),
                Err(_) => tracing::debug!(protocol = label, "dav tls handshake timed out"),
            }
            tracing::debug!(protocol = label, "dav connection ended");
        });
    }
}
