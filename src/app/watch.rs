//! Long-running Tuta event-bus watcher, and the `serve` command that
//! hosts it next to the IMAP listener.
//!
//! [`WatchUseCase`] resumes the stored session, reconciles the local index
//! with a baseline (re)sync, and then consumes the event bus until it is
//! stopped. Network failures — including connects that hang until the
//! connect timeout — reconnect with a capped backoff; every other error is
//! fatal because it needs the user to act. A run of batches whose entity
//! lookups fail resyncs the index, exactly like an expired marker. The
//! output is fixed text and counters only: ids, tokens, subjects,
//! addresses, and URLs never appear in it. An optional notifier
//! additionally broadcasts local mailbox ids — nothing else — after
//! each applied batch and after each resync.
//!
//! [`ServeUseCase`] runs that watch loop as a task next to a TLS-only
//! loopback IMAP listener that answers from the same state store. One
//! broadcast channel connects them: the watch publishes mailbox ids,
//! idling sessions drain them. The listener binds `127.0.0.1` only and
//! never a configurable address; Ctrl-C (or the injected stop future)
//! ends the accept loop, which then ends the watch loop and returns its
//! result as the command's own.

use std::collections::HashMap;
use std::future::Future;
use std::path::PathBuf;
use std::pin::pin;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::{broadcast, oneshot};

use crate::adapters::imap::backend::TutaImapBackend;
use crate::adapters::imap::server::{ensure_certificate, tls_acceptor};
use crate::adapters::imap::session::run_session;
use crate::adapters::mime::MimeRenderer;
use crate::adapters::tuta::generated_id::{batch_is_expired, timestamp_to_generated_id};
use crate::app::enrich::EnvelopeEnricher;
use crate::app::event_sync::EventProcessor;
use crate::app::state_sync::{current_uidvalidity, next_uidvalidity, resync_with, sync_with};
use crate::config::{resolve_imap_port, validate_imap_port, Config};
use crate::domain::{AccountId, Error, EventFrame, Result};
use crate::ports::clock::Clock;
use crate::ports::credentials::CredentialStore;
use crate::ports::imap_backend::ImapBackend;
use crate::ports::local_password::LocalPasswordStore;
use crate::ports::mailbox_events::{MailboxChanged, MailboxEventSender};
use crate::ports::renderer::MessageRenderer;
use crate::ports::session::{Session, SessionFactory};
use crate::ports::state_store::StateStore;

/// Reconnect delays for the event bus.
pub struct BackoffPolicy {
    pub first_ms: u64,
    pub second_ms: u64,
    pub max_ms: u64,
}

/// Production bound on one event-bus connect attempt.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Production consecutive-batch count of lookup failures before the
/// index is reset and resynced.
pub const LOOKUP_FAILURE_THRESHOLD: usize = 10;

impl BackoffPolicy {
    /// Production delays: 5 s, 20 s, then capped at 60 s.
    pub fn production() -> Self {
        Self {
            first_ms: 5_000,
            second_ms: 20_000,
            max_ms: 60_000,
        }
    }

    /// Delay before retry number `attempt`, counting from one.
    pub fn delay_ms(&self, attempt: u32) -> u64 {
        match attempt {
            0 | 1 => self.first_ms,
            2 => self.second_ms,
            _ => self.max_ms,
        }
    }
}

/// Whether an error must end the watch loop.
///
/// Only network errors are retried; authentication, storage, and
/// configuration errors need the user to act, so they are fatal.
pub fn is_fatal(error: &Error) -> bool {
    !matches!(error, Error::Network(_))
}

/// Streams Tuta events into the local index until stopped.
pub struct WatchUseCase {
    pub factory: Arc<dyn SessionFactory>,
    pub credentials: Arc<dyn CredentialStore>,
    pub config_path: PathBuf,
    pub state: Arc<dyn StateStore>,
    pub clock: Arc<dyn Clock>,
    pub backoff: BackoffPolicy,
    /// How long one `events` connect may hang before it is abandoned
    /// and retried like a dropped connection.
    pub connect_timeout: Duration,
    /// Consecutive batches with failed lookups before the index is
    /// reset and resynced; unreadable or unhandled events never count.
    pub lookup_failure_threshold: usize,
    /// Broadcasts one [`MailboxChanged`] per mailbox each applied batch
    /// touched, and one per current mailbox after a resync. `None` — the
    /// default — publishes nothing; send errors from a closed channel
    /// are ignored because they only mean nobody idles.
    pub notifier: Option<MailboxEventSender>,
}

impl WatchUseCase {
    /// Attach a mailbox-change broadcaster.
    ///
    /// Additive: construction sites without a notifier keep their
    /// behavior, and the watch loop runs the same either way.
    pub fn with_notifier(mut self, sender: MailboxEventSender) -> Self {
        self.notifier = Some(sender);
        self
    }

    /// Watch until Ctrl-C.
    pub async fn run(&self) -> Result<()> {
        println!("watching for Tuta events; press Ctrl-C to stop");
        self.run_until(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
    }

    /// Watch until `stop` resolves.
    pub async fn run_until<F>(&self, stop: F) -> Result<()>
    where
        F: Future<Output = ()>,
    {
        // 1. Resume the stored session; watch never logs in or prompts.
        let config = Config::load(&self.config_path).map_err(|e| Error::Config(e.to_string()))?;
        let account = config.active_account.ok_or(Error::NoActiveAccount)?;
        let credentials = self
            .credentials
            .load(&AccountId(account))?
            .ok_or(Error::MissingCredentials)?;
        let session = self.factory.resume(&credentials).await?;

        // 2. Local account row and the groups to subscribe to.
        let account_id = self.state.upsert_account(&credentials.login).await?;
        let groups = session.event_groups();
        if groups.is_empty() {
            return Err(Error::Network("no event groups".into()));
        }

        // 3. Baseline, then the UIDVALIDITY stamped on event folders.
        let mut batches = self.baseline(session.as_ref(), account_id, &groups).await?;
        let max_stored = self
            .state
            .mailboxes(account_id)
            .await?
            .into_iter()
            .map(|mailbox| mailbox.uidvalidity)
            .max();
        let event_uidvalidity = next_uidvalidity(max_stored, current_uidvalidity())?;

        // 4. Reconnect loop: network errors retry, everything else is fatal.
        let processor = EventProcessor::new(Arc::clone(&self.state));
        let mut stop = pin!(stop);
        let mut attempt: u32 = 0;
        // Consecutive batches with failed lookups; a long enough run
        // triggers the resync valve below.
        let mut failing_batches: usize = 0;
        loop {
            // A failed or hung connect is retried like a dropped
            // connection: it shares the backoff below with frame errors.
            // The timeout bounds how long one connect may stall the
            // loop, and the stop future stays responsive while it runs.
            let connected = tokio::select! {
                biased;
                connected = tokio::time::timeout(
                    self.connect_timeout,
                    session.events(&batches, self.clock.now_ms()),
                ) => match connected {
                    Ok(Ok(handles)) => Some(handles),
                    Ok(Err(e)) if is_fatal(&e) => return Err(e),
                    // A network error or a timed-out connect is retried
                    // on a fresh connection.
                    Ok(Err(_)) | Err(_) => None,
                },
                () = &mut stop => return Ok(()),
            };

            if let Some(handles) = connected {
                let lookup = handles.lookup;
                let mut stream = handles.stream;
                loop {
                    let frame = tokio::select! {
                        () = &mut stop => return Ok(()),
                        frame = stream.next_frame() => frame,
                    };
                    let frame = match frame {
                        Ok(frame) => frame,
                        Err(e) if is_fatal(&e) => return Err(e),
                        // A network error is retried on a fresh connection.
                        Err(_) => break,
                    };
                    // Any successful frame proves the connection works again.
                    attempt = 0;
                    match frame {
                        EventFrame::Batch(batch) => {
                            let report = processor
                                .apply(account_id, lookup.as_ref(), event_uidvalidity, &batch)
                                .await?;
                            batches.insert(batch.owner_group_id.clone(), batch.batch_id.clone());
                            if report.changes > 0 {
                                println!("applied {} changes", report.changes);
                            }
                            // Idling sessions learn which mailboxes the
                            // batch changed; a closed channel only means
                            // nobody idles, so send errors are ignored.
                            if let Some(notifier) = &self.notifier {
                                for mailbox in &report.touched_mailboxes {
                                    let _ = notifier.send(MailboxChanged(*mailbox));
                                }
                            }
                            // A run of batches whose lookups failed has
                            // silently skipped events, so the index may
                            // have desynced. After enough consecutive
                            // ones the account is reset, resynced, and
                            // the markers re-stamped — the same path an
                            // expired marker takes — and the stream
                            // continues on the fresh state.
                            if report.lookup_failures > 0 {
                                failing_batches += 1;
                                if failing_batches >= self.lookup_failure_threshold {
                                    batches = self
                                        .resync_and_remark(
                                            session.as_ref(),
                                            account_id,
                                            &groups,
                                            self.clock.now_ms(),
                                        )
                                        .await?;
                                    println!("event lookups failed repeatedly; index resynced");
                                    failing_batches = 0;
                                }
                            } else {
                                failing_batches = 0;
                            }
                        }
                        EventFrame::InitialSyncDone => println!("event stream caught up"),
                        EventFrame::Ignored => continue,
                    }
                }
            }

            attempt += 1;
            let delay = self.backoff.delay_ms(attempt);
            println!("event stream lost; retrying in {delay} ms");
            tokio::select! {
                () = &mut stop => return Ok(()),
                () = tokio::time::sleep(Duration::from_millis(delay)) => {}
            }
        }
    }

    /// Reconcile the index with a baseline (re)sync and return the batch
    /// markers to resume from.
    ///
    /// An expired marker can no longer be replayed by the server, so the
    /// account is reset and resynced through [`Self::resync_and_remark`];
    /// that sync already ran, so no ordinary sync follows it. A missing
    /// marker — or a still-empty index — runs the ordinary sync instead.
    /// Groups still without a marker afterwards resume from five seconds
    /// ago, and the stamp is persisted so a restart does not replay from
    /// the beginning.
    async fn baseline(
        &self,
        session: &dyn Session,
        account_id: i64,
        groups: &[String],
    ) -> Result<HashMap<String, String>> {
        let now_ms = self.clock.now_ms();
        let mailboxes = self.state.mailboxes(account_id).await?;

        let mut batches: HashMap<String, String> = HashMap::new();
        let mut missing = false;
        let mut expired = false;
        for group in groups {
            match self.state.last_batch(account_id, group).await? {
                Some(marker) if batch_is_expired(&marker, now_ms) => expired = true,
                Some(marker) => {
                    batches.insert(group.clone(), marker);
                }
                None => missing = true,
            }
        }

        if expired {
            batches = self
                .resync_and_remark(session, account_id, groups, now_ms)
                .await?;
        } else if mailboxes.is_empty() || missing {
            sync_with(
                Arc::clone(&self.state),
                session.mail(),
                account_id,
                current_uidvalidity(),
            )
            .await?;
        }

        let resume_id = timestamp_to_generated_id((now_ms - 5_000).max(0));
        for group in groups {
            if batches.contains_key(group) {
                continue;
            }
            self.state
                .set_last_batch(account_id, group, &resume_id)
                .await?;
            batches.insert(group.clone(), resume_id.clone());
        }

        Ok(batches)
    }

    /// Reset the account, resync it, and re-stamp every group's resume
    /// marker; returns the fresh markers.
    ///
    /// Shared by the expired-marker path in [`Self::baseline`] and the
    /// lookup-failure valve in [`Self::run_until`]: both mean the stored
    /// index can no longer be brought up to date by events alone, so it
    /// is rebuilt and the stream resumes from five seconds before
    /// `now_ms`.
    async fn resync_and_remark(
        &self,
        session: &dyn Session,
        account_id: i64,
        groups: &[String],
        now_ms: i64,
    ) -> Result<HashMap<String, String>> {
        // `resync_with` resets the account and syncs it again, so the
        // stored markers are gone together with the rest of the state.
        resync_with(
            Arc::clone(&self.state),
            session.mail(),
            account_id,
            current_uidvalidity(),
        )
        .await?;
        let resume_id = timestamp_to_generated_id((now_ms - 5_000).max(0));
        let mut batches = HashMap::new();
        for group in groups {
            self.state
                .set_last_batch(account_id, group, &resume_id)
                .await?;
            batches.insert(group.clone(), resume_id.clone());
        }
        // A resync never goes through `apply_batch`, so every current
        // mailbox is announced here: idling sessions must re-examine
        // UIDVALIDITY and their cached views. A closed channel only
        // means nobody idles, so send errors are ignored.
        if let Some(notifier) = &self.notifier {
            for mailbox in self.state.mailboxes(account_id).await? {
                let _ = notifier.send(MailboxChanged(mailbox.id));
            }
        }
        Ok(batches)
    }
}

// ---------------------------------------------------------------------------
// serve
// ---------------------------------------------------------------------------

/// Capacity of the mailbox-change broadcast: one event per touched
/// mailbox per batch, plus one per mailbox after a resync. A consumer
/// that falls behind treats the lag as "everything changed", so the
/// exact size only bounds buffer memory.
const NOTIFIER_CAPACITY: usize = 256;

/// Serve the local index over IMAP while the event loop keeps it fresh.
///
/// One process runs both loops: the TLS-only loopback listener that
/// answers from the state store, and the watch task that feeds it.
/// Every dependency is injected exactly like [`WatchUseCase`]'s, so
/// tests drive the whole command against the in-memory fakes.
pub struct ServeUseCase {
    pub factory: Arc<dyn SessionFactory>,
    pub credentials: Arc<dyn CredentialStore>,
    /// The bridge password store IMAP clients authenticate against;
    /// `serve` only reads it, `passwd` writes it.
    pub passwords: Arc<dyn LocalPasswordStore>,
    pub config_path: PathBuf,
    pub state: Arc<dyn StateStore>,
    pub clock: Arc<dyn Clock>,
    /// Directory that holds (or receives) the TLS certificate pair.
    pub data_dir: PathBuf,
    pub backoff: BackoffPolicy,
    /// How long one watch `events` connect may hang before it is
    /// abandoned and retried like a dropped connection.
    pub connect_timeout: Duration,
    /// Consecutive watch batches with failed lookups before the index
    /// is reset and resynced.
    pub lookup_failure_threshold: usize,
}

impl ServeUseCase {
    /// Serve until Ctrl-C.
    pub async fn run(&self) -> Result<()> {
        self.run_until(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
    }

    /// Serve until `stop` resolves, then end the watch loop and return
    /// its result.
    ///
    /// The output is fixed text: the listen address and counters only.
    /// The listener binds `127.0.0.1:{port}` and nothing else — the
    /// address is not configurable — after the port passes
    /// [`validate_imap_port`], so a reserved port fails the command
    /// instead of silently binding an ephemeral one. The Tuta session
    /// is resumed once and never closed; its shared mail source keeps
    /// the logged-in state alive for the backend. A fatal watch error
    /// ends serve with that error; a lost event connection does not,
    /// because the watch retries it itself.
    pub async fn run_until<F>(&self, stop: F) -> Result<()>
    where
        F: Future<Output = ()>,
    {
        // 1. Configuration: the active account and the listen port.
        //    The port is validated before anything is opened.
        let config = Config::load(&self.config_path).map_err(|e| Error::Config(e.to_string()))?;
        let account = config
            .active_account
            .clone()
            .ok_or(Error::NoActiveAccount)?;
        let port = resolve_imap_port(&config);
        validate_imap_port(port).map_err(Error::Config)?;

        // 2. Resume the session and resolve the account row. serve
        //    never closes the session; the binding below keeps it for
        //    the process lifetime next to the shared source the
        //    backend now owns.
        let credentials = self
            .credentials
            .load(&AccountId(account))?
            .ok_or(Error::MissingCredentials)?;
        let session = self.factory.resume(&credentials).await?;
        let account_id = self.state.upsert_account(&credentials.login).await?;
        let expected_user = session.account().mail_address;

        // 3. The bridge password must exist before anything listens.
        //    A missing password is a configuration problem the user
        //    fixes with `tuta-bridge passwd`.
        if self.passwords.load().await?.is_none() {
            return Err(Error::Config(
                "local IMAP password not set; run tuta-bridge passwd first".into(),
            ));
        }

        // 4. The backend: stored metadata for listings and searches,
        //    on-demand rendering for bodies. One renderer instance
        //    serves the enricher and the fetches.
        let renderer: Arc<dyn MessageRenderer> = Arc::new(MimeRenderer);
        let backend: Arc<dyn ImapBackend> = Arc::new(TutaImapBackend {
            account_id,
            expected_user,
            passwords: Arc::clone(&self.passwords),
            store: Arc::clone(&self.state),
            enricher: Arc::new(EnvelopeEnricher {
                store: Arc::clone(&self.state),
                renderer: Arc::clone(&renderer),
            }),
            source: session.shared_mail(),
            renderer,
        });
        let _session = session;

        // 5. The watch task feeds the same store and broadcasts every
        //    mailbox change to the idling sessions.
        let (sender, _) = broadcast::channel::<MailboxChanged>(NOTIFIER_CAPACITY);
        let (stop_watch, watch_stopped) = oneshot::channel::<()>();
        let watch = WatchUseCase {
            factory: Arc::clone(&self.factory),
            credentials: Arc::clone(&self.credentials),
            config_path: self.config_path.clone(),
            state: Arc::clone(&self.state),
            clock: Arc::clone(&self.clock),
            backoff: BackoffPolicy {
                first_ms: self.backoff.first_ms,
                second_ms: self.backoff.second_ms,
                max_ms: self.backoff.max_ms,
            },
            connect_timeout: self.connect_timeout,
            lookup_failure_threshold: self.lookup_failure_threshold,
            notifier: None,
        }
        .with_notifier(sender.clone());
        let mut watch_task = tokio::spawn(async move {
            watch
                .run_until(async move {
                    let _ = watch_stopped.await;
                })
                .await
        });

        // 6. TLS on loopback only. The certificate is generated (0600)
        //    or reused, the port comes from the config, and the
        //    address is fixed.
        let (cert_pem, key_pem) = ensure_certificate(&self.data_dir)?;
        let tls = tls_acceptor(&cert_pem, &key_pem)?;
        let listener = TcpListener::bind(("127.0.0.1", port))
            .await
            .map_err(|_| Error::Network("imap listener bind failed".into()))?;
        println!("serving IMAP on 127.0.0.1:{port}; press Ctrl-C to stop");

        // 7. Accept until the stop future resolves, then end the
        //    watch loop and return its result. A watch that ended on
        //    its own — only a fatal error can — ends serve with that
        //    error. Failures close one connection at most.
        let mut stop = pin!(stop);
        loop {
            tokio::select! {
                biased;
                _ = &mut stop => break,
                watched = &mut watch_task => {
                    return match watched {
                        Ok(result) => result,
                        Err(_) => Err(Error::Storage("watch task failed".into())),
                    };
                }
                accepted = listener.accept() => {
                    let (stream, _peer) = accepted.map_err(accept_failed)?;
                    let tls = tls.clone();
                    let backend = Arc::clone(&backend);
                    let events = sender.subscribe();
                    tokio::spawn(async move {
                        match tls.accept(stream).await {
                            Ok(stream) => {
                                let _ = run_session(stream, backend, events).await;
                            }
                            Err(_) => tracing::debug!("tls handshake failed"),
                        }
                        tracing::debug!("connection ended");
                    });
                }
            }
        }
        let _ = stop_watch.send(());
        match watch_task.await {
            Ok(result) => result,
            Err(_) => Err(Error::Storage("watch task failed".into())),
        }
    }
}

/// A failed accept ends the command: the listener is dead.
fn accept_failed(_: std::io::Error) -> Error {
    Error::Network("listener accept failed".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_grows_and_caps() {
        let policy = BackoffPolicy {
            first_ms: 5_000,
            second_ms: 20_000,
            max_ms: 60_000,
        };
        assert_eq!(policy.delay_ms(1), 5_000);
        assert_eq!(policy.delay_ms(2), 20_000);
        assert_eq!(policy.delay_ms(3), 60_000);
        assert_eq!(policy.delay_ms(20), 60_000);
    }

    #[test]
    fn only_network_errors_are_retried() {
        assert!(!is_fatal(&Error::Network("x".into())));
        assert!(is_fatal(&Error::Login("x".into())));
        assert!(is_fatal(&Error::Storage("x".into())));
        assert!(is_fatal(&Error::MissingCredentials));
        assert!(is_fatal(&Error::Unsupported("x".into())));
    }
}
