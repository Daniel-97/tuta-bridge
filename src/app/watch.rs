//! Long-running Tuta event-bus watcher, and the `serve` command that
//! hosts it next to the IMAP listener.
//!
//! [`WatchUseCase`] resumes the stored session, brings the local index up
//! to date with a sync when the stored batch markers cannot do it, and
//! then consumes the event bus until it is stopped. Network failures —
//! a failed sync, connects that hang until the connect timeout, a
//! dropped stream — retry with a capped backoff; every other error is
//! fatal because it needs the user to act. A batch whose entity lookups
//! fail is retried without moving its marker, and when it keeps failing
//! the index is synced instead. That sync is the ordinary
//! non-destructive one: the watch loop never resets the index, so UIDs
//! and UIDVALIDITY survive every recovery. The output is fixed text and
//! counters only: ids, tokens, subjects, addresses, and URLs never
//! appear in it. An optional notifier additionally broadcasts local
//! mailbox ids — nothing else — after each applied batch and after each
//! sync.
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
use std::pin::{pin, Pin};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::{broadcast, oneshot};

use crate::adapters::imap::backend::TutaImapBackend;
use crate::adapters::imap::server::{self, ensure_certificate, tls_acceptor, ServeLimits};
use crate::adapters::mime::MimeRenderer;
use crate::adapters::pop3::server::{serve_pop3, Pop3ServeLimits};
use crate::adapters::smtp::server::{serve_smtp, SmtpServeLimits};
use crate::adapters::sqlite_state::STATE_BUSY_MESSAGE;
use crate::adapters::tuta::event_wire::is_invalid_event;
use crate::adapters::tuta::generated_id::{
    batch_is_expired, generated_id_timestamp, timestamp_to_generated_id,
};
use crate::app::enrich::EnvelopeEnricher;
use crate::app::event_sync::{deletes_folder, EventProcessor, EventReport};
use crate::app::state_sync::{current_uidvalidity, sync_with};
use crate::app::sync::{SyncEngine, SyncReport};
use crate::config::{resolve_imap_port, validate_imap_port, Config};
use crate::domain::{AccountId, Error, EventBatch, EventFrame, Result};
use crate::ports::clock::Clock;
use crate::ports::credentials::CredentialStore;
use crate::ports::event_lookup::EventLookup;
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

/// Production number of attempts at applying one event batch before the
/// index is synced instead.
pub const LOOKUP_FAILURE_THRESHOLD: usize = 10;

/// Connections in a row that may end on the same unparseable event
/// message before the index is synced and the markers are moved past it.
pub const INVALID_FRAME_LIMIT: u32 = 3;

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
/// configuration errors need the user to act, so they are fatal. The one
/// storage error with a retry of its own is a momentarily locked state
/// database while a batch is applied.
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
    /// Attempts at applying one batch whose entity lookups fail before
    /// the index is synced instead; unreadable or unhandled events
    /// never count as failures.
    pub lookup_failure_threshold: usize,
    /// Broadcasts one [`MailboxChanged`] per mailbox each applied batch
    /// touched, and one per current mailbox after a sync. `None` — the
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
    ///
    /// `stop` is raced against every wait of the loop — the index sync,
    /// the connect, each frame read, the application of a batch
    /// including its retries, and every backoff sleep — so it takes
    /// effect promptly wherever the loop is. Abandoning a step is safe:
    /// a batch is written in one transaction together with its marker,
    /// and an interrupted sync is simply repeated by the next one.
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

        // 3. The stored markers, and whether the index must be synced
        //    before the stream can be trusted to bring it up to date.
        let (mut batches, mut needs_sync) = self.stored_markers(account_id, &groups).await?;

        // 4. Sync-and-reconnect loop: network errors retry with the
        //    backoff, everything else is fatal.
        let processor = EventProcessor::new(Arc::clone(&self.state));
        let mut stop = pin!(stop);
        let mut attempt: u32 = 0;
        // Connections in a row that ended on an unparseable frame.
        let mut invalid_frames: u32 = 0;
        // A folder was deleted on the server and not yet removed here.
        let mut folders_stale = false;
        loop {
            // The index sync runs first whenever events alone cannot be
            // trusted: at startup without usable markers, and after a
            // batch that could not be applied or parsed. It never resets anything,
            // so every UID and UIDVALIDITY survives it. A network
            // failure leaves the markers alone and comes back here
            // after the backoff.
            if needs_sync {
                let recovery = self.recover(session.as_ref(), account_id, &groups);
                let Some(recovered) = unless_stopped(&mut stop, recovery).await else {
                    return Ok(());
                };
                match recovered {
                    Ok(markers) => {
                        batches = markers;
                        needs_sync = false;
                        // The sync reconciled the folder list as well.
                        folders_stale = false;
                    }
                    Err(e) if is_fatal(&e) => return Err(e),
                    Err(_) => {
                        attempt += 1;
                        let delay = self.backoff.delay_ms(attempt);
                        println!("index sync failed; retrying in {delay} ms");
                        let sleep = tokio::time::sleep(Duration::from_millis(delay));
                        if unless_stopped(&mut stop, sleep).await.is_none() {
                            return Ok(());
                        }
                        continue;
                    }
                }
            }

            // A folder reconciliation that failed earlier is tried again
            // before every connect.
            if folders_stale {
                let reconcile = self.reconcile_folders(session.as_ref(), account_id);
                let Some(reconciled) = unless_stopped(&mut stop, reconcile).await else {
                    return Ok(());
                };
                folders_stale = !reconciled?;
            }

            // A failed or hung connect is retried like a dropped
            // connection: it shares the backoff below with frame errors.
            // The timeout bounds how long one connect may stall the
            // loop.
            let connected_ms = self.clock.now_ms();
            let connect =
                tokio::time::timeout(self.connect_timeout, session.events(&batches, connected_ms));
            let Some(connected) = unless_stopped(&mut stop, connect).await else {
                return Ok(());
            };
            let handles = match connected {
                Ok(Ok(handles)) => Some(handles),
                Ok(Err(e)) if is_fatal(&e) => return Err(e),
                // A network error or a timed-out connect is retried
                // on a fresh connection.
                Ok(Err(_)) | Err(_) => None,
            };

            if let Some(handles) = handles {
                let lookup = handles.lookup;
                let mut stream = handles.stream;
                loop {
                    let Some(frame) = unless_stopped(&mut stop, stream.next_frame()).await else {
                        return Ok(());
                    };
                    let frame = match frame {
                        Ok(frame) => frame,
                        Err(e) if is_fatal(&e) => return Err(e),
                        // A network error is retried on a fresh
                        // connection. A frame that does not parse ends
                        // the stream the same way, but the server will
                        // replay it unchanged, so those are counted.
                        Err(e) => {
                            if is_invalid_event(&e) {
                                invalid_frames += 1;
                            } else {
                                invalid_frames = 0;
                            }
                            break;
                        }
                    };
                    // Any successful frame proves the connection works again.
                    attempt = 0;
                    match frame {
                        EventFrame::Batch(batch) => {
                            let applying = self.apply_with_retries(
                                &processor,
                                account_id,
                                lookup.as_ref(),
                                &batch,
                            );
                            let Some(applied) = unless_stopped(&mut stop, applying).await else {
                                return Ok(());
                            };
                            let Some(report) = applied? else {
                                // The batch kept failing. Its marker
                                // never moved, so nothing is lost yet:
                                // the sync at the top of the loop reads
                                // the current state instead and resumes
                                // the stream after it.
                                println!("event batch could not be applied; syncing the index");
                                needs_sync = true;
                                break;
                            };
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
                            // A deleted folder cannot be resolved from
                            // its event, and no `sync` can run beside
                            // this process, so the stored folders are
                            // compared with the server's list here. A
                            // network failure keeps the flag for the
                            // next applied batch or connect.
                            folders_stale |= deletes_folder(&batch);
                            if folders_stale {
                                let reconcile =
                                    self.reconcile_folders(session.as_ref(), account_id);
                                let Some(reconciled) = unless_stopped(&mut stop, reconcile).await
                                else {
                                    return Ok(());
                                };
                                folders_stale = !reconciled?;
                            }
                        }
                        EventFrame::InitialSyncDone => {
                            println!("event stream caught up");
                            self.refresh_quiet_markers(
                                account_id,
                                &groups,
                                &mut batches,
                                connected_ms,
                            )
                            .await?;
                        }
                        EventFrame::Ignored => continue,
                    }
                }
            }

            // Reconnecting cannot get past a frame the server keeps
            // replaying: without a bound the group would stall forever.
            // After a few identical failures the index is synced, which
            // re-stamps the markers past the frame.
            if invalid_frames >= INVALID_FRAME_LIMIT {
                println!("event message could not be read; syncing the index");
                invalid_frames = 0;
                needs_sync = true;
            }
            if needs_sync {
                // The sync replaces the failed batch right away.
                continue;
            }
            attempt += 1;
            // Repeated unreadable frames back off even though each
            // connection delivered frames before them.
            let delay = self.backoff.delay_ms(attempt.max(invalid_frames));
            println!("event stream lost; retrying in {delay} ms");
            let sleep = tokio::time::sleep(Duration::from_millis(delay));
            if unless_stopped(&mut stop, sleep).await.is_none() {
                return Ok(());
            }
        }
    }

    /// Load the stored batch markers and decide whether the index needs
    /// a sync before events are consumed.
    ///
    /// It does when the index is still empty, when a group has no marker
    /// yet, or when a marker is older than the server's replay window:
    /// in each case the events since the stored state cannot be replayed
    /// in full. Only replayable markers are returned.
    async fn stored_markers(
        &self,
        account_id: i64,
        groups: &[String],
    ) -> Result<(HashMap<String, String>, bool)> {
        let now_ms = self.clock.now_ms();
        let mut needs_sync = self.state.mailboxes(account_id).await?.is_empty();
        let mut batches: HashMap<String, String> = HashMap::new();
        for group in groups {
            match self.state.last_batch(account_id, group).await? {
                Some(marker) if !batch_is_expired(&marker, now_ms) => {
                    batches.insert(group.clone(), marker);
                }
                _ => needs_sync = true,
            }
        }
        Ok((batches, needs_sync))
    }

    /// Bring the index up to date with a sync and return fresh markers.
    ///
    /// This is the one recovery path for an index that events alone
    /// cannot repair: no usable marker at startup, or a batch that could
    /// not be applied. The sync is the ordinary non-destructive one —
    /// known mail keeps its UID and no UIDVALIDITY changes — so IMAP
    /// clients keep their caches.
    ///
    /// The resume stamp is taken five seconds before the sync starts and
    /// written for every group only after it succeeded: events that
    /// arrive while it runs postdate the stamp and are replayed, and a
    /// failed sync leaves the old markers in place. Stamping every group
    /// is safe because the sync has just read the complete mail state
    /// and events of other applications are skipped anyway.
    async fn recover(
        &self,
        session: &dyn Session,
        account_id: i64,
        groups: &[String],
    ) -> Result<HashMap<String, String>> {
        let resume_id = timestamp_to_generated_id((self.clock.now_ms() - 5_000).max(0));
        let report = sync_with(
            Arc::clone(&self.state),
            session.mail(),
            account_id,
            current_uidvalidity(),
        )
        .await?;
        print_sync_report(&report);

        let mut batches = HashMap::new();
        for group in groups {
            self.state
                .set_last_batch(account_id, group, &resume_id)
                .await?;
            batches.insert(group.clone(), resume_id.clone());
        }
        // A sync never goes through `apply_batch`, so every current
        // mailbox is announced here: idling sessions must re-examine
        // their cached views. A closed channel only means nobody idles,
        // so send errors are ignored.
        if let Some(notifier) = &self.notifier {
            for mailbox in self.state.mailboxes(account_id).await? {
                let _ = notifier.send(MailboxChanged(mailbox.id));
            }
        }
        Ok(batches)
    }

    /// Remove the mailboxes of folders that no longer exist on the server.
    ///
    /// `Ok(true)` means the stored folders now match the server's list;
    /// every removed mailbox is announced so sessions that have it
    /// selected notice. `Ok(false)` means the list could not be loaded
    /// and the caller should try again later.
    async fn reconcile_folders(&self, session: &dyn Session, account_id: i64) -> Result<bool> {
        let engine = SyncEngine::new(Arc::clone(&self.state));
        match engine.reconcile_folders(account_id, session.mail()).await {
            Ok(removed) => {
                if !removed.is_empty() {
                    println!("removed {} deleted folders", removed.len());
                }
                if let Some(notifier) = &self.notifier {
                    for mailbox in removed {
                        let _ = notifier.send(MailboxChanged(mailbox));
                    }
                }
                Ok(true)
            }
            Err(e) if is_fatal(&e) => Err(e),
            Err(_) => Ok(false),
        }
    }

    /// Apply one batch, retrying it in place while it cannot be applied.
    ///
    /// A batch whose entity lookup failed is not persisted and its
    /// marker does not move, so the same batch is tried again after the
    /// backoff delay, up to `lookup_failure_threshold` attempts in all;
    /// `Ok(None)` then tells the caller to fall back to the index sync.
    /// A state database that is momentarily locked by another process is
    /// retried the same way, but if it stays locked the error is
    /// returned: a sync could not write either. Every other error is
    /// returned at once.
    async fn apply_with_retries(
        &self,
        processor: &EventProcessor,
        account_id: i64,
        lookup: &dyn EventLookup,
        batch: &EventBatch,
    ) -> Result<Option<EventReport>> {
        let mut failures: usize = 0;
        loop {
            let applied = processor
                .apply(account_id, lookup, current_uidvalidity(), batch)
                .await;
            let busy = match applied {
                Ok(report) if report.lookup_failures == 0 => return Ok(Some(report)),
                Ok(_) => None,
                Err(Error::Storage(message)) if message == STATE_BUSY_MESSAGE => {
                    Some(Error::Storage(message))
                }
                Err(e) => return Err(e),
            };
            failures += 1;
            if failures >= self.lookup_failure_threshold {
                return match busy {
                    Some(error) => Err(error),
                    None => Ok(None),
                };
            }
            let delay = self
                .backoff
                .delay_ms(u32::try_from(failures).unwrap_or(u32::MAX));
            println!("event batch not applied; retrying in {delay} ms");
            tokio::time::sleep(Duration::from_millis(delay)).await;
        }
    }

    /// Move the markers of groups without recent events up to the
    /// moment this connection was opened.
    ///
    /// A marker only advances when a batch of its group is applied, so a
    /// group that never has events would keep its first stamp until it
    /// fell out of the server's replay window and forced a sync at the
    /// next start. The server announces `initialSyncDone` once it has
    /// replayed everything the markers of this connection were missing,
    /// so at that point no group has an unprocessed batch older than
    /// the connect: markers older than five seconds before it are
    /// re-stamped to that instant. Markers that are newer, or that do
    /// not decode as generated ids, are left alone.
    async fn refresh_quiet_markers(
        &self,
        account_id: i64,
        groups: &[String],
        batches: &mut HashMap<String, String>,
        connected_ms: i64,
    ) -> Result<()> {
        let floor_ms = (connected_ms - 5_000).max(0);
        let floor_id = timestamp_to_generated_id(floor_ms);
        for group in groups {
            let quiet = batches
                .get(group)
                .and_then(|marker| generated_id_timestamp(marker))
                .is_some_and(|stamped_ms| stamped_ms < floor_ms);
            if quiet {
                self.state
                    .set_last_batch(account_id, group, &floor_id)
                    .await?;
                batches.insert(group.clone(), floor_id.clone());
            }
        }
        Ok(())
    }
}

/// Run `work` to completion unless `stop` resolves first.
///
/// `None` means the stop won and `work` was dropped where it stood; the
/// caller must return without polling `stop` again.
async fn unless_stopped<S, W>(stop: &mut Pin<&mut S>, work: W) -> Option<W::Output>
where
    S: Future<Output = ()>,
    W: Future,
{
    tokio::select! {
        biased;
        output = work => Some(output),
        () = stop.as_mut() => None,
    }
}

/// Print the counters of an index sync; counts only, never mail data.
fn print_sync_report(report: &SyncReport) {
    println!(
        "index synced: {} folders, {} messages, {} removed, {} messages skipped, {} folders skipped",
        report.folders,
        report.messages,
        report.removed,
        report.skipped_messages,
        report.skipped_folders
    );
}

// ---------------------------------------------------------------------------
// serve
// ---------------------------------------------------------------------------

/// Capacity of the mailbox-change broadcast: one event per touched
/// mailbox per batch, plus one per mailbox after a sync. A consumer
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
    /// Attempts at applying one watch batch whose lookups fail before
    /// the index is synced instead.
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
            writer: session.shared_writer(),
        });
        let mail_sender = session.shared_sender();
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
        // POP3 is opt-in: it listens only when the config names a port.
        let pop3_listener = match config.pop3_port {
            Some(pop3_port) => {
                validate_imap_port(pop3_port)
                    .map_err(|_| Error::Config("pop3_port must be between 1 and 65535".into()))?;
                let pop3_listener = TcpListener::bind(("127.0.0.1", pop3_port))
                    .await
                    .map_err(|_| Error::Network("pop3 listener bind failed".into()))?;
                println!("serving POP3 on 127.0.0.1:{pop3_port}");
                Some(pop3_listener)
            }
            None => None,
        };
        // SMTP is opt-in as well: sending is non-confidential (see the
        // README), so it listens only when the config names a port.
        let smtp_listener = match config.smtp_port {
            Some(smtp_port) => {
                validate_imap_port(smtp_port)
                    .map_err(|_| Error::Config("smtp_port must be between 1 and 65535".into()))?;
                let smtp_listener = TcpListener::bind(("127.0.0.1", smtp_port))
                    .await
                    .map_err(|_| Error::Network("smtp listener bind failed".into()))?;
                println!(
                    "serving SMTP submission on 127.0.0.1:{smtp_port} (not end-to-end encrypted)"
                );
                Some(smtp_listener)
            }
            None => None,
        };
        println!("serving IMAP on 127.0.0.1:{port}; press Ctrl-C to stop");

        // 7. Accept until the stop future resolves, then end the
        //    watch loop and return its result. A watch that ended on
        //    its own — only a fatal error can — ends serve with that
        //    error. Failures close one connection at most, a failed
        //    accept included: the accept loop itself never ends.
        let mut stop = pin!(stop);
        let smtp_auth = Arc::clone(&backend);
        let smtp_tls = tls.clone();
        let mut smtp_accepting = pin!(async move {
            match smtp_listener {
                Some(smtp_listener) => {
                    serve_smtp(
                        smtp_listener,
                        smtp_tls,
                        smtp_auth,
                        mail_sender,
                        SmtpServeLimits::default(),
                    )
                    .await
                }
                None => std::future::pending().await,
            }
        });
        let pop3_backend = Arc::clone(&backend);
        let pop3_tls = tls.clone();
        let mut pop3_accepting = pin!(async move {
            match pop3_listener {
                Some(pop3_listener) => {
                    serve_pop3(
                        pop3_listener,
                        pop3_tls,
                        pop3_backend,
                        Pop3ServeLimits::default(),
                    )
                    .await
                }
                None => std::future::pending().await,
            }
        });
        let mut accepting = pin!(server::serve(
            listener,
            tls,
            backend,
            sender,
            ServeLimits::default()
        ));
        tokio::select! {
            biased;
            _ = &mut stop => {}
            watched = &mut watch_task => {
                return match watched {
                    Ok(result) => result,
                    Err(_) => Err(Error::Storage("watch task failed".into())),
                };
            }
            () = &mut accepting => {}
            () = &mut pop3_accepting => {}
            () = &mut smtp_accepting => {}
        }
        let _ = stop_watch.send(());
        match watch_task.await {
            Ok(result) => result,
            Err(_) => Err(Error::Storage("watch task failed".into())),
        }
    }
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
