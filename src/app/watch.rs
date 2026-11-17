//! Long-running Tuta event-bus watcher.
//!
//! [`WatchUseCase`] resumes the stored session, reconciles the local index
//! with a baseline (re)sync, and then consumes the event bus until it is
//! stopped. Network failures — including connects that hang until the
//! connect timeout — reconnect with a capped backoff; every other error is
//! fatal because it needs the user to act. A run of batches whose entity
//! lookups fail resyncs the index, exactly like an expired marker. The
//! output is fixed text and counters only: ids, tokens, subjects,
//! addresses, and URLs never appear in it.

use std::collections::HashMap;
use std::future::Future;
use std::path::PathBuf;
use std::pin::pin;
use std::sync::Arc;
use std::time::Duration;

use crate::adapters::tuta::generated_id::{batch_is_expired, timestamp_to_generated_id};
use crate::app::event_sync::EventProcessor;
use crate::app::state_sync::{current_uidvalidity, next_uidvalidity, resync_with, sync_with};
use crate::config::Config;
use crate::domain::{AccountId, Error, EventFrame, Result};
use crate::ports::clock::Clock;
use crate::ports::credentials::CredentialStore;
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
}

impl WatchUseCase {
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
        Ok(batches)
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
