use std::process;
use std::sync::Arc;

use tracing_subscriber::EnvFilter;

use tuta_bridge::adapters::cli::Command;
use tuta_bridge::adapters::keyring_store::KeyringCredentialStore;
use tuta_bridge::adapters::mime::MimeRenderer;
use tuta_bridge::adapters::terminal_prompt::TerminalPrompt;
use tuta_bridge::adapters::tuta::session::TutaSessionFactory;
use tuta_bridge::app::dump::{DumpArgs, DumpUseCase};
use tuta_bridge::app::login::LoginUseCase;
use tuta_bridge::app::logout::LogoutUseCase;
use tuta_bridge::app::state_sync::{open_state_store, StateSyncUseCase};
use tuta_bridge::app::status::StatusUseCase;
use tuta_bridge::app::sync::SyncReport;
use tuta_bridge::app::watch::{
    BackoffPolicy, WatchUseCase, CONNECT_TIMEOUT, LOOKUP_FAILURE_THRESHOLD,
};
use tuta_bridge::config::{config_path, data_dir, resolve_base_url, validate_base_url, Config};
use tuta_bridge::domain::Error;
use tuta_bridge::ports::clock::Clock;
use tuta_bridge::ports::renderer::MessageRenderer;

use tutasdk::bindings::native_file_client::NativeFileClient;
use tutasdk::bindings::rest_client::RestClient;
use tutasdk::bindings::suspendable_rest_client::SuspendableRestClient;
use tutasdk::date::{DateProvider, DateTime};
use tutasdk::net::native_rest_client::NativeRestClient;
use tutasdk::Sdk;

/// A local [`DateProvider`] that returns the current system time.
struct SystemClock;

impl DateProvider for SystemClock {
    fn now(&self) -> DateTime {
        DateTime::from_system_time(std::time::SystemTime::now())
    }
}

impl Clock for SystemClock {
    fn now_ms(&self) -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX))
            .unwrap_or(0)
    }
}

fn main() {
    // 1. Initialise tracing (writes to stderr).
    let mut filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    // Always silence the keyring/secret-service targets so `RUST_LOG=debug`
    // cannot emit the account address (the keyring username) or other secrets.
    for directive in [
        "keyring=off",
        "secret_service=off",
        "zbus=off",
        "tutasdk::bindings::native_file_client=off",
    ] {
        filter = filter.add_directive(directive.parse().expect("valid directive"));
    }
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();

    // 2. Parse CLI arguments.
    let cli = match tuta_bridge::adapters::cli::parse_from(std::env::args_os()) {
        Ok(cli) => cli,
        Err(e) => e.exit(),
    };
    let debug = cli.debug;

    // 3. Load configuration and resolve the base URL.
    let config_path = match config_path() {
        Ok(p) => p,
        Err(e) => exit_with_error(Error::Config(e.to_string())),
    };
    let config = match Config::load(&config_path) {
        Ok(c) => c,
        Err(e) => exit_with_error(Error::Config(e.to_string())),
    };
    let base_url = resolve_base_url(
        cli.base_url.as_deref(),
        std::env::var("TUTA_BRIDGE_BASE_URL").ok().as_deref(),
        &config,
    );

    // 4. Validate the base URL.
    if let Err(msg) = validate_base_url(&base_url) {
        exit_with_error(Error::Config(msg));
    }

    // 5. Build the SDK components.
    let raw: Arc<dyn RestClient> = match NativeRestClient::try_new() {
        Ok(c) => Arc::new(c),
        Err(e) => exit_with_error(Error::Network(e.to_string())),
    };
    let data_dir = match data_dir() {
        Ok(d) => d,
        Err(e) => exit_with_error(Error::Config(e.to_string())),
    };
    let file_client = match NativeFileClient::try_new(data_dir) {
        Ok(fc) => Arc::new(fc),
        Err(e) => exit_with_error(Error::Config(e.to_string())),
    };
    let sdk = Sdk::new(base_url.clone(), Arc::clone(&raw), file_client);
    let suspendable: Arc<dyn RestClient> = Arc::new(SuspendableRestClient::new(
        Arc::clone(&raw),
        Arc::new(SystemClock),
    ));

    let store = Arc::new(KeyringCredentialStore::new("tuta-bridge"));
    let prompt = Arc::new(TerminalPrompt);
    let factory = Arc::new(TutaSessionFactory::new(sdk, suspendable, base_url, debug));

    // 6. Dispatch.
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => exit_with_error(Error::Network(e.to_string())),
    };

    let result = rt.block_on(async {
        match cli.command {
            Command::Login { email } => {
                let uc = LoginUseCase::new(
                    Arc::clone(&factory) as Arc<dyn tuta_bridge::ports::session::SessionFactory>,
                    Arc::clone(&store) as Arc<dyn tuta_bridge::ports::credentials::CredentialStore>,
                    Arc::clone(&prompt) as Arc<dyn tuta_bridge::ports::prompt::LoginPrompt>,
                    config_path,
                );
                let info = uc.execute(email).await?;
                println!("logged in as {}", info.mail_address);
                Ok(())
            }
            Command::Status => {
                let uc = StatusUseCase {
                    store: Arc::clone(&store)
                        as Arc<dyn tuta_bridge::ports::credentials::CredentialStore>,
                    config_path,
                };
                match uc.execute().await? {
                    Some(info) => println!("{} ({})", info.mail_address, info.user_id),
                    None => println!("not logged in"),
                }
                Ok(())
            }
            Command::Sync => {
                let uc = StateSyncUseCase::new(
                    Arc::clone(&factory) as Arc<dyn tuta_bridge::ports::session::SessionFactory>,
                    Arc::clone(&store) as Arc<dyn tuta_bridge::ports::credentials::CredentialStore>,
                    config_path,
                );
                let report = uc.sync().await?;
                print_sync_report("synced", &report);
                Ok(())
            }
            Command::Resync => {
                let uc = StateSyncUseCase::new(
                    Arc::clone(&factory) as Arc<dyn tuta_bridge::ports::session::SessionFactory>,
                    Arc::clone(&store) as Arc<dyn tuta_bridge::ports::credentials::CredentialStore>,
                    config_path,
                );
                let report = uc.resync().await?;
                print_sync_report("resynced", &report);
                Ok(())
            }
            Command::Watch => {
                let state = open_state_store().await?;
                let uc = WatchUseCase {
                    factory: Arc::clone(&factory)
                        as Arc<dyn tuta_bridge::ports::session::SessionFactory>,
                    credentials: Arc::clone(&store)
                        as Arc<dyn tuta_bridge::ports::credentials::CredentialStore>,
                    config_path,
                    state,
                    clock: Arc::new(SystemClock),
                    backoff: BackoffPolicy::production(),
                    connect_timeout: CONNECT_TIMEOUT,
                    lookup_failure_threshold: LOOKUP_FAILURE_THRESHOLD,
                    notifier: None,
                };
                uc.run().await?;
                Ok(())
            }
            Command::Logout => {
                let uc = LogoutUseCase {
                    factory: Arc::clone(&factory)
                        as Arc<dyn tuta_bridge::ports::session::SessionFactory>,
                    store: Arc::clone(&store)
                        as Arc<dyn tuta_bridge::ports::credentials::CredentialStore>,
                    config_path,
                };
                uc.execute().await?;
                println!("logged out");
                Ok(())
            }
            Command::Dump { folder, limit, out } => {
                let uc = DumpUseCase::new(
                    Arc::clone(&factory) as Arc<dyn tuta_bridge::ports::session::SessionFactory>,
                    Arc::clone(&store) as Arc<dyn tuta_bridge::ports::credentials::CredentialStore>,
                    Arc::new(MimeRenderer) as Arc<dyn MessageRenderer>,
                    config_path,
                );
                let report = uc
                    .execute(DumpArgs {
                        folder,
                        limit,
                        out: out.clone(),
                    })
                    .await?;
                println!("wrote {} messages to {}", report.written, out.display());
                Ok(())
            }
        }
    });

    if let Err(e) = result {
        exit_with_error(e);
    }
}

/// Print sync counters, showing optional counters only when non-zero.
///
/// Only aggregate counts are written; subjects and addresses never appear.
fn print_sync_report(verb: &str, report: &SyncReport) {
    println!(
        "{verb} {} folders, {} messages",
        report.folders, report.messages
    );
    if report.removed > 0 {
        println!("removed {} messages", report.removed);
    }
    if report.skipped_messages > 0 {
        println!("skipped {} messages", report.skipped_messages);
    }
    if report.skipped_folders > 0 {
        println!("skipped {} folders", report.skipped_folders);
    }
}

fn exit_with_error(e: Error) -> ! {
    eprintln!("error: {e}");
    process::exit(e.exit_code() as i32);
}

#[cfg(test)]
mod tests {
    #[test]
    fn error_exit_codes_are_used() {
        assert_eq!(tuta_bridge::domain::Error::NoActiveAccount.exit_code(), 3);
    }
}
