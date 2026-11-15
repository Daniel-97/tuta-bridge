use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::adapters::tuta::mail_source::resolve_folder;
use crate::config::Config;
use crate::domain::{AccountId, Error, Result};
use crate::ports::credentials::CredentialStore;
use crate::ports::renderer::MessageRenderer;
use crate::ports::session::SessionFactory;

/// Arguments for the dump use case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DumpArgs {
    pub folder: String,
    pub limit: usize,
    pub out: PathBuf,
}

/// Outcome of a successful dump. On partial failure the use case returns
/// [`Error::PartialDump`] instead, so `failed` is always empty here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DumpReport {
    pub written: usize,
    pub failed: Vec<String>,
}

pub struct DumpUseCase {
    pub factory: Arc<dyn SessionFactory>,
    pub store: Arc<dyn CredentialStore>,
    pub renderer: Arc<dyn MessageRenderer>,
    pub config_path: PathBuf,
}

impl DumpUseCase {
    pub fn new(
        factory: Arc<dyn SessionFactory>,
        store: Arc<dyn CredentialStore>,
        renderer: Arc<dyn MessageRenderer>,
        config_path: PathBuf,
    ) -> Self {
        Self {
            factory,
            store,
            renderer,
            config_path,
        }
    }

    pub async fn execute(&self, args: DumpArgs) -> Result<DumpReport> {
        // 1. Load configuration and require an active account.
        let config = Config::load(&self.config_path).map_err(|e| Error::Config(e.to_string()))?;
        let account = config.active_account.ok_or(Error::NoActiveAccount)?;

        // 2. Load credentials for the active account.
        let credentials = match self.store.load(&AccountId(account))? {
            Some(c) => c,
            None => return Err(Error::MissingCredentials),
        };

        // 3. Resume the session and read the mail source. Never closed here.
        let session = self.factory.resume(&credentials).await?;
        let source = session.mail();

        // 4. Resolve the requested folder and list its messages.
        let folders = source.folders().await?;
        let folder = resolve_folder(&folders, &args.folder)?;
        let messages = source.messages(folder, args.limit).await?;

        // 5. Create the output directory with mode 0700 when missing.
        create_private_dir(&args.out)?;

        // 6. Render and write one .eml file per message. Per-message errors are
        //    collected by "{list_id}/{element_id}" and never logged in detail.
        let mut written = 0usize;
        let mut failed = Vec::new();

        for message in messages {
            let bytes = match source.content(&message).await {
                Ok(content) => match self.renderer.render(&content) {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        failed.push(format!("{}/{}", message.list_id, message.element_id));
                        continue;
                    }
                },
                Err(_) => {
                    failed.push(format!("{}/{}", message.list_id, message.element_id));
                    continue;
                }
            };

            let path = args.out.join(format!("{}.eml", message.file_stem()));
            if std::fs::write(&path, &bytes).is_err() {
                failed.push(format!("{}/{}", message.list_id, message.element_id));
                continue;
            }
            written += 1;
        }

        if !failed.is_empty() {
            return Err(Error::PartialDump {
                failed: failed.len(),
            });
        }

        Ok(DumpReport { written, failed })
    }
}

/// Create `path` (and parents) with mode `0700` on Unix, leaving an existing
/// directory untouched.
fn create_private_dir(path: &Path) -> Result<()> {
    if path.exists() {
        return Ok(());
    }
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(path)
        .map_err(|_| Error::Storage(format!("failed to create directory {}", path.display())))
}
