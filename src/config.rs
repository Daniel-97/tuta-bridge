use anyhow::{anyhow, Context};
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const DEFAULT_BASE_URL: &str = "https://app.tuta.com";
const APP_DIR: &str = "tuta-bridge";

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_account: Option<String>,
    pub base_url: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            active_account: None,
            base_url: DEFAULT_BASE_URL.to_owned(),
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        match fs::read_to_string(path) {
            Ok(text) => toml::from_str(&text)
                .map_err(|_| anyhow!("failed to parse config file {}", path.display())),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(anyhow::Error::new(e)
                .context(format!("failed to read config file {}", path.display()))),
        }
    }

    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            create_private_dir(parent)?;
        }
        let text = toml::to_string(self).context("failed to serialize config")?;
        write_private_file(path, text.as_bytes())
            .with_context(|| format!("failed to write config file {}", path.display()))
    }
}

/// Write `contents` to `path`, creating the file (and tightening an existing
/// one) with mode `0600` on Unix so it is never world-readable.
pub(crate) fn write_private_file(path: &Path, contents: &[u8]) -> io::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    use std::io::Write;
    file.write_all(contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Tighten an already-existing file that may carry looser permissions.
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

pub fn validate_base_url(url: &str) -> std::result::Result<(), String> {
    let error =
        || "base URL must be https://app.tuta.com (http is allowed only for loopback)".to_string();

    if let Some(rest) = url.strip_prefix("https://") {
        // Only the official Tuta API hosts, with no userinfo, path, query,
        // fragment, or explicit port.
        if rest.contains(['/', '?', '#', '@']) {
            return Err(error());
        }
        return match rest {
            "app.tuta.com" | "app.tutanota.com" => Ok(()),
            _ => Err(error()),
        };
    }

    let Some(rest) = url.strip_prefix("http://") else {
        return Err(error());
    };
    if rest.is_empty() || rest.contains(['/', '?', '#', '@']) {
        return Err(error());
    }

    // http is only allowed for loopback hosts.
    let authority = rest;
    let host = if authority.starts_with('[') {
        authority
            .find(']')
            .map(|i| &authority[..=i])
            .unwrap_or(authority)
    } else {
        authority.split(':').next().unwrap_or(authority)
    };

    if host == "127.0.0.1" || host == "localhost" || host == "[::1]" {
        Ok(())
    } else {
        Err(error())
    }
}

pub fn resolve_base_url(cli: Option<&str>, env: Option<&str>, config: &Config) -> String {
    cli.filter(|s| !s.is_empty())
        .or(env.filter(|s| !s.is_empty()))
        .unwrap_or(&config.base_url)
        .to_owned()
}

pub fn config_path() -> anyhow::Result<PathBuf> {
    let base = xdg_base(
        std::env::var_os("XDG_CONFIG_HOME"),
        std::env::var_os("HOME"),
        ".config",
    )?;
    Ok(base.join(APP_DIR).join("config.toml"))
}

pub fn data_dir() -> anyhow::Result<PathBuf> {
    let base = xdg_base(
        std::env::var_os("XDG_DATA_HOME"),
        std::env::var_os("HOME"),
        ".local/share",
    )?;
    let dir = base.join(APP_DIR);
    create_private_dir(&dir)?;
    tighten_private_dir(&dir)?;
    Ok(dir)
}

/// Path of the SQLite state database inside the private data directory.
pub fn state_path() -> anyhow::Result<PathBuf> {
    Ok(data_dir()?.join("state.sqlite3"))
}

fn xdg_base(
    xdg: Option<OsString>,
    home: Option<OsString>,
    home_fallback: &str,
) -> anyhow::Result<PathBuf> {
    if let Some(dir) = xdg.map(PathBuf::from).filter(|p| p.is_absolute()) {
        return Ok(dir);
    }
    let home = home
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .ok_or_else(|| anyhow!("HOME is not set to an absolute path"))?;
    Ok(home.join(home_fallback))
}

fn create_private_dir(path: &Path) -> anyhow::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(path)
        .with_context(|| format!("failed to create directory {}", path.display()))
}

/// Restrict an already existing directory to owner-only access.
///
/// `DirBuilder::mode` only affects newly created directories, so the data
/// directory is tightened explicitly in case it predates this code or was
/// created with a looser mode.
#[cfg(unix)]
fn tighten_private_dir(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("failed to tighten permissions on {}", path.display()))
}

#[cfg(not(unix))]
fn tighten_private_dir(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xdg_base_prefers_absolute_xdg_then_home() {
        assert_eq!(
            xdg_base(Some("/x/cfg".into()), Some("/home/u".into()), ".config").unwrap(),
            PathBuf::from("/x/cfg")
        );
        assert_eq!(
            xdg_base(Some("relative".into()), Some("/home/u".into()), ".config").unwrap(),
            PathBuf::from("/home/u/.config")
        );
        assert_eq!(
            xdg_base(None, Some("/home/u".into()), ".local/share").unwrap(),
            PathBuf::from("/home/u/.local/share")
        );
        assert!(xdg_base(None, None, ".config").is_err());
    }

    #[test]
    fn empty_cli_and_env_fall_back_to_config() {
        let cfg = Config {
            active_account: None,
            base_url: "https://cfg.example".into(),
        };
        assert_eq!(
            resolve_base_url(Some(""), Some(""), &cfg),
            "https://cfg.example"
        );
        assert_eq!(
            resolve_base_url(Some(""), Some("https://env.example"), &cfg),
            "https://env.example"
        );
    }

    #[test]
    fn parse_error_names_path_without_file_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, "base_url = \"secret-looking-value\n").unwrap();
        let err = match Config::load(&path) {
            Err(e) => e,
            Ok(_) => panic!("expected parse error"),
        };
        let msg = format!("{:#}", err);
        assert!(msg.contains(&path.display().to_string()));
        assert!(!msg.contains("secret-looking-value"));
    }

    #[test]
    fn missing_file_returns_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = Config::load(&dir.path().join("config.toml")).unwrap();
        assert_eq!(cfg.active_account, None);
        assert_eq!(cfg.base_url, "https://app.tuta.com");
    }

    #[test]
    fn roundtrips_and_resolves_precedence() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let cfg = Config {
            active_account: Some("a@b.c".into()),
            base_url: "https://cfg.example".into(),
        };
        cfg.save(&path).unwrap();
        assert!(Config::load(&path).unwrap() == cfg);
        assert_eq!(
            resolve_base_url(
                Some("https://cli.example"),
                Some("https://env.example"),
                &cfg
            ),
            "https://cli.example"
        );
        assert_eq!(
            resolve_base_url(None, Some("https://env.example"), &cfg),
            "https://env.example"
        );
        assert_eq!(resolve_base_url(None, None, &cfg), "https://cfg.example");
    }

    #[test]
    fn validate_base_url_accepts_only_official_tuta_hosts() {
        assert!(validate_base_url("https://app.tuta.com").is_ok());
        assert!(validate_base_url("https://app.tutanota.com").is_ok());
        assert!(validate_base_url("https://app.tuta.com.evil.example").is_err());
        assert!(validate_base_url("https://evil.example").is_err());
        assert!(validate_base_url("https://app.tuta.com/path").is_err());
        assert!(validate_base_url("https://user@app.tuta.com").is_err());
        assert!(validate_base_url("https://app.tuta.com:443").is_err());
        assert!(validate_base_url("https://").is_err());
        assert!(validate_base_url("https:///path").is_err());
    }

    #[test]
    fn validate_base_url_accepts_http_loopback() {
        assert!(validate_base_url("http://127.0.0.1").is_ok());
        assert!(validate_base_url("http://127.0.0.1:8080").is_ok());
        assert!(validate_base_url("http://localhost").is_ok());
        assert!(validate_base_url("http://localhost:3000").is_ok());
        assert!(validate_base_url("http://[::1]").is_ok());
        assert!(validate_base_url("http://[::1]:9000").is_ok());
    }

    #[test]
    fn validate_base_url_rejects_http_non_loopback() {
        assert!(validate_base_url("http://example.com").is_err());
        assert!(validate_base_url("http://192.168.1.1").is_err());
    }

    #[test]
    fn validate_base_url_rejects_other_schemes() {
        assert!(validate_base_url("ftp://example.com").is_err());
        assert!(validate_base_url("file:///etc/passwd").is_err());
        assert!(validate_base_url("not-a-url").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn tighten_private_dir_tightens_existing_directory() {
        use std::os::unix::fs::PermissionsExt;

        let parent = tempfile::tempdir().unwrap();
        let dir = parent.path().join("state");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();

        tighten_private_dir(&dir).unwrap();

        let mode = fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "existing directory must be tightened");
    }
}
