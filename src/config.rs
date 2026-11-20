use anyhow::{anyhow, Context};
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const DEFAULT_BASE_URL: &str = "https://app.tuta.com";
const APP_DIR: &str = "tuta-bridge";

/// Local IMAP listen port used when the config names none.
pub const DEFAULT_IMAP_PORT: u16 = 9930;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_account: Option<String>,
    pub base_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub imap_port: Option<u16>,
    /// The POP3S listen port. POP3 is opt-in: without this key `serve`
    /// does not listen for POP3 at all.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pop3_port: Option<u16>,
    /// The SMTP submission (implicit TLS) listen port. SMTP is opt-in:
    /// without this key `serve` does not accept mail to send.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub smtp_port: Option<u16>,
    /// The CalDAV (HTTPS, read-only) listen port. CalDAV is opt-in:
    /// without this key `serve` does not serve calendars. Suggested:
    /// 9933.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caldav_port: Option<u16>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            active_account: None,
            base_url: DEFAULT_BASE_URL.to_owned(),
            imap_port: None,
            pop3_port: None,
            smtp_port: None,
            caldav_port: None,
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

/// Write `contents` to `path` atomically, as a file with mode `0600` on Unix.
///
/// The bytes go to a fresh sibling file — created exclusively, so a planted
/// symlink or a file someone else already holds open is never written
/// through, and private from its first byte — which then replaces `path`
/// in one rename. A crash leaves either the old file or the new one, never
/// a truncated one.
pub(crate) fn write_private_file(path: &Path, contents: &[u8]) -> io::Result<()> {
    use std::io::Write;

    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;
    let mut temp_name = OsString::from(".");
    temp_name.push(name);
    temp_name.push(format!(".tmp{}", std::process::id()));
    let temp = path.with_file_name(temp_name);

    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = match options.open(&temp) {
        Ok(file) => file,
        // A leftover of an interrupted run of this same pid: replace it.
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            fs::remove_file(&temp)?;
            options.open(&temp)?
        }
        Err(e) => return Err(e),
    };

    let written = file
        .write_all(contents)
        .and_then(|()| file.sync_all())
        .and_then(|()| fs::rename(&temp, path));
    if written.is_err() {
        let _ = fs::remove_file(&temp);
        return written;
    }
    sync_parent_dir(path)
}

/// Flush the directory entry the rename just changed, so the replacement
/// itself survives a crash and not only the file's bytes.
#[cfg(unix)]
fn sync_parent_dir(path: &Path) -> io::Result<()> {
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    fs::File::open(parent)?.sync_all()
}

/// Directories cannot be opened for syncing outside Unix; the rename is
/// as durable as the platform makes it.
#[cfg(not(unix))]
fn sync_parent_dir(_path: &Path) -> io::Result<()> {
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

    // http is only allowed for loopback hosts, optionally followed by
    // one valid port and nothing else.
    let authority = rest;
    let (host, port) = if authority.starts_with('[') {
        match authority.find(']') {
            Some(i) => (&authority[..=i], &authority[i + 1..]),
            None => return Err(error()),
        }
    } else {
        match authority.find(':') {
            Some(i) => (&authority[..i], &authority[i..]),
            None => (authority, ""),
        }
    };
    let port_ok = match port.strip_prefix(':') {
        Some(digits) => {
            !digits.is_empty()
                && digits.bytes().all(|b| b.is_ascii_digit())
                && digits.parse::<u16>().is_ok_and(|port| port != 0)
        }
        None => port.is_empty(),
    };

    if port_ok && (host == "127.0.0.1" || host == "localhost" || host == "[::1]") {
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

/// Resolve the local IMAP listen port: the configured value, or the
/// default 9930 when the config names none.
pub fn resolve_imap_port(config: &Config) -> u16 {
    config.imap_port.unwrap_or(DEFAULT_IMAP_PORT)
}

/// Validate a configured IMAP port: only the range 1..=65535 is valid.
///
/// `u16` already bounds the upper end, so the only rejected value is
/// the reserved port 0.
pub fn validate_imap_port(port: u16) -> std::result::Result<(), String> {
    if (1..=u16::MAX).contains(&port) {
        Ok(())
    } else {
        Err("imap_port must be between 1 and 65535".to_string())
    }
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
            imap_port: None,
            pop3_port: None,
            smtp_port: None,
            caldav_port: None,
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
            imap_port: None,
            pop3_port: None,
            smtp_port: None,
            caldav_port: None,
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
    fn imap_port_roundtrips_and_defaults_to_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");

        // A configured port survives a save/load round trip. `Config`
        // deliberately has no `Debug` (it carries the account address),
        // so the comparison is PartialEq.
        let cfg = Config {
            imap_port: Some(10143),
            pop3_port: None,
            smtp_port: None,
            caldav_port: None,
            ..Config::default()
        };
        cfg.save(&path).unwrap();
        let loaded = Config::load(&path).unwrap();
        assert!(loaded == cfg);
        assert_eq!(loaded.imap_port, Some(10143));
        assert_eq!(resolve_imap_port(&loaded), 10143);

        // A config that names no port keeps `None`; serve resolves the
        // documented default.
        let plain = Config::default();
        plain.save(&path).unwrap();
        assert_eq!(Config::load(&path).unwrap().imap_port, None);
        assert_eq!(resolve_imap_port(&plain), DEFAULT_IMAP_PORT);
    }

    #[test]
    fn caldav_port_is_opt_in_and_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        Config::default().save(&path).unwrap();
        assert_eq!(Config::load(&path).unwrap().caldav_port, None);
        assert!(!fs::read_to_string(&path).unwrap().contains("caldav_port"));
        fs::write(&path, "caldav_port = 9933\n").unwrap();
        assert_eq!(Config::load(&path).unwrap().caldav_port, Some(9933));
    }

    #[test]
    fn imap_port_validation_accepts_the_range_and_rejects_zero() {
        assert!(validate_imap_port(1).is_ok());
        assert!(validate_imap_port(DEFAULT_IMAP_PORT).is_ok());
        assert!(validate_imap_port(u16::MAX).is_ok());
        assert_eq!(
            validate_imap_port(0),
            Err("imap_port must be between 1 and 65535".to_string())
        );
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
    fn validate_base_url_rejects_malformed_loopback_authorities() {
        assert!(validate_base_url("http://localhost:").is_err());
        assert!(validate_base_url("http://localhost:abc").is_err());
        assert!(validate_base_url("http://localhost:0").is_err());
        assert!(validate_base_url("http://localhost:70000").is_err());
        assert!(validate_base_url("http://127.0.0.1:80:90").is_err());
        assert!(validate_base_url("http://[::1]evil.example").is_err());
        assert!(validate_base_url("http://[::1").is_err());
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

    #[test]
    fn write_private_file_replaces_the_file_and_leaves_no_temp() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        write_private_file(&path, b"first").unwrap();
        write_private_file(&path, b"second").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"second");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn write_private_file_never_writes_through_a_symlink() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        fs::write(&victim, b"untouched").unwrap();
        let path = dir.path().join("mail.eml");
        std::os::unix::fs::symlink(&victim, &path).unwrap();

        write_private_file(&path, b"secret").unwrap();

        assert_eq!(fs::read(&victim).unwrap(), b"untouched");
        assert!(!fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(fs::read(&path).unwrap(), b"secret");
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn write_private_file_tightens_a_loose_existing_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, b"old").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        write_private_file(&path, b"new").unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
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
