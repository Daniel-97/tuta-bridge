use anyhow::{anyhow, Context};
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const DEFAULT_BASE_URL: &str = "https://app.tuta.com";
const APP_DIR: &str = "tuta-bridge";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
        fs::write(path, text)
            .with_context(|| format!("failed to write config file {}", path.display()))
    }
}

pub fn resolve_base_url(cli: Option<&str>, env: Option<&str>, config: &Config) -> String {
    cli.or(env).unwrap_or(&config.base_url).to_owned()
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
    Ok(dir)
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
    fn parse_error_names_path_without_file_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, "base_url = \"secret-looking-value\n").unwrap();
        let msg = format!("{:#}", Config::load(&path).unwrap_err());
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
        assert_eq!(Config::load(&path).unwrap(), cfg);
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
}
