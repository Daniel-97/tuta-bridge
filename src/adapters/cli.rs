use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "tuta-bridge",
    version,
    about = "Local CLI bridge for Tuta Mail"
)]
pub struct Cli {
    #[arg(long, global = true)]
    pub base_url: Option<String>,
    /// Print HTTP phase, status, and sanitized server error details to stderr.
    #[arg(long, global = true)]
    pub debug: bool,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Login {
        #[arg(long)]
        email: Option<String>,
    },
    Logout,
    Status,
    /// Sync folder and message metadata, keeping existing UIDs stable.
    Sync,
    /// Discard all local state and sync from scratch.
    ///
    /// WARNING: this assigns new UIDs, invalidating any UID mappings held by
    /// mail clients.
    Resync,
    Dump {
        #[arg(long)]
        folder: String,
        #[arg(long)]
        limit: usize,
        #[arg(long)]
        out: PathBuf,
    },
}

pub fn parse_from<I, T>(args: I) -> Result<Cli, clap::Error>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    Cli::try_parse_from(args)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_status() {
        let cli = parse_from(["tuta-bridge", "status"]).unwrap();
        assert!(matches!(cli.command, Command::Status));
        assert_eq!(cli.base_url, None);
        assert!(!cli.debug);
    }

    #[test]
    fn parses_debug_flag() {
        let cli = parse_from(["tuta-bridge", "--debug", "status"]).unwrap();
        assert!(cli.debug);
    }

    #[test]
    fn parses_sync_commands() {
        assert!(matches!(
            parse_from(["tuta-bridge", "sync"]).unwrap().command,
            Command::Sync
        ));
        assert!(matches!(
            parse_from(["tuta-bridge", "resync"]).unwrap().command,
            Command::Resync
        ));
    }

    #[test]
    fn parses_login_email_and_dump() {
        let cli = parse_from(["tuta-bridge", "login", "--email", "a@b.c"]).unwrap();
        assert!(matches!(cli.command, Command::Login { email: Some(ref e) } if e == "a@b.c"));

        let cli = parse_from([
            "tuta-bridge",
            "--base-url",
            "http://127.0.0.1:9",
            "dump",
            "--folder",
            "inbox",
            "--limit",
            "10",
            "--out",
            "/tmp/x",
        ])
        .unwrap();
        assert_eq!(cli.base_url.as_deref(), Some("http://127.0.0.1:9"));
        assert!(
            matches!(cli.command, Command::Dump { ref folder, limit: 10, ref out }
            if folder == "inbox" && out == std::path::Path::new("/tmp/x"))
        );
    }
}
