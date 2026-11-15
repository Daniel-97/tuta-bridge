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
