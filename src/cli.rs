use std::path::PathBuf;

use clap::{ArgAction, Args, Parser, Subcommand};

const RELAY_URL_HELP: &str = "Use only these relay servers, replacing the defaults (repeatable)";
const EXTRA_RELAY_URL_HELP: &str = "Add relay servers alongside the defaults (repeatable)";
const KEY_DIR_HELP: &str = "Directory for iroh-ssh identity keys (default: ~/.ssh)";

#[derive(Parser, Debug)]
#[command(name = "iroh-ssh", about = "ssh without ip", version)]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Subcommand, Debug)]
pub enum Cmd {
    Server(ServerArgs),
    Proxy(ProxyArgs),
}

#[derive(Args, Clone, Debug)]
pub struct ProxyArgs {
    #[arg(help = "Proxy Endpoint ID")]
    pub endpoint_id: String,

    #[arg(long, value_name = "URL", help = RELAY_URL_HELP, action = ArgAction::Append)]
    pub relay_url: Vec<String>,

    #[arg(long, value_name = "URL", help = EXTRA_RELAY_URL_HELP, action = ArgAction::Append)]
    pub extra_relay_url: Vec<String>,
}

#[derive(Args, Clone, Debug)]
pub struct ServerArgs {
    #[arg(long, default_value = "22")]
    pub ssh_port: u16,

    #[arg(short, long, default_value_t = false)]
    pub persist: bool,

    #[arg(long, value_name = "DIR", help = KEY_DIR_HELP)]
    pub key_dir: Option<PathBuf>,

    #[arg(long, value_name = "URL", help = RELAY_URL_HELP, action = ArgAction::Append)]
    pub relay_url: Vec<String>,

    #[arg(long, value_name = "URL", help = EXTRA_RELAY_URL_HELP, action = ArgAction::Append)]
    pub extra_relay_url: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_server_and_proxy_are_accepted() {
        assert!(Cli::try_parse_from(["iroh-ssh", "server"]).is_ok());
        assert!(Cli::try_parse_from(["iroh-ssh", "proxy", "abc"]).is_ok());

        for args in [
            vec!["iroh-ssh"],
            vec!["iroh-ssh", "user@abc"],
            vec!["iroh-ssh", "connect", "user@abc"],
            vec!["iroh-ssh", "exec", "user@abc", "ls"],
            vec!["iroh-ssh", "info"],
            vec!["iroh-ssh", "service", "uninstall"],
            vec!["iroh-ssh", "run-service"],
            vec!["iroh-ssh", "version"],
        ] {
            assert!(Cli::try_parse_from(&args).is_err(), "{args:?} should fail");
        }
    }
}
