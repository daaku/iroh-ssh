use clap::Parser;
use iroh_ssh::{Cli, Cmd, api};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.cmd {
        Cmd::Server(args) => api::server_mode(args).await,
        Cmd::Proxy(args) => api::proxy_mode(args).await,
    }
}
