use std::str::FromStr as _;

use homedir::my_home;
use iroh::{EndpointId, RelayUrl};

use crate::{
    IrohSsh,
    cli::{ProxyArgs, ServerArgs},
};

fn parse_relay_urls(urls: &[String]) -> anyhow::Result<Vec<RelayUrl>> {
    urls.iter()
        .map(|s| RelayUrl::from_str(s).map_err(|e| anyhow::anyhow!("invalid relay URL '{s}': {e}")))
        .collect()
}

pub async fn server_mode(server_args: ServerArgs) -> anyhow::Result<()> {
    let mut iroh_ssh_builder = IrohSsh::builder()
        .accept_incoming(true)
        .accept_port(server_args.ssh_port)
        .key_dir(server_args.key_dir.clone())
        .relay_urls(parse_relay_urls(&server_args.relay_url)?)
        .extra_relay_urls(parse_relay_urls(&server_args.extra_relay_url)?);
    if server_args.persist {
        iroh_ssh_builder = iroh_ssh_builder.dot_ssh_integration();
    }
    let iroh_ssh = iroh_ssh_builder.build().await?;

    println!("Connect to this this machine:");
    println!(
        "\n  ssh -o ProxyCommand=\"iroh-ssh proxy %h\" {}@{}\n",
        whoami::username().unwrap_or("UNKNOWN_USER".to_string()),
        iroh_ssh.endpoint_id()
    );
    if server_args.persist {
        let ssh_dir = match server_args.key_dir {
            Some(dir) => dir,
            None => {
                let distro_home =
                    my_home()?.ok_or_else(|| anyhow::anyhow!("home directory not found"))?;
                distro_home.join(".ssh")
            }
        };
        println!("  (using persistent keys in {})", ssh_dir.display());
    } else {
        println!(
            "  warning: (using ephemeral keys, run 'iroh-ssh server --persist' to create persistent keys)"
        );
    }
    println!();
    println!(
        "client -> iroh-ssh -> direct connect -> iroh-ssh -> local ssh :{}",
        server_args.ssh_port
    );

    println!("Waiting for incoming connections...");
    println!("Press Ctrl+C to exit");
    tokio::signal::ctrl_c().await?;
    Ok(())
}

/// Parses the `%h` or `%h:%p` argument given to the proxy into an endpoint id.
fn parse_proxy_target(target: &str) -> anyhow::Result<EndpointId> {
    let hostname = target.split(':').next().unwrap_or_default();
    EndpointId::from_str(hostname)
        .map_err(|e| anyhow::anyhow!("invalid endpoint id '{hostname}': {e}"))
}

pub async fn proxy_mode(proxy_args: ProxyArgs) -> anyhow::Result<()> {
    let endpoint_id = parse_proxy_target(&proxy_args.endpoint_id)?;
    let iroh_ssh = IrohSsh::builder()
        .accept_incoming(false)
        .relay_urls(parse_relay_urls(&proxy_args.relay_url)?)
        .extra_relay_urls(parse_relay_urls(&proxy_args.extra_relay_url)?)
        .build()
        .await?;
    iroh_ssh.connect_pubkey(endpoint_id).await
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENDPOINT_ID: &str = "38b7dc10df96005255c3beaeaeef6cfebd88344aa8c85e1dbfc1ad5e50f372ac";

    #[test]
    fn proxy_target_accepts_endpoint_id_with_or_without_port() {
        let expected = EndpointId::from_str(ENDPOINT_ID).unwrap();
        assert_eq!(parse_proxy_target(ENDPOINT_ID).unwrap(), expected);
        assert_eq!(
            parse_proxy_target(&format!("{ENDPOINT_ID}:22")).unwrap(),
            expected
        );
    }

    #[test]
    fn proxy_target_rejects_hostnames_and_ips() {
        for target in ["localhost", "localhost:22", "127.0.0.1:22", "example.com"] {
            assert!(parse_proxy_target(target).is_err(), "{target} should fail");
        }
    }
}
