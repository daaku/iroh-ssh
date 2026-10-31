use std::{
    io::Write as _,
    path::{Path, PathBuf},
    str::FromStr as _,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context as _, anyhow, bail};
use clap::{Args, Parser, Subcommand};
use homedir::my_home;
use iroh::{
    Endpoint, EndpointId, RelayConfig, RelayMap, RelayUrl, SecretKey,
    endpoint::{Connection, RelayMode},
    protocol::{AcceptError, ProtocolHandler, Router},
};
use iroh_mainline_address_lookup::DhtAddressLookup;
use tokio::{
    io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader},
    net::TcpStream,
};

const ALPN: &[u8] = b"/iroh/ssh";

#[derive(Parser)]
#[command(name = "iroh-ssh", about = "ssh without ip", version)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Accept iroh connections and forward them to the local ssh server
    Server(ServerArgs),
    /// Connect stdin and stdout to a server, for use as ssh's ProxyCommand
    Proxy(ProxyArgs),
}

#[derive(Args)]
struct RelayArgs {
    /// Use only these relay servers, replacing the defaults (repeatable)
    #[arg(long, value_name = "URL", conflicts_with = "extra_relay_url")]
    relay_url: Vec<RelayUrl>,

    /// Add relay servers alongside the defaults (repeatable)
    #[arg(long, value_name = "URL")]
    extra_relay_url: Vec<RelayUrl>,
}

#[derive(Args)]
struct ProxyArgs {
    /// Server endpoint id, as ssh's %h or %h:%p
    #[arg(value_name = "ENDPOINT_ID", value_parser = parse_proxy_target)]
    endpoint_id: EndpointId,

    #[command(flatten)]
    relay: RelayArgs,
}

#[derive(Args)]
struct ServerArgs {
    /// Port of the local ssh server
    #[arg(long, default_value_t = 22)]
    ssh_port: u16,

    /// Keep the same endpoint id across restarts
    #[arg(short, long)]
    persist: bool,

    /// Directory for iroh-ssh identity keys (default: ~/.ssh)
    #[arg(long, value_name = "DIR", requires = "persist")]
    key_dir: Option<PathBuf>,

    #[command(flatten)]
    relay: RelayArgs,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let runtime = tokio::runtime::Runtime::new()?;
    let result = runtime.block_on(async {
        match cli.cmd {
            Cmd::Server(args) => server_mode(args).await,
            Cmd::Proxy(args) => proxy_mode(args).await,
        }
    });
    // A blocking read of stdin can't be cancelled and would hang a normal shutdown.
    runtime.shutdown_background();
    result
}

async fn server_mode(args: ServerArgs) -> anyhow::Result<()> {
    let ssh_port = args.ssh_port;
    check_ssh_server(ssh_port).await.with_context(|| {
        format!("no ssh server on port {ssh_port}, please install one or set --ssh-port")
    })?;

    let key_dir = if args.persist {
        Some(match args.key_dir {
            Some(dir) => dir,
            None => my_home()?.context("home directory not found")?.join(".ssh"),
        })
    } else {
        None
    };
    let secret_key = match &key_dir {
        Some(dir) => load_or_create_key(dir)?,
        None => SecretKey::generate(),
    };

    let endpoint = bind_endpoint(secret_key, true, &args.relay).await?;
    let router = Router::builder(endpoint.clone())
        .accept(ALPN, SshForwarder { ssh_port })
        .spawn();

    println!("Connect to this machine:");
    println!(
        "\n  ssh -o ProxyCommand=\"iroh-ssh proxy %h\" {}@{}\n",
        whoami::username().unwrap_or("UNKNOWN_USER".to_string()),
        endpoint.id()
    );
    match key_dir {
        Some(dir) => println!("  (using persistent keys in {})", dir.display()),
        None => println!(
            "  warning: (using ephemeral keys, run 'iroh-ssh server --persist' to create persistent keys)"
        ),
    }
    println!();
    println!("client -> iroh-ssh -> direct connect -> iroh-ssh -> local ssh :{ssh_port}");

    println!("Waiting for incoming connections...");
    println!("Press Ctrl+C to exit");
    tokio::signal::ctrl_c().await?;
    router.shutdown().await?;
    Ok(())
}

/// Parses the `%h` or `%h:%p` argument given to the proxy into an endpoint id.
fn parse_proxy_target(target: &str) -> anyhow::Result<EndpointId> {
    let hostname = target.split_once(':').map_or(target, |(host, _port)| host);
    EndpointId::from_str(hostname).with_context(|| format!("invalid endpoint id '{hostname}'"))
}

async fn proxy_mode(args: ProxyArgs) -> anyhow::Result<()> {
    let endpoint = bind_endpoint(SecretKey::generate(), false, &args.relay).await?;

    let connection = endpoint.connect(args.endpoint_id, ALPN).await?;
    let (mut send, mut recv) = connection.open_bi().await?;

    // A failed write means the server stopped reading, and whatever it sent
    // before that is still worth receiving, so only the read side's errors matter.
    let stdin_to_remote = async {
        tokio::io::copy(&mut tokio::io::stdin(), &mut send)
            .await
            .ok();
        send.finish().ok();
    };
    let mut stdout = tokio::io::stdout();
    let remote_to_stdout = tokio::io::copy(&mut recv, &mut stdout);
    tokio::pin!(remote_to_stdout);

    // Keep reading after stdin closes, but don't wait for stdin once the server
    // is done: ssh only closes it after seeing EOF from us.
    tokio::select! {
        result = &mut remote_to_stdout => result?,
        () = stdin_to_remote => remote_to_stdout.await?,
    };

    connection.close(0u32.into(), b"done");
    endpoint.close().await;
    Ok(())
}

async fn bind_endpoint(
    secret_key: SecretKey,
    announce: bool,
    relay: &RelayArgs,
) -> anyhow::Result<Endpoint> {
    let mdns_lookup = iroh_mdns_peer_lookup::Options::new()
        .announce(announce)
        .build();
    let mut builder = Endpoint::builder(iroh::endpoint::presets::N0)
        .secret_key(secret_key)
        .address_lookup(DhtAddressLookup::builder())
        .address_lookup(iroh_mdns_peer_lookup::lookup(mdns_lookup).await?);

    if let Some(relay_map) = custom_relay_map(
        &relay.relay_url,
        &relay.extra_relay_url,
        relay_auth_token().as_deref(),
    ) {
        builder = builder.relay_mode(RelayMode::Custom(relay_map));
    }

    Ok(builder.bind().await?)
}

fn relay_auth_token() -> Option<String> {
    std::env::var("IROH_RELAY_TOKEN")
        .ok()
        .filter(|token| !token.is_empty())
}

/// Builds the relay map for the configured relays, or `None` to use the iroh
/// defaults. The token only goes to the configured relays, never the defaults.
fn custom_relay_map(
    relay_urls: &[RelayUrl],
    extra_relay_urls: &[RelayUrl],
    token: Option<&str>,
) -> Option<RelayMap> {
    let (relay_map, urls) = if !relay_urls.is_empty() {
        (RelayMap::empty(), relay_urls)
    } else if !extra_relay_urls.is_empty() {
        (RelayMode::Default.relay_map(), extra_relay_urls)
    } else {
        return None;
    };

    for url in urls {
        let mut config = RelayConfig::from(url.clone());
        if let Some(token) = token {
            config = config.with_auth_token(token);
        }
        relay_map.insert(url.clone(), Arc::new(config));
    }
    Some(relay_map)
}

async fn check_ssh_server(port: u16) -> anyhow::Result<()> {
    let probe = async {
        let stream = TcpStream::connect(("localhost", port)).await?;
        let mut lines = BufReader::new(stream).split(b'\n');
        while let Some(line) = lines.next_segment().await? {
            if line.starts_with(b"SSH-") {
                return Ok(());
            }
        }
        bail!("connection closed before the ssh banner")
    };
    tokio::time::timeout(Duration::from_secs(10), probe)
        .await
        .context("timed out")?
}

/// Forwards incoming iroh connections to the local ssh server.
#[derive(Debug, Clone)]
struct SshForwarder {
    ssh_port: u16,
}

impl SshForwarder {
    async fn forward(&self, connection: &Connection) -> anyhow::Result<()> {
        let (mut iroh_send, mut iroh_recv) = connection.accept_bi().await?;
        let mut ssh_stream = TcpStream::connect(("localhost", self.ssh_port))
            .await
            .context("failed to connect to the ssh server")?;
        let (mut ssh_read, mut ssh_write) = ssh_stream.split();

        let ssh_to_remote = async {
            tokio::io::copy(&mut ssh_read, &mut iroh_send).await.ok();
            iroh_send.finish().ok();
        };
        let remote_to_ssh = async {
            tokio::io::copy(&mut iroh_recv, &mut ssh_write).await.ok();
            ssh_write.shutdown().await.ok();
        };
        tokio::join!(ssh_to_remote, remote_to_ssh);

        // Dropping the connection discards data the client hasn't received yet,
        // so let the client, which reads last, close it.
        connection.closed().await;
        Ok(())
    }
}

impl ProtocolHandler for SshForwarder {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let remote = connection.remote_id();
        println!("Accepted connection from {remote}");
        if let Err(e) = self.forward(&connection).await {
            eprintln!("Connection from {remote} failed: {e:#}");
        }
        Ok(())
    }
}

/// Loads the server's key from `dir`, creating it on first use.
fn load_or_create_key(dir: &Path) -> anyhow::Result<SecretKey> {
    let priv_key = dir.join("irohssh_ed25519");
    if priv_key.exists() {
        let encoded = std::fs::read(&priv_key)
            .with_context(|| format!("failed to read secret key from {}", priv_key.display()))?;
        let bytes: [u8; 32] = z32::decode(&encoded)?
            .try_into()
            .map_err(|_| anyhow!("invalid secret key in {}", priv_key.display()))?;
        return Ok(SecretKey::from_bytes(&bytes));
    }

    let secret_key = SecretKey::generate();
    std::fs::create_dir_all(dir)?;
    write_private(&priv_key, &z32::encode(&secret_key.to_bytes()))?;
    std::fs::write(
        dir.join("irohssh_ed25519.pub"),
        z32::encode(secret_key.public().as_bytes()),
    )?;
    Ok(secret_key)
}

/// Creates a file only the current user can read, failing if it already exists.
fn write_private(path: &Path, contents: &str) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path)?.write_all(contents.as_bytes())
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

    fn url() -> RelayUrl {
        RelayUrl::from_str("https://relay.example.com").unwrap()
    }

    #[test]
    fn no_custom_relays_keeps_defaults() {
        assert!(custom_relay_map(&[], &[], Some("secret")).is_none());
    }

    #[test]
    fn relay_urls_get_the_token() {
        let map = custom_relay_map(&[url()], &[], Some("secret")).unwrap();
        assert_eq!(map.len(), 1);
        assert_eq!(
            map.get(&url()).unwrap().auth_token.as_deref(),
            Some("secret")
        );
    }

    #[test]
    fn extra_relay_urls_get_the_token_but_defaults_do_not() {
        let map = custom_relay_map(&[], &[url()], Some("secret")).unwrap();
        let relays: Vec<Arc<RelayConfig>> = map.relays();
        assert!(relays.len() > 1);
        for relay in relays {
            let expected = (relay.url == url()).then_some("secret");
            assert_eq!(relay.auth_token.as_deref(), expected);
        }
    }

    #[test]
    fn no_token_leaves_relays_unauthenticated() {
        let map = custom_relay_map(&[url()], &[], None).unwrap();
        assert_eq!(map.get(&url()).unwrap().auth_token, None);
    }

    #[test]
    fn only_server_and_proxy_are_accepted() {
        assert!(Cli::try_parse_from(["iroh-ssh", "server"]).is_ok());
        assert!(Cli::try_parse_from(["iroh-ssh", "proxy", ENDPOINT_ID]).is_ok());

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

    #[test]
    fn key_survives_a_missing_public_key_file() {
        let dir = tempfile::tempdir().unwrap();
        let key = load_or_create_key(dir.path()).unwrap();
        std::fs::remove_file(dir.path().join("irohssh_ed25519.pub")).unwrap();

        let reloaded = load_or_create_key(dir.path()).unwrap();
        assert_eq!(reloaded.to_bytes(), key.to_bytes());
    }

    #[cfg(unix)]
    #[test]
    fn private_key_is_only_readable_by_owner() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        load_or_create_key(dir.path()).unwrap();

        let metadata = std::fs::metadata(dir.path().join("irohssh_ed25519")).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn wrong_length_key_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        // valid z-base32, but not 32 bytes
        std::fs::write(dir.path().join("irohssh_ed25519"), "yyyy").unwrap();

        assert!(load_or_create_key(dir.path()).is_err());
    }

    #[test]
    fn relay_flags_conflict() {
        let url = "https://relay.example.com";
        let args = [
            "iroh-ssh",
            "server",
            "--relay-url",
            url,
            "--extra-relay-url",
            url,
        ];
        assert!(Cli::try_parse_from(args).is_err());
    }

    #[test]
    fn invalid_relay_url_is_rejected() {
        let args = ["iroh-ssh", "server", "--relay-url", "not a url"];
        assert!(Cli::try_parse_from(args).is_err());
    }

    #[test]
    fn key_dir_requires_persist() {
        assert!(Cli::try_parse_from(["iroh-ssh", "server", "--key-dir", "/tmp"]).is_err());
        assert!(Cli::try_parse_from(["iroh-ssh", "server", "-p", "--key-dir", "/tmp"]).is_ok());
    }
}
