use std::{
    io::Write as _,
    path::{Path, PathBuf},
    str::FromStr as _,
    sync::Arc,
    time::Duration,
};

use anyhow::bail;
use clap::{ArgAction, Args, Parser, Subcommand};
use ed25519_dalek::{PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH};
use homedir::my_home;
use iroh::{
    Endpoint, EndpointId, RelayConfig, RelayMap, RelayUrl, SecretKey,
    endpoint::{Connection, RelayMode},
    protocol::{ProtocolHandler, Router},
};
use iroh_mainline_address_lookup::DhtAddressLookup;
use regex::Regex;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
};

const RELAY_URL_HELP: &str = "Use only these relay servers, replacing the defaults (repeatable)";
const EXTRA_RELAY_URL_HELP: &str = "Add relay servers alongside the defaults (repeatable)";
const KEY_DIR_HELP: &str = "Directory for iroh-ssh identity keys (default: ~/.ssh)";

#[derive(Parser, Debug)]
#[command(name = "iroh-ssh", about = "ssh without ip", version)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    Server(ServerArgs),
    Proxy(ProxyArgs),
}

#[derive(Args, Clone, Debug)]
struct ProxyArgs {
    #[arg(help = "Proxy Endpoint ID")]
    endpoint_id: String,

    #[arg(long, value_name = "URL", help = RELAY_URL_HELP, action = ArgAction::Append)]
    relay_url: Vec<String>,

    #[arg(long, value_name = "URL", help = EXTRA_RELAY_URL_HELP, action = ArgAction::Append)]
    extra_relay_url: Vec<String>,
}

#[derive(Args, Clone, Debug)]
struct ServerArgs {
    #[arg(long, default_value = "22")]
    ssh_port: u16,

    #[arg(short, long, default_value_t = false)]
    persist: bool,

    #[arg(long, value_name = "DIR", help = KEY_DIR_HELP)]
    key_dir: Option<PathBuf>,

    #[arg(long, value_name = "URL", help = RELAY_URL_HELP, action = ArgAction::Append)]
    relay_url: Vec<String>,

    #[arg(long, value_name = "URL", help = EXTRA_RELAY_URL_HELP, action = ArgAction::Append)]
    extra_relay_url: Vec<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.cmd {
        Cmd::Server(args) => server_mode(args).await,
        Cmd::Proxy(args) => proxy_mode(args).await,
    }
}

fn parse_relay_urls(urls: &[String]) -> anyhow::Result<Vec<RelayUrl>> {
    urls.iter()
        .map(|s| RelayUrl::from_str(s).map_err(|e| anyhow::anyhow!("invalid relay URL '{s}': {e}")))
        .collect()
}

async fn server_mode(server_args: ServerArgs) -> anyhow::Result<()> {
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

async fn proxy_mode(proxy_args: ProxyArgs) -> anyhow::Result<()> {
    let endpoint_id = parse_proxy_target(&proxy_args.endpoint_id)?;
    let iroh_ssh = IrohSsh::builder()
        .accept_incoming(false)
        .relay_urls(parse_relay_urls(&proxy_args.relay_url)?)
        .extra_relay_urls(parse_relay_urls(&proxy_args.extra_relay_url)?)
        .build()
        .await?;
    iroh_ssh.connect_pubkey(endpoint_id).await
}

#[derive(Debug, Clone)]
struct IrohSsh {
    #[allow(dead_code)]
    secret_key: [u8; SECRET_KEY_LENGTH],
    #[allow(dead_code)]
    public_key: [u8; PUBLIC_KEY_LENGTH],
    inner: Option<Inner>,
    ssh_port: u16,
}

#[derive(Debug, Clone)]
struct Inner {
    endpoint: Endpoint,
    #[allow(dead_code)]
    router: Router,
}

#[derive(Debug, Clone)]
struct Builder {
    secret_key: [u8; SECRET_KEY_LENGTH],
    accept_incoming: bool,
    accept_port: Option<u16>,
    key_dir: Option<PathBuf>,
    relay_urls: Vec<RelayUrl>,
    extra_relay_urls: Vec<RelayUrl>,
}

const RELAY_TOKEN_ENV: &str = "IROH_RELAY_TOKEN";

impl Builder {
    fn new() -> Self {
        Self {
            secret_key: SecretKey::generate().to_bytes(),
            accept_incoming: false,
            accept_port: None,
            key_dir: None,
            relay_urls: Vec::new(),
            extra_relay_urls: Vec::new(),
        }
    }

    fn accept_incoming(mut self, accept_incoming: bool) -> Self {
        self.accept_incoming = accept_incoming;
        self
    }

    fn accept_port(mut self, accept_port: u16) -> Self {
        self.accept_port = Some(accept_port);
        self
    }

    fn relay_urls(mut self, urls: Vec<RelayUrl>) -> Self {
        self.relay_urls = urls;
        self
    }

    fn extra_relay_urls(mut self, urls: Vec<RelayUrl>) -> Self {
        self.extra_relay_urls = urls;
        self
    }

    fn key_dir(mut self, key_dir: Option<std::path::PathBuf>) -> Self {
        self.key_dir = key_dir;
        self
    }

    fn dot_ssh_integration(mut self) -> Self {
        match dot_ssh(
            &SecretKey::from_bytes(&self.secret_key),
            self.key_dir.as_deref(),
        ) {
            Ok(secret_key) => self.secret_key = secret_key.to_bytes(),
            Err(e) => {
                eprintln!("Warning: Failed to load/create persistent SSH keys: {e:#}");
                eprintln!("Continuing with ephemeral keys...");
            }
        }
        self
    }

    async fn build(&mut self) -> anyhow::Result<IrohSsh> {
        // Iroh setup
        let secret_key = SecretKey::from_bytes(&self.secret_key);
        let mdns_lookup = iroh_mdns_peer_lookup::Options::new()
            .announce(self.accept_incoming)
            .build();
        let mut builder = Endpoint::builder(iroh::endpoint::presets::N0)
            .secret_key(secret_key)
            .address_lookup(DhtAddressLookup::builder())
            .address_lookup(iroh_mdns_peer_lookup::lookup(mdns_lookup).await?);

        if let Some(relay_map) = custom_relay_map(
            &self.relay_urls,
            &self.extra_relay_urls,
            relay_auth_token().as_deref(),
        ) {
            builder = builder.relay_mode(RelayMode::Custom(relay_map));
        }

        let endpoint = builder.bind().await?;

        let mut iroh_ssh = IrohSsh {
            public_key: *endpoint.id().as_bytes(),
            secret_key: self.secret_key,
            inner: None,
            ssh_port: self.accept_port.unwrap_or(22),
        };

        let router = if self.accept_incoming {
            if is_ssh_server_available(iroh_ssh.ssh_port, Duration::from_secs(10)).await.is_err() {
                eprintln!("SSH server not available on port {}, incoming connections will fail. Please ensure you have an SSH server installed and running on port {}.", iroh_ssh.ssh_port, iroh_ssh.ssh_port);
                bail!("no ssh server available on specified port")
            }
            Router::builder(endpoint.clone()).accept(IrohSsh::ALPN(), iroh_ssh.clone())
        } else {
            Router::builder(endpoint.clone())
        }
        .spawn();

        iroh_ssh.add_inner(endpoint, router);

        Ok(iroh_ssh)
    }
}

fn relay_auth_token() -> Option<String> {
    std::env::var(RELAY_TOKEN_ENV)
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
    if !relay_urls.is_empty() {
        let relay_map: RelayMap = relay_urls.iter().cloned().collect();
        Some(match token {
            Some(token) => relay_map.with_auth_token(token),
            None => relay_map,
        })
    } else if !extra_relay_urls.is_empty() {
        let relay_map = RelayMode::Default.relay_map();
        for url in extra_relay_urls {
            let mut config = RelayConfig::from(url.clone());
            if let Some(token) = token {
                config = config.with_auth_token(token);
            }
            relay_map.insert(url.clone(), Arc::new(config));
        }
        Some(relay_map)
    } else {
        None
    }
}

async fn is_ssh_server_available(port: u16, timeout: Duration) -> anyhow::Result<()> {
    tokio::time::timeout(timeout, async {
        let stream = TcpStream::connect(format!("localhost:{port}")).await?;
        let mut reader = BufReader::new(stream);
        let mut line_buf = String::new();
        let regex = Regex::new(r"^SSH-\d+\.\d+-").expect("valid regex");

        loop {
            line_buf.clear();
            if reader.read_line(&mut line_buf).await? == 0 {
                bail!("SSH server closed the connection");
            }
            if regex.is_match(&line_buf) {
                reader.shutdown().await.ok();
                return Ok(());
            }
        }
    })
    .await?
}

impl Default for Builder {
    fn default() -> Self {
        Self::new()
    }
}

impl IrohSsh {
    fn builder() -> Builder {
        Builder::new()
    }

    #[allow(non_snake_case)]
    fn ALPN() -> Vec<u8> {
        b"/iroh/ssh".to_vec()
    }

    fn add_inner(&mut self, endpoint: Endpoint, router: Router) {
        self.inner = Some(Inner { endpoint, router });
    }

    async fn connect_pubkey(&self, endpoint_id: EndpointId) -> anyhow::Result<()> {
        let inner = self.inner.as_ref().expect("inner not set");
        let conn = inner
            .endpoint
            .connect(endpoint_id, &IrohSsh::ALPN())
            .await?;
        let (mut iroh_send, mut iroh_recv) = conn.open_bi().await?;
        let (mut local_read, mut local_write) = (tokio::io::stdin(), tokio::io::stdout());
        let a_to_b = async move {
            let res = tokio::io::copy(&mut local_read, &mut iroh_send).await;
            iroh_send.finish().ok();
            res
        };
        let b_to_a = async move { tokio::io::copy(&mut iroh_recv, &mut local_write).await };

        let (_, _) = tokio::join!(a_to_b, b_to_a);
        Ok(())
    }

    fn endpoint_id(&self) -> EndpointId {
        self.inner.as_ref().expect("inner not set").endpoint.id()
    }
}

impl ProtocolHandler for IrohSsh {
    async fn accept(&self, connection: Connection) -> Result<(), iroh::protocol::AcceptError> {
        let endpoint_id = connection.remote_id();

        match connection.accept_bi().await {
            Ok((mut iroh_send, mut iroh_recv)) => {
                println!("Accepted bidirectional stream from {endpoint_id}");

                match TcpStream::connect(format!("127.0.0.1:{}", self.ssh_port)).await {
                    Ok(mut ssh_stream) => {
                        println!("Connected to local SSH server on port {}", self.ssh_port);

                        let (mut local_read, mut local_write) = ssh_stream.split();

                        let a_to_b = async move {
                            let res = tokio::io::copy(&mut local_read, &mut iroh_send).await;
                            iroh_send.finish().ok();
                            res
                        };
                        let b_to_a = async move {
                            let res = tokio::io::copy(&mut iroh_recv, &mut local_write).await;
                            local_write.shutdown().await.ok();
                            res
                        };

                        let (_, _) = tokio::join!(a_to_b, b_to_a);
                    }
                    Err(e) => {
                        println!("Failed to connect to SSH server: {e}");
                    }
                }
            }
            Err(e) => {
                println!("Failed to accept bidirectional stream: {e}");
            }
        }

        Ok(())
    }
}

fn dot_ssh(default_secret_key: &SecretKey, key_dir: Option<&Path>) -> anyhow::Result<SecretKey> {
    let ssh_dir = if let Some(dir) = key_dir {
        dir.to_path_buf()
    } else {
        let distro_home = my_home()?.ok_or_else(|| anyhow::anyhow!("home directory not found"))?;
        distro_home.join(".ssh")
    };

    let pub_key = ssh_dir.join("irohssh_ed25519.pub");
    let priv_key = ssh_dir.join("irohssh_ed25519");

    if !ssh_dir.exists() {
        std::fs::create_dir_all(&ssh_dir)?;
        println!("[INFO] created .ssh folder: {}", ssh_dir.display());
    }

    if priv_key.exists() {
        // read secret key
        if let Ok(secret_key) = std::fs::read(priv_key.clone()) {
            let mut sk_bytes = [0u8; SECRET_KEY_LENGTH];
            sk_bytes.copy_from_slice(z32::decode(secret_key.as_slice())?.as_slice());
            Ok(SecretKey::from_bytes(&sk_bytes))
        } else {
            bail!("failed to read secret key from {}", priv_key.display())
        }
    } else {
        let secret_key = default_secret_key.clone();
        let public_key = secret_key.public();

        write_private(&priv_key, &z32::encode(&secret_key.to_bytes()))?;
        std::fs::write(&pub_key, z32::encode(public_key.as_bytes()))?;

        Ok(secret_key)
    }
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
        let relays: Vec<std::sync::Arc<RelayConfig>> = map.relays();
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

    #[test]
    fn key_survives_a_missing_public_key_file() {
        let dir = tempfile::tempdir().unwrap();
        let key = dot_ssh(&SecretKey::generate(), Some(dir.path())).unwrap();
        std::fs::remove_file(dir.path().join("irohssh_ed25519.pub")).unwrap();

        let reloaded = dot_ssh(&SecretKey::generate(), Some(dir.path())).unwrap();
        assert_eq!(reloaded.to_bytes(), key.to_bytes());
    }

    #[cfg(unix)]
    #[test]
    fn private_key_is_only_readable_by_owner() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        dot_ssh(&SecretKey::generate(), Some(dir.path())).unwrap();

        let metadata = std::fs::metadata(dir.path().join("irohssh_ed25519")).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    }
}
