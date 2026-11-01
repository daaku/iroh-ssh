use std::{
    io::{self, Write as _},
    net::{SocketAddrV4, SocketAddrV6},
    path::{Path, PathBuf},
    str::FromStr as _,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context as _, bail};
use clap::{Parser, Subcommand};
use homedir::my_home;
use iroh::{
    Endpoint, EndpointId, RelayConfig, RelayMap, RelayUrl, SecretKey,
    endpoint::{Accepting, RecvStream, RelayMode, SendStream},
};
use iroh_mainline_address_lookup::DhtAddressLookup;
use tokio::{
    io::{
        AsyncBufReadExt as _, AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _,
        BufReader,
    },
    net::TcpStream,
    time::timeout,
};
use tracing_subscriber::EnvFilter;

const ALPN: &[u8] = b"/iroh/ssh";
const COPY_BUFFER_SIZE: usize = 64 * 1024;
const ONLINE_TIMEOUT: Duration = Duration::from_secs(5);

/// ssh without ip.
///
/// One side runs a server next to an ssh server, the other side reaches it
/// through ssh's ProxyCommand. Servers are identified by a 32 byte endpoint id.
///
/// Connecting to an endpoint id is independent of its IP address. iroh-ssh will
/// try to establish a direct connection even through NATs and firewalls. If that
/// fails, it will fall back to using a relay server.
#[derive(Parser, Debug)]
#[command(version)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Accept iroh connections and forward them to the local ssh server
    Server(ServerArgs),
    /// Connect stdin and stdout to a server, for use as ssh's ProxyCommand
    Proxy(ProxyArgs),
}

#[derive(Parser, Debug)]
struct CommonArgs {
    /// The IPv4 address that the endpoint will listen on.
    ///
    /// If None, defaults to a random free port, but it can be useful to specify a
    /// fixed port, e.g. to configure a firewall rule.
    #[arg(long)]
    ipv4_addr: Option<SocketAddrV4>,

    /// The IPv6 address that the endpoint will listen on.
    ///
    /// If None, defaults to a random free port, but it can be useful to specify a
    /// fixed port, e.g. to configure a firewall rule.
    #[arg(long)]
    ipv6_addr: Option<SocketAddrV6>,

    /// Use only these relay servers, replacing the defaults (repeatable)
    #[arg(long, value_name = "URL", conflicts_with = "extra_relay_url")]
    relay_url: Vec<RelayUrl>,

    /// Add relay servers alongside the defaults (repeatable)
    #[arg(long, value_name = "URL")]
    extra_relay_url: Vec<RelayUrl>,
}

#[derive(Parser, Debug)]
struct ProxyArgs {
    /// Server endpoint id, as ssh's %h or %h:%p
    #[arg(value_name = "ENDPOINT_ID", value_parser = parse_proxy_target)]
    endpoint_id: EndpointId,

    #[command(flatten)]
    common: CommonArgs,
}

#[derive(Parser, Debug)]
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
    common: CommonArgs,
}

#[tokio::main]
async fn main() {
    // stdout carries the ssh stream in the proxy, so logs must stay on stderr.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("iroh_ssh=warn")),
        )
        .init();
    let args = Args::parse();
    let res = match args.command {
        Commands::Server(args) => server(args).await,
        Commands::Proxy(args) => proxy(args).await,
    };
    // Exit rather than return: a blocking read of stdin can't be cancelled and
    // would hang the runtime's shutdown.
    match res {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            eprintln!("error: {e:#}");
            std::process::exit(1)
        }
    }
}

async fn server(args: ServerArgs) -> anyhow::Result<()> {
    let ssh_port = args.ssh_port;
    check_ssh_server(ssh_port).await.with_context(|| {
        format!("no ssh server on port {ssh_port}, please install one or set --ssh-port")
    })?;

    let secret_key = if args.persist {
        let key_dir = match args.key_dir {
            Some(dir) => dir,
            None => my_home()?.context("home directory not found")?.join(".ssh"),
        };
        get_or_create_secret(&key_dir)?
    } else {
        SecretKey::generate()
    };

    let endpoint = create_endpoint(secret_key, &args.common, vec![ALPN.to_vec()]).await?;
    // wait for the endpoint to reach its home relay before giving out its id
    if timeout(ONLINE_TIMEOUT, endpoint.online()).await.is_err() {
        eprintln!("Warning: Failed to connect to the home relay");
    }
    println!("{}", endpoint.id());

    loop {
        let incoming = tokio::select! {
            incoming = endpoint.accept() => incoming,
            _ = tokio::signal::ctrl_c() => break,
        };
        let Some(incoming) = incoming else {
            break;
        };
        let accepting = match incoming.accept() {
            Ok(accepting) => accepting,
            Err(cause) => {
                tracing::warn!("error accepting connection: {cause}");
                // if accept fails, we want to continue accepting connections
                continue;
            }
        };
        tokio::spawn(async move {
            if let Err(cause) = handle_endpoint_accept(accepting, ssh_port).await {
                // we should know about it, but it's not fatal
                tracing::warn!("error handling connection: {cause:#}");
            }
        });
    }
    endpoint.close().await;
    Ok(())
}

/// Forward an incoming connection to the local ssh server.
async fn handle_endpoint_accept(accepting: Accepting, ssh_port: u16) -> anyhow::Result<()> {
    let connection = accepting.await.context("error accepting connection")?;
    let remote_endpoint_id = connection.remote_id();
    tracing::info!("got connection from {remote_endpoint_id}");
    let (send, recv) = connection
        .accept_bi()
        .await
        .context("error accepting stream")?;
    tracing::info!("accepted bidi stream from {remote_endpoint_id}");
    let tcp_stream = TcpStream::connect(("localhost", ssh_port))
        .await
        .context("error connecting to the ssh server")?;
    let (tcp_recv, tcp_send) = tcp_stream.into_split();

    let forward_from_tcp = copy_to_noq(tcp_recv, send);
    let forward_to_tcp = copy_from_noq(recv, tcp_send);
    let (_, _) = tokio::join!(forward_from_tcp, forward_to_tcp);

    // Dropping the connection discards data the client hasn't received yet,
    // so let the client, which reads last, close it.
    connection.closed().await;
    Ok(())
}

/// Parses the `%h` or `%h:%p` argument given to the proxy into an endpoint id.
fn parse_proxy_target(target: &str) -> anyhow::Result<EndpointId> {
    let hostname = target.split_once(':').map_or(target, |(host, _port)| host);
    EndpointId::from_str(hostname).with_context(|| format!("invalid endpoint id '{hostname}'"))
}

async fn proxy(args: ProxyArgs) -> anyhow::Result<()> {
    let endpoint = create_endpoint(SecretKey::generate(), &args.common, vec![]).await?;

    let connection = endpoint.connect(args.endpoint_id, ALPN).await?;
    tracing::info!("connected to {}", args.endpoint_id);
    let (send, recv) = connection.open_bi().await?;
    tracing::info!("opened bidi stream to {}", args.endpoint_id);

    let forward_from_stdin = copy_to_noq(tokio::io::stdin(), send);
    let forward_to_stdout = copy_from_noq(recv, tokio::io::stdout());
    tokio::pin!(forward_to_stdout);

    // Keep reading after stdin closes, but don't wait for stdin once the server
    // is done: ssh only closes it after seeing EOF from us.
    let forward = async {
        tokio::select! {
            res = &mut forward_to_stdout => res,
            // A failed write means the server stopped reading, and whatever it sent
            // before that is still worth receiving, so only the read side's errors matter.
            _ = forward_from_stdin => forward_to_stdout.await,
        }
    };

    tokio::select! {
        res = forward => res?,
        // Close the connection so the server doesn't wait for an idle timeout.
        _ = tokio::signal::ctrl_c() => {}
    }

    connection.close(0u32.into(), b"done");
    endpoint.close().await;
    Ok(())
}

/// Copy from a reader to a noq stream, then finish the stream.
async fn copy_to_noq(mut from: impl AsyncRead + Unpin, mut send: SendStream) -> io::Result<()> {
    let res = copy_flushing(&mut from, &mut send).await;
    send.finish().ok();
    res
}

/// Copy from a noq stream to a writer, then shut the writer down.
async fn copy_from_noq(mut recv: RecvStream, mut to: impl AsyncWrite + Unpin) -> io::Result<()> {
    let res = copy_flushing(&mut recv, &mut to).await;
    to.shutdown().await.ok();
    res
}

/// Copies until EOF. Unlike `tokio::io::copy` the buffer is larger than 8K, which
/// is the main limit on throughput, and unlike `tokio::io::copy_buf` every chunk
/// is flushed, because stdout holds back data that doesn't end in a newline.
async fn copy_flushing(
    from: &mut (impl AsyncRead + Unpin),
    to: &mut (impl AsyncWrite + Unpin),
) -> io::Result<()> {
    let mut buf = vec![0; COPY_BUFFER_SIZE];
    loop {
        match from.read(&mut buf).await? {
            0 => return to.flush().await,
            n => {
                to.write_all(&buf[..n]).await?;
                to.flush().await?;
            }
        }
    }
}

/// Create a new iroh endpoint.
async fn create_endpoint(
    secret_key: SecretKey,
    common: &CommonArgs,
    alpns: Vec<Vec<u8>>,
) -> anyhow::Result<Endpoint> {
    let mdns_lookup = iroh_mdns_peer_lookup::Options::new()
        .announce(!alpns.is_empty())
        .build();
    let mut builder = Endpoint::builder(iroh::endpoint::presets::N0)
        .secret_key(secret_key)
        .alpns(alpns)
        .address_lookup(DhtAddressLookup::builder())
        .address_lookup(iroh_mdns_peer_lookup::lookup(mdns_lookup).await?);

    if let Some(addr) = common.ipv4_addr {
        builder = builder.bind_addr(addr)?;
    }
    if let Some(addr) = common.ipv6_addr {
        builder = builder.bind_addr(addr)?;
    }
    if let Some(relay_map) = custom_relay_map(
        &common.relay_url,
        &common.extra_relay_url,
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
    timeout(Duration::from_secs(10), probe)
        .await
        .context("timed out")?
}

/// Loads the server's key from `dir`, creating it on first use.
fn get_or_create_secret(dir: &Path) -> anyhow::Result<SecretKey> {
    let priv_key = dir.join("irohssh_ed25519");
    if priv_key.exists() {
        let encoded = std::fs::read(&priv_key)
            .with_context(|| format!("failed to read secret key from {}", priv_key.display()))?;
        let bytes: [u8; 32] = z32::decode(&encoded)
            .ok()
            .and_then(|decoded| decoded.try_into().ok())
            .with_context(|| format!("invalid secret key in {}", priv_key.display()))?;
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
fn write_private(path: &Path, contents: &str) -> io::Result<()> {
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
        assert!(Args::try_parse_from(["iroh-ssh", "server"]).is_ok());
        assert!(Args::try_parse_from(["iroh-ssh", "proxy", ENDPOINT_ID]).is_ok());

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
            assert!(Args::try_parse_from(&args).is_err(), "{args:?} should fail");
        }
    }

    #[test]
    fn key_survives_a_missing_public_key_file() {
        let dir = tempfile::tempdir().unwrap();
        let key = get_or_create_secret(dir.path()).unwrap();
        std::fs::remove_file(dir.path().join("irohssh_ed25519.pub")).unwrap();

        let reloaded = get_or_create_secret(dir.path()).unwrap();
        assert_eq!(reloaded.to_bytes(), key.to_bytes());
    }

    #[cfg(unix)]
    #[test]
    fn private_key_is_only_readable_by_owner() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        get_or_create_secret(dir.path()).unwrap();

        let metadata = std::fs::metadata(dir.path().join("irohssh_ed25519")).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn wrong_length_key_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        // valid z-base32, but not 32 bytes
        std::fs::write(dir.path().join("irohssh_ed25519"), "yyyy").unwrap();

        assert!(get_or_create_secret(dir.path()).is_err());
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
        assert!(Args::try_parse_from(args).is_err());
    }

    #[test]
    fn invalid_relay_url_is_rejected() {
        let args = ["iroh-ssh", "server", "--relay-url", "not a url"];
        assert!(Args::try_parse_from(args).is_err());
    }

    #[test]
    fn bind_addrs_are_parsed() {
        let args = Args::try_parse_from([
            "iroh-ssh",
            "server",
            "--ipv4-addr",
            "0.0.0.0:4433",
            "--ipv6-addr",
            "[::]:4433",
        ])
        .unwrap();
        let Commands::Server(args) = args.command else {
            panic!("expected the server command");
        };
        assert_eq!(args.common.ipv4_addr.unwrap().port(), 4433);
        assert_eq!(args.common.ipv6_addr.unwrap().port(), 4433);
    }

    #[test]
    fn key_dir_requires_persist() {
        assert!(Args::try_parse_from(["iroh-ssh", "server", "--key-dir", "/tmp"]).is_err());
        assert!(Args::try_parse_from(["iroh-ssh", "server", "-p", "--key-dir", "/tmp"]).is_ok());
    }

    #[tokio::test]
    async fn copy_flushing_flushes_without_a_newline_or_eof() {
        let (mut input, mut reader) = tokio::io::duplex(64);
        let (output, mut sink) = tokio::io::duplex(COPY_BUFFER_SIZE);
        let mut writer = tokio::io::BufWriter::new(output);

        let copy = tokio::spawn(async move { copy_flushing(&mut reader, &mut writer).await });

        input.write_all(b"no newline").await.unwrap();
        let mut received = [0; 10];
        tokio::time::timeout(Duration::from_secs(5), sink.read_exact(&mut received))
            .await
            .expect("data should arrive while the input is still open")
            .unwrap();
        assert_eq!(&received, b"no newline");

        drop(input);
        copy.await.unwrap().unwrap();
    }
}
