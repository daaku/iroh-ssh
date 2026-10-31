use crate::{Builder, Inner, IrohSsh};
use std::{path::Path, time::Duration};

use anyhow::bail;
use ed25519_dalek::SECRET_KEY_LENGTH;
use homedir::my_home;
use iroh_mainline_address_lookup::DhtAddressLookup;
use regex::Regex;
use std::sync::Arc;

use iroh::{
    Endpoint, EndpointId, RelayConfig, RelayMap, RelayUrl, SecretKey,
    endpoint::{Connection, RelayMode},
    protocol::{ProtocolHandler, Router},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
};

const RELAY_TOKEN_ENV: &str = "IROH_RELAY_TOKEN";

impl Builder {
    pub fn new() -> Self {
        Self {
            secret_key: SecretKey::generate().to_bytes(),
            accept_incoming: false,
            accept_port: None,
            key_dir: None,
            relay_urls: Vec::new(),
            extra_relay_urls: Vec::new(),
        }
    }

    pub fn accept_incoming(mut self, accept_incoming: bool) -> Self {
        self.accept_incoming = accept_incoming;
        self
    }

    pub fn accept_port(mut self, accept_port: u16) -> Self {
        self.accept_port = Some(accept_port);
        self
    }

    pub fn secret_key(mut self, secret_key: &[u8; SECRET_KEY_LENGTH]) -> Self {
        self.secret_key = *secret_key;
        self
    }

    pub fn relay_urls(mut self, urls: Vec<RelayUrl>) -> Self {
        self.relay_urls = urls;
        self
    }

    pub fn extra_relay_urls(mut self, urls: Vec<RelayUrl>) -> Self {
        self.extra_relay_urls = urls;
        self
    }

    pub fn key_dir(mut self, key_dir: Option<std::path::PathBuf>) -> Self {
        self.key_dir = key_dir;
        self
    }

    pub fn dot_ssh_integration(mut self) -> Self {
        match dot_ssh(
            &SecretKey::from_bytes(&self.secret_key),
            self.key_dir.as_deref(),
        ) {
            Ok(secret_key) => {
                tracing::info!("dot_ssh_integration: Successfully loaded/created SSH keys");
                self.secret_key = secret_key.to_bytes();
            }
            Err(e) => {
                tracing::error!(
                    "dot_ssh_integration: Failed to load/create SSH keys: {:#}",
                    e
                );
                eprintln!("Warning: Failed to load/create persistent SSH keys: {e:#}");
                eprintln!("Continuing with ephemeral keys...");
            }
        }
        self
    }

    pub async fn build(&mut self) -> anyhow::Result<IrohSsh> {
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
    pub fn builder() -> Builder {
        Builder::new()
    }

    #[allow(non_snake_case)]
    pub fn ALPN() -> Vec<u8> {
        b"/iroh/ssh".to_vec()
    }

    fn add_inner(&mut self, endpoint: Endpoint, router: Router) {
        self.inner = Some(Inner { endpoint, router });
    }

    pub async fn connect_pubkey(&self, endpoint_id: EndpointId) -> anyhow::Result<()> {
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

    pub fn endpoint_id(&self) -> EndpointId {
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

pub fn dot_ssh(
    default_secret_key: &SecretKey,
    key_dir: Option<&Path>,
) -> anyhow::Result<SecretKey> {
    tracing::info!("dot_ssh: Function called, key_dir={:?}", key_dir);

    let ssh_dir = if let Some(dir) = key_dir {
        dir.to_path_buf()
    } else {
        let distro_home = my_home()?.ok_or_else(|| anyhow::anyhow!("home directory not found"))?;
        distro_home.join(".ssh")
    };

    let pub_key = ssh_dir.join("irohssh_ed25519.pub");
    let priv_key = ssh_dir.join("irohssh_ed25519");

    tracing::debug!("dot_ssh: ssh_dir exists = {}", ssh_dir.exists());
    tracing::debug!("dot_ssh: pub_key path = {}", pub_key.display());
    tracing::debug!("dot_ssh: priv_key path = {}", priv_key.display());

    if !ssh_dir.exists() {
        tracing::info!("dot_ssh: Creating ssh_dir: {}", ssh_dir.display());
        std::fs::create_dir_all(&ssh_dir)?;
        println!("[INFO] created .ssh folder: {}", ssh_dir.display());
    }

    // check pub and priv key already exists
    if pub_key.exists() && priv_key.exists() {
        tracing::info!("dot_ssh: Keys exist, reading them");
        // read secret key
        if let Ok(secret_key) = std::fs::read(priv_key.clone()) {
            let mut sk_bytes = [0u8; SECRET_KEY_LENGTH];
            sk_bytes.copy_from_slice(z32::decode(secret_key.as_slice())?.as_slice());
            Ok(SecretKey::from_bytes(&sk_bytes))
        } else {
            bail!("failed to read secret key from {}", priv_key.display())
        }
    } else {
        tracing::info!("dot_ssh: Keys don't exist, creating new keys");

        let secret_key = default_secret_key.clone();
        let public_key = secret_key.public();

        match std::fs::write(&pub_key, z32::encode(public_key.as_bytes())) {
            Ok(_) => {
                tracing::info!("dot_ssh: Successfully wrote pub_key");
            }
            Err(e) => {
                tracing::error!(
                    "dot_ssh: Failed to write pub_key: {} (error kind: {:?})",
                    e,
                    e.kind()
                );
                return Err(e.into());
            }
        }

        match std::fs::write(&priv_key, z32::encode(&secret_key.to_bytes())) {
            Ok(_) => {
                tracing::info!("dot_ssh: Successfully wrote priv_key");
            }
            Err(e) => {
                tracing::error!(
                    "dot_ssh: Failed to write priv_key: {} (error kind: {:?})",
                    e,
                    e.kind()
                );
                return Err(e.into());
            }
        }

        Ok(secret_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr as _;

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
}
