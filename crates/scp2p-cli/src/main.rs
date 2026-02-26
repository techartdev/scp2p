use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use scp2p_core::{
    describe_content, BoxedStream, DirectRequestTransport, ItemV1, ManifestV1, Node, NodeConfig,
    NodeId, PeerAddr, PeerConnector, SearchQuery, ShareId, ShareKeypair, SqliteStore, Store,
    TransportProtocol,
};
use tokio::net::TcpStream;

#[derive(Parser)]
#[command(name = "scp2p")]
#[command(about = "SCP2P reference CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    GenIdentity,
    PrintIds,
    Start {
        #[arg(long, default_value = "scp2p.db")]
        state_db: String,
        #[arg(long = "bootstrap", value_name = "IP:PORT", num_args = 0..)]
        bootstrap: Vec<String>,
        #[arg(long, default_value_t = 30)]
        sync_interval_secs: u64,
        #[arg(long, default_value_t = 300)]
        republish_interval_secs: u64,
    },
    Subscribe {
        #[arg(long, default_value = "scp2p.db")]
        state_db: String,
        #[arg(long)]
        share_id: String,
        #[arg(long)]
        share_pubkey: Option<String>,
    },
    PublishTestShare {
        #[arg(long, default_value = "scp2p.db")]
        state_db: String,
        #[arg(long)]
        share_secret: Option<String>,
        #[arg(long, default_value = "LAN Test Share")]
        title: String,
        #[arg(long, default_value = "lan-test-item.txt")]
        item_name: String,
        #[arg(long, default_value = "scp2p test payload")]
        item_text: String,
    },
    SyncNow {
        #[arg(long, default_value = "scp2p.db")]
        state_db: String,
        #[arg(long = "bootstrap", value_name = "IP:PORT", num_args = 1..)]
        bootstrap: Vec<String>,
    },
    Search {
        #[arg(long, default_value = "scp2p.db")]
        state_db: String,
        #[arg(long)]
        query: String,
    },
    InspectState {
        #[arg(long, default_value = "scp2p.db")]
        state_db: String,
    },
}

struct CliTcpConnector;

#[async_trait]
impl PeerConnector for CliTcpConnector {
    async fn connect(&self, peer: &PeerAddr) -> anyhow::Result<BoxedStream> {
        if peer.transport != TransportProtocol::Tcp {
            anyhow::bail!("cli tcp connector only supports tcp peers");
        }
        let socket = SocketAddr::new(peer.ip, peer.port);
        let stream = TcpStream::connect(socket).await?;
        Ok(Box::new(stream) as BoxedStream)
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::GenIdentity => {
            let mut rng = OsRng;
            let key = SigningKey::generate(&mut rng);
            println!("private_key: {}", hex::encode(key.to_bytes()));
            println!(
                "public_key: {}",
                hex::encode(key.verifying_key().to_bytes())
            );
        }
        Command::PrintIds => {
            let mut rng = OsRng;
            let key = SigningKey::generate(&mut rng);
            let pubkey = key.verifying_key();
            let node_id = NodeId::from_pubkey(&pubkey);
            let share_id = ShareId::from_pubkey(&pubkey);
            println!("node_id: {}", hex::encode(node_id.0));
            println!("share_id: {}", hex::encode(share_id.0));
        }
        Command::Start {
            state_db,
            bootstrap,
            sync_interval_secs,
            republish_interval_secs,
        } => {
            let node = open_node(&state_db, &bootstrap).await?;
            let mut rng = OsRng;
            let node_key = SigningKey::generate(&mut rng);
            let _service = node.clone().start_tcp_dht_service(
                "0.0.0.0:7001".parse()?,
                node_key,
                scp2p_core::Capabilities::default(),
            );
            let peers = bootstrap
                .iter()
                .map(|entry| parse_bootstrap_peer(entry))
                .collect::<anyhow::Result<Vec<_>>>()?;

            if !peers.is_empty() {
                let transport = Arc::new(DirectRequestTransport::new(CliTcpConnector));
                let republish_peers = peers.clone();
                let _sync = node.clone().start_subscription_sync_loop(
                    transport.clone(),
                    peers,
                    Duration::from_secs(sync_interval_secs.max(1)),
                );
                let _republish = node.clone().start_dht_republish_loop(
                    transport,
                    republish_peers,
                    Duration::from_secs(republish_interval_secs.max(1)),
                );
                println!(
                    "node started; periodic signed sync={}s republish={}s",
                    sync_interval_secs.max(1),
                    republish_interval_secs.max(1)
                );
            } else {
                println!("node started; no bootstrap peers configured");
            }
            tokio::signal::ctrl_c().await?;
        }
        Command::Subscribe {
            state_db,
            share_id,
            share_pubkey,
        } => {
            let node = open_node(&state_db, &[]).await?;
            let share_id = parse_hex_32(&share_id, "share_id")?;
            let share_pubkey = share_pubkey
                .as_deref()
                .map(|hex| parse_hex_32(hex, "share_pubkey"))
                .transpose()?;
            node.subscribe_with_pubkey(ShareId(share_id), share_pubkey)
                .await?;
            println!("subscribed share_id={}", hex::encode(share_id));
        }
        Command::PublishTestShare {
            state_db,
            share_secret,
            title,
            item_name,
            item_text,
        } => {
            let node = open_node(&state_db, &[]).await?;
            let share = share_secret
                .as_deref()
                .map(parse_signing_key_hex)
                .transpose()?
                .map(ShareKeypair::new)
                .unwrap_or_else(|| {
                    let mut rng = OsRng;
                    ShareKeypair::new(SigningKey::generate(&mut rng))
                });
            let content = describe_content(item_text.as_bytes());
            let now = now_unix_secs()?;
            let manifest = ManifestV1 {
                version: 1,
                share_pubkey: share.verifying_key().to_bytes(),
                share_id: share.share_id().0,
                seq: now,
                created_at: now,
                expires_at: None,
                title: Some(title),
                description: Some("generated by scp2p-cli publish-test-share".into()),
                items: vec![ItemV1 {
                    content_id: content.content_id.0,
                    size: item_text.len() as u64,
                    name: item_name,
                    mime: Some("text/plain".into()),
                    tags: vec!["lan".into(), "test".into()],
                    chunks: content.chunks,
                }],
                recommended_shares: vec![],
                signature: None,
            };
            let manifest_id = node.publish_share(manifest, &share).await?;
            println!(
                "share_secret: {}",
                hex::encode(share.signing_key.to_bytes())
            );
            println!(
                "share_pubkey: {}",
                hex::encode(share.verifying_key().to_bytes())
            );
            println!("share_id: {}", hex::encode(share.share_id().0));
            println!("manifest_id: {}", hex::encode(manifest_id));
        }
        Command::SyncNow {
            state_db,
            bootstrap,
        } => {
            let node = open_node(&state_db, &bootstrap).await?;
            let peers = bootstrap
                .iter()
                .map(|entry| parse_bootstrap_peer(entry))
                .collect::<anyhow::Result<Vec<_>>>()?;
            let transport = DirectRequestTransport::new(CliTcpConnector);
            node.sync_subscriptions_over_dht(&transport, &peers).await?;
            let state = load_state(&state_db).await?;
            println!(
                "sync complete: subscriptions={} manifests={} search_index={}",
                state.subscriptions.len(),
                state.manifests.len(),
                state
                    .search_index
                    .as_ref()
                    .map(|_| "present")
                    .unwrap_or("absent")
            );
            for sub in state.subscriptions {
                println!(
                    "sub share_id={} latest_seq={} manifest_id={}",
                    hex::encode(sub.share_id),
                    sub.latest_seq,
                    sub.latest_manifest_id
                        .map(hex::encode)
                        .unwrap_or_else(|| "<none>".into())
                );
            }
        }
        Command::Search { state_db, query } => {
            let node = open_node(&state_db, &[]).await?;
            let hits = node.search(SearchQuery { text: query }).await?;
            if hits.is_empty() {
                println!("no results");
            } else {
                for hit in hits {
                    println!(
                        "score={:.2} share_id={} content_id={} name={}",
                        hit.score,
                        hex::encode(hit.share_id.0),
                        hex::encode(hit.content_id),
                        hit.name
                    );
                }
            }
        }
        Command::InspectState { state_db } => {
            let state = load_state(&state_db).await?;
            println!(
                "state: subscriptions={} manifests={} search_index={} partials={}",
                state.subscriptions.len(),
                state.manifests.len(),
                state
                    .search_index
                    .as_ref()
                    .map(|_| "present")
                    .unwrap_or("absent"),
                state.partial_downloads.len()
            );
            for sub in state.subscriptions {
                println!(
                    "sub share_id={} latest_seq={} manifest_id={}",
                    hex::encode(sub.share_id),
                    sub.latest_seq,
                    sub.latest_manifest_id
                        .map(hex::encode)
                        .unwrap_or_else(|| "<none>".into())
                );
            }
            for (mid, manifest) in state.manifests {
                println!(
                    "manifest id={} share_id={} seq={} items={}",
                    hex::encode(mid),
                    hex::encode(manifest.share_id),
                    manifest.seq,
                    manifest.items.len()
                );
            }
        }
    }

    Ok(())
}

fn parse_bootstrap_peer(input: &str) -> anyhow::Result<PeerAddr> {
    let socket: SocketAddr = input.parse()?;
    Ok(PeerAddr {
        ip: socket.ip(),
        port: socket.port(),
        transport: TransportProtocol::Tcp,
        pubkey_hint: None,
    })
}

async fn open_node(state_db: &str, bootstrap: &[String]) -> anyhow::Result<scp2p_core::NodeHandle> {
    let store = SqliteStore::open(state_db)?;
    let config = NodeConfig {
        bootstrap_peers: bootstrap.to_vec(),
        ..NodeConfig::default()
    };
    Node::start_with_store(config, store).await
}

async fn load_state(state_db: &str) -> anyhow::Result<scp2p_core::PersistedState> {
    let store = SqliteStore::open(state_db)?;
    store.load_state().await
}

fn parse_hex_32(input: &str, label: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = hex::decode(input)?;
    if bytes.len() != 32 {
        anyhow::bail!("{label} must be 32 bytes hex");
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_signing_key_hex(input: &str) -> anyhow::Result<SigningKey> {
    Ok(SigningKey::from_bytes(&parse_hex_32(
        input,
        "share_secret",
    )?))
}

fn now_unix_secs() -> anyhow::Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
