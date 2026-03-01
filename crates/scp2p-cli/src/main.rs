// Copyright (c) 2024-2026 Vanyo Vanev / Tech Art Ltd
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
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
    BoxedStream, Capabilities, DirectRequestTransport, FetchPolicy, ItemV1, ManifestV1, Node,
    NodeConfig, NodeId, PeerAddr, PeerConnector, SearchQuery, ShareId, ShareKeypair,
    ShareVisibility, SqliteStore, Store, TransportProtocol, build_tls_server_handle,
    describe_content, quic_connect_bi_session_insecure, tls_connect_session_insecure,
};

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
    Download {
        #[arg(long, default_value = "scp2p.db")]
        state_db: String,
        #[arg(long)]
        content_id: String,
        #[arg(long)]
        out: String,
        #[arg(long = "bootstrap", value_name = "IP:PORT", num_args = 1..)]
        bootstrap: Vec<String>,
    },
    PublishFiles {
        #[arg(long, default_value = "scp2p.db")]
        state_db: String,
        #[arg(long, default_value = "Shared Files")]
        title: String,
        /// One or more file paths to publish.
        #[arg(long = "file", num_args = 1..)]
        files: Vec<String>,
        #[arg(long, default_value = "private")]
        visibility: String,
    },
    PublishFolder {
        #[arg(long, default_value = "scp2p.db")]
        state_db: String,
        #[arg(long, default_value = "Shared Folder")]
        title: String,
        /// Path to the directory to publish.
        #[arg(long)]
        dir: String,
        #[arg(long, default_value = "private")]
        visibility: String,
    },
    BrowseShare {
        #[arg(long, default_value = "scp2p.db")]
        state_db: String,
        #[arg(long)]
        share_id: String,
    },
    DownloadShare {
        #[arg(long, default_value = "scp2p.db")]
        state_db: String,
        #[arg(long)]
        share_id: String,
        /// Optional content IDs to download selectively. Omit to download all.
        #[arg(long = "content-id", num_args = 0..)]
        content_ids: Vec<String>,
        #[arg(long)]
        out_dir: String,
        #[arg(long = "bootstrap", value_name = "IP:PORT", num_args = 0..)]
        bootstrap: Vec<String>,
    },
}

struct CliSessionConnector {
    signing_key: SigningKey,
    capabilities: Capabilities,
}

#[async_trait]
impl PeerConnector for CliSessionConnector {
    async fn connect(&self, peer: &PeerAddr) -> anyhow::Result<BoxedStream> {
        let remote = SocketAddr::new(peer.ip, peer.port);
        let expected = peer.pubkey_hint;
        match peer.transport {
            TransportProtocol::Tcp => {
                let (stream, _session) = tls_connect_session_insecure(
                    remote,
                    &self.signing_key,
                    self.capabilities.clone(),
                    expected,
                )
                .await?;
                Ok(Box::new(stream) as BoxedStream)
            }
            TransportProtocol::Quic => {
                let session = quic_connect_bi_session_insecure(
                    remote,
                    &self.signing_key,
                    self.capabilities.clone(),
                    expected,
                )
                .await?;
                Ok(Box::new(session.stream) as BoxedStream)
            }
        }
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
            let tls_server = Arc::new(build_tls_server_handle().expect("build TLS server handle"));
            let _service = node.clone().start_tls_dht_service(
                "0.0.0.0:7001".parse()?,
                node_key,
                scp2p_core::Capabilities::default(),
                tls_server,
            );
            let peers = bootstrap
                .iter()
                .map(|entry| parse_bootstrap_peer(entry))
                .collect::<anyhow::Result<Vec<_>>>()?;

            if !peers.is_empty() {
                let transport = Arc::new(DirectRequestTransport::new(CliSessionConnector {
                    signing_key: SigningKey::generate(&mut rng),
                    capabilities: Capabilities::default(),
                }));
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
                visibility: scp2p_core::ShareVisibility::Private,
                communities: vec![],
                items: vec![ItemV1 {
                    content_id: content.content_id.0,
                    size: item_text.len() as u64,
                    name: item_name,
                    path: None,
                    mime: Some("text/plain".into()),
                    tags: vec!["lan".into(), "test".into()],
                    chunk_count: content.chunk_count,
                    chunk_list_hash: content.chunk_list_hash,
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
            let mut rng = OsRng;
            let transport = DirectRequestTransport::new(CliSessionConnector {
                signing_key: SigningKey::generate(&mut rng),
                capabilities: Capabilities::default(),
            });
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
        Command::Download {
            state_db,
            content_id,
            out,
            bootstrap,
        } => {
            let node = open_node(&state_db, &bootstrap).await?;
            let peers = bootstrap
                .iter()
                .map(|entry| parse_bootstrap_peer(entry))
                .collect::<anyhow::Result<Vec<_>>>()?;
            let content_id = parse_hex_32(&content_id, "content_id")?;
            let mut rng = OsRng;
            let connector = CliSessionConnector {
                signing_key: SigningKey::generate(&mut rng),
                capabilities: Capabilities::default(),
            };
            node.download_from_peers(
                &connector,
                &peers,
                content_id,
                &out,
                &FetchPolicy::default(),
                None,
                None,
            )
            .await?;
            println!(
                "downloaded content_id={} -> {}",
                hex::encode(content_id),
                out
            );
        }
        Command::PublishFiles {
            state_db,
            title,
            files,
            visibility,
        } => {
            let node = open_node(&state_db, &[]).await?;
            let vis = parse_visibility(&visibility)?;
            let share = node.ensure_publisher_identity("default").await?;
            let bind: SocketAddr = "0.0.0.0:7001".parse()?;
            let provider = PeerAddr {
                ip: "127.0.0.1".parse()?,
                port: bind.port(),
                transport: TransportProtocol::Tcp,
                pubkey_hint: None,
                relay_via: None,
            };
            let paths: Vec<std::path::PathBuf> =
                files.iter().map(std::path::PathBuf::from).collect();
            let manifest_id = node
                .publish_files(
                    &paths,
                    None,
                    &title,
                    Some("published via scp2p-cli"),
                    vis,
                    &[],
                    provider,
                    &share,
                )
                .await?;
            println!("share_id: {}", hex::encode(share.share_id().0));
            println!(
                "share_pubkey: {}",
                hex::encode(share.verifying_key().to_bytes())
            );
            println!("manifest_id: {}", hex::encode(manifest_id));
            println!("items: {}", files.len());
        }
        Command::PublishFolder {
            state_db,
            title,
            dir,
            visibility,
        } => {
            let node = open_node(&state_db, &[]).await?;
            let vis = parse_visibility(&visibility)?;
            let share = node.ensure_publisher_identity("default").await?;
            let bind: SocketAddr = "0.0.0.0:7001".parse()?;
            let provider = PeerAddr {
                ip: "127.0.0.1".parse()?,
                port: bind.port(),
                transport: TransportProtocol::Tcp,
                pubkey_hint: None,
                relay_via: None,
            };
            let dir_path = std::path::Path::new(&dir);
            let manifest_id = node
                .publish_folder(
                    dir_path,
                    &title,
                    Some("published via scp2p-cli"),
                    vis,
                    &[],
                    provider,
                    &share,
                )
                .await?;
            println!("share_id: {}", hex::encode(share.share_id().0));
            println!(
                "share_pubkey: {}",
                hex::encode(share.verifying_key().to_bytes())
            );
            println!("manifest_id: {}", hex::encode(manifest_id));
        }
        Command::BrowseShare { state_db, share_id } => {
            let node = open_node(&state_db, &[]).await?;
            let share_id = parse_hex_32(&share_id, "share_id")?;
            let items = node.list_share_items(share_id).await?;
            if items.is_empty() {
                println!("no items in share");
            } else {
                println!("{} items:", items.len());
                for (i, item) in items.iter().enumerate() {
                    println!(
                        "  [{}] content_id={} size={} name={} path={} mime={}",
                        i + 1,
                        hex::encode(item.content_id),
                        item.size,
                        item.name,
                        item.path.as_deref().unwrap_or("-"),
                        item.mime.as_deref().unwrap_or("-"),
                    );
                }
            }
        }
        Command::DownloadShare {
            state_db,
            share_id,
            content_ids,
            out_dir,
            bootstrap,
        } => {
            let node = open_node(&state_db, &bootstrap).await?;
            let share_id = parse_hex_32(&share_id, "share_id")?;
            let content_ids: Vec<[u8; 32]> = content_ids
                .iter()
                .map(|h| parse_hex_32(h, "content_id"))
                .collect::<anyhow::Result<_>>()?;
            let target = std::path::Path::new(&out_dir);
            let items = node.list_share_items(share_id).await?;
            let to_download: Vec<_> = if content_ids.is_empty() {
                items.iter().collect()
            } else {
                items
                    .iter()
                    .filter(|i| content_ids.contains(&i.content_id))
                    .collect()
            };
            if to_download.is_empty() {
                anyhow::bail!("no matching items found in share");
            }
            let peers = bootstrap
                .iter()
                .map(|e| parse_bootstrap_peer(e))
                .collect::<anyhow::Result<Vec<_>>>()?;
            let mut rng = OsRng;
            let connector = CliSessionConnector {
                signing_key: SigningKey::generate(&mut rng),
                capabilities: Capabilities::default(),
            };
            let policy = FetchPolicy::default();
            let mut downloaded_paths = Vec::new();
            for item in to_download {
                let rel = item.path.as_deref().unwrap_or(&item.name);
                let dest = rel
                    .replace('\\', "/")
                    .split('/')
                    .filter(|p| !p.is_empty() && *p != "..")
                    .fold(target.to_path_buf(), |acc, p| acc.join(p));
                if let Some(parent) = dest.parent() {
                    tokio::fs::create_dir_all(parent).await?;
                }
                node.download_from_peers(
                    &connector,
                    &peers,
                    item.content_id,
                    &dest.to_string_lossy(),
                    &policy,
                    None,
                    None,
                )
                .await?;
                downloaded_paths.push(dest);
            }
            println!("downloaded {} files to {}", downloaded_paths.len(), out_dir);
            for path in &downloaded_paths {
                println!("  {}", path.display());
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
        relay_via: None,
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

fn parse_visibility(input: &str) -> anyhow::Result<ShareVisibility> {
    match input.to_lowercase().as_str() {
        "private" => Ok(ShareVisibility::Private),
        "public" => Ok(ShareVisibility::Public),
        _ => anyhow::bail!("visibility must be 'private' or 'public'"),
    }
}
