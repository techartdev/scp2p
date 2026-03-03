// Copyright (c) 2024-2026 Vanyo Vanev / Tech Art Ltd
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::{io::IsTerminal, net::SocketAddr, sync::Arc, time::Duration};

use async_trait::async_trait;
use ed25519_dalek::SigningKey;
use indicatif::{ProgressBar, ProgressStyle};
use inquire::{InquireError, Select, Text};
use rand::rngs::OsRng;
use scp2p_core::{
    BoxedStream, Capabilities, FetchPolicy, Node, NodeConfig, NodeId, OwnedRelayAwareTransport,
    PeerAddr, PeerConnector, PeerRecord, PersistedCommunity, RelayAwareTransport,
    RequestTransport, SearchQuery, ShareId, ShareVisibility, SqliteStore, Store,
    TransportProtocol, build_tls_server_handle, quic_connect_bi_session_insecure,
    start_quic_server, tls_connect_session_insecure,
};
use tracing::{info, warn};

// ── Internal connector ────────────────────────────────────────────────────────

struct CliConnector {
    signing_key: SigningKey,
}

#[async_trait]
impl PeerConnector for CliConnector {
    async fn connect(&self, peer: &PeerAddr) -> anyhow::Result<BoxedStream> {
        let remote = SocketAddr::new(peer.ip, peer.port);
        let expected = peer.pubkey_hint;
        match peer.transport {
            TransportProtocol::Tcp => {
                let (stream, _) = tls_connect_session_insecure(
                    remote,
                    &self.signing_key,
                    Capabilities::default(),
                    expected,
                )
                .await?;
                Ok(Box::new(stream))
            }
            TransportProtocol::Quic => {
                let s = quic_connect_bi_session_insecure(
                    remote,
                    &self.signing_key,
                    Capabilities::default(),
                    expected,
                )
                .await?;
                Ok(Box::new(s.stream))
            }
        }
    }
}

// ── Shell context ─────────────────────────────────────────────────────────────

struct Ctx {
    node: scp2p_core::NodeHandle,
    node_key: SigningKey,
    node_id: NodeId,
    share_id: ShareId,
    connector: CliConnector,
    db: String,
    port: u16,
    quic_port: u16,
    bootstrap_peers: Vec<PeerAddr>,
    dht_transport: Arc<dyn RequestTransport>,
}

impl Ctx {
    fn new_connector(&self) -> CliConnector {
        CliConnector {
            signing_key: self.node_key.clone(),
        }
    }

    fn unique_publisher_label() -> String {
        let mut buf = [0u8; 8];
        rand::RngCore::fill_bytes(&mut OsRng, &mut buf);
        format!("share-{}", hex::encode(buf))
    }

    fn transport(&self) -> RelayAwareTransport<'_, CliConnector> {
        RelayAwareTransport::new(&self.connector)
    }

    fn provider_addr(&self) -> PeerAddr {
        PeerAddr {
            ip: "127.0.0.1".parse().unwrap(),
            port: self.port,
            transport: TransportProtocol::Tcp,
            pubkey_hint: None,
            relay_via: None,
        }
    }

    async fn load_state(&self) -> anyhow::Result<scp2p_core::PersistedState> {
        let store = SqliteStore::open(&self.db)?;
        store.load_state().await
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

pub async fn run(db: String, bootstrap_raw: Vec<String>, port: u16, quic_port: u16) -> anyhow::Result<()> {
    let pb = spinner("Opening database…");
    let store = SqliteStore::open(&db)?;
    let config = NodeConfig {
        bootstrap_peers: bootstrap_raw.clone(),
        ..NodeConfig::default()
    };
    let node = Node::start_with_store(config, store).await?;
    let node_key = node.ensure_node_identity().await?;
    pb.finish_and_clear();

    let node_id = NodeId::from_pubkey(&node_key.verifying_key());
    let share_id = ShareId::from_pubkey(&node_key.verifying_key());

    // Start background TLS listener so we can serve content to peers.
    let tls = Arc::new(build_tls_server_handle().expect("TLS server handle"));
    let bind_tcp: SocketAddr = format!("0.0.0.0:{port}").parse()?;
    let _svc = node.clone().start_tls_dht_service(
        bind_tcp,
        node_key.clone(),
        Capabilities::default(),
        tls,
    );

    // Start QUIC listener (disabled when quic_port == 0).
    let _quic_svc = if quic_port > 0 {
        let bind_quic: SocketAddr = format!("0.0.0.0:{quic_port}").parse()?;
        let quic_server = start_quic_server(bind_quic)?;
        Some(node.clone().start_quic_dht_service(
            quic_server,
            node_key.clone(),
            Capabilities::default(),
        ))
    } else {
        None
    };

    let bootstrap_peers: Vec<PeerAddr> = bootstrap_raw
        .iter()
        .filter_map(|s| parse_peer(s).ok())
        .collect();

    // Start background DHT republish + subscription sync loops.
    let connector_arc = Arc::new(CliConnector {
        signing_key: node_key.clone(),
    });
    let owned_transport: Arc<dyn RequestTransport> =
        Arc::new(OwnedRelayAwareTransport::new(connector_arc));
    let _dht_loop = node.clone().start_dht_republish_loop(
        owned_transport.clone(),
        bootstrap_peers.clone(),
        Duration::from_secs(60),
    );
    let _sync_loop = node.clone().start_subscription_sync_loop(
        owned_transport.clone(),
        bootstrap_peers.clone(),
        Duration::from_secs(60),
    );

    // ── Relay tunnel registration ─────────────────────────────────────────
    // Maintain a persistent relay tunnel so that peers behind NAT can reach
    // us for content downloads.
    let _relay_tunnel = {
        let tunnel_handle = node.clone();
        let tunnel_key = node_key.clone();
        let tunnel_bootstrap = bootstrap_peers.clone();
        let tunnel_transport = owned_transport.clone();
        tokio::spawn(async move {
            let connector = CliConnector {
                signing_key: tunnel_key,
            };
            loop {
                if !tunnel_handle.active_relay_slots().await.is_empty() {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    continue;
                }
                let mut registered = false;
                for peer in &tunnel_bootstrap {
                    match tunnel_handle.register_relay_tunnel(&connector, peer).await {
                        Ok(slot) => {
                            info!(
                                slot_id = slot.slot_id,
                                relay = %format!("{}:{}", peer.ip, peer.port),
                                "relay tunnel registered"
                            );
                            registered = true;
                            // Re-announce provider entries with relayed address.
                            let peer_records = tunnel_handle.peer_records().await;
                            if let Ok(adv_ip) = resolve_advertise_ip(bind_tcp, &peer_records) {
                                let self_addr = tunnel_handle
                                    .relayed_self_addr(PeerAddr {
                                        ip: adv_ip,
                                        port: bind_tcp.port(),
                                        transport: TransportProtocol::Tcp,
                                        pubkey_hint: None,
                                        relay_via: None,
                                    })
                                    .await;
                                let _ = tunnel_handle
                                    .reannounce_content_providers(self_addr)
                                    .await;
                            }
                            // Push to relay immediately.
                            let _ = tunnel_handle
                                .dht_republish_once(
                                    tunnel_transport.as_ref(),
                                    &tunnel_bootstrap,
                                )
                                .await;
                            break;
                        }
                        Err(e) => {
                            warn!(
                                relay = %format!("{}:{}", peer.ip, peer.port),
                                error = %e,
                                "relay tunnel registration failed, trying next"
                            );
                        }
                    }
                }
                if !registered {
                    warn!("relay tunnel: no peer accepted, retrying in 30s");
                }
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        })
    };

    let connector = CliConnector {
        signing_key: node_key.clone(),
    };
    let ctx = Ctx {
        node,
        node_key,
        node_id,
        share_id,
        connector,
        db,
        port,
        quic_port,
        bootstrap_peers,
        dht_transport: owned_transport,
    };

    // ── Welcome banner ────────────────────────────────────────────────────────
    print_banner(&ctx);
    println!();

    // ── Main REPL loop ────────────────────────────────────────────────────────
    loop {
        let actions = vec![
            "📋  Status",
            "📤  Publish files",
            "📁  Publish folder",
            "📚  Browse / inspect a share",
            "🔔  Subscriptions",
            "🏘  Communities",
            "🔍  Search",
            "⬇   Download by content ID",
            "⬇   Download share",
            "🔄  Sync now",
            "🔑  Generate new keypair",
            "❌  Quit",
        ];

        println!();
        let choice = match Select::new("What would you like to do?", actions).prompt() {
            Ok(c) => c,
            Err(InquireError::OperationCanceled | InquireError::OperationInterrupted) => break,
            Err(e) => return Err(e.into()),
        };

        let res: anyhow::Result<()> = match choice {
            c if c.contains("Status") => cmd_status(&ctx).await,
            c if c.contains("Publish files") => cmd_publish_files(&ctx).await,
            c if c.contains("Publish folder") => cmd_publish_folder(&ctx).await,
            c if c.contains("Browse") => cmd_browse_share(&ctx).await,
            c if c.contains("Subscription") => cmd_subscriptions(&ctx).await,
            c if c.contains("Communit") => cmd_communities(&ctx).await,
            c if c.contains("Search") => cmd_search(&ctx).await,
            c if c.contains("content ID") => cmd_download_content(&ctx).await,
            c if c.contains("Download share") => cmd_download_share(&ctx).await,
            c if c.contains("Sync") => cmd_sync(&ctx).await,
            c if c.contains("keypair") => {
                cmd_gen_keypair();
                Ok(())
            }
            _ => break,
        };

        if let Err(e) = res {
            eprintln!("\n  ✗  {e:#}\n");
        }
    }

    println!("\n  Goodbye!\n");
    Ok(())
}

// ── Status ────────────────────────────────────────────────────────────────────

async fn cmd_status(ctx: &Ctx) -> anyhow::Result<()> {
    let s = ctx.load_state().await?;
    println!();
    println!("  Node ID  : {}", hex::encode(ctx.node_id.0));
    println!("  Share ID : {}", hex::encode(ctx.share_id.0));
    println!("  Database : {}", ctx.db);
    println!("  TCP port : {}", ctx.port);
    println!(
        "  QUIC port: {}",
        if ctx.quic_port > 0 { ctx.quic_port.to_string() } else { "disabled".to_owned() }
    );
    println!("  Subscriptions  : {}", s.subscriptions.len());
    println!("  Manifests      : {}", s.manifests.len());
    println!("  Partial DLs    : {}", s.partial_downloads.len());
    println!(
        "  Search index   : {}",
        if s.search_index.is_some() {
            "present"
        } else {
            "absent"
        }
    );
    Ok(())
}

// ── Publish files ─────────────────────────────────────────────────────────────

async fn cmd_publish_files(ctx: &Ctx) -> anyhow::Result<()> {
    let title = match opt(Text::new("Share title:")
        .with_default("Shared Files")
        .prompt())?
    {
        Some(v) => v,
        None => return Ok(()),
    };

    let files_raw = match opt(Text::new("File paths (comma-separated):")
        .with_placeholder("/a/b.txt,/c/d.txt")
        .prompt())?
    {
        Some(v) => v,
        None => return Ok(()),
    };

    let vis_choice = match opt(Select::new("Visibility:", vec!["private", "public"]).prompt())? {
        Some(v) => v,
        None => return Ok(()),
    };

    let paths: Vec<std::path::PathBuf> = files_raw
        .split(',')
        .map(|p| std::path::PathBuf::from(p.trim()))
        .filter(|p| !p.as_os_str().is_empty())
        .collect();

    if paths.is_empty() {
        println!("\n  No file paths provided.");
        return Ok(());
    }

    let vis = parse_vis(vis_choice);
    let label = Ctx::unique_publisher_label();
    let share = ctx.node.ensure_publisher_identity(&label).await?;
    let provider = ctx.provider_addr();

    let pb = spinner(format!("Publishing {} file(s)…", paths.len()).as_str());
    let manifest_id = ctx
        .node
        .publish_files(&paths, None, &title, None, vis, &[], provider, &share)
        .await?;
    pb.finish_and_clear();

    // Push to DHT immediately so the share is discoverable right away.
    trigger_dht_republish(ctx).await;

    println!();
    println!("  ✓  Published {} file(s)", paths.len());
    println!("  Share ID    : {}", hex::encode(share.share_id().0));
    println!("  Manifest ID : {}", hex::encode(manifest_id));
    Ok(())
}

// ── Publish folder ────────────────────────────────────────────────────────────

async fn cmd_publish_folder(ctx: &Ctx) -> anyhow::Result<()> {
    let dir = match opt(Text::new("Folder path:").prompt())? {
        Some(v) => v,
        None => return Ok(()),
    };

    let title = match opt(Text::new("Share title:")
        .with_default("Shared Folder")
        .prompt())?
    {
        Some(v) => v,
        None => return Ok(()),
    };

    let vis_choice = match opt(Select::new("Visibility:", vec!["private", "public"]).prompt())? {
        Some(v) => v,
        None => return Ok(()),
    };

    let vis = parse_vis(vis_choice);
    let label = Ctx::unique_publisher_label();
    let share = ctx.node.ensure_publisher_identity(&label).await?;
    let provider = ctx.provider_addr();

    let pb = spinner("Publishing folder…");
    let manifest_id = ctx
        .node
        .publish_folder(
            std::path::Path::new(&dir),
            &title,
            None,
            vis,
            &[],
            provider,
            &share,
        )
        .await?;
    pb.finish_and_clear();

    // Push to DHT immediately so the share is discoverable right away.
    trigger_dht_republish(ctx).await;

    println!();
    println!("  ✓  Folder published");
    println!("  Share ID    : {}", hex::encode(share.share_id().0));
    println!("  Manifest ID : {}", hex::encode(manifest_id));
    Ok(())
}

// ── Browse / inspect a share ──────────────────────────────────────────────────

async fn cmd_browse_share(ctx: &Ctx) -> anyhow::Result<()> {
    let state = ctx.load_state().await?;

    // Build an option list from known manifests; fall back to manual entry.
    let share_id_hex: String;
    if !state.manifests.is_empty() {
        let mut choices: Vec<String> = state
            .manifests
            .values()
            .map(|m| {
                let sid = hex::encode(m.share_id);
                let title = m.title.as_deref().unwrap_or("untitled");
                format!("{title}  [{}…]  {} item(s)", &sid[..12], m.items.len())
            })
            .collect();
        choices.push("↩  Enter share ID manually".to_owned());

        let pick = match opt(Select::new("Pick a share to browse:", choices.clone()).prompt())? {
            Some(p) => p,
            None => return Ok(()),
        };

        if pick.starts_with("↩") {
            share_id_hex = match opt(Text::new("Share ID (64 hex chars):").prompt())? {
                Some(s) => s,
                None => return Ok(()),
            };
        } else {
            let idx = choices.iter().position(|c| *c == pick).unwrap_or(0);
            let manifest = state.manifests.values().nth(idx).unwrap();
            share_id_hex = hex::encode(manifest.share_id);
        }
    } else {
        println!("  No local manifests cached – enter a share ID to look up.");
        share_id_hex = match opt(Text::new("Share ID (64 hex chars):").prompt())? {
            Some(s) => s,
            None => return Ok(()),
        };
    }

    let sid = parse_hex_32(&share_id_hex, "share_id")?;
    let items = ctx.node.list_share_items(sid).await?;

    if items.is_empty() {
        println!("\n  No items found in share {}.", &share_id_hex[..16]);
        return Ok(());
    }

    println!(
        "\n  {} item(s) in share {}…",
        items.len(),
        &share_id_hex[..16]
    );
    println!();
    for (i, item) in items.iter().enumerate() {
        println!(
            "  [{:>3}]  {:40}  {:>9}  {}",
            i + 1,
            item.name,
            human_size(item.size),
            hex::encode(item.content_id),
        );
    }
    Ok(())
}

// ── Subscriptions ─────────────────────────────────────────────────────────────

async fn cmd_subscriptions(ctx: &Ctx) -> anyhow::Result<()> {
    loop {
        let sub_actions = vec![
            "📋  List subscriptions",
            "➕  Subscribe to a new share",
            "🔄  Sync subscriptions now",
            "←   Back",
        ];

        println!();
        let choice = match opt(Select::new("Subscriptions:", sub_actions).prompt())? {
            Some(c) => c,
            None => return Ok(()),
        };

        match choice {
            c if c.contains("List") => {
                let state = ctx.load_state().await?;
                if state.subscriptions.is_empty() {
                    println!("\n  No active subscriptions.");
                } else {
                    println!("\n  {} subscription(s):", state.subscriptions.len());
                    for sub in &state.subscriptions {
                        println!(
                            "  share_id={}  seq={}  manifest={}",
                            hex::encode(sub.share_id),
                            sub.latest_seq,
                            sub.latest_manifest_id
                                .map(hex::encode)
                                .unwrap_or_else(|| "<none>".into()),
                        );
                    }
                }
            }
            c if c.contains("Subscribe") => {
                let share_id_hex = match opt(Text::new("Share ID (64 hex chars):").prompt())? {
                    Some(s) => s,
                    None => continue,
                };
                let pubkey_hex = match opt(Text::new(
                    "Share public key (hex, optional – press Enter to skip):",
                )
                .with_default("")
                .prompt())?
                {
                    Some(s) => s,
                    None => continue,
                };

                let share_id = parse_hex_32(&share_id_hex, "share_id")?;
                let pubkey = if pubkey_hex.is_empty() {
                    None
                } else {
                    Some(parse_hex_32(&pubkey_hex, "share_pubkey")?)
                };

                ctx.node
                    .subscribe_with_pubkey(ShareId(share_id), pubkey)
                    .await?;
                println!("\n  ✓  Subscribed to {}", hex::encode(share_id));
            }
            c if c.contains("Sync") => {
                cmd_sync(ctx).await?;
            }
            _ => return Ok(()),
        }
    }
}

// ── Communities ───────────────────────────────────────────────────────────────

async fn cmd_communities(ctx: &Ctx) -> anyhow::Result<()> {
    loop {
        let sub_actions = vec![
            "📋  List communities",
            "➕  Create a new community",
            "🔗  Join a community",
            "🚪  Leave a community",
            "🔍  Browse a community",
            "\u{2190}   Back",
        ];

        println!();
        let choice = match opt(Select::new("Communities:", sub_actions).prompt())? {
            Some(c) => c,
            None => return Ok(()),
        };

        match choice {
            // ── List ─────────────────────────────────────────────────────────
            c if c.contains("List") => {
                let communities = ctx.node.communities().await;
                if communities.is_empty() {
                    println!("\n  No communities joined yet.");
                } else {
                    println!("\n  {} community / communities:", communities.len());
                    for c in &communities {
                        let label = c.name.as_deref().unwrap_or("unnamed");
                        println!(
                            "  {}  share_id={}  pubkey={}",
                            label,
                            hex::encode(c.share_id),
                            hex::encode(c.share_pubkey),
                        );
                    }
                }
            }

            // ── Create ───────────────────────────────────────────────────────
            c if c.contains("Create") => {
                let name = match opt(Text::new("Community name (local label):").prompt())? {
                    Some(v) => v,
                    None => continue,
                };
                let label = format!("community:{}", name.trim());
                let pb = spinner("Generating community keypair…");
                let keypair = ctx.node.ensure_publisher_identity(&label).await?;
                let share_id = keypair.share_id();
                let share_pubkey = keypair.verifying_key();
                ctx.node
                    .join_community_named(share_id, share_pubkey.to_bytes(), &name)
                    .await?;
                pb.finish_and_clear();

                let sid_hex = hex::encode(share_id.0);
                let pk_hex = hex::encode(share_pubkey.to_bytes());
                let sk_hex = hex::encode(keypair.signing_key.to_bytes());

                println!();
                println!("  \u{2713}  Community created");
                println!("  Share ID   : {sid_hex}");
                println!("  Public Key : {pk_hex}");
                println!();
                println!("  \u{26a0}  PRIVATE KEY (save this — it will not be shown again):");
                println!("  {sk_hex}");
            }

            // ── Join ─────────────────────────────────────────────────────────
            c if c.contains("Join") => {
                let share_id_hex =
                    match opt(Text::new("Community Share ID (64 hex chars):").prompt())? {
                        Some(s) => s,
                        None => continue,
                    };
                let pubkey_hex =
                    match opt(Text::new("Community Public Key (64 hex chars):").prompt())? {
                        Some(s) => s,
                        None => continue,
                    };

                let share_id = parse_hex_32(&share_id_hex, "share_id")?;
                let share_pubkey = parse_hex_32(&pubkey_hex, "share_pubkey")?;
                ctx.node
                    .join_community(ShareId(share_id), share_pubkey)
                    .await?;
                println!("\n  \u{2713}  Joined community {}", hex::encode(share_id));
            }

            // ── Leave ─────────────────────────────────────────────────────────
            c if c.contains("Leave") => {
                let communities: Vec<PersistedCommunity> = ctx.node.communities().await;
                if communities.is_empty() {
                    println!("\n  No communities to leave.");
                    continue;
                }
                let choices: Vec<String> = communities
                    .iter()
                    .map(|c| format!("{}...", hex::encode(&c.share_id[..8])))
                    .collect();
                let pick =
                    match opt(Select::new("Pick a community to leave:", choices.clone()).prompt())?
                    {
                        Some(p) => p,
                        None => continue,
                    };
                let idx = choices.iter().position(|ch| *ch == pick).unwrap_or(0);
                let target = &communities[idx];
                ctx.node.leave_community(ShareId(target.share_id)).await?;
                println!(
                    "\n  \u{2713}  Left community {}",
                    hex::encode(target.share_id)
                );
            }

            // ── Browse ────────────────────────────────────────────────────────
            c if c.contains("Browse") => {
                let communities: Vec<PersistedCommunity> = ctx.node.communities().await;
                if communities.is_empty() {
                    println!("\n  No communities joined yet.");
                    continue;
                }
                if ctx.bootstrap_peers.is_empty() {
                    println!("\n  No bootstrap peers configured — unable to browse without peers.");
                    continue;
                }

                let choices: Vec<String> = communities
                    .iter()
                    .map(|c| format!("{}...", hex::encode(&c.share_id[..8])))
                    .collect();
                let pick = match opt(
                    Select::new("Pick a community to browse:", choices.clone()).prompt()
                )? {
                    Some(p) => p,
                    None => continue,
                };
                let idx = choices.iter().position(|ch| *ch == pick).unwrap_or(0);
                let community = &communities[idx];

                let transport = ctx.transport();
                let pb = spinner("Querying peers for community status…");
                let mut participants = Vec::new();
                let mut discovered_name: Option<String> = None;
                for peer in &ctx.bootstrap_peers {
                    if let Ok((true, peer_name)) = ctx
                        .node
                        .fetch_community_status_from_peer(
                            &transport,
                            peer,
                            ShareId(community.share_id),
                            community.share_pubkey,
                        )
                        .await
                    {
                        if discovered_name.is_none()
                            && let Some(ref n) = peer_name
                            && !n.is_empty()
                        {
                            discovered_name = Some(n.clone());
                        }
                        participants.push(format!("{}:{}", peer.ip, peer.port));
                    }
                }
                pb.finish_and_clear();

                // Persist discovered community name locally.
                if let Some(ref name) = discovered_name {
                    let _ = ctx
                        .node
                        .update_community_name(ShareId(community.share_id), name)
                        .await;
                }

                let display_name = discovered_name
                    .or_else(|| community.name.clone())
                    .unwrap_or_else(|| hex::encode(community.share_id));
                println!("\n  Community {display_name}");
                if participants.is_empty() {
                    println!("  No participants discovered via bootstrap peers.");
                } else {
                    println!("  {} participant(s):", participants.len());
                    for p in &participants {
                        println!("    {p}");
                    }
                }
            }

            _ => return Ok(()),
        }
    }
}

// ── Search ────────────────────────────────────────────────────────────────────

async fn cmd_search(ctx: &Ctx) -> anyhow::Result<()> {
    let query = match opt(Text::new("Search query:").prompt())? {
        Some(q) => q,
        None => return Ok(()),
    };

    let pb = spinner("Searching…");
    let hits = ctx.node.search(SearchQuery { text: query }).await?;
    pb.finish_and_clear();

    if hits.is_empty() {
        println!("\n  No results.");
        return Ok(());
    }

    println!("\n  {} result(s):", hits.len());
    println!();
    for hit in &hits {
        println!(
            "  [{:.2}]  {:40}  share={}…  content={}…",
            hit.score,
            hit.name,
            hex::encode(&hit.share_id.0[..8]),
            hex::encode(&hit.content_id[..8]),
        );
    }
    Ok(())
}

// ── Download by content ID ────────────────────────────────────────────────────

async fn cmd_download_content(ctx: &Ctx) -> anyhow::Result<()> {
    let cid_hex = match opt(Text::new("Content ID (64 hex chars):").prompt())? {
        Some(s) => s,
        None => return Ok(()),
    };
    let out_path = match opt(Text::new("Output file path:").prompt())? {
        Some(s) => s,
        None => return Ok(()),
    };
    let extra = prompt_extra_peers()?;

    let content_id = parse_hex_32(&cid_hex, "content_id")?;
    let mut peers = ctx.bootstrap_peers.clone();
    peers.extend(extra);

    let connector = ctx.new_connector();
    let pb = spinner("Downloading…");
    ctx.node
        .download_from_peers(
            &connector,
            &peers,
            content_id,
            &out_path,
            &FetchPolicy::default(),
            None,
            None,
        )
        .await?;
    pb.finish_and_clear();

    println!("\n  ✓  Downloaded  →  {out_path}");
    Ok(())
}

// ── Download share ────────────────────────────────────────────────────────────

async fn cmd_download_share(ctx: &Ctx) -> anyhow::Result<()> {
    let share_id_hex = match opt(Text::new("Share ID (64 hex chars):").prompt())? {
        Some(s) => s,
        None => return Ok(()),
    };
    let out_dir = match opt(Text::new("Output directory:").prompt())? {
        Some(s) => s,
        None => return Ok(()),
    };
    let extra = prompt_extra_peers()?;

    let share_id = parse_hex_32(&share_id_hex, "share_id")?;
    let items = ctx.node.list_share_items(share_id).await?;

    if items.is_empty() {
        println!("\n  Share has no items.");
        return Ok(());
    }

    // Present a numbered list and let the user choose which items to fetch.
    println!("\n  {} item(s) available:", items.len());
    println!();
    for (i, item) in items.iter().enumerate() {
        println!(
            "  [{:>3}]  {}  ({})",
            i + 1,
            item.name,
            human_size(item.size)
        );
    }
    println!();

    let sel_raw = match opt(
        Text::new("Item numbers to download (e.g. 1,3,5 – or 'all'):")
            .with_default("all")
            .prompt(),
    )? {
        Some(s) => s,
        None => return Ok(()),
    };

    let to_download: Vec<&scp2p_core::ShareItemInfo> = if sel_raw.trim().eq_ignore_ascii_case("all")
    {
        items.iter().collect()
    } else {
        let indices: Vec<usize> = sel_raw
            .split(',')
            .filter_map(|s| s.trim().parse::<usize>().ok())
            .filter(|&n| n >= 1 && n <= items.len())
            .map(|n| n - 1)
            .collect();
        indices.iter().filter_map(|&i| items.get(i)).collect()
    };

    if to_download.is_empty() {
        println!("\n  Nothing selected.");
        return Ok(());
    }

    let mut peers = ctx.bootstrap_peers.clone();
    peers.extend(extra);

    let connector = ctx.new_connector();
    let policy = FetchPolicy::default();
    let target = std::path::Path::new(&out_dir);

    let pb = spinner(format!("Downloading {}/{} file(s)…", 0, to_download.len()).as_str());
    let mut count = 0usize;

    for item in &to_download {
        let rel = item.path.as_deref().unwrap_or(&item.name);
        let rel_norm = rel.replace('\\', "/");
        let dest = rel_norm
            .split('/')
            .filter(|p: &&str| !p.is_empty() && *p != "..")
            .fold(target.to_path_buf(), |acc: std::path::PathBuf, p| {
                acc.join(p)
            });
        if let Some(parent) = dest.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        ctx.node
            .download_from_peers(
                &connector,
                &peers,
                item.content_id,
                &dest.to_string_lossy(),
                &policy,
                None,
                None,
            )
            .await?;
        count += 1;
        pb.set_message(format!(
            "Downloading {}/{} file(s)…",
            count,
            to_download.len()
        ));
    }
    pb.finish_and_clear();

    println!(
        "\n  ✓  Downloaded {} file(s)  →  {out_dir}",
        to_download.len()
    );
    Ok(())
}

// ── Sync now ──────────────────────────────────────────────────────────────────

async fn cmd_sync(ctx: &Ctx) -> anyhow::Result<()> {
    let mut peers = ctx.bootstrap_peers.clone();
    if peers.is_empty() {
        let extra = prompt_extra_peers()?;
        if extra.is_empty() {
            println!("\n  No peers configured – skipping sync.");
            return Ok(());
        }
        peers = extra;
    }

    let transport = ctx.transport();
    let pb = spinner("Syncing subscriptions…");
    ctx.node
        .sync_subscriptions_over_dht(&transport, &peers)
        .await?;
    pb.finish_and_clear();

    let s = ctx.load_state().await?;
    println!(
        "\n  ✓  Sync complete – {} subscription(s), {} manifest(s)",
        s.subscriptions.len(),
        s.manifests.len()
    );
    Ok(())
}

// ── Generate new keypair ──────────────────────────────────────────────────────

fn cmd_gen_keypair() {
    let mut rng = OsRng;
    let key = SigningKey::generate(&mut rng);
    let pubkey = key.verifying_key();
    let node_id = NodeId::from_pubkey(&pubkey);
    let share_id = ShareId::from_pubkey(&pubkey);

    println!();
    println!("  ┌──────────────────────────────────────────────────────────────────┐");
    println!("  │  New keypair – keep the private key secret!                      │");
    println!("  └──────────────────────────────────────────────────────────────────┘");
    println!("  Private key   : {}", hex::encode(key.to_bytes()));
    println!("  Public key    : {}", hex::encode(pubkey.to_bytes()));
    println!("  Node ID       : {}", hex::encode(node_id.0));
    println!("  Share ID      : {}", hex::encode(share_id.0));
}

// ── Utilities ─────────────────────────────────────────────────────────────────

/// Convert an `InquireError` cancel/interrupt into `Ok(None)` so that pressing
/// Escape or Ctrl+C inside a prompt returns the user to the main menu instead
/// of crashing or propagating an error.
fn opt<T>(result: Result<T, InquireError>) -> anyhow::Result<Option<T>> {
    match result {
        Ok(v) => Ok(Some(v)),
        Err(InquireError::OperationCanceled | InquireError::OperationInterrupted) => Ok(None),
        Err(e) => Err(anyhow::anyhow!("prompt error: {e}")),
    }
}

fn spinner(msg: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.cyan} {msg}")
            .unwrap(),
    );
    pb.set_message(msg.to_owned());
    pb.enable_steady_tick(Duration::from_millis(100));
    pb
}

fn parse_hex_32(input: &str, label: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = hex::decode(input.trim())?;
    anyhow::ensure!(bytes.len() == 32, "{label} must be 32 bytes (64 hex chars)");
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_vis(s: &str) -> ShareVisibility {
    match s {
        "public" => ShareVisibility::Public,
        _ => ShareVisibility::Private,
    }
}

fn parse_peer(s: &str) -> anyhow::Result<PeerAddr> {
    let sock: SocketAddr = s.parse()?;
    Ok(PeerAddr {
        ip: sock.ip(),
        port: sock.port(),
        transport: TransportProtocol::Tcp,
        pubkey_hint: None,
        relay_via: None,
    })
}

fn human_size(bytes: u64) -> String {
    const KB: u64 = 1_024;
    const MB: u64 = KB * 1_024;
    const GB: u64 = MB * 1_024;
    match bytes {
        b if b >= GB => format!("{:.1} GB", b as f64 / GB as f64),
        b if b >= MB => format!("{:.1} MB", b as f64 / MB as f64),
        b if b >= KB => format!("{:.1} KB", b as f64 / KB as f64),
        b => format!("{b} B"),
    }
}

/// Prompt for extra peer addresses to use for a single operation.
/// Returns an empty vec on cancel or empty input.
fn prompt_extra_peers() -> anyhow::Result<Vec<PeerAddr>> {
    let raw = match opt(Text::new(
        "Extra peer addresses (comma-separated IP:PORT, or Enter to skip):",
    )
    .with_default("")
    .prompt())?
    {
        Some(s) => s,
        None => return Ok(vec![]),
    };
    Ok(raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(|s| parse_peer(s).ok())
        .collect())
}

// ── Logo banner ───────────────────────────────────────────────────────────────
//
// Mirrors the SVG icon geometry:
//   • 4 peer nodes (N/E/S/W) at the diamond corners  ●
//   • center node ◉ where the cross lines meet
//   • vertical + horizontal cross through center      │ ─
//   • diamond outline (NW↗NE↘SE↙SW)                  ╱ ╲
//   • outer dashed ring                               ·
//
// Column positions (0-indexed from line start, after 2-space indent):
//   ◉ center col 19 │ top ● col 19 │ left ● col 6 │ right ● col 32 │ bot ● col 19
//
fn print_banner(ctx: &Ctx) {
    let col = std::io::stdout().is_terminal();
    let b = if col { "\x1b[94m" } else { "" }; // bright blue  — nodes + lines
    let d = if col { "\x1b[2m" } else { "" }; // dim          — ring dots
    let r = if col { "\x1b[0m" } else { "" }; // reset
    let w = if col { "\x1b[1m" } else { "" }; // bold         — wordmark

    println!();
    //                              col: 0         1         2         3
    //                                   0123456789012345678901234567890123456
    println!("  {d}             · · · · · ·{r}"); // ring top
    println!("  {d}     ·                     ·{r}"); // ring arc
    println!("  {d}   · {r}            {b}●{r}{d}            ·{r}"); // top node (col 19)
    println!("  {d}  · {r}         {b}╱   │   ╲{r}{d}          ·{r}"); // diag row 1
    println!("  {d} · {r}     {b}╱        │        ╲{r}{d}      ·{r}"); // diag row 2
    println!("  {d}·{r}   {b}●────────────◉────────────●{r}   {d}·{r}"); // horizontal
    println!("  {d} · {r}     {b}╲        │        ╱{r}{d}      ·{r}"); // diag row 2
    println!("  {d}  · {r}         {b}╲   │   ╱{r}{d}         ·{r}"); // diag row 1
    println!("  {d}   · {r}            {b}●{r}{d}           ·{r}"); // bottom node
    println!("  {d}     ·                     ·{r}"); // ring arc
    println!("  {d}             · · · · · ·{r}"); // ring bottom
    println!();
    println!("  {w}           S  C  P  2  P{r}  \u{2014}  Interactive Shell");
    println!();

    // ── Node info ────────────────────────────────────────────────────────────
    println!("  Node ID  : {}", hex::encode(ctx.node_id.0));
    println!("  Share ID : {}", hex::encode(ctx.share_id.0));
    println!("  Database : {}", ctx.db);
    println!("  TCP port : {}", ctx.port);
    println!(
        "  QUIC port: {}",
        if ctx.quic_port > 0 { ctx.quic_port.to_string() } else { "disabled".to_owned() }
    );
    println!(
        "  Network  : {}",
        if ctx.bootstrap_peers.is_empty() {
            "offline \u{2013} no bootstrap peers".to_owned()
        } else {
            format!("{} bootstrap peer(s)", ctx.bootstrap_peers.len())
        }
    );
}

// ── Immediate DHT republish after publish ─────────────────────────────────────

async fn trigger_dht_republish(ctx: &Ctx) {
    let node = ctx.node.clone();
    let transport = ctx.dht_transport.clone();
    let peers = ctx.bootstrap_peers.clone();
    tokio::spawn(async move {
        if let Err(e) = node.dht_republish_once(transport.as_ref(), &peers).await {
            warn!(error = %e, "immediate DHT republish after publish failed");
        }
    });
}

// ── Resolve advertise IP (for relay provider entries) ─────────────────────────

fn resolve_advertise_ip(
    bind_tcp: SocketAddr,
    peers: &[PeerRecord],
) -> anyhow::Result<std::net::IpAddr> {
    if !bind_tcp.ip().is_unspecified() {
        return Ok(bind_tcp.ip());
    }
    if let Some(peer) = peers.first() {
        let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
        let _ = socket.connect(SocketAddr::new(peer.addr.ip, peer.addr.port));
        let local = socket.local_addr()?;
        if !local.ip().is_unspecified() {
            return Ok(local.ip());
        }
    }
    Ok("127.0.0.1".parse().expect("loopback ip"))
}
