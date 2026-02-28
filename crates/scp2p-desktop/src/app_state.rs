// Copyright (c) 2024-2026 Vanyo Vanev / Tech Art Ltd
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
use std::{path::PathBuf, sync::Arc};

use anyhow::Context;
use async_trait::async_trait;
use ed25519_dalek::SigningKey;
use rand::{rngs::OsRng, RngCore};
use scp2p_core::{
    describe_content, transport_net::tcp_connect_session, BoxedStream, Capabilities,
    DirectRequestTransport, FetchPolicy, ItemV1, ManifestV1, Node, NodeConfig, NodeHandle,
    OwnedShareRecord, PeerAddr, PeerConnector, PeerRecord, PublicShareSummary, SearchPageQuery,
    ShareItemInfo, ShareVisibility, SqliteStore, Store, TransportProtocol,
};
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio::time::{self, Duration};

use crate::dto::{
    CommunityBrowseView, CommunityParticipantView, CommunityView, DesktopClientConfig,
    OwnedShareView, PeerView, PublicShareView, PublishResultView, PublishVisibility, RuntimeStatus,
    SearchResultView, SearchResultsView, ShareItemView, StartNodeRequest, SubscriptionView,
};

#[derive(Clone, Default)]
pub struct DesktopAppState {
    inner: Arc<RwLock<RuntimeState>>,
}

#[derive(Default)]
struct RuntimeState {
    node: Option<NodeHandle>,
    state_db_path: Option<PathBuf>,
    content_data_dir: Option<PathBuf>,
    tcp_service_task: Option<JoinHandle<anyhow::Result<()>>>,
    lan_discovery_task: Option<JoinHandle<anyhow::Result<()>>>,
    last_public_shares: Vec<PublicShareView>,
}

const LAN_DISCOVERY_PORT: u16 = 46123;
const LAN_DISCOVERY_INTERVAL_SECS: u64 = 3;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct LanDiscoveryAnnouncement {
    version: u8,
    instance_id: [u8; 16],
    tcp_port: u16,
}

struct DesktopSessionConnector {
    signing_key: SigningKey,
    capabilities: Capabilities,
}

#[async_trait]
impl PeerConnector for DesktopSessionConnector {
    async fn connect(&self, peer: &PeerAddr) -> anyhow::Result<BoxedStream> {
        if peer.transport != TransportProtocol::Tcp {
            anyhow::bail!("desktop connector only supports tcp peers");
        }
        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);
        let remote = std::net::SocketAddr::new(peer.ip, peer.port);
        let (stream, _) = tcp_connect_session(
            remote,
            &self.signing_key,
            self.capabilities.clone(),
            nonce,
            peer.pubkey_hint,
        )
        .await?;
        Ok(Box::new(stream) as BoxedStream)
    }
}

impl DesktopAppState {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn start_node(&self, request: StartNodeRequest) -> anyhow::Result<RuntimeStatus> {
        {
            let state = self.inner.read().await;
            if state.node.is_some() {
                return self.status().await;
            }
        }

        let db_path = PathBuf::from(request.state_db_path);
        let store: Arc<dyn Store> = SqliteStore::open(&db_path)
            .with_context(|| format!("open sqlite state at {}", db_path.display()))?;

        let content_data_dir = db_path.parent().map(|p| p.join("content_data"));
        let config = NodeConfig {
            bind_quic: request.bind_quic,
            bind_tcp: request.bind_tcp,
            bootstrap_peers: request.bootstrap_peers,
            ..NodeConfig::default()
        };

        let handle = Node::start_with_store(config, store).await?;
        let mut state = self.inner.write().await;
        if let Some(bind_tcp) = request.bind_tcp {
            let mut rng = OsRng;
            let service_key = SigningKey::generate(&mut rng);
            state.tcp_service_task = Some(handle.clone().start_tcp_dht_service(
                bind_tcp,
                service_key,
                Capabilities::default(),
            ));
            let mut instance_id = [0u8; 16];
            OsRng.fill_bytes(&mut instance_id);
            state.lan_discovery_task = Some(tokio::spawn(start_lan_discovery(
                handle.clone(),
                bind_tcp.port(),
                instance_id,
            )));
        }
        state.node = Some(handle);
        state.state_db_path = Some(db_path);
        state.content_data_dir = content_data_dir;
        drop(state);
        self.status().await
    }

    pub async fn stop_node(&self) -> RuntimeStatus {
        let mut state = self.inner.write().await;
        if let Some(task) = state.tcp_service_task.take() {
            task.abort();
        }
        if let Some(task) = state.lan_discovery_task.take() {
            task.abort();
        }
        state.node = None;
        state.last_public_shares.clear();
        RuntimeStatus {
            running: false,
            state_db_path: state
                .state_db_path
                .as_ref()
                .map(|p| p.to_string_lossy().to_string()),
            bind_quic: None,
            bind_tcp: None,
            bootstrap_peers: Vec::new(),
            warnings: Vec::new(),
        }
    }

    pub async fn status(&self) -> anyhow::Result<RuntimeStatus> {
        let state = self.inner.read().await;
        let config = match &state.node {
            Some(node) => Some(node.runtime_config().await),
            None => None,
        };
        Ok(RuntimeStatus {
            running: state.node.is_some(),
            state_db_path: state
                .state_db_path
                .as_ref()
                .map(|p| p.to_string_lossy().to_string()),
            bind_quic: config.as_ref().and_then(|cfg| cfg.bind_quic),
            bind_tcp: config.as_ref().and_then(|cfg| cfg.bind_tcp),
            bootstrap_peers: config
                .as_ref()
                .map(|cfg| cfg.bootstrap_peers.clone())
                .unwrap_or_default(),
            warnings: config
                .as_ref()
                .and_then(|cfg| {
                    cfg.bind_quic.map(|_| {
                        "QUIC listener is not started by the Windows shell yet".to_string()
                    })
                })
                .into_iter()
                .collect(),
        })
    }

    pub async fn peer_views(&self) -> anyhow::Result<Vec<PeerView>> {
        let node = self.node_handle().await?;
        Ok(node
            .peer_records()
            .await
            .into_iter()
            .map(peer_view)
            .collect())
    }

    pub async fn subscription_views(&self) -> anyhow::Result<Vec<SubscriptionView>> {
        let node = self.node_handle().await?;
        let subs = node.subscriptions().await;
        let mut views = Vec::with_capacity(subs.len());
        for sub in subs {
            let (title, description) = match sub.latest_manifest_id {
                Some(mid) => node.cached_manifest_meta(&mid).await,
                None => (None, None),
            };
            views.push(SubscriptionView {
                share_id_hex: hex::encode(sub.share_id),
                share_pubkey_hex: sub.share_pubkey.map(hex::encode),
                latest_seq: sub.latest_seq,
                latest_manifest_id_hex: sub.latest_manifest_id.map(hex::encode),
                trust_level: sub.trust_level,
                title,
                description,
            });
        }
        Ok(views)
    }

    pub async fn community_views(&self) -> anyhow::Result<Vec<CommunityView>> {
        let node = self.node_handle().await?;
        Ok(node
            .communities()
            .await
            .into_iter()
            .map(community_view)
            .collect())
    }

    pub async fn join_community(
        &self,
        share_id_hex: &str,
        share_pubkey_hex: &str,
    ) -> anyhow::Result<Vec<CommunityView>> {
        let node = self.node_handle().await?;
        let share_id = parse_hex_32(share_id_hex, "community share_id")?;
        let share_pubkey = parse_hex_32(share_pubkey_hex, "community share_pubkey")?;
        node.join_community(scp2p_core::ShareId(share_id), share_pubkey)
            .await?;
        self.community_views().await
    }

    pub async fn subscribe_share(
        &self,
        share_id_hex: &str,
    ) -> anyhow::Result<Vec<SubscriptionView>> {
        let node = self.node_handle().await?;
        let share_id = parse_hex_32(share_id_hex, "share_id")?;
        node.subscribe(scp2p_core::ShareId(share_id)).await?;
        self.subscription_views().await
    }

    pub async fn unsubscribe_share(
        &self,
        share_id_hex: &str,
    ) -> anyhow::Result<Vec<SubscriptionView>> {
        let node = self.node_handle().await?;
        let share_id = parse_hex_32(share_id_hex, "share_id")?;
        node.unsubscribe(scp2p_core::ShareId(share_id)).await?;
        self.subscription_views().await
    }

    pub async fn sync_now(&self) -> anyhow::Result<Vec<SubscriptionView>> {
        let node = self.node_handle().await?;
        let mut peers = node.configured_bootstrap_peers().await?;
        for record in node.peer_records().await {
            if !peers.iter().any(|peer| peer == &record.addr) {
                peers.push(record.addr);
            }
        }
        let mut rng = OsRng;
        let transport = DirectRequestTransport::new(DesktopSessionConnector {
            signing_key: SigningKey::generate(&mut rng),
            capabilities: Capabilities::default(),
        });
        node.sync_subscriptions_over_dht(&transport, &peers).await?;
        self.subscription_views().await
    }

    pub async fn search_catalogs(&self, text: &str) -> anyhow::Result<SearchResultsView> {
        let node = self.node_handle().await?;
        let page = node
            .search_page(SearchPageQuery {
                text: text.to_string(),
                offset: 0,
                limit: 100,
                include_snippets: true,
            })
            .await?;
        Ok(SearchResultsView {
            total: page.total,
            results: page.results.into_iter().map(search_result_view).collect(),
        })
    }

    pub async fn browse_public_shares(&self) -> anyhow::Result<Vec<PublicShareView>> {
        let node = self.node_handle().await?;
        let peers = self.sync_peer_targets(&node).await?;
        if peers.is_empty() {
            let mut state = self.inner.write().await;
            state.last_public_shares.clear();
            return Ok(Vec::new());
        }

        let mut rng = OsRng;
        let transport = DirectRequestTransport::new(DesktopSessionConnector {
            signing_key: SigningKey::generate(&mut rng),
            capabilities: Capabilities::default(),
        });
        let mut first_err = None;
        let mut views = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for peer in peers {
            match node
                .fetch_public_shares_from_peer(&transport, &peer, 64)
                .await
            {
                Ok(shares) => {
                    for share in shares {
                        if seen.insert(share.share_id) {
                            views.push(public_share_view(&peer, share));
                        }
                    }
                }
                Err(err) => {
                    if first_err.is_none() {
                        first_err = Some(err);
                    }
                }
            }
        }
        if views.is_empty() {
            if let Some(err) = first_err {
                return Err(err);
            }
        }
        views.sort_by(|a, b| {
            b.latest_seq
                .cmp(&a.latest_seq)
                .then(a.title.cmp(&b.title))
                .then(a.share_id_hex.cmp(&b.share_id_hex))
        });
        let mut state = self.inner.write().await;
        state.last_public_shares = views.clone();
        Ok(views)
    }

    pub async fn browse_community(
        &self,
        share_id_hex: &str,
    ) -> anyhow::Result<CommunityBrowseView> {
        let node = self.node_handle().await?;
        let share_id = parse_hex_32(share_id_hex, "community share_id")?;
        let community = node
            .communities()
            .await
            .into_iter()
            .find(|community| community.share_id == share_id)
            .ok_or_else(|| anyhow::anyhow!("community is not joined"))?;
        let peers = self.sync_peer_targets(&node).await?;
        if peers.is_empty() {
            return Ok(CommunityBrowseView {
                community_share_id_hex: hex::encode(community.share_id),
                participants: Vec::new(),
                public_shares: Vec::new(),
            });
        }

        let mut rng = OsRng;
        let transport = DirectRequestTransport::new(DesktopSessionConnector {
            signing_key: SigningKey::generate(&mut rng),
            capabilities: Capabilities::default(),
        });
        let mut participants = Vec::new();
        let mut public_shares = Vec::new();
        let mut seen_shares = std::collections::HashSet::new();
        let mut first_err = None;
        for peer in peers {
            match node
                .fetch_community_status_from_peer(
                    &transport,
                    &peer,
                    scp2p_core::ShareId(community.share_id),
                    community.share_pubkey,
                )
                .await
            {
                Ok(true) => {
                    participants.push(CommunityParticipantView {
                        community_share_id_hex: hex::encode(community.share_id),
                        peer_addr: format!("{}:{}", peer.ip, peer.port),
                        transport: format!("{:?}", peer.transport),
                    });
                    match node
                        .fetch_community_public_shares_from_peer(
                            &transport,
                            &peer,
                            scp2p_core::ShareId(community.share_id),
                            community.share_pubkey,
                            64,
                        )
                        .await
                    {
                        Ok(shares) => {
                            for share in shares {
                                if seen_shares.insert(share.share_id) {
                                    public_shares.push(public_share_view(&peer, share));
                                }
                            }
                        }
                        Err(err) => {
                            if first_err.is_none() {
                                first_err = Some(err);
                            }
                        }
                    }
                }
                Ok(false) => {}
                Err(err) => {
                    if first_err.is_none() {
                        first_err = Some(err);
                    }
                }
            }
        }
        participants.sort_by(|a, b| a.peer_addr.cmp(&b.peer_addr));
        public_shares.sort_by(|a, b| {
            b.latest_seq
                .cmp(&a.latest_seq)
                .then(a.title.cmp(&b.title))
                .then(a.share_id_hex.cmp(&b.share_id_hex))
        });
        if participants.is_empty() && public_shares.is_empty() {
            if let Some(err) = first_err {
                return Err(err);
            }
        }
        Ok(CommunityBrowseView {
            community_share_id_hex: hex::encode(community.share_id),
            participants,
            public_shares,
        })
    }

    pub async fn subscribe_public_share(
        &self,
        one_based_index: usize,
    ) -> anyhow::Result<Vec<SubscriptionView>> {
        if one_based_index == 0 {
            anyhow::bail!("public share index must be >= 1");
        }
        let selected = {
            let state = self.inner.read().await;
            state
                .last_public_shares
                .get(one_based_index - 1)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("public share index is out of range"))?
        };
        let node = self.node_handle().await?;
        let share_id = parse_hex_32(&selected.share_id_hex, "share_id")?;
        let share_pubkey = parse_hex_32(&selected.share_pubkey_hex, "share_pubkey")?;
        node.subscribe_with_pubkey(scp2p_core::ShareId(share_id), Some(share_pubkey))
            .await?;
        self.subscription_views().await
    }

    pub async fn download_content(
        &self,
        content_id_hex: &str,
        target_path: &str,
    ) -> anyhow::Result<()> {
        let node = self.node_handle().await?;
        let content_id = parse_hex_32(content_id_hex, "content_id")?;
        let peers = self.sync_peer_targets(&node).await?;
        let mut rng = OsRng;
        let connector = DesktopSessionConnector {
            signing_key: SigningKey::generate(&mut rng),
            capabilities: Capabilities::default(),
        };

        // Resolve our own advertise address so we can self-seed after download.
        let self_addr = self.resolve_self_addr(&node).await.ok();

        node.download_from_peers(
            &connector,
            &peers,
            content_id,
            target_path,
            &scp2p_core::FetchPolicy::default(),
            self_addr,
            None,
        )
        .await
    }

    pub async fn publish_text_share(
        &self,
        title: &str,
        item_name: &str,
        item_text: &str,
        visibility: PublishVisibility,
        community_ids_hex: &[String],
    ) -> anyhow::Result<PublishResultView> {
        let node = self.node_handle().await?;
        let runtime = node.runtime_config().await;
        let bind_tcp = runtime
            .bind_tcp
            .ok_or_else(|| anyhow::anyhow!("tcp bind must be enabled to publish"))?;
        let peer_records = node.peer_records().await;
        let advertise_ip = resolve_advertise_ip(bind_tcp, &peer_records)?;
        let provider = node
            .relayed_self_addr(PeerAddr {
                ip: advertise_ip,
                port: bind_tcp.port(),
                transport: TransportProtocol::Tcp,
                pubkey_hint: None,
                relay_via: None,
            })
            .await;

        let payload = item_text.as_bytes().to_vec();
        let content = describe_content(&payload);
        let data_dir = {
            let state = self.inner.read().await;
            state
                .content_data_dir
                .clone()
                .unwrap_or_else(|| std::env::temp_dir().join("scp2p-content"))
        };
        node.register_content_from_bytes(provider.clone(), &payload, &data_dir)
            .await?;

        let share = node.ensure_publisher_identity("default").await?;
        let now = now_unix_secs()?;
        let communities = resolve_joined_communities(&node, community_ids_hex).await?;
        let next_seq = node
            .published_share_head(share.share_id())
            .await
            .map(|head| head.latest_seq.saturating_add(1))
            .unwrap_or(1);
        let manifest = ManifestV1 {
            version: 1,
            share_pubkey: share.verifying_key().to_bytes(),
            share_id: share.share_id().0,
            seq: next_seq,
            created_at: now,
            expires_at: None,
            title: Some(title.trim().to_string()),
            description: Some("published from scp2p-desktop".to_string()),
            visibility: share_visibility(visibility),
            communities: communities
                .iter()
                .map(|community| community.share_id)
                .collect(),
            items: vec![ItemV1 {
                content_id: content.content_id.0,
                size: item_text.len() as u64,
                name: item_name.trim().to_string(),
                path: None,
                mime: Some("text/plain".to_string()),
                tags: vec!["desktop".to_string(), "lan".to_string()],
                chunk_count: content.chunk_count,
                chunk_list_hash: content.chunk_list_hash,
            }],
            recommended_shares: vec![],
            signature: None,
        };
        let manifest_id = node.publish_share(manifest, &share).await?;

        Ok(PublishResultView {
            share_id_hex: hex::encode(share.share_id().0),
            share_pubkey_hex: hex::encode(share.verifying_key().to_bytes()),
            share_secret_hex: hex::encode(share.signing_key.to_bytes()),
            manifest_id_hex: hex::encode(manifest_id),
            provider_addr: format!("{}:{}", provider.ip, provider.port),
            visibility,
            community_ids_hex: communities
                .iter()
                .map(|community| hex::encode(community.share_id))
                .collect(),
        })
    }

    pub async fn save_client_config(
        &self,
        path: impl Into<PathBuf>,
        config: &DesktopClientConfig,
    ) -> anyhow::Result<()> {
        let path = path.into();
        let bytes = serde_cbor::to_vec(config)?;
        std::fs::write(&path, bytes)
            .with_context(|| format!("write desktop config to {}", path.display()))?;
        Ok(())
    }

    pub async fn load_client_config(
        &self,
        path: impl Into<PathBuf>,
    ) -> anyhow::Result<DesktopClientConfig> {
        let path = path.into();
        if !path.exists() {
            return Ok(DesktopClientConfig::default());
        }

        let bytes = std::fs::read(&path)
            .with_context(|| format!("read desktop config from {}", path.display()))?;
        Ok(serde_cbor::from_slice(&bytes)?)
    }

    async fn node_handle(&self) -> anyhow::Result<NodeHandle> {
        self.inner
            .read()
            .await
            .node
            .clone()
            .context("node is not running")
    }

    async fn sync_peer_targets(&self, node: &NodeHandle) -> anyhow::Result<Vec<PeerAddr>> {
        let mut peers = node.configured_bootstrap_peers().await?;
        for record in node.peer_records().await {
            if !peers.iter().any(|peer| peer == &record.addr) {
                peers.push(record.addr);
            }
        }
        Ok(peers)
    }

    /// Resolve this node's own advertise address for self-seeding.
    ///
    /// If the node has an active relay tunnel (firewalled mode), the
    /// returned address includes `relay_via` so remote peers can reach
    /// this node through the relay.
    async fn resolve_self_addr(&self, node: &NodeHandle) -> anyhow::Result<PeerAddr> {
        let runtime = node.runtime_config().await;
        let bind_tcp = runtime
            .bind_tcp
            .ok_or_else(|| anyhow::anyhow!("tcp bind not enabled"))?;
        let peer_records = node.peer_records().await;
        let advertise_ip = resolve_advertise_ip(bind_tcp, &peer_records)?;
        let direct_addr = PeerAddr {
            ip: advertise_ip,
            port: bind_tcp.port(),
            transport: TransportProtocol::Tcp,
            pubkey_hint: None,
            relay_via: None,
        };
        // If we have a relay tunnel active, wrap the address with relay routing.
        Ok(node.relayed_self_addr(direct_addr).await)
    }

    pub async fn publish_files(
        &self,
        file_paths: &[String],
        title: &str,
        visibility: PublishVisibility,
        community_ids_hex: &[String],
    ) -> anyhow::Result<PublishResultView> {
        let node = self.node_handle().await?;
        let runtime = node.runtime_config().await;
        let bind_tcp = runtime
            .bind_tcp
            .ok_or_else(|| anyhow::anyhow!("tcp bind must be enabled to publish"))?;
        let peer_records = node.peer_records().await;
        let advertise_ip = resolve_advertise_ip(bind_tcp, &peer_records)?;
        let provider = node
            .relayed_self_addr(PeerAddr {
                ip: advertise_ip,
                port: bind_tcp.port(),
                transport: TransportProtocol::Tcp,
                pubkey_hint: None,
                relay_via: None,
            })
            .await;

        let paths: Vec<std::path::PathBuf> =
            file_paths.iter().map(std::path::PathBuf::from).collect();
        let share = node.ensure_publisher_identity("default").await?;
        let communities = resolve_joined_communities(&node, community_ids_hex).await?;
        let community_ids: Vec<[u8; 32]> = communities.iter().map(|c| c.share_id).collect();

        let manifest_id = node
            .publish_files(
                &paths,
                None,
                title,
                Some("published from scp2p-desktop"),
                share_visibility(visibility),
                &community_ids,
                provider.clone(),
                &share,
            )
            .await?;

        Ok(PublishResultView {
            share_id_hex: hex::encode(share.share_id().0),
            share_pubkey_hex: hex::encode(share.verifying_key().to_bytes()),
            share_secret_hex: hex::encode(share.signing_key.to_bytes()),
            manifest_id_hex: hex::encode(manifest_id),
            provider_addr: format!("{}:{}", provider.ip, provider.port),
            visibility,
            community_ids_hex: communities
                .iter()
                .map(|c| hex::encode(c.share_id))
                .collect(),
        })
    }

    pub async fn publish_folder(
        &self,
        dir_path: &str,
        title: &str,
        visibility: PublishVisibility,
        community_ids_hex: &[String],
    ) -> anyhow::Result<PublishResultView> {
        let node = self.node_handle().await?;
        let runtime = node.runtime_config().await;
        let bind_tcp = runtime
            .bind_tcp
            .ok_or_else(|| anyhow::anyhow!("tcp bind must be enabled to publish"))?;
        let peer_records = node.peer_records().await;
        let advertise_ip = resolve_advertise_ip(bind_tcp, &peer_records)?;
        let provider = node
            .relayed_self_addr(PeerAddr {
                ip: advertise_ip,
                port: bind_tcp.port(),
                transport: TransportProtocol::Tcp,
                pubkey_hint: None,
                relay_via: None,
            })
            .await;

        let share = node.ensure_publisher_identity("default").await?;
        let communities = resolve_joined_communities(&node, community_ids_hex).await?;
        let community_ids: Vec<[u8; 32]> = communities.iter().map(|c| c.share_id).collect();

        let dir = std::path::Path::new(dir_path);
        let manifest_id = node
            .publish_folder(
                dir,
                title,
                Some("published from scp2p-desktop"),
                share_visibility(visibility),
                &community_ids,
                provider.clone(),
                &share,
            )
            .await?;

        Ok(PublishResultView {
            share_id_hex: hex::encode(share.share_id().0),
            share_pubkey_hex: hex::encode(share.verifying_key().to_bytes()),
            share_secret_hex: hex::encode(share.signing_key.to_bytes()),
            manifest_id_hex: hex::encode(manifest_id),
            provider_addr: format!("{}:{}", provider.ip, provider.port),
            visibility,
            community_ids_hex: communities
                .iter()
                .map(|c| hex::encode(c.share_id))
                .collect(),
        })
    }

    // ── My Shares management ───────────────────────────────────────────────────

    /// List all shares that this node has published.
    pub async fn list_my_shares(&self) -> anyhow::Result<Vec<OwnedShareView>> {
        let node = self.node_handle().await?;
        let records = node.list_owned_shares().await;
        Ok(records.into_iter().map(owned_share_view).collect())
    }

    /// Delete (unpublish) a locally-published share by its hex share ID.
    pub async fn delete_my_share(&self, share_id_hex: &str) -> anyhow::Result<Vec<OwnedShareView>> {
        let node = self.node_handle().await?;
        let share_id = parse_hex_32(share_id_hex, "share_id")?;
        node.delete_published_share(scp2p_core::ShareId(share_id))
            .await?;
        self.list_my_shares().await
    }

    /// Toggle the visibility of a locally-published share.
    pub async fn update_my_share_visibility(
        &self,
        share_id_hex: &str,
        visibility: PublishVisibility,
    ) -> anyhow::Result<Vec<OwnedShareView>> {
        let node = self.node_handle().await?;
        let share_id = parse_hex_32(share_id_hex, "share_id")?;
        node.update_share_visibility(scp2p_core::ShareId(share_id), share_visibility(visibility))
            .await?;
        self.list_my_shares().await
    }

    pub async fn browse_share_items(
        &self,
        share_id_hex: &str,
    ) -> anyhow::Result<Vec<ShareItemView>> {
        let node = self.node_handle().await?;
        let share_id = parse_hex_32(share_id_hex, "share_id")?;
        let items = node.list_share_items(share_id).await?;
        Ok(items
            .into_iter()
            .map(|item| ShareItemView {
                content_id_hex: hex::encode(item.content_id),
                size: item.size,
                name: item.name,
                path: item.path,
                mime: item.mime,
            })
            .collect())
    }

    pub async fn download_share_items(
        &self,
        share_id_hex: &str,
        content_ids_hex: &[String],
        target_dir: &str,
        on_progress: Option<&scp2p_core::ProgressCallback>,
    ) -> anyhow::Result<Vec<String>> {
        let node = self.node_handle().await?;
        let share_id = parse_hex_32(share_id_hex, "share_id")?;
        let content_ids: Vec<[u8; 32]> = content_ids_hex
            .iter()
            .map(|h| parse_hex_32(h, "content_id"))
            .collect::<anyhow::Result<_>>()?;

        // List items from the cached manifest.
        let items = node.list_share_items(share_id).await?;
        let to_download: Vec<&ShareItemInfo> = if content_ids.is_empty() {
            items.iter().collect()
        } else {
            items
                .iter()
                .filter(|item| content_ids.contains(&item.content_id))
                .collect()
        };
        if to_download.is_empty() {
            anyhow::bail!("no matching items found in share");
        }

        // Build connector and peer list — same as download_content.
        let peers = self.sync_peer_targets(&node).await?;
        let mut rng = OsRng;
        let connector = DesktopSessionConnector {
            signing_key: SigningKey::generate(&mut rng),
            capabilities: Capabilities::default(),
        };
        let self_addr = self.resolve_self_addr(&node).await.ok();
        let policy = FetchPolicy::default();
        let target = std::path::Path::new(target_dir);

        let mut downloaded = Vec::with_capacity(to_download.len());
        for item in to_download {
            // Sanitise relative path: normalise separators, reject traversal.
            let rel = item
                .path
                .as_deref()
                .unwrap_or(&item.name)
                .replace('\\', "/");
            let parts: Vec<&str> = rel
                .split('/')
                .filter(|p| !p.is_empty() && *p != "..")
                .collect();
            let dest = parts
                .iter()
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
                self_addr.clone(),
                on_progress,
            )
            .await?;
            downloaded.push(dest.to_string_lossy().to_string());
        }
        Ok(downloaded)
    }
}

fn peer_view(record: PeerRecord) -> PeerView {
    PeerView {
        addr: format!("{}:{}", record.addr.ip, record.addr.port),
        transport: format!("{:?}", record.addr.transport),
        last_seen_unix: record.last_seen_unix,
    }
}

fn community_view(community: scp2p_core::PersistedCommunity) -> CommunityView {
    CommunityView {
        share_id_hex: hex::encode(community.share_id),
        share_pubkey_hex: hex::encode(community.share_pubkey),
    }
}

fn search_result_view(result: scp2p_core::SearchResult) -> SearchResultView {
    SearchResultView {
        share_id_hex: hex::encode(result.share_id.0),
        content_id_hex: hex::encode(result.content_id),
        name: result.name,
        snippet: result.snippet,
        score: result.score,
    }
}

fn public_share_view(peer: &PeerAddr, share: PublicShareSummary) -> PublicShareView {
    PublicShareView {
        source_peer_addr: format!("{}:{}", peer.ip, peer.port),
        share_id_hex: hex::encode(share.share_id),
        share_pubkey_hex: hex::encode(share.share_pubkey),
        latest_seq: share.latest_seq,
        title: share.title,
        description: share.description,
    }
}

fn owned_share_view(record: OwnedShareRecord) -> OwnedShareView {
    let visibility = match record.visibility {
        ShareVisibility::Public => PublishVisibility::Public,
        ShareVisibility::Private => PublishVisibility::Private,
    };
    OwnedShareView {
        share_id_hex: hex::encode(record.share_id),
        share_pubkey_hex: hex::encode(record.share_pubkey),
        share_secret_hex: hex::encode(record.share_secret),
        latest_seq: record.latest_seq,
        manifest_id_hex: hex::encode(record.manifest_id),
        title: record.title,
        description: record.description,
        visibility,
        item_count: record.item_count,
        community_ids_hex: record.community_ids.iter().map(hex::encode).collect(),
    }
}

fn share_visibility(visibility: PublishVisibility) -> ShareVisibility {
    match visibility {
        PublishVisibility::Private => ShareVisibility::Private,
        PublishVisibility::Public => ShareVisibility::Public,
    }
}

async fn resolve_joined_communities(
    node: &NodeHandle,
    community_ids_hex: &[String],
) -> anyhow::Result<Vec<scp2p_core::PersistedCommunity>> {
    if community_ids_hex.is_empty() {
        return Ok(Vec::new());
    }
    let joined = node.communities().await;
    let mut resolved = Vec::new();
    for share_id_hex in community_ids_hex {
        let share_id = parse_hex_32(share_id_hex, "community share_id")?;
        let community = joined
            .iter()
            .find(|community| community.share_id == share_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("community {} is not joined", share_id_hex.trim()))?;
        if !resolved
            .iter()
            .any(|existing: &scp2p_core::PersistedCommunity| {
                existing.share_id == community.share_id
            })
        {
            resolved.push(community);
        }
    }
    Ok(resolved)
}

fn parse_hex_32(input: &str, label: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = hex::decode(input.trim())?;
    if bytes.len() != 32 {
        anyhow::bail!("{label} must be 32 bytes hex");
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

async fn start_lan_discovery(
    node: NodeHandle,
    tcp_port: u16,
    instance_id: [u8; 16],
) -> anyhow::Result<()> {
    let socket = UdpSocket::bind(("0.0.0.0", LAN_DISCOVERY_PORT)).await?;
    socket.set_broadcast(true)?;
    let broadcast = std::net::SocketAddr::from(([255, 255, 255, 255], LAN_DISCOVERY_PORT));
    let announcement = serde_cbor::to_vec(&LanDiscoveryAnnouncement {
        version: 1,
        instance_id,
        tcp_port,
    })?;
    let mut interval = time::interval(Duration::from_secs(LAN_DISCOVERY_INTERVAL_SECS));
    let mut buf = [0u8; 1024];

    loop {
        tokio::select! {
            _ = interval.tick() => {
                let _ = socket.send_to(&announcement, broadcast).await;
            }
            recv = socket.recv_from(&mut buf) => {
                let Ok((len, from)) = recv else {
                    continue;
                };
                let Ok(packet) = serde_cbor::from_slice::<LanDiscoveryAnnouncement>(&buf[..len]) else {
                    continue;
                };
                if packet.version != 1 || packet.instance_id == instance_id {
                    continue;
                }
                let peer = PeerAddr {
                    ip: from.ip(),
                    port: packet.tcp_port,
                    transport: TransportProtocol::Tcp,
                    pubkey_hint: None,
                    relay_via: None,
                };
                let _ = node.record_peer_seen(peer).await;
            }
        }
    }
}

fn resolve_advertise_ip(
    bind_tcp: std::net::SocketAddr,
    peers: &[PeerRecord],
) -> anyhow::Result<std::net::IpAddr> {
    if !bind_tcp.ip().is_unspecified() {
        return Ok(bind_tcp.ip());
    }

    if let Some(peer) = peers.first() {
        let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
        let _ = socket.connect(std::net::SocketAddr::new(peer.addr.ip, peer.addr.port));
        let local = socket.local_addr()?;
        if !local.ip().is_unspecified() {
            return Ok(local.ip());
        }
    }

    Ok("127.0.0.1".parse().expect("loopback ip"))
}

fn now_unix_secs() -> anyhow::Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn start_stop_status_roundtrip() {
        let state = DesktopAppState::new();
        let temp = std::env::temp_dir().join(format!(
            "scp2p-desktop-test-{}-{}.db",
            std::process::id(),
            1
        ));
        let status = state
            .start_node(StartNodeRequest {
                state_db_path: temp.to_string_lossy().to_string(),
                bind_quic: None,
                bind_tcp: None,
                bootstrap_peers: Vec::new(),
            })
            .await
            .expect("start node");
        assert!(status.running);
        assert_eq!(status.bind_tcp, None);

        let stopped = state.stop_node().await;
        assert!(!stopped.running);

        let _ = std::fs::remove_file(temp);
    }

    #[tokio::test]
    async fn desktop_config_file_roundtrip() {
        let state = DesktopAppState::new();
        let path = std::env::temp_dir().join(format!(
            "scp2p-desktop-config-{}-{}.cbor",
            std::process::id(),
            2
        ));
        let config = DesktopClientConfig {
            state_db_path: "desktop-state.db".to_string(),
            bind_quic: "127.0.0.1:7400".parse().ok(),
            bind_tcp: "127.0.0.1:7401".parse().ok(),
            bootstrap_peers: vec!["127.0.0.1:7501".to_string()],
        };

        state
            .save_client_config(path.clone(), &config)
            .await
            .expect("save config");
        let loaded = state
            .load_client_config(path.clone())
            .await
            .expect("load config");
        assert_eq!(loaded, config);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn lan_discovery_announcement_roundtrip() {
        let packet = LanDiscoveryAnnouncement {
            version: 1,
            instance_id: [7u8; 16],
            tcp_port: 7001,
        };
        let bytes = serde_cbor::to_vec(&packet).expect("encode");
        let decoded: LanDiscoveryAnnouncement = serde_cbor::from_slice(&bytes).expect("decode");
        assert_eq!(decoded, packet);
    }
}
